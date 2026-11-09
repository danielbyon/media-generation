"""Opt-in ComfyUI graph execution with exact local HTTP evidence.

The adapter in this module is separate from the stable-diffusion.cpp command
adapter. It re-verifies a T07 candidate, expands one pinned API graph into the
exact request body sent to an application-owned loopback ComfyUI process, and
persists that body before any process starts. Process supervision remains an
application responsibility. This module cannot prove operating-system network
isolation or descendant containment.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO

from ._candidate_contract import (
    COMPONENT_ROLES,
    CORRUPT,
    INCOMPATIBLE,
    MISSING,
    READY,
    CandidateDeclaration,
    ComponentDeclaration,
)
from ._candidate_evaluation import CandidateEvaluation, evaluate_candidate
from ._comfyui_node_authority import (
    MAX_NODE_AUTHORITY_ARCHIVE_BYTES,
    NodeAuthority,
    NodeAuthorityError,
    NodeInputs,
    parse_node_authority,
    verify_node_authority,
    verify_node_authority_component,
)
from .adapters import BACKEND_EXECUTION_CONTRACT_VERSION, AdapterCapabilities, ImageMetadata
from .backend_provenance import (
    COMFYUI_APP_DIMENSION_MULTIPLE,
    COMFYUI_APP_MAX_DIMENSION,
    COMFYUI_APP_MIN_DIMENSION,
    COMFYUI_RESOLVED_BACKEND_KIND,
    COMFYUI_RESOLVED_CLI_CONTRACT,
    COMFYUI_RESOLVED_INVOCATION_CONTRACT,
    COMFYUI_WORKFLOW_APPROVAL_SCHEMA,
    EFFECTIVE_EXECUTION_SCHEMA,
    EFFECTIVE_EXECUTION_SCHEMA_VERSION,
    MAX_COMFYUI_WORKFLOW_APPROVAL_BYTES,
    PROCESS_TREE_RESOURCE_RELEASE_SCOPE,
    RESOURCE_RELEASE_DECLARATION_KEY,
    RESOURCE_RELEASE_DECLARATION_SCHEMA,
    RESOURCE_RELEASE_DECLARATION_VERSION,
    RESOLVED_RECORD_SCHEMA_VERSION,
    RESOLVED_SCHEMA,
    capture_runtime_fingerprint,
    canonical_json,
    digest,
    environment_record,
    validate_comfyui_qwen_conditioning_graph,
    validate_comfyui_source_conditioning_path,
)
from .candidate import TrustedEvidence, parse_candidate, parse_trusted_evidence
from .comfyui_runtime_pins import (
    COMFYUI_CLOSED_PATH,
    COMFYUI_PYTHON_BOOTSTRAP_PATH,
    RuntimePinApproval,
    RuntimePinError,
    load_runtime_pin_approval,
    verify_candidate_binding,
    verify_runtime_launch_binding,
)
from .domain import GenerationPlan
from .errors import (
    AmbiguousBackendOutcome,
    BackendEvidenceError,
    BackendPreparationError,
    GenerationError,
    InputValidationError,
)
from .images import open_regular, validate_image
from .privacy import (
    COMFYUI_ADAPTER_ID,
    COMFYUI_CONFIGURATION_VERSION,
    COMFYUI_SAFE_ENVIRONMENT_NAMES,
    COMFYUI_TOOL_ID,
    PrivacyComplianceStatus,
    PrivacyControl,
    application_privacy_policy,
    comfyui_invocation_privacy_settings,
    comfyui_resolved_privacy_evidence,
)
from .supervisor import ManagedProcessControl, ProcessSupervisor

COMFYUI_BACKEND_KIND = COMFYUI_RESOLVED_BACKEND_KIND
COMFYUI_INVOCATION_CONTRACT = COMFYUI_RESOLVED_INVOCATION_CONTRACT
COMFYUI_CLI_CONTRACT = COMFYUI_RESOLVED_CLI_CONTRACT
COMFYUI_RECIPE_SCHEMA = "media-generation.comfyui-recipe"
COMFYUI_RECIPE_SCHEMA_VERSION = 2
COMFYUI_LEGACY_RECIPE_SCHEMA_VERSION = 1
COMFYUI_SYNTHETIC_TOOL_VERSION_PREFIX = "synthetic-"
COMFYUI_MODEL_FAMILY = "qwen_image_edit_2511"
COMFYUI_OUTPUT_BASENAME = "output.png"
COMFYUI_OUTPUT_PREFIX = "media-generation-output"
COMFYUI_MAX_RECIPE_BYTES = 1024 * 1024
COMFYUI_APP_MAX_REFERENCES = 1
COMFYUI_APP_MAX_REFERENCE_UPLOAD_BYTES = 32 * 1024 * 1024
COMFYUI_SCRATCH_PREFIX = "media-generation-comfyui-"
_FRONTEND_MAX_ENTRIES = 4096
_FRONTEND_MAX_DEPTH = 64
_FRONTEND_MAX_BYTES = 128 * 1024 * 1024
_SAMPLING_METHODS = frozenset({"euler", "euler_a", "ddim", "dpm++2m", "uni_pc"})
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NODE_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_PLACEHOLDER = re.compile(r"^\$(?:prompt|seed|width|height|steps|cfg_scale|flow_shift|output_basename|artifact:[0-9]+)$")
_SAFE_OUTPUT_NAME = re.compile(r"^[^/\\\x00]{1,255}$")
_MODEL_DIRECTORIES = MappingProxyType(
    {
        "checkpoint": "checkpoints",
        "diffusion_model": "diffusion_models",
        "text_encoder": "text_encoders",
        "vae": "vae",
        "lora": "loras",
        "controlnet": "controlnet",
        "adapter": "adapters",
        "projector": "clip_vision",
    }
)
_MODEL_SELECTOR_BINDINGS = MappingProxyType(
    {
        ("CheckpointLoaderSimple", "ckpt_name"): "checkpoint",
        ("UNETLoader", "unet_name"): "diffusion_model",
        ("CLIPLoader", "clip_name"): "text_encoder",
        ("VAELoader", "vae_name"): "vae",
        ("LoraLoader", "lora_name"): "lora",
        ("LoraLoaderModelOnly", "lora_name"): "lora",
        ("ControlNetLoader", "control_net_name"): "controlnet",
        ("CLIPVisionLoader", "clip_name"): "projector",
    }
)
_MODEL_SELECTOR_NAMES = frozenset(input_name for _, input_name in _MODEL_SELECTOR_BINDINGS)


def _invalid(detail: str) -> None:
    raise BackendPreparationError("recipe_invalid", detail)


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _invalid(f"{label} must be an object")
    return value


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        _invalid(f"{label} must be an array")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        _invalid(f"{label} must be a non-empty string")
    return value


def _integer(
    value: object, *, label: str, minimum: int, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _invalid(f"{label} must be an integer at least {minimum}")
    if maximum is not None and value > maximum:
        _invalid(f"{label} must not exceed {maximum}")
    return value


def _number(value: object, *, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid(f"{label} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        _invalid(f"{label} must be between {minimum} and {maximum}")
    return result


def _exact_keys(value: Mapping[str, object], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        pieces = []
        if missing:
            pieces.append("missing " + ", ".join(missing))
        if unexpected:
            pieces.append("unexpected " + ", ".join(unexpected))
        _invalid(f"{label} has invalid fields: {'; '.join(pieces)}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json(data: bytes) -> object:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError) as error:
        _invalid(f"recipe document is not strict JSON: {error}")


def _read_pinned_regular(
    path: Path,
    *,
    size: int,
    sha256: str,
    label: str,
    maximum: int = COMFYUI_MAX_RECIPE_BYTES,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as error:
        raise BackendPreparationError("bundle_missing", f"{label} is missing") from error
    except OSError as error:
        raise BackendPreparationError("bundle_corrupt", f"{label} cannot be read") from error
    with os.fdopen(descriptor, "rb") as stream:
        observed = os.fstat(stream.fileno())
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != size:
            raise BackendPreparationError("bundle_corrupt", f"{label} pin mismatch")
        if size > maximum:
            raise BackendPreparationError("bundle_corrupt", f"{label} is too large")
        data = stream.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise BackendPreparationError("bundle_corrupt", f"{label} pin mismatch")
    return data


@dataclass(frozen=True, slots=True)
class _Sampling:
    method: str
    steps: int
    cfg_scale: float
    flow_shift: float
    strength: float | None


@dataclass(frozen=True, slots=True)
class _Operation:
    name: str
    required_roles: tuple[str, ...]
    reference_roles: tuple[str, ...]
    graph: Mapping[str, object]
    approved_graph_sha256: str
    approval: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _Server:
    host: str
    initial_port: int
    argv: tuple[str, ...]
    environment_names: tuple[str, ...]
    readiness_path: str
    identity_path: tuple[str, ...]
    identity_value: str
    shutdown_timeout_seconds: float


@dataclass(frozen=True, slots=True)
class _Api:
    prompt_path: str
    jobs_path: str
    queue_path: str
    node_replacements_path: str
    history_path: str
    view_path: str
    upload_path: str
    request_timeout_seconds: float
    poll_timeout_seconds: float
    readiness_timeout_seconds: float
    max_output_bytes: int


@dataclass(frozen=True, slots=True)
class _Recipe:
    schema_version: int
    id: str
    model_family: str
    sampling: _Sampling
    operations: Mapping[str, _Operation]
    max_width: int
    max_height: int
    nodes: Mapping[str, Mapping[str, object]]
    server: _Server
    api: _Api
    output_node: str
    output_field: str


@dataclass(frozen=True, slots=True)
class ComfyUICandidate:
    declaration: CandidateDeclaration
    recipe: _Recipe
    candidate_id: str
    verification_id: str
    trusted_evidence: tuple[TrustedEvidence, ...]
    node_authority: NodeAuthority | None


@dataclass(frozen=True, slots=True)
class _Upload:
    filename: str
    path: Path
    artifact_id: str
    content_sha256: str
    role: str


@dataclass(slots=True)
class _ComfyUISideEffectState:
    """Track whether a request with possible server-side effects was sent."""

    may_have_been_accepted: bool = False


@dataclass(frozen=True, slots=True)
class ResolvedComfyUIExecution:
    attempt_id: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    scratch_directory: Path
    output_path: Path
    resolved_record: Mapping[str, object]
    request_body_bytes: bytes
    prompt_id: str
    uploads: tuple[_Upload, ...]
    width: int
    height: int
    side_effect_state: _ComfyUISideEffectState


def _parse_sampling(value: object) -> _Sampling:
    item = _mapping(value, label="recipe.sampling")
    _exact_keys(
        item,
        {"sampling_method", "steps", "cfg_scale", "flow_shift", "strength"},
        label="recipe.sampling",
    )
    method = _string(item["sampling_method"], label="recipe.sampling.sampling_method")
    if method not in _SAMPLING_METHODS:
        _invalid("recipe.sampling.sampling_method is unsupported")
    strength = item["strength"]
    if strength is not None:
        strength = _number(strength, label="recipe.sampling.strength", minimum=0.0, maximum=1.0)
    return _Sampling(
        method=method,
        steps=_integer(item["steps"], label="recipe.sampling.steps", minimum=1, maximum=50),
        cfg_scale=_number(item["cfg_scale"], label="recipe.sampling.cfg_scale", minimum=0.0, maximum=15.0),
        flow_shift=_number(item["flow_shift"], label="recipe.sampling.flow_shift", minimum=0.0, maximum=10.0),
        strength=strength,
    )


def _parse_graph(
    value: object,
    *,
    label: str,
    trusted_nodes: Mapping[str, Mapping[str, object]],
) -> Mapping[str, object]:
    graph = _mapping(value, label=label)
    if not graph or len(graph) > 2048:
        _invalid(f"{label} must contain a bounded non-empty node map")
    for node_id, raw_node in graph.items():
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            _invalid(f"{label} has an invalid node ID")
        node = _mapping(raw_node, label=f"{label}.{node_id}")
        _exact_keys(node, {"class_type", "inputs"}, label=f"{label}.{node_id}")
        class_type = _string(node["class_type"], label=f"{label}.{node_id}.class_type")
        if (
            _NODE_CLASS.fullmatch(class_type) is None
            or class_type not in trusted_nodes
        ):
            _invalid(f"{label}.{node_id}.class_type has no independent T07 implementation pin")
        inputs = _mapping(node["inputs"], label=f"{label}.{node_id}.inputs")
        pin = trusted_nodes[class_type]
        contract = pin.get("input_contract")
        if contract is None:
            allowed_inputs = pin["inputs"]
            if not isinstance(allowed_inputs, tuple) or not set(inputs) <= set(
                allowed_inputs
            ):
                _invalid(f"{label}.{node_id}.inputs contains an unsupported parameter")
        else:
            if not isinstance(contract, NodeInputs):
                raise BackendPreparationError(
                    "bundle_unverified",
                    "ComfyUI node input contract is unavailable",
                )
            supplied = set(inputs)
            if supplied & set(contract.hidden):
                _invalid(f"{label}.{node_id}.inputs supplies a hidden parameter")
            if not set(contract.required) <= supplied:
                _invalid(f"{label}.{node_id}.inputs omits a required parameter")
            if not supplied <= set(contract.graph_inputs):
                _invalid(f"{label}.{node_id}.inputs contains an unsupported parameter")
        for input_name, input_value in inputs.items():
            if not isinstance(input_name, str) or not input_name:
                _invalid(f"{label}.{node_id}.inputs has an invalid name")
            _validate_template_value(input_value, label=f"{label}.{node_id}.inputs.{input_name}")
            if isinstance(input_value, list):
                if (
                    len(input_value) != 2
                    or not isinstance(input_value[0], str)
                    or isinstance(input_value[1], bool)
                    or not isinstance(input_value[1], int)
                    or input_value[1] < 0
                    or input_value[0] not in graph
                ):
                    _invalid(f"{label}.{node_id}.inputs.{input_name} is not a valid node link")
            if isinstance(input_value, str) and input_value.startswith("$"):
                if not _placeholder_location_supported(
                    input_value, input_name=input_name
                ):
                    _invalid(
                        f"{label}.{node_id}.inputs.{input_name} uses an unsupported placeholder location"
                    )
    return MappingProxyType(dict(graph))


def _validate_template_value(value: object, *, label: str) -> None:
    if isinstance(value, str):
        if "$" in value and _PLACEHOLDER.fullmatch(value) is None:
            _invalid(f"{label} contains an unsupported placeholder")
        if len(value) > 4096:
            _invalid(f"{label} is too large")
        return
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not value == value:
            _invalid(f"{label} must be finite")
        return
    if isinstance(value, list):
        if len(value) > 4096:
            _invalid(f"{label} is too large")
        for item in value:
            _validate_template_value(item, label=label)
        return
    _invalid(f"{label} uses an unsupported value")


def _placeholder_location_supported(placeholder: str, *, input_name: str) -> bool:
    if placeholder == "$prompt":
        return input_name in {"prompt", "text"}
    scalar_inputs = {
        "$seed": "seed",
        "$steps": "steps",
        "$cfg_scale": "cfg",
        "$flow_shift": "shift",
        "$width": "width",
        "$height": "height",
    }
    if placeholder in scalar_inputs:
        return input_name == scalar_inputs[placeholder]
    if placeholder.startswith("$artifact:"):
        return input_name in {"image", "image1", "image2", "image3"}
    if placeholder == "$output_basename":
        return input_name == "filename_prefix"
    return False


def _parse_operation(
    name: str,
    value: object,
    *,
    profile_version: int,
    declaration: CandidateDeclaration,
    trusted_nodes: Mapping[str, Mapping[str, object]],
    approved_graph_sha256: str,
    approval: Mapping[str, object],
) -> _Operation:
    item = _mapping(value, label=f"recipe.operations.{name}")
    _exact_keys(
        item,
        {"required_component_roles", "references", "graph"},
        label=f"recipe.operations.{name}",
    )
    roles_value = _list(item["required_component_roles"], label="required_component_roles")
    roles: list[str] = []
    for raw_role in roles_value:
        if not isinstance(raw_role, str) or raw_role not in COMPONENT_ROLES or raw_role in roles:
            _invalid(f"recipe.operations.{name} has an invalid required role")
        roles.append(raw_role)
    declared_roles = {component.role for component in declaration.components}
    if not roles or not set(roles) <= declared_roles:
        _invalid(f"recipe.operations.{name} requires undeclared roles")
    references = _list(item["references"], label=f"recipe.operations.{name}.references")
    if not all(isinstance(role, str) for role in references):
        _invalid(f"recipe.operations.{name}.references must contain strings")
    if any(role not in {"reference", "source"} for role in references):
        _invalid(f"recipe.operations.{name}.references contains an unsupported role")
    if profile_version == COMFYUI_RECIPE_SCHEMA_VERSION:
        expected_roles = ("reference",) if name == "generate" else ("source",)
        if tuple(references) != expected_roles:
            _invalid(
                f"recipe.operations.{name}.references must be exactly "
                f"{list(expected_roles)!r} in Qwen profile v2"
            )
    if references.count("source") > 1:
        _invalid(f"recipe.operations.{name}.references permits more than one source")
    if len(references) > COMFYUI_APP_MAX_REFERENCES:
        _invalid(
            f"recipe.operations.{name}.references supports at most one reference"
        )
    graph = _parse_graph(
        item["graph"],
        label=f"recipe.operations.{name}.graph",
        trusted_nodes=trusted_nodes,
    )
    expected_placeholders = {
        "$prompt", "$seed", "$width", "$height", "$steps", "$cfg_scale",
        "$flow_shift", "$output_basename",
        *(f"$artifact:{index}" for index in range(len(references))),
    }
    observed_placeholders = _graph_placeholders(graph)
    if observed_placeholders != expected_placeholders:
        _invalid(f"recipe.operations.{name}.graph has missing or unsupported placeholders")
    return _Operation(
        name,
        tuple(roles),
        tuple(references),
        graph,
        approved_graph_sha256,
        approval,
    )


def _graph_contains(value: object, placeholder: str) -> bool:
    if isinstance(value, str):
        return value == placeholder
    if isinstance(value, Mapping):
        return any(_graph_contains(item, placeholder) for item in value.values())
    if isinstance(value, list):
        return any(_graph_contains(item, placeholder) for item in value)
    return False


def _graph_placeholders(value: object) -> set[str]:
    if isinstance(value, str):
        return {value} if value.startswith("$") else set()
    if isinstance(value, Mapping):
        return set().union(*(_graph_placeholders(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_graph_placeholders(item) for item in value))
    return set()


def _graph_link_topology(graph: Mapping[str, object]) -> list[dict[str, object]]:
    """Return canonical named node edges from one validated operation graph."""
    links: list[dict[str, object]] = []
    for consumer, raw_node in graph.items():
        node = _mapping(raw_node, label=f"operation graph.{consumer}")
        inputs = _mapping(node["inputs"], label=f"operation graph.{consumer}.inputs")
        consumer_class = _string(
            node["class_type"], label=f"operation graph.{consumer}.class_type"
        )
        for input_name, value in inputs.items():
            if not isinstance(value, list):
                continue
            source = _string(
                value[0], label=f"operation graph.{consumer}.inputs.{input_name}.source"
            )
            source_node = _mapping(graph[source], label=f"operation graph.{source}")
            links.append(
                {
                    "consumer": consumer,
                    "consumer_class": consumer_class,
                    "input": input_name,
                    "source": source,
                    "source_class": _string(
                        source_node["class_type"],
                        label=f"operation graph.{source}.class_type",
                    ),
                    "output": value[1],
                }
            )
    return sorted(links, key=lambda link: (str(link["consumer"]), str(link["input"])))


def _component_by_id(declaration: CandidateDeclaration, component_id: str) -> ComponentDeclaration:
    matches = [item for item in declaration.components if item.id == component_id]
    if len(matches) != 1:
        _invalid(f"node implementation {component_id!r} is not uniquely pinned")
    return matches[0]


def _trusted_node_implementations(
    trusted: tuple[TrustedEvidence, ...], declaration: CandidateDeclaration
) -> tuple[Mapping[str, Mapping[str, object]], NodeAuthority | None]:
    node_records = [
        record
        for record in trusted
        if record.expected.get("schema")
        == "media-generation.comfyui-node-implementations"
    ]
    authorities = [
        record
        for record in node_records
        if record.document_size_bytes
        == len(canonical_json(record.expected).encode("utf-8")) + 1
        and record.document_sha256
        == hashlib.sha256(
            (canonical_json(record.expected) + "\n").encode("utf-8")
        ).hexdigest()
    ]
    if len(authorities) != 1 or len(node_records) != 1:
        raise BackendPreparationError(
            "bundle_unverified",
            "one independent ComfyUI node implementation pin set is required",
        )
    authority_record = authorities[0]
    authority = authority_record.expected
    approval_bytes = (canonical_json(authority) + "\n").encode("utf-8")
    if len(approval_bytes) > MAX_COMFYUI_WORKFLOW_APPROVAL_BYTES:
        raise BackendPreparationError(
            "bundle_unverified",
            "independent ComfyUI workflow approval exceeds its size limit",
        )
    approval = MappingProxyType(
        {
            "schema": COMFYUI_WORKFLOW_APPROVAL_SCHEMA,
            "authority_id": authority_record.authority_id,
            "document_sha256": authority_record.document_sha256,
            "document_size_bytes": authority_record.document_size_bytes,
            "document": json.loads(canonical_json(authority)),
            "component_id": declaration.recipe.id,
            "component_sha256": declaration.recipe.document.sha256,
        }
    )
    if (
        type(authority.get("schema_version")) is not int
        or authority.get("schema_version") not in {2, 3}
        or authority.get("tool_id") != declaration.engine.id
        or authority.get("tool_version") != declaration.engine.version
    ):
        raise BackendPreparationError(
            "bundle_unverified", "independent ComfyUI node pin identity is invalid"
        )
    if authority["schema_version"] == 3:
        try:
            parsed = parse_node_authority(authority)
            component = _component_by_id(declaration, parsed.component_id)
            if (
                component.role != "other"
                or component.artifact.size_bytes != parsed.component_size_bytes
                or component.artifact.sha256 != parsed.component_sha256
            ):
                raise NodeAuthorityError(
                    "node-authority component does not match its T07 artifact"
                )
            archive = _read_pinned_regular(
                component.artifact.resolved_path(declaration.root_index),
                size=component.artifact.size_bytes,
                sha256=component.artifact.sha256,
                label="ComfyUI node-authority component",
                maximum=MAX_NODE_AUTHORITY_ARCHIVE_BYTES,
            )
            verify_node_authority_component(
                parsed,
                archive,
                expected_component_id=component.id,
                expected_component_size_bytes=component.artifact.size_bytes,
                expected_component_sha256=component.artifact.sha256,
            )
        except (NodeAuthorityError, OSError) as error:
            raise BackendPreparationError(
                "bundle_unverified",
                "independent ComfyUI node-authority bundle is invalid",
            ) from error
        node_pins: dict[str, Mapping[str, object]] = {}
        for class_type, node in parsed.nodes.items():
            node_pins[class_type] = MappingProxyType(
                {
                    "class": class_type,
                    "component_id": parsed.component_id,
                    "sha256": parsed.component_sha256,
                    "inputs": tuple(
                        sorted((*node.inputs.required, *node.inputs.optional))
                    ),
                    "input_contract": node.inputs,
                    "registration_api": node.registration_api,
                    "source_path": node.source_path,
                }
            )
        return MappingProxyType(node_pins), parsed

    if set(authority) != {
        "schema",
        "schema_version",
        "tool_id",
        "tool_version",
        "nodes",
    }:
        raise BackendPreparationError(
            "bundle_unverified", "independent ComfyUI node pin identity is invalid"
        )
    raw_nodes = authority.get("nodes")
    if not isinstance(raw_nodes, Mapping) or not raw_nodes:
        raise BackendPreparationError(
            "bundle_unverified", "independent ComfyUI node pin set is empty or malformed"
        )
    result: dict[str, Mapping[str, object]] = {}
    for class_type, raw_pin in raw_nodes.items():
        if (
            not isinstance(class_type, str)
            or _NODE_CLASS.fullmatch(class_type) is None
            or not isinstance(raw_pin, Mapping)
            or set(raw_pin) != {"component_id", "sha256", "inputs"}
            or not isinstance(raw_pin.get("component_id"), str)
            or not isinstance(raw_pin.get("sha256"), str)
        ):
            raise BackendPreparationError(
                "bundle_unverified", "independent ComfyUI node pin set is unsupported"
            )
        raw_inputs = raw_pin.get("inputs")
        if (
            not isinstance(raw_inputs, list)
            or not raw_inputs
            or any(not isinstance(name, str) or not name for name in raw_inputs)
            or len(raw_inputs) != len(set(raw_inputs))
        ):
            raise BackendPreparationError(
                "bundle_unverified", "independent ComfyUI node input pins are unsupported"
            )
        component = _component_by_id(declaration, str(raw_pin["component_id"]))
        if (
            component.role != "other"
            or component.artifact.sha256 != raw_pin["sha256"]
        ):
            raise BackendPreparationError(
                "bundle_unverified", "trusted node implementation does not match its T07 artifact"
            )
        result[class_type] = MappingProxyType(
            {
                "class": class_type,
                "component_id": component.id,
                "sha256": component.artifact.sha256,
                "inputs": tuple(raw_inputs),
            }
        )
    return MappingProxyType(result), None


def _trusted_workflow_approvals(
    trusted: tuple[TrustedEvidence, ...],
    declaration: CandidateDeclaration,
    node_pins: Mapping[str, Mapping[str, object]],
) -> Mapping[str, Mapping[str, object]]:
    """Return independently approved exact operation templates and node sets."""
    records = [
        record
        for record in trusted
        if record.expected.get("schema")
        == "media-generation.comfyui-workflow-approval"
    ]
    authorities = [
        record
        for record in records
        if record.document_size_bytes
        == len(canonical_json(record.expected).encode("utf-8")) + 1
        and record.document_sha256
        == hashlib.sha256(
            (canonical_json(record.expected) + "\n").encode("utf-8")
        ).hexdigest()
    ]
    if len(authorities) != 1 or len(records) != 1:
        raise BackendPreparationError(
            "bundle_unverified",
            "one independent ComfyUI workflow graph pin set is required",
        )
    authority = authorities[0].expected
    if (
        set(authority)
        != {
            "schema",
            "schema_version",
            "tool_id",
            "tool_version",
            "recipe_document_sha256",
            "operations",
        }
        or type(authority.get("schema_version")) is not int
        or authority.get("schema_version") != 1
        or authority.get("tool_id") != declaration.engine.id
        or authority.get("tool_version") != declaration.engine.version
        or authority.get("recipe_document_sha256")
        != declaration.recipe.document.sha256
    ):
        raise BackendPreparationError(
            "bundle_unverified", "independent ComfyUI workflow pin identity is invalid"
        )
    authority_approval = MappingProxyType(
        {
            "schema": COMFYUI_WORKFLOW_APPROVAL_SCHEMA,
            "authority_id": authorities[0].authority_id,
            "document_sha256": authorities[0].document_sha256,
            "document_size_bytes": authorities[0].document_size_bytes,
            "document": dict(authority),
            "component_id": declaration.recipe.id,
            "component_sha256": declaration.recipe.document.sha256,
        }
    )
    raw_operations = authority.get("operations")
    if not isinstance(raw_operations, Mapping) or set(raw_operations) != {
        "generate",
        "edit",
    }:
        raise BackendPreparationError(
            "bundle_unverified", "independent ComfyUI workflow operations are incomplete"
        )
    result: dict[str, Mapping[str, object]] = {}
    for operation_name, raw_operation in raw_operations.items():
        operation = _mapping(
            raw_operation, label=f"trusted workflow operations.{operation_name}"
        )
        if set(operation) != {"graph_sha256", "nodes"}:
            raise BackendPreparationError(
                "bundle_unverified", "independent ComfyUI workflow operation is malformed"
            )
        graph_sha256 = operation["graph_sha256"]
        if (
            not isinstance(graph_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", graph_sha256) is None
        ):
            raise BackendPreparationError(
                "bundle_unverified", "independent ComfyUI workflow graph digest is invalid"
            )
        raw_nodes = operation["nodes"]
        if not isinstance(raw_nodes, Mapping) or not raw_nodes:
            raise BackendPreparationError(
                "bundle_unverified", "independent ComfyUI workflow node map is missing"
            )
        approved_nodes: dict[str, Mapping[str, str]] = {}
        for class_type, raw_pin in raw_nodes.items():
            if (
                not isinstance(class_type, str)
                or class_type not in node_pins
                or not isinstance(raw_pin, Mapping)
                or set(raw_pin) != {"component_id", "sha256"}
            ):
                raise BackendPreparationError(
                    "bundle_unverified", "independent ComfyUI workflow node pin is malformed"
                )
            node_pin = node_pins[class_type]
            if (
                raw_pin["component_id"] != node_pin["component_id"]
                or raw_pin["sha256"] != node_pin["sha256"]
            ):
                raise BackendPreparationError(
                    "bundle_unverified", "independent ComfyUI workflow node pin disagrees"
                )
            approved_nodes[class_type] = MappingProxyType(
                {
                    "component_id": str(raw_pin["component_id"]),
                    "sha256": str(raw_pin["sha256"]),
                }
            )
        result[operation_name] = MappingProxyType(
            {
                "graph_sha256": graph_sha256,
                "nodes": MappingProxyType(approved_nodes),
                "approval": authority_approval,
            }
        )
    return MappingProxyType(result)


def _parse_recipe(
    data: bytes,
    declaration: CandidateDeclaration,
    trusted_nodes: Mapping[str, Mapping[str, object]],
    trusted_workflows: Mapping[str, Mapping[str, object]],
) -> _Recipe:
    item = _mapping(_strict_json(data), label="recipe document")
    _exact_keys(
        item,
        {
            "schema",
            "schema_version",
            "id",
            "engine_id",
            "model_family",
            "sampling",
            "operations",
            "limits",
            "nodes",
            "server",
            "api",
            "output",
        },
        label="recipe document",
    )
    if (
        item["schema"] != COMFYUI_RECIPE_SCHEMA
        or type(item["schema_version"]) is not int
        or item["schema_version"]
        not in {
            COMFYUI_LEGACY_RECIPE_SCHEMA_VERSION,
            COMFYUI_RECIPE_SCHEMA_VERSION,
        }
    ):
        _invalid("recipe document has an unsupported schema")
    profile_version = int(item["schema_version"])
    recipe_id = _string(item["id"], label="recipe.id")
    if recipe_id != declaration.recipe.id or item["engine_id"] != declaration.engine.id:
        _invalid("recipe identity does not match the declaration")
    model_family = _string(item["model_family"], label="recipe.model_family")
    if model_family != COMFYUI_MODEL_FAMILY:
        raise BackendPreparationError("bundle_incompatible", "recipe model family is unsupported")
    operations_value = _mapping(item["operations"], label="recipe.operations")
    _exact_keys(operations_value, {"generate", "edit"}, label="recipe.operations")
    limits = _mapping(item["limits"], label="recipe.limits")
    _exact_keys(limits, {"max_width", "max_height"}, label="recipe.limits")

    nodes_value = _mapping(item["nodes"], label="recipe.nodes")
    nodes: dict[str, Mapping[str, object]] = {}
    for class_type, raw_pin in nodes_value.items():
        if (
            not isinstance(class_type, str)
            or _NODE_CLASS.fullmatch(class_type) is None
            or class_type not in trusted_nodes
        ):
            _invalid("recipe.nodes contains a class without an independent T07 pin")
        pin = _mapping(raw_pin, label=f"recipe.nodes.{class_type}")
        _exact_keys(pin, {"component_id", "sha256"}, label=f"recipe.nodes.{class_type}")
        component_id = _string(pin["component_id"], label="recipe.nodes.component_id")
        component = _component_by_id(declaration, component_id)
        trusted_pin = trusted_nodes[class_type]
        if (
            component.role != "other"
            or component_id != trusted_pin["component_id"]
            or pin["sha256"] != trusted_pin["sha256"]
            or component.artifact.sha256 != trusted_pin["sha256"]
        ):
            _invalid("recipe.nodes pin does not match independent T07 authority")
        nodes[class_type] = trusted_pin
    if not nodes:
        _invalid("recipe.nodes must declare independently trusted node implementations")
    operations = {
        name: _parse_operation(
            name,
            operations_value[name],
    profile_version=profile_version,
            declaration=declaration,
            trusted_nodes=trusted_nodes,
            approved_graph_sha256=str(trusted_workflows[name]["graph_sha256"]),
            approval=trusted_workflows[name]["approval"],
        )
        for name in ("generate", "edit")
    }
    used_by_operations = {
        str(node["class_type"])
        for operation in operations.values()
        for node in operation.graph.values()
        if isinstance(node, Mapping)
    }
    if not used_by_operations <= set(nodes):
        _invalid("recipe.nodes omits an operation graph implementation pin")
    if profile_version == COMFYUI_RECIPE_SCHEMA_VERSION and set(nodes) != used_by_operations:
        _invalid("recipe.nodes must exactly match the Qwen profile v2 graph classes")

    for operation in operations.values():
        approval = trusted_workflows[operation.name]
        if digest(dict(operation.graph)) != approval["graph_sha256"]:
            raise BackendPreparationError(
                "bundle_unverified",
                f"ComfyUI {operation.name} workflow graph pin does not match the exact template",
            )
        approved_nodes = approval["nodes"]
        operation_classes = {
            str(node["class_type"])
            for node in operation.graph.values()
            if isinstance(node, Mapping)
        }
        if not isinstance(approved_nodes, Mapping) or operation_classes != set(approved_nodes):
            raise BackendPreparationError(
                "bundle_unverified",
                f"ComfyUI {operation.name} workflow node pins do not match the exact template",
            )
        for node in operation.graph.values():
            if not isinstance(node, Mapping):
                continue
            class_type = str(node["class_type"])
            pin = nodes[class_type]
            approved = approved_nodes[class_type]
            if (
                approved["component_id"] != pin["component_id"]
                or approved["sha256"] != pin["sha256"]
            ):
                raise BackendPreparationError(
                    "bundle_unverified",
                    f"ComfyUI {operation.name} workflow node pin disagrees with T07 authority",
                )

    server_value = _mapping(item["server"], label="recipe.server")
    _exact_keys(
        server_value,
        {
            "host",
            "port",
            "argv",
            "environment_names",
            "readiness_path",
            "identity_path",
            "identity_value",
            "shutdown_timeout_seconds",
        },
        label="recipe.server",
    )
    host = _string(server_value["host"], label="recipe.server.host")
    if host != "127.0.0.1":
        raise BackendPreparationError("bundle_incompatible", "ComfyUI must bind IPv4 loopback")
    port = _integer(server_value["port"], label="recipe.server.port", minimum=0, maximum=65535)
    argv_value = _list(server_value["argv"], label="recipe.server.argv")
    if not argv_value or any(not isinstance(token, str) or not token for token in argv_value):
        _invalid("recipe.server.argv must contain non-empty strings")
    argv = tuple(argv_value)
    for token in argv:
        if token.startswith("$") and _PLACEHOLDER.fullmatch(token) is None and token not in {
            "$host",
            "$port",
            "$base_directory",
            "$input_directory",
            "$output_directory",
            "$temp_directory",
            "$frontend_root",
        }:
            _invalid("recipe.server.argv contains an unsupported placeholder")
    for required_flag in (
        "--listen",
        "--port",
        "--base-directory",
        "--disable-all-custom-nodes",
        "--disable-auto-launch",
        "--offline",
        "--front-end-root",
        "--feature-flag",
        "--output-directory",
        "--temp-directory",
        "--input-directory",
    ):
        if required_flag not in argv:
            _invalid(f"recipe.server.argv must declare {required_flag}")
    if argv.count("--feature-flag") != 1 or argv[argv.index("--feature-flag") + 1 : argv.index("--feature-flag") + 2] != (
        "enable_telemetry=false",
    ):
        _invalid("recipe.server.argv must disable ComfyUI telemetry explicitly")
    env_value = _list(server_value["environment_names"], label="recipe.server.environment_names")
    if (
        any(not isinstance(name, str) for name in env_value)
        or len(env_value) != len(set(env_value))
        or not set(env_value) <= COMFYUI_SAFE_ENVIRONMENT_NAMES
    ):
        _invalid("recipe.server.environment_names is not a unique safe allowlist")
    environment_names = tuple(sorted(env_value))
    identity_path = _list(server_value["identity_path"], label="recipe.server.identity_path")
    if not identity_path or any(not isinstance(part, str) or not part for part in identity_path):
        _invalid("recipe.server.identity_path must be a non-empty string path")
    shutdown_timeout = _number(
        server_value["shutdown_timeout_seconds"],
        label="recipe.server.shutdown_timeout_seconds",
        minimum=0.1,
        maximum=60.0,
    )

    api_value = _mapping(item["api"], label="recipe.api")
    _exact_keys(
        api_value,
        {
            "prompt_path",
            "jobs_path",
            "queue_path",
            "node_replacements_path",
            "history_path_template",
            "view_path",
            "upload_path",
            "request_timeout_seconds",
            "poll_timeout_seconds",
            "readiness_timeout_seconds",
            "max_output_bytes",
        },
        label="recipe.api",
    )
    if (
        api_value["prompt_path"] != "/prompt"
        or api_value["jobs_path"] != "/api/jobs?limit=1000"
        or api_value["queue_path"] != "/queue"
        or api_value["node_replacements_path"] != "/node_replacements"
        or api_value["history_path_template"] != "/history/{prompt_id}"
        or api_value["view_path"] != "/view"
        or api_value["upload_path"] != "/upload/image"
    ):
        raise BackendPreparationError("bundle_incompatible", "ComfyUI API routes are unsupported")
    max_output_bytes = _integer(
        api_value["max_output_bytes"], label="recipe.api.max_output_bytes", minimum=1, maximum=32 * 1024 * 1024
    )

    output = _mapping(item["output"], label="recipe.output")
    _exact_keys(output, {"node_id", "field"}, label="recipe.output")
    output_node_id = _string(output["node_id"], label="recipe.output.node_id")
    output_field = _string(output["field"], label="recipe.output.field")
    for operation in operations.values():
        if (
            profile_version != COMFYUI_LEGACY_RECIPE_SCHEMA_VERSION
            or "source" not in operation.reference_roles
        ):
            continue
        try:
            validate_comfyui_source_conditioning_path(
                operation.graph,
                output_node_id=output_node_id,
                output_field=output_field,
                require_artifact_placeholder=True,
                label=f"ComfyUI {operation.name} workflow",
            )
        except BackendEvidenceError as error:
            raise BackendPreparationError("recipe_invalid", str(error)) from error
    if profile_version == COMFYUI_RECIPE_SCHEMA_VERSION:
        for operation in operations.values():
            try:
                validate_comfyui_qwen_conditioning_graph(
                    operation.graph,
                    operation=operation.name,
                    output_node_id=output_node_id,
                    output_field=output_field,
                    expected_prompt="$prompt",
                    expected_width="$width",
                    expected_height="$height",
                    require_artifact_placeholder=True,
                    label=f"ComfyUI Qwen profile v2 {operation.name} workflow",
                )
            except BackendEvidenceError as error:
                raise BackendPreparationError("recipe_invalid", str(error)) from error
    sampling = _parse_sampling(item["sampling"])
    if profile_version == COMFYUI_RECIPE_SCHEMA_VERSION and sampling != _Sampling(
        method="euler",
        steps=40,
        cfg_scale=4.0,
        flow_shift=3.1,
        strength=None,
    ):
        _invalid("recipe.sampling must match the approved Qwen profile v2 values")
    return _Recipe(
        schema_version=profile_version,
        id=recipe_id,
        model_family=model_family,
        sampling=sampling,
        operations=MappingProxyType(operations),
        max_width=_integer(limits["max_width"], label="recipe.limits.max_width", minimum=1, maximum=16384),
        max_height=_integer(limits["max_height"], label="recipe.limits.max_height", minimum=1, maximum=16384),
        nodes=MappingProxyType(nodes),
        server=_Server(
            host=host,
            initial_port=port,
            argv=argv,
            environment_names=environment_names,
            readiness_path=_string(server_value["readiness_path"], label="recipe.server.readiness_path"),
            identity_path=tuple(identity_path),
            identity_value=_string(server_value["identity_value"], label="recipe.server.identity_value"),
            shutdown_timeout_seconds=shutdown_timeout,
        ),
        api=_Api(
            prompt_path="/prompt",
            jobs_path="/api/jobs?limit=1000",
            queue_path="/queue",
            node_replacements_path="/node_replacements",
            history_path="/history/{prompt_id}",
            view_path="/view",
            upload_path="/upload/image",
            request_timeout_seconds=_number(api_value["request_timeout_seconds"], label="recipe.api.request_timeout_seconds", minimum=0.1, maximum=60.0),
            poll_timeout_seconds=_number(api_value["poll_timeout_seconds"], label="recipe.api.poll_timeout_seconds", minimum=0.1, maximum=3600.0),
            readiness_timeout_seconds=_number(api_value["readiness_timeout_seconds"], label="recipe.api.readiness_timeout_seconds", minimum=0.1, maximum=60.0),
            max_output_bytes=max_output_bytes,
        ),
        output_node=output_node_id,
        output_field=output_field,
    )


def load_comfyui_candidate(
    candidate_path: Path,
    trusted_evidence_path: Path | None,
    *,
    approved_tool_version: str | None = None,
) -> ComfyUICandidate:
    declaration = parse_candidate(Path(candidate_path))
    trusted = () if trusted_evidence_path is None else parse_trusted_evidence(Path(trusted_evidence_path))
    if (
        declaration.engine.launch is None
        or declaration.engine.launch.kind != "python-script"
    ):
        raise BackendPreparationError(
            "bundle_incompatible",
            "ComfyUI candidate requires an explicit Python-script launch contract",
        )
    if (
        declaration.engine.id != COMFYUI_TOOL_ID
        or (
            approved_tool_version is not None
            and declaration.engine.version != approved_tool_version
        )
    ):
        raise BackendPreparationError(
            "bundle_unverified",
            "candidate ComfyUI version does not match the independent runtime approval",
        )
    recipe_data = _read_pinned_regular(
        declaration.recipe.document.resolved_path(declaration.root_index),
        size=declaration.recipe.document.size_bytes,
        sha256=declaration.recipe.document.sha256,
        label="ComfyUI recipe",
    )
    trusted_nodes, node_authority = _trusted_node_implementations(
        trusted, declaration
    )
    trusted_workflows = _trusted_workflow_approvals(
        trusted, declaration, trusted_nodes
    )
    recipe = _parse_recipe(
        recipe_data, declaration, trusted_nodes, trusted_workflows
    )
    if node_authority is not None:
        used_classes = {
            str(node["class_type"])
            for operation in recipe.operations.values()
            for node in operation.graph.values()
            if isinstance(node, Mapping)
        }
        if (
            recipe.schema_version != COMFYUI_RECIPE_SCHEMA_VERSION
            or set(node_authority.nodes) != used_classes
        ):
            raise BackendPreparationError(
                "bundle_unverified",
                "ComfyUI node authority does not exactly cover the Qwen graph classes",
            )
    if (
        recipe.schema_version == COMFYUI_LEGACY_RECIPE_SCHEMA_VERSION
        and not declaration.engine.version.startswith(
            COMFYUI_SYNTHETIC_TOOL_VERSION_PREFIX
        )
    ):
        raise BackendPreparationError(
            "bundle_incompatible",
            "production ComfyUI requires the Qwen reference/edit graph profile v2",
        )
    evaluation = evaluate_candidate(
        declaration,
        trusted_evidence=trusted,
        selected_backend_kind=COMFYUI_BACKEND_KIND,
    )
    if evaluation.status != READY or evaluation.evidence_authority_status != READY:
        raise BackendPreparationError(_evaluation_code(evaluation), _evaluation_detail(evaluation))
    return ComfyUICandidate(
        declaration=declaration,
        recipe=recipe,
        candidate_id=evaluation.candidate_id,
        verification_id=evaluation.verification_id,
        trusted_evidence=trusted,
        node_authority=node_authority,
    )


def _evaluation_code(evaluation: CandidateEvaluation) -> str:
    if evaluation.status == MISSING:
        return "bundle_missing"
    if evaluation.status == CORRUPT:
        return "bundle_corrupt"
    if evaluation.status == INCOMPATIBLE:
        return "bundle_incompatible"
    return "bundle_unverified"


def _evaluation_detail(evaluation: CandidateEvaluation) -> str:
    reasons = sorted(
        {f"{item.artifact}: {item.code}" for item in evaluation.items if item.status != READY}
    )
    return "candidate is not statically ready: " + "; ".join(reasons[:8])


def _require_independent_runtime_pin_binding(
    candidate: ComfyUICandidate,
    approval: RuntimePinApproval | None = None,
) -> RuntimePinApproval:
    """Authenticate and bind one candidate to the host-approved runtime pins."""
    try:
        approval = approval or _load_runtime_pin_approval()
        declaration = candidate.declaration
        root_index = declaration.root_index
        workflow_path = declaration.recipe.document.resolved_path(root_index)
        frontend_root = workflow_path.parent / "frontend"
        launch = declaration.engine.launch
        if launch is None or launch.kind != "python-script":
            raise RuntimePinError("ComfyUI candidate has no Python-script launch contract")
        verify_candidate_binding(
            approval,
            tool_id=declaration.engine.id,
            tool_version=declaration.engine.version,
            configuration_version=COMFYUI_CONFIGURATION_VERSION,
            candidate_id=candidate.candidate_id,
            interpreter={
                "path": str(
                    launch.interpreter.resolved_path(root_index).resolve(strict=True)
                ),
                "size_bytes": launch.interpreter.size_bytes,
                "sha256": launch.interpreter.sha256,
            },
        entrypoint={
                "path": str(declaration.engine.executable.resolved_path(root_index).resolve(strict=True)),
                "size_bytes": declaration.engine.executable.size_bytes,
                "sha256": declaration.engine.executable.sha256,
            },
            workflow={
                "id": candidate.recipe.id,
                "path": str(workflow_path.resolve(strict=True)),
                "size_bytes": declaration.recipe.document.size_bytes,
                "sha256": declaration.recipe.document.sha256,
            },
            components=[
                {
                    "component_id": component.id,
                    "role": component.role,
                    "path": str(component.artifact.resolved_path(root_index).resolve(strict=True)),
                    "size_bytes": component.artifact.size_bytes,
                    "sha256": component.artifact.sha256,
                }
                for component in declaration.components
            ],
            trusted_evidence=[
                {
                    "authority_id": item.authority_id,
                    "document_size_bytes": item.document_size_bytes,
                    "document_sha256": item.document_sha256,
                }
                for item in candidate.trusted_evidence
            ],
            frontend_root=frontend_root,
        )
        if candidate.node_authority is not None:
            source_root_pin = next(
                (
                    item
                    for item in approval.payload.get("roots", [])
                    if isinstance(item, Mapping)
                    and item.get("role") == "comfyui_source"
                ),
                None,
            )
            if (
                not isinstance(source_root_pin, Mapping)
                or not isinstance(source_root_pin.get("path"), str)
                or not isinstance(source_root_pin.get("sha256"), str)
            ):
                raise RuntimePinError("ComfyUI signed source root is unavailable")
            component = _component_by_id(
                declaration, candidate.node_authority.component_id
            )
            archive = _read_pinned_regular(
                component.artifact.resolved_path(root_index),
                size=component.artifact.size_bytes,
                sha256=component.artifact.sha256,
                label="ComfyUI node-authority component",
                maximum=MAX_NODE_AUTHORITY_ARCHIVE_BYTES,
            )
            verify_node_authority(
                candidate.node_authority,
                archive,
                expected_component_id=component.id,
                expected_component_size_bytes=component.artifact.size_bytes,
                expected_component_sha256=component.artifact.sha256,
                source_root=Path(str(source_root_pin["path"])),
                signed_source_root_sha256=str(source_root_pin["sha256"]),
            )
        if approval.configuration_version != COMFYUI_CONFIGURATION_VERSION:
            raise RuntimePinError("ComfyUI configuration version is not supported")
        return approval
    except (NodeAuthorityError, RuntimePinError, OSError, ValueError) as error:
        raise BackendPreparationError(
            "bundle_unverified",
            "ComfyUI requires an independently approved signed runtime pin manifest and host-provisioned public key",
        ) from error


def _require_runtime_launch_binding(
    candidate: ComfyUICandidate,
    approval: RuntimePinApproval,
    *,
    argv: Sequence[str],
    environment: Mapping[str, str],
    models_directory: Path,
    model_files: Sequence[Mapping[str, object]],
) -> None:
    try:
        workflow_path = candidate.declaration.recipe.document.resolved_path(
            candidate.declaration.root_index
        )
        verify_runtime_launch_binding(
            approval,
            argv=argv,
            environment=environment,
            workflow_path=workflow_path,
            models_directory=models_directory,
            model_files=model_files,
        )
    except (RuntimePinError, OSError, TypeError, ValueError) as error:
        raise BackendPreparationError(
            "bundle_unverified",
            "ComfyUI signed runtime roots do not match the child launch paths",
        ) from error


def _load_runtime_pin_approval() -> RuntimePinApproval:
    try:
        return load_runtime_pin_approval()
    except (RuntimePinError, OSError, ValueError) as error:
        raise BackendPreparationError(
            "bundle_unverified",
            "ComfyUI requires an independently approved signed runtime pin manifest and host-provisioned public key",
        ) from error


def _static_components(declaration: CandidateDeclaration) -> list[dict[str, object]]:
    return [
        {
            "id": item.id,
            "role": item.role,
            "sha256": item.artifact.sha256,
            "precision": item.precision,
            "quantization": item.quantization,
        }
        for item in declaration.components
    ]


def _static_configuration(
    candidate: ComfyUICandidate, approval: RuntimePinApproval
) -> dict[str, object]:
    declaration = candidate.declaration
    privacy = _candidate_privacy_settings(candidate, approval)
    return {
        "configuration_version": COMFYUI_CONFIGURATION_VERSION,
        "backend_kind": COMFYUI_BACKEND_KIND,
        RESOURCE_RELEASE_DECLARATION_KEY: {
            "schema": RESOURCE_RELEASE_DECLARATION_SCHEMA,
            "schema_version": RESOURCE_RELEASE_DECLARATION_VERSION,
            "required_scope": PROCESS_TREE_RESOURCE_RELEASE_SCOPE,
        },
        "runtime_pin_approval": {
            "schema": "media-generation.comfyui-runtime-pin-approval",
            "manifest_sha256": approval.manifest_sha256,
            "public_key_sha256": approval.public_key_sha256,
        },
        "candidate_id": candidate.candidate_id,
        "declaration_sha256": declaration.declaration_sha256,
        "invocation_contract": COMFYUI_INVOCATION_CONTRACT,
        "cli_contract": COMFYUI_CLI_CONTRACT,
        "engine": {
            "id": declaration.engine.id,
            "version": declaration.engine.version,
            "build": declaration.engine.build,
            "executable_sha256": declaration.engine.executable.sha256,
            "executable": declaration.engine.executable.identity(),
        },
        "recipe": {"id": declaration.recipe.id, "document_sha256": declaration.recipe.document.sha256},
        "workflow": {"id": candidate.recipe.id, "model_family": candidate.recipe.model_family},
        "workflow_approval": dict(
            candidate.recipe.operations["generate"].approval
        ),
        "components": _static_components(declaration),
        "adapters": [adapter.to_dict() for adapter in declaration.adapters],
        "operations": {
            name: {"required_roles": list(operation.required_roles)}
            for name, operation in candidate.recipe.operations.items()
        },
        "privacy": privacy,
        "privacy_validation": {
            "admission_scope": "validated-durable-template",
            "pre_dispatch_scope": "exact-effective-invocation",
            "pre_dispatch_rechecks": [
                "argv",
                "environment",
                "loopback_endpoint",
                "run_scoped_directories",
                "frontend_root_and_digest",
                "graph",
                "request_body",
            ],
        },
    }


def _candidate_privacy_settings(
    candidate: ComfyUICandidate,
    approval: RuntimePinApproval,
) -> dict[str, bool | None]:
    """Derive admission privacy facts from both validated operation graphs.

    Admission has no attempt-specific directories yet. This check evaluates
    the candidate's exact launch template, environment allowlist, endpoint
    contract, node pins, and both graph shapes using private placeholder paths.
    The dispatcher repeats the check against the concrete invocation.
    """
    unknown = {control.value: None for control in PrivacyControl}
    try:
        frontend_root = (
            candidate.declaration.recipe.document.resolved_path(
                candidate.declaration.root_index
            ).parent
            / "frontend"
        ).resolve(strict=True)
        frontend_sha256 = _frontend_tree_sha256(frontend_root)
        port = candidate.recipe.server.initial_port or 1
        base_directory = "/private/media-generation-admission/base"
        models_directory = f"{base_directory}/models"
        server = {
            "host": "127.0.0.1",
            "port": port,
            "offline": True,
            "base_directory": base_directory,
            "models_directory": models_directory,
            "frontend_root": str(frontend_root),
            "frontend_root_sha256": frontend_sha256,
            "output_directory": "/private/media-generation-admission/output",
            "temp_directory": "/private/media-generation-admission/temp",
            "input_directory": "/private/media-generation-admission/input",
        }
        replacements: dict[str, object] = {
            "$host": "127.0.0.1",
            "$port": str(port),
        "$base_directory": base_directory,
            "$output_directory": server["output_directory"],
            "$temp_directory": server["temp_directory"],
            "$input_directory": server["input_directory"],
            "$frontend_root": str(frontend_root),
            "$prompt": "admission privacy validation",
            "$seed": 0,
            "$width": COMFYUI_APP_MIN_DIMENSION,
            "$height": COMFYUI_APP_MIN_DIMENSION,
            "$steps": candidate.recipe.sampling.steps,
            "$cfg_scale": candidate.recipe.sampling.cfg_scale,
            "$flow_shift": candidate.recipe.sampling.flow_shift,
            "$output_basename": COMFYUI_OUTPUT_PREFIX,
        }
        environment = _child_environment(
            candidate.recipe.server.environment_names, approval
        )
        executable = candidate.declaration.engine.executable.resolved_path(
            candidate.declaration.root_index
        )
        interpreter_pin = approval.payload.get("interpreter")
        interpreter_path = (
            interpreter_pin.get("path")
            if isinstance(interpreter_pin, Mapping)
            else None
        )
        if not isinstance(interpreter_path, str) or not interpreter_path:
            return unknown
        argv_prefix = (interpreter_path, str(executable))
        operation_results: list[dict[str, bool | None]] = []
        for operation in candidate.recipe.operations.values():
            references = tuple(
                {
                    "artifact_id": "art_" + format(index + 1, "032x"),
                    "role": role,
                    "content_sha256": hashlib.sha256(role.encode("ascii")).hexdigest(),
                }
                for index, role in enumerate(operation.reference_roles)
            )
            for index, reference in enumerate(references):
                replacements[f"$artifact:{index}"] = (
                    f"admission-{reference['role']}-{index}.png"
                )
            graph = _substitute(operation.graph, replacements)
            if not isinstance(graph, dict):
                return unknown
            used_classes = {
                str(node["class_type"])
                for node in graph.values()
                if isinstance(node, Mapping)
            }
            model_files: list[dict[str, object]] = []
            for role in operation.required_roles:
                for item in candidate.declaration.components:
                    if item.role != role or item.role == "other":
                        continue
                    category = _MODEL_DIRECTORIES.get(item.role)
                    if category is None:
                        return unknown
                    source = item.artifact.resolved_path(
                        candidate.declaration.root_index
                    ).resolve(strict=True)
                    model_files.append(
                        {
                            "component_id": item.id,
                            "role": item.role,
                            "path": item.artifact.path,
                            "resolved_path": str(source),
                            "search_path": str(
                                Path(models_directory) / category / source.name
                            ),
                            "sha256": item.artifact.sha256,
                        }
                    )
            _verify_graph_model_bindings(graph, model_files)
            configuration = {
                "engine": {
                    "id": candidate.declaration.engine.id,
                    "version": candidate.declaration.engine.version,
                    "build": candidate.declaration.engine.build,
                    "executable_sha256": candidate.declaration.engine.executable.sha256,
                },
                "workflow": {
                    "id": candidate.recipe.id,
                    "document_sha256": candidate.declaration.recipe.document.sha256,
                    "operation": operation.name,
                },
                "server": server,
                "nodes": {
                name: {
                    "component_id": candidate.recipe.nodes[name]["component_id"],
                    "sha256": candidate.recipe.nodes[name]["sha256"],
                    "inputs": list(candidate.recipe.nodes[name]["inputs"]),
                }
                    for name in sorted(used_classes)
                },
                "components": _static_components(candidate.declaration),
                "model_files": model_files,
                "model_facing": {
                    "prompt": "admission privacy validation",
                    "seed": 0,
                    "width": COMFYUI_APP_MIN_DIMENSION,
                    "height": COMFYUI_APP_MIN_DIMENSION,
                    "sampling": {
                        "sampling_method": candidate.recipe.sampling.method,
                        "steps": candidate.recipe.sampling.steps,
                        "cfg_scale": candidate.recipe.sampling.cfg_scale,
                        "flow_shift": candidate.recipe.sampling.flow_shift,
                        "strength": candidate.recipe.sampling.strength,
                    },
                    "adapters": [
                        adapter.to_dict()
                        for adapter in candidate.declaration.adapters
                    ],
                    "conditioning": list(references),
                },
                "api": {
                    "prompt": candidate.recipe.api.prompt_path,
                    "jobs": candidate.recipe.api.jobs_path,
                    "queue": candidate.recipe.api.queue_path,
                    "node_replacements": candidate.recipe.api.node_replacements_path,
                    "history": candidate.recipe.api.history_path,
                    "view": candidate.recipe.api.view_path,
                    "upload": candidate.recipe.api.upload_path,
                },
                "output": {
                    "node_id": candidate.recipe.output_node,
                    "field": candidate.recipe.output_field,
                },
            }
            server_argv = tuple(
                str(replacements.get(token, token))
                for token in candidate.recipe.server.argv
            )
            request_body = {
                "prompt": graph,
                "prompt_id": "00000000-0000-4000-8000-000000000000",
                "client_id": "attempt-admission-validation",
            }
            effective = {
                "configuration": configuration,
                "graph": graph,
                "request_body": request_body,
            }
            operation_results.append(
                comfyui_invocation_privacy_settings(
                    (*argv_prefix, *server_argv), environment, effective
                )
            )
        if not operation_results or any(
            any(value is not False for value in result.values())
            for result in operation_results
        ):
            return unknown
        return {control.value: False for control in PrivacyControl}
    except (OSError, KeyError, TypeError, ValueError, BackendPreparationError):
        return unknown


def _operation_for(recipe: _Recipe, plan: GenerationPlan) -> _Operation:
    has_source = any(reference.role == "source" for reference in plan.references)
    name = "edit" if has_source else "generate"
    operation = recipe.operations[name]
    roles = tuple(reference.role for reference in plan.references)
    if roles != operation.reference_roles:
        raise BackendPreparationError(
            "operation_unsupported",
            "ComfyUI graph supports a different reference role or count",
        )
    return operation


def _validate_plan(candidate: ComfyUICandidate, plan: GenerationPlan) -> None:
    recipe = candidate.recipe
    for label, value, maximum in (
        ("width", plan.width, recipe.max_width),
        ("height", plan.height, recipe.max_height),
    ):
        upper = min(maximum, COMFYUI_APP_MAX_DIMENSION)
        if type(value) is not int or not COMFYUI_APP_MIN_DIMENSION <= value <= upper:
            raise BackendPreparationError("operation_unsupported", f"{label} is outside ComfyUI limits")
        if value % COMFYUI_APP_DIMENSION_MULTIPLE:
            raise BackendPreparationError(
                "operation_unsupported",
                f"{label} must be a multiple of {COMFYUI_APP_DIMENSION_MULTIPLE}",
            )
    if any(reference.role not in {"reference", "source"} for reference in plan.references):
        raise BackendPreparationError("operation_unsupported", "unsupported reference role")


def _frontend_tree_sha256(root: Path) -> str:
    """Hash a local frontend tree within fixed entry, depth, and byte limits."""
    if root.is_symlink() or not root.is_dir():
        raise BackendPreparationError("bundle_unverified", "pinned frontend root is unavailable")
    resolved_root = root.resolve(strict=True)
    entries: list[dict[str, object]] = []
    total_entries = 0
    total_bytes = 0
    for current, directories, filenames in os.walk(resolved_root, followlinks=False):
        directories.sort()
        filenames.sort()
        current_path = Path(current)
        depth = len(current_path.relative_to(resolved_root).parts)
        if depth > _FRONTEND_MAX_DEPTH:
            raise BackendPreparationError(
                "bundle_unverified", "pinned frontend exceeds its depth limit"
            )
        discovered_entries = len(directories) + len(filenames)
        if total_entries + discovered_entries > _FRONTEND_MAX_ENTRIES:
            raise BackendPreparationError(
                "bundle_unverified", "pinned frontend exceeds its entry limit"
            )
        total_entries += discovered_entries
        for name in directories:
            directory_path = current_path / name
            if directory_path.is_symlink():
                raise BackendPreparationError(
                    "bundle_unverified", "pinned frontend contains a symbolic link"
                )
            if depth + 1 > _FRONTEND_MAX_DEPTH:
                raise BackendPreparationError(
                    "bundle_unverified", "pinned frontend exceeds its depth limit"
                )
        for name in filenames:
            path = current_path / name
            try:
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode):
                    raise BackendPreparationError(
                        "bundle_unverified", "pinned frontend contains a non-regular file"
                    )
                if total_bytes + before.st_size > _FRONTEND_MAX_BYTES:
                    raise BackendPreparationError(
                        "bundle_unverified", "pinned frontend exceeds its bounded tree size"
                    )
                hasher = hashlib.sha256()
                size = 0
                with open_regular(path) as stream:
                    while chunk := stream.read(64 * 1024):
                        size += len(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > _FRONTEND_MAX_BYTES:
                            raise BackendPreparationError(
                                "bundle_unverified", "pinned frontend exceeds its bounded tree size"
                            )
                        hasher.update(chunk)
                after = path.lstat()
            except (OSError, InputValidationError) as error:
                raise BackendPreparationError(
                    "bundle_unverified", "pinned frontend changed while hashing"
                ) from error
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or size != before.st_size:
                raise BackendPreparationError(
                    "bundle_unverified", "pinned frontend changed while hashing"
                )
            entries.append(
                {
                    "path": path.relative_to(resolved_root).as_posix(),
                    "size_bytes": size,
                    "sha256": hasher.hexdigest(),
                }
            )
    if not any(entry["path"] == "index.html" for entry in entries):
        raise BackendPreparationError(
            "bundle_unverified", "pinned frontend has no root index.html"
        )
    entries.sort(key=lambda entry: str(entry["path"]))
    return digest(entries)


def _reserve_loopback_port(initial_port: int) -> int:
    family = socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", initial_port))
            port = int(listener.getsockname()[1])
    except OSError as error:
        raise BackendPreparationError(
            "engine_launch_failed", "the loopback ComfyUI port is unavailable"
        ) from error
    if not 1 <= port <= 65535:
        raise BackendPreparationError("engine_launch_failed", "loopback port reservation failed")
    return port


def _listener_owner_pid(host: str, port: int) -> int:
    """Return the unique loopback listener owner PID, or fail closed.

    Darwin/Linux environments with `lsof` can report the owning process. Other
    platforms or ambiguous process listings cannot prove that a response came
    from this application's child and are refused.
    """
    if host != "127.0.0.1" or not 1 <= port <= 65535:
        raise BackendEvidenceError("ComfyUI listener endpoint is unsupported")
    executable = shutil.which("lsof", path=COMFYUI_CLOSED_PATH)
    if executable is None:
        raise BackendEvidenceError("listener ownership proof is unavailable")
    try:
        result = subprocess.run(
            [executable, "-nP", "-a", f"-iTCP@{host}:{port}", "-sTCP:LISTEN", "-t"],
            check=False,
            capture_output=True,
            text=True,
            timeout=1.0,
            env={"PATH": COMFYUI_CLOSED_PATH},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BackendEvidenceError("listener ownership proof failed") from error
    pids: set[int] = set()
    for line in result.stdout.splitlines():
        try:
            pids.add(int(line.strip()))
        except ValueError as error:
            raise BackendEvidenceError("listener ownership output is malformed") from error
    if result.returncode not in (0, 1) or len(pids) != 1:
        stderr = " ".join((result.stderr or "").split())
        details = (
            f"lsof returncode={result.returncode}, pid_count={len(pids)}, "
            f"host={host}, port={port}"
        )
        if stderr:
            details += f", stderr={stderr[:160]!r}"
        raise BackendEvidenceError(
            "loopback listener identity is absent or ambiguous "
            f"({details})"
        )
    return next(iter(pids))


def _create_scratch(output_directory: Path) -> Path:
    for base in (None, "/tmp", "/var/tmp"):
        try:
            directory = Path(tempfile.mkdtemp(prefix=COMFYUI_SCRATCH_PREFIX, dir=base)).resolve()
        except OSError:
            continue
        try:
            os.chmod(directory, 0o700)
        except OSError:
            shutil.rmtree(directory, ignore_errors=True)
            continue
        if directory.is_relative_to(output_directory):
            shutil.rmtree(directory, ignore_errors=True)
            continue
        return directory
    raise BackendPreparationError(
        "runtime_evidence_incomplete", "no private ComfyUI scratch directory is available"
    )


def _bind_model_search(
    scratch: Path,
    candidate: ComfyUICandidate,
    operation: _Operation,
) -> tuple[Path, list[dict[str, object]]]:
    """Expose exact verified model artifacts through one private search root."""
    declaration = candidate.declaration
    models_directory = scratch / "models"
    models_directory.mkdir(mode=0o700)
    bound: list[dict[str, object]] = []
    occupied: set[tuple[str, str]] = set()
    for role in operation.required_roles:
        for component in declaration.components:
            if component.role != role or component.role == "other":
                continue
            category = _MODEL_DIRECTORIES.get(component.role)
            if category is None:
                raise BackendPreparationError(
                    "bundle_unverified",
                    f"ComfyUI has no approved run-scoped search folder for {component.role}",
                )
            source = component.artifact.resolved_path(
                declaration.root_index
            ).resolve(strict=True)
            if not source.is_file() or _SAFE_OUTPUT_NAME.fullmatch(source.name) is None:
                raise BackendPreparationError(
                    "bundle_unverified", "ComfyUI model search target is unsafe"
                )
            key = (category, source.name)
            if key in occupied:
                raise BackendPreparationError(
                    "bundle_unverified",
                    "ComfyUI model search names are ambiguous within one category",
                )
            occupied.add(key)
            search_directory = models_directory / category
            search_directory.mkdir(mode=0o700, exist_ok=True)
            search_path = search_directory / source.name
            try:
                os.symlink(source, search_path)
            except OSError as error:
                raise BackendPreparationError(
                    "engine_launch_failed", "ComfyUI model search binding failed"
                ) from error
            if os.readlink(search_path) != str(source):
                raise BackendPreparationError(
                    "bundle_unverified", "ComfyUI model search binding changed"
                )
            bound.append(
                {
                    "component_id": component.id,
                    "role": component.role,
                    "path": component.artifact.path,
                    "resolved_path": str(source),
                    "search_path": str(search_path),
                    "sha256": component.artifact.sha256,
                }
            )
    return models_directory, bound


def _verify_graph_model_bindings(
    graph: object, model_files: Sequence[Mapping[str, object]]
) -> None:
    """Require class-specific model selectors to resolve to pinned artifacts."""
    if not isinstance(graph, Mapping):
        _invalid("effective graph must be an object")
    selected_paths: set[str] = set()
    for node in graph.values():
        if not isinstance(node, Mapping) or not isinstance(node.get("inputs"), Mapping):
            _invalid("effective graph nodes must be objects")
        class_type = node.get("class_type")
        if not isinstance(class_type, str):
            _invalid("effective graph node class must be a string")
        for input_name, value in node["inputs"].items():
            selector_name = str(input_name)
            if selector_name not in _MODEL_SELECTOR_NAMES:
                continue
            role = _MODEL_SELECTOR_BINDINGS.get((class_type, selector_name))
            if role is None:
                raise BackendPreparationError(
                    "bundle_unverified",
                    f"ComfyUI graph model selector {class_type}.{selector_name} is unbound",
                )
            if not isinstance(value, str) or not value:
                raise BackendPreparationError(
                    "bundle_unverified",
                    f"ComfyUI graph model selector {class_type}.{selector_name} is malformed",
                )
            matches = [
                item
                for item in model_files
                if item["role"] == role
                and Path(str(item["search_path"])).name == value
            ]
            if len(matches) != 1:
                raise BackendPreparationError(
                    "bundle_unverified",
                    f"ComfyUI graph model selector {class_type}.{selector_name} is unbound or ambiguous",
                )
            selected_paths.add(str(matches[0]["search_path"]))
    for model_file in model_files:
        role = str(model_file["role"])
        search_path = Path(str(model_file["search_path"]))
        if str(search_path) not in selected_paths:
            raise BackendPreparationError(
                "bundle_unverified",
                f"ComfyUI graph does not select the verified {role} artifact",
            )


def _substitute(value: object, replacements: Mapping[str, object]) -> object:
    if isinstance(value, str) and value.startswith("$"):
        if value not in replacements:
            _invalid(f"unbound graph placeholder {value}")
        replacement = replacements[value]
        if not isinstance(replacement, (str, int, float, bool)) and replacement is not None:
            _invalid(f"graph placeholder {value} has an invalid replacement")
        return replacement
    if isinstance(value, Mapping):
        return {key: _substitute(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, replacements) for item in value]
    return value


def _effective_configuration(
    candidate: ComfyUICandidate,
    operation: _Operation,
    plan: GenerationPlan,
    *,
    port: int,
    server: Mapping[str, object],
    used_nodes: Mapping[str, Mapping[str, object]],
    model_files: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    declaration = candidate.declaration
    template = json.loads(canonical_json(dict(operation.graph)))
    components = [
        {
            "id": item.id,
            "role": item.role,
            "sha256": item.artifact.sha256,
            "precision": item.precision,
            "quantization": item.quantization,
        }
        for role in operation.required_roles
        for item in declaration.components
        if item.role == role
    ]
    workflow: dict[str, object] = {
        "id": candidate.recipe.id,
        "document_sha256": declaration.recipe.document.sha256,
        "operation": operation.name,
        "template_sha256": operation.approved_graph_sha256,
        "template": template,
        "approval": dict(operation.approval),
        "links": _graph_link_topology(template),
        "limits": {
            "min_width": COMFYUI_APP_MIN_DIMENSION,
            "min_height": COMFYUI_APP_MIN_DIMENSION,
            "max_width": min(candidate.recipe.max_width, COMFYUI_APP_MAX_DIMENSION),
            "max_height": min(candidate.recipe.max_height, COMFYUI_APP_MAX_DIMENSION),
            "dimension_multiple": COMFYUI_APP_DIMENSION_MULTIPLE,
        },
    }
    if candidate.recipe.schema_version == COMFYUI_RECIPE_SCHEMA_VERSION:
        workflow["profile_version"] = candidate.recipe.schema_version
        workflow["sampling_resolution"] = {
            "mode": (
                "requested-empty-latent"
                if operation.name == "generate"
                else "flux-kontext-image-scale"
            ),
            "width": plan.width if operation.name == "generate" else None,
            "height": plan.height if operation.name == "generate" else None,
        }
        workflow["output_dimensions"] = {
            "mode": (
                "post-decode-image-scale"
                if operation.name == "edit"
                else "decoder-native"
            ),
            "width": plan.width,
            "height": plan.height,
        }
    return {
        "engine": {
            "id": declaration.engine.id,
            "version": declaration.engine.version,
            "build": declaration.engine.build,
            "executable_sha256": declaration.engine.executable.sha256,
        },
        "workflow": workflow,
        "server": {**server, "port": port},
        "nodes": {
            name: {
                "class": pin["class"],
                "component_id": pin["component_id"],
                "sha256": pin["sha256"],
                "inputs": list(pin["inputs"]),
            }
            for name, pin in used_nodes.items()
        },
        "components": components,
        "model_files": [dict(item) for item in model_files],
        "model_facing": {
            "prompt": plan.resolved_prompt,
            "seed": plan.seed,
            "width": plan.width,
            "height": plan.height,
            "sampling": {
                "sampling_method": candidate.recipe.sampling.method,
                "steps": candidate.recipe.sampling.steps,
                "cfg_scale": candidate.recipe.sampling.cfg_scale,
                "flow_shift": candidate.recipe.sampling.flow_shift,
                "strength": candidate.recipe.sampling.strength,
            },
            "adapters": [adapter.to_dict() for adapter in declaration.adapters],
            "conditioning": [
                {"artifact_id": ref.artifact_id, "role": ref.role, "content_sha256": ref.content_sha256}
                for ref in plan.references
            ],
        },
        "api": {
            "prompt": candidate.recipe.api.prompt_path,
            "jobs": candidate.recipe.api.jobs_path,
            "queue": candidate.recipe.api.queue_path,
            "node_replacements": candidate.recipe.api.node_replacements_path,
            "history": candidate.recipe.api.history_path,
            "view": candidate.recipe.api.view_path,
            "upload": candidate.recipe.api.upload_path,
        },
        "output": {"node_id": candidate.recipe.output_node, "field": candidate.recipe.output_field},
    }


def _signed_runtime_roots(approval: RuntimePinApproval) -> dict[str, Path]:
    """Return each signed ComfyUI runtime root by its declared role."""

    root_pins = approval.payload.get("roots")
    if not isinstance(root_pins, list):
        raise BackendPreparationError(
            "bundle_unverified", "ComfyUI signed runtime roots are unavailable"
        )
    roots: dict[str, Path] = {}
    for item in root_pins:
        if not isinstance(item, Mapping):
            raise BackendPreparationError(
                "bundle_unverified", "ComfyUI signed runtime root is malformed"
            )
        role = item.get("role")
        path = item.get("path")
        if not isinstance(role, str) or not isinstance(path, str) or role in roots:
            raise BackendPreparationError(
                "bundle_unverified", "ComfyUI signed runtime root roles are malformed"
            )
        roots[role] = Path(path)
    expected_roles = {
        "comfyui_source",
        "python_home",
        "python_imports",
        "native_dependencies",
        "frontend",
        "node_implementations",
    }
    if set(roots) != expected_roles:
        raise BackendPreparationError(
            "bundle_unverified", "ComfyUI signed runtime roots are incomplete"
        )
    return roots


def _bind_child_node_implementations(
    scratch: Path, approval: RuntimePinApproval
) -> None:
    """Expose the signed node root at ComfyUI's base-directory node path."""

    node_root = _signed_runtime_roots(approval)["node_implementations"]
    child_node_path = scratch / "custom_nodes"
    if child_node_path.exists() or child_node_path.is_symlink():
        raise BackendPreparationError(
            "bundle_unverified", "ComfyUI custom-node path is already occupied"
        )
    try:
        child_node_path.symlink_to(node_root, target_is_directory=True)
    except OSError as error:
        raise BackendPreparationError(
            "bundle_unverified", "ComfyUI signed node root could not be bound"
        ) from error


def _child_environment(
    names: Sequence[str], approval: RuntimePinApproval
) -> dict[str, str]:
    """Keep approved variables and pin Python, native, and system paths."""

    roots = _signed_runtime_roots(approval)
    environment: dict[str, str] = {}
    for name in names:
        if name == "PYTHONHASHSEED":
            value = os.environ.get(name)
            if value:
                environment[name] = value
            continue
        if name in {"PATH", "LD_LIBRARY_PATH"} or name.upper().startswith("PYTHON"):
            continue
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment["LD_LIBRARY_PATH"] = str(roots["native_dependencies"])
    environment["PATH"] = COMFYUI_CLOSED_PATH
    return environment


def _json_path(value: object, path: Sequence[str]) -> object:
    current = value
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            raise BackendEvidenceError("ComfyUI readiness identity is missing")
        current = current[part]
    return current


class ComfyUIAdapter:
    """Execute one pinned local ComfyUI Qwen Image Edit graph."""

    adapter_id = COMFYUI_ADAPTER_ID
    backend_contract_version = BACKEND_EXECUTION_CONTRACT_VERSION
    process_contained = False

    def __init__(
        self,
        *,
        candidate_path: Path,
        output_directory: Path,
        trusted_evidence_path: Path | None = None,
    ) -> None:
        self._candidate_path = Path(candidate_path).expanduser()
        self._trusted_evidence_path = (
            None if trusted_evidence_path is None else Path(trusted_evidence_path).expanduser()
        )
        self._output_directory = Path(output_directory).expanduser().resolve()
        approval = _load_runtime_pin_approval()
        self._candidate = load_comfyui_candidate(
            self._candidate_path,
            self._trusted_evidence_path,
            approved_tool_version=approval.tool_version,
        )
        self._runtime_approval = _require_independent_runtime_pin_binding(
            self._candidate, approval
        )
        self._resolved_lock = threading.Lock()
        self._resolved: dict[str, ResolvedComfyUIExecution] = {}
        operation = self._candidate.recipe.operations["edit"]
        supports_editing = operation.reference_roles == ("source",)
        self.capabilities = AdapterCapabilities(
            min_width=COMFYUI_APP_MIN_DIMENSION,
            min_height=COMFYUI_APP_MIN_DIMENSION,
            max_width=min(self._candidate.recipe.max_width, COMFYUI_APP_MAX_DIMENSION),
            max_height=min(self._candidate.recipe.max_height, COMFYUI_APP_MAX_DIMENSION),
            supports_references=bool(operation.reference_roles),
            max_references=min(
                len(operation.reference_roles), COMFYUI_APP_MAX_REFERENCES
            ),
            supports_editing=supports_editing,
            max_source_images=1 if supports_editing else 0,
            dimension_multiple=COMFYUI_APP_DIMENSION_MULTIPLE,
            supported_operations=frozenset(self._candidate.recipe.operations),
            operation_reference_roles=(
                MappingProxyType(
                    {"generate": ("reference",), "edit": ("source",)}
                )
                if self._candidate.recipe.schema_version
                == COMFYUI_RECIPE_SCHEMA_VERSION
                else None
            ),
        )

    @property
    def configuration(self) -> dict[str, object]:
        return _static_configuration(self._candidate, self._runtime_approval)

    def resolve_execution(self, plan: GenerationPlan) -> ResolvedComfyUIExecution:
        if not isinstance(plan, GenerationPlan):
            raise ValueError("plan must be a GenerationPlan")
        approval = _load_runtime_pin_approval()
        candidate = load_comfyui_candidate(
            self._candidate_path,
            self._trusted_evidence_path,
            approved_tool_version=approval.tool_version,
        )
        _require_independent_runtime_pin_binding(candidate, approval)
        if (
            approval.manifest_sha256 != self._runtime_approval.manifest_sha256
            or approval.public_key_sha256 != self._runtime_approval.public_key_sha256
        ):
            raise BackendPreparationError(
                "bundle_corrupt", "ComfyUI runtime approval changed after adapter construction"
            )
        if candidate.candidate_id != self._candidate.candidate_id:
            raise BackendPreparationError("bundle_corrupt", "ComfyUI candidate changed")
        operation = _operation_for(candidate.recipe, plan)
        _validate_plan(candidate, plan)
        scratch = _create_scratch(self._output_directory)
        try:
            input_directory = scratch / "input"
            output_directory = scratch / "output"
            temp_directory = scratch / "temp"
            for directory in (input_directory, output_directory, temp_directory):
                directory.mkdir(mode=0o700)
            _bind_child_node_implementations(scratch, approval)
            models_directory, model_files = _bind_model_search(
                scratch, candidate, operation
            )
            workflow_path = candidate.declaration.recipe.document.resolved_path(
                candidate.declaration.root_index
            )
            frontend_root = workflow_path.parent / "frontend"
            frontend_root_sha256 = _frontend_tree_sha256(frontend_root)
            port = _reserve_loopback_port(candidate.recipe.server.initial_port)
            server_replacements = {
                "$host": candidate.recipe.server.host,
                "$port": str(port),
                "$base_directory": str(scratch),
                "$input_directory": str(input_directory),
                "$output_directory": str(output_directory),
                "$temp_directory": str(temp_directory),
                "$frontend_root": str(frontend_root.resolve()),
            }
            server_argv = tuple(
                token if token not in server_replacements else str(server_replacements[token])
                for token in candidate.recipe.server.argv
            )
            executable = candidate.declaration.engine.executable.resolved_path(
                candidate.declaration.root_index
            )
            runtime_roots = _signed_runtime_roots(approval)
            interpreter_pin = approval.payload.get("interpreter")
            interpreter_path = (
                interpreter_pin.get("path")
                if isinstance(interpreter_pin, Mapping)
                else None
            )
            if not isinstance(interpreter_path, str) or not interpreter_path:
                raise BackendPreparationError(
                    "bundle_unverified",
                    "ComfyUI signed Python interpreter pin is unavailable",
                )
            python_base_prefix = approval.payload.get("python_base_prefix")
            python_stdlib_paths = approval.payload.get("python_stdlib_paths")
            if (
                not isinstance(python_base_prefix, str)
                or not isinstance(python_stdlib_paths, list)
                or not all(isinstance(path, str) for path in python_stdlib_paths)
            ):
                raise BackendPreparationError(
                    "bundle_unverified",
                    "ComfyUI signed Python runtime paths are unavailable",
                )
            argv = (
                interpreter_path,
                "-P",
                "-s",
                "-S",
                str(COMFYUI_PYTHON_BOOTSTRAP_PATH),
                str(runtime_roots["python_home"]),
                python_base_prefix,
                "--stdlib-paths",
                *python_stdlib_paths,
                "--import-roots",
                str(runtime_roots["python_imports"]),
                str(runtime_roots["comfyui_source"]),
                "--",
                str(executable),
                *server_argv,
            )
            environment = _child_environment(
                candidate.recipe.server.environment_names, approval
            )
            _require_runtime_launch_binding(
                candidate,
                approval,
                argv=argv,
                environment=environment,
                models_directory=models_directory,
                model_files=model_files,
            )
            server_config = {
                "host": "127.0.0.1",
                "offline": "--offline" in argv,
                "base_directory": str(scratch),
                "models_directory": str(models_directory),
                "frontend_root": str(frontend_root.resolve()),
                "frontend_root_sha256": frontend_root_sha256,
                "output_directory": str(output_directory),
                "temp_directory": str(temp_directory),
                "input_directory": str(input_directory),
            }
            runtime_fingerprint = capture_runtime_fingerprint()
            uploads: list[_Upload] = []
            replacements: dict[str, object] = {
                "$prompt": plan.resolved_prompt,
                "$seed": plan.seed,
                "$width": plan.width,
                "$height": plan.height,
                "$steps": candidate.recipe.sampling.steps,
                "$cfg_scale": candidate.recipe.sampling.cfg_scale,
                "$flow_shift": candidate.recipe.sampling.flow_shift,
                "$output_basename": COMFYUI_OUTPUT_PREFIX,
            }
            for index, reference in enumerate(plan.references):
                filename = f"mg-{reference.content_sha256[:24]}.png"
                uploads.append(
                    _Upload(
                        filename=filename,
                        path=reference.path,
                        artifact_id=reference.artifact_id,
                        content_sha256=reference.content_sha256,
                        role=reference.role,
                    )
                )
                replacements[f"$artifact:{index}"] = filename
            source_node_id: str | None = None
            if candidate.recipe.schema_version == COMFYUI_RECIPE_SCHEMA_VERSION:
                try:
                    source_node_id = validate_comfyui_qwen_conditioning_graph(
                        operation.graph,
                        operation=operation.name,
                        output_node_id=candidate.recipe.output_node,
                        output_field=candidate.recipe.output_field,
                        expected_prompt="$prompt",
                        expected_width="$width",
                        expected_height="$height",
                        require_artifact_placeholder=True,
                        label="approved ComfyUI Qwen profile v2 workflow",
                    )
                except BackendEvidenceError as error:
                    raise BackendPreparationError(
                        "bundle_unverified",
                        "approved ComfyUI Qwen graph is invalid",
                    ) from error
            elif operation.name == "edit":
                try:
                    source_node_id = validate_comfyui_source_conditioning_path(
                        operation.graph,
                        output_node_id=candidate.recipe.output_node,
                        output_field=candidate.recipe.output_field,
                        require_artifact_placeholder=True,
                        label="approved ComfyUI edit workflow",
                    )
                except BackendEvidenceError as error:
                    raise BackendPreparationError(
                        "bundle_unverified",
                        "approved ComfyUI edit workflow has invalid source conditioning",
                    ) from error
            graph = _substitute(operation.graph, replacements)
            if not isinstance(graph, dict):
                _invalid("effective graph must be an object")
            if candidate.recipe.schema_version == COMFYUI_RECIPE_SCHEMA_VERSION:
                try:
                    validate_comfyui_qwen_conditioning_graph(
                        graph,
                        operation=operation.name,
                        output_node_id=candidate.recipe.output_node,
                        output_field=candidate.recipe.output_field,
                        expected_prompt=plan.resolved_prompt,
                        expected_width=plan.width,
                        expected_height=plan.height,
                        source_node_id=source_node_id,
                        label="effective ComfyUI Qwen profile v2 graph",
                    )
                except BackendEvidenceError as error:
                    raise BackendPreparationError(
                        "bundle_unverified",
                        "effective ComfyUI Qwen graph differs from its approved profile",
                    ) from error
            elif source_node_id is not None:
                try:
                    validate_comfyui_source_conditioning_path(
                        graph,
                        output_node_id=candidate.recipe.output_node,
                        output_field=candidate.recipe.output_field,
                        source_node_id=source_node_id,
                        label="effective ComfyUI edit workflow",
                    )
                except BackendEvidenceError as error:
                    raise BackendPreparationError(
                        "bundle_unverified",
                        "effective ComfyUI graph lost the approved source conditioning path",
                    ) from error
            used_classes = {
                str(node["class_type"])
                for node in graph.values()
                if isinstance(node, Mapping)
            }
            used_nodes = {name: candidate.recipe.nodes[name] for name in sorted(used_classes)}
            _verify_graph_model_bindings(graph, model_files)
            configuration = _effective_configuration(
                candidate,
                operation,
                plan,
                port=port,
                server=server_config,
                used_nodes=used_nodes,
                model_files=model_files,
            )
            configuration["engine"]["executable_path"] = str(executable)
            configuration["engine"]["runtime_fingerprint_sha256"] = digest(
                runtime_fingerprint
            )
            configuration["server"]["argv"] = list(argv)
            configuration["server"]["environment"] = dict(environment)
            prompt_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"media-generation:{plan.attempt_id}:comfyui"))
            body = {"prompt": graph, "prompt_id": prompt_id, "client_id": plan.attempt_id}
            body_bytes = json.dumps(
                body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
            effective = {
                "schema": EFFECTIVE_EXECUTION_SCHEMA,
                "schema_version": EFFECTIVE_EXECUTION_SCHEMA_VERSION,
                "api_format": "comfyui-api-prompt/v1",
                "prompt_id": prompt_id,
                "client_id": plan.attempt_id,
                "request_body": body,
                "request_body_sha256": digest(body),
                "graph": graph,
                "graph_sha256": digest(graph),
                "configuration": configuration,
                "configuration_sha256": digest(configuration),
            }
            privacy = comfyui_invocation_privacy_settings(argv, environment, effective)
            if any(value is not False for value in privacy.values()):
                raise BackendPreparationError(
                    "bundle_unverified", "ComfyUI effective privacy configuration is not local-only"
                )
            privacy_result = application_privacy_policy(self).evaluate(
                COMFYUI_ADAPTER_ID,
                {
                    "configuration_version": self.configuration["configuration_version"],
                    "privacy": privacy,
                },
            )
            if privacy_result.status is not PrivacyComplianceStatus.PASS:
                raise BackendPreparationError(
                    "bundle_unverified", "ComfyUI effective privacy configuration is not local-only"
                )
            privacy_evidence = comfyui_resolved_privacy_evidence(
                privacy_result,
                effective,
                configuration_version=self.configuration["configuration_version"],
            ).to_dict()
            record: dict[str, object] = {
                "schema": RESOLVED_SCHEMA,
                "schema_version": RESOLVED_RECORD_SCHEMA_VERSION,
                "attempt_id": plan.attempt_id,
                "backend_kind": COMFYUI_BACKEND_KIND,
                "candidate_id": candidate.candidate_id,
                "verification_id": candidate.verification_id,
                "declaration_sha256": candidate.declaration.declaration_sha256,
                "engine": {
                    key: configuration["engine"][key]
                    for key in ("id", "version", "build", "executable_sha256")
                },
                "recipe": {
                    "id": candidate.declaration.recipe.id,
                    "document_sha256": candidate.declaration.recipe.document.sha256,
                },
                "components": configuration["components"],
                "adapters": [adapter.to_dict() for adapter in candidate.declaration.adapters],
                "prompt": plan.resolved_prompt,
                "seed": plan.seed,
                "width": plan.width,
                "height": plan.height,
                "sampling": configuration["model_facing"]["sampling"],
                "conditioning": configuration["model_facing"]["conditioning"],
                "argv": list(argv),
                "environment": {
                    "names": sorted(environment),
                    "values": dict(environment),
                },
                "output_basename": COMFYUI_OUTPUT_BASENAME,
                "invocation_contract": COMFYUI_INVOCATION_CONTRACT,
                "cli_contract": COMFYUI_CLI_CONTRACT,
                "runtime": runtime_fingerprint,
                "privacy": privacy,
            "privacy_evidence": privacy_evidence,
                "verification_window": {
                    "verified_before_launch": True,
                    "engine_may_open_different_bytes_after_launch": True,
                    "statement": (
                        "Before launch, the application verified the signed runtime roots and bound the interpreter, source and "
                        "import paths, native library path, custom-node path, frontend, model search paths, and workflow pin. "
                        "This does not prove which bytes the operating system loads afterward, isolate network access, contain "
                        "descendants, or qualify APEX. The canonical POST /prompt body was persisted before dispatch."
                    ),
                },
                "effective_execution": effective,
            }
            resolved = ResolvedComfyUIExecution(
                attempt_id=plan.attempt_id,
                argv=argv,
                environment=environment,
                scratch_directory=scratch,
                output_path=scratch / COMFYUI_OUTPUT_BASENAME,
                resolved_record=record,
                request_body_bytes=body_bytes,
                prompt_id=prompt_id,
                uploads=tuple(uploads),
                width=plan.width,
                height=plan.height,
                side_effect_state=_ComfyUISideEffectState(),
            )
            with self._resolved_lock:
                if plan.attempt_id in self._resolved:
                    raise BackendPreparationError("operation_unsupported", "attempt already resolved")
                self._resolved[plan.attempt_id] = resolved
            return resolved
        except BaseException:
            shutil.rmtree(scratch, ignore_errors=True)
            raise

    def execute(
        self,
        plan: GenerationPlan,
        destination: BinaryIO,
        *,
        supervisor: ProcessSupervisor,
    ) -> ImageMetadata:
        if not isinstance(plan, GenerationPlan):
            raise ValueError("plan must be a GenerationPlan")
        if not isinstance(supervisor, ProcessSupervisor):
            raise TypeError("supervisor must be a ProcessSupervisor")
        with self._resolved_lock:
            resolved = self._resolved.pop(plan.attempt_id, None)
        if resolved is None:
            raise GenerationError("backend execution has no resolved ComfyUI plan")
        if supervisor.attempt_id != resolved.attempt_id:
            self._remove_scratch(resolved.scratch_directory)
            raise GenerationError("supervisor is bound to a different execution attempt")
        try:
            approval = _load_runtime_pin_approval()
            candidate = load_comfyui_candidate(
                self._candidate_path,
                self._trusted_evidence_path,
                approved_tool_version=approval.tool_version,
            )
            _require_independent_runtime_pin_binding(candidate, approval)
            if (
                approval.manifest_sha256 != self._runtime_approval.manifest_sha256
                or approval.public_key_sha256 != self._runtime_approval.public_key_sha256
            ):
                raise BackendPreparationError(
                    "bundle_corrupt", "ComfyUI runtime approval changed before dispatch"
                )
            if candidate.candidate_id != self._candidate.candidate_id:
                raise BackendPreparationError(
                    "bundle_corrupt", "ComfyUI candidate changed before launch"
                )
            effective = resolved.resolved_record.get("effective_execution")
            configuration = (
                effective.get("configuration") if isinstance(effective, Mapping) else None
            )
            server_configuration = (
                configuration.get("server") if isinstance(configuration, Mapping) else None
            )
            model_files = (
                configuration.get("model_files") if isinstance(configuration, Mapping) else None
            )
            if (
                not isinstance(server_configuration, Mapping)
                or not isinstance(model_files, list)
                or server_configuration.get("argv") != list(resolved.argv)
                or server_configuration.get("environment") != dict(resolved.environment)
                or not isinstance(server_configuration.get("models_directory"), str)
            ):
                raise BackendPreparationError(
                    "bundle_corrupt", "ComfyUI child launch inputs changed after resolution"
                )
            _require_runtime_launch_binding(
                candidate,
                approval,
                argv=resolved.argv,
                environment=resolved.environment,
                models_directory=Path(server_configuration["models_directory"]),
                model_files=model_files,
            )
            self._verify_frontend_root(resolved)
            supervisor.run_managed(
                resolved.argv,
                env=resolved.environment,
                cwd=resolved.scratch_directory,
                session=lambda control: self._run_http_session(control, resolved),
                shutdown_timeout_seconds=candidate.recipe.server.shutdown_timeout_seconds,
                listener_owner_pid=_listener_owner_pid,
            )
            return self._stream_execution(resolved, destination)
        finally:
            self._remove_scratch(resolved.scratch_directory)

    def _run_http_session(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> None:
        self._wait_ready(control, resolved)
        self._verify_frontend_root(resolved)
        self._verify_node_replacements(control, resolved)
        for upload in resolved.uploads:
            self._verify_node_replacements(control, resolved)
            self._upload_reference(control, resolved, upload)
        self._verify_frontend_root(resolved)
        self._verify_node_replacements(control, resolved)
        accepted = self._submit_once(control, resolved)
        if not accepted:
            self._reconcile_acceptance(control, resolved)
        entry = self._wait_for_completion(
            control, resolved, resolved.prompt_id
        )
        try:
            self._retrieve_output(control, resolved, entry)
        except AmbiguousBackendOutcome:
            raise
        except BackendEvidenceError as error:
            raise AmbiguousBackendOutcome(
                "ComfyUI output identity or retrieval became uncertain after prompt acceptance"
            ) from error

    @staticmethod
    def _verify_frontend_root(resolved: ResolvedComfyUIExecution) -> None:
        try:
            effective = resolved.resolved_record["effective_execution"]
            configuration = effective["configuration"]
            server = configuration["server"]
            root = Path(server["frontend_root"])
            expected = server["frontend_root_sha256"]
            actual = _frontend_tree_sha256(root)
        except (KeyError, TypeError, OSError, BackendPreparationError) as error:
            raise BackendEvidenceError(
                "ComfyUI pinned frontend root cannot be verified"
            ) from error
        if actual != expected:
            raise BackendEvidenceError(
                "ComfyUI frontend bytes changed after admission"
            )

    def _connection(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        timeout: float,
    ) -> http.client.HTTPConnection:
        self._require_owned_listener(control, resolved)
        server = self._candidate.recipe.server
        connection = http.client.HTTPConnection(
            server.host,
            int(resolved.argv[resolved.argv.index("--port") + 1]),
            timeout=timeout,
        )
        connection.connect()
        self._require_owned_listener(control, resolved)
        return connection

    def _require_owned_listener(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> None:
        port = int(resolved.argv[resolved.argv.index("--port") + 1])
        control.require_listener_owner(self._candidate.recipe.server.host, port)

    def _require_request_authority(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> None:
        try:
            control.require_current()
            if not control.is_running():
                raise BackendEvidenceError("ComfyUI direct child exited during HTTP execution")
            self._require_owned_listener(control, resolved)
        except AmbiguousBackendOutcome:
            raise
        except BackendEvidenceError as error:
            if resolved.side_effect_state.may_have_been_accepted:
                raise AmbiguousBackendOutcome(
                    "ComfyUI attempt authority, child, or listener proof was lost after a side-effect request"
                ) from error
            raise

    def _request_owned(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        connection: http.client.HTTPConnection,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> http.client.HTTPResponse:
        self._require_request_authority(control, resolved)
        if method == "POST":
            resolved.side_effect_state.may_have_been_accepted = True
        try:
            connection.request(method, path, body=body, headers=dict(headers or {}))
            self._require_request_authority(control, resolved)
            response = connection.getresponse()
            self._require_request_authority(control, resolved)
            return response
        except AmbiguousBackendOutcome:
            raise
        except BackendEvidenceError as error:
            if resolved.side_effect_state.may_have_been_accepted:
                raise AmbiguousBackendOutcome(
                    "ComfyUI control evidence was lost after request bytes may have been sent"
                ) from error
            raise

    def _get_json(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        path: str,
        *,
        timeout: float | None = None,
    ) -> tuple[int, object]:
        connection = self._connection(
            control,
            resolved,
            min(
                self._candidate.recipe.api.request_timeout_seconds,
                timeout if timeout is not None else float("inf"),
            ),
        )
        try:
            response = self._request_owned(
                control,
                resolved,
                connection,
                "GET",
                path,
                headers={"Accept": "application/json", "Connection": "close"},
            )
            payload = response.read(COMFYUI_MAX_RECIPE_BYTES + 1)
            self._require_request_authority(control, resolved)
            if len(payload) > COMFYUI_MAX_RECIPE_BYTES:
                raise BackendEvidenceError("ComfyUI JSON response is oversized")
            if not payload:
                return response.status, None
            return response.status, json.loads(payload.decode("utf-8"))
        except AmbiguousBackendOutcome:
            raise
        except (
            OSError,
            TimeoutError,
            http.client.HTTPException,
            UnicodeError,
            ValueError,
            RecursionError,
        ) as error:
            if resolved.side_effect_state.may_have_been_accepted:
                raise AmbiguousBackendOutcome(
                    "ComfyUI response was unavailable or malformed after a side-effect request"
                ) from error
            raise BackendEvidenceError("ComfyUI HTTP response was unavailable or malformed") from error
        finally:
            connection.close()

    def _verify_node_replacements(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> None:
        status, payload = self._get_json(
            control,
            resolved,
            self._candidate.recipe.api.node_replacements_path,
        )
        if status != 200 or not isinstance(payload, Mapping) or payload:
            raise BackendEvidenceError(
                "ComfyUI node replacement state is unavailable or nonempty"
            )

    def _wait_ready(self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution) -> None:
        deadline = time.monotonic() + self._candidate.recipe.api.readiness_timeout_seconds
        last_error: BackendEvidenceError | None = None
        while time.monotonic() < deadline:
            control.require_current()
            if not control.is_running():
                raise BackendEvidenceError("ComfyUI exited before readiness")
            try:
                status, payload = self._get_json(control, resolved, self._candidate.recipe.server.readiness_path)
            except BackendEvidenceError as error:
                last_error = error
                time.sleep(0.05)
                continue
            if status == 200:
                identity = _json_path(payload, self._candidate.recipe.server.identity_path)
                if identity != self._candidate.recipe.server.identity_value:
                    raise BackendEvidenceError("loopback server identity does not match the T07 pin")
                expected_frontend = resolved.resolved_record[
                    "effective_execution"
                ]["configuration"]["server"]["frontend_root"]
                system = payload.get("system") if isinstance(payload, Mapping) else None
                if isinstance(system, Mapping) and "web_root" in system:
                    if system["web_root"] != expected_frontend:
                        raise BackendEvidenceError(
                            "ComfyUI frontend root does not match the independently hashed local root"
                        )
                return
            time.sleep(0.05)
        message = "ComfyUI readiness timed out"
        if last_error is not None:
            detail = f"{type(last_error).__name__}: {last_error}"
            if len(detail) > 300:
                detail = f"{detail[:297]}..."
            message = f"{message}; last probe failure: {detail}"
        raise BackendEvidenceError(message) from last_error

    def _upload_reference(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        upload: _Upload,
    ) -> None:
        try:
            with open_regular(upload.path) as stream:
                data = stream.read(COMFYUI_APP_MAX_REFERENCE_UPLOAD_BYTES + 1)
        except OSError as error:
            raise BackendEvidenceError("ComfyUI reference input cannot be read") from error
        if len(data) > COMFYUI_APP_MAX_REFERENCE_UPLOAD_BYTES:
            raise BackendEvidenceError("ComfyUI reference input is oversized")
        if hashlib.sha256(data).hexdigest() != upload.content_sha256:
            raise BackendEvidenceError("ComfyUI reference input changed before upload")
        boundary = f"media-generation-{resolved.prompt_id}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="image"; filename="{upload.filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + data + (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="overwrite"\r\n\r\n'
            "true"
            f"\r\n--{boundary}--\r\n"
        ).encode("utf-8")
        connection = self._connection(
            control, resolved, self._candidate.recipe.api.request_timeout_seconds
        )
        try:
            response = self._request_owned(
                control,
                resolved,
                connection,
                "POST",
                self._candidate.recipe.api.upload_path,
                body=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                    "Connection": "close",
                },
            )
            payload = response.read(COMFYUI_MAX_RECIPE_BYTES + 1)
            self._require_request_authority(control, resolved)
            if response.status != 200 or len(payload) > COMFYUI_MAX_RECIPE_BYTES:
                raise BackendEvidenceError("ComfyUI reference upload failed")
            result = json.loads(payload.decode("utf-8"))
            if not isinstance(result, Mapping) or result.get("name") != upload.filename:
                raise BackendEvidenceError("ComfyUI changed the exact uploaded filename")
        except (OSError, TimeoutError, http.client.HTTPException, UnicodeError, ValueError) as error:
            raise BackendEvidenceError("ComfyUI reference upload outcome is unavailable") from error
        finally:
            connection.close()

    def _submit_once(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> bool:
        connection = self._connection(
            control, resolved, self._candidate.recipe.api.request_timeout_seconds
        )
        try:
            self._reverify_runtime_before_prompt(resolved)
            response = self._request_owned(
                control,
                resolved,
                connection,
                "POST",
                self._candidate.recipe.api.prompt_path,
                body=resolved.request_body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(resolved.request_body_bytes)),
                    "Connection": "close",
                },
            )
            payload = response.read(COMFYUI_MAX_RECIPE_BYTES + 1)
            self._require_request_authority(control, resolved)
            if response.status != 200 or len(payload) > COMFYUI_MAX_RECIPE_BYTES:
                return False
            result = json.loads(payload.decode("utf-8"))
            self._require_request_authority(control, resolved)
            if not isinstance(result, Mapping):
                return False
            response_prompt_id = result.get("prompt_id")
            if response_prompt_id != resolved.prompt_id:
                raise AmbiguousBackendOutcome(
                    "ComfyUI accepted a different prompt identity than the attempt-bound ID"
                )
            errors = result.get("node_errors")
            if errors not in (None, {}):
                raise AmbiguousBackendOutcome(
                    "ComfyUI returned node errors after assigning the attempt-bound prompt ID"
                )
            return True
        except AmbiguousBackendOutcome:
            raise
        except BackendEvidenceError as error:
            if resolved.side_effect_state.may_have_been_accepted:
                raise AmbiguousBackendOutcome(
                    "ComfyUI authority or listener proof was lost after prompt submission"
                ) from error
            raise
        except (
            OSError,
            TimeoutError,
            http.client.HTTPException,
            UnicodeError,
            ValueError,
            RecursionError,
        ):
            return False
        finally:
            connection.close()

    def _reverify_runtime_before_prompt(
        self, resolved: ResolvedComfyUIExecution
    ) -> None:
        """Recheck signed runtime bytes and launch bindings before prompt dispatch."""

        approval = _load_runtime_pin_approval()
        candidate = load_comfyui_candidate(
            self._candidate_path,
            self._trusted_evidence_path,
            approved_tool_version=approval.tool_version,
        )
        _require_independent_runtime_pin_binding(candidate, approval)
        if (
            approval.manifest_sha256 != self._runtime_approval.manifest_sha256
            or approval.public_key_sha256 != self._runtime_approval.public_key_sha256
        ):
            raise BackendPreparationError(
                "bundle_corrupt", "ComfyUI runtime approval changed before prompt dispatch"
            )
        if candidate.candidate_id != self._candidate.candidate_id:
            raise BackendPreparationError(
                "bundle_corrupt", "ComfyUI candidate changed before prompt dispatch"
            )

        effective = resolved.resolved_record.get("effective_execution")
        configuration = (
            effective.get("configuration") if isinstance(effective, Mapping) else None
        )
        server_configuration = (
            configuration.get("server") if isinstance(configuration, Mapping) else None
        )
        model_files = (
            configuration.get("model_files") if isinstance(configuration, Mapping) else None
        )
        if (
            not isinstance(server_configuration, Mapping)
            or not isinstance(model_files, list)
            or server_configuration.get("argv") != list(resolved.argv)
            or server_configuration.get("environment") != dict(resolved.environment)
            or not isinstance(server_configuration.get("models_directory"), str)
        ):
            raise BackendPreparationError(
                "bundle_corrupt", "ComfyUI child launch inputs changed before prompt dispatch"
            )
        _require_runtime_launch_binding(
            candidate,
            approval,
            argv=resolved.argv,
            environment=resolved.environment,
            models_directory=Path(server_configuration["models_directory"]),
            model_files=model_files,
        )

    def _history(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        prompt_id: str,
    ) -> tuple[int, object]:
        path = self._candidate.recipe.api.history_path.format(prompt_id=prompt_id)
        return self._get_json(control, resolved, path)

    def _known_history_entry(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        prompt_id: str,
        *,
        timeout: float | None = None,
    ) -> Mapping[str, object] | None:
        path = self._candidate.recipe.api.history_path.format(prompt_id=prompt_id)
        status, payload = self._get_json(control, resolved, path, timeout=timeout)
        if status != 200 or not isinstance(payload, Mapping):
            return None
        entry = payload.get(prompt_id)
        return entry if isinstance(entry, Mapping) else None

    def _reconcile_acceptance(
        self, control: ManagedProcessControl, resolved: ResolvedComfyUIExecution
    ) -> None:
        """Observe bounded positive evidence for one possibly accepted POST.

        A 404, empty queue, absent history row, or malformed observation does
        not prove rejection. This method never resubmits the persisted body.
        """
        deadline = time.monotonic() + self._candidate.recipe.api.poll_timeout_seconds
        while time.monotonic() < deadline:
            if not control.is_running():
                break
            try:
                remaining = deadline - time.monotonic()
                if self._jobs_contain_prompt(control, resolved, remaining):
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self._queue_contains_prompt(control, resolved, remaining):
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if self._known_history_entry(
                    control, resolved, resolved.prompt_id, timeout=remaining
                ) is not None:
                    return
            except AmbiguousBackendOutcome:
                raise
            except BackendEvidenceError:
                # Transient and malformed responses have no negative meaning.
                pass
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        raise AmbiguousBackendOutcome(
            "ComfyUI POST /prompt acceptance remains unknown; the owned child will be terminated"
        )

    def _jobs_contain_prompt(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        timeout: float,
    ) -> bool:
        status, payload = self._get_json(
            control,
            resolved,
            self._candidate.recipe.api.jobs_path,
            timeout=timeout,
        )
        if status != 200 or not isinstance(payload, Mapping):
            return False
        jobs = payload.get("jobs")
        if not isinstance(jobs, list) or len(jobs) > 1000:
            return False
        for job in jobs:
            if not isinstance(job, Mapping):
                return False
            if job.get("id", job.get("prompt_id")) == resolved.prompt_id:
                return True
        return False

    def _queue_contains_prompt(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        timeout: float,
    ) -> bool:
        status, payload = self._get_json(
            control,
            resolved,
            self._candidate.recipe.api.queue_path,
            timeout=timeout,
        )
        if status != 200 or not isinstance(payload, Mapping):
            return False
        for key in ("queue_running", "queue_pending"):
            rows = payload.get(key)
            if not isinstance(rows, list) or len(rows) > 1000:
                return False
            for row in rows:
                if not isinstance(row, list) or len(row) < 2 or not isinstance(row[1], str):
                    return False
                if row[1] == resolved.prompt_id:
                    return True
        return False

    def _wait_for_completion(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        prompt_id: str,
    ) -> Mapping[str, object]:
        deadline = time.monotonic() + self._candidate.recipe.api.poll_timeout_seconds
        while time.monotonic() < deadline:
            self._require_request_authority(control, resolved)
            try:
                entry = self._known_history_entry(control, resolved, prompt_id)
            except BackendEvidenceError as error:
                raise AmbiguousBackendOutcome(
                    "ComfyUI history response is unavailable or malformed"
                ) from error
            if entry is not None:
                status = entry.get("status")
                if not isinstance(status, Mapping):
                    raise AmbiguousBackendOutcome(
                        "ComfyUI history entry has no valid completion status"
                    )
                status_text = status.get("status_str")
                completed = status.get("completed")
                if status_text == "error" and completed is True:
                    raise GenerationError("ComfyUI workflow reported an execution error")
                if status_text == "success" and completed is True:
                    return entry
                if completed is False and status_text in {"success", "running", "pending"}:
                    time.sleep(0.05)
                    continue
                raise AmbiguousBackendOutcome(
                    "ComfyUI history entry has an unsupported completion identity"
                )
            time.sleep(0.05)
        raise AmbiguousBackendOutcome("ComfyUI completion timed out; the owned child will be terminated")

    def _retrieve_output(
        self,
        control: ManagedProcessControl,
        resolved: ResolvedComfyUIExecution,
        entry: Mapping[str, object],
    ) -> None:
        outputs = entry.get("outputs")
        if not isinstance(outputs, Mapping):
            raise BackendEvidenceError("ComfyUI history has no outputs")
        node = outputs.get(self._candidate.recipe.output_node)
        if not isinstance(node, Mapping):
            raise BackendEvidenceError("ComfyUI output node is absent from history")
        images = node.get(self._candidate.recipe.output_field)
        if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], Mapping):
            raise BackendEvidenceError("ComfyUI output node has an invalid image result")
        image = images[0]
        if set(image) != {"filename", "subfolder", "type"}:
            raise BackendEvidenceError("ComfyUI output identity has unexpected fields")
        filename = image.get("filename")
        subfolder = image.get("subfolder")
        kind = image.get("type")
        if (
            not isinstance(filename, str)
            or not _SAFE_OUTPUT_NAME.fullmatch(filename)
            or filename in {".", ".."}
            or not isinstance(subfolder, str)
            or (subfolder and not _SAFE_OUTPUT_NAME.fullmatch(subfolder))
            or subfolder in {".", ".."}
            or kind != "output"
        ):
            raise BackendEvidenceError("ComfyUI output identity is unsafe")
        query = urllib.parse.urlencode({"filename": filename, "subfolder": subfolder, "type": kind})
        connection = self._connection(
            control, resolved, self._candidate.recipe.api.request_timeout_seconds
        )
        try:
            response = self._request_owned(
                control,
                resolved,
                connection,
                "GET",
                f"{self._candidate.recipe.api.view_path}?{query}",
                headers={"Accept": "image/png,image/jpeg", "Connection": "close"},
            )
            data = response.read(self._candidate.recipe.api.max_output_bytes + 1)
            self._require_request_authority(control, resolved)
            if response.status != 200 or not data or len(data) > self._candidate.recipe.api.max_output_bytes:
                raise BackendEvidenceError("ComfyUI output retrieval is invalid or oversized")
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise BackendEvidenceError("ComfyUI output retrieval failed") from error
        finally:
            connection.close()
        descriptor = os.open(
            resolved.output_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def _stream_execution(
        self, resolved: ResolvedComfyUIExecution, destination: BinaryIO
    ) -> ImageMetadata:
        with open_regular(resolved.output_path) as source:
            info = validate_image(source)
            if (info.width, info.height) != (resolved.width, resolved.height):
                raise GenerationError("ComfyUI output dimensions do not match the request")
            source.seek(0)
            destination.seek(0)
            while chunk := source.read(1024 * 1024):
                destination.write(chunk)
            destination.truncate()
            destination.seek(0)
        return ImageMetadata(info.media_type, info.image_format, info.width, info.height)

    @staticmethod
    def _remove_scratch(path: Path) -> None:
        shutil.rmtree(path, ignore_errors=True)

    def cleanup_execution(self, prepared: object) -> None:
        scratch = getattr(prepared, "scratch_directory", None)
        if isinstance(scratch, Path):
            self._remove_scratch(scratch)
