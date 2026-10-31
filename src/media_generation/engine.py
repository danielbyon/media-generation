"""Opt-in local inference engine selected by one declared T07 candidate.

The adapter in this module executes a pinned stable-diffusion.cpp build. It
loads and statically re-verifies an operator-selected candidate before any
work is claimed, maps engine-neutral generation intent onto the documented
command line, and records the exact pre-dispatch plan. Process supervision and
evidence persistence remain application-owned; the engine never reports its
own compliance, launch, or termination facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
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
from ._candidate_evaluation import (
    CandidateEvaluation,
    _declares_qwen_image_edit_2511,
    evaluate_candidate,
)
from .adapters import (
    BACKEND_EXECUTION_CONTRACT_VERSION,
    AdapterCapabilities,
    ImageMetadata,
)
from .backend_provenance import (
    RECORDED_ENVIRONMENT_VALUES,
    RECORD_SCHEMA_VERSION,
    RESOLVED_SCHEMA,
    capture_runtime_fingerprint,
    environment_record,
)
from .candidate import (
    CandidateValidationError,
    TrustedEvidence,
    parse_candidate,
    parse_trusted_evidence,
)
from .domain import GenerationPlan
from .errors import BackendPreparationError, GenerationError, InputValidationError
from .images import copy_source, open_regular, validate_image
from .privacy import (
    LOCAL_INFERENCE_CONFIGURATION_VERSION,
    invocation_privacy_settings,
)
from .supervisor import ProcessSupervisor

ADAPTER_ID = "stable-diffusion-cpp-local-v1"
BACKEND_KIND = "local-inference"
INVOCATION_CONTRACT = "sd-cpp-exec-v1"
SUPPORTED_ENGINE_ID = "stable-diffusion.cpp"
RECIPE_SCHEMA = "media-generation.sd-cpp-recipe"
RECIPE_SCHEMA_VERSION = 1
CLI_CONTRACT_FLAG = "sd_cpp_cli_contract"
CLI_CONTRACTS = frozenset({"bare-flag/v1", "model-args/v1"})
ZERO_CONDITIONING_FLAG = "qwen_image_zero_cond_t"
MAX_MODEL_ARGS = 8
OUTPUT_BASENAME = "output.png"
VERIFICATION_WINDOW_STATEMENT = (
    "The application hashed every pinned executable, declared component, "
    "recipe, and evidence file before launch. The engine opens those paths "
    "itself after launch and may observe different bytes, so this record does "
    "not claim the engine loaded the hashed bytes."
)
HASH_CHUNK_BYTES = 1024 * 1024
MAX_RECIPE_BYTES = 1024 * 1024
APP_MIN_DIMENSION = 64
APP_MAX_DIMENSION = 2048
APP_DIMENSION_MULTIPLE = 8
APP_MAX_REFERENCES = 3
APP_MAX_SOURCE_IMAGES = 1


SAMPLING_METHODS = frozenset(
    {
        "euler",
        "euler_a",
        "heun",
        "dpm2",
        "dpm++2s_a",
        "dpm++2m",
        "dpm++2mv2",
        "ipndm",
        "ipndm_v",
        "lcm",
        "ddim_trailing",
        "tcd",
        "res_multistep",
        "res_2s",
        "er_sde",
        "euler_cfg_pp",
        "euler_a_cfg_pp",
        "euler_ge",
        "dpm++2m_sde",
        "dpm++2m_sde_bt",
        "lms",
    }
)

ROLE_ARGUMENTS = {
    "diffusion_model": "--diffusion-model",
    "vae": "--vae",
    "text_encoder": "--llm",
    "vision_encoder": "--llm_vision",
}

# Version-specific model profiles bind the declared identity to the exact
# component roles the documented invocation can pass. Every declared role must
# appear in ``mapped_roles``; every operation must require ``required_roles``.
MODEL_ROLE_PROFILES = {
    "qwen_image_edit_2511": {
        "required_roles": frozenset({"diffusion_model", "vae", "text_encoder"}),
        "mapped_roles": frozenset(
            {"diffusion_model", "vae", "text_encoder", "vision_encoder"}
        ),
    },
}

ENVIRONMENT_ALLOWLIST = (
    "HIP_VISIBLE_DEVICES",
    "HSA_OVERRIDE_GFX_VERSION",
    "LD_LIBRARY_PATH",
    "PATH",
    "ROCM_PATH",
)

_MODEL_ARGUMENT = re.compile(r"^([a-z0-9_]{1,64})=([a-z0-9_.-]{1,32})$")


@dataclass(frozen=True, slots=True)
class SamplingSettings:
    """Effective sampling values recorded for one operation profile."""

    sampling_method: str
    steps: int
    cfg_scale: float
    flow_shift: float
    strength: float | None


@dataclass(frozen=True, slots=True)
class OperationProfile:
    """Declared invocation settings for one supported operation."""

    required_roles: tuple[str, ...]
    model_args: tuple[str, ...]
    sampling: SamplingSettings


@dataclass(frozen=True, slots=True)
class RecipePlan:
    """Strictly validated invocation section of one recipe document."""

    id: str
    operations: Mapping[str, OperationProfile]
    max_width: int
    max_height: int
    max_references: int
    max_source_images: int


@dataclass(frozen=True, slots=True)
class EngineCandidate:
    """One parsed declared candidate and its invocable recipe contract."""

    declaration: CandidateDeclaration
    recipe: RecipePlan
    cli_contract: str
    candidate_id: str
    trusted_evidence: tuple[TrustedEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class ResolvedExecution:
    """An immutable pre-dispatch plan plus its private scratch location."""

    attempt_id: str
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    scratch_directory: Path
    output_path: Path
    resolved_record: Mapping[str, object]
    width: int
    height: int


def _invalid(detail: str) -> None:
    """Raise the stable recipe refusal used for malformed invocation data."""
    raise BackendPreparationError("recipe_invalid", detail)


def _exact_keys(
    value: Mapping[str, object], expected: set[str], *, label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        _invalid(f"{label} has invalid fields: {'; '.join(details)}")


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _invalid(f"{label} must be an object")
    return value


def _list(value: object, *, label: str) -> list[object]:
    if not isinstance(value, list):
        _invalid(f"{label} must be an array")
    return value


def _integer(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _invalid(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        _invalid(f"{label} must be between {minimum} and {maximum}")
    return value


def _number(
    value: object, *, label: str, minimum: float, maximum: float
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid(f"{label} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        _invalid(f"{label} must be between {minimum} and {maximum}")
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _strict_json(data: bytes, *, label: str) -> object:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError) as error:
        _invalid(f"{label} is not strict JSON: {error}")


def _read_recipe_document(declaration: CandidateDeclaration) -> bytes:
    """Read and re-pin the declared recipe bytes through a no-follow handle."""
    pin = declaration.recipe.document
    path = pin.resolved_path(declaration.root_index)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as error:
        raise BackendPreparationError("bundle_missing", str(error)) from error
    except OSError as error:
        raise BackendPreparationError("bundle_corrupt", str(error)) from error
    with os.fdopen(descriptor, "rb") as handle:
        observed = os.fstat(handle.fileno())
        if not stat.S_ISREG(observed.st_mode) or observed.st_size != pin.size_bytes:
            raise BackendPreparationError("bundle_corrupt", "recipe document pin mismatch")
        if pin.size_bytes > MAX_RECIPE_BYTES:
            raise BackendPreparationError("bundle_corrupt", "recipe document is too large")
        data = handle.read(pin.size_bytes + 1)
    if len(data) != pin.size_bytes or hashlib.sha256(data).hexdigest() != pin.sha256:
        raise BackendPreparationError("bundle_corrupt", "recipe document pin mismatch")
    return data


def _parse_model_args(value: object, *, label: str) -> tuple[str, ...]:
    items = _list(value, label=label)
    if len(items) > MAX_MODEL_ARGS:
        _invalid(f"{label} may contain at most {MAX_MODEL_ARGS} entries")
    parsed: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, str):
            _invalid(f"{label}[{index}] must be a key=value string")
        match = _MODEL_ARGUMENT.fullmatch(item)
        if match is None:
            _invalid(f"{label}[{index}] is not a key=value string")
        key, raw_value = match.groups()
        if key not in {ZERO_CONDITIONING_FLAG}:
            _invalid(f"{label}[{index}] uses an unsupported model argument")
        if raw_value not in {"true", "false"}:
            _invalid(f"{label}[{index}] must be true or false")
        if key in seen:
            _invalid(f"{label} repeats the {key} key")
        seen.add(key)
        parsed.append(f"{key}={raw_value}")
    return tuple(parsed)


def _parse_sampling(value: object, *, label: str) -> SamplingSettings:
    item = _mapping(value, label=label)
    _exact_keys(
        item,
        {"sampling_method", "steps", "cfg_scale", "flow_shift", "strength"},
        label=label,
    )
    method = item["sampling_method"]
    if not isinstance(method, str) or method not in SAMPLING_METHODS:
        _invalid(f"{label}.sampling_method is not a documented sampling method")
    strength = item["strength"]
    if strength is not None:
        strength = _number(
            strength, label=f"{label}.strength", minimum=0.05, maximum=1.0
        )
    return SamplingSettings(
        sampling_method=method,
        steps=_integer(item["steps"], label=f"{label}.steps", minimum=1, maximum=50),
        cfg_scale=_number(
            item["cfg_scale"], label=f"{label}.cfg_scale", minimum=0.0, maximum=15.0
        ),
        flow_shift=_number(
            item["flow_shift"], label=f"{label}.flow_shift", minimum=0.0, maximum=10.0
        ),
        strength=strength,
    )


def _parse_operation(
    name: str, value: object, *, declaration: CandidateDeclaration
) -> OperationProfile:
    label = f"recipe.operations.{name}"
    item = _mapping(value, label=label)
    _exact_keys(
        item, {"required_component_roles", "model_args", "sampling"}, label=label
    )
    roles_value = _list(item["required_component_roles"], label=f"{label}.required_component_roles")
    roles: list[str] = []
    for index, role in enumerate(roles_value):
        if not isinstance(role, str) or role not in COMPONENT_ROLES:
            _invalid(f"{label}.required_component_roles[{index}] is not a component role")
        if role not in ROLE_ARGUMENTS:
            _invalid(f"{label} requires a role the invocation contract cannot pass")
        if role in roles:
            _invalid(f"{label}.required_component_roles repeats {role}")
        roles.append(role)
    if not roles:
        _invalid(f"{label}.required_component_roles must not be empty")
    declared_roles = {component.role for component in declaration.components}
    missing = sorted(set(roles) - declared_roles)
    if missing:
        raise BackendPreparationError(
            "bundle_incompatible",
            f"{label} requires undeclared component roles: {', '.join(missing)}",
        )
    sampling = _parse_sampling(item["sampling"], label=f"{label}.sampling")
    return OperationProfile(
        required_roles=tuple(roles),
        model_args=_parse_model_args(item["model_args"], label=f"{label}.model_args"),
        sampling=sampling,
    )


_BACKEND_FLAG = "backend"
_ROCM_BACKEND = "rocm"
_GENERATE_OPERATION = "generate"
_EDIT_OPERATION = "edit"
_GIT_MARKER = ".git"
_SCRATCH_PREFIX = "media-generation-engine-"
_RECORDED_ENVIRONMENT_VALUES = RECORDED_ENVIRONMENT_VALUES


def _parse_limits(value: object) -> tuple[int, int, int]:
    """Validate the bounded dimensions and reference count of one recipe."""
    item = _mapping(value, label="recipe.limits")
    _exact_keys(
        item,
        {"max_width", "max_height", "max_references", "max_source_images"},
        label="recipe.limits",
    )
    return (
        _integer(item["max_width"], label="recipe.limits.max_width", minimum=1, maximum=16384),
        _integer(item["max_height"], label="recipe.limits.max_height", minimum=1, maximum=16384),
        _integer(item["max_references"], label="recipe.limits.max_references", minimum=0, maximum=3),
        _integer(
            item["max_source_images"],
            label="recipe.limits.max_source_images",
            minimum=0,
            maximum=1,
        ),
    )


def _parse_recipe(data: bytes, *, declaration: CandidateDeclaration) -> RecipePlan:
    """Parse the pinned recipe document into one immutable invocation plan."""
    value = _strict_json(data, label="recipe document")
    item = _mapping(value, label="recipe document")
    _exact_keys(
        item,
        {"schema", "schema_version", "id", "engine_id", "operations", "limits"},
        label="recipe document",
    )
    if item["schema"] != RECIPE_SCHEMA or item["schema_version"] != RECIPE_SCHEMA_VERSION:
        _invalid("recipe document has an unsupported schema")
    recipe_id = item["id"]
    if not isinstance(recipe_id, str) or not recipe_id:
        _invalid("recipe document id must be a non-empty string")
    if recipe_id != declaration.recipe.id:
        _invalid("recipe document id does not match the declared recipe")
    if item["engine_id"] != declaration.engine.id:
        _invalid("recipe document engine_id does not match the declared engine")
    operations_value = _mapping(item["operations"], label="recipe.operations")
    if not operations_value:
        _invalid("recipe.operations must not be empty")
    operations: dict[str, OperationProfile] = {}
    for name in sorted(operations_value):
        if name not in {_GENERATE_OPERATION, _EDIT_OPERATION}:
            _invalid("recipe.operations contains an unsupported operation")
        operations[name] = _parse_operation(
            name, operations_value[name], declaration=declaration
        )
    _validate_model_role_profile(declaration, operations)
    max_width, max_height, max_references, max_source_images = _parse_limits(
        item["limits"]
    )
    return RecipePlan(
        id=recipe_id,
        operations=MappingProxyType(operations),
        max_width=max_width,
        max_height=max_height,
        max_references=max_references,
        max_source_images=max_source_images,
    )


def _validate_model_role_profile(
    declaration: CandidateDeclaration,
    operations: Mapping[str, OperationProfile],
) -> None:
    """Enforce the exact component-role set for one version-specific model.

    A declared component role outside the profile's mapped set cannot be passed
    by the documented argument vector, so it is refused instead of being
    silently ignored. If the candidate declares a vision encoder, the edit
    operation must require it so the invocation includes ``--llm_vision``.
    """
    if not _declares_qwen_image_edit_2511(declaration):
        return
    profile = MODEL_ROLE_PROFILES["qwen_image_edit_2511"]
    mapped_roles = profile["mapped_roles"]
    required_roles = profile["required_roles"]
    declared_roles = {component.role for component in declaration.components}
    unmapped = sorted(declared_roles - mapped_roles)
    if unmapped:
        raise BackendPreparationError(
            "bundle_incompatible",
            "qwen_image_edit_2511 declares component roles the invocation "
            f"profile does not map: {', '.join(unmapped)}",
        )
    for name, operation in operations.items():
        operation_roles = set(operation.required_roles)
        missing = sorted(required_roles - operation_roles)
        if missing:
            raise BackendPreparationError(
                "bundle_incompatible",
                f"qwen_image_edit_2511 operation {name} omits required "
                f"component roles: {', '.join(missing)}",
            )
        if (
            name == _EDIT_OPERATION
            and "vision_encoder" in declared_roles
            and "vision_encoder" not in operation_roles
        ):
            raise BackendPreparationError(
                "bundle_incompatible",
                "qwen_image_edit_2511 declares a vision encoder that the edit "
                "operation must pass as --llm_vision",
            )


def _cli_contract(declaration: CandidateDeclaration) -> str:
    """Return the operator-declared stable-diffusion.cpp syntax generation.

    The zero-conditioning flag changed spelling between upstream builds. The
    engine and recipe must both name the same documented generation; this
    adapter never probes a binary and never guesses which form it supports.
    """
    engine_value = dict(declaration.engine.architecture_flags).get(CLI_CONTRACT_FLAG)
    recipe_value = dict(declaration.recipe.architecture_flags).get(CLI_CONTRACT_FLAG)
    if engine_value is None or recipe_value is None:
        _invalid(
            f"engine and recipe architecture_flags must both declare {CLI_CONTRACT_FLAG}"
        )
    if not isinstance(engine_value, str) or engine_value not in CLI_CONTRACTS:
        _invalid(f"engine {CLI_CONTRACT_FLAG} names an unknown CLI contract")
    if not isinstance(recipe_value, str) or recipe_value not in CLI_CONTRACTS:
        _invalid(f"recipe {CLI_CONTRACT_FLAG} names an unknown CLI contract")
    if engine_value != recipe_value:
        raise BackendPreparationError(
            "bundle_incompatible",
            f"engine and recipe declare different {CLI_CONTRACT_FLAG} values",
        )
    return engine_value


def _evaluation_code(evaluation: CandidateEvaluation) -> str:
    """Map one static T07 result to a stable preparation refusal code."""
    status = evaluation.status
    if status == MISSING:
        return "bundle_missing"
    if status == CORRUPT:
        return "bundle_corrupt"
    if status == INCOMPATIBLE:
        return "bundle_incompatible"
    return "bundle_unverified"


def _evaluation_detail(evaluation: CandidateEvaluation) -> str:
    """Summarize the refused static checks without inventing a new status."""
    reasons = sorted(
        {
            f"{item.artifact}: {item.code}"
            for item in evaluation.items
            if item.status != READY
        }
    )
    return "candidate is not statically ready: " + "; ".join(reasons[:8])

def _parse_declaration(candidate_path: Path) -> CandidateDeclaration:
    """Parse one candidate declaration without observing any declared file."""
    try:
        return parse_candidate(candidate_path)
    except (CandidateValidationError, OSError) as error:
        code = "bundle_missing" if not candidate_path.exists() else "bundle_corrupt"
        raise BackendPreparationError(code, str(error)) from error


def _parse_evidence(
    trusted_evidence_path: Path | None,
) -> tuple[TrustedEvidence, ...]:
    """Parse the separate host-owned evidence records, if supplied."""
    if trusted_evidence_path is None:
        return ()
    try:
        return parse_trusted_evidence(trusted_evidence_path)
    except (CandidateValidationError, OSError) as error:
        raise BackendPreparationError("bundle_unverified", str(error)) from error


def _declared_candidate(
    declaration: CandidateDeclaration,
    trusted_evidence: tuple[TrustedEvidence, ...],
) -> EngineCandidate:
    """Validate declaration-level execution policy and read its recipe."""
    if declaration.engine.id != SUPPORTED_ENGINE_ID:
        raise BackendPreparationError(
            "bundle_incompatible",
            f"engine id must be {SUPPORTED_ENGINE_ID!r}",
        )
    if declaration.recipe.engine_id != declaration.engine.id:
        raise BackendPreparationError(
            "bundle_incompatible",
            "recipe engine_id does not match the declared engine id",
        )
    if dict(declaration.engine.architecture_flags).get(_BACKEND_FLAG) != _ROCM_BACKEND:
        raise BackendPreparationError(
            "bundle_incompatible",
            f"engine architecture_flags must declare {_BACKEND_FLAG}={_ROCM_BACKEND}",
        )
    contract = _cli_contract(declaration)
    executable = declaration.engine.executable.resolved_path(declaration.root_index)
    if not os.access(executable, os.X_OK):
        raise BackendPreparationError(
            "bundle_incompatible", "declared engine executable is not executable"
        )
    recipe = _parse_recipe(
        _read_recipe_document(declaration), declaration=declaration
    )
    return EngineCandidate(
        declaration=declaration,
        recipe=recipe,
        cli_contract=contract,
        candidate_id=declaration.stable_candidate_id(),
        trusted_evidence=trusted_evidence,
    )


def load_engine_candidate(
    candidate_path: Path,
    trusted_evidence_path: Path | None = None,
) -> EngineCandidate:
    """Parse one declared candidate without hashing pinned model files.

    The recipe document is read and strictly validated so static capabilities
    and invocation policy are known. Component, engine, and evidence bytes are
    hashed later by :meth:`StableDiffusionCppAdapter.resolve_execution`.
    """
    declaration = _parse_declaration(candidate_path)
    evidence = _parse_evidence(trusted_evidence_path)
    return _declared_candidate(declaration, evidence)


def _static_invocation_tokens(candidate: EngineCandidate) -> list[str]:
    """Return every static argument surface the adapter can emit.

    Request-specific values such as the prompt, dimensions, seed, and reference
    paths are deliberately excluded because they are data rather than engine
    configuration. Component, recipe, CLI-contract, and executable facts are
    included so the privacy policy evaluates the same surfaces the invocation
    builder uses.
    """
    declaration = candidate.declaration
    roots = declaration.root_index
    tokens = [str(declaration.engine.executable.resolved_path(roots))]
    tokens.extend(ROLE_ARGUMENTS.values())
    for component in declaration.components:
        tokens.append(str(component.artifact.resolved_path(roots)))
    for operation in candidate.recipe.operations.values():
        tokens.append(operation.sampling.sampling_method)
        tokens.extend(operation.model_args)
    tokens.append(candidate.cli_contract)
    tokens.append(OUTPUT_BASENAME)
    return tokens


def _privacy_settings(candidate: EngineCandidate) -> dict[str, bool | None]:
    """Derive configuration-only controls from the static invocation surface.

    The values are computed by the application-owned privacy module from the
    executable, component paths, documented flags, model arguments, and the
    exact child environment the adapter will pass. No control is asserted by a
    hard-coded adapter boolean. The result describes configuration compliance
    only; it is not an operating-system network confinement claim.
    """
    return invocation_privacy_settings(
        _static_invocation_tokens(candidate), _child_environment()
    )


def _static_configuration(candidate: EngineCandidate) -> dict[str, object]:
    """Return the restart-stable identity persisted with every queued job.

    Timestamps, absolute paths, verification observation identity, and values
    derived by hashing the configuration itself are excluded so independent
    submissions and workers compare the same candidate selections.
    The executable pin and required operation roles are retained so dispatch
    can compare an adapter resolution with the selected candidate without
    repeating the T07 file hashing pass.
    """
    declaration = candidate.declaration
    return {
        "configuration_version": LOCAL_INFERENCE_CONFIGURATION_VERSION,
        "backend_kind": BACKEND_KIND,
        "invocation_contract": INVOCATION_CONTRACT,
        "cli_contract": candidate.cli_contract,
        "candidate_id": candidate.candidate_id,
        "declaration_sha256": declaration.declaration_sha256,
        "declared_id": declaration.id,
        "profile": {
            "recipe_id": declaration.recipe.id,
            "pipeline_version": declaration.recipe.pipeline_version,
            "template_version": declaration.recipe.template_version,
        },
        "engine": {
            "id": declaration.engine.id,
            "version": declaration.engine.version,
            "build": declaration.engine.build,
            "executable_sha256": declaration.engine.executable.sha256,
            "executable": declaration.engine.executable.identity(),
        },
        "recipe": {
            "id": declaration.recipe.id,
            "document_sha256": declaration.recipe.document.sha256,
        },
        "components": [
            {
                "id": component.id,
                "role": component.role,
                "sha256": component.artifact.sha256,
                "precision": component.precision,
                "quantization": component.quantization,
            }
            for component in declaration.components
        ],
        "adapters": [adapter.to_dict() for adapter in declaration.adapters],
        "operations": {
            name: {"required_roles": list(operation.required_roles)}
            for name, operation in candidate.recipe.operations.items()
        },
        "privacy": _privacy_settings(candidate),
    }


def _component_for_role(
    declaration: CandidateDeclaration, role: str
) -> ComponentDeclaration:
    """Return the one declared component the argument vector can pass for a role."""
    matches = [component for component in declaration.components if component.role == role]
    if len(matches) != 1:
        raise BackendPreparationError(
            "bundle_incompatible",
            f"role {role!r} requires exactly one declared component",
        )
    return matches[0]


def _format_number(value: float) -> str:
    """Return a stable decimal spelling for one documented numeric flag."""
    if value == int(value):
        return str(int(value))
    return repr(value)


def _select_operation(recipe: RecipePlan, plan: GenerationPlan) -> tuple[str, OperationProfile]:
    """Select the declared operation implied by reference roles."""
    name = (
        _EDIT_OPERATION
        if any(reference.role == "source" for reference in plan.references)
        else _GENERATE_OPERATION
    )
    operation = recipe.operations.get(name)
    if operation is None:
        raise BackendPreparationError(
            "operation_unsupported",
            f"recipe does not declare the {name} operation",
        )
    return name, operation


def _require_qwen_edit_policy(
    declaration: CandidateDeclaration,
    operation_name: str,
    operation: OperationProfile,
) -> None:
    """Require explicit zero-conditioning for the matching Qwen edit policy."""
    if operation_name != _EDIT_OPERATION:
        return
    if not _declares_qwen_image_edit_2511(declaration):
        return
    if f"{ZERO_CONDITIONING_FLAG}=true" not in operation.model_args:
        _invalid(
            "the Qwen Image Edit 2511 operation requires "
            f"{ZERO_CONDITIONING_FLAG}=true"
        )

def _build_invocation(
    candidate: EngineCandidate,
    plan: GenerationPlan,
    operation: OperationProfile,
    output_path: Path,
) -> tuple[list[str], list[dict[str, object]]]:
    """Return the exact argument vector and ordered component record."""
    declaration = candidate.declaration
    roots = declaration.root_index
    argv = [str(declaration.engine.executable.resolved_path(roots))]
    components: list[dict[str, object]] = []
    for role in operation.required_roles:
        component = _component_for_role(declaration, role)
        components.append(
            {
                "id": component.id,
                "role": component.role,
                "sha256": component.artifact.sha256,
                "precision": component.precision,
                "quantization": component.quantization,
            }
        )
        argv.extend([ROLE_ARGUMENTS[role], str(component.artifact.resolved_path(roots))])

    sampling = operation.sampling
    if sampling.strength is not None:
        raise BackendPreparationError(
            "operation_unsupported",
            "the documented operation does not support --strength; "
            "Qwen Image Edit 2511 conditions every input through -r",
        )
    argv.extend(
        [
            "-p",
            plan.resolved_prompt,
            "-W",
            str(plan.width),
            "-H",
            str(plan.height),
            "--seed",
            str(plan.seed),
            "--sampling-method",
            sampling.sampling_method,
            "--steps",
            str(sampling.steps),
            "--cfg-scale",
            _format_number(sampling.cfg_scale),
            "--flow-shift",
            _format_number(sampling.flow_shift),
        ]
    )

    for reference in plan.references:
        argv.extend(["-r", str(reference.path)])

    if operation.model_args:
        if candidate.cli_contract == "bare-flag/v1":
            for entry in operation.model_args:
                key, value = entry.split("=", 1)
                if key != ZERO_CONDITIONING_FLAG or value != "true":
                    _invalid(
                        "the bare-flag CLI contract can express only "
                        f"{ZERO_CONDITIONING_FLAG}=true"
                    )
                argv.append("--qwen-image-zero-cond-t")
        else:
            argv.extend(["--model-args", ",".join(operation.model_args)])

    argv.extend(["-o", str(output_path)])
    return argv, components


def _child_environment() -> dict[str, str]:
    """Rebuild the child environment from the fixed allowlist."""
    environment: dict[str, str] = {}
    for name in ENVIRONMENT_ALLOWLIST:
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _environment_record(environment: Mapping[str, str]) -> dict[str, object]:
    """Describe the allowlist without copying sensitive values into evidence."""
    return environment_record(environment)


def _validate_runtime(runtime: Mapping[str, object]) -> None:
    """Refuse dispatch unless the declared ROCm runtime markers are readable."""
    if runtime.get("platform") != "linux":
        raise BackendPreparationError(
            "runtime_platform_mismatch",
            "the pinned engine requires a Linux ROCm host",
        )
    if not runtime.get("rocm_version") or not runtime.get("amdgpu_version"):
        raise BackendPreparationError(
            "runtime_evidence_incomplete",
            "ROCm and amdgpu version markers are required before dispatch",
        )


def _validate_plan_limits(candidate: EngineCandidate, plan: GenerationPlan) -> None:
    """Enforce request-safe ceilings independently of recipe-declared limits."""
    limits = (
        ("width", plan.width, candidate.recipe.max_width),
        ("height", plan.height, candidate.recipe.max_height),
    )
    for label, value, recipe_limit in limits:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BackendPreparationError(
                "operation_unsupported", f"{label} must be an integer"
            )
        maximum = min(recipe_limit, APP_MAX_DIMENSION)
        if not APP_MIN_DIMENSION <= value <= maximum:
            raise BackendPreparationError(
                "operation_unsupported",
                f"{label} must be between {APP_MIN_DIMENSION} and {maximum}",
            )
        if value % APP_DIMENSION_MULTIPLE:
            raise BackendPreparationError(
                "operation_unsupported",
                f"{label} must be a multiple of {APP_DIMENSION_MULTIPLE}",
            )

    references = plan.references
    if len(references) > min(candidate.recipe.max_references, APP_MAX_REFERENCES):
        raise BackendPreparationError(
            "operation_unsupported",
            "requested references exceed the application or recipe limit",
        )
    sources = [reference for reference in references if reference.role == "source"]
    if len(sources) > min(candidate.recipe.max_source_images, APP_MAX_SOURCE_IMAGES):
        raise BackendPreparationError(
            "operation_unsupported",
            "requested source images exceed the application or recipe limit",
        )
    if any(reference.role not in {"reference", "source"} for reference in references):
        raise BackendPreparationError(
            "operation_unsupported", "requested references use an unsupported role"
        )


def _git_worktree_root(path: Path) -> Path | None:
    """Return the nearest ancestor containing a Git metadata entry, if any."""
    current = path
    while True:
        if (current / _GIT_MARKER).exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _create_scratch(output_directory: Path) -> Path:
    """Create a private scratch directory outside output storage and Git.

    ``tempfile.mkdtemp`` creates the directory with mode 0700. Candidate
    locations are checked before use; the system temporary directory is tried
    first, then conventional POSIX alternatives when it is unsuitable.
    """
    bases: list[str | None] = [None]
    for fallback in ("/tmp", "/var/tmp"):
        if os.path.isdir(fallback):
            bases.append(fallback)
    for base in bases:
        try:
            directory = Path(tempfile.mkdtemp(prefix=_SCRATCH_PREFIX, dir=base)).resolve()
        except OSError:
            continue
        try:
            os.chmod(directory, 0o700)
        except OSError:
            shutil.rmtree(directory, ignore_errors=True)
            continue
        if directory.is_relative_to(output_directory) or _git_worktree_root(directory):
            shutil.rmtree(directory, ignore_errors=True)
            continue
        return directory
    raise BackendPreparationError(
        "runtime_evidence_incomplete",
        "no private scratch location is available outside output storage and Git",
    )


class StableDiffusionCppAdapter:
    """Execute one pinned stable-diffusion.cpp candidate on a local ROCm host.

    The adapter owns T07 re-evaluation, exact argument construction, the private
    scratch output, and direct-child invocation. It never reports its own privacy
    compliance, launch, or termination facts: the application's privacy policy
    evaluates the persisted configuration, and the application's supervisor
    records process evidence. The adapter also exposes no privacy policy
    object: the service selects the application-owned profile from its registry
    using this adapter identity and the persisted configuration. Process-tree
    containment is deliberately not claimed.
    """

    adapter_id = ADAPTER_ID
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
        candidate = load_engine_candidate(
            self._candidate_path, self._trusted_evidence_path
        )
        self._candidate = candidate
        self._resolved_lock = threading.Lock()
        self._resolved: dict[str, ResolvedExecution] = {}
        max_references = min(candidate.recipe.max_references, APP_MAX_REFERENCES)
        self.capabilities = AdapterCapabilities(
            min_width=APP_MIN_DIMENSION,
            min_height=APP_MIN_DIMENSION,
            max_width=min(candidate.recipe.max_width, APP_MAX_DIMENSION),
            max_height=min(candidate.recipe.max_height, APP_MAX_DIMENSION),
            supports_references=max_references > 0,
            max_references=max_references,
            supports_editing=_EDIT_OPERATION in candidate.recipe.operations,
            max_source_images=(
                min(candidate.recipe.max_source_images, APP_MAX_SOURCE_IMAGES)
                if _EDIT_OPERATION in candidate.recipe.operations
                else 0
            ),
            dimension_multiple=APP_DIMENSION_MULTIPLE,
            supported_operations=frozenset(candidate.recipe.operations),
        )

    @property
    def configuration(self) -> dict[str, object]:
        """Return the restart-stable static candidate selection."""

        return _static_configuration(self._candidate)

    def resolve_execution(self, plan: GenerationPlan) -> ResolvedExecution:
        """Re-evaluate the candidate and return one immutable pre-dispatch plan.

        Every pinned declaration, recipe, component, and trusted evidence file is
        read again through the T07 evaluator. The fresh verification identity is
        retained only in the attempt-scoped resolved record; it never enters the
        restart-stable adapter configuration used to match queued candidates.
        """
        if not isinstance(plan, GenerationPlan):
            raise ValueError("plan must be a GenerationPlan")
        candidate = load_engine_candidate(
            self._candidate_path, self._trusted_evidence_path
        )
        if candidate.candidate_id != self._candidate.candidate_id:
            raise BackendPreparationError(
                "bundle_corrupt",
                "candidate declaration changed after the adapter configuration was captured",
            )
        evaluation = evaluate_candidate(
            candidate.declaration,
            trusted_evidence=candidate.trusted_evidence,
        )
        if evaluation.status != READY:
            raise BackendPreparationError(
                _evaluation_code(evaluation), _evaluation_detail(evaluation)
            )
        if evaluation.evidence_authority_status != READY:
            raise BackendPreparationError(
                "bundle_unverified",
                "independent provenance, license, conversion, and compatibility "
                "evidence is not ready",
            )
        if evaluation.candidate_id != candidate.candidate_id:
            raise BackendPreparationError(
                "bundle_corrupt",
                "candidate evaluation identity changed during execution resolution",
            )
        declaration = candidate.declaration
        operation_name, operation = _select_operation(candidate.recipe, plan)
        if declaration.adapters:
            raise BackendPreparationError(
                "operation_unsupported",
                "the documented invocation contract cannot apply declared adapters",
            )
        _validate_plan_limits(candidate, plan)
        _require_qwen_edit_policy(declaration, operation_name, operation)
        runtime = capture_runtime_fingerprint()
        _validate_runtime(runtime)

        scratch = _create_scratch(self._output_directory)
        try:
            output_path = scratch / OUTPUT_BASENAME
            argv, components = _build_invocation(
                candidate, plan, operation, output_path
            )
            environment = _child_environment()
            sampling = operation.sampling
            record: dict[str, object] = {
                "schema": RESOLVED_SCHEMA,
                "schema_version": RECORD_SCHEMA_VERSION,
                "attempt_id": plan.attempt_id,
                "backend_kind": BACKEND_KIND,
                "candidate_id": candidate.candidate_id,
                "verification_id": evaluation.verification_id,
                "declaration_sha256": declaration.declaration_sha256,
                "engine": {
                    "id": declaration.engine.id,
                    "version": declaration.engine.version,
                    "build": declaration.engine.build,
                    "executable_sha256": declaration.engine.executable.sha256,
                },
                "recipe": {
                    "id": declaration.recipe.id,
                    "document_sha256": declaration.recipe.document.sha256,
                },
                "components": components,
                "adapters": [],
                "prompt": plan.resolved_prompt,
                "seed": plan.seed,
                "width": plan.width,
                "height": plan.height,
                "sampling": {
                    "sampling_method": sampling.sampling_method,
                    "steps": sampling.steps,
                    "cfg_scale": sampling.cfg_scale,
                    "flow_shift": sampling.flow_shift,
                    "strength": sampling.strength,
                },
                "conditioning": [
                    {
                        "artifact_id": reference.artifact_id,
                        "role": reference.role,
                        "content_sha256": reference.content_sha256,
                    }
                    for reference in plan.references
                ],
                "argv": list(argv),
                "environment": _environment_record(environment),
                "output_basename": OUTPUT_BASENAME,
                "invocation_contract": INVOCATION_CONTRACT,
                "cli_contract": candidate.cli_contract,
                "runtime": dict(runtime),
                "privacy": invocation_privacy_settings(argv, environment),
                "verification_window": {
                    "verified_before_launch": True,
                    "engine_may_open_different_bytes_after_launch": True,
                    "statement": VERIFICATION_WINDOW_STATEMENT,
                },
            }
            resolved = ResolvedExecution(
                attempt_id=plan.attempt_id,
                argv=tuple(argv),
                environment=environment,
                scratch_directory=scratch,
                output_path=output_path,
                resolved_record=record,
                width=plan.width,
                height=plan.height,
            )
            with self._resolved_lock:
                if plan.attempt_id in self._resolved:
                    raise BackendPreparationError(
                        "operation_unsupported",
                        "this attempt already has a resolved execution plan",
                    )
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
        """Spawn the resolved direct child and stream its validated image output.

        The service-owned supervisor is already bound to this attempt and to
        the exact resolved argv and environment. It spawns the direct child,
        records launch before waiting, and records reaped-child facts after the
        direct child exits. Adapter code cannot supply either record. The
        private scratch directory is removed in ``finally`` whether execution,
        image validation, or evidence persistence succeeds.
        """
        if not isinstance(plan, GenerationPlan):
            raise ValueError("plan must be a GenerationPlan")
        if not isinstance(supervisor, ProcessSupervisor):
            raise TypeError("supervisor must be a ProcessSupervisor")
        with self._resolved_lock:
            resolved = self._resolved.pop(plan.attempt_id, None)
        if resolved is None:
            raise GenerationError(
                "backend execution has no resolved plan for this attempt"
            )

        if supervisor.attempt_id != resolved.attempt_id:
            self._remove_scratch(resolved.scratch_directory)
            raise GenerationError(
                "supervisor is bound to a different execution attempt"
            )

        try:
            process_observation = supervisor.run(
                resolved.argv,
                env=resolved.environment,
                cwd=resolved.scratch_directory,
            )
            if (
                process_observation.exit_code != 0
                or process_observation.signal is not None
            ):
                if process_observation.signal is not None:
                    detail = f"signal {process_observation.signal}"
                else:
                    detail = f"exit code {process_observation.exit_code}"
                raise GenerationError(f"declared engine failed with {detail}")
            return self._stream_execution(resolved, destination)
        finally:
            self._remove_scratch(resolved.scratch_directory)

    def _stream_execution(
        self, resolved: ResolvedExecution, staged: BinaryIO
    ) -> ImageMetadata:
        """Validate the scratch image and stream it into the publisher's stream.

        The scratch file is opened without following symlinks. Complete image
        validation, including dimensions, runs before any bytes reach the
        publisher's staging descriptor. The descriptor is rewritten from offset
        zero and truncated, and it is never closed here.
        """
        output_path = Path(resolved.output_path)
        try:
            with open_regular(output_path) as source:
                info = validate_image(source)
                if (info.width, info.height) != (resolved.width, resolved.height):
                    raise GenerationError(
                        "declared engine wrote an image with unexpected dimensions"
                    )
                copy_source(source, staged)
        except FileNotFoundError as error:
            raise GenerationError(
                "declared engine did not write its declared output file"
            ) from error
        except InputValidationError as error:
            raise GenerationError(
                "declared engine output failed image validation"
            ) from error
        return ImageMetadata(info.media_type, info.image_format, info.width, info.height)

    def cleanup_execution(self, resolved: ResolvedExecution) -> None:
        """Remove scratch after an aborted publication or an adapter-side failure.

        Normal execution performs the same idempotent cleanup in ``execute``.
        This method covers failures between resolution and opening the publisher's
        staging descriptor, when ``execute`` is never called.
        """
        with self._resolved_lock:
            pending = self._resolved.get(resolved.attempt_id)
            if pending is resolved:
                self._resolved.pop(resolved.attempt_id, None)
        self._remove_scratch(resolved.scratch_directory)

    @staticmethod
    def _remove_scratch(directory: Path) -> None:
        """Remove one directory only when it carries this adapter's prefix."""
        scratch = Path(directory)
        if scratch.name.startswith(_SCRATCH_PREFIX):
            shutil.rmtree(scratch, ignore_errors=True)
