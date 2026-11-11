"""Validated character-screening manifests and deterministic case expansion."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ._candidate_contract import COMPONENT_ROLES
from .adapters import DeterministicCpuAdapter
from .domain import GenerationRequest
from .errors import InputValidationError



MANIFEST_SCHEMA = "media-generation.character-screening"

MANIFEST_VERSION = 1

MAX_MANIFEST_BYTES = 4 * 1024 * 1024

_ID = re.compile(r"\A[a-z][a-z0-9._-]{0,63}\Z")

_ARTIFACT_ID = re.compile(r"\Aart_[0-9a-f]{32}\Z")

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")

_SUPPLEMENTARY_KINDS = frozenset(
    {
        "capability",
        "edit",
        "regeneration",
        "chain",
        "large_composition",
        "outfit_unlocked",
        "preview_final",
    }
)

class ScreeningError(RuntimeError):
    """The screening protocol cannot safely create or advance the requested run."""

class ScreeningManifestError(ValueError):
    """The versioned screening manifest is malformed or internally inconsistent."""

class ScreeningConfigurationError(ScreeningError):
    """The current execution inputs differ from the configuration frozen in a run."""

@dataclass(frozen=True, slots=True)
class ScreeningManifest:
    """An immutable validated manifest represented by its canonical JSON bytes."""

    document_json: str
    fingerprint: str

    @classmethod
    def from_mapping(cls, value: object) -> ScreeningManifest:
        """Validate a manifest object and freeze its canonical representation."""
        try:
            copied = json.loads(_canonical_json(value))
        except (TypeError, ValueError, RecursionError) as error:
            raise ScreeningManifestError("manifest must be finite JSON") from error
        data = _mapping(copied, "manifest")
        _validate_manifest(data)
        document_json = _canonical_json(data)
        return cls(document_json, _sha256(document_json.encode("utf-8")))

    @classmethod
    def from_json(cls, path: Path) -> ScreeningManifest:
        """Load one bounded, duplicate-key-free manifest file."""
        path = Path(path).expanduser().resolve()
        try:
            size = path.stat().st_size
            if size < 1 or size > MAX_MANIFEST_BYTES:
                raise ScreeningManifestError("manifest size is outside the supported limit")
            raw = path.read_bytes()
        except OSError as error:
            raise ScreeningManifestError("manifest cannot be read") from error
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ScreeningManifestError("manifest exceeds the supported size limit")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, RecursionError) as error:
            raise ScreeningManifestError("manifest is not valid strict JSON") from error
        return cls.from_mapping(value)

    def to_dict(self) -> dict[str, object]:
        """Return a fresh mutable copy of the frozen manifest document."""
        return json.loads(self.document_json)

def build_case_definitions(
    manifest: ScreeningManifest, *, run_id: str
) -> list[dict[str, object]]:
    """Expand a frozen protocol into 24 matrix cases and separate supplements."""
    if not isinstance(manifest, ScreeningManifest):
        raise ScreeningManifestError("manifest must be a validated ScreeningManifest")
    if not re.fullmatch(r"run_[0-9a-f]{32}", run_id):
        raise ScreeningManifestError("run id must be ledger-owned run identity")
    data = manifest.to_dict()
    profile = data["request_profile"]
    assert isinstance(profile, dict)
    styles = data["reference_styles"]
    scenarios = data["scenario_changes"]
    seeds = data["seeds"]
    assert isinstance(styles, list) and isinstance(scenarios, list) and isinstance(seeds, list)

    cases: list[dict[str, object]] = []
    for style in styles:
        assert isinstance(style, dict)
        for scenario in scenarios:
            assert isinstance(scenario, dict)
            for seed in seeds:
                source_case_id = f"matrix:{style['id']}:{scenario['id']}:{seed}"
                case_id = _case_id(run_id, source_case_id)
                references = list(style["artifact_ids"])
                roles = list(style["roles"])
                request = _request(
                    prompt=str(scenario["prompt"]),
                    seed=seed,
                    width=profile["width"],
                    height=profile["height"],
                    reference_ids=references,
                    reference_roles=roles,
                    output_slot=f"{profile['output_slot_prefix']}-{case_id}",
                    operation_intent=str(scenario["operation_intent"]),
                    label=source_case_id,
                )
                cases.append(
                    _case_record(
                        run_id=run_id,
                        case_id=case_id,
                        source_case_id=source_case_id,
                        kind="matrix",
                        label=f"{style['label']} / {scenario['label']} / seed {seed}",
                        request=request,
                        operation_intent=str(scenario["operation_intent"]),
                        conditioning_inputs=_conditioning_inputs(
                            references, roles, list(style["sha256"])
                        ),
                        creative_origin_artifact_ids=[],
                        pairing=None,
                        matrix_coordinates={
                            "reference_style_id": style["id"],
                            "scenario_change_id": scenario["id"],
                            "seed": seed,
                        },
                        control_profile=None,
                    )
                )

    for supplementary in data["supplementary_cases"]:
        assert isinstance(supplementary, dict)
        source_case_id = f"supplementary:{supplementary['id']}"
        case_id = _case_id(run_id, source_case_id)
        request_data = dict(supplementary["request"])
        request_data.setdefault("width", profile["width"])
        request_data.setdefault("height", profile["height"])
        request_data.setdefault("reference_ids", [])
        request_data.setdefault("reference_roles", [])
        request_data["output_slot"] = f"{profile['output_slot_prefix']}-{case_id}"
        request = _request(
            prompt=str(request_data["prompt"]),
            seed=request_data.get("seed"),
            width=request_data["width"],
            height=request_data["height"],
            reference_ids=list(request_data["reference_ids"]),
            reference_roles=list(request_data["reference_roles"]),
            output_slot=str(request_data["output_slot"]),
            operation_intent=str(supplementary["operation_intent"]),
            label=source_case_id,
        )
        input_hashes = supplementary.get("conditioning_sha256", [])
        if not input_hashes:
            input_hashes = [None] * len(request.reference_ids)
        pairing = supplementary.get("pairing")
        cases.append(
            _case_record(
                run_id=run_id,
                case_id=case_id,
                source_case_id=source_case_id,
                kind=str(supplementary["kind"]),
                label=str(supplementary["label"]),
                request=request,
                operation_intent=str(supplementary["operation_intent"]),
                conditioning_inputs=_conditioning_inputs(
                    list(request.reference_ids),
                    list(request.reference_roles or ("reference",) * len(request.reference_ids)),
                    list(input_hashes),
                ),
                creative_origin_artifact_ids=list(
                    supplementary["creative_origin_artifact_ids"]
                ),
                pairing=None if pairing is None else dict(pairing),
                matrix_coordinates=None,
                control_profile=_control_profile(supplementary),
                supplementary_metadata={
                    key: supplementary[key]
                    for key in ("chain_id", "chain_step", "notes")
                    if key in supplementary
                },
            )
        )

    case_ids = [case["case_id"] for case in cases]
    request_digests = [case["request_digest"] for case in cases if case["kind"] == "matrix"]
    output_slots = [case["request"]["output_slot"] for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ScreeningManifestError("case identities are not unique")
    if len(request_digests) != 24 or len(request_digests) != len(set(request_digests)):
        raise ScreeningManifestError("the 24 matrix cases must have distinct requests")
    if len(output_slots) != len(set(output_slots)):
        raise ScreeningManifestError("every case must use a distinct output slot label")
    _validate_pairings(cases)
    return cases

def _validate_manifest(data: dict[str, object]) -> None:
    _exact_keys(
        data,
        {
            "schema",
            "schema_version",
            "protocol_id",
            "selected_model_variant",
            "request_profile",
            "reference_styles",
            "scenario_changes",
            "seeds",
            "supplementary_cases",
        },
        "manifest",
        required={
            "schema",
            "schema_version",
            "protocol_id",
            "selected_model_variant",
            "request_profile",
            "reference_styles",
            "scenario_changes",
            "seeds",
        },
    )
    if data["schema"] != MANIFEST_SCHEMA:
        raise ScreeningManifestError(f"schema must be {MANIFEST_SCHEMA}")
    if (
        isinstance(data["schema_version"], bool)
        or not isinstance(data["schema_version"], int)
        or data["schema_version"] != MANIFEST_VERSION
    ):
        raise ScreeningManifestError("schema_version must be the integer 1")
    _text(data["protocol_id"], "protocol_id")
    _validate_variant(data["selected_model_variant"])
    profile = _mapping(data["request_profile"], "request_profile")
    _exact_keys(
        profile,
        {"width", "height", "output_slot_prefix"},
        "request_profile",
        required={"width", "height", "output_slot_prefix"},
    )
    _integer(profile["width"], "request_profile.width", 1, 16384)
    _integer(profile["height"], "request_profile.height", 1, 16384)
    prefix = _text(profile["output_slot_prefix"], "request_profile.output_slot_prefix")
    if not _ID.fullmatch(prefix):
        raise ScreeningManifestError("output_slot_prefix has invalid characters")

    styles = _list(data["reference_styles"], "reference_styles")
    if len(styles) != 3:
        raise ScreeningManifestError("reference_styles must contain exactly three styles")
    style_ids: set[str] = set()
    style_inputs: set[str] = set()
    for index, value in enumerate(styles):
        label = f"reference_styles[{index}]"
        style = _mapping(value, label)
        _exact_keys(
            style,
            {"id", "label", "artifact_ids", "sha256", "roles"},
            label,
            required={"id", "label", "artifact_ids", "sha256", "roles"},
        )
        style_id = _identifier(style["id"], f"{label}.id")
        if style_id in style_ids:
            raise ScreeningManifestError("reference style IDs must be unique")
        style_ids.add(style_id)
        _text(style["label"], f"{label}.label")
        artifacts = _list(style["artifact_ids"], f"{label}.artifact_ids")
        if not artifacts or len(artifacts) > 8:
            raise ScreeningManifestError(f"{label}.artifact_ids must contain 1-8 references")
        for artifact in artifacts:
            _artifact_id(artifact, f"{label}.artifact_ids")
        if len(artifacts) != len(set(artifacts)):
            raise ScreeningManifestError(f"{label}.artifact_ids must be unique")
        digests = _list(style["sha256"], f"{label}.sha256")
        if len(digests) != len(artifacts):
            raise ScreeningManifestError(f"{label}.sha256 must align with artifact_ids")
        for digest in digests:
            _digest(digest, f"{label}.sha256")
        roles = _list(style["roles"], f"{label}.roles")
        if len(roles) != len(artifacts) or any(
            not isinstance(role, str) or role not in {"reference", "source"}
            for role in roles
        ):
            raise ScreeningManifestError(f"{label}.roles must align with valid conditioning inputs")
        if roles.count("source") > 1:
            raise ScreeningManifestError(f"{label}.roles may contain at most one source")
        style_input = _canonical_json(
            {"artifact_ids": artifacts, "sha256": digests, "roles": roles}
        )
        if style_input in style_inputs:
            raise ScreeningManifestError("reference styles must have distinct conditioning inputs")
        style_inputs.add(style_input)

    scenarios = _list(data["scenario_changes"], "scenario_changes")
    if len(scenarios) != 4:
        raise ScreeningManifestError("scenario_changes must contain exactly four labeled changes")
    scenario_ids: set[str] = set()
    scenario_changes: set[str] = set()
    for index, value in enumerate(scenarios):
        label = f"scenario_changes[{index}]"
        scenario = _mapping(value, label)
        _exact_keys(
            scenario,
            {"id", "label", "prompt", "operation_intent"},
            label,
            required={"id", "label", "prompt", "operation_intent"},
        )
        scenario_id = _identifier(scenario["id"], f"{label}.id")
        if scenario_id in scenario_ids:
            raise ScreeningManifestError("scenario change IDs must be unique")
        scenario_ids.add(scenario_id)
        _text(scenario["label"], f"{label}.label")
        _text(scenario["prompt"], f"{label}.prompt", maximum=16384)
        if not isinstance(scenario["operation_intent"], str) or scenario["operation_intent"] not in {"generate", "edit"}:
            raise ScreeningManifestError(f"{label}.operation_intent must be generate or edit")
        scenario_change = _canonical_json(
            {"prompt": scenario["prompt"], "operation_intent": scenario["operation_intent"]}
        )
        if scenario_change in scenario_changes:
            raise ScreeningManifestError("scenario changes must have distinct prompts and operations")
        scenario_changes.add(scenario_change)

    seeds = _list(data["seeds"], "seeds")
    if len(seeds) != 2:
        raise ScreeningManifestError("seeds must contain exactly two values")
    for seed in seeds:
        _integer(seed, "seed", 0, 4_294_967_295)
    if len(set(seeds)) != 2:
        raise ScreeningManifestError("seeds must be distinct")

    supplements = _list(data.get("supplementary_cases", []), "supplementary_cases")
    if len(supplements) > 128:
        raise ScreeningManifestError("supplementary_cases exceeds the supported limit")
    supplement_ids: set[str] = set()
    chain_steps: dict[str, list[int]] = {}
    for index, value in enumerate(supplements):
        label = f"supplementary_cases[{index}]"
        supplemental = _mapping(value, label)
        _validate_supplementary(supplemental, label)
        supplement_id = str(supplemental["id"])
        if supplement_id in supplement_ids:
            raise ScreeningManifestError("supplementary case IDs must be unique")
        supplement_ids.add(supplement_id)
        if supplemental["kind"] == "chain":
            chain_steps.setdefault(str(supplemental["chain_id"]), []).append(
                int(supplemental["chain_step"])
            )
    for chain_id, steps in chain_steps.items():
        if len(steps) < 2 or sorted(steps) != list(range(1, len(steps) + 1)):
            raise ScreeningManifestError(
                f"chain {chain_id} must define consecutive, separately counted steps starting at one"
            )

    data.setdefault("supplementary_cases", [])
    cases = _validate_expanded_requests(data)
    if len([case for case in cases if case["kind"] == "matrix"]) != 24:
        raise ScreeningManifestError("manifest does not expand to 24 matrix cases")

def _validate_expanded_requests(data: Mapping[str, object]) -> list[dict[str, object]]:
    """Validate conditioning and request uniqueness before freezing a run."""
    try:
        return build_case_definitions(
            ScreeningManifest(_canonical_json(dict(data)), _fingerprint(data)),
            run_id="run_" + "0" * 32,
        )
    except (InputValidationError, ValueError) as error:
        if isinstance(error, ScreeningManifestError):
            raise
        raise ScreeningManifestError(
            f"invalid conditioning or operation intent in screening cases: {error}"
        ) from error

def _validate_variant(value: object) -> None:
    variant = _mapping(value, "selected_model_variant")
    _exact_keys(
        variant,
        {"id", "family", "repository", "revision", "components", "architecture_flags", "worker_context"},
        "selected_model_variant",
        required={"id", "family", "repository", "revision", "components"},
    )
    for key in ("id", "family", "repository", "revision"):
        _text(variant[key], f"selected_model_variant.{key}")
    components = _list(variant["components"], "selected_model_variant.components")
    if not components:
        raise ScreeningManifestError("selected_model_variant.components cannot be empty")
    component_ids: set[str] = set()
    for index, value in enumerate(components):
        label = f"selected_model_variant.components[{index}]"
        component = _mapping(value, label)
        _exact_keys(
            component,
            {"id", "role", "path", "size_bytes", "sha256", "precision", "quantization"},
            label,
            required={"id", "role", "path", "size_bytes", "sha256", "precision", "quantization"},
        )
        component_id = _identifier(component["id"], f"{label}.id")
        if component_id in component_ids:
            raise ScreeningManifestError("model component IDs must be unique")
        component_ids.add(component_id)
        for key in ("role", "path", "precision", "quantization"):
            _text(component[key], f"{label}.{key}")
        if not Path(str(component["path"])).is_absolute():
            raise ScreeningManifestError(f"{label}.path must be an absolute local path")
        _integer(component["size_bytes"], f"{label}.size_bytes", 1, 2**63 - 1)
        _digest(component["sha256"], f"{label}.sha256")
    for optional in ("architecture_flags", "worker_context"):
        if optional in variant:
            _mapping(variant[optional], f"selected_model_variant.{optional}")

def _validate_supplementary(value: dict[str, object], label: str) -> None:
    _exact_keys(
        value,
        {
            "id",
            "label",
            "kind",
            "request",
            "operation_intent",
            "conditioning_sha256",
            "creative_origin_artifact_ids",
            "pairing",
            "chain_id",
            "chain_step",
            "notes",
        },
        label,
        required={"id", "label", "kind", "request", "operation_intent"},
    )
    _identifier(value["id"], f"{label}.id")
    _text(value["label"], f"{label}.label")
    if not isinstance(value["kind"], str) or value["kind"] not in _SUPPLEMENTARY_KINDS:
        raise ScreeningManifestError(f"{label}.kind is unsupported")
    if not isinstance(value["operation_intent"], str) or value["operation_intent"] not in {"generate", "edit"}:
        raise ScreeningManifestError(f"{label}.operation_intent must be generate or edit")
    request = _mapping(value["request"], f"{label}.request")
    _exact_keys(
        request,
        {"prompt", "seed", "width", "height", "reference_ids", "reference_roles"},
        f"{label}.request",
        required={"prompt"},
    )
    _text(request["prompt"], f"{label}.request.prompt", maximum=16384)
    if "seed" in request and request["seed"] is not None:
        _integer(request["seed"], f"{label}.request.seed", 0, 4_294_967_295)
    for key in ("width", "height"):
        if key in request:
            _integer(request[key], f"{label}.request.{key}", 1, 16384)
    references = _list(request.get("reference_ids", []), f"{label}.request.reference_ids")
    roles = _list(request.get("reference_roles", []), f"{label}.request.reference_roles")
    for artifact in references:
        _artifact_id(artifact, f"{label}.request.reference_ids")
    if len(references) != len(set(references)):
        raise ScreeningManifestError(f"{label}.request.reference_ids must be unique")
    if roles and len(roles) != len(references):
        raise ScreeningManifestError(f"{label}.request.reference_roles must align with reference_ids")
    if any(
        not isinstance(role, str) or role not in {"reference", "source"}
        for role in roles
    ) or roles.count("source") > 1:
        raise ScreeningManifestError(f"{label}.request.reference_roles are invalid")
    hashes = _list(value.get("conditioning_sha256", []), f"{label}.conditioning_sha256")
    if len(hashes) != len(references):
        raise ScreeningManifestError(f"{label}.conditioning_sha256 must align with reference_ids")
    for digest in hashes:
        _digest(digest, f"{label}.conditioning_sha256")
    origins = _list(value.get("creative_origin_artifact_ids", []), f"{label}.creative_origin_artifact_ids")
    for artifact in origins:
        _artifact_id(artifact, f"{label}.creative_origin_artifact_ids")
    if len(origins) != len(set(origins)):
        raise ScreeningManifestError(f"{label}.creative_origin_artifact_ids must be unique")
    value.setdefault("creative_origin_artifact_ids", [])
    if value["kind"] == "preview_final" and "pairing" not in value:
        raise ScreeningManifestError(f"{label} preview_final cases require pairing")
    if "pairing" in value:
        pairing = _mapping(value["pairing"], f"{label}.pairing")
        _exact_keys(pairing, {"pair_id", "role"}, f"{label}.pairing", required={"pair_id", "role"})
        _identifier(pairing["pair_id"], f"{label}.pairing.pair_id")
        if not isinstance(pairing["role"], str) or pairing["role"] not in {"preview", "final"}:
            raise ScreeningManifestError(f"{label}.pairing.role must be preview or final")
        if value["kind"] != "preview_final":
            raise ScreeningManifestError("pairing relations require preview_final cases")
    if value["kind"] == "edit" and value["operation_intent"] != "edit":
        raise ScreeningManifestError(f"{label} edit cases must freeze edit operation intent")
    if value["kind"] == "chain":
        if "chain_id" not in value or "chain_step" not in value:
            raise ScreeningManifestError(f"{label} chain cases require chain_id and chain_step")
        _identifier(value["chain_id"], f"{label}.chain_id")
        _integer(value["chain_step"], f"{label}.chain_step", 1, 1024)
    if value["kind"] == "outfit_unlocked":
        value.setdefault("notes", "Outfit variation is intentionally unlocked for this case.")
    if "notes" in value:
        _text(value["notes"], f"{label}.notes", maximum=2048)

def _request(
    *,
    prompt: str,
    seed: object,
    width: object,
    height: object,
    reference_ids: list[object],
    reference_roles: list[object],
    output_slot: str,
    operation_intent: str,
    label: str,
) -> GenerationRequest:
    try:
        return GenerationRequest(
            prompt=prompt,
            seed=seed,  # type: ignore[arg-type]
            width=width,  # type: ignore[arg-type]
            height=height,  # type: ignore[arg-type]
            reference_ids=tuple(reference_ids),  # type: ignore[arg-type]
            reference_roles=tuple(reference_roles),  # type: ignore[arg-type]
            output_slot=output_slot,
            operation=operation_intent,
        )
    except (InputValidationError, TypeError, ValueError) as error:
        raise ScreeningManifestError(
            f"{label} has invalid conditioning or operation intent: {error}"
        ) from error

def _case_record(
    *,
    run_id: str,
    case_id: str,
    source_case_id: str,
    kind: str,
    label: str,
    request: GenerationRequest,
    operation_intent: str,
    conditioning_inputs: list[dict[str, object]],
    creative_origin_artifact_ids: list[str],
    pairing: dict[str, object] | None,
    matrix_coordinates: dict[str, object] | None,
    control_profile: dict[str, object] | None,
    supplementary_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    snapshot = request.to_dict()
    return {
        "run_id": run_id,
        "case_id": case_id,
        "source_case_id": source_case_id,
        "kind": kind,
        "label": label,
        "request": snapshot,
        "request_digest": request.digest(),
        "operation_intent": operation_intent,
        "single_output": True,
        "conditioning_inputs": conditioning_inputs,
        "creative_origin_artifact_ids": creative_origin_artifact_ids,
        "pairing": pairing,
        "matrix_coordinates": matrix_coordinates,
        "control_profile": control_profile,
        "supplementary_metadata": supplementary_metadata or {},
    }

def _conditioning_inputs(
    artifact_ids: list[object], roles: list[object], hashes: list[object]
) -> list[dict[str, object]]:
    if not hashes:
        hashes = [None] * len(artifact_ids)
    normalized_roles = roles or ["reference"] * len(artifact_ids)
    return [
        {"artifact_id": artifact_id, "role": role, "sha256": digest}
        for artifact_id, role, digest in zip(artifact_ids, normalized_roles, hashes, strict=True)
    ]

def _control_profile(supplementary: Mapping[str, object]) -> dict[str, object]:
    kind = supplementary["kind"]
    if kind == "outfit_unlocked":
        return {"outfit": "intentionally_unlocked"}
    if kind == "large_composition":
        return {"composition_change": "large"}
    if kind == "preview_final":
        return {"profile": "experimental_test_profile", "accepted_product_target": False}
    if kind == "edit":
        return {"source_image_edit": True}
    if kind == "regeneration":
        return {"canonical_reference_regeneration": True}
    if kind == "chain":
        return {
            "chain_id": supplementary.get("chain_id"),
            "chain_step": supplementary.get("chain_step"),
            "conditioning_artifacts_pinned_before_run": True,
        }
    if kind == "capability":
        return {"capability_probe": True}
    return {}

def _validate_pairings(cases: list[dict[str, object]]) -> None:
    groups: dict[str, list[str]] = {}
    for case in cases:
        pairing = case.get("pairing")
        if isinstance(pairing, dict):
            groups.setdefault(str(pairing["pair_id"]), []).append(str(pairing["role"]))
    for pair_id, roles in groups.items():
        if sorted(roles) != ["final", "preview"]:
            raise ScreeningManifestError(
                f"preview/final pair {pair_id} must contain one preview and one final case"
            )

def _validate_variant_against_candidate(
    selected_variant: object,
    execution_identity: Mapping[str, object],
    *,
    operation_intents: tuple[object, ...] = (),
) -> None:
    """Match component pins and exercised roles to the frozen T07 candidate.

    Every selected component must match by ID, role, digest, precision, and
    quantization. The variant must include each role required by its frozen case
    operations. Optional candidate components may remain unselected. The
    deterministic CPU adapter is the explicit no-candidate path for local tests.
    """
    variant = _mapping(selected_variant, "selected_model_variant")
    configuration = execution_identity.get("adapter_configuration")
    if (
        execution_identity.get("adapter_id") == DeterministicCpuAdapter.adapter_id
        and configuration == DeterministicCpuAdapter().configuration
    ):
        return
    if not isinstance(configuration, Mapping):
        raise ScreeningConfigurationError(
            "real execution identity has no pinned T07 candidate configuration"
        )
    candidate_id = configuration.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise ScreeningConfigurationError(
            "real execution identity has no pinned T07 candidate ID"
        )
    candidate_components = configuration.get("components")
    if not isinstance(candidate_components, list):
        raise ScreeningConfigurationError(
            "pinned candidate configuration does not expose its component fingerprints"
        )
    components_by_id: dict[str, Mapping[str, object]] = {}
    candidate_ids_by_role: dict[str, set[str]] = {}
    for component in candidate_components:
        if not isinstance(component, Mapping):
            raise ScreeningConfigurationError(
                "pinned candidate configuration contains an invalid component"
            )
        component_id = component.get("id")
        if not isinstance(component_id, str) or not component_id:
            raise ScreeningConfigurationError(
                "pinned candidate component has no ID"
            )
        if component_id in components_by_id:
            raise ScreeningConfigurationError(
                f"pinned candidate configuration repeats component ID {component_id!r}"
            )
        components_by_id[component_id] = component
        role = component.get("role")
        if not isinstance(role, str) or role not in COMPONENT_ROLES:
            raise ScreeningConfigurationError(
                "pinned candidate component has an invalid role"
            )
        candidate_ids_by_role.setdefault(role, set()).add(component_id)
    variant_components = variant.get("components")
    if not isinstance(variant_components, list) or not variant_components:
        raise ScreeningConfigurationError("selected model variant has no component pins")
    identity_fields = ("id", "role", "sha256", "precision", "quantization")
    selected_ids: set[str] = set()
    selected_ids_by_role: dict[str, set[str]] = {}
    for selected in variant_components:
        if not isinstance(selected, Mapping):
            raise ScreeningConfigurationError(
                "selected ModelVariant contains an invalid component pin"
            )
        component_id = selected.get("id")
        if not isinstance(component_id, str) or not component_id:
            raise ScreeningConfigurationError(
                "selected ModelVariant component pin has no ID"
            )
        if component_id in selected_ids:
            raise ScreeningConfigurationError(
                f"selected ModelVariant repeats component ID {component_id!r}"
            )
        selected_ids.add(component_id)
        selected_role = selected.get("role")
        if not isinstance(selected_role, str) or not selected_role:
            raise ScreeningConfigurationError(
                "selected ModelVariant component pin has no role"
            )
        selected_ids_by_role.setdefault(selected_role, set()).add(component_id)
        candidate = components_by_id.get(component_id)
        if candidate is None or any(
            candidate.get(field) != selected.get(field) for field in identity_fields
        ):
            raise ScreeningConfigurationError(
                "selected ModelVariant component pins do not match the T07 candidate configuration"
            )

    if not operation_intents:
        raise ScreeningConfigurationError(
            "frozen screening case operation intents are required"
        )
    operations = configuration.get("operations")
    if not isinstance(operations, Mapping):
        raise ScreeningConfigurationError(
            "pinned candidate configuration does not expose operation required roles"
        )
    required_roles_by_operations: set[str] = set()
    for operation_intent in operation_intents:
        if not isinstance(operation_intent, str) or not operation_intent:
            raise ScreeningConfigurationError(
                "frozen screening case has an invalid operation intent"
            )
        operation = operations.get(operation_intent)
        if not isinstance(operation, Mapping):
            raise ScreeningConfigurationError(
                f"pinned candidate configuration does not declare the {operation_intent!r} operation"
            )
        operation_roles = operation.get("required_roles")
        if (
            not isinstance(operation_roles, list)
            or not operation_roles
            or not all(isinstance(role, str) and role for role in operation_roles)
        ):
            raise ScreeningConfigurationError(
                f"pinned candidate {operation_intent!r} operation has invalid required roles"
            )
        required_roles_by_operations.update(operation_roles)
    ambiguous_roles = {
        role
        for role in required_roles_by_operations
        if len(candidate_ids_by_role.get(role, set())) != 1
    }
    if ambiguous_roles:
        raise ScreeningConfigurationError(
            "pinned candidate configuration has missing or ambiguous required roles: "
            + ", ".join(sorted(ambiguous_roles))
        )
    missing_roles = {
        role
        for role in required_roles_by_operations
        if selected_ids_by_role.get(role) != candidate_ids_by_role[role]
    }
    if missing_roles:
        raise ScreeningConfigurationError(
            "selected ModelVariant omits required candidate component roles: "
            + ", ".join(sorted(missing_roles))
        )

def _case_id(run_id: str, source_case_id: str) -> str:
    return f"case_{_sha256(f'{run_id}:{source_case_id}'.encode('utf-8'))[:32]}"

def _fingerprint(value: object) -> str:
    return _sha256(_canonical_json(value).encode("utf-8"))

def _canonical_json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise ScreeningManifestError("screening inputs must be finite JSON values") from error

def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ScreeningManifestError(f"duplicate JSON field: {key}")
        result[key] = value
    return result

def _reject_constant(value: str) -> object:
    raise ScreeningManifestError(f"non-finite JSON value is not allowed: {value}")

def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ScreeningManifestError(f"{label} must be a JSON object")
    return value

def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ScreeningManifestError(f"{label} must be a JSON array")
    return value

def _exact_keys(
    value: Mapping[str, object],
    allowed: set[str],
    label: str,
    *,
    required: set[str],
) -> None:
    missing = required - set(value)
    unexpected = set(value) - allowed
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if unexpected:
            details.append("unexpected " + ", ".join(sorted(unexpected)))
        raise ScreeningManifestError(f"{label} has invalid fields: {'; '.join(details)}")

def _text(value: object, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
        raise ScreeningManifestError(f"{label} must be a nonempty string of at most {maximum} characters")
    return value.strip()

def _identifier(value: object, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not _ID.fullmatch(result):
        raise ScreeningManifestError(f"{label} has invalid identifier characters")
    return result

def _artifact_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ARTIFACT_ID.fullmatch(value):
        raise ScreeningManifestError(f"{label} must contain persisted artifact IDs")
    return value

def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ScreeningManifestError(f"{label} must contain lowercase SHA-256 fingerprints")
    return value

def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ScreeningManifestError(f"{label} must be an integer from {minimum} to {maximum}")
    return value
