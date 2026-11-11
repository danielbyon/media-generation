from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from media_generation.adapters import AdapterCapabilities, DeterministicCpuAdapter
from media_generation.domain import GenerationRequest
from media_generation.screening import (
    ScreeningConfigurationError,
    ScreeningManifest,
    ScreeningRunner,
    build_case_definitions,
    _validate_variant_against_candidate,
)
from media_generation.screening_store import ScreeningLedger
from media_generation.service import GenerationService
from media_generation.store import SQLiteStore


ARTIFACT_IDS = (
    "art_00000000000000000000000000000001",
    "art_00000000000000000000000000000002",
    "art_00000000000000000000000000000003",
)
PIN = "a" * 64


def _manifest_mapping() -> dict[str, object]:
    return {
        "schema": "media-generation.character-screening",
        "schema_version": 1,
        "protocol_id": "character-screening-v1",
        "selected_model_variant": {
            "id": "owner-selected-qwen-variant",
            "family": "qwen-image-edit",
            "repository": "owner/model-variant",
            "revision": "0123456789abcdef",
            "components": [
                {
                    "id": "diffusion",
                    "role": "diffusion_model",
                    "path": "/models/diffusion.gguf",
                    "size_bytes": 1024,
                    "sha256": PIN,
                    "precision": "q4",
                    "quantization": "q4_k_m",
                }
            ],
        },
        "request_profile": {"width": 64, "height": 64, "output_slot_prefix": "t10"},
        "reference_styles": [
            {
                "id": f"style-{index}",
                "label": f"Reference style {index}",
                "artifact_ids": [artifact_id],
                "sha256": [PIN],
                "roles": ["reference"],
            }
            for index, artifact_id in enumerate(ARTIFACT_IDS, start=1)
        ],
        "scenario_changes": [
            {
                "id": f"change-{index}",
                "label": f"Scenario change {index}",
                "prompt": f"Keep the same adult fictional character; apply change {index}.",
                "operation_intent": "generate",
            }
            for index in range(1, 5)
        ],
        "seeds": [17, 29],
        "supplementary_cases": [
            {
                "id": "preview-profile",
                "label": "Experimental preview profile",
                "kind": "preview_final",
                "request": {
                    "prompt": "Experimental preview test profile.",
                    "seed": 41,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["reference"],
                    "width": 64,
                    "height": 64,
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
                "creative_origin_artifact_ids": [ARTIFACT_IDS[1]],
                "pairing": {"pair_id": "preview-final-1", "role": "preview"},
            },
            {
                "id": "final-profile",
                "label": "Experimental final profile",
                "kind": "preview_final",
                "request": {
                    "prompt": "Experimental final test profile.",
                    "seed": 41,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["reference"],
                    "width": 128,
                    "height": 128,
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
                "creative_origin_artifact_ids": [ARTIFACT_IDS[1]],
                "pairing": {"pair_id": "preview-final-1", "role": "final"},
            },
            {
                "id": "reference-order-capability",
                "label": "Multiple reference order capability probe",
                "kind": "capability",
                "request": {
                    "prompt": "Capability probe with two ordered canonical references.",
                    "seed": 43,
                    "reference_ids": [ARTIFACT_IDS[0], ARTIFACT_IDS[1]],
                    "reference_roles": ["reference", "reference"],
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN, PIN],
            },
            {
                "id": "single-reference-capability",
                "label": "Single canonical reference capability probe",
                "kind": "capability",
                "request": {
                    "prompt": "Capability probe with one canonical reference.",
                    "seed": 45,
                    "reference_ids": [ARTIFACT_IDS[2]],
                    "reference_roles": ["reference"],
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
            },
            {
                "id": "source-edit",
                "label": "Source-image editing capability case",
                "kind": "edit",
                "request": {
                    "prompt": "Edit the source image with a restrained change.",
                    "seed": 47,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["source"],
                },
                "operation_intent": "edit",
                "conditioning_sha256": [PIN],
            },
            {
                "id": "canonical-regeneration",
                "label": "New canonical-reference regeneration case",
                "kind": "regeneration",
                "request": {
                    "prompt": "Regenerate from the canonical reference without source editing.",
                    "seed": 53,
                    "reference_ids": [ARTIFACT_IDS[2]],
                    "reference_roles": ["reference"],
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
            },
            {
                "id": "chain-step-one",
                "label": "Pinned chain step one",
                "kind": "chain",
                "request": {
                    "prompt": "First pinned step in an existing edit chain.",
                    "seed": 59,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["source"],
                },
                "operation_intent": "edit",
                "conditioning_sha256": [PIN],
                "chain_id": "test-chain",
                "chain_step": 1,
            },
            {
                "id": "chain-step-two",
                "label": "Pinned chain step two",
                "kind": "chain",
                "request": {
                    "prompt": "Second pinned step in an existing edit chain.",
                    "seed": 60,
                    "reference_ids": [ARTIFACT_IDS[1]],
                    "reference_roles": ["source"],
                },
                "operation_intent": "edit",
                "conditioning_sha256": [PIN],
                "chain_id": "test-chain",
                "chain_step": 2,
            },
            {
                "id": "large-composition",
                "label": "Large composition change",
                "kind": "large_composition",
                "request": {
                    "prompt": "Move the subject from a close portrait to a wide establishing composition.",
                    "seed": 61,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["reference"],
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
            },
            {
                "id": "outfit-unlocked",
                "label": "Outfit variation with outfit intentionally unlocked",
                "kind": "outfit_unlocked",
                "request": {
                    "prompt": "Change clothing while keeping the adult fictional character recognizable.",
                    "seed": 67,
                    "reference_ids": [ARTIFACT_IDS[0]],
                    "reference_roles": ["reference"],
                },
                "operation_intent": "generate",
                "conditioning_sha256": [PIN],
            },
        ],
    }


def _manifest() -> ScreeningManifest:
    return ScreeningManifest.from_mapping(_manifest_mapping())


def _cpu_identity(service: GenerationService, db: Path, output: Path) -> dict[str, object]:
    return {
        "adapter_id": service.adapter.adapter_id,
        "adapter_configuration": service.adapter.configuration,
        "service_database": str(db.resolve()),
        "output_directory": str(output.resolve()),
    }


def _runner(tmp_path: Path, *, clock=lambda: 1000.0) -> tuple[ScreeningRunner, Path, Path]:
    db = tmp_path / "generation.sqlite3"
    output = tmp_path / "artifacts"
    adapter = DeterministicCpuAdapter()
    identity = {
        "adapter_id": adapter.adapter_id,
        "adapter_configuration": adapter.configuration,
        "service_database": str(db.resolve()),
        "output_directory": str(output.resolve()),
    }

    def make_service() -> GenerationService:
        return GenerationService(db, output, adapter=DeterministicCpuAdapter())

    runner = ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=db,
        output_directory=output,
        execution_identity=identity,
        service_factory=make_service,
        clock=clock,
        lease_seconds=10,
        heartbeat_interval=None,
    )
    return runner, db, output


def _add_reference(service: GenerationService, label: str) -> str:
    result = service.submit(
        f"test-reference-{label}",
        GenerationRequest(prompt=f"Synthetic test reference {label}", seed=1, width=64, height=64),
    )
    assert result.artifact_id is not None
    return result.artifact_id


def _pin_distinct_references(
    service: GenerationService,
    mapping: dict[str, object],
    label: str,
    *,
    incorrect_digests: bool = False,
) -> None:
    styles = mapping["reference_styles"]
    assert isinstance(styles, list)
    for index, style in enumerate(styles):
        assert isinstance(style, dict)
        artifact_id = _add_reference(service, f"{label}-{index}")
        digest = SQLiteStore(service.database_path).get_artifact(artifact_id).sha256
        style["artifact_ids"] = [artifact_id]
        style["sha256"] = ["b" * 64 if incorrect_digests else digest]


def _job_count(database: Path) -> int:
    with sqlite3.connect(database) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM generation_jobs").fetchone()[0])


def test_manifest_expands_exactly_24_distinct_single_output_requests() -> None:
    manifest = _manifest()
    cases = build_case_definitions(manifest, run_id="run_" + "0" * 32)

    matrix = [case for case in cases if case["kind"] == "matrix"]
    assert len(matrix) == 24
    assert len({case["case_id"] for case in matrix}) == 24
    assert len({case["request_digest"] for case in matrix}) == 24
    for case in matrix:
        snapshot = case["request"]
        assert "operation" not in snapshot
        assert case["operation_intent"] == "generate"
        assert snapshot["output_slot"].startswith("t10-")
        assert len(case["conditioning_inputs"]) == 1
        request = GenerationRequest(**snapshot, operation=case["operation_intent"])
        assert request.digest() == case["request_digest"]
    assert len([case for case in cases if case["kind"] == "preview_final"]) == 2


def test_preview_final_cases_require_pairing_relationships() -> None:
    mapping = _manifest_mapping()
    for case in mapping["supplementary_cases"]:
        if case["kind"] == "preview_final":
            case.pop("pairing")

    with pytest.raises(ValueError, match="preview_final cases require pairing"):
        ScreeningManifest.from_mapping(mapping)


def test_screening_facade_preserves_manifest_schema_constants() -> None:
    from media_generation import screening

    assert screening.MANIFEST_SCHEMA == "media-generation.character-screening"
    assert screening.MANIFEST_VERSION == 1
    assert screening.MAX_MANIFEST_BYTES == 4 * 1024 * 1024


def _t07_candidate_identity(
    components: list[dict[str, object]],
    *,
    operations: dict[str, dict[str, list[str]]] | None = None,
) -> dict[str, object]:
    configuration: dict[str, object] = {
        "candidate_id": "t07-approved-candidate-1",
        "components": components,
    }
    if operations is not None:
        configuration["operations"] = operations
    return {
        "adapter_id": "stable-diffusion-cpp-local-v1",
        "adapter_configuration": configuration,
    }


def _candidate_components_for_variant(
    variant: dict[str, object],
) -> tuple[list[dict[str, object]], list[str]]:
    raw_components = variant["components"]
    assert isinstance(raw_components, list)
    fields = ("id", "role", "sha256", "precision", "quantization")
    candidate_components: list[dict[str, object]] = []
    selected_roles: list[str] = []
    for component in raw_components:
        assert isinstance(component, dict)
        candidate_components.append({field: component[field] for field in fields})
        selected_roles.append(str(component["role"]))
    return candidate_components, selected_roles


def _candidate_component_with_role(role: str) -> dict[str, object]:
    return {
        "id": f"candidate-{role}",
        "role": role,
        "sha256": "e" * 64,
        "precision": "fp16",
        "quantization": "none",
    }


def _candidate_runner(
    tmp_path: Path,
    variant: dict[str, object],
    *,
    operations: dict[str, dict[str, list[str]]],
    additional_roles: tuple[str, ...] = (),
) -> ScreeningRunner:
    candidate_components, _ = _candidate_components_for_variant(variant)
    candidate_components.extend(
        _candidate_component_with_role(role) for role in additional_roles
    )
    identity = _t07_candidate_identity(candidate_components, operations=operations)
    database = tmp_path / "generation.sqlite3"
    output = tmp_path / "artifacts"
    return ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=database,
        output_directory=output,
        execution_identity=identity,
        service_factory=lambda: GenerationService(
            database, output, adapter=DeterministicCpuAdapter()
        ),
        clock=lambda: 1000.0,
        lease_seconds=10,
        heartbeat_interval=None,
    )


def test_candidate_validation_rejects_a_missing_selected_component() -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    selected_components = variant["components"]
    assert isinstance(selected_components, list)
    selected_encoder = {
        "id": "selected-text-encoder",
        "role": "text_encoder",
        "path": "/models/selected-text-encoder.gguf",
        "size_bytes": 512,
        "sha256": "d" * 64,
        "precision": "fp16",
        "quantization": "fp16",
    }
    selected_components.append(selected_encoder)
    diffusion = {
        key: value
        for key, value in selected_components[0].items()
        if key in {"id", "role", "sha256", "precision", "quantization"}
    }
    auxiliary = {
        "id": "auxiliary-text-encoder",
        "role": "text_encoder",
        "sha256": "d" * 64,
        "precision": "fp16",
        "quantization": "fp16",
    }

    with pytest.raises(ScreeningConfigurationError, match="component"):
        _validate_variant_against_candidate(
            variant, _t07_candidate_identity([diffusion, auxiliary])
        )


@pytest.mark.parametrize(
    ("field", "candidate_value"),
    [("precision", "fp16"), ("quantization", "q8_0")],
)
def test_candidate_validation_checks_selected_precision_and_quantization(
    field: str, candidate_value: str
) -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    selected = dict(variant["components"][0])
    selected[field] = candidate_value
    auxiliary = {
        "id": "tokenizer",
        "role": "text_encoder",
        "sha256": "c" * 64,
        "precision": "fp32",
        "quantization": "none",
    }

    with pytest.raises(ScreeningConfigurationError, match="component"):
        _validate_variant_against_candidate(
            variant, _t07_candidate_identity([selected, auxiliary])
        )


def test_candidate_validation_allows_unselected_auxiliary_candidate_components() -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    candidate_components, selected_roles = _candidate_components_for_variant(variant)
    selected_role_set = set(selected_roles)
    auxiliary_role = next(
        role
        for role in ("tokenizer", "projector", "upscaler", "controlnet", "other")
        if role not in selected_role_set
    )
    candidate_components.append(_candidate_component_with_role(auxiliary_role))

    _validate_variant_against_candidate(
        variant,
        _t07_candidate_identity(
            candidate_components,
            operations={"generate": {"required_roles": selected_roles}},
        ),
        operation_intents=("generate",),
    )


@pytest.mark.parametrize("role", [None, "not-a-t07-role"])
def test_candidate_validation_rejects_malformed_unselected_candidate_role(
    role: object,
) -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    candidate_components, selected_roles = _candidate_components_for_variant(variant)
    malformed_auxiliary = _candidate_component_with_role("unused")
    malformed_auxiliary["role"] = role
    candidate_components.append(malformed_auxiliary)

    with pytest.raises(ScreeningConfigurationError, match="role"):
        _validate_variant_against_candidate(
            variant,
            _t07_candidate_identity(
                candidate_components,
                operations={"generate": {"required_roles": selected_roles}},
            ),
            operation_intents=("generate",),
        )


def test_candidate_validation_rejects_ambiguous_required_candidate_role() -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    candidate_components, selected_roles = _candidate_components_for_variant(variant)
    required_role = selected_roles[0]
    candidate_components.append(_candidate_component_with_role(required_role))

    with pytest.raises(ScreeningConfigurationError, match=required_role):
        _validate_variant_against_candidate(
            variant,
            _t07_candidate_identity(
                candidate_components,
                operations={"generate": {"required_roles": [required_role]}},
            ),
            operation_intents=("generate",),
        )


def test_candidate_validation_requires_frozen_operation_intents() -> None:
    variant = _manifest_mapping()["selected_model_variant"]
    assert isinstance(variant, dict)
    candidate_components, selected_roles = _candidate_components_for_variant(variant)

    with pytest.raises(ScreeningConfigurationError, match="operation intent"):
        _validate_variant_against_candidate(
            variant,
            _t07_candidate_identity(
                candidate_components,
                operations={"generate": {"required_roles": selected_roles}},
            ),
            operation_intents=(),
        )


def test_create_run_rejects_component_omitted_for_an_exercised_operation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    cases = build_case_definitions(manifest, run_id="run_" + "0" * 32)
    operation_intents = {str(case["operation_intent"]) for case in cases}
    assert {"generate", "edit"} <= operation_intents

    variant = manifest.to_dict()["selected_model_variant"]
    assert isinstance(variant, dict)
    _, selected_roles = _candidate_components_for_variant(variant)
    selected_role_set = set(selected_roles)
    omitted_role = next(
        role
        for role in ("vae", "vision_encoder", "text_encoder", "tokenizer")
        if role not in selected_role_set
    )
    runner = _candidate_runner(
        tmp_path,
        variant,
        operations={
            "generate": {"required_roles": [*selected_roles, omitted_role]},
            "edit": {"required_roles": [*selected_roles, omitted_role]},
        },
        additional_roles=(omitted_role,),
    )

    with pytest.raises(ScreeningConfigurationError, match=omitted_role):
        runner.create_run(manifest)


def test_candidate_validation_allows_unselected_component_not_required_by_operation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    cases = build_case_definitions(manifest, run_id="run_" + "0" * 32)
    operation_intents = {str(case["operation_intent"]) for case in cases}
    assert {"generate", "edit"} <= operation_intents
    variant = manifest.to_dict()["selected_model_variant"]
    assert isinstance(variant, dict)
    _, selected_roles = _candidate_components_for_variant(variant)
    selected_role_set = set(selected_roles)
    auxiliary_role = next(
        role
        for role in ("tokenizer", "projector", "upscaler", "controlnet", "other")
        if role not in selected_role_set
    )
    runner = _candidate_runner(
        tmp_path,
        variant,
        operations={
            "generate": {"required_roles": selected_roles},
            "edit": {"required_roles": selected_roles},
        },
        additional_roles=(auxiliary_role,),
    )
    runner.create_run(manifest)


def test_create_run_unions_mixed_generate_and_edit_requirements(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    cases = build_case_definitions(manifest, run_id="run_" + "0" * 32)
    operation_intents = {str(case["operation_intent"]) for case in cases}
    assert {"generate", "edit"} <= operation_intents
    variant = manifest.to_dict()["selected_model_variant"]
    assert isinstance(variant, dict)
    _, selected_roles = _candidate_components_for_variant(variant)
    selected_role_set = set(selected_roles)
    edit_only_role = next(
        role
        for role in ("vae", "vision_encoder", "text_encoder", "tokenizer")
        if role not in selected_role_set
    )
    runner = _candidate_runner(
        tmp_path,
        variant,
        operations={
            "generate": {"required_roles": selected_roles},
            "edit": {"required_roles": [*selected_roles, edit_only_role]},
        },
        additional_roles=(edit_only_role,),
    )

    with pytest.raises(ScreeningConfigurationError, match=edit_only_role):
        runner.create_run(manifest)


def test_unpinned_real_engine_identity_cannot_skip_candidate_validation() -> None:
    variant = _manifest_mapping()["selected_model_variant"]

    for identity in (
        {
            "adapter_id": "stable-diffusion-cpp-local-v1",
            "adapter_configuration": {"revision": "untracked"},
        },
        {
            "adapter_id": DeterministicCpuAdapter.adapter_id,
            "adapter_configuration": {"engine": "untracked"},
        },
    ):
        with pytest.raises(ScreeningConfigurationError, match="candidate"):
            _validate_variant_against_candidate(variant, identity)


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda data: data["reference_styles"].pop(), "exactly three"),
        (lambda data: data["scenario_changes"].pop(), "exactly four"),
        (lambda data: data.update(seeds=[17]), "exactly two"),
        (lambda data: data.update(seeds=[17, 17]), "distinct"),
        (
            lambda data: data["reference_styles"][1].update(id=data["reference_styles"][0]["id"]),
            "unique",
        ),
        (
            lambda data: data["reference_styles"][0].update(roles=["source"]),
            "operation intent",
        ),
        (
            lambda data: data["selected_model_variant"]["components"][0].update(
                path="models/diffusion.gguf"
            ),
            "absolute local path",
        ),
        (
            lambda data: data["reference_styles"][1].update(
                artifact_ids=list(data["reference_styles"][0]["artifact_ids"]),
                sha256=list(data["reference_styles"][0]["sha256"]),
                roles=list(data["reference_styles"][0]["roles"]),
            ),
            "distinct conditioning inputs",
        ),
        (
            lambda data: data["scenario_changes"][1].update(
                prompt=data["scenario_changes"][0]["prompt"],
                operation_intent=data["scenario_changes"][0]["operation_intent"],
            ),
            "distinct prompts and operations",
        ),
    ],
)
def test_manifest_rejects_invalid_matrix_and_conditioning(edit, message: str) -> None:
    mapping = _manifest_mapping()
    edit(mapping)
    with pytest.raises(ValueError, match=message):
        ScreeningManifest.from_mapping(mapping)


def test_ledger_persists_all_requests_before_any_service_call_and_new_runs_get_new_keys(
    tmp_path: Path,
) -> None:
    runner, _, _ = _runner(tmp_path)
    first = runner.create_run(_manifest())
    second = runner.create_run(_manifest())

    first_cases = runner.ledger.list_cases(first)
    second_cases = runner.ledger.list_cases(second)
    assert len(first_cases) == len(second_cases) == 34
    assert all(case["status"] == "pending" for case in first_cases)
    assert all(case["request_digest"] for case in first_cases)
    assert all(case["idempotency_key"] for case in first_cases)
    assert {case["idempotency_key"] for case in first_cases}.isdisjoint(
        {case["idempotency_key"] for case in second_cases}
    )
    assert first != second


def test_sqlite_claim_fences_second_runner_and_stale_owner(tmp_path: Path) -> None:
    runner, _, _ = _runner(tmp_path / "execution")
    ledger = runner.ledger
    run_id = runner.create_run(_manifest())
    case = runner.ledger.list_cases(run_id)[0]

    first = ledger.claim_case(run_id, case["case_id"], "runner-a", now=10.0, lease_seconds=5.0)
    assert first is not None
    assert ledger.claim_case(run_id, case["case_id"], "runner-b", now=11.0, lease_seconds=5.0) is None

    second = ledger.claim_case(run_id, case["case_id"], "runner-b", now=16.0, lease_seconds=5.0)
    assert second is not None
    assert second.claim_epoch == first.claim_epoch + 1
    with pytest.raises(RuntimeError, match="claim was lost"):
        ledger.set_case_status(first, "succeeded", now=17.0)


def test_resume_reconciles_acceptance_after_runner_termination_without_duplicate_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current_time = [1000.0]
    runner, db, output = _runner(tmp_path, clock=lambda: current_time[0])
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(service, mapping, "crash-window")
    manifest = ScreeningManifest.from_mapping(mapping)
    run_id = runner.create_run(manifest)
    original_submit = GenerationService.submit
    accepted = []

    def accept_then_terminate(self, *args, **kwargs):
        result = original_submit(self, *args, **kwargs)
        accepted.append(result)
        raise SystemExit("simulated runner termination after service acceptance")

    monkeypatch.setattr(GenerationService, "submit", accept_then_terminate)
    with pytest.raises(SystemExit, match="simulated runner termination"):
        runner.resume(run_id, max_cases=1)
    monkeypatch.setattr(GenerationService, "submit", original_submit)
    assert len(accepted) == 1
    jobs_after_acceptance = _job_count(db)

    current_time[0] += 11
    resumed = ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=db,
        output_directory=output,
        execution_identity={
            "adapter_id": "different-adapter",
            "adapter_configuration": {"revision": "changed"},
        },
        service_factory=None,
        clock=lambda: current_time[0],
        lease_seconds=10,
        heartbeat_interval=None,
    )
    report = resumed.resume(run_id, max_cases=1)
    case = report["matrix_cases"][0]
    assert case["status"] == "succeeded"
    assert case["job_id"] == accepted[0].job_id
    assert case["request_id"] == accepted[0].request_id
    assert _job_count(db) == jobs_after_acceptance


def test_read_only_lookup_does_not_create_service_database(tmp_path: Path) -> None:
    db = tmp_path / "not-created.sqlite3"
    assert GenerationService.lookup_existing_idempotency_key(db, "screening:key") is None
    assert not db.exists()


def test_read_only_lookup_reuses_existing_job_without_constructing_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "generation.sqlite3"
    output = tmp_path / "artifacts"
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    request = GenerationRequest(prompt="Existing lookup", seed=3, width=64, height=64)
    submitted = service.submit("screening:existing", request)

    def refuse_construction(*args, **kwargs):
        raise AssertionError("lookup must not construct a service or evaluate current policy")

    monkeypatch.setattr(GenerationService, "__init__", refuse_construction)

    original_connect = sqlite3.connect

    def connect_read_only(database, *args, **kwargs):
        assert kwargs.get("uri") is True
        assert "mode=ro" in str(database)
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect_read_only)
    assert GenerationService.lookup_existing_idempotency_key(db, "screening:existing") == (
        submitted.job_id,
        request.digest(),
    )


def test_reconciliation_fails_closed_on_a_persisted_key_with_different_digest(
    tmp_path: Path,
) -> None:
    runner, db, output = _runner(tmp_path)
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    manifest = _manifest()
    run_id = runner.create_run(manifest)
    case = runner.ledger.list_cases(run_id)[0]
    conflict_request = GenerationRequest(
        prompt="Different request under the benchmark key", seed=2, width=64, height=64
    )
    service.submit(str(case["idempotency_key"]), conflict_request)

    report = runner.resume(run_id, max_cases=1)
    observed = report["matrix_cases"][0]
    assert observed["status"] == "blocked"
    assert observed["error_code"] == "idempotency_digest_conflict"
    assert observed["request_digest"] != conflict_request.digest()
    assert _job_count(db) == 1


def test_intentionally_new_runs_receive_new_service_submission_identities(
    tmp_path: Path,
) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "fresh-runs")
    manifest = ScreeningManifest.from_mapping(mapping)

    first_run = runner.create_run(manifest)
    first = runner.resume(first_run, max_cases=1)["matrix_cases"][0]
    second_run = runner.create_run(manifest)
    second = runner.resume(second_run, max_cases=1)["matrix_cases"][0]

    assert first_run != second_run
    assert first["idempotency_key"] != second["idempotency_key"]
    assert first["request_id"] != second["request_id"]
    assert first["job_id"] != second["job_id"]
    assert _job_count(db) == 5


def test_resume_blocks_new_execution_with_changed_execution_identity(tmp_path: Path) -> None:
    runner, db, output = _runner(tmp_path)
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(service, mapping, "changed-identity")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    first_case = runner.ledger.list_cases(run_id)[0]
    assert first_case["definition"]["fixture_preflight"]["status"] == "ready"
    jobs_before_resume = _job_count(db)
    changed = ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=db,
        output_directory=output,
        execution_identity={
            "adapter_id": "different-adapter",
            "adapter_configuration": {"revision": "changed"},
        },
        service_factory=None,
        clock=lambda: 1000.0,
        lease_seconds=10,
        heartbeat_interval=None,
    )
    assert changed.execution_identity != runner.execution_identity
    report = changed.resume(run_id, max_cases=1)
    case = report["matrix_cases"][0]
    assert case["status"] == "blocked"
    assert case["error_code"] == "resume_configuration_mismatch"
    assert case["benchmark_status"] == "blocked"
    assert case["service_status"] is None
    assert not runner.ledger.list_cases(run_id)[0]["submission_started"]
    assert _job_count(db) == jobs_before_resume


def test_unavailable_resume_preserves_blocked_outcome_and_queued_service_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, db, output = _runner(tmp_path)
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(service, mapping, "queued-recovery")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    case = runner.ledger.list_cases(run_id)[0]
    request = GenerationRequest(
        **case["request"], operation=str(case["operation_intent"])
    )
    original = service.enqueue(str(case["idempotency_key"]), request)
    assert original.status == "queued"
    jobs_before_resume = _job_count(db)

    unavailable = ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=db,
        output_directory=output,
        execution_identity=None,
        service_factory=None,
        clock=lambda: 1000.0,
        lease_seconds=10,
        heartbeat_interval=None,
    )
    report = unavailable.resume(run_id, max_cases=1)
    observed = report["matrix_cases"][0]

    assert observed["status"] == "blocked"
    assert observed["benchmark_status"] == "blocked"
    assert observed["service_status"] == "queued"
    assert report["matrix_execution"]["status"] == "incomplete"
    assert report["matrix_execution"]["unresolved"] == 24
    assert observed["error_code"] == "resume_configuration_mismatch"
    assert "changed or unavailable inputs block further execution" in observed["reason"]
    assert observed["job_id"] == original.job_id
    assert not runner.ledger.list_cases(run_id)[0]["submission_started"]
    assert SQLiteStore(db).get_job(original.job_id).execution_status == "queued"
    assert _job_count(db) == jobs_before_resume

    def fail_read_only_lookup(*_args: object) -> None:
        raise sqlite3.OperationalError("database unavailable")

    monkeypatch.setattr(
        GenerationService,
        "lookup_existing_idempotency_key",
        fail_read_only_lookup,
    )
    reconciled = unavailable.report(run_id)["matrix_cases"][0]
    assert reconciled["status"] == "blocked"
    assert reconciled["benchmark_status"] == "blocked"
    assert reconciled["error_code"] == observed["error_code"]
    assert reconciled["reason"] == observed["reason"]
    assert reconciled["service_reconciliation_error"]["error_code"] == (
        "service_lookup_unavailable"
    )


@pytest.mark.parametrize("wrong_location", ["database", "output"])
def test_runner_rejects_service_factory_paths_outside_frozen_identity(
    tmp_path: Path, wrong_location: str
) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, f"wrong-service-{wrong_location}")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    jobs_before_resume = _job_count(db)

    service_database = db
    output_directory = output
    if wrong_location == "database":
        service_database = tmp_path / "foreign.sqlite3"
    else:
        output_directory = tmp_path / "foreign-artifacts"
    foreign_service = GenerationService(
        service_database, output_directory, adapter=DeterministicCpuAdapter()
    )
    runner.service_factory = lambda: foreign_service

    report = runner.resume(run_id, max_cases=1)
    case = report["matrix_cases"][0]
    assert case["status"] == "blocked"
    assert case["error_code"] == "screening_configuration_error"
    assert not runner.ledger.list_cases(run_id)[0]["submission_started"]
    assert _job_count(db) == jobs_before_resume


def test_report_keeps_all_24_matrix_cases_in_the_denominator_when_unexecuted(
    tmp_path: Path,
) -> None:
    runner, _, _ = _runner(tmp_path)
    run_id = runner.create_run(_manifest())
    report = runner.resume(run_id, max_cases=0)
    assert report["status"] == "available"
    assert report["matrix_execution"]["status"] == "incomplete"
    assert report["matrix_execution"]["execution_success"] is None
    assert report["summary"]["matrix_denominator"] == 24
    assert report["summary"]["matrix_accounted"] == 24
    assert report["summary"]["matrix_status_counts"] == {"blocked": 24}
    assert report["apex_execution"]["status"] == "unverified"
    assert report["qualification"]["status"] == "unverified"


def test_report_cli_succeeds_for_an_incomplete_run_without_qualification_claim(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from media_generation.cli import main

    runner, _, _ = _runner(tmp_path)
    run_id = runner.create_run(_manifest())

    result = main(
        [
            "screen",
            "report",
            "--run-id",
            run_id,
            "--data-dir",
            str(tmp_path / "screening-data"),
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert result == 0
    assert report["status"] == "available"
    assert report["matrix_execution"]["status"] == "incomplete"
    assert report["apex_execution"]["status"] == "unverified"
    assert report["qualification"]["status"] == "unverified"


def test_fixture_fingerprint_mismatch_blocks_before_service_admission(tmp_path: Path) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "fixture-mismatch", incorrect_digests=True)
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))

    report = runner.resume(run_id, max_cases=1)
    case = report["matrix_cases"][0]
    assert case["status"] == "blocked"
    assert case["error_code"] == "fixture_fingerprint_unverified"
    assert not runner.ledger.list_cases(run_id)[0]["submission_started"]
    assert _job_count(db) == 3


def test_complete_deterministic_cpu_matrix_does_not_claim_apex_qualification(
    tmp_path: Path,
) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "complete-cpu-matrix")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))

    report = runner.resume(run_id)

    assert report["status"] == "available"
    assert report["summary"]["matrix_denominator"] == 24
    assert report["summary"]["matrix_accounted"] == 24
    assert report["matrix_execution"] == {
        "status": "complete",
        "denominator": 24,
        "accounted": 24,
        "completed": 24,
        "successful": 24,
        "failed": 0,
        "unresolved": 0,
        "execution_success": True,
    }
    assert report["apex_execution"]["status"] == "unverified"
    assert report["qualification"]["status"] == "unverified"
    assert len(report["supplementary_cases"]) == 10


def test_unsupported_adapter_capability_is_a_terminal_unsupported_case(tmp_path: Path) -> None:
    class NoReferenceAdapter(DeterministicCpuAdapter):
        capabilities = AdapterCapabilities(
            max_width=256,
            max_height=256,
            supports_references=False,
            max_references=0,
        )

    db = tmp_path / "generation.sqlite3"
    output = tmp_path / "artifacts"
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "unsupported-case")
    adapter_service = GenerationService(db, output, adapter=NoReferenceAdapter())
    runner = ScreeningRunner(
        data_directory=tmp_path / "screening-data",
        service_database=db,
        output_directory=output,
        execution_identity=_cpu_identity(adapter_service, db, output),
        service_factory=lambda: adapter_service,
        clock=lambda: 1000.0,
        lease_seconds=10,
        heartbeat_interval=None,
    )
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))

    report = runner.resume(run_id, max_cases=1)
    case = report["matrix_cases"][0]
    assert case["status"] == "unsupported"
    assert case["error_code"] == "unsupported_capability"
    assert case["execution_succeeded"] is None
    assert _job_count(db) == 3


@pytest.mark.parametrize(
    ("replacement", "expected_integrity"),
    [(b"corrupt published media", "corrupt"), (None, "missing")],
)
def test_report_separates_execution_from_artifact_integrity_and_never_replaces(
    tmp_path: Path, replacement: bytes | None, expected_integrity: str
) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "artifact-check")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    first_report = runner.resume(run_id, max_cases=1)
    first_case = first_report["matrix_cases"][0]
    assert first_case["status"] == "succeeded"
    artifact = SQLiteStore(db).get_artifact(first_case["artifact_id"])
    if replacement is None:
        Path(artifact.path).unlink()
    else:
        Path(artifact.path).write_bytes(replacement)

    refreshed = runner.report(run_id)
    refreshed_case = refreshed["matrix_cases"][0]
    assert refreshed_case["execution_status"] == "succeeded"
    assert refreshed_case["execution_succeeded"] is True
    assert refreshed_case["artifact_integrity"]["status"] == expected_integrity
    assert _job_count(db) == 4


def test_recovery_and_report_inspect_artifacts_without_writing_integrity_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, db, output = _runner(tmp_path)
    setup = GenerationService(db, runner.output_directory, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(setup, mapping, "read-only-integrity")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    case = runner.ledger.list_cases(run_id)[0]
    request = GenerationRequest(
        **case["request"], operation=str(case["operation_intent"])
    )
    setup.submit(str(case["idempotency_key"]), request)
    resumer = ScreeningRunner(
        data_directory=runner.data_directory,
        service_database=db,
        output_directory=output,
        execution_identity=None,
        service_factory=None,
        clock=runner.clock,
    )

    writes: list[tuple[object, ...]] = []
    original = SQLiteStore.record_integrity

    def track_integrity_write(store: SQLiteStore, *args: object) -> None:
        writes.append(args)
        original(store, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(SQLiteStore, "record_integrity", track_integrity_write)

    recovered = resumer.resume(run_id, max_cases=1)
    reported = resumer.report(run_id)

    assert recovered["matrix_cases"][0]["artifact_integrity"]["status"] == "ok"
    assert reported["matrix_cases"][0]["artifact_integrity"]["status"] == "ok"
    assert writes == []


def test_report_does_not_create_a_missing_generation_service_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, db, output = _runner(tmp_path)
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(service, mapping, "missing-service-db")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    case = runner.ledger.list_cases(run_id)[0]
    request = GenerationRequest(
        **case["request"], operation=str(case["operation_intent"])
    )
    service.submit(str(case["idempotency_key"]), request)

    original_lookup = GenerationService.lookup_existing_idempotency_key
    removed_database = False

    def remove_database_after_lookup(
        database_path: Path, idempotency_key: str
    ) -> tuple[str, str] | None:
        nonlocal removed_database
        existing = original_lookup(database_path, idempotency_key)
        if existing is not None and not removed_database:
            Path(database_path).unlink()
            removed_database = True
        return existing

    monkeypatch.setattr(
        GenerationService,
        "lookup_existing_idempotency_key",
        staticmethod(remove_database_after_lookup),
    )

    report = runner.report(run_id)

    assert removed_database
    assert not db.exists()
    assert (
        report["matrix_cases"][0]["service_reconciliation_error"]["error_code"]
        == "service_job_unavailable"
    )


def test_matrix_summary_counts_benchmark_status_separately_from_service_execution(
    tmp_path: Path,
) -> None:
    runner, db, output = _runner(tmp_path)
    service = GenerationService(db, output, adapter=DeterministicCpuAdapter())
    mapping = _manifest_mapping()
    _pin_distinct_references(service, mapping, "separate-matrix-statuses")
    run_id = runner.create_run(ScreeningManifest.from_mapping(mapping))
    case = runner.ledger.list_cases(run_id)[0]
    request = GenerationRequest(
        **case["request"], operation=str(case["operation_intent"])
    )
    service.submit(str(case["idempotency_key"]), request)

    report = runner.report(run_id)
    observed = next(
        item for item in report["matrix_cases"] if item["case_id"] == case["case_id"]
    )
    expected_status_counts: dict[str, int] = {}
    for item in report["matrix_cases"]:
        status = str(item["benchmark_status"])
        expected_status_counts[status] = expected_status_counts.get(status, 0) + 1

    assert observed["benchmark_status"] == case["status"]
    assert observed["service_execution_status"] == "succeeded"
    assert report["summary"]["matrix_status_counts"] == expected_status_counts
    assert report["matrix_execution"]["completed"] == 1
    assert report["matrix_execution"]["successful"] == 1
    assert report["matrix_execution"]["unresolved"] == 23


def test_supplementary_report_keeps_conditioning_separate_from_origin_and_pairing() -> None:
    manifest = _manifest()
    cases = build_case_definitions(manifest, run_id="run_" + "0" * 32)
    preview = next(case for case in cases if case["label"] == "Experimental preview profile")
    assert [item["artifact_id"] for item in preview["conditioning_inputs"]] == [ARTIFACT_IDS[0]]
    assert preview["creative_origin_artifact_ids"] == [ARTIFACT_IDS[1]]
    assert preview["pairing"] == {"pair_id": "preview-final-1", "role": "preview"}
    chain = [case for case in cases if case["kind"] == "chain"]
    assert [case["supplementary_metadata"]["chain_step"] for case in chain] == [1, 2]


def test_canonical_generation_request_digest_contract_is_unchanged() -> None:
    request = GenerationRequest(
        prompt="Same canonical request",
        seed=7,
        width=64,
        height=64,
        reference_ids=(ARTIFACT_IDS[0],),
        reference_roles=("reference",),
        output_slot="main",
        operation="generate",
    )
    without_operation = GenerationRequest(
        prompt="Same canonical request",
        seed=7,
        width=64,
        height=64,
        reference_ids=(ARTIFACT_IDS[0],),
        reference_roles=("reference",),
        output_slot="main",
    )
    assert "operation" not in request.to_dict()
    assert request.to_dict() == without_operation.to_dict()
    assert request.digest() == without_operation.digest()
