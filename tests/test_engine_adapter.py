"""Focused contracts for the pinned local stable-diffusion.cpp adapter."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from media_generation import cli, engine
from media_generation.adapters import (
    BACKEND_EXECUTION_CONTRACT_VERSION,
    AdapterCapabilities,
    backend_execution_contract,
)
from media_generation.candidate import parse_candidate
from media_generation.domain import GenerationPlan, GenerationRequest, ResolvedReference
from media_generation.errors import (
    BackendEvidenceError,
    BackendPreparationError,
    GenerationError,
    InputValidationError,
    PrivacyComplianceError,
    RecordNotFoundError,
    UnsupportedCapabilityError,
)
from media_generation.privacy import (
    APPLICATION_PRIVACY_REGISTRY,
    DEFAULT_PRIVACY_POLICY,
    LOCAL_INFERENCE_CONFIGURATION_VERSION,
    LOCAL_INFERENCE_ENGINE_VERSION,
    PrivacyComplianceStatus,
    PrivacyControl,
    application_privacy_policy,
    application_privacy_profile,
    invocation_privacy_settings,
)
from media_generation.service import GenerationService
from media_generation.supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)
from test_t08_support import (
    EngineBundle,
    build_bundle,
    default_recipe_document,
    heavy_admission_profile,
    heavy_workload_demand,
)

RUNTIME = {
    "platform": "linux",
    "machine": "x86_64",
    "rocm_path": "/opt/rocm",
    "rocm_version": "6.4.0",
    "amdgpu_version": "6.12.0",
    "hsa_override_gfx_version": None,
    "hip_visible_devices": "0",
}


@pytest.fixture(autouse=True)
def synthetic_rocm_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply deterministic read-only runtime evidence on any test host."""
    monkeypatch.setattr(
        engine, "capture_runtime_fingerprint", lambda: dict(RUNTIME)
    )


def _adapter(bundle: EngineBundle, output_directory: Path) -> engine.StableDiffusionCppAdapter:
    return engine.StableDiffusionCppAdapter(
        candidate_path=bundle.declaration_path,
        output_directory=output_directory,
        trusted_evidence_path=bundle.trusted_evidence_path,
    )


def _request(**overrides: object) -> GenerationRequest:
    values: dict[str, object] = {
        "prompt": "a red cube",
        "seed": 7,
        "width": 64,
        "height": 64,
    }
    values.update(overrides)
    return GenerationRequest(**values)  # type: ignore[arg-type]


def _reference(tmp_path: Path, name: str, role: str = "reference") -> ResolvedReference:
    path = tmp_path / name
    data = f"reference-bytes-{name}".encode()
    path.write_bytes(data)
    identifier = "art_" + hashlib.sha256(name.encode()).hexdigest()[:32]
    return ResolvedReference(
        artifact_id=identifier,
        content_sha256=hashlib.sha256(data).hexdigest(),
        path=path,
        role=role,
    )


def _plan(**overrides: object) -> GenerationPlan:
    values: dict[str, object] = {
        "job_id": "job_fixture",
        "attempt_id": "att_fixture",
        "resolved_prompt": "a red cube",
        "seed": 7,
    "width": 64,
    "height": 64,
        "references": (),
        "output_slot": "primary",
        "output_slot_id": "slot_fixture",
    }
    values.update(overrides)
    return GenerationPlan(**values)  # type: ignore[arg-type]


class _RecordingAuthority(ExecutionEvidenceAuthority):
    """Retain app-owned supervisor facts for assertions."""

    def __init__(self, attempt_id: str) -> None:
        self._attempt_id = attempt_id
        self.launches: list[LaunchFact] = []
        self.observations: list[ProcessObservation] = []

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    def verify_current(self) -> bool:
        return True

    def record_launch(self, fact: LaunchFact) -> None:
        assert isinstance(fact, LaunchFact)
        self.launches.append(fact)

    def record_observation(self, fact: ProcessObservation) -> None:
        assert isinstance(fact, ProcessObservation)
        self.observations.append(fact)


def _run(prepared: engine.ResolvedExecution) -> tuple[object, list[object]]:
    authority = _RecordingAuthority(prepared.attempt_id)
    supervisor = _supervisor(prepared, authority)
    observation = supervisor.run(
        prepared.argv,
        env=prepared.environment,
        cwd=prepared.scratch_directory,
    )
    return observation, authority.launches + authority.observations


def _supervisor(
    prepared: engine.ResolvedExecution,
    authority: ExecutionEvidenceAuthority | None = None,
) -> ProcessSupervisor:
    return ProcessSupervisor(
        authority or _RecordingAuthority(prepared.attempt_id),
        expected_argv=prepared.argv,
        expected_environment=prepared.environment,
        drain_timeout_seconds=0.2,
    )


def test_supervisor_converts_invalid_argv_to_preparation_failure(
    tmp_path: Path,
) -> None:
    """A Popen ValueError is a proven no-spawn preparation failure."""

    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    prepared = adapter.resolve_execution(_plan())
    try:
        assert prepared.scratch_directory.exists()
        argv = (*prepared.argv, "\x00")
        authority = _RecordingAuthority(prepared.attempt_id)
        supervisor = ProcessSupervisor(
            authority,
            expected_argv=argv,
            expected_environment=prepared.environment,
        )
        with pytest.raises(BackendPreparationError) as failed:
            supervisor.run(
                argv,
                env=prepared.environment,
                cwd=prepared.scratch_directory,
            )
        assert failed.value.code == "engine_launch_failed"
        assert supervisor.process_started is False
        assert authority.launches == []
        assert authority.observations == []
    finally:
        adapter.cleanup_execution(prepared)


def test_conformance_fixture_parses_version_and_writes_valid_png(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    completed = subprocess.run(
        [str(bundle.engine_path), "--version"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0
    assert "conformance" in completed.stdout


def test_generate_argv_orders_components_and_references(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    report = tmp_path / "report.json"
    bundle.set_mode(report_path=str(report))
    adapter = _adapter(bundle, output)
    first = _reference(tmp_path, "first.png")
    second = _reference(tmp_path, "second.png")
    prepared = adapter.resolve_execution(
        _plan(references=(first, second))
    )
    observation, callbacks = _run(prepared)
    assert observation.exit_code == 0  # type: ignore[attr-defined]
    values = json.loads(report.read_text())
    assert values["references"] == [str(first.path), str(second.path)]
    assert values["model_args"] == []
    assert values["prompt"] == "a red cube"
    assert values["width"] == 64 and values["height"] == 64
    assert values["seed"] == 7
    assert values["steps"] == 8
    assert values["cfg_scale"] == 2.5
    assert values["flow_shift"] == 3.0
    assert values["sampling_method"] == "euler"
    assert "init_image" not in values
    assert "strength" not in values
    assert prepared.argv.index("--diffusion-model") < prepared.argv.index("--vae")
    assert prepared.argv.index("--vae") < prepared.argv.index("--llm")
    assert [item.__class__.__name__ for item in callbacks] == [
        "LaunchFact",
        "ProcessObservation",
    ]


def test_vision_component_maps_to_llm_vision_argument(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, include_vision=True)
    output = tmp_path / "images"
    report = tmp_path / "report.json"
    bundle.set_mode(report_path=str(report))
    adapter = _adapter(bundle, output)
    source = _reference(tmp_path, "source.png", role="source")
    prepared = adapter.resolve_execution(_plan(references=(source,)))
    observation, _ = _run(prepared)
    assert observation.exit_code == 0  # type: ignore[attr-defined]
    values = json.loads(report.read_text())
    assert values["llm_vision"] == str(bundle.component_paths["vision_encoder"])
    assert prepared.argv.index("--llm") < prepared.argv.index("--llm_vision")


def test_qwen_edit_requires_model_roles_when_recipe_omits_them(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(
        tmp_path,
        component_roles=("diffusion_model", "vae"),
    )
    with pytest.raises(BackendPreparationError) as raised:
        _adapter(bundle, tmp_path / "images")
    assert raised.value.code == "bundle_incompatible"


def test_qwen_edit_refuses_declared_vision_role_the_edit_cannot_pass(
    tmp_path: Path,
) -> None:
    recipe = default_recipe_document(roles=("diffusion_model", "vae", "text_encoder"))
    bundle = build_bundle(
        tmp_path,
        component_roles=(
            "diffusion_model",
            "vae",
            "text_encoder",
            "vision_encoder",
        ),
        recipe_document=recipe,
    )
    with pytest.raises(BackendPreparationError) as raised:
        _adapter(bundle, tmp_path / "images")
    assert raised.value.code == "bundle_incompatible"


def test_qwen_edit_refuses_unmapped_declared_component_role(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path, extra_component_roles=("tokenizer",))
    with pytest.raises(BackendPreparationError) as raised:
        _adapter(bundle, tmp_path / "images")
    assert raised.value.code == "bundle_incompatible"


def test_edit_operation_keeps_source_in_ordered_ref_image_arguments(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    report = tmp_path / "report.json"
    bundle.set_mode(report_path=str(report))
    adapter = _adapter(bundle, output)
    reference = _reference(tmp_path, "reference.png")
    source = _reference(tmp_path, "source.png", role="source")
    prepared = adapter.resolve_execution(
        _plan(references=(reference, source))
    )
    observation, _ = _run(prepared)
    assert observation.exit_code == 0  # type: ignore[attr-defined]
    values = json.loads(report.read_text())
    assert values["references"] == [str(reference.path), str(source.path)]
    assert values["model_args"] == ["qwen_image_zero_cond_t=true"]
    assert "init_image" not in values
    assert "strength" not in values
    assert "-i" not in prepared.argv
    assert "--strength" not in prepared.argv


def test_qwen_edit_refuses_init_img_source_argument_and_strength(
    tmp_path: Path,
) -> None:
    legacy = default_recipe_document()
    legacy["operations"]["edit"]["source_image_argument"] = "init-img"  # type: ignore[index]
    with pytest.raises(BackendPreparationError) as refused:
        _adapter(build_bundle(tmp_path / "legacy", recipe_document=legacy), tmp_path / "out")
    assert refused.value.code == "recipe_invalid"

    with_strength = default_recipe_document(sampling={"strength": 0.65})
    bundle = build_bundle(tmp_path / "strength", recipe_document=with_strength)
    adapter = _adapter(bundle, tmp_path / "images")
    reference = _reference(tmp_path, "reference.png")
    source = _reference(tmp_path, "source.png", role="source")
    with pytest.raises(BackendPreparationError) as strength_refused:
        adapter.resolve_execution(_plan(references=(reference, source)))
    assert strength_refused.value.code == "operation_unsupported"


def test_missing_edit_operation_is_operation_unsupported(tmp_path: Path) -> None:
    recipe = default_recipe_document()
    del recipe["operations"]["edit"]  # type: ignore[index]
    bundle = build_bundle(tmp_path, recipe_document=recipe)
    adapter = _adapter(bundle, tmp_path / "images")
    source = _reference(tmp_path, "source.png", role="source")
    with pytest.raises(BackendPreparationError) as raised:
        adapter.resolve_execution(_plan(references=(source,)))
    assert raised.value.code == "operation_unsupported"


def test_application_execution_ceilings_refuse_unsafe_requests(tmp_path: Path) -> None:
    recipe = default_recipe_document()
    recipe["limits"] = {
        "max_width": 4096,
        "max_height": 4096,
        "max_references": 3,
        "max_source_images": 1,
    }
    bundle = build_bundle(tmp_path, recipe_document=recipe)
    adapter = _adapter(bundle, tmp_path / "images")
    references = tuple(_reference(tmp_path, f"limit-{index}.png") for index in range(4))
    sources = tuple(
        _reference(tmp_path, f"source-{index}.png", role="source") for index in range(2)
    )

    invalid_plans = (
        _plan(width=56, height=64),
        _plan(width=68, height=64),
        _plan(width=2056, height=64),
        _plan(width=64, height=64, references=references),
        _plan(width=64, height=64, references=sources),
    )
    for plan in invalid_plans:
        with pytest.raises(BackendPreparationError) as refused:
            adapter.resolve_execution(plan)
        assert refused.value.code == "operation_unsupported"


def test_bare_flag_contract_uses_documented_boolean_flag(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path, cli_contract="bare-flag/v1")
    output = tmp_path / "images"
    report = tmp_path / "report.json"
    bundle.set_mode(report_path=str(report))
    adapter = _adapter(bundle, output)
    source = _reference(tmp_path, "source.png", role="source")
    prepared = adapter.resolve_execution(_plan(references=(source,)))
    observation, _ = _run(prepared)
    assert observation.exit_code == 0  # type: ignore[attr-defined]
    values = json.loads(report.read_text())
    assert values["zero_conditioning_bare"] is True
    assert values["model_args"] == []
    assert "--model-args" not in prepared.argv


def test_strict_recipe_schema_rejects_unknown_keys_and_ranges(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    declaration = parse_candidate(bundle.declaration_path)

    def parse(payload: dict[str, object]) -> object:
        return engine._parse_recipe(
            (json.dumps(payload) + "\n").encode(), declaration=declaration
        )

    base = json.loads(bundle.recipe_path.read_text())
    unknown_top = json.loads(json.dumps(base))
    unknown_top["unexpected"] = True
    unknown_operation = json.loads(json.dumps(base))
    unknown_operation["operations"]["generate"]["unexpected"] = True  # type: ignore[index]
    bad_steps = json.loads(json.dumps(base))
    bad_steps["operations"]["generate"]["sampling"]["steps"] = 0  # type: ignore[index]
    bad_method = json.loads(json.dumps(base))
    bad_method["operations"]["generate"]["sampling"]["sampling_method"] = "bogus"  # type: ignore[index]
    bad_cfg_scale = json.loads(json.dumps(base))
    bad_cfg_scale["operations"]["generate"]["sampling"]["cfg_scale"] = 15.1  # type: ignore[index]
    bad_flow_shift = json.loads(json.dumps(base))
    bad_flow_shift["operations"]["generate"]["sampling"]["flow_shift"] = 10.1  # type: ignore[index]
    too_many_args = json.loads(json.dumps(base))
    too_many_args["operations"]["edit"]["model_args"] = [  # type: ignore[index]
        "qwen_image_zero_cond_t=true"
    ] * 9
    unknown_arg = json.loads(json.dumps(base))
    unknown_arg["operations"]["edit"]["model_args"] = ["other_key=true"]  # type: ignore[index]
    wrong_id = json.loads(json.dumps(base))
    wrong_id["id"] = "different-recipe"
    wrong_engine_id = json.loads(json.dumps(base))
    wrong_engine_id["engine_id"] = "different-engine"
    too_many_sources = json.loads(json.dumps(base))
    too_many_sources["limits"]["max_source_images"] = 2  # type: ignore[index]
    for payload in (
        unknown_top,
        unknown_operation,
        bad_steps,
        bad_method,
        bad_cfg_scale,
        bad_flow_shift,
        too_many_args,
        unknown_arg,
        wrong_id,
        wrong_engine_id,
        too_many_sources,
    ):
        with pytest.raises(BackendPreparationError) as raised:
            parse(payload)
        assert raised.value.code == "recipe_invalid"


def test_recipe_requires_matching_operator_declared_cli_contract(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    declaration = parse_candidate(bundle.declaration_path)
    engine_only = replace(
        declaration,
        recipe=replace(
            declaration.recipe,
            architecture_flags=(("qwen_image_zero_cond_t", True),),
        ),
    )
    with pytest.raises(BackendPreparationError) as missing:
        engine._cli_contract(engine_only)
    assert missing.value.code == "recipe_invalid"
    mismatched = replace(
        declaration,
        recipe=replace(
            declaration.recipe,
            architecture_flags=(
                ("sd_cpp_cli_contract", "bare-flag/v1"),
                ("qwen_image_zero_cond_t", True),
            ),
        ),
    )
    with pytest.raises(BackendPreparationError) as mismatch:
        engine._cli_contract(mismatched)
    assert mismatch.value.code == "bundle_incompatible"


def test_recipe_declaration_with_wrong_engine_id_is_bundle_incompatible(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    declaration = json.loads(json.dumps(bundle.declaration))
    declaration["recipe"]["engine_id"] = "different-engine"
    mutated = bundle.declaration_path.with_name("candidate-wrong-engine.json")
    mutated.write_text(json.dumps(declaration), encoding="utf-8")
    with pytest.raises(BackendPreparationError) as raised:
        engine.StableDiffusionCppAdapter(
            candidate_path=mutated,
            output_directory=tmp_path / "images",
            trusted_evidence_path=bundle.trusted_evidence_path,
        )
    assert raised.value.code == "bundle_incompatible"


def test_backend_contract_version_must_be_declared_directly(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")

    class InheritedExecutionAdapter(engine.StableDiffusionCppAdapter):
        """Inherit the implementation without declaring its protocol identity."""

    inherited = InheritedExecutionAdapter(
        candidate_path=bundle.declaration_path,
        output_directory=tmp_path / "images",
        trusted_evidence_path=bundle.trusted_evidence_path,
    )
    assert backend_execution_contract(adapter) == BACKEND_EXECUTION_CONTRACT_VERSION
    assert backend_execution_contract(inherited) is None


def test_service_capability_limits_cover_editing_sources_and_dimensions(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    adapter.capabilities = AdapterCapabilities(
        min_width=64,
        min_height=64,
        max_width=2048,
        max_height=2048,
        supports_references=True,
        max_references=3,
        supports_editing=True,
        max_source_images=1,
        dimension_multiple=8,
        supported_operations=frozenset({"generate", "edit"}),
    )
    service = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images", adapter)
    references = tuple(f"art_{index:032x}" for index in range(4))

    with pytest.raises(UnsupportedCapabilityError, match="width from 64"):
        service._validate_capabilities(_request(width=56, height=64))
    with pytest.raises(UnsupportedCapabilityError, match="multiples of 8"):
        service._validate_capabilities(_request(width=68, height=64))
    with pytest.raises(UnsupportedCapabilityError, match="width up to 2048"):
        service._validate_capabilities(_request(width=2056, height=64))
    with pytest.raises(UnsupportedCapabilityError, match="at most 3 reference"):
        service._validate_capabilities(
            _request(width=64, height=64, reference_ids=references)
        )

    adapter.capabilities = replace(
        adapter.capabilities,
        supports_editing=False,
        max_source_images=0,
    )
    source = GenerationRequest(
        "edit",
        width=64,
        height=64,
        reference_ids=(references[0],),
        reference_roles=("source",),
    )
    with pytest.raises(UnsupportedCapabilityError, match="does not support editing"):
        service._validate_capabilities(source)

    adapter.capabilities = replace(
        adapter.capabilities,
        supports_editing=True,
        max_source_images=0,
    )
    with pytest.raises(UnsupportedCapabilityError, match="at most 0 source images"):
        service._validate_capabilities(source)


def test_declaration_preparation_references_fail_closed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    declaration = json.loads(json.dumps(bundle.declaration))
    declaration["prepared_manifest"] = {"path": "prepared-manifest.json"}
    mutated = bundle.declaration_path.with_name("candidate-with-preparation.json")
    mutated.write_text(json.dumps(declaration), encoding="utf-8")
    with pytest.raises(BackendPreparationError) as referenced:
        engine.StableDiffusionCppAdapter(
            candidate_path=mutated,
            output_directory=output,
            trusted_evidence_path=bundle.trusted_evidence_path,
        )
    assert referenced.value.code == "bundle_corrupt"
    manifest = bundle.declaration_path.with_name("prepared-manifest.json")
    manifest.write_text(
        json.dumps(
            {
                "schema": "media-generation.candidate-preparation-manifest",
                "schema_version": 1,
                "candidate_id": "sha256:" + "0" * 64,
                "status": "ready",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(BackendPreparationError) as substituted:
        engine.StableDiffusionCppAdapter(
            candidate_path=manifest,
            output_directory=output,
            trusted_evidence_path=bundle.trusted_evidence_path,
        )
    assert substituted.value.code == "bundle_corrupt"


def test_candidate_refusals_use_stable_codes(tmp_path: Path) -> None:
    output = tmp_path / "images"
    with pytest.raises(BackendPreparationError) as missing:
        engine.StableDiffusionCppAdapter(
            candidate_path=tmp_path / "missing.json",
            output_directory=output,
        )
    assert missing.value.code == "bundle_missing"

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("not json")
    with pytest.raises(BackendPreparationError) as broken:
        engine.StableDiffusionCppAdapter(
            candidate_path=corrupt,
            output_directory=output,
        )
    assert broken.value.code == "bundle_corrupt"

    bundle = build_bundle(tmp_path / "unverified")
    unverified_adapter = engine.StableDiffusionCppAdapter(
        candidate_path=bundle.declaration_path,
        output_directory=output,
    )
    with pytest.raises(BackendPreparationError) as unverified:
        unverified_adapter.resolve_execution(_plan())
    assert unverified.value.code == "bundle_unverified"

    wrong_backend = build_bundle(tmp_path / "backend", backend="cuda")
    with pytest.raises(BackendPreparationError) as incompatible:
        _adapter(wrong_backend, output)
    assert incompatible.value.code == "bundle_incompatible"

    tokenizer = build_bundle(tmp_path / "tokenizer", include_tokenizer=True)
    with pytest.raises(BackendPreparationError) as unsupported_role:
        _adapter(tokenizer, output)
    assert unsupported_role.value.code == "recipe_invalid"


def test_changed_component_bytes_fail_closed_before_dispatch(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    adapter = _adapter(bundle, output)
    bundle.component_paths["vae"].write_bytes(b"changed-vae-bytes")
    with pytest.raises(BackendPreparationError) as raised:
        adapter.resolve_execution(_plan())
    assert raised.value.code == "bundle_corrupt"


def test_runtime_preflight_refuses_unverified_platform(tmp_path: Path, monkeypatch) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    monkeypatch.setattr(
        engine,
        "capture_runtime_fingerprint",
        lambda: {**RUNTIME, "platform": "darwin"},
    )
    with pytest.raises(BackendPreparationError) as platform:
        adapter.resolve_execution(_plan())
    assert platform.value.code == "runtime_platform_mismatch"
    monkeypatch.setattr(
        engine,
        "capture_runtime_fingerprint",
        lambda: {**RUNTIME, "rocm_version": None},
    )
    with pytest.raises(BackendPreparationError) as evidence:
        adapter.resolve_execution(_plan())
    assert evidence.value.code == "runtime_evidence_incomplete"


def test_qwen_edit_requires_zero_conditioning_model_argument(tmp_path: Path) -> None:
    recipe = default_recipe_document(edit_model_args=())
    bundle = build_bundle(tmp_path, recipe_document=recipe)
    adapter = _adapter(bundle, tmp_path / "images")
    source = _reference(tmp_path, "source.png", role="source")
    with pytest.raises(BackendPreparationError) as raised:
        adapter.resolve_execution(_plan(references=(source,)))
    assert raised.value.code == "recipe_invalid"


def test_scratch_is_private_outside_output_and_removed_after_cleanup(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    adapter = _adapter(bundle, output)
    prepared = adapter.resolve_execution(_plan())
    scratch = prepared.scratch_directory
    assert scratch.is_dir()
    assert (scratch.stat().st_mode & 0o777) == 0o700
    assert not scratch.is_relative_to(output.resolve())
    assert engine._git_worktree_root(scratch) is None
    adapter.cleanup_execution(prepared)
    assert not scratch.exists()


def test_execute_copies_validated_bytes_and_rejects_bad_images(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    adapter = _adapter(bundle, output)
    plan = _plan()
    prepared = adapter.resolve_execution(plan)
    scratch = prepared.scratch_directory
    destination = tmp_path / "staged.bin"
    with open(destination, "w+b") as handle:
        metadata = adapter.execute(plan, handle, supervisor=_supervisor(prepared))
        handle.seek(0)
        staged_bytes = handle.read()
    assert metadata.width == 64 and metadata.height == 64
    assert staged_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert not scratch.exists()

    bundle.set_mode(behavior="invalid_bytes")
    prepared = adapter.resolve_execution(plan)
    scratch = prepared.scratch_directory
    with open(destination, "w+b") as handle:
        with pytest.raises(GenerationError):
            adapter.execute(plan, handle, supervisor=_supervisor(prepared))
    assert not scratch.exists()


def test_execute_never_follows_symlinked_output(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    adapter = _adapter(bundle, output)
    plan = _plan()
    prepared = adapter.resolve_execution(plan)
    scratch = prepared.scratch_directory
    real = tmp_path / "real-output.png"
    Path(prepared.output_path).symlink_to(real)
    with open(tmp_path / "staged.bin", "w+b") as handle:
        with pytest.raises(GenerationError):
            adapter.execute(plan, handle, supervisor=_supervisor(prepared))
    assert not scratch.exists()


def test_remote_argv_token_cannot_produce_privacy_pass(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    settings = invocation_privacy_settings(
        [str(bundle.engine_path), "--server", "http://remote.example/endpoint"],
        {},
    )
    result = application_privacy_policy(adapter).evaluate(
        adapter.adapter_id,
        {
            "configuration_version": LOCAL_INFERENCE_CONFIGURATION_VERSION,
            "privacy": settings,
        },
    )
    assert result.status is PrivacyComplianceStatus.FAIL
    assert settings["remote_endpoint_or_proxy"] is True


def test_proxy_environment_cannot_produce_privacy_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        engine,
        "_child_environment",
        lambda: {"HTTP_PROXY": "http://proxy.example:8080"},
    )
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    with pytest.raises(PrivacyComplianceError) as failed:
        GenerationService(
            tmp_path / "proxy.sqlite3",
            tmp_path / "proxy-images",
            adapter=adapter,
            admission_profile=heavy_admission_profile(),
        )
    assert failed.value.result.status is PrivacyComplianceStatus.FAIL


def test_unknown_invocation_setting_stays_unverified(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    settings = invocation_privacy_settings(
        [str(bundle.engine_path), "--unmapped-option", "value"],
        {},
    )
    result = application_privacy_policy(adapter).evaluate(
        adapter.adapter_id,
        {
            "configuration_version": LOCAL_INFERENCE_CONFIGURATION_VERSION,
            "privacy": settings,
        },
    )
    assert result.status is PrivacyComplianceStatus.UNVERIFIED
    assert settings["telemetry"] is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("random", False),
        ("0", False),
        ("0001", False),
        ("4294967295", False),
        ("", None),
        ("Random", None),
        ("-1", None),
        ("4294967296", None),
        ("1.5", None),
        ("١", None),
    ],
)
def test_python_hash_seed_value_controls_privacy_confidence(
    value: str, expected: bool | None
) -> None:
    settings = invocation_privacy_settings(
        ["engine"], {"PYTHONHASHSEED": value}
    )

    assert set(settings.values()) == {expected}


def test_unverified_invocation_control_blocks_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unclassifiable environment setting keeps the attempt unverified and blocked."""
    monkeypatch.setattr(
        engine,
        "_child_environment",
        lambda: {"PATH": "/usr/bin", "UNKNOWN_SETTING": "1"},
    )
    bundle = build_bundle(tmp_path)
    with pytest.raises(PrivacyComplianceError) as failed:
        GenerationService(
            tmp_path / "unverified.sqlite3",
            tmp_path / "unverified-images",
            adapter=_adapter(bundle, tmp_path / "unverified-images"),
            admission_profile=heavy_admission_profile(),
        )

    assert failed.value.result.status is PrivacyComplianceStatus.UNVERIFIED


def test_resolved_privacy_map_must_match_recomputed_invocation(
    tmp_path: Path,
) -> None:
    """A tampered all-False privacy map cannot excuse a remote argv entry."""
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "gate.sqlite3",
        tmp_path / "gate-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    prepared = adapter.resolve_execution(_plan())
    remote_argv = [str(bundle.engine_path), "--server", "http://remote.example"]
    record = dict(prepared.resolved_record)
    record["argv"] = remote_argv
    record["privacy"] = {name: False for name in record["privacy"]}
    recomputed = invocation_privacy_settings(
        tuple(remote_argv), dict(prepared.environment)
    )
    assert recomputed["remote_endpoint_or_proxy"] is True
    tampered = replace(prepared, argv=tuple(remote_argv), resolved_record=record)

    with pytest.raises(PrivacyComplianceError) as failed:
        service._require_execution_privacy(tampered)

    assert "resolved_privacy_mismatch" in failed.value.result.reason_codes


def test_resolved_record_argv_must_match_prepared_invocation(tmp_path: Path) -> None:
    """A resolved record cannot describe a different argv than the prepared one."""
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "divergence.sqlite3",
        tmp_path / "divergence-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    prepared = adapter.resolve_execution(_plan())
    divergent = replace(prepared, argv=(*prepared.argv, "--server"))

    with pytest.raises(BackendEvidenceError):
        service._require_execution_privacy(divergent)


def test_tampered_resolved_privacy_is_rejected_before_insert_or_spawn(
    tmp_path: Path,
) -> None:
    """A tampered privacy map cannot reach the store or start a process."""
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "tampered.sqlite3",
        tmp_path / "tampered-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    prepared = adapter.resolve_execution(_plan())
    remote_argv = [str(bundle.engine_path), "--server", "http://remote.example"]
    record = dict(prepared.resolved_record)
    record["argv"] = remote_argv
    record["privacy"] = {name: False for name in record["privacy"]}
    tampered = replace(prepared, argv=tuple(remote_argv), resolved_record=record)
    adapter.resolve_execution = lambda plan: tampered  # type: ignore[method-assign]
    executed: list[str] = []

    def execute(plan, destination, *, supervisor):
        executed.append(plan.attempt_id)
        raise AssertionError("a tampered invocation must never spawn")

    adapter.execute = execute  # type: ignore[method-assign]
    queued = service.enqueue(
        "tampered-privacy",
        GenerationRequest("a red cube", seed=7, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    )

    report = service.work()

    assert report["processed"] == 1
    assert executed == []
    provenance = service.get_provenance(queued.job_id)
    assert provenance["status"] == "failed"
    assert provenance["backend_execution"] is None
    with pytest.raises(RecordNotFoundError):
        service.get_execution(queued.job_id)
    adapter.cleanup_execution(prepared)


def _substituted_execution(prepared: object, case: str) -> object:
    """Return one prepared execution with a single selected field replaced."""
    record = dict(prepared.resolved_record)
    argv = tuple(prepared.argv)
    if case == "benign_argv":
        argv = ("/bin/true",)
        record["argv"] = list(argv)
    elif case == "unrelated_executable":
        argv = (sys.executable, *argv[1:])
        record["argv"] = list(argv)
    elif case == "candidate_id":
        record["candidate_id"] = "sha256:" + "0" * 64
    elif case == "executable_sha256":
        record["engine"] = {**record["engine"], "executable_sha256": "0" * 64}
    elif case == "executable_bytes":
        source = Path(argv[0])
        substitute = source.parent.parent / "substitute" / source.name
        substitute.parent.mkdir(parents=True, exist_ok=True)
        substitute.write_bytes(b"#!/bin/sh\nexit 0\n")
        argv = (str(substitute), *argv[1:])
        record["argv"] = list(argv)
    elif case == "recipe_document_sha256":
        record["recipe"] = {**record["recipe"], "document_sha256": "0" * 64}
    elif case == "recipe_identity":
        record["recipe"] = {**record["recipe"], "id": "other-recipe"}
    elif case == "cli_contract":
        record["cli_contract"] = "other-contract/v1"
    elif case == "invocation_contract":
        record["invocation_contract"] = "other-contract/v1"
    elif case == "component_id":
        components = [dict(item) for item in record["components"]]
        components[0]["id"] = "substituted-component"
        record["components"] = components
    elif case == "component_role":
        components = [dict(item) for item in record["components"]]
        components[0]["role"] = "vision_encoder"
        record["components"] = components
    elif case == "component_sha256":
        components = [dict(item) for item in record["components"]]
        components[0]["sha256"] = "0" * 64
        record["components"] = components
    elif case == "empty_components":
        record["components"] = []
    elif case == "combined":
        argv = ("/bin/true",)
        record["argv"] = list(argv)
        record["candidate_id"] = "sha256:" + "0" * 64
        record["engine"] = {**record["engine"], "executable_sha256": "0" * 64}
        record["recipe"] = {**record["recipe"], "document_sha256": "0" * 64}
        record["components"] = []
    else:
        raise AssertionError(f"unknown substitution case {case!r}")
    return replace(prepared, argv=argv, resolved_record=record)


@pytest.mark.parametrize(
    "case",
    [
        "benign_argv",
        "unrelated_executable",
        "executable_bytes",
        "candidate_id",
        "executable_sha256",
        "recipe_document_sha256",
        "recipe_identity",
        "cli_contract",
        "invocation_contract",
        "component_id",
        "component_role",
        "component_sha256",
        "empty_components",
        "combined",
    ],
)
def test_substituted_resolved_execution_is_refused_before_insert_or_spawn(
    tmp_path: Path, case: str
) -> None:
    """A resolved record cannot replace the candidate selected at admission."""
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "substitution.sqlite3",
        tmp_path / "substitution-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    original_resolve = adapter.resolve_execution

    def resolve(plan: object) -> object:
        return _substituted_execution(original_resolve(plan), case)

    adapter.resolve_execution = resolve  # type: ignore[method-assign]
    executed: list[str] = []

    def execute(plan: object, destination: object, *, supervisor: object) -> object:
        executed.append(plan.attempt_id)  # type: ignore[attr-defined]
        raise AssertionError("a substituted execution must never spawn")

    adapter.execute = execute  # type: ignore[method-assign]
    queued = service.enqueue(
        f"substitution-{case}",
        GenerationRequest("a red cube", seed=7, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    )

    report = service.work()

    assert report["processed"] == 1
    assert executed == []
    provenance = service.get_provenance(queued.job_id)
    assert provenance["status"] == "failed"
    assert provenance["attempt"]["failure_class"] == "terminal"
    assert provenance["attempt"]["termination_proven"] is True
    assert provenance["backend_execution"] is None
    assert provenance["execution"]["failure_message"] == (
        "execution_preparation_failed: resolved_execution_mismatch"
    )
    assert service._store.resource_snapshot()["state"] == "available"
    with pytest.raises(RecordNotFoundError):
        service.get_execution(queued.job_id)


def test_privacy_gate_rejects_benign_argv_without_a_claim(tmp_path: Path) -> None:
    """A benign argv cannot pass because the adapter identity is registered."""
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "direct-substitution.sqlite3",
        tmp_path / "direct-substitution-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    prepared = adapter.resolve_execution(_plan())
    try:
        record = dict(prepared.resolved_record)
        record["argv"] = ["/bin/true"]
        tampered = replace(
            prepared, argv=("/bin/true",), resolved_record=record
        )

        with pytest.raises(BackendPreparationError) as failed:
            service._require_execution_privacy(tampered)

        assert failed.value.code == "resolved_execution_mismatch"
    finally:
        adapter.cleanup_execution(prepared)


def test_explicit_policy_cannot_override_backend_privacy_policy(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    with pytest.raises(ValueError, match="cannot replace"):
        GenerationService(
            tmp_path / "override.sqlite3",
            tmp_path / "override-images",
            adapter=adapter,
            privacy_policy=DEFAULT_PRIVACY_POLICY,
            admission_profile=heavy_admission_profile(),
        )


def test_static_configuration_is_restart_stable_and_candidate_bound(tmp_path: Path) -> None:
    first = build_bundle(tmp_path / "first")
    first_adapter = _adapter(first, tmp_path / "first" / "images")
    second_adapter = _adapter(first, tmp_path / "first" / "images")
    assert first_adapter.configuration == second_adapter.configuration
    serialized = json.dumps(first_adapter.configuration, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "verification_id" not in serialized
    assert first_adapter.configuration["candidate_id"].startswith("sha256:")
    resolved = first_adapter.resolve_execution(_plan())
    assert "verification_id" not in first_adapter.configuration
    assert resolved.resolved_record["verification_id"].startswith("sha256:")
    first_adapter.cleanup_execution(resolved)


def test_worker_candidate_mismatch_hard_errors_instead_of_falling_back(
    tmp_path: Path,
) -> None:
    first = build_bundle(tmp_path / "one")
    second = build_bundle(tmp_path / "two")
    declaration = json.loads(second.declaration_path.read_text())
    declaration["id"] = "t08-qwen-edit-2511-candidate-second"
    second.declaration_path.write_text(json.dumps(declaration))
    output = tmp_path / "images"
    first_service = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=_adapter(first, output),
        admission_profile=heavy_admission_profile(),
    )
    first_service.enqueue(
        "matching", _request(), workload_demand=heavy_workload_demand()
    )
    worker = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=_adapter(second, output),
        admission_profile=heavy_admission_profile(),
    )
    with pytest.raises(GenerationError):
        worker.work()


def test_reference_roles_reject_malformed_values() -> None:
    """Malformed role entries raise a validation error instead of a TypeError."""
    with pytest.raises(InputValidationError):
        GenerationRequest(
            prompt="a red cube",
            seed=7,
            width=64,
            height=64,
            reference_ids=("art_reference",),
            reference_roles=(["source"],),  # type: ignore[arg-type]
        )
    with pytest.raises(InputValidationError):
        GenerationRequest(
            prompt="a red cube",
            seed=7,
            width=64,
            height=64,
            reference_ids=("art_reference",),
        reference_roles=(1,),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("operation", [["generate"], {"intent": "generate"}])
def test_cli_non_string_operation_is_rejected_as_input_validation(
    operation: object,
) -> None:
    request = json.dumps({"prompt": "a red cube", "operation": operation})

    with pytest.raises(
        InputValidationError, match="operation must be generate or edit"
    ):
        cli._parse_request(request)


def test_request_digest_omits_all_reference_roles_and_binds_source() -> None:
    identifier = "art_" + "0" * 32
    without_roles = GenerationRequest(
        "same prompt", reference_ids=(identifier,)
    )
    explicit_default = GenerationRequest(
        "same prompt", reference_ids=(identifier,), reference_roles=("reference",)
    )
    source = GenerationRequest(
        "same prompt", reference_ids=(identifier,), reference_roles=("source",)
    )
    assert "reference_roles" not in without_roles.to_dict()
    assert "reference_roles" not in explicit_default.to_dict()
    assert without_roles.digest() == explicit_default.digest()
    assert explicit_default.digest() != source.digest()
    assert source.digest() == GenerationRequest(
        "same prompt", reference_ids=(identifier,), reference_roles=("source",)
    ).digest()


def test_explicit_edit_request_requires_exactly_one_source_image() -> None:
    with pytest.raises(
        InputValidationError, match="edit requests require exactly one source image"
    ):
        GenerationRequest("edit this image", operation="edit")


def test_explicit_edit_intent_preserves_the_existing_source_request_digest() -> None:
    identifier = "art_" + "1" * 32
    implicit_edit = GenerationRequest(
        "same prompt", reference_ids=(identifier,), reference_roles=("source",)
    )
    explicit_edit = GenerationRequest(
        "same prompt",
        reference_ids=(identifier,),
        reference_roles=("source",),
        operation="edit",
    )

    assert explicit_edit.digest() == implicit_edit.digest()
    assert "operation" not in explicit_edit.to_dict()


def test_cli_edit_intent_without_source_is_rejected_as_input_validation() -> None:
    with pytest.raises(
        InputValidationError, match="edit requests require exactly one source image"
    ):
        cli._parse_request('{"prompt":"edit this image","operation":"edit"}')


def test_engine_cli_is_opt_in_and_execution_command_returns_records(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = build_bundle(tmp_path)
    inventory = tmp_path / "inventory.json"
    policy = tmp_path / "policy.json"
    demand = tmp_path / "demand.json"
    inventory.write_text(json.dumps(__import__("test_resource_admission").inventory_report()))
    policy.write_text(
        json.dumps(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * 1024**3},
            }
        )
    )
    demand.write_text(json.dumps(__import__("test_resource_admission").workload_demand()))
    arguments = [
        "submit",
        "--db",
        str(tmp_path / "studio.sqlite3"),
        "--output-dir",
        str(tmp_path / "images"),
        "--idempotency-key",
        "engine",
        "--request-json",
        json.dumps({"prompt": "a red cube", "seed": 7, "width": 64, "height": 64}),
        "--inventory-report",
        str(inventory),
        "--admission-policy",
        str(policy),
        "--workload-demand",
        str(demand),
        "--engine-candidate",
        str(bundle.declaration_path),
        "--engine-trusted-evidence",
        str(bundle.trusted_evidence_path),
    ]
    assert cli.main(arguments) == 0
    submitted = json.loads(capsys.readouterr().out)
    assert submitted["status"] == "succeeded"
    assert (
        cli.main(
            [
                "execution",
                "--db",
                str(tmp_path / "studio.sqlite3"),
                "--job-id",
                submitted["job_id"],
            ]
        )
        == 0
    )
    execution = json.loads(capsys.readouterr().out)
    assert execution["state"] == "observed"
    assert execution["observed"]["direct_child_reaped"] is True
    assert execution["resolved"]["candidate_id"].startswith("sha256:")
    assert "--sampling-method" in execution["resolved"]["argv"]
    assert (
        cli.main(
            [
                "execution",
                "--db",
                str(tmp_path / "studio.sqlite3"),
                "--job-id",
                submitted["job_id"],
                "--attempt-id",
                execution["attempt_id"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == execution
    assert (
        cli.main(
            [
                "execution",
                "--db",
                str(tmp_path / "studio.sqlite3"),
                "--job-id",
                submitted["job_id"],
                "--attempt-id",
                "att_unknown",
            ]
        )
        == 4
    )
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "not_found"


def test_engine_cli_flags_require_candidate_and_are_not_global(
    tmp_path: Path,
) -> None:
    assert (
        cli.main(
            [
                "submit",
                "--db",
                str(tmp_path / "db.sqlite3"),
                "--output-dir",
                str(tmp_path / "images"),
                "--idempotency-key",
                "key",
                "--request-json",
                json.dumps({"prompt": "x"}),
                "--engine-trusted-evidence",
                str(tmp_path / "evidence.json"),
            ]
        )
        == 2
    )
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as rejected:
        parser.parse_args(
            [
                "request",
                "--db",
                "db.sqlite3",
                "--id",
                "req_x",
                "--engine-candidate",
                "candidate.json",
            ]
        )
    assert rejected.value.code == 2


def test_engine_cli_flags_are_available_on_enqueue_and_worker() -> None:
    parser = cli.build_parser()
    engine_arguments = [
        "--engine-candidate",
        "candidate.json",
        "--engine-trusted-evidence",
        "trusted.json",
    ]
    enqueue = parser.parse_args(
        [
            "enqueue",
            "--db",
            "db.sqlite3",
            "--output-dir",
            "images",
            "--idempotency-key",
            "key",
            "--request-json",
            json.dumps({"prompt": "x"}),
            *engine_arguments,
        ]
    )
    worker = parser.parse_args(
        [
            "worker",
            "--db",
            "db.sqlite3",
            "--output-dir",
            "images",
            *engine_arguments,
        ]
    )
    assert enqueue.engine_candidate == Path("candidate.json")
    assert worker.engine_trusted_evidence == Path("trusted.json")


def test_engine_enqueue_and_worker_use_persisted_admission_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = build_bundle(tmp_path)
    inventory = tmp_path / "inventory.json"
    policy = tmp_path / "policy.json"
    demand = tmp_path / "demand.json"
    inventory.write_text(json.dumps(__import__("test_resource_admission").inventory_report()))
    policy.write_text(
        json.dumps(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * 1024**3},
            }
        )
    )
    demand.write_text(json.dumps(__import__("test_resource_admission").workload_demand()))
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    engine_arguments = [
        "--engine-candidate",
        str(bundle.declaration_path),
        "--engine-trusted-evidence",
        str(bundle.trusted_evidence_path),
    ]
    assert (
        cli.main(
            [
                "enqueue",
                "--db",
                str(database),
                "--output-dir",
                str(output),
                "--idempotency-key",
                "engine-worker",
                "--request-json",
                json.dumps(
                    {"prompt": "a red cube", "seed": 7, "width": 64, "height": 64}
                ),
                "--inventory-report",
                str(inventory),
                "--admission-policy",
                str(policy),
                "--workload-demand",
                str(demand),
                *engine_arguments,
            ]
        )
        == 0
    )
    queued = json.loads(capsys.readouterr().out)
    assert queued["status"] == "queued"
    assert (
        cli.main(
            [
                "worker",
                "--db",
                str(database),
                "--output-dir",
                str(output),
                "--limit",
                "1",
                *engine_arguments,
            ]
        )
        == 0
    )
    worker = json.loads(capsys.readouterr().out)
    assert worker["status"] == "complete"
    assert worker["outcomes"][0]["execution_status"] == "succeeded"
    execution = GenerationService(database, output).get_execution(queued["job_id"])
    assert execution["state"] == "observed"


def test_cpu_default_is_unchanged_without_engine_flags(tmp_path: Path) -> None:
    service = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images")
    result = service.submit("cpu", GenerationRequest("plain", seed=1, width=12, height=9))
    provenance = service.get_provenance(result.job_id)
    assert provenance["adapter_id"] == "deterministic-cpu-png-v1"
    assert provenance["backend_execution"] is None


def test_lineage_records_source_role_and_preserves_source_bytes(tmp_path: Path) -> None:
    cpu = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images")
    seed = cpu.submit("seed", GenerationRequest("seed image", seed=2, width=16, height=16))
    source_path = Path(cpu.get_artifact(seed.artifact_id).path)
    before = source_path.read_bytes()

    bundle = build_bundle(tmp_path / "engine")
    output = tmp_path / "images"
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=_adapter(bundle, output),
        admission_profile=heavy_admission_profile(),
    )
    result = service.submit(
        "edit",
        GenerationRequest(
            "edit the source",
            seed=3,
            width=64,
            height=64,
            reference_ids=(seed.artifact_id,),
            reference_roles=("source",),
        ),
        workload_demand=heavy_workload_demand(),
    )
    lineage = service.get_lineage(result.artifact_id)
    assert lineage["parents"] == [
        {
            "source_id": seed.artifact_id,
            "target_id": result.artifact_id,
            "role": "source",
            "position": 0,
        }
    ]
    assert source_path.read_bytes() == before
    execution = service.get_execution(result.job_id)
    assert execution["resolved"]["conditioning"] == [
        {
            "artifact_id": seed.artifact_id,
            "role": "source",
            "content_sha256": hashlib.sha256(before).hexdigest(),
        }
    ]


def test_lineage_preserves_mixed_reference_role_order_and_source_bytes(
    tmp_path: Path,
) -> None:
    cpu = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images")
    reference_seed = cpu.submit(
        "reference seed", GenerationRequest("reference", seed=2, width=16, height=16)
    )
    source_seed = cpu.submit(
        "source seed", GenerationRequest("source", seed=3, width=16, height=16)
    )
    reference_path = Path(cpu.get_artifact(reference_seed.artifact_id).path)
    source_path = Path(cpu.get_artifact(source_seed.artifact_id).path)
    reference_bytes = reference_path.read_bytes()
    source_bytes = source_path.read_bytes()

    bundle = build_bundle(tmp_path / "engine")
    output = tmp_path / "images"
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=_adapter(bundle, output),
        admission_profile=heavy_admission_profile(),
    )
    identifiers = (reference_seed.artifact_id, source_seed.artifact_id)
    result = service.submit(
        "mixed edit",
        GenerationRequest(
            "edit with ordered conditioning",
            seed=4,
            width=64,
            height=64,
            reference_ids=identifiers,
            reference_roles=("reference", "source"),
        ),
        workload_demand=heavy_workload_demand(),
    )

    assert service.get_lineage(result.artifact_id)["parents"] == [
        {
            "source_id": identifiers[0],
            "target_id": result.artifact_id,
            "role": "reference",
            "position": 0,
        },
        {
            "source_id": identifiers[1],
            "target_id": result.artifact_id,
            "role": "source",
            "position": 1,
        },
    ]
    execution = service.get_execution(result.job_id)
    assert [item["artifact_id"] for item in execution["resolved"]["conditioning"]] == list(
        identifiers
    )
    assert reference_path.read_bytes() == reference_bytes
    assert source_path.read_bytes() == source_bytes

class _PassingAdapterPolicy:
    """Policy object an adapter supplies that reports a pass if consulted.

    The application must ignore it. It returns a genuine PASS result produced
    by the real policy machinery for an all-clear configuration, so any adapter
    that could win trust this way would let a failing engine configuration
    through.
    """

    profiles: tuple[()] = ()

    def __init__(self, passing: object) -> None:
        self._passing = passing
        self.calls = 0

    def evaluate(self, adapter_id: str, configuration: object) -> object:
        """Return the canned pass result and record that the object was used."""

        self.calls += 1
        return self._passing


def _identity_adapter(
    adapter: engine.StableDiffusionCppAdapter,
    *,
    adapter_id: str | None = None,
    engine_id: str | None = None,
    engine_version: str | None = None,
    configuration_version: object = LOCAL_INFERENCE_CONFIGURATION_VERSION,
) -> object:
    """Return a backend adapter whose declared identity can be edited per test."""

    configuration = dict(adapter.configuration)
    if engine_id is not None or engine_version is not None:
        configuration["engine"] = {
            **configuration["engine"],
            **({"id": engine_id} if engine_id is not None else {}),
            **({"version": engine_version} if engine_version is not None else {}),
        }
    configuration["configuration_version"] = configuration_version

    class _IdentityAdapter:
        backend_contract_version = BACKEND_EXECUTION_CONTRACT_VERSION
        capabilities = adapter.capabilities

        def __init__(self) -> None:
            self.adapter_id = adapter_id or adapter.adapter_id
            self.configuration = configuration

        def resolve_execution(self, plan: object) -> object:
            raise AssertionError("resolution must not start")

        def execute(self, plan: object, destination: object, *, supervisor: object):
            raise AssertionError("execution must not start")

    return _IdentityAdapter()


def test_application_registry_binds_the_declared_engine_adapter() -> None:
    registration = APPLICATION_PRIVACY_REGISTRY[engine.ADAPTER_ID]
    assert registration.tool_id == engine.SUPPORTED_ENGINE_ID
    assert registration.tool_version == LOCAL_INFERENCE_ENGINE_VERSION
    assert registration.configuration_version == LOCAL_INFERENCE_CONFIGURATION_VERSION


def test_adapter_supplied_policy_cannot_override_the_application_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permissive adapter policy cannot authorize a failing engine configuration."""

    monkeypatch.setattr(
        engine,
        "_child_environment",
        lambda: {"HTTP_PROXY": "http://proxy.example:8080"},
    )
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    clean_configuration = {
        "configuration_version": LOCAL_INFERENCE_CONFIGURATION_VERSION,
        "privacy": {control.value: False for control in PrivacyControl},
    }
    passing = application_privacy_policy(adapter).evaluate(
        adapter.adapter_id, clean_configuration
    )
    assert passing.status is PrivacyComplianceStatus.PASS
    permissive = _PassingAdapterPolicy(passing)
    adapter.privacy_policy = permissive  # type: ignore[attr-defined]

    with pytest.raises(PrivacyComplianceError) as failed:
        GenerationService(
            tmp_path / "permissive.sqlite3",
            tmp_path / "permissive-images",
            adapter=adapter,
            admission_profile=heavy_admission_profile(),
        )

    assert failed.value.result.status is PrivacyComplianceStatus.FAIL
    assert permissive.calls == 0


def test_unregistered_backend_identity_is_refused(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    with pytest.raises(ValueError, match="no application-owned privacy registration"):
        GenerationService(
            tmp_path / "unregistered.sqlite3",
            tmp_path / "unregistered-images",
            adapter=_identity_adapter(adapter, adapter_id="unregistered-engine-v1"),
            admission_profile=heavy_admission_profile(),
        )


def test_registered_backend_identity_requires_the_exact_engine(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    with pytest.raises(ValueError, match="engine does not match"):
        GenerationService(
            tmp_path / "wrong-engine.sqlite3",
            tmp_path / "wrong-engine-images",
            adapter=_identity_adapter(adapter, engine_id="other-engine"),
            admission_profile=heavy_admission_profile(),
        )
    with pytest.raises(ValueError, match="engine version"):
        GenerationService(
            tmp_path / "wrong-version.sqlite3",
            tmp_path / "wrong-version-images",
            adapter=_identity_adapter(adapter, engine_version=""),
            admission_profile=heavy_admission_profile(),
        )


def test_profile_binds_the_exact_declared_engine_version(tmp_path: Path) -> None:
    """The profile requires the exact engine version registered by the app."""

    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    exact = _identity_adapter(
        adapter, engine_version=LOCAL_INFERENCE_ENGINE_VERSION
    )
    profile = application_privacy_profile(exact.adapter_id, exact.configuration)
    assert profile.tool_version == LOCAL_INFERENCE_ENGINE_VERSION
    assert profile.adapter_id == adapter.adapter_id
    assert profile.configuration_version == LOCAL_INFERENCE_CONFIGURATION_VERSION

    wrong = _identity_adapter(
        adapter, engine_version="master-2099-01-01"
    )
    with pytest.raises(ValueError, match="engine version does not match"):
        application_privacy_profile(wrong.adapter_id, wrong.configuration)
    with pytest.raises(ValueError, match="engine version does not match"):
        GenerationService(
            tmp_path / "wrong-version.sqlite3",
            tmp_path / "wrong-version-images",
            adapter=wrong,
            admission_profile=heavy_admission_profile(),
        )

    for variant in (
        f"{LOCAL_INFERENCE_ENGINE_VERSION}-dirty",
        LOCAL_INFERENCE_ENGINE_VERSION[:-1],
        LOCAL_INFERENCE_ENGINE_VERSION.upper(),
    ):
        variant_adapter = _identity_adapter(adapter, engine_version=variant)
        with pytest.raises(ValueError, match="engine version does not match"):
            application_privacy_profile(
                variant_adapter.adapter_id, variant_adapter.configuration
            )


def test_dispatch_requires_the_exact_resolved_engine_identity(
    tmp_path: Path,
) -> None:
    """Dispatch refuses a resolved record whose engine identity diverges."""

    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    service = GenerationService(
        tmp_path / "dispatch-engine.sqlite3",
        tmp_path / "dispatch-engine-images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    prepared = adapter.resolve_execution(_plan())
    try:
        for update in (
            {"id": "other-engine"},
            {"version": "master-2099-01-01"},
        ):
            record = dict(prepared.resolved_record)
            record["engine"] = {**record["engine"], **update}
            tampered = replace(prepared, resolved_record=record)
            with pytest.raises(PrivacyComplianceError) as failed:
                service._require_execution_privacy(tampered)
            assert "resolved_engine_mismatch" in failed.value.result.reason_codes
    finally:
        adapter.cleanup_execution(prepared)


def test_registered_backend_identity_requires_the_exact_configuration_version(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    with pytest.raises(ValueError, match="configuration version does not match"):
        GenerationService(
            tmp_path / "wrong-config.sqlite3",
            tmp_path / "wrong-config-images",
            adapter=_identity_adapter(adapter, configuration_version="sd-cpp-local/v2"),
            admission_profile=heavy_admission_profile(),
        )
