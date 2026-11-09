"""ComfyUI adapter contract, transport, privacy, and refusal tests."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import signal
import sqlite3
import subprocess
import struct
import threading
import sys
import zlib
import select
import socket
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import cli
from media_generation import _comfyui_python_bootstrap as comfyui_python_bootstrap
from media_generation import comfyui_runtime_pins
from media_generation import service as service_module
from media_generation.backend_provenance import (
    canonical_json,
    validate_comfyui_qwen_conditioning_graph,
    validate_comfyui_source_conditioning_path,
    validate_resolved_record,
)
from media_generation.comfyui import (
    COMFYUI_INVOCATION_CONTRACT,
    ComfyUIAdapter,
    load_comfyui_candidate,
)
from media_generation.domain import GenerationPlan, GenerationRequest, ResolvedReference
from media_generation.errors import (
    AmbiguousBackendOutcome,
    BackendEvidenceError,
    BackendPreparationError,
    PrivacyComplianceError,
    ResourceBusyError,
    UnsupportedCapabilityError,
)
from media_generation._candidate_contract import CandidateValidationError
from media_generation import comfyui
from media_generation.privacy import (
    COMFYUI_CONFIGURATION_VERSION,
    PrivacyControl,
    PrivacyComplianceStatus,
    application_privacy_policy,
    comfyui_resolved_privacy_evidence,
    comfyui_invocation_privacy_settings,
)
from media_generation.service import GenerationService
from media_generation.supervisor import ManagedProcessControl

from test_t08_support import heavy_admission_profile, heavy_workload_demand
from test_t09_support import (
    SYNTHETIC_COMFYUI_TOOL_VERSION,
    allow_synthetic_runtime_for_tests,
    build_comfyui_bundle,
    recipe_document,
    synthetic_comfyui_runtime_roots_for_tests,
    synthetic_runtime_approval_for_tests,
    synthetic_child_environment_for_tests,
)


def test_synthetic_python_home_matches_resolved_interpreter_prefix() -> None:
    runtime_roots = {
        item["role"]: item["path"]
        for item in synthetic_comfyui_runtime_roots_for_tests()
    }
    interpreter = str(Path(sys.executable).resolve(strict=True))
    result = subprocess.run(
        [interpreter, "-P", "-s", "-S", "-c", "import sys; print(sys.prefix)"],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )

    assert runtime_roots["python_home"] == result.stdout.strip()


@pytest.fixture(autouse=True)
def _allow_only_synthetic_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    approval = synthetic_runtime_approval_for_tests()

    def load_synthetic_approval(*, verify_paths: bool = True) -> SimpleNamespace:
        assert verify_paths in {True, False}
        return approval

    monkeypatch.setattr(
        comfyui,
        "_require_independent_runtime_pin_binding",
        allow_synthetic_runtime_for_tests,
    )
    monkeypatch.setattr(
        comfyui,
        "_require_runtime_launch_binding",
        allow_synthetic_runtime_for_tests,
    )
    monkeypatch.setattr(
        comfyui,
        "_bind_child_node_implementations",
        lambda *_launch_inputs: None,
    )
    monkeypatch.setattr(
        comfyui,
        "_child_environment",
        synthetic_child_environment_for_tests,
    )
    monkeypatch.setattr(
        comfyui,
        "_load_runtime_pin_approval",
        load_synthetic_approval,
    )
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "load_runtime_pin_approval",
        load_synthetic_approval,
    )


def test_python_bootstrap_rejects_wrong_prefix_and_accepts_fixture_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval = synthetic_runtime_approval_for_tests()
    roots = {item["role"]: item["path"] for item in approval.payload["roots"]}
    python_home = roots["python_home"]
    python_imports = roots["python_imports"]
    comfyui_source = roots["comfyui_source"]
    python_base_prefix = approval.payload["python_base_prefix"]
    python_stdlib_paths = approval.payload["python_stdlib_paths"]
    entrypoint = str(Path(comfyui_source) / "comfyui-server.py")
    bootstrap_sys = SimpleNamespace(
        platform=sys.platform,
        flags=SimpleNamespace(safe_path=True, no_user_site=True, no_site=True),
        argv=[
            "bootstrap",
            python_home,
            python_base_prefix,
            "--stdlib-paths",
            *python_stdlib_paths,
            "--import-roots",
            python_imports,
            comfyui_source,
            "--",
            entrypoint,
        ],
        prefix=str(Path(python_home).parent / "unsigned-home"),
        exec_prefix=python_home,
        base_prefix=python_base_prefix,
        base_exec_prefix=python_base_prefix,
        path=list(python_stdlib_paths),
    )
    run_path_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(comfyui_python_bootstrap, "sys", bootstrap_sys)
    monkeypatch.setitem(
        sys.modules,
        "runpy",
        SimpleNamespace(
            run_path=lambda path, run_name: run_path_calls.append((path, run_name))
        ),
    )

    assert python_home == str(Path(sys.base_prefix).resolve())
    assert python_base_prefix == str(Path(sys.base_prefix).resolve())
    with pytest.raises(
        SystemExit,
        match="sys.prefix does not match the signed Python home",
    ):
        comfyui_python_bootstrap._main()

    bootstrap_sys.prefix = python_home
    bootstrap_sys.argv[2] = str(Path(python_base_prefix).parent / "unsigned-base")
    with pytest.raises(SystemExit, match="sys.base_prefix does not match"):
        comfyui_python_bootstrap._main()

    bootstrap_sys.argv[2] = python_base_prefix
    bootstrap_sys.argv[4] = str(Path(python_base_prefix).parent / "unsigned-stdlib")
    with pytest.raises(SystemExit, match="standard library root is outside"):
        comfyui_python_bootstrap._main()

    bootstrap_sys.argv[4] = python_stdlib_paths[0]
    comfyui_python_bootstrap._main()

    assert run_path_calls == [(entrypoint, "__main__")]
    assert bootstrap_sys.path == [
        *python_stdlib_paths,
        python_imports,
        comfyui_source,
    ]


def test_production_adapter_refuses_runtime_without_independent_pin_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.undo()
    bundle = build_comfyui_bundle(tmp_path)

    with pytest.raises(BackendPreparationError) as error:
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )

    assert error.value.code == "bundle_unverified"
    assert not (tmp_path / "images").exists()
    with pytest.raises(BackendPreparationError) as cli_error:
        cli._engine_adapter(
            Namespace(
                engine_candidate=bundle.declaration_path,
                engine_trusted_evidence=bundle.trusted_evidence_path,
                engine_backend="comfyui",
            ),
            tmp_path / "cli-images",
        )
    assert cli_error.value.code == "bundle_unverified"


def test_candidate_requires_independent_workflow_approval(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path, omit_workflow_authority=True)

    with pytest.raises(BackendPreparationError) as error:
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)

    assert error.value.code == "bundle_unverified"
    assert "workflow" in str(error.value)


def test_workflow_approval_must_bind_each_exact_operation_graph(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path, tamper_workflow_sha=True)

    with pytest.raises(BackendPreparationError) as error:
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)

    assert error.value.code == "bundle_unverified"
    assert "graph pin" in str(error.value)


def test_qwen_profile_v2_rejects_text_only_generate_before_queueing(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    service = _service(tmp_path, bundle)
    tables = (
        "artifact_edges",
        "artifact_integrity",
        "artifact_publication_authority",
        "artifact_publications",
        "backend_executions",
        "execution_admissions",
        "execution_attempts",
        "execution_jobs",
        "execution_resource",
        "generation_artifacts",
        "generation_attempts",
        "generation_jobs",
        "generation_requests",
    )

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        before = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }

    request = GenerationRequest(
        "text-only generate",
        seed=7,
        width=64,
        height=64,
        operation="generate",
    )

    with pytest.raises(
        UnsupportedCapabilityError,
        match=r"requires reference roles \('reference',\) for generate requests",
    ):
        service.enqueue(
            "text-only-generate",
            request,
            workload_demand=heavy_workload_demand(),
        )

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        after = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        }

    assert after == before
    assert all(
        after[table] == 0
        for table in tables
        if table != "execution_resource"
    )


def test_legacy_synthetic_text_only_generate_remains_admissible(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=1)
    service = _service(tmp_path, bundle)

    submission = service.enqueue(
        "legacy-text-only-generate",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    assert submission.status == "queued"
    assert service._store.get_job(submission.job_id).execution_status == "queued"


def test_run_scoped_model_search_binds_exact_verified_artifacts(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_model_binding",
            attempt_id="attempt_model_binding",
            resolved_prompt="model binding",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        base_directory = prepared.scratch_directory
        assert prepared.argv[prepared.argv.index("--base-directory") + 1] == str(
            base_directory
        )
        effective = prepared.resolved_record["effective_execution"]
        configuration = effective["configuration"]
        assert configuration["server"]["base_directory"] == str(base_directory)
        node_pins = configuration["nodes"]
        assert all(
            set(pin) == {"class", "component_id", "sha256", "inputs"}
            and pin["class"] == class_type
            for class_type, pin in node_pins.items()
        )
        expected_folders = {
            "diffusion_model": "diffusion_models",
            "text_encoder": "text_encoders",
            "vae": "vae",
        }
        for model_file in configuration["model_files"]:
            role = model_file["role"]
            source = bundle.component_paths[role].resolve()
            search_path = Path(model_file["search_path"])
            assert model_file["resolved_path"] == str(source)
            assert search_path.parent == base_directory / "models" / expected_folders[role]
            assert search_path.name == source.name
            assert search_path.is_symlink()
            assert os.readlink(search_path) == str(source)
        model_entries = [
            path
            for path in (base_directory / "models").rglob("*")
            if path.is_file() or path.is_symlink()
        ]
        assert len(model_entries) == 3
    finally:
        adapter.cleanup_execution(prepared)

    assert not prepared.scratch_directory.exists()
    assert all(path.exists() for path in bundle.component_paths.values())


def _service(tmp_path: Path, bundle) -> GenerationService:
    output = tmp_path / "images"
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=output,
    )
    return GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )


def _request() -> GenerationRequest:
    return GenerationRequest("a synthetic red cube", seed=7, width=64, height=64)


def _privacy_result(
    adapter: ComfyUIAdapter, settings: dict[str, bool | None]
):
    return application_privacy_policy(adapter).evaluate(
        adapter.adapter_id,
        {
            "configuration_version": adapter.configuration["configuration_version"],
            "privacy": settings,
        },
    )


def _rgb_png(width: int, height: int) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)

    pixels = b"\x00" + b"\x40\x80\xc0" * width
    rows = pixels * height
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, level=9))
        + chunk(b"IEND", b"")
    )


def _execute(service: GenerationService, key: str = "comfy") -> str:
    job_id = service.enqueue(
        key, _request(), workload_demand=heavy_workload_demand()
    ).job_id
    report = service.work()
    assert report["processed"] == 1
    return job_id


def _selector_model_file(
    tmp_path: Path, role: str, folder: str, filename: str
) -> dict[str, str]:
    path = tmp_path / folder / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(role.encode("utf-8"))
    return {"role": role, "search_path": str(path)}


def _rewrite_recipe_document(bundle, mutate) -> None:
    recipe = json.loads(bundle.recipe_path.read_text(encoding="utf-8"))
    mutate(recipe)
    data = (canonical_json(recipe) + "\n").encode("utf-8")
    recipe_sha256 = hashlib.sha256(data).hexdigest()
    bundle.recipe_path.write_bytes(data)
    declaration = json.loads(bundle.declaration_path.read_text(encoding="utf-8"))
    declaration["recipe"]["document"].update(
        {"size_bytes": len(data), "sha256": recipe_sha256}
    )
    bundle.declaration_path.write_text(json.dumps(declaration), encoding="utf-8")
    trusted = json.loads(bundle.trusted_evidence_path.read_text(encoding="utf-8"))
    for record in trusted["records"]:
        expected = record["expected"]
        if expected.get("schema") == "media-generation.comfyui-workflow-approval":
            expected["recipe_document_sha256"] = recipe_sha256
        expected_data = (canonical_json(expected) + "\n").encode("utf-8")
        record["document_size_bytes"] = len(expected_data)
        record["document_sha256"] = hashlib.sha256(expected_data).hexdigest()
    bundle.trusted_evidence_path.write_text(
        json.dumps(trusted, sort_keys=True), encoding="utf-8"
    )


def _v2_reference(tmp_path: Path, role: str) -> ResolvedReference:
    image = tmp_path / f"{role}.png"
    image.write_bytes(_rgb_png(64, 64))
    return ResolvedReference(
        artifact_id="art_" + hashlib.sha256(role.encode()).hexdigest()[:32],
        content_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
        path=image,
        role=role,
    )


def _v2_plan(operation: str, reference: ResolvedReference) -> GenerationPlan:
    return GenerationPlan(
        job_id=f"job_qwen_v2_{operation}",
        attempt_id=f"attempt_qwen_v2_{operation}",
        resolved_prompt="Qwen profile probe",
        seed=19,
        width=64,
        height=64,
        references=(reference,),
        output_slot="slot",
        output_slot_id="slot_id",
    )


def test_qwen_profile_v2_resolves_reference_generate_and_source_edit(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )

    for operation, role in (("generate", "reference"), ("edit", "source")):
        reference = _v2_reference(tmp_path, role)
        prepared = adapter.resolve_execution(_v2_plan(operation, reference))
        try:
            record = prepared.resolved_record
            validate_resolved_record(record)
            effective = record["effective_execution"]
            configuration = effective["configuration"]
            workflow = configuration["workflow"]
            graph = effective["graph"]

            assert workflow["profile_version"] == 2
            assert workflow["sampling_resolution"] == (
                {
                    "mode": "requested-empty-latent",
                    "width": 64,
                    "height": 64,
                }
                if operation == "generate"
                else {"mode": "flux-kontext-image-scale", "width": None, "height": None}
            )
            assert workflow["output_dimensions"] == {
                "mode": (
                    "decoder-native" if operation == "generate" else "post-decode-image-scale"
                ),
                "width": 64,
                "height": 64,
            }
            assert [
                node["class_type"]
                for node in graph.values()
                if node["class_type"] == "TextEncodeQwenImageEditPlus"
            ] == ["TextEncodeQwenImageEditPlus", "TextEncodeQwenImageEditPlus"]
            assert [
                node["inputs"]["reference_latents_method"]
                for node in graph.values()
                if node["class_type"] == "FluxKontextMultiReferenceLatentMethod"
            ] == ["index_timestep_zero", "index_timestep_zero"]
            assert prepared.request_body_bytes == canonical_json(
                effective["request_body"]
            ).encode("utf-8")
            assert json.loads(prepared.request_body_bytes)["prompt"] == graph
        finally:
            adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("operation", "role"),
    [("generate", "reference"), ("edit", "source")],
)
def test_qwen_profile_v2_operations_complete_through_generation_service(
    tmp_path: Path, operation: str, role: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    service = _service(tmp_path, bundle)
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / f"{role}.png").write_bytes(_rgb_png(64, 64))
    source = service.import_image(source_root, f"{role}.png")
    request = GenerationRequest(
        f"Qwen {operation} conformance probe",
        seed=23,
        width=64,
        height=64,
        reference_ids=(source.artifact_id,),
        reference_roles=(role,),
        operation=operation,  # type: ignore[arg-type]
    )
    job_id = service.enqueue(
        f"qwen-v2-{operation}", request, workload_demand=heavy_workload_demand()
    ).job_id

    assert service.work()["processed"] == 1
    assert service.get_provenance(job_id)["status"] == "succeeded"
    effective = service.get_execution(job_id)["resolved"]["effective_execution"]
    workflow = effective["configuration"]["workflow"]
    assert workflow["profile_version"] == 2
    assert workflow["sampling_resolution"]["mode"] == (
        "requested-empty-latent" if operation == "generate" else "flux-kontext-image-scale"
    )
    assert workflow["output_dimensions"]["mode"] == (
        "decoder-native" if operation == "generate" else "post-decode-image-scale"
    )


@pytest.mark.parametrize(
    ("operation", "references"),
    [
        ("generate", []),
        ("generate", ["reference", "reference"]),
        ("generate", ["source"]),
        ("edit", []),
        ("edit", ["reference"]),
        ("edit", ["source", "source"]),
    ],
)
def test_qwen_profile_v2_rejects_unsupported_reference_roles_and_counts(
    tmp_path: Path,
    operation: str,
    references: list[str],
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)

    def mutate(recipe: dict[str, object]) -> None:
        recipe["operations"][operation]["references"] = references  # type: ignore[index]

    _rewrite_recipe_document(bundle, mutate)

    with pytest.raises(BackendPreparationError, match="references"):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


@pytest.mark.parametrize(
    "mutation",
    [
        "generic_positive_encoder",
        "swapped_conditioning",
        "missing_reference_method",
        "disconnected_image",
        "extra_qwen_encoder",
        "lightning_lora",
        "wrong_model_order",
        "bad_sampler",
        "generate_dimensions",
        "edit_latent",
        "edit_output",
        "edit_scale_method",
    ],
)
def test_qwen_profile_v2_rejects_unsafe_graph_mutations(mutation: str) -> None:
    recipe = recipe_document(node_sha256="0" * 64, profile_version=2)
    operation = "edit" if mutation.startswith("edit_") else "generate"
    graph = recipe["operations"][operation]["graph"]

    if mutation == "generic_positive_encoder":
        graph["6"]["class_type"] = "CLIPTextEncode"
    elif mutation == "swapped_conditioning":
        graph["8"]["inputs"]["conditioning"] = ["7", 0]
        graph["9"]["inputs"]["conditioning"] = ["6", 0]
    elif mutation == "missing_reference_method":
        graph["8"]["inputs"]["reference_latents_method"] = "zero"
    elif mutation == "disconnected_image":
        graph["6"]["inputs"]["image1"] = ["4", 0]
        graph["7"]["inputs"]["image1"] = ["4", 0]
    elif mutation == "extra_qwen_encoder":
        graph["99"] = {
            "class_type": "TextEncodeQwenImageEditPlus",
            "inputs": {
                "clip": ["2", 0],
                "image1": ["5", 0],
                "prompt": "unused",
                "vae": ["3", 0],
            },
        }
    elif mutation == "lightning_lora":
        graph["99"] = {
            "class_type": "LoraLoaderModelOnly",
            "inputs": {"lora_name": "lightning.safetensors", "model": ["1", 0]},
        }
        graph["10"]["inputs"]["model"] = ["99", 0]
    elif mutation == "wrong_model_order":
        graph["11"]["inputs"]["model"] = ["1", 0]
    elif mutation == "bad_sampler":
        graph["13"]["inputs"]["sampler_name"] = "heun"
    elif mutation == "generate_dimensions":
        graph["12"]["inputs"]["width"] = 128
    elif mutation == "edit_latent":
        graph["12"]["inputs"]["pixels"] = ["4", 0]
    elif mutation == "edit_output":
        graph["16"]["inputs"]["images"] = ["14", 0]
    elif mutation == "edit_scale_method":
        graph["15"]["inputs"]["upscale_method"] = "nearest-exact"
    else:
        raise AssertionError(f"unhandled mutation {mutation}")

    with pytest.raises(BackendEvidenceError):
        validate_comfyui_qwen_conditioning_graph(
            graph,
            operation=operation,
            output_node_id="16",
            output_field="images",
            expected_prompt="$prompt",
            expected_width="$width",
            expected_height="$height",
            require_artifact_placeholder=True,
        )


def test_trusted_recipe_v2_policy_requires_exact_reference_timestep_zero_graph(
    tmp_path: Path,
) -> None:
    valid = build_comfyui_bundle(tmp_path / "valid", profile_version=2)
    candidate = load_comfyui_candidate(
        valid.declaration_path,
        valid.trusted_evidence_path,
    )
    assert candidate.recipe.schema_version == 2

    invalid = build_comfyui_bundle(
        tmp_path / "invalid",
        profile_version=2,
        reference_latents_method="index_timestep_one",
    )
    with pytest.raises(BackendPreparationError) as error:
        load_comfyui_candidate(
            invalid.declaration_path,
            invalid.trusted_evidence_path,
        )

    assert error.value.code == "recipe_invalid"
    assert "index_timestep_zero" in str(error.value)


def test_legacy_source_validator_rejects_post_decode_scale() -> None:
    recipe = recipe_document(node_sha256="0" * 64, profile_version=1)
    graph = recipe["operations"]["edit"]["graph"]
    graph["12"] = {
        "class_type": "ImageScale",
        "inputs": {
            "image": ["8", 0],
            "upscale_method": "lanczos",
            "width": "$width",
            "height": "$height",
            "crop": "center",
        },
    }
    graph["9"]["inputs"]["images"] = ["12", 0]

    with pytest.raises(BackendEvidenceError):
        validate_comfyui_source_conditioning_path(
            graph,
            output_node_id="9",
            output_field="images",
            source_node_id="6",
            require_artifact_placeholder=True,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sampling_method", "uni_pc"),
        ("steps", 8),
        ("cfg_scale", 2.5),
        ("flow_shift", 3.0),
        ("strength", 0.5),
    ],
)
def test_qwen_profile_v2_requires_exact_model_sampling(
    tmp_path: Path, field: str, value: object
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)

    def mutate(recipe: dict[str, object]) -> None:
        recipe["sampling"][field] = value  # type: ignore[index]

    _rewrite_recipe_document(bundle, mutate)
    with pytest.raises(BackendPreparationError, match="sampling"):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


def test_production_comfyui_refuses_legacy_recipe_profile(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(
        tmp_path, tool_version="comfyui-local-v1", profile_version=1
    )

    with pytest.raises(BackendPreparationError) as error:
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)

    assert error.value.code == "bundle_incompatible"
    assert "profile v2" in str(error.value)


def test_qwen_profile_v2_record_tampering_fails_closed(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        _v2_plan("generate", _v2_reference(tmp_path, "reference"))
    )
    try:
        valid = prepared.resolved_record
        validate_resolved_record(valid)
        for field in ("graph", "sampling_resolution", "output_dimensions"):
            tampered = json.loads(json.dumps(valid))
            effective = tampered["effective_execution"]
            if field == "graph":
                effective["graph"]["16"]["inputs"]["filename_prefix"] = "changed"
            else:
                effective["configuration"]["workflow"][field]["width"] = 128
            with pytest.raises(BackendEvidenceError):
                validate_resolved_record(tampered)
    finally:
        adapter.cleanup_execution(prepared)


def test_model_binding_supports_repeated_pinned_node_classes(tmp_path: Path) -> None:
    text_encoder = _selector_model_file(
        tmp_path, "text_encoder", "text_encoders", "text.safetensors"
    )
    graph = {
        "primary": {
            "class_type": "CLIPLoader",
            "inputs": {"clip_name": "text.safetensors", "type": "qwen_image"},
        },
        "secondary": {
            "class_type": "CLIPLoader",
            "inputs": {"clip_name": "text.safetensors", "type": "qwen_image"},
        },
    }

    comfyui._verify_graph_model_bindings(graph, [text_encoder])


def test_model_binding_disambiguates_clip_name_by_node_class(tmp_path: Path) -> None:
    shared_name = "shared.safetensors"
    text_encoder = _selector_model_file(
        tmp_path, "text_encoder", "text_encoders", shared_name
    )
    projector = _selector_model_file(
        tmp_path, "projector", "clip_vision", shared_name
    )
    graph = {
        "text": {
            "class_type": "CLIPLoader",
            "inputs": {"clip_name": shared_name, "type": "qwen_image"},
        },
        "vision": {
            "class_type": "CLIPVisionLoader",
            "inputs": {"clip_name": shared_name},
        },
    }

    comfyui._verify_graph_model_bindings(graph, [text_encoder, projector])


def test_model_binding_rejects_selector_on_unapproved_node_class(
    tmp_path: Path,
) -> None:
    text_encoder = _selector_model_file(
        tmp_path, "text_encoder", "text_encoders", "text.safetensors"
    )
    graph = {
        "approved": {
            "class_type": "CLIPLoader",
            "inputs": {"clip_name": "text.safetensors", "type": "qwen_image"},
        },
        "synthetic": {
            "class_type": "ComfyUIModelLoader",
            "inputs": {"clip_name": "text.safetensors"},
        },
    }

    with pytest.raises(BackendPreparationError) as error:
        comfyui._verify_graph_model_bindings(graph, [text_encoder])

    assert error.value.code == "bundle_unverified"
    assert "clip_name" in str(error.value)


def test_comfyui_qwen_2511_does_not_require_sd_cpp_zero_conditioning(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    candidate = load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)
    assert candidate.recipe.model_family == "qwen_image_edit_2511"
    assert "sd_cpp_cli_contract" not in bundle.declaration["engine"]["architecture_flags"]
    assert "qwen_image_zero_cond_t" not in bundle.declaration["engine"]["architecture_flags"]


def test_candidate_prepare_cli_selects_comfyui_recipe_v2_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    policy_artifact = (
        "recipe.compatibility.policy:"
        "comfyui-qwen-image-edit-2511-reference-latent-timestep-zero"
    )

    default_exit = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(bundle.declaration_path),
            "--trusted-evidence",
            str(bundle.trusted_evidence_path),
            "--manifest-output",
            str(tmp_path / "default-prepared.json"),
            "--journal-output",
            str(tmp_path / "default-journal.json"),
        ]
    )
    default_report = json.loads(capsys.readouterr().out)
    default_policy = next(
        item
        for item in default_report["items"]
        if item["artifact"]
        == "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
    )

    assert default_exit == 3
    assert default_report["status"] == "incompatible"
    assert default_policy["code"] == "qwen_2511_zero_conditioning_required"

    comfyui_exit = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(bundle.declaration_path),
            "--trusted-evidence",
            str(bundle.trusted_evidence_path),
            "--manifest-output",
            str(tmp_path / "comfyui-prepared.json"),
            "--journal-output",
            str(tmp_path / "comfyui-journal.json"),
            "--engine-backend",
            "comfyui",
        ]
    )
    comfyui_capture = capsys.readouterr()
    comfyui_report = json.loads(comfyui_capture.out)
    comfyui_policy = next(
        item
        for item in comfyui_report["items"]
        if item["artifact"] == policy_artifact
    )

    assert comfyui_exit == 0
    assert comfyui_capture.err == ""
    assert comfyui_report["status"] == "ready"
    assert comfyui_policy["status"] == "ready"
    assert comfyui_policy["code"] == "comfyui_conditioning_policy_trusted"


def test_exact_dispatched_prompt_bytes_match_immutable_v3_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PYTHONHASHSEED", "random")
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(mode="lose_response_history")
    service = _service(tmp_path, bundle)
    job_id = _execute(service)
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "succeeded"
    record = service.get_execution(job_id)
    effective = record["resolved"]["effective_execution"]
    captured = (bundle.files / "captured-prompt.bin").read_bytes()
    assert captured == canonical_json(effective["request_body"]).encode("utf-8")
    assert hashlib.sha256(captured).hexdigest() == effective["request_body_sha256"]
    assert record["launch"]["schema_version"] == 2
    assert record["observed"]["schema_version"] == 2
    assert effective["client_id"] == record["attempt_id"]
    request_body = json.loads(captured)
    assert request_body["prompt_id"] == effective["prompt_id"]
    assert request_body["client_id"] == record["attempt_id"]


def test_unknown_post_acceptance_is_not_resubmitted_and_quarantines(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(
        lose_response=True,
        jobs_unknown=True,
        queue_unknown=True,
        history_unknown=True,
    )
    service = _service(tmp_path, bundle)
    job_id = _execute(service, "ambiguous")
    assert (bundle.files / "prompt-count.txt").read_text() == "1"
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["artifact"] is None
    assert provenance["attempt"]["termination_proven"] is False
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    observed = service.get_execution(job_id)["observed"]
    assert observed["direct_child_reaped"] is True
    assert observed["process_tree_containment"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


@pytest.mark.parametrize("failure_stage", ["after-send", "after-acceptance"])
def test_post_prompt_control_loss_is_ambiguous_and_quarantines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    sent = threading.Event()
    accepted = threading.Event()
    prompt_requests: list[str] = []
    original_request = http.client.HTTPConnection.request
    original_getresponse = http.client.HTTPConnection.getresponse
    original_require_current = ManagedProcessControl.require_current
    failure_injected = False

    def request(connection, method, url, *args, **kwargs):
        if method == "POST" and url == "/prompt":
            prompt_requests.append(url)
            connection._t09_prompt_request = True
        result = original_request(connection, method, url, *args, **kwargs)
        if method == "POST" and url == "/prompt":
            sent.set()
        return result

    def getresponse(connection, *args, **kwargs):
        response = original_getresponse(connection, *args, **kwargs)
        if getattr(connection, "_t09_prompt_request", False):
            accepted.set()
        return response

    def require_current(control):
        nonlocal failure_injected
        trigger = sent if failure_stage == "after-send" else accepted
        if trigger.is_set() and not failure_injected:
            failure_injected = True
            raise comfyui.BackendEvidenceError("simulated authority loss")
        return original_require_current(control)

    monkeypatch.setattr(http.client.HTTPConnection, "request", request)
    monkeypatch.setattr(http.client.HTTPConnection, "getresponse", getresponse)
    monkeypatch.setattr(ManagedProcessControl, "require_current", require_current)

    job_id = _execute(service, f"ambiguous-control-{failure_stage}")
    provenance = service.get_provenance(job_id)
    assert failure_injected, "\n".join(
        f"{key}={value!r}" for key, value in provenance["attempt"].items()
    )
    assert prompt_requests == ["/prompt"]
    assert provenance["status"] == "ambiguous"
    assert provenance["artifact"] is None
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert service._store.resource_snapshot()["state"] == "quarantined"


@pytest.mark.parametrize(
    ("mode", "evidence_path"),
    [
        ({"jobs_unknown": False, "queue_unknown": True}, "/api/jobs"),
        ({"jobs_unknown": True, "queue_unknown": False}, "/queue"),
    ],
)
def test_lost_post_response_reconciles_from_positive_server_observation(
    tmp_path: Path, mode: dict[str, object], evidence_path: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(lose_response=True, **mode)
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "lost-response-positive-observation")

    assert service.get_provenance(job_id)["status"] == "succeeded"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"
    counts = json.loads((bundle.files / "request-counts.json").read_text())
    assert counts[evidence_path] >= 1
    assert counts["/prompt"] == 1


def test_node_replacements_fail_closed_before_prompt_dispatch(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(node_replacements={"KSampler": "UntrustedSampler"})
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "node-replacement-refused")

    assert service.get_provenance(job_id)["status"] == "failed"
    assert not (bundle.files / "prompt-count.txt").exists()
    counts = json.loads((bundle.files / "request-counts.json").read_text())
    assert counts["/node_replacements"] >= 1
    assert counts.get("/prompt", 0) == 0


@pytest.mark.parametrize(
    "missing_flag",
    [
        "--disable-all-custom-nodes",
        "--disable-auto-launch",
        "--offline",
        "--base-directory",
        "--front-end-root",
        "--feature-flag",
    ],
)
def test_admission_rejects_comfyui_recipe_without_required_privacy_controls(
    tmp_path: Path, missing_flag: str
) -> None:
    node_sha = hashlib.sha256(b"synthetic-comfyui-node-bundle-v1").hexdigest()
    recipe = recipe_document(node_sha256=node_sha)
    server = dict(recipe["server"])
    argv = list(server["argv"])
    index = argv.index(missing_flag)
    del argv[index : index + (2 if missing_flag in {"--base-directory", "--front-end-root", "--feature-flag"} else 1)]
    server["argv"] = argv
    bundle = build_comfyui_bundle(tmp_path, alter_recipe={"server": server})

    with pytest.raises(BackendPreparationError):
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )


def test_comfyui_admission_privacy_refuses_unapproved_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    monkeypatch.setattr(
        comfyui,
        "_child_environment",
        lambda names: {"HTTPS_PROXY": "https://remote.example"},
    )
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )

    with pytest.raises(PrivacyComplianceError):
        GenerationService(
            tmp_path / "studio.sqlite3",
            tmp_path / "images",
            adapter=adapter,
            admission_profile=heavy_admission_profile(),
        )
    assert not (tmp_path / "studio.sqlite3").exists()


def test_admission_privacy_evidence_names_template_scope_and_dispatch_rechecks(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )

    evidence = adapter.configuration["privacy_validation"]

    assert adapter.configuration["configuration_version"] == "comfyui-local/v2"
    assert evidence == {
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
    }
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        admission_profile=heavy_admission_profile(),
    )
    job_id = service.enqueue(
        "privacy-template-scope",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    admitted = service.get_provenance(job_id)
    assert admitted["adapter_configuration"]["privacy_validation"] == evidence


def test_comfyui_dispatch_rechecks_privacy_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    job_id = service.enqueue(
        "privacy-pre-dispatch",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    observed: list[tuple[tuple[str, ...], dict[str, str], dict[str, object]]] = []

    def refuse(argv, environment, effective):
        observed.append((tuple(argv), dict(environment), dict(effective)))
        return {control.value: None for control in PrivacyControl}

    monkeypatch.setattr(service_module, "comfyui_invocation_privacy_settings", refuse)
    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(job_id)["status"] == "failed"
    assert observed and observed[0][0][0] == str(Path(sys.executable).resolve())
    assert service._store.resource_snapshot()["state"] == "available"
    argv = observed[0][0]
    assert argv[argv.index("--") + 1] == str(bundle.engine_path)
    effective = observed[0][2]
    server = effective["configuration"]["server"]
    assert server["port"] == int(argv[argv.index("--port") + 1])
    assert server["port"] != 1
    for argument, key in (
        ("--input-directory", "input_directory"),
        ("--output-directory", "output_directory"),
        ("--temp-directory", "temp_directory"),
    ):
        assert server[key] == argv[argv.index(argument) + 1]
    run_directories = [
        Path(server[name])
        for name in ("input_directory", "output_directory", "temp_directory")
    ]
    assert all(path.is_absolute() for path in run_directories)
    assert len({path.parent for path in run_directories}) == 1
    assert run_directories[0].parent.name.startswith("media-generation-comfyui-")
    assert effective["request_body"]["prompt"] == effective["graph"]
    assert observed[0][1].get("PATH") == comfyui_runtime_pins.COMFYUI_CLOSED_PATH
    assert set(observed[0][1]) <= {"PATH", "LD_LIBRARY_PATH", "PYTHONHASHSEED"}
    assert not (bundle.files / "prompt-count.txt").exists()


def test_frontend_tree_hash_maps_open_io_errors_to_preparation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "index.html").write_text("synthetic frontend", encoding="utf-8")

    def fail_open(_path: Path):
        raise OSError("synthetic open failure")

    monkeypatch.setattr(comfyui, "open_regular", fail_open)

    with pytest.raises(BackendPreparationError) as error:
        comfyui._frontend_tree_sha256(frontend)

    assert error.value.code == "bundle_unverified"
    assert "changed while hashing" in str(error.value)


def test_frontend_tree_hash_is_independent_of_walk_traversal_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    frontend = tmp_path / "frontend"
    (frontend / "assets" / "nested").mkdir(parents=True)
    (frontend / "index.html").write_text("index\n", encoding="utf-8")
    (frontend / "z.js").write_text("script\n", encoding="utf-8")
    (frontend / "a.css").write_text("style\n", encoding="utf-8")
    (frontend / "assets" / "nested" / "module.js").write_text(
        "module\n", encoding="utf-8"
    )

    original_walk = os.walk
    rows = [
        (current, list(directories), list(filenames))
        for current, directories, filenames in original_walk(
            frontend, followlinks=False
        )
    ]
    assert len(rows) > 1

    def use_traversal_order(*, reverse: bool) -> None:
        ordered_rows = list(reversed(rows)) if reverse else rows

        def synthetic_walk(_root: Path, *, followlinks: bool = False):
            assert followlinks is False
            for current, directories, filenames in ordered_rows:
                yield (
                    current,
                    list(reversed(directories)) if reverse else list(directories),
                    list(reversed(filenames)) if reverse else list(filenames),
                )

        monkeypatch.setattr(comfyui.os, "walk", synthetic_walk)

    use_traversal_order(reverse=False)
    forward_digest = comfyui._frontend_tree_sha256(frontend)
    use_traversal_order(reverse=True)
    reverse_digest = comfyui._frontend_tree_sha256(frontend)

    assert forward_digest == reverse_digest


def test_frontend_tree_change_after_resolution_is_refused(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_frontend",
            attempt_id="attempt_frontend",
            resolved_prompt="frontend integrity",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    frontend = Path(prepared.argv[prepared.argv.index("--front-end-root") + 1])
    (frontend / "index.html").write_text("changed after resolution", encoding="utf-8")
    try:
        with pytest.raises(BackendEvidenceError, match="frontend"):
            adapter._verify_frontend_root(prepared)
    finally:
        adapter.cleanup_execution(prepared)


def test_frontend_tree_counts_empty_directories_toward_entry_limit(
    tmp_path: Path,
) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "index.html").write_text("", encoding="utf-8")
    for index in range(4096):
        (frontend / f"empty-{index}").mkdir()

    with pytest.raises(BackendPreparationError, match="entry limit"):
        comfyui._frontend_tree_sha256(frontend)


def test_frontend_tree_rejects_excessive_directory_depth(tmp_path: Path) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    (frontend / "index.html").write_text("", encoding="utf-8")
    nested = frontend
    for _ in range(65):
        nested = nested / "d"
        nested.mkdir()

    with pytest.raises(BackendPreparationError, match="depth limit"):
        comfyui._frontend_tree_sha256(frontend)


def test_frontend_tree_accepts_complete_upstream_frontend_size(
    tmp_path: Path,
) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    index = frontend / "index.html"
    index.touch()
    os.truncate(index, 101_053_847)

    assert comfyui._frontend_tree_sha256(frontend)


def test_frontend_tree_rejects_tree_one_byte_over_128_mib(
    tmp_path: Path,
) -> None:
    frontend = tmp_path / "frontend"
    frontend.mkdir()
    index = frontend / "index.html"
    index.touch()
    os.truncate(index, 128 * 1024 * 1024 + 1)

    with pytest.raises(BackendPreparationError, match="bounded tree size"):
        comfyui._frontend_tree_sha256(frontend)


def test_single_source_edit_completes_through_generation_service(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "source.png").write_bytes(_rgb_png(64, 64))
    source = service.import_image(source_root, "source.png")
    request = GenerationRequest(
        "edit the source scene",
        seed=17,
        width=64,
        height=64,
        reference_ids=(source.artifact_id,),
        reference_roles=("source",),
        operation="edit",
    )
    job_id = service.enqueue(
        "single-source-edit",
        request,
        workload_demand=heavy_workload_demand(),
    ).job_id

    assert service.work()["processed"] == 1
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "succeeded"
    assert service._store.resource_snapshot()["state"] == "quarantined"
    execution = service.get_execution(job_id)
    effective = execution["resolved"]["effective_execution"]
    assert effective["configuration"]["model_facing"]["conditioning"] == [
        {
            "artifact_id": source.artifact_id,
            "role": "source",
            "content_sha256": source.sha256,
        }
    ]
    source_nodes = [
        node
        for node in effective["graph"].values()
        if node["class_type"] == "LoadImage"
    ]
    assert len(source_nodes) == 1
    source_node = source_nodes[0]
    assert source_node["class_type"] == "LoadImage"
    assert source_node["inputs"]["image"].startswith("mg-")
    counts = json.loads((bundle.files / "request-counts.json").read_text())
    assert counts["/upload/image"] == 1


def test_worker_cli_reports_quarantine_after_successful_comfyui_publication(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A succeeded asset cannot hide a quarantined T06 resource."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    job_id = service.enqueue(
        "cli-quarantined-success",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id

    exit_code = cli.main(
        [
            "worker",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--limit",
            "1",
            "--engine-candidate",
            str(bundle.declaration_path),
            "--engine-trusted-evidence",
            str(bundle.trusted_evidence_path),
            "--engine-backend",
            "comfyui",
        ]
    )
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert report["status"] == "attention_required"
    assert report["outcomes"][0]["status"] == "succeeded"
    assert report["outcomes"][0]["execution_status"] == "succeeded"
    assert report["outcomes"][0]["resource_state"] == "quarantined"
    assert "process-tree" in report["outcomes"][0]["resource_reason"]
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "succeeded"
    assert provenance["artifact"] is not None
    resource = service._store.resource_snapshot()
    assert resource["state"] == "quarantined"
    assert provenance["execution"]["resource_reason"] == resource["reason"]

    restarted = _service(tmp_path, bundle)
    restarted_report = restarted.work()
    assert restarted_report["status"] == "attention_required"
    assert restarted_report["processed"] == 0
    assert restarted_report["resource_state"] == "quarantined"
    assert restarted_report["resource_reason"] == resource["reason"]

    capsys.readouterr()
    reconcile_exit = cli.main(
        [
            "reconcile",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
        ]
    )
    reconcile_report = json.loads(capsys.readouterr().out)
    assert reconcile_exit == 1
    assert reconcile_report["status"] == "attention_required"
    assert reconcile_report["resource_state"] == "quarantined"
    assert reconcile_report["resource_reason"] == resource["reason"]


def test_submit_cli_reports_quarantine_after_successful_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Synchronous submit preserves success while reporting quarantined capacity."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    monkeypatch.setattr(
        "media_generation.cli.GenerationService", lambda *args, **kwargs: service
    )
    monkeypatch.setattr(
        cli,
        "_admission_inputs",
        lambda _options: (heavy_admission_profile(), heavy_workload_demand()),
    )

    exit_code = cli.main(
        [
            "submit",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--idempotency-key",
            "cli-submit-quarantine",
            "--request-json",
            json.dumps(_request().to_dict()),
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["status"] == "succeeded"
    assert report["artifact_id"]
    assert report["resource_state"] == "quarantined"
    assert "process-tree" in report["resource_reason"]
    assert service.get_provenance(report["job_id"])["status"] == "succeeded"


def test_synchronous_submit_refuses_another_job_quarantine_without_attempt(
    tmp_path: Path,
) -> None:
    """A quarantined owner blocks new work before a claim is created."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    first_job_id = _execute(service, "quarantine-owner")
    assert service.get_provenance(first_job_id)["status"] == "succeeded"

    with pytest.raises(ResourceBusyError) as failure:
        service.submit(
            "quarantine-waiter",
            _request(),
            workload_demand=heavy_workload_demand(),
        )

    snapshot = service.get_provenance(failure.value.job_id)
    assert snapshot["status"] == "queued"
    assert snapshot["attempts"] == []
    assert snapshot["execution"]["retry_eligible"] is False
    resource = service._store.resource_snapshot()
    assert resource["state"] == "quarantined"
    assert resource["job_id"] == first_job_id


def test_submit_cli_reports_another_job_quarantine_as_resource_busy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Synchronous CLI submission reports unavailable capacity as resource busy."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    first_job_id = _execute(service, "cli-quarantine-owner")
    monkeypatch.setattr(
        "media_generation.cli.GenerationService", lambda *args, **kwargs: service
    )
    monkeypatch.setattr(
        cli,
        "_admission_inputs",
        lambda _options: (heavy_admission_profile(), heavy_workload_demand()),
    )

    exit_code = cli.main(
        [
            "submit",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--idempotency-key",
            "cli-quarantine-waiter",
            "--request-json",
            json.dumps(_request().to_dict()),
        ]
    )
    captured = capsys.readouterr()
    error = json.loads(captured.err)

    assert exit_code == 1
    assert captured.out == ""
    assert error["error"]["code"] == "resource_busy"
    queued = service.get_provenance(error["error"]["job_id"])
    assert queued["status"] == "queued"
    assert queued["attempts"] == []
    assert queued["execution"]["retry_eligible"] is False
    assert service._store.resource_snapshot()["job_id"] == first_job_id


def test_detached_descendant_keeps_t06_capacity_quarantined(tmp_path: Path) -> None:
    """A reaped ComfyUI server does not prove that its descendants ended."""
    bundle = build_comfyui_bundle(tmp_path)
    descendant_pid_path = tmp_path / "comfyui-descendant.pid"
    bundle.set_mode(
        detached_descendant_pid_path=str(descendant_pid_path),
        detached_descendant_sleep_seconds=30.0,
    )
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "detached-descendant")

    descendant_pid = int(descendant_pid_path.read_text(encoding="ascii"))
    try:
        os.kill(descendant_pid, 0)
        provenance = service.get_provenance(job_id)
        execution = service.get_execution(job_id)
        resource = service._store.resource_snapshot()
        assert provenance["status"] == "succeeded"
        assert provenance["artifact"] is not None
        assert provenance["attempt"]["termination_proven"] is False
        assert execution["observed"]["direct_child_reaped"] is True
        assert execution["observed"]["process_tree_containment"] is False
        assert resource["state"] == "quarantined"
        assert "process-tree" in resource["reason"]
    finally:
        try:
            os.kill(descendant_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_effective_configuration_keeps_unused_declared_component_consistent(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, include_unused_vision_encoder=True)
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    assert any(
        component.role == "vision_encoder"
        for component in candidate.declaration.components
    )
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "unused-component")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "succeeded"
    resolved = service.get_execution(job_id)["resolved"]
    configuration = resolved["effective_execution"]["configuration"]
    declared_roles = {
        item.role for item in candidate.declaration.components
    }
    resolved_roles = {item["role"] for item in resolved["components"]}
    configured_roles = {item["role"] for item in configuration["components"]}
    model_file_roles = {item["role"] for item in configuration["model_files"]}
    assert "vision_encoder" in declared_roles
    assert configured_roles == resolved_roles
    assert model_file_roles == resolved_roles - {"other"}
    assert "vision_encoder" not in configured_roles


@pytest.mark.parametrize(
    "mode",
    [
        {"wrong_prompt_id": True},
        {"malformed_history": True},
        {"history_delay": 1.0},
        {"history_wrong_id": True},
    ],
)
def test_post_acceptance_identity_or_history_uncertainty_is_ambiguous(
    tmp_path: Path, mode: dict[str, object]
) -> None:
    bundle = build_comfyui_bundle(
        tmp_path,
        request_timeout_seconds=0.2,
        poll_timeout_seconds=0.6,
    )
    bundle.set_mode(**mode)
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "uncertain-identity")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["artifact"] is None
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert provenance["attempt"]["termination_proven"] is False
    observed = service.get_execution(job_id)["observed"]
    assert observed["direct_child_reaped"] is True
    assert observed["process_tree_containment"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"


def test_malformed_post_response_reconciles_only_the_known_prompt_id(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(malformed_prompt_response=True)
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "malformed-response")

    assert service.get_provenance(job_id)["status"] == "succeeded"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"
    request = json.loads((bundle.files / "captured-prompt.bin").read_bytes())
    assert request["prompt_id"] == service.get_execution(job_id)["resolved"][
        "effective_execution"
    ]["prompt_id"]


def test_authority_loss_after_prompt_response_parse_is_ambiguous_without_resubmit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    parsed_prompt_response = False
    preparation_errors: list[Exception] = []
    original_loads = json.loads
    original_require_current = ManagedProcessControl.require_current
    original_resolve_execution = service.adapter.resolve_execution
    original_execute = service.adapter.execute
    original_require_privacy = service._require_execution_privacy
    original_publish = service._publication.publish

    def capture_resolve_execution(plan):
        try:
            return original_resolve_execution(plan)
        except Exception as error:
            preparation_errors.append(error)
            raise

    def capture_require_privacy(prepared, *, claim=None):
        try:
            return original_require_privacy(prepared, claim=claim)
        except Exception as error:
            preparation_errors.append(error)
            raise

    def capture_execute(plan, staged, *, supervisor):
        try:
            return original_execute(plan, staged, supervisor=supervisor)
        except Exception as error:
            preparation_errors.append(error)
            raise

    def capture_publish(*args, **kwargs):
        try:
            return original_publish(*args, **kwargs)
        except Exception as error:
            preparation_errors.append(error)
            raise

    monkeypatch.setattr(service.adapter, "resolve_execution", capture_resolve_execution)
    monkeypatch.setattr(service.adapter, "execute", capture_execute)
    monkeypatch.setattr(service._publication, "publish", capture_publish)
    monkeypatch.setattr(service, "_require_execution_privacy", capture_require_privacy)

    def parse_json(data, *args, **kwargs):
        nonlocal parsed_prompt_response
        result = original_loads(data, *args, **kwargs)
        if isinstance(result, dict) and "prompt_id" in result and "node_errors" in result:
            parsed_prompt_response = True
        return result

    def require_current_after_parse(control: ManagedProcessControl) -> None:
        if parsed_prompt_response:
            raise BackendEvidenceError("injected authority loss after prompt response parse")
        original_require_current(control)

    monkeypatch.setattr(json, "loads", parse_json)
    monkeypatch.setattr(
        ManagedProcessControl, "require_current", require_current_after_parse
    )

    job_id = _execute(service, "authority-loss-after-parse")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous", (
        repr(provenance["attempt"]), repr(preparation_errors)
    )
    assert parsed_prompt_response
    assert provenance["artifact"] is None
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert service._store.resource_snapshot()["state"] == "quarantined"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"


def test_submit_wraps_authority_loss_after_response_parse_as_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_post_authority_loss",
            attempt_id="attempt_post_authority_loss",
            resolved_prompt="authority loss after response parse",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    parsed_response = False
    original_loads = json.loads

    class Response:
        status = 200

        def read(self, _maximum: int) -> bytes:
            return json.dumps(
                {"prompt_id": prepared.prompt_id, "node_errors": {}}
            ).encode("utf-8")

    class Connection:
        def close(self) -> None:
            return None

    class Control:
        def require_current(self) -> None:
            if parsed_response:
                raise BackendEvidenceError("injected authority loss")

        def is_running(self) -> bool:
            return True

        def require_listener_owner(self, _host: str, _port: int) -> None:
            if parsed_response:
                raise BackendEvidenceError("injected listener proof loss")

    def parse_json(data, *args, **kwargs):
        nonlocal parsed_response
        value = original_loads(data, *args, **kwargs)
        if isinstance(value, dict) and value.get("prompt_id") == prepared.prompt_id:
            parsed_response = True
        return value

    def request_owned(_control, resolved, _connection, *_args, **_kwargs):
        resolved.side_effect_state.may_have_been_accepted = True
        return Response()

    monkeypatch.setattr(comfyui.json, "loads", parse_json)
    monkeypatch.setattr(adapter, "_connection", lambda *_args, **_kwargs: Connection())
    monkeypatch.setattr(adapter, "_reverify_runtime_before_prompt", lambda _resolved: None)
    monkeypatch.setattr(adapter, "_request_owned", request_owned)

    try:
        with pytest.raises(AmbiguousBackendOutcome):
            adapter._submit_once(Control(), prepared)
        assert parsed_response
    finally:
        adapter.cleanup_execution(prepared)


def test_listener_proof_does_not_use_a_path_shadow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shadow_directory = tmp_path / "attacker-bin"
    shadow_directory.mkdir()
    shadow_lsof = shadow_directory / "lsof"
    shadow_lsof.write_text("#!/bin/sh\nprintf '4242\\n'\n", encoding="utf-8")
    shadow_lsof.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow_directory))
    executed: list[Path] = []

    def run_helper(argv, **kwargs):
        executable = Path(argv[0])
        executed.append(executable)
        if executable == shadow_lsof:
            return subprocess.CompletedProcess(argv, 0, "4242\n", "")
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(comfyui.subprocess, "run", run_helper)

    with pytest.raises(BackendEvidenceError):
        comfyui._listener_owner_pid("127.0.0.1", 65534)

    assert shadow_lsof not in executed


@pytest.mark.parametrize(
    ("nested_group", "observation_mode"),
    [
        ("jobs", {"queue_unknown": True, "history_unknown": True}),
        ("queue", {"jobs_unknown": True, "history_unknown": True}),
        ("history", {"jobs_unknown": True, "queue_unknown": True}),
    ],
)
def test_deeply_nested_reconciliation_json_is_ambiguous_without_retry(
    tmp_path: Path,
    nested_group: str,
    observation_mode: dict[str, object],
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(
        lose_response=True,
        deeply_nested_json=nested_group,
        **observation_mode,
    )
    service = _service(tmp_path, bundle)

    job_id = _execute(service, f"deep-nested-{nested_group}")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["artifact"] is None
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_foreign_server_identity_fails_before_prompt(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(mode="foreign", identity="foreign-comfyui")
    service = _service(tmp_path, bundle)
    job_id = _execute(service, "foreign")
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "failed"
    assert not (bundle.files / "prompt-count.txt").exists()
    assert provenance["attempt"]["termination_proven"] is False
    observed = service.get_execution(job_id)["observed"]
    assert observed["direct_child_reaped"] is True
    assert observed["process_tree_containment"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_readiness_accepts_upstream_system_stats_without_web_root(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(omit_web_root=True)
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "missing-web-root")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "succeeded"
    assert (bundle.files / "prompt-count.txt").read_text() == "1"


def test_readiness_rejects_inconsistent_reported_web_root_before_prompt(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(web_root=str(tmp_path / "unapproved-frontend"))
    service = _service(tmp_path, bundle)

    job_id = _execute(service, "wrong-web-root")

    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "failed"
    assert not (bundle.files / "prompt-count.txt").exists()
    assert provenance["attempt"]["termination_proven"] is False
    observed = service.get_execution(job_id)["observed"]
    assert observed["direct_child_reaped"] is True
    assert observed["process_tree_containment"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_occupied_loopback_port_refuses_before_spawn(tmp_path: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        port = holder.getsockname()[1]
        bundle = build_comfyui_bundle(tmp_path, initial_port=port)
        service = _service(tmp_path, bundle)
        job_id = _execute(service, "occupied")
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "failed"
    assert provenance["backend_execution"] is None
    assert service._store.resource_snapshot()["state"] == "available"


def test_port_taken_after_reservation_never_receives_http_from_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    foreign_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    foreign_listener.bind(("127.0.0.1", 0))
    foreign_port = foreign_listener.getsockname()[1]
    foreign_listener.listen()
    original_reserve = comfyui._reserve_loopback_port
    accepted = []

    def record_foreign_accept() -> None:
        foreign_listener.settimeout(0.2)
        try:
            client, _address = foreign_listener.accept()
        except TimeoutError:
            return
        accepted.append(client.recv(1))
        client.close()

    def reserve_then_occupy(_initial_port: int) -> int:
        selected = original_reserve(0)
        foreign_listener.close()
        foreign_listener.bind(("127.0.0.1", selected))
        foreign_listener.listen()
        return selected

    monkeypatch.setattr(comfyui, "_reserve_loopback_port", reserve_then_occupy)
    try:
        import threading

        watcher = threading.Thread(target=record_foreign_accept)
        watcher.start()
        job_id = _execute(service, "foreign-race")
        watcher.join(timeout=1.0)
        assert service.get_provenance(job_id)["artifact"] is None
        assert accepted in ([], [b""])
    finally:
        foreign_listener.close()


def test_listener_owner_reports_ambiguous_pid_count(monkeypatch):
    import subprocess

    import pytest

    from media_generation import comfyui
    from media_generation.errors import BackendEvidenceError

    monkeypatch.setattr(
        comfyui.shutil,
        "which",
        lambda _name, **_kwargs: "/usr/sbin/lsof",
    )
    monkeypatch.setattr(
        comfyui.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(
            args, 0, stdout="321\n654\n", stderr=""
        ),
    )

    with pytest.raises(
        BackendEvidenceError,
        match=r"lsof returncode=0, pid_count=2",
    ):
        comfyui._listener_owner_pid("127.0.0.1", 51423)


def test_readiness_timeout_preserves_last_probe_error(monkeypatch):
    from types import SimpleNamespace

    import pytest

    from media_generation import comfyui
    from media_generation.errors import BackendEvidenceError

    adapter = object.__new__(comfyui.ComfyUIAdapter)
    adapter._candidate = SimpleNamespace(
        recipe=SimpleNamespace(
            api=SimpleNamespace(readiness_timeout_seconds=0.2),
            server=SimpleNamespace(readiness_path="/health"),
        )
    )

    def fail_connection(*_args):
        raise BackendEvidenceError("listener ownership probe timed out")

    adapter._get_json = fail_connection
    control = SimpleNamespace(
        is_running=lambda: True,
        require_current=lambda: None,
    )
    resolved = SimpleNamespace()
    now = 0.0

    def monotonic():
        nonlocal now
        now += 0.1
        return now

    monkeypatch.setattr(comfyui.time, "monotonic", monotonic)
    monkeypatch.setattr(comfyui.time, "sleep", lambda _duration: None)

    with pytest.raises(
        BackendEvidenceError,
        match="listener ownership probe timed out",
    ):
        adapter._wait_ready(control, resolved)


@pytest.mark.parametrize(
    ("mode", "key"),
    [
        ({"mode": "readiness_delay", "readiness_delay": 1.0}, "readiness-timeout"),
        (
            {
                "mode": "prompt_hang",
                "prompt_hang": 1.0,
                "history_unknown": True,
            },
            "prompt-timeout",
        ),
        ({"exit_on_history": True}, "interrupted"),
    ],
)
def test_lifecycle_timeouts_and_interruption_fail_closed(
    tmp_path: Path, mode: dict[str, object], key: str
) -> None:
    bundle = build_comfyui_bundle(
        tmp_path,
        request_timeout_seconds=0.2,
        readiness_timeout_seconds=0.2,
        poll_timeout_seconds=0.5,
    )
    bundle.set_mode(**mode)
    service = _service(tmp_path, bundle)
    job_id = _execute(service, key)
    provenance = service.get_provenance(job_id)
    assert provenance["status"] in {"failed", "ambiguous"}
    assert provenance["artifact"] is None
    assert provenance["attempt"]["termination_proven"] is False
    observed = service.get_execution(job_id)["observed"]
    assert observed["direct_child_reaped"] is True
    assert observed["process_tree_containment"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_tampered_node_pin_is_refused_before_execution(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)

    def tamper_recipe_node_pin(recipe: dict[str, object]) -> None:
        nodes = recipe["nodes"]
        assert isinstance(nodes, dict)
        pin = nodes["UNETLoader"]
        assert isinstance(pin, dict)
        pin["sha256"] = "0" * 64

    _rewrite_recipe_document(bundle, tamper_recipe_node_pin)
    with pytest.raises(BackendPreparationError) as error:
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )
    assert error.value.code == "recipe_invalid"


def test_candidate_authored_node_map_cannot_replace_missing_trusted_pins(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, omit_node_authority=True)
    with pytest.raises(BackendPreparationError):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


def test_process_listener_identity_is_required_before_http_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    adapter = service.adapter
    plan = GenerationPlan(
        job_id="job_identity",
        attempt_id="attempt_identity",
        resolved_prompt="identity",
        seed=1,
        width=64,
        height=64,
        references=(),
        output_slot="slot",
        output_slot_id="slot_id",
    )
    prepared = adapter.resolve_execution(plan)
    calls = []
    class FakeControl:
        pid = 12345
        def require_current(self): calls.append("authority")
        def is_running(self): return True
        def require_listener_owner(self, host, port): calls.append(("owner", host, port))
    class FakeConnection:
        def __init__(self, *args, **kwargs): pass
        def connect(self): calls.append("connect")
        def request(self, *args, **kwargs): calls.append("request")
        def getresponse(self):
            class R:
                status = 200
                def read(self, limit): return b'{"system":{"comfyui_version":"synthetic-unqualified-comfyui/v1"}}'
            return R()
        def close(self): pass
    monkeypatch.setattr(comfyui.http.client, "HTTPConnection", FakeConnection)
    monkeypatch.setattr(
        FakeControl,
        "require_listener_owner",
        lambda self, _host, _port: (_ for _ in ()).throw(BackendEvidenceError("foreign")),
    )
    with pytest.raises(BackendEvidenceError):
        adapter._get_json(FakeControl(), prepared, "/system_stats")
    assert "request" not in calls
    adapter.cleanup_execution(prepared)


def test_http_status_request_rechecks_listener_owner_each_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = _service(tmp_path, bundle).adapter
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_listener_recheck",
            attempt_id="attempt_listener_recheck",
            resolved_prompt="probe",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    calls = []
    class FakeControl:
        pid = 12345
        def require_current(self): calls.append("authority")
        def is_running(self): return True
        def require_listener_owner(self, _host, _port): calls.append("owner")
    class FakeConnection:
        def __init__(self, *args, **kwargs): pass
        def connect(self): calls.append("connect")
        def request(self, *args, **kwargs): calls.append("request")
        def getresponse(self):
            class Response:
                status = 200
                def read(self, _limit):
                    calls.append("body")
                    return b'{"system":{"comfyui_version":"synthetic-unqualified-comfyui/v1"}}'
            return Response()
        def close(self): pass
    monkeypatch.setattr(comfyui.http.client, "HTTPConnection", FakeConnection)
    status, _ = adapter._get_json(FakeControl(), prepared, "/system_stats")
    assert status == 200
    assert calls.count("owner") >= 4
    assert calls.index("request") < calls.index("body")
    adapter.cleanup_execution(prepared)


@pytest.mark.parametrize("unsafe_name", [".", ".."])
@pytest.mark.parametrize("identity_field", ["filename", "subfolder"])
def test_dot_output_paths_are_rejected_before_view_request(
    tmp_path: Path, unsafe_name: str, identity_field: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    bundle.set_mode(**{f"unsafe_{identity_field}": unsafe_name})
    service = _service(tmp_path, bundle)
    job_id = _execute(service, f"unsafe-{unsafe_name}")
    provenance = service.get_provenance(job_id)
    counts_path = bundle.files / "request-counts.json"
    counts = json.loads(counts_path.read_text())
    assert provenance["artifact"] is None
    assert counts.get("/view", 0) == 0


@pytest.mark.parametrize("path", ["/upload/image", "/prompt"])
def test_http_dispatch_refuses_after_attempt_authority_is_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = _service(tmp_path, bundle).adapter
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_lost_authority",
            attempt_id="attempt_lost_authority",
            resolved_prompt="probe",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    calls = []
    class FakeControl:
        pid = 12345
        def require_current(self): raise BackendEvidenceError("fenced")
        def is_running(self): return True
        def require_listener_owner(self, _host, _port): calls.append("owner")
    class FakeConnection:
        def __init__(self, *args, **kwargs): pass
        def connect(self): calls.append("connect")
        def request(self, *args, **kwargs): calls.append("request")
        def close(self): pass
    monkeypatch.setattr(comfyui.http.client, "HTTPConnection", FakeConnection)
    connection = adapter._connection(FakeControl(), prepared, 1.0)
    with pytest.raises(BackendEvidenceError):
        adapter._request_owned(
            FakeControl(), prepared, connection, "POST", path, body=b"test"
        )
    assert "request" not in calls
    adapter.cleanup_execution(prepared)


def test_each_template_placeholder_must_use_its_supported_graph_input(
    tmp_path: Path,
) -> None:
    recipe = recipe_document(node_sha256="0" * 64)
    graph = recipe["operations"]["generate"]["graph"]
    graph["1"]["inputs"]["unet_name"] = "$prompt"
    bundle = build_comfyui_bundle(tmp_path, alter_recipe={"operations": recipe["operations"]})
    with pytest.raises(BackendPreparationError):
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )


@pytest.mark.parametrize("artifact", ["workflow", "executable", "node", "model"])
def test_modified_pinned_comfyui_artifact_is_refused_before_resolution(
    tmp_path: Path, artifact: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    if artifact == "workflow":
        document = json.loads(bundle.recipe_path.read_text(encoding="utf-8"))
        document["operations"]["generate"]["graph"]["1"]["inputs"][
            "unet_name"
        ] = "unapproved.safetensors"
        bundle.recipe_path.write_text(json.dumps(document), encoding="utf-8")
    elif artifact == "executable":
        bundle.engine_path.chmod(0o644)
        bundle.engine_path.write_bytes(bundle.engine_path.read_bytes() + b"\n# changed")
    elif artifact == "node":
        node = bundle.component_paths["other"]
        node.write_bytes(node.read_bytes() + b"changed")
    else:
        model = bundle.component_paths["vae"]
        model.write_bytes(model.read_bytes() + b"changed")

    with pytest.raises(BackendPreparationError):
        adapter.resolve_execution(
            GenerationPlan(
                job_id="job_modified_pin",
                attempt_id=f"attempt_modified_{artifact}",
                resolved_prompt="must refuse modified artifacts",
                seed=3,
                width=64,
                height=64,
                references=(),
                output_slot="slot",
                output_slot_id="slot_id",
            )
        )


def test_unapproved_upstream_comfyui_version_is_refused(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    declaration = json.loads(bundle.declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["version"] = "0.43.0"
    declaration["recipe"]["engine_version"] = "0.43.0"
    bundle.declaration_path.write_text(json.dumps(declaration), encoding="utf-8")

    with pytest.raises(BackendPreparationError):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


def test_graph_rejects_unsupported_node_input_parameters(tmp_path: Path) -> None:
    recipe = recipe_document(node_sha256="0" * 64)
    operations = recipe["operations"]
    operations["generate"]["graph"]["1"]["inputs"]["remote_url"] = "https://invalid"
    bundle = build_comfyui_bundle(tmp_path, alter_recipe={"operations": operations})
    with pytest.raises(BackendPreparationError):
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )


def test_reference_count_and_dimension_limits_are_refused(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    assert adapter.capabilities.max_references == 1
    reference = ResolvedReference(
        artifact_id="art_" + "1" * 32,
        content_sha256="2" * 64,
        path=bundle.component_paths["vae"],
        role="source",
    )
    plan = GenerationPlan(
        job_id="job_test",
        attempt_id="attempt_test",
        resolved_prompt="edit",
        seed=1,
        width=64,
        height=64,
        references=(reference, reference),
        output_slot="slot",
        output_slot_id="slot_id",
    )
    with pytest.raises(BackendPreparationError) as count_error:
        adapter.resolve_execution(plan)
    assert count_error.value.code == "operation_unsupported"
    bad_dimensions = GenerationPlan(
        job_id="job_test",
        attempt_id="attempt_test_2",
        resolved_prompt="generate",
        seed=1,
        width=65,
        height=64,
        references=(),
        output_slot="slot",
        output_slot_id="slot_id",
    )
    with pytest.raises(BackendPreparationError) as dimension_error:
        adapter.resolve_execution(bad_dimensions)
    assert dimension_error.value.code == "operation_unsupported"


def test_candidate_admission_rejects_more_references_than_graph_supports(
    tmp_path: Path,
) -> None:
    node_sha = hashlib.sha256(b"synthetic-comfyui-node-bundle-v1").hexdigest()
    recipe = recipe_document(node_sha256=node_sha)
    operations = recipe["operations"]
    edit = operations["edit"]
    edit["references"] = ["source", "reference"]
    edit["graph"]["10"] = {
        "class_type": "LoadImage",
        "inputs": {
            "image": "$artifact:1",
            "width": "$width",
            "height": "$height",
        },
    }
    bundle = build_comfyui_bundle(
        tmp_path,
        alter_recipe={"operations": operations},
    )

    with pytest.raises(BackendPreparationError, match="at most one reference"):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


@pytest.mark.parametrize("invalid_role", [["source"], {"role": "source"}])
def test_candidate_admission_rejects_non_string_reference_roles(
    tmp_path: Path,
    invalid_role: object,
) -> None:
    node_sha = hashlib.sha256(b"synthetic-comfyui-node-bundle-v1").hexdigest()
    recipe = recipe_document(node_sha256=node_sha)
    operations = recipe["operations"]
    edit = operations["edit"]
    edit["references"] = [invalid_role]
    bundle = build_comfyui_bundle(
        tmp_path,
        alter_recipe={"operations": operations},
    )

    with pytest.raises(BackendPreparationError) as error:
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)

    assert error.value.code == "recipe_invalid"


def test_comfyui_privacy_profile_classifies_proxy_fail_and_unknown_graph(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    plan = GenerationPlan(
        job_id="job_privacy",
        attempt_id="attempt_privacy",
        resolved_prompt="privacy",
        seed=1,
        width=64,
        height=64,
        references=(),
        output_slot="slot",
        output_slot_id="slot_id",
    )
    prepared = adapter.resolve_execution(plan)
    effective = prepared.resolved_record["effective_execution"]
    settings = comfyui_invocation_privacy_settings(
        prepared.argv,
        {**prepared.environment, "HTTPS_PROXY": "http://remote.example"},
        effective,
    )
    result = application_privacy_policy(adapter).evaluate(
        adapter.adapter_id,
        {"configuration_version": adapter.configuration["configuration_version"], "privacy": settings},
    )
    assert result.status is PrivacyComplianceStatus.FAIL
    assert "prohibited_setting_enabled" in result.reason_codes
    tampered = json.loads(json.dumps(effective))
    first = next(iter(tampered["graph"].values()))
    first["class_type"] = "RemoteUploadNode"
    settings = comfyui_invocation_privacy_settings(prepared.argv, prepared.environment, tampered)
    assert any(value is not False for value in settings.values())
    adapter.cleanup_execution(prepared)


@pytest.mark.parametrize("setting", ("host", "offline", "upload"))
def test_comfyui_known_forbidden_settings_fail_policy(
    tmp_path: Path, setting: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id=f"job_forbidden_{setting}",
            attempt_id=f"attempt_forbidden_{setting}",
            resolved_prompt="privacy",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        effective = json.loads(json.dumps(prepared.resolved_record["effective_execution"]))
        argv = prepared.argv
        expected_control = PrivacyControl.REMOTE_ENDPOINT_OR_PROXY
        if setting == "host":
            effective["configuration"]["server"]["host"] = "backend.example"
        elif setting == "offline":
            effective["configuration"]["server"]["offline"] = False
            expected_control = PrivacyControl.AUTOMATIC_NETWORK_FETCH_OR_UPDATE
        else:
            modified_argv = list(prepared.argv)
            feature_flag = modified_argv.index("--feature-flag")
            modified_argv[feature_flag + 1] = "enable_upload=true"
            argv = tuple(modified_argv)
            effective["configuration"]["server"]["argv"] = modified_argv
            expected_control = PrivacyControl.CONTENT_UPLOAD

        settings = comfyui_invocation_privacy_settings(
            argv, prepared.environment, effective
        )
        result = _privacy_result(adapter, settings)

        assert settings[expected_control.value] is True
        assert result.status is PrivacyComplianceStatus.FAIL
        assert "prohibited_setting_enabled" in result.reason_codes
    finally:
        adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("input_name", "input_value", "expected_control"),
    [
        ("remote_backend", "backend.example", PrivacyControl.REMOTE_ENDPOINT_OR_PROXY),
        ("telemetry", True, PrivacyControl.TELEMETRY),
    ],
    ids=("remote-endpoint", "telemetry"),
)
def test_comfyui_unknown_synchronized_pinned_input_is_unverified_and_refused(
    tmp_path: Path,
    input_name: str,
    input_value: object,
    expected_control: PrivacyControl,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    adapter = service.adapter
    assert isinstance(adapter, ComfyUIAdapter)
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_unknown_network_input",
            attempt_id="attempt_unknown_network_input",
            resolved_prompt="privacy",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        effective = json.loads(json.dumps(prepared.resolved_record["effective_execution"]))
        node_class, pin = next(iter(effective["configuration"]["nodes"].items()))
        pin["inputs"].append(input_name)
        node = next(
            node
            for node in effective["graph"].values()
            if node["class_type"] == node_class
        )
        node["inputs"][input_name] = input_value
        effective["request_body"]["prompt"] = effective["graph"]
        settings = comfyui_invocation_privacy_settings(
            prepared.argv, prepared.environment, effective
        )
        result = _privacy_result(adapter, settings)

        assert result.status is not PrivacyComplianceStatus.PASS
        assert settings[expected_control.value] is None
        assert "setting_value_unrecognized" in result.reason_codes

        record = dict(prepared.resolved_record)
        record["effective_execution"] = effective
        record["privacy"] = settings
        record["privacy_evidence"] = comfyui_resolved_privacy_evidence(
            result,
            effective,
            configuration_version=adapter.configuration["configuration_version"],
        ).to_dict()
        with pytest.raises(PrivacyComplianceError) as refused:
            service._require_execution_privacy(
                replace(prepared, resolved_record=record)
            )
        assert refused.value.result.status is not PrivacyComplianceStatus.PASS
        assert "setting_value_unrecognized" in refused.value.result.reason_codes
    finally:
        adapter.cleanup_execution(prepared)


def test_comfyui_privacy_profile_accepts_explicit_pinned_node_classes(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_privacy_node_class",
            attempt_id="attempt_privacy_node_class",
            resolved_prompt="privacy node class",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        settings = comfyui_invocation_privacy_settings(
            prepared.argv,
            prepared.environment,
            prepared.resolved_record["effective_execution"],
        )
        assert all(value is False for value in settings.values())
    finally:
        adapter.cleanup_execution(prepared)


def test_comfyui_privacy_profile_validates_python_hash_seed(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_privacy_hash_seed",
            attempt_id="attempt_privacy_hash_seed",
            resolved_prompt="privacy hash seed",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        for value, expected in (
            ("random", False),
            ("4294967296", None),
            ("-1", None),
            ("١", None),
        ):
            effective = json.loads(
                json.dumps(prepared.resolved_record["effective_execution"])
            )
            environment = {**prepared.environment, "PYTHONHASHSEED": value}
            effective["configuration"]["server"]["environment"] = environment
            settings = comfyui_invocation_privacy_settings(
                prepared.argv,
                environment,
                effective,
            )

            assert set(settings.values()) == {expected}
    finally:
        adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "changed", "empty", "non_string"],
)
def test_comfyui_privacy_profile_rejects_invalid_pinned_node_classes(
    tmp_path: Path,
    mutation: str,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id=f"job_privacy_node_class_{mutation}",
            attempt_id=f"attempt_privacy_node_class_{mutation}",
            resolved_prompt="privacy node class",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        effective = json.loads(json.dumps(prepared.resolved_record["effective_execution"]))
        _, pin = next(iter(effective["configuration"]["nodes"].items()))
        if mutation == "missing":
            pin.pop("class")
        elif mutation == "changed":
            pin["class"] = "RemoteUploadNode"
        elif mutation == "empty":
            pin["class"] = ""
        else:
            pin["class"] = 7  # type: ignore[assignment]

        settings = comfyui_invocation_privacy_settings(
            prepared.argv,
            prepared.environment,
            effective,
        )
        assert all(value is None for value in settings.values())
    finally:
        adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(("field", "value"), [("host", "0.0.0.0"), ("offline", False)])
def test_comfyui_privacy_profile_rejects_tampered_local_only_settings(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id=f"job_privacy_setting_{field}",
            attempt_id=f"attempt_privacy_setting_{field}",
            resolved_prompt="privacy setting",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        effective = json.loads(json.dumps(prepared.resolved_record["effective_execution"]))
        effective["configuration"]["server"][field] = value
        settings = comfyui_invocation_privacy_settings(
            prepared.argv,
            prepared.environment,
            effective,
        )
        control = (
            PrivacyControl.REMOTE_ENDPOINT_OR_PROXY
            if field == "host"
            else PrivacyControl.AUTOMATIC_NETWORK_FETCH_OR_UPDATE
        )
        assert settings[control.value] is True
        result = _privacy_result(adapter, settings)
        assert result.status is PrivacyComplianceStatus.FAIL
        assert "prohibited_setting_enabled" in result.reason_codes
    finally:
        adapter.cleanup_execution(prepared)


def test_comfyui_non_loopback_synchronized_listen_is_prohibited_and_refused(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    adapter = service.adapter
    assert isinstance(adapter, ComfyUIAdapter)
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_non_loopback_listen",
            attempt_id="attempt_non_loopback_listen",
            resolved_prompt="privacy listen",
            seed=1,
            width=64,
            height=64,
            references=(),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )

    try:
        effective = json.loads(json.dumps(prepared.resolved_record["effective_execution"]))
        argv = list(prepared.argv)
        listen_index = argv.index("--listen")
        argv[listen_index + 1] = "0.0.0.0"
        effective["configuration"]["server"]["argv"] = argv
        settings = comfyui_invocation_privacy_settings(
            argv, prepared.environment, effective
        )
        result = _privacy_result(adapter, settings)

        assert result.status is PrivacyComplianceStatus.FAIL
        assert settings[PrivacyControl.REMOTE_ENDPOINT_OR_PROXY.value] is True
        assert "prohibited_setting_enabled" in result.reason_codes

        record = dict(prepared.resolved_record)
        record["argv"] = argv
        record["effective_execution"] = effective
        record["privacy"] = settings
        record["privacy_evidence"] = comfyui_resolved_privacy_evidence(
            result,
            effective,
            configuration_version=adapter.configuration["configuration_version"],
        ).to_dict()
        with pytest.raises(PrivacyComplianceError) as refused:
            service._require_execution_privacy(
                replace(prepared, argv=tuple(argv), resolved_record=record)
            )

        assert refused.value.result.status is PrivacyComplianceStatus.FAIL
        assert "prohibited_setting_enabled" in refused.value.result.reason_codes
    finally:
        adapter.cleanup_execution(prepared)


def test_cli_requires_explicit_comfyui_candidate_and_selects_adapter(tmp_path: Path) -> None:
    with pytest.raises(cli.InputValidationError):
        cli._engine_adapter(
            Namespace(engine_candidate=None, engine_trusted_evidence=None, engine_backend="comfyui"),
            tmp_path / "images",
        )
    bundle = build_comfyui_bundle(tmp_path)
    adapter = cli._engine_adapter(
        Namespace(
            engine_candidate=bundle.declaration_path,
            engine_trusted_evidence=bundle.trusted_evidence_path,
            engine_backend="comfyui",
        ),
        tmp_path / "images",
    )
    assert isinstance(adapter, ComfyUIAdapter)
    assert adapter.configuration["invocation_contract"] == COMFYUI_INVOCATION_CONTRACT


def test_blackbox_cli_refuses_comfyui_without_explicit_candidate(
    tmp_path: Path,
) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source_root)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "submit",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--idempotency-key",
            "missing-comfyui-candidate",
            "--request-json",
            json.dumps({"prompt": "synthetic request"}),
            "--engine-backend",
            "comfyui",
        ],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    error = json.loads(result.stderr)
    assert error["error"]["message"] == (
        "--engine-backend comfyui requires --engine-candidate"
    )


def test_blackbox_cli_refuses_synthetic_job_without_runtime_pin_binding(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    job_id = service.enqueue(
        "blackbox-comfyui-worker",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    source_root = Path(__file__).resolve().parents[1] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source_root)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "worker",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--limit",
            "1",
            "--engine-candidate",
            str(bundle.declaration_path),
            "--engine-trusted-evidence",
            str(bundle.trusted_evidence_path),
            "--engine-backend",
            "comfyui",
        ],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode != 0
    assert "independently approved" in result.stderr
    assert service.get_provenance(job_id)["status"] == "queued"
    assert not (bundle.files / "prompt-count.txt").exists()


def test_source_edit_with_disconnected_load_image_is_refused_before_dispatch(
    tmp_path: Path,
) -> None:
    base = build_comfyui_bundle(tmp_path / "base")
    operations = json.loads(canonical_json(base.recipe_document["operations"]))
    edit_graph = operations["edit"]["graph"]
    edit_graph["12"] = {
        "class_type": "EmptyLatentImage",
        "inputs": {"width": "$width", "height": "$height", "batch_size": 1},
    }
    edit_graph["11"]["inputs"]["pixels"] = ["12", 0]
    bundle = build_comfyui_bundle(
        tmp_path / "disconnected-source",
        alter_recipe={"operations": operations},
    )
    output = tmp_path / "images"

    with pytest.raises(BackendPreparationError, match="source conditioning path"):
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=output,
        )

    assert not output.exists()
    assert not (bundle.files / "request-counts.json").exists()


def test_editing_capability_requires_a_validated_source_role(tmp_path: Path) -> None:
    base = build_comfyui_bundle(tmp_path / "base")
    operations = json.loads(canonical_json(base.recipe_document["operations"]))
    operations["edit"]["references"] = ["reference"]
    bundle = build_comfyui_bundle(
        tmp_path / "without-source-role",
        alter_recipe={"operations": operations},
    )

    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )

    assert adapter.capabilities.supports_editing is False
    assert adapter.capabilities.max_source_images == 0


def test_edit_plan_rejects_reference_roles_not_supported_by_workflow(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    source = ResolvedReference(
        artifact_id="art_" + "1" * 32,
        content_sha256="2" * 64,
        path=bundle.component_paths["vae"],
        role="source",
    )
    extra_reference = ResolvedReference(
        artifact_id="art_" + "3" * 32,
        content_sha256="4" * 64,
        path=bundle.component_paths["vae"],
        role="reference",
    )
    plan = GenerationPlan(
        job_id="job_unsupported_edit_roles",
        attempt_id="attempt_unsupported_edit_roles",
        resolved_prompt="edit with unsupported roles",
        seed=1,
        width=64,
        height=64,
        references=(source, extra_reference),
        output_slot="slot",
        output_slot_id="slot_id",
    )

    with pytest.raises(BackendPreparationError) as error:
        adapter.resolve_execution(plan)

    assert error.value.code == "operation_unsupported"


def test_effective_edit_graph_must_keep_the_approved_source_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    source = ResolvedReference(
        artifact_id="art_" + "5" * 32,
        content_sha256="6" * 64,
        path=bundle.component_paths["vae"],
        role="source",
    )
    plan = GenerationPlan(
        job_id="job_disconnected_effective_edit",
        attempt_id="attempt_disconnected_effective_edit",
        resolved_prompt="edit source path",
        seed=1,
        width=64,
        height=64,
        references=(source,),
        output_slot="slot",
        output_slot_id="slot_id",
    )
    original_substitute = comfyui._substitute

    def disconnected_substitute(value: object, replacements: object) -> object:
        graph = original_substitute(value, replacements)
        if isinstance(graph, dict) and "11" in graph and "10" in graph:
            graph["12"] = {
                "class_type": "EmptyLatentImage",
                "inputs": {"width": 64, "height": 64, "batch_size": 1},
            }
            graph["11"]["inputs"]["pixels"] = ["12", 0]
        return graph

    monkeypatch.setattr(comfyui, "_substitute", disconnected_substitute)

    with pytest.raises(BackendPreparationError, match="approved source conditioning"):
        adapter.resolve_execution(plan)


def test_edit_workflow_without_source_image_input_is_refused(tmp_path: Path) -> None:
    base = build_comfyui_bundle(tmp_path / "base")
    operations = json.loads(canonical_json(base.recipe_document["operations"]))
    operations["edit"]["graph"].pop("10")
    bundle = build_comfyui_bundle(
        tmp_path / "without-source-input",
        alter_recipe={"operations": operations},
    )

    with pytest.raises(BackendPreparationError, match="not a valid node link"):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)
