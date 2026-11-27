from __future__ import annotations

import pytest

from media_generation.cli import (
    MAX_INFERENCE_REQUEST_FILE_BYTES,
    _load_llama_cpp_configuration,
    _load_inference_workload_demands,
    _parse_inference_request_file,
    build_parser,
)
from media_generation.errors import InputValidationError
from media_generation.inference import InferenceKind, response_contract
from media_generation.privacy import LLAMA_CPP_SOURCE_VERSION


@pytest.mark.parametrize(
    ("action", "arguments"),
    [
        (
            "enqueue",
            [
                "--idempotency-key", "vision-request-1", "--request-file", "request.json",
                "--runtime-config", "runtime.json",
                "--inventory-report", "inventory.json",
                "--admission-policy", "policy.json",
                "--workload-demands", "demands.json",
            ],
        ),
        (
            "worker",
            [
                "--output-dir", "private-stage",
                "--runtime-config", "runtime.json",
                "--runtime-qualification", "qualification.json",
                "--candidate", "candidate.json",
                "--trusted-evidence", "trusted.json",
                "--inventory-report", "inventory.json",
                "--admission-policy", "policy.json",
                "--workload-demands", "demands.json",
            ],
        ),
        ("cancel", ["--job-id", "job-1"]),
        ("recover", ["--output-dir", "private-stage"]),
        ("provenance", ["--job-id", "job-1"]),
    ],
)
def test_parser_exposes_inference_lifecycle_commands(action, arguments):
    options = build_parser().parse_args(
        ["inference", action, "--db", "state.sqlite", *arguments]
    )

    assert options.command == "inference"
    assert options.inference_command == action


def test_request_file_parses_a_vision_request_without_cli_prompt_arguments(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        '{"kind":"vision","prompt":"Describe the scene",'
        '"image_path":"photo.png"}',
        encoding="utf-8",
    )

    request = _parse_inference_request_file(request_file)

    assert request.kind is InferenceKind.VISION
    assert request.prompt == "Describe the scene"
    assert request.image_path == tmp_path / "photo.png"


def test_request_file_rejects_duplicate_json_keys(tmp_path):
    request_file = tmp_path / "request.json"
    request_file.write_text(
        '{"kind":"text","kind":"vision","prompt":"hello"}',
        encoding="utf-8",
    )

    with pytest.raises(InputValidationError, match="duplicate"):
        _parse_inference_request_file(request_file)


def test_inference_request_file_reads_only_one_byte_past_its_limit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pathlib import Path

    source = tmp_path / "oversized-request.json"
    source.write_bytes(b"x" * (MAX_INFERENCE_REQUEST_FILE_BYTES + 1))
    read_sizes: list[int] = []
    original_open = Path.open

    class TrackingReader:
        def __init__(self, handle) -> None:
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            self.handle.close()

        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return self.handle.read(size)

    def tracked_open(path, mode="r", *args, **kwargs):
        return TrackingReader(original_open(path, mode, *args, **kwargs))

    monkeypatch.setattr(
        Path, "read_bytes", lambda *_args: pytest.fail("unbounded read_bytes was used")
    )
    monkeypatch.setattr(Path, "open", tracked_open)
    with pytest.raises(InputValidationError, match="size limit"):
        _parse_inference_request_file(source)

    assert read_sizes == [MAX_INFERENCE_REQUEST_FILE_BYTES + 1]


def test_runtime_configuration_resolves_component_paths_from_its_file(tmp_path):
    import hashlib
    import json

    executable = tmp_path / "llama-cli"
    model = tmp_path / "model.gguf"
    projector = tmp_path / "mmproj.gguf"
    executable.write_bytes(b"runtime")
    model.write_bytes(b"model")
    projector.write_bytes(b"projector")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    configuration_file = tmp_path / "runtime.json"
    configuration_file.write_text(
        json.dumps(
            {
                "executable_path": executable.name,
                "model_component": {
                    "role": "checkpoint",
                    "path": model.name,
                    "sha256": digest(model),
                },
                "projector_component": {
                    "role": "projector",
                    "path": projector.name,
                    "sha256": digest(projector),
                },
                "max_tokens": 256,
            }
        ),
        encoding="utf-8",
    )

    configuration = _load_llama_cpp_configuration(configuration_file)

    assert configuration.executable_path == executable
    assert configuration.model_component.path == model
    assert configuration.projector_component.path == projector
    assert configuration.max_tokens == 256


def test_runtime_qualification_file_parses_kind_specific_stream_evidence(tmp_path):
    import hashlib
    import json

    from media_generation.cli import _load_runtime_qualifications

    executable = tmp_path / "llama-cli"
    executable.write_bytes(b"runtime")
    model_sha256 = "1" * 64
    projector_sha256 = "2" * 64
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    hardware_sha256 = "3" * 64

    def qualification(kind):
        common = {
            "executable_sha256": executable_sha256,
            "model_sha256": model_sha256,
            "projector_sha256": projector_sha256,
            "hardware_fingerprint_sha256": hardware_sha256,
        }
        stream_common = {
            key: value
            for key, value in common.items()
            if key != "hardware_fingerprint_sha256"
        }
        return {
            "build": {
                "executable_path": executable.name,
                "source_version": LLAMA_CPP_SOURCE_VERSION,
                "binary_sha256": executable_sha256,
                "build_id": "test-build",
                "evidence_sha256": "4" * 64,
            },
            "response_stream": {
                **stream_common,
                "source_version": LLAMA_CPP_SOURCE_VERSION,
                "inference_kind": kind.value,
                "schema_sha256": response_contract(kind)["schema_sha256"],
                "stdout_contract": "single-json-document",
                "stderr_contract": "diagnostics-only",
                "evidence_sha256": "5" * 64,
            },
            "hardware": {
                **common,
                "assessment": "compatible",
                "evidence_sha256": "6" * 64,
            },
            "resources": {
                **common,
                "max_tokens": 256,
            "context_tokens": 4096,
            "max_image_pixels": 8_388_608 if kind is InferenceKind.VISION else None,
                "measured_peak_bytes": 1024,
                "available_memory_bytes": 4096,
                "evidence_sha256": "7" * 64,
            },
        }

    qualification_file = tmp_path / "qualification.json"
    qualification_file.write_text(
        json.dumps(
            {
                InferenceKind.TEXT.value: qualification(InferenceKind.TEXT),
                InferenceKind.VISION.value: qualification(InferenceKind.VISION),
            }
        ),
        encoding="utf-8",
    )

    qualifications = _load_runtime_qualifications(qualification_file)

    assert set(qualifications) == {InferenceKind.TEXT, InferenceKind.VISION}
    assert qualifications[InferenceKind.TEXT].response_stream.inference_kind is InferenceKind.TEXT
    assert qualifications[InferenceKind.VISION].response_stream.inference_kind is InferenceKind.VISION
    assert qualifications[InferenceKind.TEXT].resources.context_tokens == 4096
    assert qualifications[InferenceKind.TEXT].resources.max_image_pixels is None
    assert qualifications[InferenceKind.VISION].resources.context_tokens == 4096
    assert qualifications[InferenceKind.VISION].resources.max_image_pixels == 8_388_608


def test_workload_demand_file_loads_distinct_text_and_vision_budgets(tmp_path):
    import json

    def demand(kind, system_ram_bytes):
        return {
            "schema": "media-generation.workload-demand",
            "schema_version": 1,
            "kind": kind,
            "memory": {
                "status": "known",
                "system_ram_bytes": system_ram_bytes,
                "accelerator_memory_bytes": 0,
            },
            "context": {"status": "not_applicable"},
            "offload": {"status": "known", "mode": "none"},
            "residency": {"status": "known", "mode": "resident"},
        }

    demand_file = tmp_path / "demands.json"
    demand_file.write_text(
        json.dumps(
            {
                "text": demand("text", 1024),
                "vision": demand("vision", 2048),
            }
        ),
        encoding="utf-8",
    )

    demands = _load_inference_workload_demands(demand_file)

    assert demands[InferenceKind.TEXT].system_ram_bytes == 1024
    assert demands[InferenceKind.VISION].system_ram_bytes == 2048


def test_workload_demand_file_rejects_mismatched_kind(tmp_path):
    import json

    demand_file = tmp_path / "demands.json"
    demand_file.write_text(
        json.dumps(
            {
                "text": {
                    "schema": "media-generation.workload-demand",
                    "schema_version": 1,
                    "kind": "vision",
                    "memory": {"status": "unknown", "reason": "test"},
                    "context": {"status": "not_applicable"},
                    "offload": {"status": "not_applicable"},
                    "residency": {"status": "not_applicable"},
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(InputValidationError, match="mismatched kind"):
        _load_inference_workload_demands(demand_file)


def test_enqueue_command_keeps_prompt_out_of_json_output_and_uses_request_file(
    tmp_path, monkeypatch, capsys
):
    import json
    import sys
    from types import ModuleType

    from media_generation.cli import main
    import media_generation.cli as cli_module

    prompt = "private text that must not appear in command output"
    request_file = tmp_path / "request.json"
    request_file.write_text(
        json.dumps({"kind": "text", "prompt": prompt}), encoding="utf-8"
    )
    calls = {}

    class FakeInferenceService:
        def __init__(self, *, database_path, output_directory, **options):
            calls["init"] = (database_path, output_directory, options)

        def enqueue(self, idempotency_key, request, *, deadline_seconds):
            calls["request"] = (idempotency_key, request, deadline_seconds)
            return {"status": "queued", "job_id": "job-1"}

    module = ModuleType("media_generation.inference_service")
    module.InferenceService = FakeInferenceService
    monkeypatch.setitem(sys.modules, "media_generation.inference_service", module)
    configuration = object()
    admission_profile = object()
    workload_demands = {InferenceKind.TEXT: object()}
    monkeypatch.setattr(
        cli_module, "_load_llama_cpp_configuration", lambda _: configuration
    )
    monkeypatch.setattr(
        cli_module, "load_admission_profile", lambda *_: admission_profile
    )
    monkeypatch.setattr(
        cli_module, "_load_inference_workload_demands", lambda _: workload_demands
    )

    exit_code = main(
        [
            "inference", "enqueue", "--db", str(tmp_path / "jobs.sqlite"),
            "--idempotency-key", "request-1", "--request-file", str(request_file),
            "--runtime-config", "runtime.json",
            "--inventory-report", "inventory.json",
            "--admission-policy", "policy.json",
            "--workload-demands", "demands.json",
        ]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert calls["request"][1].prompt == prompt
    assert calls["init"][2] == {
        "configuration": configuration,
        "admission_profile": admission_profile,
        "workload_demand": workload_demands,
    }
    assert prompt not in output
    assert json.loads(output)["job_id"] == "job-1"


def test_inference_json_loader_reads_only_one_byte_past_its_limit(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pathlib import Path

    from media_generation.cli import _load_inference_json_object
    from media_generation.errors import InputValidationError

    limit = 256 * 1024
    source = tmp_path / "oversized.json"
    source.write_bytes(b"x" * (limit + 1))
    read_sizes: list[int] = []
    original_open = Path.open

    class TrackingReader:
        def __init__(self, handle) -> None:
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            self.handle.close()

        def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return self.handle.read(size)

    def tracked_open(path, mode="r", *args, **kwargs):
        return TrackingReader(original_open(path, mode, *args, **kwargs))

    monkeypatch.setattr(Path, "open", tracked_open)
    with pytest.raises(InputValidationError, match="size limit"):
        _load_inference_json_object(source, "inference configuration")

    assert read_sizes == [limit + 1]
