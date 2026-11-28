"""Contracts for a direct local llama.cpp invocation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from media_generation import llama_cpp
from media_generation.inference import (
    InferenceKind,
    ResponseCategory,
    response_contract,
    response_schema,
    render_prompt,
)
from media_generation.privacy import (
    LLAMA_CPP_ADAPTER_ID,
    LLAMA_CPP_CONFIGURATION_VERSION,
    LLAMA_CPP_SOURCE_VERSION,
    LLAMA_CPP_TOOL_ID,
    PrivacyControl,
    application_privacy_profile,
    invocation_privacy_settings,
)
from media_generation.supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)


def _write_file(path: Path, contents: bytes) -> str:
    path.write_bytes(contents)
    return hashlib.sha256(contents).hexdigest()


def _configuration(
    root: Path,
    *,
    executable: Path | None = None,
    max_tokens: int = 512,
    hardware_fingerprint_sha256: str | None = None,
) -> llama_cpp.LlamaCppConfiguration:
    root.mkdir(parents=True, exist_ok=True)
    executable = executable or root / "mtmd-cli"
    if not executable.exists():
        _write_file(executable, b"fake runtime binary")
    model_path = root / "language-model.gguf"
    projector_path = root / "vision-projector.gguf"
    model_hash = _write_file(model_path, b"fake model bytes")
    projector_hash = _write_file(projector_path, b"fake projector bytes")
    return llama_cpp.LlamaCppConfiguration(
        executable_path=executable,
        model_component=llama_cpp.LlamaCppComponent(
            role="checkpoint", path=model_path, sha256=model_hash
        ),
        projector_component=llama_cpp.LlamaCppComponent(
            role="vision_encoder", path=projector_path, sha256=projector_hash
        ),
        max_tokens=max_tokens,
        hardware_fingerprint_sha256=hardware_fingerprint_sha256,
    )


def _request(
    kind: InferenceKind = InferenceKind.TEXT,
    *,
    image_path: Path | None = None,
) -> llama_cpp.LlamaCppRequest:
    return llama_cpp.LlamaCppRequest(
        kind=kind,
        prompt="Describe the provided input.",
        image_path=image_path,
    )


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _qualification(
    config: llama_cpp.LlamaCppConfiguration,
    prepared: llama_cpp.PreparedInvocation,
    *,
    model_hash: str | None = None,
) -> llama_cpp.RuntimeQualification:
    contract = response_contract(prepared.request.kind)
    actual_binary_hash = hashlib.sha256(config.executable_path.read_bytes()).hexdigest()
    model_hash = model_hash or config.model_component.sha256
    host_hash = config.hardware_fingerprint_sha256 or _digest("qualified host")
    return llama_cpp.RuntimeQualification(
        build=llama_cpp.RuntimeBuildEvidence(
            executable_path=config.executable_path,
            source_version=LLAMA_CPP_SOURCE_VERSION,
            binary_sha256=actual_binary_hash,
            build_id="synthetic-test-build",
            evidence_sha256=_digest("build record"),
        ),
        response_stream=llama_cpp.ResponseStreamVerification(
            executable_sha256=actual_binary_hash,
            source_version=LLAMA_CPP_SOURCE_VERSION,
            model_sha256=model_hash,
            projector_sha256=config.projector_component.sha256,
            inference_kind=prepared.request.kind,
            schema_sha256=contract["schema_sha256"],
            stdout_contract="single-json-document",
            stderr_contract="diagnostics-only",
            evidence_sha256=_digest("stream record"),
        ),
        hardware=llama_cpp.HardwareCompatibilityEvidence(
            executable_sha256=actual_binary_hash,
            model_sha256=config.model_component.sha256,
            projector_sha256=config.projector_component.sha256,
            hardware_fingerprint_sha256=host_hash,
            assessment="compatible",
            evidence_sha256=_digest("hardware record"),
        ),
        resources=llama_cpp.ResourceDemandEvidence(
            executable_sha256=actual_binary_hash,
            model_sha256=config.model_component.sha256,
            projector_sha256=config.projector_component.sha256,
            hardware_fingerprint_sha256=host_hash,
            max_tokens=config.max_tokens,
            context_tokens=4096,
            max_image_pixels=(
                8_388_608 if prepared.request.kind is InferenceKind.VISION else None
            ),
            measured_peak_bytes=768,
            available_memory_bytes=1024,
            evidence_sha256=_digest("resource record"),
        ),
    )


class _RecordingAuthority(ExecutionEvidenceAuthority):
    def __init__(self) -> None:
        self._attempt_id = "fake-child-attempt"
        self.launches: list[LaunchFact] = []
        self.observations: list[ProcessObservation] = []

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    def verify_current(self) -> bool:
        return True

    def record_launch(self, fact: LaunchFact) -> None:
        self.launches.append(fact)

    def record_observation(self, fact: ProcessObservation) -> None:
        self.observations.append(fact)


def test_supervisor_checks_stop_request_before_spawning_a_child(tmp_path: Path) -> None:
    marker = tmp_path / "spawned"
    argv = (
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).write_text('started')",
    )
    authority = _RecordingAuthority()
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        stop_requested=lambda: True,
    )

    with pytest.raises(TimeoutError, match="before child start"):
        supervisor.run(argv, env={}, cwd=tmp_path)

    assert not marker.exists()
    assert authority.launches == []
    assert authority.observations == []


def test_application_configuration_binds_identity_privacy_and_components(
    tmp_path: Path,
) -> None:
    config = _configuration(
        tmp_path, hardware_fingerprint_sha256=_digest("qualified host")
    )
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )

        configuration = prepared.configuration

    assert "Describe the provided input." not in json.dumps(configuration)
    assert "Describe the provided input." not in repr(prepared)
    assert prepared.adapter_id == LLAMA_CPP_ADAPTER_ID
    assert configuration["backend_kind"] == "local-inference"
    assert configuration["invocation_contract"] == "llama-cpp-mtmd-exec-v1"
    assert configuration["cli_contract"] == "mtmd-cli-single-turn/v1"
    assert configuration["configuration_version"] == LLAMA_CPP_CONFIGURATION_VERSION
    assert configuration["engine"] == {
        "id": LLAMA_CPP_TOOL_ID,
        "version": LLAMA_CPP_SOURCE_VERSION,
    }
    assert configuration["privacy"] == invocation_privacy_settings(
        prepared.argv, prepared.environment
    )
    assert set(configuration["privacy"]) == {control.value for control in PrivacyControl}
    assert all(value is False for value in configuration["privacy"].values())
    assert configuration["components"]["model"] == {
        "role": "checkpoint",
        "path": str(config.model_component.path),
        "sha256": config.model_component.sha256,
    }
    assert configuration["components"]["projector"] == {
        "role": "vision_encoder",
        "path": str(config.projector_component.path),
        "sha256": config.projector_component.sha256,
    }
    assert configuration["dispatch_readiness"] == "requires-evidence"
    profile = application_privacy_profile(prepared.adapter_id, configuration)
    assert profile.tool_id == LLAMA_CPP_TOOL_ID
    assert profile.tool_version == LLAMA_CPP_SOURCE_VERSION
    assert profile.configuration_version == LLAMA_CPP_CONFIGURATION_VERSION
    assert configuration["responses"]["text"]["prompt_version"] == (
        "llama.cpp-mtmd-prompt/v1"
    )


def test_text_invocation_uses_private_files_offline_schema_and_finite_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _configuration(tmp_path, max_tokens=384)
    monkeypatch.setenv("LEAKED_PARENT_SETTING", "must-not-reach-child")

    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )

        argv = list(prepared.argv)
        assert "Describe the provided input." not in argv
        assert argv[argv.index("--file") + 1] == str(workspace / "prompt.txt")
        assert (workspace / "prompt.txt").read_text(encoding="utf-8") == (
            "Describe the provided input."
        )
        schema_path = Path(argv[argv.index("--json-schema-file") + 1])
        assert json.loads(schema_path.read_text(encoding="utf-8")) == response_schema(
            InferenceKind.TEXT
        )
        assert "--offline" in argv
        assert "--no-perf" in argv
        assert argv[argv.index("--predict") + 1] == "384"
        assert "--image" not in argv
        assert prepared.environment == {
            "PATH": os.defpath,
            "LLAMA_OFFLINE": "1",
            "LC_ALL": "C",
        }
        assert "LEAKED_PARENT_SETTING" not in prepared.environment
        assert all(value is False for value in prepared.configuration["privacy"].values())
        assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
        assert stat.S_IMODE((workspace / "prompt.txt").stat().st_mode) == 0o600
        assert stat.S_IMODE(schema_path.stat().st_mode) == 0o600

        contract = response_contract(InferenceKind.TEXT)
        assert prepared.schema_sha256 == contract["schema_sha256"]


def test_vision_invocation_passes_only_a_local_image_path(tmp_path: Path) -> None:
    config = _configuration(tmp_path)
    image_path = tmp_path / "input.png"
    image_path.write_bytes(b"fake image bytes")

    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config,
            _request(InferenceKind.VISION, image_path=image_path),
            workspace=workspace,
        )

        assert prepared.argv[prepared.argv.index("--image") + 1] == str(image_path)
        schema_path = Path(
            prepared.argv[prepared.argv.index("--json-schema-file") + 1]
        )
        assert json.loads(schema_path.read_text(encoding="utf-8")) == response_schema(
            InferenceKind.VISION
        )


def test_preparation_rechecks_model_and_projector_component_hashes(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path)
    config.model_component.path.write_bytes(b"changed model bytes")
    config.projector_component.path.write_bytes(b"changed projector bytes")

    with llama_cpp.private_workspace(tmp_path) as workspace:
        with pytest.raises(ValueError, match="component hash"):
            llama_cpp.prepare_invocation(config, _request(), workspace=workspace)


@pytest.mark.parametrize("max_tokens", [0, -1, True, 513, 8193])
def test_configuration_rejects_unbounded_or_invalid_token_limits(
    tmp_path: Path, max_tokens: int
) -> None:
    with pytest.raises(ValueError, match="max_tokens"):
        _configuration(tmp_path, max_tokens=max_tokens)


def test_runtime_configuration_binds_context_and_image_bounds(tmp_path: Path) -> None:
    config = _configuration(tmp_path, max_tokens=512)
    image_path = tmp_path / "image.png"
    image_path.write_bytes(b"synthetic image")
    cases = (
        (_request(), None),
        (
            llama_cpp.LlamaCppRequest(
                InferenceKind.VISION,
                "Describe the provided input.",
                image_path=image_path,
            ),
            8_388_608,
        ),
    )

    for request, expected_pixels in cases:
        with llama_cpp.private_workspace(tmp_path) as workspace:
            prepared = llama_cpp.prepare_invocation(
                config, request, workspace=workspace
            )

        assert "--ctx-size" in prepared.argv
        assert prepared.argv[prepared.argv.index("--ctx-size") + 1] == "4096"
        assert prepared.configuration["context_tokens"] == 4096
        assert prepared.configuration["image_limits"] == {
            "max_pixels": expected_pixels
        }
        assert prepared.configuration["generation"] == {"max_tokens": 512}


def test_qualification_rejects_resource_evidence_for_other_context_or_image_limit(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path, max_tokens=512)
    request = _request()
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(config, request, workspace=workspace)
    qualification = _qualification(config, prepared)

    bad_context = replace(
        qualification,
        resources=replace(qualification.resources, context_tokens=2048),
    )
    with pytest.raises(llama_cpp.RuntimeQualificationError):
        bad_context.require_for(config, prepared)

    bad_pixels = replace(
        qualification,
        resources=replace(qualification.resources, max_image_pixels=8_388_608),
    )
    with pytest.raises(llama_cpp.RuntimeQualificationError):
        bad_pixels.require_for(config, prepared)


def test_invocation_rejects_remote_or_mismatched_image_inputs(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path)
    with llama_cpp.private_workspace(tmp_path) as workspace:
        with pytest.raises(ValueError, match="local image"):
            llama_cpp.prepare_invocation(
                config,
                _request(InferenceKind.VISION, image_path=Path("https://example.invalid/a.png")),
                workspace=workspace,
            )

    with llama_cpp.private_workspace(tmp_path) as workspace:
        with pytest.raises(ValueError, match="requires an image"):
            llama_cpp.prepare_invocation(
                config,
                _request(InferenceKind.VISION),
                workspace=workspace,
            )


def test_dispatch_requires_records_before_calling_the_supervisor(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path)
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )

        class _UnusedSupervisor:
            calls = 0

            def run_capturing_stdout(self, *args: object, **kwargs: object) -> None:
                self.calls += 1
                raise AssertionError("dispatch must be blocked before spawn")

        supervisor = _UnusedSupervisor()
        with pytest.raises(llama_cpp.RuntimeQualificationError, match="evidence"):
            llama_cpp.execute_invocation(prepared, supervisor, qualification=None)
        assert supervisor.calls == 0


def test_dispatch_rejects_evidence_bound_to_a_different_model(
    tmp_path: Path,
) -> None:
    config = _configuration(tmp_path)
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )
        evidence = _qualification(config, prepared, model_hash=_digest("other model"))

        with pytest.raises(llama_cpp.RuntimeQualificationError, match="stream"):
            evidence.require_for(config, prepared)


def test_dispatch_rejects_modified_process_arguments_before_supervision(
    tmp_path: Path,
) -> None:
    config = _configuration(
        tmp_path, hardware_fingerprint_sha256=_digest("qualified host")
    )
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )
        altered = replace(
            prepared,
            argv=(*prepared.argv, "--prompt", "prompt text in argv"),
        )
        qualification = _qualification(config, prepared)

        class _UnusedSupervisor(ProcessSupervisor):
            def __init__(self) -> None:
                self.calls = 0

            def run_capturing_stdout(self, *args: object, **kwargs: object) -> None:
                self.calls += 1
                raise AssertionError("modified arguments must be rejected first")

        supervisor = _UnusedSupervisor()
        with pytest.raises(llama_cpp.RuntimeQualificationError, match="invocation"):
            llama_cpp.execute_invocation(
                altered, supervisor, qualification=qualification
            )
        assert supervisor.calls == 0


def test_persisted_response_prefix_can_be_reloaded_for_one_repair() -> None:
    prefix = b'{"status":"ok","answer":"bad json"'
    digest = hashlib.sha256(prefix).hexdigest()

    restored = llama_cpp.restore_response_prefix(
        prefix,
        response_size=len(prefix),
        response_sha256=digest,
    )

    assert restored == prefix
    with pytest.raises(ValueError, match="incomplete"):
        llama_cpp.restore_response_prefix(
            prefix,
            response_size=len(prefix) + 1,
            response_sha256=_digest("full output"),
        )


def test_dispatch_rechecks_component_hashes_before_supervision(
    tmp_path: Path,
) -> None:
    config = _configuration(
        tmp_path, hardware_fingerprint_sha256=_digest("qualified host")
    )
    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )
        qualification = _qualification(config, prepared)
        config.model_component.path.write_bytes(b"replaced after preparation")

        class _UnusedSupervisor(ProcessSupervisor):
            def __init__(self) -> None:
                self.calls = 0

            def run_capturing_stdout(self, *args: object, **kwargs: object) -> None:
                self.calls += 1
                raise AssertionError("changed component must be rejected first")

        supervisor = _UnusedSupervisor()
        with pytest.raises(
            llama_cpp.RuntimeQualificationError, match="component hash"
        ):
            llama_cpp.execute_invocation(
                prepared, supervisor, qualification=qualification
            )
        assert supervisor.calls == 0


def test_fake_child_response_is_captured_by_the_process_supervisor(
    tmp_path: Path,
) -> None:
    fake_executable = tmp_path / "fake-mtmd-cli"
    fake_executable.write_text(
        "#!" + sys.executable + "\n"
        "import sys\n"
        "sys.stdout.write('{\"status\":\"ok\",\"answer\":\"yes\","
        "\"evidence_spans\":[]}')\n"
        "sys.stderr.write('fake runtime diagnostic\\n')\n",
        encoding="utf-8",
    )
    fake_executable.chmod(0o700)
    config = _configuration(
        tmp_path,
        executable=fake_executable,
        hardware_fingerprint_sha256=_digest("qualified host"),
    )

    with llama_cpp.private_workspace(tmp_path) as workspace:
        prepared = llama_cpp.prepare_invocation(
            config, _request(), workspace=workspace
        )
        qualification = _qualification(config, prepared)
        authority = _RecordingAuthority()
        supervisor = ProcessSupervisor(
            authority,
            expected_argv=prepared.argv,
            expected_environment=prepared.environment,
            drain_timeout_seconds=0.2,
        )

        outcome = llama_cpp.execute_invocation(
            prepared, supervisor, qualification=qualification
        )

    assert outcome.response.category is ResponseCategory.VALID_OUTPUT
    assert outcome.response.value == {
        "status": "ok",
        "answer": "yes",
        "evidence_spans": [],
    }
    assert outcome.observation.exit_code == 0
    assert outcome.stdout_prefix == (
        b'{"status":"ok","answer":"yes","evidence_spans":[]}'
    )
    assert outcome.stdout_bytes == outcome.observation.stdout_bytes
    assert outcome.stdout_sha256 == outcome.observation.stdout_sha256
    assert outcome.stdout_prefix_sha256 == hashlib.sha256(
        outcome.stdout_prefix
    ).hexdigest()
    assert outcome.capture_record == {
        "response_bytes": outcome.stdout_prefix,
        "response_size": outcome.observation.stdout_bytes,
        "response_sha256": outcome.observation.stdout_sha256,
    }
    assert "Describe the provided input." not in repr(outcome)
    assert len(authority.launches) == 1
    assert len(authority.observations) == 1


def _run_text_response(
    root: Path,
    *,
    source_text: str,
    runtime_prompt: str,
    evidence_span: str,
) -> llama_cpp.LlamaCppOutcome:
    root.mkdir(parents=True, exist_ok=True)
    executable = root / "fake-text-response"
    payload = json.dumps(
        {
            "status": "ok",
            "answer": "checked",
            "evidence_spans": [evidence_span],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    executable.write_text(
        "#!" + sys.executable + "\n"
        "import sys\n"
        f"sys.stdout.write({payload!r})\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    config = _configuration(
        root,
        executable=executable,
        hardware_fingerprint_sha256=_digest("qualified host"),
    )
    request = llama_cpp.LlamaCppRequest(
        InferenceKind.TEXT,
        runtime_prompt,
        source_text=source_text,
    )
    with llama_cpp.private_workspace(root) as workspace:
        prepared = llama_cpp.prepare_invocation(config, request, workspace=workspace)
        qualification = _qualification(config, prepared)
        authority = _RecordingAuthority()
        supervisor = ProcessSupervisor(
            authority,
            expected_argv=prepared.argv,
            expected_environment=prepared.environment,
            drain_timeout_seconds=0.2,
        )
        return llama_cpp.execute_invocation(
            prepared, supervisor, qualification=qualification
        )


def test_text_evidence_uses_original_source_not_rendered_prompt(tmp_path: Path) -> None:
    source_text = 'The sign reads "LEAVE".\nPath: C:\\orchard.'
    evidence_span = '"LEAVE".\nPath: C:\\orchard.'
    runtime_prompt = render_prompt(InferenceKind.TEXT, source_text)
    accepted = _run_text_response(
        tmp_path / "accepted",
        source_text=source_text,
        runtime_prompt=runtime_prompt,
        evidence_span=evidence_span,
    )

    assert accepted.response.category is ResponseCategory.VALID_OUTPUT


def test_text_evidence_cannot_quote_application_instructions(tmp_path: Path) -> None:
    source_text = "A small bird in a tree."
    instruction = "Answer only from the supplied text"
    runtime_prompt = render_prompt(InferenceKind.TEXT, source_text)
    assert instruction in runtime_prompt
    assert instruction not in source_text

    outcome = _run_text_response(
        tmp_path,
        source_text=source_text,
        runtime_prompt=runtime_prompt,
        evidence_span=instruction,
    )

    assert outcome.response.category is ResponseCategory.SEMANTIC_REJECTION


def test_repair_text_evidence_cannot_quote_previous_response(tmp_path: Path) -> None:
    source_text = "A small bird in a tree."
    previous_response_text = "prior-only marker"
    runtime_prompt = render_prompt(
        InferenceKind.TEXT,
        source_text,
        repair_category=ResponseCategory.SEMANTIC_REJECTION,
        prior_response=previous_response_text,
    )
    assert previous_response_text in runtime_prompt
    assert previous_response_text not in source_text

    outcome = _run_text_response(
        tmp_path,
        source_text=source_text,
        runtime_prompt=runtime_prompt,
        evidence_span=previous_response_text,
    )

    assert outcome.response.category is ResponseCategory.SEMANTIC_REJECTION
