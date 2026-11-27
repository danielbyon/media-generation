"""Exercise inference attempts through the real service and SQLite store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sys

from PIL import Image
import pytest

import media_generation.inference_service as inference_service_module
from media_generation.domain import GenerationRequest
from media_generation.admission import (
    build_admission_profile,
    evaluate_admission,
    parse_admission_policy,
    parse_admission_profile,
    parse_workload_demand,
)
from media_generation.admission_store import PendingAdmission
from media_generation.inference import InferenceKind
from media_generation.inference_service import InferenceService
from media_generation.llama_cpp import (
    LlamaCppComponent,
    LlamaCppConfiguration,
    LlamaCppRequest,
    prepare_invocation,
    private_workspace,
)
from media_generation.privacy import PrivacyComplianceResult
from media_generation.service import GenerationService
from media_generation.store import SQLiteStore
from test_llama_cpp import _qualification
from test_resource_admission import GIB, inventory_report, workload_demand


def _demand(
    kind: InferenceKind, *, system_ram_bytes: int = 64 * GIB
):
    payload = workload_demand(
        kind=kind.value,
        system_ram_bytes=system_ram_bytes,
        accelerator_memory_bytes=0,
    )
    payload["context"] = {"status": "known", "tokens": 4096}
    return parse_workload_demand(payload)


def _write_fake_runtime(
    root: Path,
    responses: list[dict[str, object]],
    *,
    raw_stdout_by_index: dict[int, bytes] | None = None,
    delay_seconds: float = 0.0,
    started_marker: Path | None = None,
) -> tuple[Path, Path]:
    response_file = root / "responses.json"
    counter_file = root / "invocations.txt"
    prompt_log = root / "prompts.jsonl"
    image_hash = root / "image.sha256"
    response_file.write_text(json.dumps(responses), encoding="utf-8")
    marker_statement = (
        ""
        if started_marker is None
        else f"pathlib.Path({str(started_marker)!r}).write_text('started')\n"
    )
    executable = root / "fake-mtmd-cli"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, json, pathlib, sys, time\n"
        f"response_file = pathlib.Path({str(response_file)!r})\n"
        f"counter_file = pathlib.Path({str(counter_file)!r})\n"
        f"prompt_log = pathlib.Path({str(prompt_log)!r})\n"
        "responses = json.loads(response_file.read_text(encoding='utf-8'))\n"
        f"raw_stdout_by_index = {raw_stdout_by_index or {}}\n"
        "index = int(counter_file.read_text() if counter_file.exists() else '0')\n"
        "counter_file.write_text(str(index + 1))\n"
        "prompt_path = pathlib.Path(sys.argv[sys.argv.index('--file') + 1])\n"
        "with prompt_log.open('a', encoding='utf-8') as output:\n"
        "    output.write(json.dumps(prompt_path.read_text(encoding='utf-8')) + '\\n')\n"
        "if '--image' in sys.argv:\n"
        "    image_path = pathlib.Path(sys.argv[sys.argv.index('--image') + 1])\n"
        f"    pathlib.Path({str(image_hash)!r}).write_text("
        "hashlib.sha256(image_path.read_bytes()).hexdigest())\n"
        f"{marker_statement}"
        f"time.sleep({delay_seconds!r})\n"
        "raw_stdout = raw_stdout_by_index.get(index)\n"
        "if raw_stdout is not None:\n"
        "    sys.stdout.buffer.write(raw_stdout)\n"
        "else:\n"
        "    sys.stdout.buffer.write(json.dumps("
        "responses[min(index, len(responses) - 1)],"
        " separators=(',', ':')).encode('utf-8'))\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable, counter_file


def _restarted_service(service: InferenceService) -> InferenceService:
    """Open a new worker service over the same durable request database."""
    return InferenceService(
        database_path=service.database_path,
        output_directory=service.output_directory,
        configuration=service.configuration,
        runtime_qualification=service.runtime_qualifications,
        candidate_declaration_path=service.candidate_declaration_path,
        candidate_trusted_evidence=service.candidate_trusted_evidence,
        admission_profile=service.admission_profile,
        workload_demand=service.workload_demands,
    )


def _service(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: InferenceKind,
    prompt: str,
    responses: list[dict[str, object]],
    *,
    image_path: Path | None = None,
    raw_stdout_by_index: dict[int, bytes] | None = None,
    delay_seconds: float = 0.0,
    started_marker: Path | None = None,
) -> tuple[InferenceService, LlamaCppRequest, Path]:
    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 0},
            }
        ),
    )
    executable, counter_file = _write_fake_runtime(
        root,
        responses,
        raw_stdout_by_index=raw_stdout_by_index,
        delay_seconds=delay_seconds,
        started_marker=started_marker,
    )
    model = root / "checkpoint.gguf"
    projector = root / "projector.gguf"
    model.write_bytes(b"synthetic model bytes")
    projector.write_bytes(b"synthetic projector bytes")
    configuration = LlamaCppConfiguration(
        executable_path=executable,
        model_component=LlamaCppComponent(
            role="checkpoint",
            path=model,
            sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        ),
        projector_component=LlamaCppComponent(
            role="vision_encoder",
            path=projector,
            sha256=hashlib.sha256(projector.read_bytes()).hexdigest(),
        ),
        max_tokens=64,
        hardware_fingerprint_sha256=profile.environment_fingerprint.removeprefix(
            "sha256:"
        ),
    )
    request = LlamaCppRequest(kind, prompt, image_path)
    with private_workspace(root) as workspace:
        prepared = prepare_invocation(configuration, request, workspace=workspace)
        qualification = _qualification(configuration, prepared)
    candidate_path = root / "candidate.json"
    candidate_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        inference_service_module, "parse_candidate", lambda _: object()
    )
    monkeypatch.setattr(
        inference_service_module,
        "verify_candidate",
        lambda *args, **kwargs: {
            "status": "ready",
            "evidence": {"independent_evidence_authority": "ready"},
        },
    )
    monkeypatch.setattr(
        InferenceService, "_candidate_matches_configuration", lambda self, _: True
    )
    demand = _demand(kind)
    service = InferenceService(
        database_path=root / "inference.sqlite3",
        output_directory=root / "private-output",
        configuration=configuration,
        runtime_qualification={kind: qualification},
        candidate_declaration_path=candidate_path,
        admission_profile=profile,
        workload_demand={kind: demand},
    )
    capacity = evaluate_admission(profile, demand)
    assert capacity.status == "queued"
    service._admission_for = lambda _kind, _privacy: PendingAdmission(
        profile=profile,
        demand=demand,
        decision=capacity.status,
        reason=capacity.reason,
        required_bytes=capacity.required_bytes,
        unknown_reasons=capacity.unknown_reasons,
    )
    service.admission_profile = replace(
        profile, apex_qualification="ready", apex_evidence=True
    )
    return service, request, counter_file


@pytest.mark.parametrize(
    ("kind", "response"),
    [
        (
            InferenceKind.TEXT,
            {
                "status": "ok",
                "answer": "blue fox",
                "evidence_spans": ["blue fox says \"hello\" at C:\\tmp.\n"],
            },
        ),
        (
            InferenceKind.VISION,
            {"status": "ok", "observations": []},
        ),
    ],
)
def test_successful_inference_persists_result_after_group_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: InferenceKind,
    response: dict[str, object],
) -> None:
    root = tmp_path / kind.value
    root.mkdir()
    image_path = None
    if kind is InferenceKind.VISION:
        image_path = root / "input.png"
        with Image.new("RGB", (4, 3), "blue") as image:
            image.save(image_path, format="PNG")
    service, request, counter_file = _service(
        root,
        monkeypatch,
        kind,
        'A blue fox says "hello" at C:\\tmp.\n',
        [response],
        image_path=image_path,
    )
    queued = service.enqueue(f"success-{kind.value}", request)
    assert queued["status"] == "queued"
    store = service._store
    finalize = store.finalize_inference_attempt
    proof_seen_before_finalize = False

    def finalize_after_proof(**values: object) -> bool:
        nonlocal proof_seen_before_finalize
        with store._connection() as connection:
            attempt = connection.execute(
                "SELECT observation_evidence_json FROM execution_attempts WHERE attempt_id = ?",
                (values["attempt_id"],),
            ).fetchone()
            resource = connection.execute(
                "SELECT state FROM execution_resource WHERE id = 1"
            ).fetchone()
        observation = json.loads(attempt["observation_evidence_json"])
        assert observation["process_group_terminated"] is True
        assert resource["state"] == "claimed"
        proof_seen_before_finalize = True
        return finalize(**values)

    store.finalize_inference_attempt = finalize_after_proof
    report = service.work(job_id=str(queued["job_id"]))

    assert proof_seen_before_finalize
    assert report["status"] == "complete"
    assert counter_file.read_text(encoding="utf-8") == "1"
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["status"] == "succeeded"
    assert len(provenance["attempts"]) == 1
    attempt = provenance["attempts"][0]
    assert attempt["status"] == "succeeded"
    assert attempt["termination_proven"] is True
    assert "value" not in attempt["result"]
    with store._connection() as connection:
        persisted_result = connection.execute(
            "SELECT result_json FROM inference_attempt_results WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
    assert json.loads(persisted_result["result_json"]) == response
    validation = attempt["result"]["validation"]
    receipt = validation["qualification_receipt"]
    configuration = service.configuration
    qualification = service.runtime_qualifications[kind]
    with service._store._connection() as connection:
        configuration_json = connection.execute(
            "SELECT adapter_configuration_json FROM inference_requests WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()["adapter_configuration_json"]
    assert receipt["attempt_id"] == attempt["attempt_id"]
    assert receipt["configuration_sha256"] == hashlib.sha256(
        configuration_json.encode("utf-8")
    ).hexdigest()
    assert receipt["source_version"] == qualification.build.source_version
    assert receipt["build_id_sha256"] == hashlib.sha256(
        qualification.build.build_id.encode("utf-8")
    ).hexdigest()
    assert receipt["executable_sha256"] == qualification.build.binary_sha256
    assert receipt["model_sha256"] == configuration.model_component.sha256
    assert receipt["projector_sha256"] == configuration.projector_component.sha256
    assert receipt["hardware_fingerprint_sha256"] == (
        configuration.hardware_fingerprint_sha256
    )
    assert receipt["stream_evidence_sha256"] == (
        qualification.response_stream.evidence_sha256
    )
    assert receipt["build_evidence_sha256"] == qualification.build.evidence_sha256
    assert receipt["hardware_evidence_sha256"] == qualification.hardware.evidence_sha256
    assert receipt["resource_evidence_sha256"] == qualification.resources.evidence_sha256
    assert str(configuration.executable_path) not in json.dumps(receipt)
    assert request.prompt not in json.dumps(validation)
    assert provenance["execution"]["resource_state"] == "available"
    reused = service.enqueue(f"success-{kind.value}", request)
    assert reused["job_id"] == queued["job_id"]
    assert reused["created"] is False
    assert reused["status"] == "succeeded"
    assert counter_file.read_text(encoding="utf-8") == "1"


@pytest.mark.parametrize(
    ("response", "private_content"),
    [
        pytest.param(
            {
                "status": "ok",
                "answer": "private generated answer",
                "evidence_spans": ["private source phrase"],
            },
            "private generated answer",
            id="answer",
        ),
        pytest.param(
            {"status": "refused", "reason": "private refusal detail"},
            "private refusal detail",
            id="refusal",
        ),
    ],
)
def test_public_provenance_omits_validated_response_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
    private_content: str,
) -> None:
    service, request, _ = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A private test prompt.",
        [response],
    )
    queued = service.enqueue("redacted-response", request)
    service.work(job_id=str(queued["job_id"]))

    provenance = service.provenance(str(queued["job_id"]))
    public_json = json.dumps(provenance, ensure_ascii=False)
    assert private_content not in public_json
    attempt_result = provenance["attempts"][0]["result"]
    assert "value" not in attempt_result
    assert "validation" in attempt_result


def test_prelaunch_runtime_failure_persists_no_qualification_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue("prelaunch-without-receipt", request)

    def fail_before_launch(*args: object, **kwargs: object):
        raise RuntimeError("simulated runtime setup failure")

    monkeypatch.setattr(
        inference_service_module,
        "execute_invocation",
        fail_before_launch,
    )
    service.work(job_id=str(queued["job_id"]))

    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["attempts"][0]["result"]["validation"][
        "qualification_receipt"
    ] is None
    assert not counter_file.exists()


def test_claim_rejects_admission_different_from_worker_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued_demand = service.workload_demands[InferenceKind.TEXT]
    queued = service.enqueue("admission-preflight-binding", request)
    assert queued["status"] == "queued"
    with service._store._connection() as connection:
        admission_json = connection.execute(
            "SELECT admission_profile_json FROM execution_admissions WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()["admission_profile_json"]
    profile = parse_admission_profile(json.loads(admission_json))

    worker_demand = _demand(InferenceKind.TEXT, system_ram_bytes=32 * GIB)
    worker_capacity = evaluate_admission(profile, worker_demand)
    assert worker_capacity.status == "queued"
    assert worker_demand != queued_demand
    service.workload_demands = {InferenceKind.TEXT: worker_demand}
    service._admission_for = lambda _kind, _privacy: PendingAdmission(
        profile=profile,
        demand=worker_demand,
        decision=worker_capacity.status,
        reason=worker_capacity.reason,
        required_bytes=worker_capacity.required_bytes,
        unknown_reasons=worker_capacity.unknown_reasons,
    )

    report = service.work(job_id=str(queued["job_id"]))

    assert report == {
        "job_id": queued["job_id"],
        "status": "preflight_blocked",
        "reason": "admission_evidence_mismatch",
    }
    assert not counter_file.exists()
    with service._store._connection() as connection:
        attempt_count = connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()[0]
        resource = connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()
        admission = connection.execute(
            "SELECT decision, workload_demand_json FROM execution_admissions "
            "WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
    assert attempt_count == 0
    assert resource["state"] == "available"
    assert admission["decision"] == "queued"
    assert json.loads(admission["workload_demand_json"]) == queued_demand.to_dict()


def test_vision_execution_uses_the_image_bytes_validated_during_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "vision-image-snapshot"
    root.mkdir()
    image_path = root / "input.png"
    with Image.new("RGB", (4, 3), "blue") as image:
        image.save(image_path, format="PNG")
    validated_digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
    service, request, counter_file = _service(
        root,
        monkeypatch,
        InferenceKind.VISION,
        "Describe the image.",
        [{"status": "ok", "observations": []}],
        image_path=image_path,
    )
    queued = service.enqueue("vision-image-snapshot", request)
    assert queued["status"] == "queued"

    execute = inference_service_module.execute_invocation

    def replace_source_after_preflight(prepared, supervisor, *, qualification):
        with Image.new("RGB", (4, 3), "red") as image:
            image.save(image_path, format="PNG")
        return execute(prepared, supervisor, qualification=qualification)

    monkeypatch.setattr(
        inference_service_module,
        "execute_invocation",
        replace_source_after_preflight,
    )

    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "complete"
    assert (root / "image.sha256").read_text(encoding="utf-8") == validated_digest
    assert hashlib.sha256(image_path.read_bytes()).hexdigest() != validated_digest
    assert counter_file.read_text(encoding="utf-8") == "1"


def test_invalid_response_repairs_once_with_a_distinct_attempt_and_original_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_span = 'The sign says "ORCHARD" at C:\\orchard.\n'
    source = f"Read this line: {source_span}"
    first_response = {
        "status": "ok",
        "answer": "The sign names a place.",
        "evidence_spans": ["repair-only marker"],
    }
    repaired_response = {
        "status": "ok",
        "answer": "The sign names a place.",
        "evidence_spans": [source_span],
    }
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        source,
        [first_response, repaired_response],
    )
    queued = service.enqueue("repair-source", request)

    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "complete"
    assert report["jobs"][0]["outcome"] == "succeeded"
    assert counter_file.read_text(encoding="utf-8") == "2"
    prompts = [
        json.loads(line)
        for line in (tmp_path / "prompts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "repair-only marker" in prompts[1]
    provenance = service.provenance(str(queued["job_id"]))
    attempts = provenance["attempts"]
    assert len(attempts) == 2
    assert attempts[0]["attempt_id"] != attempts[1]["attempt_id"]
    assert attempts[0]["result"]["validation"]["category"] == "semantic_rejection"
    assert "value" not in attempts[1]["result"]
    with service._store._connection() as connection:
        persisted_result = connection.execute(
            "SELECT result_json FROM inference_attempt_results WHERE attempt_id = ?",
            (attempts[1]["attempt_id"],),
        ).fetchone()
    assert json.loads(persisted_result["result_json"]) == repaired_response


@pytest.mark.parametrize("worker_restart", [False, True], ids=["same-worker", "restart"])
def test_non_utf8_response_repairs_without_leaving_request_queued(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    worker_restart: bool,
) -> None:
    invalid_response = b"\xff{not-json"
    repaired_response = {
        "status": "ok",
        "answer": "The gate is open.",
        "evidence_spans": ["The gate is open."],
    }
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "The gate is open.",
        [repaired_response],
        raw_stdout_by_index={0: invalid_response},
    )
    queued = service.enqueue("non-utf8-response-repair", request)

    if worker_restart:
        invoke = service._invoke_and_finalize

        def lose_worker_after_first_invalid(*args: object, **kwargs: object):
            result = invoke(*args, **kwargs)
            if result.outcome == "invalid_output":
                raise RuntimeError("simulated worker loss after invalid output")
            return result

        service._invoke_and_finalize = lose_worker_after_first_invalid
        with pytest.raises(RuntimeError, match="after invalid output"):
            service.work(job_id=str(queued["job_id"]))
        service = _restarted_service(service)

    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "complete"
    assert report["jobs"][0]["outcome"] == "succeeded"
    assert counter_file.read_text(encoding="utf-8") == "2"
    prompts = [
        json.loads(line)
        for line in (tmp_path / "prompts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "\ufffd" in prompts[1]
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["status"] == "succeeded"
    assert len(provenance["attempts"]) == 2
    assert provenance["attempts"][0]["result"]["validation"]["category"] == (
        "malformed_json_unknown_termination"
    )
    assert provenance["attempts"][0]["result"]["repair_eligible"] is True
    assert provenance["attempts"][0]["result"]["response_sha256"] == hashlib.sha256(
        invalid_response
    ).hexdigest()
    assert "value" not in provenance["attempts"][1]["result"]
    with service._store._connection() as connection:
        persisted_result = connection.execute(
            "SELECT result_json FROM inference_attempt_results WHERE attempt_id = ?",
            (provenance["attempts"][1]["attempt_id"],),
        ).fetchone()
    assert json.loads(persisted_result["result_json"]) == repaired_response


def test_repair_budget_survives_worker_restart_and_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "The orchard gate is open."
    first_response = {
        "status": "ok",
        "answer": "The gate is open.",
        "evidence_spans": ["invalid first response"],
    }
    second_response = {
        "status": "ok",
        "answer": "The gate is open.",
        "evidence_spans": ["invalid repair response"],
    }
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        source,
        [first_response, second_response],
    )
    queued = service.enqueue("repair-restart", request)
    invoke = service._invoke_and_finalize

    def lose_worker_after_finalization(*args: object, **kwargs: object):
        result = invoke(*args, **kwargs)
        if result.outcome == "invalid_output":
            raise RuntimeError("simulated worker loss after durable finalization")
        return result

    service._invoke_and_finalize = lose_worker_after_finalization
    with pytest.raises(RuntimeError, match="simulated worker loss"):
        service.work(job_id=str(queued["job_id"]))

    restarted = _restarted_service(service)
    before_recovery = restarted.provenance(str(queued["job_id"]))
    recovery = restarted.recover()
    after_recovery = restarted.provenance(str(queued["job_id"]))
    assert recovery == {"status": "complete", "resource_state": "available"}
    assert after_recovery == before_recovery
    assert after_recovery["status"] == "queued"
    assert after_recovery["admission"]["decision"] == "queued"
    assert after_recovery["attempts"][0]["result"]["repair_eligible"] is True
    report = restarted.work(job_id=str(queued["job_id"]))

    assert report["status"] == "complete"
    assert report["jobs"][0]["outcome"] == "repair_exhausted"
    assert counter_file.read_text(encoding="utf-8") == "2"
    prompts = [
        json.loads(line)
        for line in (tmp_path / "prompts.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "invalid first response" in prompts[1]
    attempts = restarted.provenance(str(queued["job_id"]))["attempts"]
    assert len(attempts) == 2
    assert attempts[0]["attempt_id"] != attempts[1]["attempt_id"]
    assert attempts[0]["result"]["outcome"] == "invalid_output"
    assert attempts[1]["result"]["outcome"] == "repair_exhausted"
    assert attempts[1]["result"]["validation"]["category"] == "semantic_rejection"
    assert attempts[1]["result"]["repair_eligible"] is False

    restarted.work(job_id=str(queued["job_id"]))
    assert counter_file.read_text(encoding="utf-8") == "2"


def test_deadline_expiring_during_preflight_prevents_claim_and_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deadline"
    root.mkdir()
    started_marker = root / "started"
    service, request, counter_file = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
        started_marker=started_marker,
    )
    queued = service.enqueue("preflight-deadline", request, deadline_seconds=1.0)
    frozen_time = inference_service_module._utc_now()
    clock = [frozen_time]
    monkeypatch.setattr(inference_service_module, "_utc_now", lambda: clock[0])
    original_preflight = service._preflight

    def expire_after_preflight(*args: object, **kwargs: object):
        prepared = original_preflight(*args, **kwargs)
        clock[0] += timedelta(seconds=2)
        return prepared

    service._preflight = expire_after_preflight
    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "preflight_blocked"
    assert report["reason"] == "request_deadline_expired"
    assert not started_marker.exists()
    assert not counter_file.exists()
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["attempts"] == []
    assert provenance["execution"]["resource_state"] == "available"


def test_timeout_after_launch_releases_only_after_confirmed_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "timeout"
    root.mkdir()
    service, request, counter_file = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
        delay_seconds=5.0,
    )
    queued = service.enqueue("timeout-after-launch", request, deadline_seconds=0.1)

    report = service.work(job_id=str(queued["job_id"]))

    assert counter_file.read_text(encoding="utf-8") == "1"
    assert report["status"] == "complete"
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["attempts"][0]["termination_proven"] is True
    assert provenance["execution"]["resource_state"] == "available"


def test_cancellation_releases_after_supervisor_confirms_group_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cancel"
    root.mkdir()
    started_marker = root / "started"
    service, request, counter_file = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
        delay_seconds=10.0,
        started_marker=started_marker,
    )
    queued = service.enqueue("cancel-after-launch", request)
    results: list[dict[str, object]] = []
    errors: list[BaseException] = []

    def run_worker() -> None:
        try:
            results.append(service.work(job_id=str(queued["job_id"])))
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run_worker)
    worker.start()
    deadline = time.monotonic() + 5.0
    while not started_marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started_marker.exists()

    service.cancel(str(queued["job_id"]))
    worker.join(timeout=10.0)

    assert not worker.is_alive()
    assert errors == []
    assert results[0]["status"] == "complete"
    assert counter_file.read_text(encoding="utf-8") == "1"
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["status"] == "canceled"
    assert provenance["attempts"][0]["termination_proven"] is True
    assert provenance["execution"]["resource_state"] == "available"


def test_recover_fails_interrupted_inference_after_proven_termination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue("recover-proven-interruption", request)
    execute = inference_service_module.execute_invocation

    def lose_worker_after_supervised_exit(prepared, supervisor, *, qualification):
        execute(prepared, supervisor, qualification=qualification)
        raise SystemExit("simulated worker loss after supervised exit")

    monkeypatch.setattr(
        inference_service_module,
        "execute_invocation",
        lose_worker_after_supervised_exit,
    )
    with pytest.raises(SystemExit, match="simulated worker loss"):
        service.work(job_id=str(queued["job_id"]))

    report = service.recover()
    provenance = service.provenance(str(queued["job_id"]))

    assert report["status"] == "complete"
    assert report["resource_state"] == "available"
    assert provenance["status"] == "failed"
    assert provenance["execution"]["retry_eligible"] is False
    assert len(provenance["attempts"]) == 1
    assert provenance["attempts"][0]["failure_class"] == "terminal"
    assert provenance["attempts"][0]["termination_proven"] is True
    assert provenance["attempts"][0]["result"]["outcome"] == "runtime_failure"
    assert counter_file.read_text(encoding="utf-8") == "1"


def test_recover_quarantines_interrupted_inference_without_termination_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue("recover-unproven-interruption", request)
    mark_observed = service._store.mark_inference_execution_observed

    def record_unsettled_group(**values: object) -> bool:
        record = dict(values["record"])
        record["process_group_terminated"] = False
        return mark_observed(**{**values, "record": record})

    service._store.mark_inference_execution_observed = record_unsettled_group
    execute = inference_service_module.execute_invocation

    def lose_worker_with_unsettled_group(prepared, supervisor, *, qualification):
        execute(prepared, supervisor, qualification=qualification)
        raise SystemExit("simulated worker loss without termination proof")

    monkeypatch.setattr(
        inference_service_module,
        "execute_invocation",
        lose_worker_with_unsettled_group,
    )
    with pytest.raises(SystemExit, match="without termination proof"):
        service.work(job_id=str(queued["job_id"]))

    report = service.recover()
    provenance = service.provenance(str(queued["job_id"]))
    repeated_report = service.recover()
    repeated_provenance = service.provenance(str(queued["job_id"]))

    assert report["status"] == "attention_required"
    assert report["resource_state"] == "quarantined"
    assert provenance["status"] == "ambiguous"
    assert provenance["attempts"][0]["failure_class"] == "ambiguous"
    assert provenance["attempts"][0]["termination_proven"] is False
    assert provenance["attempts"][0]["result"]["outcome"] == "runtime_failure"
    assert repeated_report == report
    assert repeated_provenance == provenance
    assert counter_file.read_text(encoding="utf-8") == "1"


def test_unsettled_process_group_evidence_keeps_resource_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "unsettled"
    root.mkdir()
    service, request, _ = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue("unsettled-process-group", request)
    mark_observed = service._store.mark_inference_execution_observed

    def record_unsettled_group(**values: object) -> bool:
        record = dict(values["record"])
        record["process_group_terminated"] = False
        return mark_observed(**{**values, "record": record})

    service._store.mark_inference_execution_observed = record_unsettled_group
    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "attention_required"
    job_report = report["jobs"][0]
    assert job_report["outcome"] == "runtime_failure"
    assert job_report["category"] == "runtime_failure"
    assert job_report["result"] is None
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["status"] == "ambiguous"
    assert provenance["attempts"][0]["termination_proven"] is False
    assert provenance["attempts"][0]["status"] == "failed"
    assert provenance["attempts"][0]["result"]["outcome"] == "runtime_failure"
    assert "value" not in provenance["attempts"][0]["result"]
    assert (
        provenance["attempts"][0]["result"]["validation"][
            "validated_response_category"
        ]
        == "valid_output"
    )
    assert provenance["execution"]["resource_state"] == "quarantined"


@pytest.mark.parametrize("failure_point", ["result", "resource"])
def test_finalization_failure_rolls_back_result_and_resource_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    root = tmp_path / failure_point
    root.mkdir()
    service, request, _ = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue(f"rollback-{failure_point}", request)
    with sqlite3.connect(service.database_path) as connection:
        if failure_point == "result":
            connection.execute(
                """CREATE TRIGGER reject_inference_result
                   BEFORE INSERT ON inference_attempt_results
                   BEGIN SELECT RAISE(ABORT, 'result write rejected'); END"""
            )
        else:
            connection.execute(
                """CREATE TRIGGER reject_resource_release
                   BEFORE UPDATE OF state ON execution_resource
                   WHEN OLD.state = 'claimed' AND NEW.state = 'available'
                   BEGIN SELECT RAISE(ABORT, 'resource release rejected'); END"""
            )

    report = service.work(job_id=str(queued["job_id"]))

    with service._store._connection() as connection:
        job = connection.execute(
            "SELECT status, current_attempt_id FROM execution_jobs WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        attempt = connection.execute(
            "SELECT status, termination_proven, observation_evidence_json "
            "FROM execution_attempts WHERE attempt_id = ?",
            (job["current_attempt_id"],),
        ).fetchone()
        resource = connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()
        result_count = connection.execute(
            "SELECT count(*) FROM inference_attempt_results WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()[0]

    assert report["status"] == "attention_required"
    assert report["jobs"][0]["outcome"] == "runtime_failure"
    assert report["jobs"][0]["result"] is None
    assert job["status"] == "running"
    assert attempt["status"] == "running"
    observation = json.loads(attempt["observation_evidence_json"])
    assert observation["process_group_terminated"] is True
    assert attempt["termination_proven"] == 0
    assert resource["state"] == "claimed"
    assert result_count == 0


def test_stale_success_finalization_does_not_return_authoritative_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    queued = service.enqueue("stale-success-finalization", request)
    execute = inference_service_module.execute_invocation

    def cancel_after_supervised_response(prepared, supervisor, *, qualification):
        outcome = execute(prepared, supervisor, qualification=qualification)
        cancellation = service.cancel(str(queued["job_id"]))
        assert cancellation["status"] == "requested"
        return outcome

    monkeypatch.setattr(
        inference_service_module,
        "execute_invocation",
        cancel_after_supervised_response,
    )

    report = service.work(job_id=str(queued["job_id"]))

    assert report["status"] == "attention_required"
    assert report["jobs"][0]["outcome"] == "runtime_failure"
    assert report["jobs"][0]["result"] is None
    assert counter_file.read_text(encoding="utf-8") == "1"
    with service._store._connection() as connection:
        job = connection.execute(
            "SELECT status FROM execution_jobs WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
        attempt_count = connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()[0]
        result_count = connection.execute(
            "SELECT count(*) FROM inference_attempt_results WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()[0]
    assert job["status"] == "canceled"
    assert attempt_count == 1
    assert result_count == 0


def test_inference_and_image_generation_share_exclusive_resource(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "shared-resource"
    root.mkdir()
    started_marker = root / "inference-started"
    inference, request, _ = _service(
        root,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
        delay_seconds=2.0,
        started_marker=started_marker,
    )
    inference_job = inference.enqueue("shared-resource-inference", request)
    generation = GenerationService(inference.database_path, root / "generated-output")
    generation_job = generation.enqueue(
        "shared-resource-image",
        GenerationRequest(
            prompt="A small blue landscape",
            seed=19,
            width=48,
            height=48,
        ),
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        inference_future = executor.submit(
            inference.work,
            job_id=str(inference_job["job_id"]),
        )
        deadline = time.monotonic() + 10.0
        while not started_marker.exists() and time.monotonic() < deadline:
            if inference_future.done():
                break
            time.sleep(0.01)

        assert started_marker.exists()
        busy = generation.work()
        recovery_busy = inference.recover()
        assert busy["status"] == "resource_busy"
        assert busy["processed"] == 0
        assert recovery_busy == {"status": "resource_busy"}
        assert generation.get_provenance(generation_job.job_id)["status"] == "queued"

        assert inference_future.result(timeout=10.0)["status"] == "complete"

    completed = generation.work()
    assert completed["status"] == "complete"
    assert completed["processed"] == 1
    assert generation.get_provenance(generation_job.job_id)["status"] == "succeeded"


def test_reenqueuing_inference_keeps_original_deadline_and_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, counter_file = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    now = inference_service_module._utc_now()
    clock = [now]
    monkeypatch.setattr(inference_service_module, "_utc_now", lambda: clock[0])

    first = service.enqueue("stable-inference-deadline", request, deadline_seconds=60)
    with service._store._connection() as connection:
        first_deadline = connection.execute(
            "SELECT deadline_at FROM inference_requests WHERE job_id = ?",
            (first["job_id"],),
        ).fetchone()["deadline_at"]

    clock[0] += timedelta(seconds=5)
    repeated = service.enqueue("stable-inference-deadline", request, deadline_seconds=60)
    changed_deadline = service.enqueue(
        "stable-inference-deadline", request, deadline_seconds=61
    )

    assert repeated["job_id"] == first["job_id"]
    assert repeated["created"] is False
    assert changed_deadline == {
        "status": "preflight_blocked",
        "reason": "idempotency_conflict",
    }
    with service._store._connection() as connection:
        stored_deadline = connection.execute(
            "SELECT deadline_at FROM inference_requests WHERE job_id = ?",
            (first["job_id"],),
        ).fetchone()["deadline_at"]
    assert stored_deadline == first_deadline
    assert not counter_file.exists()


def test_reenqueuing_inference_reports_persisted_admission_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, request, _ = _service(
        tmp_path,
        monkeypatch,
        InferenceKind.TEXT,
        "A short source.",
        [{"status": "ok", "answer": "short", "evidence_spans": ["short"]}],
    )
    original_admission_for = service._admission_for
    admission_calls = 0

    def block_on_retry(
        kind: InferenceKind,
        privacy: PrivacyComplianceResult,
    ) -> PendingAdmission:
        nonlocal admission_calls
        pending = original_admission_for(kind, privacy)
        admission_calls += 1
        if admission_calls == 2:
            return replace(pending, decision="blocked", reason="capacity_changed")
        return pending

    monkeypatch.setattr(service, "_admission_for", block_on_retry)
    first = service.enqueue("persisted-admission-status", request)
    assert first["status"] == "queued"

    repeated = service.enqueue("persisted-admission-status", request)

    assert repeated["job_id"] == first["job_id"]
    assert repeated["created"] is False
    assert repeated["status"] == "queued"
