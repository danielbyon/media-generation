"""Durable batch coordination remains on the T04 execution boundary."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from media_generation.adapters import DeterministicCpuAdapter
from media_generation.admission import parse_workload_demand
from media_generation.domain import GenerationRequest
from media_generation.errors import InputValidationError
from media_generation.publication import PublicationManager
from media_generation.service import GenerationService
from media_generation.store import (
    SQLiteStore,
    _WRITER_EPOCH,
    _WRITER_EPOCH_FUNCTION,
)
from media_generation.batch_execution import GenerationBatchService
from media_generation.cli import _load_batch_workload_demands, main
from test_cpu_adapter_support import cpu_adapter, heavyweight_adapter
from test_durable_execution import _heavyweight_profile
from test_resource_admission import GIB, workload_demand


def _service(root: Path) -> GenerationService:
    return GenerationService(root / "studio.sqlite3", root / "images")


def _request(slot: str, prompt: str) -> GenerationRequest:
    return GenerationRequest(
        prompt,
        seed=73,
        width=12,
        height=9,
        output_slot=slot,
    )


def _heavy_demand(system_ram_bytes: int = 16 * GIB):
    return parse_workload_demand(
        workload_demand(
            system_ram_bytes=system_ram_bytes,
            accelerator_memory_bytes=32 * GIB,
        )
    )


def _heavy_profile():
    return _heavyweight_profile()


def test_batch_submission_persists_and_reports_each_slot(tmp_path: Path) -> None:
    service = _service(tmp_path)
    batches = GenerationBatchService(service)

    submitted = batches.submit(
        "batch-basic",
        (_request("portrait", "A copper fox"), _request("landscape", "A blue heron")),
    )

    assert submitted["coordinator_state"] == "complete"
    slots = submitted["slots"]
    assert len(slots) == 2
    assert {slot["output_slot"] for slot in slots} == {"portrait", "landscape"}
    assert {slot["execution_status"] for slot in slots} == {"succeeded"}
    assert len({slot["job_id"] for slot in slots}) == 2
    assert len({slot["output_slot_id"] for slot in slots}) == 2
    assert len({slot["artifact_id"] for slot in slots}) == 2

    restarted = GenerationBatchService(_service(tmp_path))
    report = restarted.report(str(submitted["batch_id"]))
    assert report == submitted
    assert all(slot["artifact_integrity"] == "ok" for slot in report["slots"])


def test_batch_cli_runs_and_reports_without_executor_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    request_json = json.dumps(
        [{"prompt": "CLI batch", "seed": 7, "width": 8, "height": 9, "output_slot": "only"}]
    )
    assert main(
        [
            "batch",
            "run",
            "--db",
            str(database),
            "--output-dir",
            str(output),
            "--batch-key",
            "batch-cli",
            "--requests-json",
            request_json,
        ]
    ) == 0
    submitted = json.loads(capsys.readouterr().out)
    assert submitted["coordinator_state"] == "complete"

    assert main(
        [
            "batch",
            "report",
            "--db",
            str(database),
            "--batch-id",
            submitted["batch_id"],
        ]
    ) == 0
    reported = json.loads(capsys.readouterr().out)
    assert reported["slots"][0]["execution_status"] == "succeeded"
    assert reported["slots"][0]["artifact_integrity"] == "ok"


def test_batch_cli_rejects_heavyweight_adapter_without_admission_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "media_generation.cli._engine_adapter",
        lambda options, output: heavyweight_adapter(),
    )
    exit_code = main(
        [
            "batch",
            "run",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--batch-key",
            "batch-cli-heavy",
            "--requests-json",
            '[{"prompt":"Requires capacity evidence","output_slot":"only"}]',
        ]
    )
    error = json.loads(capsys.readouterr().err)
    assert exit_code == 2
    assert "admission profile and demand" in error["error"]["message"]
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_batches").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone() == (0,)


def test_batch_workload_demand_file_is_versioned_and_slot_keyed(tmp_path: Path) -> None:
    demand = _heavy_demand()
    path = tmp_path / "batch-demands.json"
    path.write_text(
        json.dumps(
            {
                "schema": "media-generation.batch-workload-demands",
                "schema_version": 1,
                "demands": {"hero": demand.to_dict()},
            }
        ),
        encoding="utf-8",
    )

    parsed = _load_batch_workload_demands(path)

    assert set(parsed) == {"hero"}
    assert parsed["hero"].to_dict() == demand.to_dict()


def test_never_attempted_queued_job_resumes_through_t04_submit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    original_submit = service.submit

    def lose_before_attempt(*args, **kwargs):
        raise RuntimeError("coordinator stopped before the service call")

    monkeypatch.setattr(service, "submit", lose_before_attempt)
    batches = GenerationBatchService(service)
    first = batches.submit("batch-first-attempt", (_request("only", "First attempt"),))
    slot = first["slots"][0]
    assert slot["execution_status"] == "queued"
    assert slot["attempt_count"] == 0
    assert slot["retry_eligible"] is False

    monkeypatch.setattr(service, "submit", original_submit)
    restarted = GenerationBatchService(_service(tmp_path))
    resumed = restarted.resume(str(first["batch_id"]))

    assert resumed["coordinator_state"] == "complete"
    assert resumed["slots"][0]["execution_status"] == "succeeded"
    assert resumed["slots"][0]["attempt_count"] == 1


def test_retryable_failure_queued_job_uses_t04_retry_then_submit(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()
    calls = 0

    def fail_once(plan, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("verified transient failure")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = fail_once
    profile = _heavy_profile()
    demand = _heavy_demand()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        admission_profile=profile,
    )
    batches = GenerationBatchService(service)
    requests = (_request("retry", "Retry me"),)
    first = batches.submit(
        "batch-retryable-queued",
        requests,
        workload_demands={"retry": demand},
        max_attempts=2,
    )
    first_slot = first["slots"][0]
    assert first["coordinator_state"] == "running"
    assert first["report_state"] == "running"
    assert first_slot["execution_status"] == "queued"
    assert first_slot["retry_eligible"] is True
    assert first_slot["attempt_count"] == 1
    assert first_slot["retry_pending"] is True
    assert first_slot["requires_attention"] is False
    assert first_slot["attempt_history"] == [
        {
            "attempt_id": first_slot["attempt_history"][0]["attempt_id"],
            "attempt_number": 1,
            "status": "failed",
            "failure_class": "retryable",
            "termination_proven": True,
        }
    ]

    repeated = batches.submit(
        "batch-retryable-queued",
        requests,
        workload_demands={"retry": demand},
        max_attempts=2,
    )
    assert repeated["slots"][0]["job_id"] == first_slot["job_id"]
    assert repeated["slots"][0]["attempt_count"] == 1
    assert repeated["slots"][0]["retry_pending"] is True
    assert calls == 1

    resumed_service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=cpu_adapter(),
        admission_profile=profile,
    )
    resumed = GenerationBatchService(resumed_service).resume(
        str(first["batch_id"]), workload_demands={"retry": demand}
    )

    assert resumed["coordinator_state"] == "complete"
    assert resumed["slots"][0]["execution_status"] == "succeeded"
    assert resumed["slots"][0]["attempt_count"] == 2
    history = resumed["slots"][0]["attempt_history"]
    assert [attempt["attempt_number"] for attempt in history] == [1, 2]
    assert [attempt["status"] for attempt in history] == ["failed", "succeeded"]
    assert [attempt["failure_class"] for attempt in history] == ["retryable", None]
    assert all(attempt["termination_proven"] is True for attempt in history)
    assert all(
        set(attempt)
        == {
            "attempt_id",
            "attempt_number",
            "status",
            "failure_class",
            "termination_proven",
        }
        for attempt in history
    )
    assert len({attempt["attempt_id"] for attempt in history}) == 2
    assert calls == 1


def test_failed_retry_eligible_job_uses_t04_retry_operation(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()
    calls = 0

    def fail_once(plan, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("safe retry fixture")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = fail_once
    profile = _heavy_profile()
    demand = _heavy_demand()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        admission_profile=profile,
    )
    first = GenerationBatchService(service).submit(
        "batch-failed-eligible",
        (_request("retry", "Retry failed state"),),
        workload_demands={"retry": demand},
        max_attempts=2,
    )
    job_id = str(first["slots"][0]["job_id"])
    assert first["slots"][0]["retry_eligible"] is True

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE execution_jobs SET status = 'failed' WHERE job_id = ?",
            (job_id,),
        )
        connection.execute(
            "UPDATE generation_jobs SET status = 'failed' WHERE job_id = ?",
            (job_id,),
        )
        # A failed retryable heavyweight job has released its resource claim;
        # T04 retry transitions this admission record back to queued.
        connection.execute(
            """UPDATE execution_admissions
               SET decision = 'released', decision_reason = 'safe_retry_eligible'
               WHERE job_id = ?""",
            (job_id,),
        )

    resumed_service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=cpu_adapter(),
        admission_profile=profile,
    )
    resumed = GenerationBatchService(resumed_service).resume(
        str(first["batch_id"]), workload_demands={"retry": demand}
    )

    assert resumed["coordinator_state"] == "complete"
    assert resumed["slots"][0]["execution_status"] == "succeeded"
    assert resumed["slots"][0]["attempt_count"] == 2
    assert calls == 1


def test_t04_authorized_queued_retry_resumes_after_dispatch_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = cpu_adapter()

    def fail_once(plan, destination):
        from media_generation.errors import RetryableGenerationError

        raise RetryableGenerationError("retry handoff fixture")

    adapter.generate = fail_once
    profile = _heavy_profile()
    demand = _heavy_demand()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=adapter,
        admission_profile=profile,
    )
    first = GenerationBatchService(service).submit(
        "batch-authorized-queued-retry",
        (_request("retry", "Resume authorized retry"),),
        workload_demands={"retry": demand},
        max_attempts=2,
    )
    job_id = str(first["slots"][0]["job_id"])
    assert first["slots"][0]["execution_status"] == "queued"
    assert first["slots"][0]["retry_eligible"] is True

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE execution_jobs SET status = 'failed' WHERE job_id = ?",
            (job_id,),
        )
        connection.execute(
            "UPDATE generation_jobs SET status = 'failed' WHERE job_id = ?",
            (job_id,),
        )
        connection.execute(
            """UPDATE execution_admissions
               SET decision = 'released', decision_reason = 'safe_retry_eligible'
               WHERE job_id = ?""",
            (job_id,),
        )

    # T04 persists retry authorization by changing failed to queued and clearing
    # retry_eligible. A restart between this call and submit must dispatch the
    # same accepted job without authorizing a second retry.
    authorized = service.retry(job_id)
    assert authorized.status == "queued"
    assert service.get_provenance(job_id)["execution"]["retry_eligible"] is False
    assert service.inspect_admission(job_id).admission.decision == "queued"

    restarted_service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=cpu_adapter(),
        admission_profile=profile,
    )
    monkeypatch.setattr(
        restarted_service,
        "retry",
        lambda _job_id: pytest.fail("T04 retry was already durably authorized"),
    )
    resumed = GenerationBatchService(restarted_service).resume(
        str(first["batch_id"]), workload_demands={"retry": demand}
    )

    assert resumed["coordinator_state"] == "complete"
    assert resumed["slots"][0]["execution_status"] == "succeeded"
    assert resumed["slots"][0]["attempt_count"] == 2


def test_failed_retryable_slot_keeps_batch_running_until_retry_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = cpu_adapter()
    calls = 0

    def fail_first(plan, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("leave retry pending")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = fail_first
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )

    def interrupt_retry(_job_id: str):
        raise RuntimeError("retry handoff interrupted")

    monkeypatch.setattr(service, "retry", interrupt_retry)
    first = GenerationBatchService(service).submit(
        "batch-retry-pending",
        (_request("retry", "Retryable slot"), _request("done", "Later slot")),
        max_attempts=2,
    )
    retry_job_id = str(first["slots"][0]["job_id"])
    assert first["slots"][0]["retry_eligible"] is True
    assert first["slots"][1]["execution_status"] == "succeeded"

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE execution_jobs SET status = 'failed' WHERE job_id = ?",
            (retry_job_id,),
        )
        connection.execute(
            "UPDATE generation_jobs SET status = 'failed' WHERE job_id = ?",
            (retry_job_id,),
        )

    restarted_service = _service(tmp_path)
    monkeypatch.setattr(restarted_service, "retry", interrupt_retry)
    report = GenerationBatchService(restarted_service).resume(str(first["batch_id"]))

    assert report["coordinator_state"] == "running"
    assert report["slots"][0]["execution_status"] == "failed"
    assert report["slots"][0]["retry_pending"] is True
    assert report["slots"][0]["attempt_count"] == 1
    assert report["slots"][1]["execution_status"] == "succeeded"


def test_failed_job_without_retry_eligibility_is_observed_without_replay(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()

    def fail_terminal(plan, destination):
        from media_generation.errors import GenerationExecutionError

        raise GenerationExecutionError(plan.job_id, "terminal fixture failure")

    adapter.generate = fail_terminal
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    first = GenerationBatchService(service).submit(
        "batch-failed-terminal",
        (_request("only", "No retry"),),
        max_attempts=2,
    )
    attempts_before = first["slots"][0]["attempt_count"]
    assert first["slots"][0]["execution_status"] == "failed"
    assert first["slots"][0]["retry_eligible"] is False

    resumed = GenerationBatchService(_service(tmp_path)).resume(str(first["batch_id"]))

    assert resumed["slots"][0]["execution_status"] == "failed"
    assert resumed["slots"][0]["attempt_count"] == attempts_before == 1


def test_retryable_failure_at_attempt_budget_is_not_replayed(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()

    def fail_retryably(plan, destination):
        from media_generation.errors import RetryableGenerationError

        raise RetryableGenerationError("attempt budget exhausted")

    adapter.generate = fail_retryably
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    first = GenerationBatchService(service).submit(
        "batch-retry-budget-exhausted",
        (_request("only", "No remaining attempt"),),
        max_attempts=1,
    )
    slot = first["slots"][0]
    assert slot["execution_status"] == "failed"
    assert slot["retry_eligible"] is False
    assert slot["attempt_count"] == slot["max_attempts"] == 1

    resumed = GenerationBatchService(_service(tmp_path)).resume(str(first["batch_id"]))

    assert resumed["slots"][0]["execution_status"] == "failed"
    assert resumed["slots"][0]["attempt_count"] == 1


def test_canceled_service_job_is_observed_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr(service, "submit", lambda *args, **kwargs: None)
    first = GenerationBatchService(service).submit(
        "batch-canceled",
        (_request("only", "Cancel before attempt"),),
    )
    job_id = str(first["slots"][0]["job_id"])
    service.cancel(job_id)
    database = tmp_path / "studio.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE generation_batch_slots SET coordinator_state = 'accepted' WHERE slot_id = ?",
            (first["slots"][0]["slot_id"],),
        )
        connection.execute(
            "UPDATE generation_batches SET coordinator_state = 'running' WHERE batch_id = ?",
            (first["batch_id"],),
        )
    before_report = hashlib.sha256(database.read_bytes()).hexdigest()

    observed = GenerationBatchService(_service(tmp_path)).report(str(first["batch_id"]))

    assert observed["report_state"] == "running"
    assert observed["requires_attention"] is False
    assert observed["slots"][0]["execution_status"] == "canceled"
    assert observed["slots"][0]["requires_attention"] is False
    assert observed["slots"][0]["issue"] is None
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before_report

    report = GenerationBatchService(_service(tmp_path)).resume(str(first["batch_id"]))

    assert report["coordinator_state"] == "failed"
    assert report["report_state"] == "failed"
    assert report["requires_attention"] is False
    assert report["slots"][0]["execution_status"] == "canceled"
    assert report["slots"][0]["attempt_count"] == 0
    assert report["slots"][0]["requires_attention"] is False


def test_canceled_service_job_with_unresolved_resource_still_requires_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    monkeypatch.setattr(service, "submit", lambda *args, **kwargs: None)
    first = GenerationBatchService(service).submit(
        "batch-canceled-resource-owned",
        (_request("only", "Canceled with unresolved resource"),),
    )
    job_id = str(first["slots"][0]["job_id"])
    service.cancel(job_id)

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE generation_batch_slots SET coordinator_state = 'accepted' WHERE slot_id = ?",
            (first["slots"][0]["slot_id"],),
        )
        connection.execute(
            "UPDATE generation_batches SET coordinator_state = 'running' WHERE batch_id = ?",
            (first["batch_id"],),
        )
        connection.execute(
            """UPDATE execution_resource
               SET state = 'claimed', job_id = ?, attempt_id = ?, owner_id = ?,
                   reason = NULL WHERE id = 1""",
            (job_id, "unresolved-attempt", "unresolved-owner"),
        )

    report = GenerationBatchService(_service(tmp_path)).report(str(first["batch_id"]))

    assert report["report_state"] == "attention_required"
    assert report["requires_attention"] is True
    assert report["slots"][0]["execution_status"] == "canceled"
    assert report["slots"][0]["requires_attention"] is True


def test_heavyweight_batch_rejects_missing_admission_evidence(tmp_path: Path) -> None:
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=heavyweight_adapter(),
    )

    with pytest.raises(InputValidationError, match="admission profile and demand"):
        GenerationBatchService(service).submit(
            "batch-heavy-without-evidence", (_request("only", "Needs admission"),)
        )

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_batches").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone() == (0,)


def test_changed_admission_evidence_refuses_resume_without_new_attempt(
    tmp_path: Path,
) -> None:
    profile = _heavy_profile()
    original_demand = _heavy_demand()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=cpu_adapter(),
        admission_profile=profile,
    )
    first = GenerationBatchService(service).submit(
        "batch-admission-drift",
        (_request("only", "Pinned workload"),),
        workload_demands={"only": original_demand},
    )
    slot = first["slots"][0]
    before_attempts = slot["attempt_count"]

    restarted = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=cpu_adapter(),
        admission_profile=profile,
    )
    with pytest.raises(InputValidationError, match="workload demand changed"):
        GenerationBatchService(restarted).resume(
            str(first["batch_id"]),
            workload_demands={"only": _heavy_demand(15 * GIB)},
        )
    assert restarted.get_provenance(str(slot["job_id"]))["attempts"]
    assert len(restarted.get_provenance(str(slot["job_id"]))["attempts"]) == before_attempts


def test_changed_adapter_or_output_identity_refuses_pending_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    original_submit = service.submit
    monkeypatch.setattr(service, "submit", lambda *args, **kwargs: None)
    first = GenerationBatchService(service).submit(
        "batch-execution-identity", (_request("only", "Pinned output"),)
    )
    assert first["slots"][0]["execution_status"] == "queued"

    changed = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "other-images",
        adapter=DeterministicCpuAdapter(),
    )
    with pytest.raises(InputValidationError, match="output destination changed"):
        GenerationBatchService(changed).resume(str(first["batch_id"]))
    monkeypatch.setattr(service, "submit", original_submit)


def test_lost_submission_ack_and_duplicate_batch_submission_reuse_one_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    original_submit = service.submit
    calls = 0

    def submit_then_lose_ack(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_submit(*args, **kwargs)
        raise RuntimeError("simulated acknowledgement loss")

    monkeypatch.setattr(service, "submit", submit_then_lose_ack)
    batches = GenerationBatchService(service)
    requests = (_request("one", "Exactly once"),)
    first = batches.submit("batch-lost-ack", requests)
    repeated = batches.submit("batch-lost-ack", requests)

    assert first["batch_id"] == repeated["batch_id"]
    assert first["slots"][0]["job_id"] == repeated["slots"][0]["job_id"]
    assert first["slots"][0]["attempt_count"] == 1
    assert repeated["slots"][0]["attempt_count"] == 1
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM generation_attempts").fetchone() == (1,)
    assert calls == 1


def test_concurrent_batch_runners_are_fenced_by_the_coordinator_claim(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    original_submit = service.submit
    calls = 0

    def blocked_submit(*args, **kwargs):
        nonlocal calls
        calls += 1
        entered.set()
        if not release.wait(10):
            raise RuntimeError("test synchronization timed out")
        return original_submit(*args, **kwargs)

    service.submit = blocked_submit
    first_runner = GenerationBatchService(service)
    second_runner = GenerationBatchService(_service(tmp_path))
    with ThreadPoolExecutor(max_workers=2) as workers:
        first_future = workers.submit(
            first_runner.submit,
            "batch-concurrent",
            (_request("only", "Single attempt"),),
        )
        assert entered.wait(10), "first runner did not enter T04 submission"
        batch_id = str(first_runner._store.get_generation_batch("batch-concurrent")["batch_id"])
        second_future = workers.submit(second_runner.resume, batch_id)
        second_report = second_future.result(timeout=10)
        release.set()
        first_report = first_future.result(timeout=10)

    assert second_report["coordinator_claim_state"] == "held"
    assert first_report["coordinator_state"] == "complete"
    assert calls == 1
    assert first_report["slots"][0]["attempt_count"] == 1


def test_slow_t04_execution_renews_claim_and_progresses_later_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = cpu_adapter()
    entered = threading.Event()
    release = threading.Event()
    generated_slots: list[str] = []

    def slow_generate(plan, destination):
        generated_slots.append(plan.output_slot)
        if plan.output_slot == "slow":
            entered.set()
            if not release.wait(10):
                raise RuntimeError("test synchronization timed out")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = slow_generate
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    batches = GenerationBatchService(service, claim_lease_seconds=1)
    original_renew = batches._store.renew_generation_batch_claim
    heartbeat_renewals = 0
    renewed_past_original_lease = threading.Event()

    def record_renewal(*args, **kwargs):
        nonlocal heartbeat_renewals
        renewed = original_renew(*args, **kwargs)
        if (
            renewed
            and threading.current_thread().name.startswith(
                "generation-batch-claim-heartbeat-"
            )
        ):
            heartbeat_renewals += 1
            if heartbeat_renewals >= 4:
                renewed_past_original_lease.set()
        return renewed

    monkeypatch.setattr(batches._store, "renew_generation_batch_claim", record_renewal)
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(
            batches.submit,
            "batch-slow-t04",
            (_request("slow", "Slow first slot"), _request("later", "Next slot")),
        )
        try:
            assert entered.wait(10), "T04 did not enter the slow adapter call"
            assert renewed_past_original_lease.wait(10), (
                "batch claim was not renewed while T04 was running"
            )
        finally:
            release.set()
        report = future.result(timeout=10)

    assert report["coordinator_state"] == "complete"
    assert [slot["execution_status"] for slot in report["slots"]] == [
        "succeeded",
        "succeeded",
    ]
    assert generated_slots == ["slow", "later"]
    assert heartbeat_renewals >= 4


def test_claim_takeover_during_slow_t04_execution_stops_later_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = cpu_adapter()
    entered = threading.Event()
    release_execution = threading.Event()
    heartbeat_waiting = threading.Event()
    allow_heartbeat = threading.Event()
    heartbeat_lost_claim = threading.Event()
    generated_slots: list[str] = []

    def slow_generate(plan, destination):
        generated_slots.append(plan.output_slot)
        if plan.output_slot == "slow":
            entered.set()
            if not release_execution.wait(10):
                raise RuntimeError("test synchronization timed out")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = slow_generate
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    first_runner = GenerationBatchService(service, claim_lease_seconds=1)
    takeover_adapter = cpu_adapter()

    def record_takeover_generate(plan, destination):
        generated_slots.append(plan.output_slot)
        return DeterministicCpuAdapter.generate(takeover_adapter, plan, destination)

    takeover_adapter.generate = record_takeover_generate
    takeover_runner = GenerationBatchService(
        GenerationService(
            tmp_path / "studio.sqlite3", tmp_path / "images", adapter=takeover_adapter
        ),
        claim_lease_seconds=1,
    )
    original_renew = first_runner._store.renew_generation_batch_claim
    def gate_heartbeat(*args, **kwargs):
        is_heartbeat = threading.current_thread().name.startswith(
            "generation-batch-claim-heartbeat-"
        )
        if is_heartbeat:
            heartbeat_waiting.set()
            if not allow_heartbeat.wait(10):
                raise RuntimeError("test synchronization timed out")
        renewed = original_renew(*args, **kwargs)
        if is_heartbeat and not renewed:
            heartbeat_lost_claim.set()
        return renewed

    monkeypatch.setattr(
        first_runner._store, "renew_generation_batch_claim", gate_heartbeat
    )
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(
            first_runner.submit,
            "batch-takeover-during-t04",
            (_request("slow", "Slow slot"), _request("later", "Unstarted slot")),
        )
        takeover = None
        takeover_epoch = None
        try:
            assert entered.wait(10), "T04 did not enter the slow adapter call"
            batch_id = str(
                first_runner._store.get_generation_batch("batch-takeover-during-t04")[
                    "batch_id"
                ]
            )
            assert heartbeat_waiting.wait(10), "claim heartbeat did not start"
            now = datetime.now(timezone.utc)
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.create_function(
                    _WRITER_EPOCH_FUNCTION,
                    0,
                    lambda: _WRITER_EPOCH,
                    deterministic=True,
                )
                connection.execute(
                    "UPDATE generation_batches SET claim_expires_at = ? WHERE batch_id = ?",
                    ((now - timedelta(seconds=1)).isoformat(timespec="microseconds"), batch_id),
                )
            takeover = takeover_runner._store.claim_generation_batch(
                batch_id,
                "runner-takeover",
                now.isoformat(timespec="microseconds"),
                (now + timedelta(seconds=5)).isoformat(timespec="microseconds"),
            )
            assert takeover is not None
            takeover_epoch = int(takeover["claim_epoch"])
            allow_heartbeat.set()
            assert heartbeat_lost_claim.wait(10), "old coordinator did not observe takeover"
        finally:
            allow_heartbeat.set()
            release_execution.set()
        first_report = future.result(timeout=10)

    assert generated_slots == ["slow"]
    assert first_report["slots"][0]["execution_status"] == "succeeded"
    assert first_report["slots"][1]["execution_status"] == "not_accepted"
    assert takeover is not None and takeover_epoch is not None
    takeover_runner._store.release_generation_batch_claim(
        batch_id,
        "runner-takeover",
        takeover_epoch,
        datetime.now(timezone.utc).isoformat(timespec="microseconds"),
    )

    resumed = takeover_runner.resume(batch_id)

    assert resumed["coordinator_state"] == "complete"
    assert [slot["execution_status"] for slot in resumed["slots"]] == [
        "succeeded",
        "succeeded",
    ]
    assert generated_slots == ["slow", "later"]


def test_claim_loss_during_retry_attempt_prevents_another_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = cpu_adapter()
    calls = 0
    retry_entered = threading.Event()
    release_retry = threading.Event()

    def fail_first_two(plan, destination):
        nonlocal calls
        calls += 1
        if calls == 1:
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("first recoverable failure")
        if calls == 2:
            retry_entered.set()
            if not release_retry.wait(10):
                raise RuntimeError("test synchronization timed out")
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("second recoverable failure")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = fail_first_two
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    batches = GenerationBatchService(service, claim_lease_seconds=1)
    first = batches.submit(
        "batch-retry-takeover",
        (_request("retry", "Retry across takeover"),),
        max_attempts=3,
    )
    batch_id = str(first["batch_id"])
    assert first["slots"][0]["retry_pending"] is True
    assert first["slots"][0]["attempt_count"] == 1

    retry_calls = 0
    original_retry = service.retry

    def count_retry(job_id: str):
        nonlocal retry_calls
        retry_calls += 1
        return original_retry(job_id)

    monkeypatch.setattr(service, "retry", count_retry)
    takeover_runner = GenerationBatchService(_service(tmp_path), claim_lease_seconds=1)
    heartbeat_waiting = threading.Event()
    allow_heartbeat = threading.Event()
    heartbeat_lost_claim = threading.Event()
    original_renew = batches._store.renew_generation_batch_claim

    def gate_heartbeat(*args, **kwargs):
        is_heartbeat = threading.current_thread().name.startswith(
            "generation-batch-claim-heartbeat-"
        )
        if is_heartbeat:
            heartbeat_waiting.set()
            if not allow_heartbeat.wait(10):
                raise RuntimeError("test synchronization timed out")
        renewed = original_renew(*args, **kwargs)
        if is_heartbeat and not renewed:
            heartbeat_lost_claim.set()
        return renewed

    monkeypatch.setattr(batches._store, "renew_generation_batch_claim", gate_heartbeat)
    takeover = None
    takeover_epoch = None
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(batches.resume, batch_id)
        try:
            assert retry_entered.wait(10), "retry did not enter the slow adapter call"
            assert heartbeat_waiting.wait(10), "claim heartbeat did not start"
            now = datetime.now(timezone.utc)
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.create_function(
                    _WRITER_EPOCH_FUNCTION,
                    0,
                    lambda: _WRITER_EPOCH,
                    deterministic=True,
                )
                connection.execute(
                    "UPDATE generation_batches SET claim_expires_at = ? WHERE batch_id = ?",
                    ((now - timedelta(seconds=1)).isoformat(timespec="microseconds"), batch_id),
                )
            takeover = takeover_runner._store.claim_generation_batch(
                batch_id,
                "runner-retry-takeover",
                now.isoformat(timespec="microseconds"),
                (now + timedelta(seconds=5)).isoformat(timespec="microseconds"),
            )
            assert takeover is not None
            takeover_epoch = int(takeover["claim_epoch"])
            allow_heartbeat.set()
            assert heartbeat_lost_claim.wait(10), "old coordinator did not observe takeover"
        finally:
            allow_heartbeat.set()
            release_retry.set()
        report = future.result(timeout=10)

    assert calls == 2
    assert retry_calls == 1
    assert report["slots"][0]["attempt_count"] == 2
    assert report["slots"][0]["retry_pending"] is True
    assert takeover is not None and takeover_epoch is not None
    takeover_runner._store.release_generation_batch_claim(
        batch_id,
        "runner-retry-takeover",
        takeover_epoch,
        datetime.now(timezone.utc).isoformat(timespec="microseconds"),
    )

    resumed = batches.resume(batch_id)

    assert resumed["coordinator_state"] == "complete"
    assert resumed["slots"][0]["attempt_count"] == 3
    assert calls == 3
    assert retry_calls == 2


def test_expired_batch_claim_does_not_end_an_active_t04_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = threading.Event()
    release = threading.Event()
    adapter = DeterministicCpuAdapter()
    original_generate = adapter.generate

    def blocked_generate(plan, destination):
        entered.set()
        if not release.wait(10):
            raise RuntimeError("test synchronization timed out")
        return original_generate(plan, destination)

    adapter.generate = blocked_generate
    first_service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    first_runner = GenerationBatchService(first_service)
    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(
            first_runner.submit,
            "batch-active-attempt-lease-expiry",
            (_request("only", "Coordinator lease expires"),),
        )
        try:
            assert entered.wait(10), "T04 attempt did not start"
            batch_id = str(
                first_runner._store.get_generation_batch(
                    "batch-active-attempt-lease-expiry"
                )["batch_id"]
            )
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.create_function(
                    _WRITER_EPOCH_FUNCTION,
                    0,
                    lambda: _WRITER_EPOCH,
                    deterministic=True,
                )
                connection.execute(
                    "UPDATE generation_batches SET claim_expires_at = ? WHERE batch_id = ?",
                    ("2000-01-01T00:00:00.000000+00:00", batch_id),
                )

            second_runner = GenerationBatchService(_service(tmp_path))
            observed = second_runner.resume(batch_id)
            assert observed["slots"][0]["execution_status"] == "running"
            assert observed["slots"][0]["attempt_count"] == 1

            job_id = str(
                first_runner._store.get_generation_batch_slots(batch_id)[0][
                    "service_job_id"
                ]
            )
            provenance = first_service.get_provenance(job_id)
            active_attempt = provenance["attempt"]
            attempt_id = str(active_attempt["attempt_id"])
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.create_function(
                    _WRITER_EPOCH_FUNCTION,
                    0,
                    lambda: _WRITER_EPOCH,
                    deterministic=True,
                )
                connection.execute(
                    "UPDATE execution_resource SET attempt_id = ? WHERE job_id = ?",
                    ("different-attempt", job_id),
                )

            mismatched_service = _service(tmp_path)
            monkeypatch.setattr(
                mismatched_service,
                "recover",
                lambda: pytest.fail("recovery must not touch a different attempt"),
            )
            try:
                mismatch = GenerationBatchService(mismatched_service).resume(batch_id)
                assert mismatch["report_state"] == "attention_required"
                assert mismatch["slots"][0]["execution_status"] == "running"
            finally:
                with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                    connection.create_function(
                        _WRITER_EPOCH_FUNCTION,
                        0,
                        lambda: _WRITER_EPOCH,
                        deterministic=True,
                    )
                    connection.execute(
                        "UPDATE execution_resource SET attempt_id = ? WHERE job_id = ?",
                        (attempt_id, job_id),
                    )

            release.set()
            first_report = future.result(timeout=10)
            assert first_report["slots"][0]["execution_status"] == "succeeded"
            assert first_report["slots"][0]["attempt_count"] == 1

            recovered = second_runner.resume(batch_id)
            assert recovered["coordinator_state"] == "complete"
            assert recovered["slots"][0]["attempt_count"] == 1
        finally:
            release.set()
            if not future.done():
                future.result(timeout=10)


def test_expired_batch_claim_only_fences_coordinator_checkpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    batches = GenerationBatchService(_service(tmp_path))
    monkeypatch.setattr(
        batches,
        "_run",
        lambda batch_id, demands, **kwargs: {"batch_id": batch_id},
    )
    batches.submit("batch-stale-claim", (_request("only", "Claim fencing"),))
    batch_id = str(batches._store.get_generation_batch("batch-stale-claim")["batch_id"])
    first = batches._store.claim_generation_batch(
        batch_id,
        "runner-a",
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:05.000000+00:00",
    )
    assert first is not None
    assert batches._store.claim_generation_batch(
        batch_id,
        "runner-b",
        "2026-01-01T00:00:04.000000+00:00",
        "2026-01-01T00:00:09.000000+00:00",
    ) is None
    second = batches._store.claim_generation_batch(
        batch_id,
        "runner-b",
        "2026-01-01T00:00:06.000000+00:00",
        "2026-01-01T00:00:11.000000+00:00",
    )
    assert second is not None
    assert second["claim_epoch"] == first["claim_epoch"] + 1
    slot = batches._store.get_generation_batch_slots(batch_id)[0]
    assert not batches._store.checkpoint_generation_batch_slot(
        batch_id=batch_id,
        slot_id=str(slot["slot_id"]),
        owner="runner-a",
        epoch=int(first["claim_epoch"]),
        now="2026-01-01T00:00:07.000000+00:00",
        coordinator_state="succeeded",
    )
    assert slot["coordinator_state"] == "planned"


def test_success_with_corrupt_artifact_reports_attention_without_mutation(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    batches = GenerationBatchService(service)
    submitted = batches.submit("batch-corrupt-output", (_request("only", "Corrupt me"),))
    artifact_id = str(submitted["slots"][0]["artifact_id"])
    artifact = service.get_artifact(artifact_id)
    Path(artifact.path).write_bytes(b"not an image")
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService(_service(tmp_path)).report(str(submitted["batch_id"]))

    after = hashlib.sha256(database.read_bytes()).hexdigest()
    slot = report["slots"][0]
    assert report["coordinator_state"] == "complete"
    assert report["report_state"] == "attention_required"
    assert report["requires_attention"] is True
    assert slot["execution_status"] == "succeeded"
    assert slot["publication_state"] == "committed"
    assert slot["artifact_integrity"] == "corrupt"
    assert slot["requires_attention"] is True
    assert before == after


def test_success_with_missing_artifact_reports_attention_without_mutation(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    submitted = GenerationBatchService(service).submit(
        "batch-missing-output", (_request("only", "Remove the file"),)
    )
    artifact = service.get_artifact(str(submitted["slots"][0]["artifact_id"]))
    Path(artifact.path).unlink()
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService(_service(tmp_path)).report(str(submitted["batch_id"]))

    slot = report["slots"][0]
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["publication_state"] == "committed"
    assert slot["artifact_integrity"] == "missing"
    assert slot["lineage_state"] == "ok"
    assert slot["requires_attention"] is True
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_success_with_missing_publication_reports_attention_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submitted = GenerationBatchService(_service(tmp_path)).submit(
        "batch-missing-publication", (_request("only", "Check publication"),)
    )
    original_publication_for_artifact = SQLiteStore.publication_for_artifact
    original_publications = SQLiteStore.publications

    def no_publication_for_artifact(
        store: SQLiteStore, artifact_id: str
    ) -> None:
        assert original_publication_for_artifact(store, artifact_id) is not None
        return None

    def no_publications(store: SQLiteStore, root: str | Path) -> list[dict[str, object]]:
        assert original_publications(store, root)
        return []

    monkeypatch.setattr(SQLiteStore, "publication_for_artifact", no_publication_for_artifact)
    monkeypatch.setattr(SQLiteStore, "publications", no_publications)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService.report_database(
        database, str(submitted["batch_id"])
    )

    slot = report["slots"][0]
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["publication_state"] == "missing"
    assert slot["artifact_integrity"] == "ok"
    assert slot["lineage_state"] == "ok"
    assert slot["issue"] == "publication_evidence_inconsistent"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_success_with_inconsistent_lineage_reports_attention_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    submitted = GenerationBatchService(service).submit(
        "batch-inconsistent-lineage", (_request("only", "Check lineage"),)
    )
    reporter = GenerationBatchService(_service(tmp_path))
    original_get_lineage = SQLiteStore.get_lineage

    def inconsistent_lineage(
        store: SQLiteStore, artifact_id: str
    ) -> dict[str, object]:
        lineage = original_get_lineage(store, artifact_id)
        lineage["parents"] = [{"source_id": "unexpected-parent"}]
        return lineage

    monkeypatch.setattr(SQLiteStore, "get_lineage", inconsistent_lineage)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = reporter.report(str(submitted["batch_id"]))

    slot = report["slots"][0]
    assert report["coordinator_state"] == "complete"
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["lineage_state"] == "inconsistent"
    assert slot["artifact_integrity"] == "inconsistent"
    assert slot["issue"] == "artifact_lineage_inconsistent"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_success_with_unavailable_lineage_reports_attention_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submitted = GenerationBatchService(_service(tmp_path)).submit(
        "batch-unavailable-lineage", (_request("only", "Read lineage"),)
    )

    def unavailable_lineage(
        store: SQLiteStore, artifact_id: str
    ) -> dict[str, object]:
        raise RuntimeError("lineage inspection unavailable")

    monkeypatch.setattr(SQLiteStore, "get_lineage", unavailable_lineage)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService.report_database(
        database, str(submitted["batch_id"])
    )

    slot = report["slots"][0]
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["lineage_state"] == "missing"
    assert slot["issue"] == "artifact_lineage_missing"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_report_sanitizes_invalid_attempt_history_and_requires_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submitted = GenerationBatchService(_service(tmp_path)).submit(
        "batch-invalid-attempt-history", (_request("only", "Check attempt history"),)
    )
    reporter = GenerationBatchService(_service(tmp_path))
    original_get_provenance = SQLiteStore.get_provenance

    def invalid_attempt_history(
        store: SQLiteStore, job_id: str
    ) -> dict[str, object]:
        provenance = original_get_provenance(store, job_id)
        attempts = [dict(attempt) for attempt in provenance["attempts"]]
        attempts[0]["attempt_id"] = "invalid attempt id"
        attempts[0]["attempt_number"] = True
        attempts[0]["status"] = "unsafe-status"
        attempts[0]["failure_class"] = "raw backend exception"
        attempts[0]["termination_proven"] = "unknown"
        attempts[0]["raw_error"] = "private backend detail"
        provenance["attempts"] = attempts
        return provenance

    monkeypatch.setattr(SQLiteStore, "get_provenance", invalid_attempt_history)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = reporter.report(str(submitted["batch_id"]))

    slot = report["slots"][0]
    attempt = slot["attempt_history"][0]
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["issue"] == "service_attempt_history_invalid"
    assert attempt["attempt_id"] is None
    assert attempt["attempt_number"] is None
    assert attempt["status"] == "unknown"
    assert attempt["failure_class"] is None
    assert attempt["termination_proven"] is None
    assert set(attempt) == {
        "attempt_id",
        "attempt_number",
        "status",
        "failure_class",
        "termination_proven",
    }
    assert "raw_error" not in attempt
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_report_handles_malformed_execution_identity_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submitted = GenerationBatchService(_service(tmp_path)).submit(
        "batch-malformed-execution-identity",
        (_request("only", "Check execution identity"),),
    )
    original_get_batch = SQLiteStore.get_generation_batch

    def malformed_execution_identity(
        store: SQLiteStore, batch_id: str
    ) -> dict[str, object]:
        batch = original_get_batch(store, batch_id)
        batch["execution_identity_json"] = "{malformed"
        return batch

    monkeypatch.setattr(SQLiteStore, "get_generation_batch", malformed_execution_identity)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService.report_database(
        database, str(submitted["batch_id"])
    )

    slot = report["slots"][0]
    assert report["manifest_integrity"] == "inconsistent"
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["issue"] == "batch_execution_identity_invalid"
    assert slot["publication_state"] == "committed"
    assert slot["artifact_integrity"] == "unknown"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_report_skips_integrity_inspection_for_unverified_execution_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    submitted = GenerationBatchService(_service(tmp_path)).submit(
        "batch-mismatched-execution-identity",
        (_request("only", "Check identity binding"),),
    )
    original_get_batch = SQLiteStore.get_generation_batch

    def mismatched_execution_identity(
        store: SQLiteStore, batch_id: str
    ) -> dict[str, object]:
        batch = original_get_batch(store, batch_id)
        identity = json.loads(str(batch["execution_identity_json"]))
        identity["output_directory"] = str(tmp_path / "unverified-output")
        batch["execution_identity_json"] = json.dumps(identity, sort_keys=True)
        return batch

    monkeypatch.setattr(SQLiteStore, "get_generation_batch", mismatched_execution_identity)
    inspected: list[str] = []

    def record_inspection(
        manager: PublicationManager, artifact_id: str
    ) -> dict[str, object]:
        inspected.append(artifact_id)
        return {"artifact_id": artifact_id, "status": "ok"}

    monkeypatch.setattr(PublicationManager, "inspect_integrity", record_inspection)
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    report = GenerationBatchService.report_database(
        database, str(submitted["batch_id"])
    )

    slot = report["slots"][0]
    assert report["manifest_integrity"] == "inconsistent"
    assert report["report_state"] == "attention_required"
    assert slot["execution_status"] == "succeeded"
    assert slot["issue"] == "batch_execution_identity_invalid"
    assert slot["publication_state"] == "committed"
    assert slot["artifact_integrity"] == "unknown"
    assert inspected == []
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_batch_slot_identity_is_immutable_after_submission(tmp_path: Path) -> None:
    service = _service(tmp_path)
    submitted = GenerationBatchService(service).submit(
        "batch-immutable-slot", (_request("only", "Immutable request"),)
    )
    database = tmp_path / "studio.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        with pytest.raises(sqlite3.IntegrityError, match="batch slot identity is immutable"):
            connection.execute(
                "UPDATE generation_batch_slots SET request_json = '{}' WHERE slot_id = ?",
                (submitted["slots"][0]["slot_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="batch identity is immutable"):
            connection.execute(
                "UPDATE generation_batches SET execution_identity_json = '{}' WHERE batch_id = ?",
                (submitted["batch_id"],),
            )


def test_batch_success_preserves_authoritative_reference_lineage(tmp_path: Path) -> None:
    service = _service(tmp_path)
    source = service.submit(
        "lineage-source",
        GenerationRequest("Source image", seed=4, width=12, height=9, output_slot="source"),
    )
    assert source.artifact_id is not None
    request = GenerationRequest(
        "Derived image",
        seed=5,
        width=12,
        height=9,
        reference_ids=(source.artifact_id,),
        output_slot="derived",
    )

    report = GenerationBatchService(service).submit("batch-lineage", (request,))
    slot = report["slots"][0]
    lineage = service.get_lineage(str(slot["artifact_id"]))

    assert slot["execution_status"] == "succeeded"
    assert slot["lineage_state"] == "ok"
    assert [edge["source_id"] for edge in lineage["parents"]] == [source.artifact_id]


def test_read_only_report_detects_missing_artifact_without_recovery_or_writes(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    batches = GenerationBatchService(service)
    submitted = batches.submit("batch-missing-output", (_request("only", "Remove me"),))
    artifact = service.get_artifact(str(submitted["slots"][0]["artifact_id"]))
    Path(artifact.path).unlink()
    database = tmp_path / "studio.sqlite3"
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    with sqlite3.connect(database) as connection:
        observations_before = connection.execute(
            "SELECT artifact_id, status, checked_at, detail FROM artifact_integrity"
        ).fetchall()

    report = batches.report(str(submitted["batch_id"]))

    with sqlite3.connect(database) as connection:
        observations_after = connection.execute(
            "SELECT artifact_id, status, checked_at, detail FROM artifact_integrity"
        ).fetchall()
    assert report["slots"][0]["execution_status"] == "succeeded"
    assert report["slots"][0]["artifact_integrity"] == "missing"
    assert report["report_state"] == "attention_required"
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert observations_after == observations_before


def test_partial_success_is_reported_without_rewriting_successful_history(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()
    def fail_second(plan, destination):
        if plan.output_slot == "bad":
            from media_generation.errors import GenerationExecutionError

            raise GenerationExecutionError(plan.job_id, "terminal fixture failure")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = fail_second
    service = GenerationService(
        tmp_path / "studio.sqlite3", tmp_path / "images", adapter=adapter
    )
    report = GenerationBatchService(service).submit(
        "batch-partial-success",
        (_request("good", "One succeeds"), _request("bad", "One fails")),
    )

    assert report["coordinator_state"] == "partial"
    assert [slot["execution_status"] for slot in report["slots"]] == [
        "succeeded",
        "failed",
    ]
    successful_id = str(report["slots"][0]["job_id"])
    assert len(service.get_provenance(successful_id)["attempts"]) == 1


def test_partial_success_restart_retries_only_failed_slot_and_preserves_lineage(
    tmp_path: Path,
) -> None:
    adapter = cpu_adapter()
    failed_once = False

    def retry_one_slot(plan, destination):
        nonlocal failed_once
        if plan.output_slot == "retry" and not failed_once:
            failed_once = True
            from media_generation.errors import RetryableGenerationError

            raise RetryableGenerationError("one recoverable failure")
        return DeterministicCpuAdapter.generate(adapter, plan, destination)

    adapter.generate = retry_one_slot
    database = tmp_path / "studio.sqlite3"
    output = tmp_path / "images"
    service = GenerationService(database, output, adapter=adapter)
    batches = GenerationBatchService(service)
    first = batches.submit(
        "batch-partial-restart",
        (_request("success", "Keep this output"), _request("retry", "Retry this output")),
        max_attempts=2,
    )

    assert first["coordinator_state"] == "running"
    assert first["slots"][0]["execution_status"] == "succeeded"
    assert first["slots"][1]["retry_pending"] is True
    original_success = first["slots"][0]
    successful_job_id = str(original_success["job_id"])
    successful_artifact_id = str(original_success["artifact_id"])
    original_provenance = service.get_provenance(successful_job_id)
    original_attempt_ids = tuple(
        attempt["attempt_id"] for attempt in original_provenance["attempts"]
    )
    original_store = SQLiteStore(database, read_only=True)
    original_publication = original_store.publication_for_artifact(
        successful_artifact_id
    )
    original_lineage = original_store.get_lineage(successful_artifact_id)

    restarted_service = GenerationService(database, output, adapter=cpu_adapter())
    resumed = GenerationBatchService(restarted_service).resume(str(first["batch_id"]))

    assert resumed["coordinator_state"] == "complete"
    assert [slot["execution_status"] for slot in resumed["slots"]] == [
        "succeeded",
        "succeeded",
    ]
    after_success = resumed["slots"][0]
    after_provenance = restarted_service.get_provenance(successful_job_id)
    after_store = SQLiteStore(database, read_only=True)
    assert after_success["job_id"] == successful_job_id
    assert after_success["artifact_id"] == successful_artifact_id
    assert tuple(
        attempt["attempt_id"] for attempt in after_provenance["attempts"]
    ) == original_attempt_ids
    assert after_store.publication_for_artifact(successful_artifact_id) == original_publication
    assert after_store.get_lineage(successful_artifact_id) == original_lineage
    assert resumed["slots"][1]["attempt_count"] == 2
    assert len(resumed["slots"][1]["attempt_history"]) == 2


@pytest.mark.parametrize("checkpoint", ("before_commit", "after_commit"))
def test_publication_faults_preserve_t04_recovery_authority(
    tmp_path: Path, checkpoint: str
) -> None:
    def fail_at(name: str) -> None:
        if name == checkpoint:
            raise RuntimeError("injected batch publication checkpoint fault")

    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        publication_checkpoint=fail_at,
    )
    first = GenerationBatchService(service).submit(
        f"batch-publication-{checkpoint}",
        (_request("only", "Publication fault"),),
    )
    if checkpoint == "before_commit":
        assert first["slots"][0]["execution_status"] == "running"
        assert first["slots"][0]["publication_state"] == "ready"
    else:
        assert first["slots"][0]["execution_status"] == "succeeded"
        assert first["slots"][0]["publication_state"] == "committed"

    recovered_service = _service(tmp_path)
    recovered = GenerationBatchService(recovered_service).resume(str(first["batch_id"]))
    assert recovered["slots"][0]["execution_status"] == "succeeded"
    assert recovered["slots"][0]["publication_state"] == "committed"
    assert recovered["slots"][0]["attempt_count"] == 1
