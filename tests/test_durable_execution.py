"""Black-box contracts for durable local admission, execution, and cancellation."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import threading
from typing import BinaryIO

import pytest

from media_generation.adapters import DeterministicCpuAdapter, PROCESS_CONTAINED_CONTRACT
from media_generation.domain import GenerationPlan, GenerationRequest
from media_generation.errors import (
    GenerationError,
    IdempotencyConflictError,
    ResourceBusyError,
    RetryableGenerationError,
)
from media_generation.service import GenerationService


PREPUBLICATION_CHECKPOINTS = (
    "intent_committed",
    "stage_created",
    "before_stage_write",
    "stage_written",
    "before_validation",
    "validated",
    "before_file_sync",
    "file_synced",
    "ready_committed",
    "before_publish",
    "file_published",
    "before_directory_sync",
    "directory_synced",
    "before_commit",
)

POSTCOMMIT_CHECKPOINTS = (
    "after_commit",
    "cleanup_captured",
    "before_cleanup_unlink",
    "cleanup_unlinked",
    "cleanup_complete",
    "before_reply",
)

ALL_PUBLICATION_CHECKPOINTS = PREPUBLICATION_CHECKPOINTS + POSTCOMMIT_CHECKPOINTS


def service_at(root: Path, **kwargs) -> GenerationService:
    """Open an independent service instance in the same local resource domain."""
    return GenerationService(root / "studio.sqlite3", root / "images", **kwargs)


def request(prompt: str = "A copper fox") -> GenerationRequest:
    return GenerationRequest(prompt, seed=73, width=12, height=9)


def cli(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Exercise the installed module in an independently started process."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            *arguments,
            "--db",
            str(root / "studio.sqlite3"),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


def test_enqueue_survives_restart_without_attempt_or_output(tmp_path: Path) -> None:
    queued = service_at(tmp_path).enqueue("first", request())
    assert queued.status == "queued" and queued.artifact_id is None

    restarted = service_at(tmp_path)
    snapshot = restarted.get_provenance(queued.job_id)
    assert snapshot["attempt"] is None
    assert snapshot["attempts"] == []
    assert snapshot["execution"]["max_attempts"] == 1
    assert not (tmp_path / "images").exists()

    result = restarted.work()
    assert result["status"] == "complete"
    assert restarted.get_job(queued.job_id).status == "succeeded"
    assert len(restarted.get_provenance(queued.job_id)["attempts"]) == 1


def test_parallel_admission_reuses_exactly_one_job_and_slot(tmp_path: Path) -> None:
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(
            pool.map(
                lambda _: service_at(tmp_path).enqueue("shared", request()),
                range(12),
            )
        )

    assert len({result.job_id for result in results}) == 1
    assert len({result.output_slot_id for result in results}) == 1
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_requests").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM generation_attempts").fetchone()[0] == 0


def test_omitted_budget_reuses_queued_then_succeeded_admission(tmp_path: Path) -> None:
    """Synchronous compatibility reuses a persisted policy without changing it."""
    service = service_at(tmp_path)
    queued = service.enqueue("budget-reuse", request(), max_attempts=2)

    submitted = service.submit("budget-reuse", request())
    assert submitted.job_id == queued.job_id
    assert submitted.output_slot_id == queued.output_slot_id
    assert submitted.status == "succeeded"
    assert submitted.artifact_id is not None
    assert service.get_job(queued.job_id).max_attempts == 2

    before_reuse = service.get_provenance(queued.job_id)
    reused = service.submit("budget-reuse", request())
    after_reuse = service.get_provenance(queued.job_id)
    assert reused.job_id == queued.job_id
    assert reused.output_slot_id == queued.output_slot_id
    assert reused.artifact_id == submitted.artifact_id
    assert service.get_job(queued.job_id).max_attempts == 2
    assert after_reuse["attempts"] == before_reuse["attempts"]


def test_omitted_budget_defaults_once_and_reuses_under_concurrency(tmp_path: Path) -> None:
    """An omitted policy is fixed at admission and never overwritten."""
    first = service_at(tmp_path).enqueue("default-policy", request())
    second = service_at(tmp_path).enqueue("default-policy", request())
    assert second.job_id == first.job_id
    assert second.output_slot_id == first.output_slot_id
    assert service_at(tmp_path).get_job(first.job_id).max_attempts == 1

    winner = service_at(tmp_path).enqueue("explicit-policy", request(), max_attempts=2)
    with ThreadPoolExecutor(max_workers=6) as pool:
        reused = list(
            pool.map(
                lambda _: service_at(tmp_path).enqueue("explicit-policy", request()),
                range(12),
            )
        )
    assert {item.job_id for item in reused} == {winner.job_id}
    assert {item.output_slot_id for item in reused} == {winner.output_slot_id}
    assert service_at(tmp_path).get_job(winner.job_id).max_attempts == 2


    with pytest.raises(IdempotencyConflictError, match="attempt budget"):
        service_at(tmp_path).enqueue("explicit-policy", request(), max_attempts=3)
    assert service_at(tmp_path).get_job(winner.job_id).max_attempts == 2


def test_cli_enqueue_preserves_omitted_budget_and_rejects_explicit_conflict(
    tmp_path: Path,
) -> None:
    """CLI reuse distinguishes an omitted policy from an explicit budget."""
    output = tmp_path / "images"
    payload = json.dumps(request().to_dict())
    first = cli(
        tmp_path,
        "enqueue",
        "--output-dir",
        str(output),
        "--idempotency-key",
        "cli-budget",
        "--max-attempts",
        "2",
        "--request-json",
        payload,
    )
    assert first.returncode == 0, first.stderr
    admitted = json.loads(first.stdout)

    reused = cli(
        tmp_path,
        "enqueue",
        "--output-dir",
        str(output),
        "--idempotency-key",
        "cli-budget",
        "--request-json",
        payload,
    )
    assert reused.returncode == 0, reused.stderr
    reused_result = json.loads(reused.stdout)
    assert reused_result["job_id"] == admitted["job_id"]
    assert reused_result["output_slot_id"] == admitted["output_slot_id"]

    submitted = cli(
        tmp_path,
        "submit",
        "--output-dir",
        str(output),
        "--idempotency-key",
        "cli-budget",
        "--request-json",
        payload,
    )
    assert submitted.returncode == 0, submitted.stderr
    submitted_result = json.loads(submitted.stdout)
    assert submitted_result["job_id"] == admitted["job_id"]
    assert submitted_result["output_slot_id"] == admitted["output_slot_id"]
    assert submitted_result["status"] == "succeeded"

    inspected = cli(tmp_path, "provenance", "--job-id", admitted["job_id"])
    assert inspected.returncode == 0, inspected.stderr
    snapshot = json.loads(inspected.stdout)
    assert snapshot["artifact"]["artifact_id"] == submitted_result["artifact_id"]
    assert snapshot["execution"]["max_attempts"] == 2
    assert len(snapshot["attempts"]) == 1

    default = cli(
        tmp_path,
        "enqueue",
        "--output-dir",
        str(output),
        "--idempotency-key",
        "cli-default-budget",
        "--request-json",
        payload,
    )
    assert default.returncode == 0, default.stderr
    default_job_id = json.loads(default.stdout)["job_id"]
    inspected_default = cli(tmp_path, "provenance", "--job-id", default_job_id)
    assert inspected_default.returncode == 0, inspected_default.stderr
    default_snapshot = json.loads(inspected_default.stdout)
    assert default_snapshot["status"] == "queued"
    assert default_snapshot["execution"]["max_attempts"] == 1
    assert default_snapshot["attempts"] == []

    conflict = cli(
        tmp_path,
        "enqueue",
        "--output-dir",
        str(output),
        "--idempotency-key",
        "cli-budget",
        "--max-attempts",
        "3",
        "--request-json",
        payload,
    )
    assert conflict.returncode == 0, conflict.stderr
    assert json.loads(conflict.stdout)["artifact_id"] == submitted_result["artifact_id"]
    inspected_final = cli(tmp_path, "provenance", "--job-id", admitted["job_id"])
    assert inspected_final.returncode == 0, inspected_final.stderr
    assert json.loads(inspected_final.stdout) == snapshot


@pytest.mark.parametrize(
    "change",
    ("intent", "configuration", "destination", "budget", "output_slot"),
)
def test_changed_resolved_work_conflicts_even_after_restart(tmp_path: Path, change: str) -> None:
    service_at(tmp_path).enqueue("immutable", request(), max_attempts=2)
    adapter = DeterministicCpuAdapter()
    if change == "configuration":
        class ChangedAdapter(DeterministicCpuAdapter):
            @property
            def configuration(self):
                return {**super().configuration, "revision": 99}

        adapter = ChangedAdapter()

    output = tmp_path / ("elsewhere" if change == "destination" else "images")
    service = GenerationService(tmp_path / "studio.sqlite3", output, adapter)
    payload = GenerationRequest("Changed intent") if change == "intent" else request()
    if change == "output_slot":
        payload = GenerationRequest(
            payload.prompt,
            seed=payload.seed,
            width=12,
            height=9,
            output_slot="secondary",
        )

    with pytest.raises(IdempotencyConflictError):
        service.enqueue(
            "immutable",
            payload,
            max_attempts=3 if change == "budget" else 2,
        )


@pytest.mark.parametrize("budget", (0, -1, True, 1.5, "2"))
def test_invalid_attempt_budget_is_rejected_before_admission(tmp_path: Path, budget) -> None:
    with pytest.raises(GenerationError):
        service_at(tmp_path).enqueue("invalid-budget", request(), max_attempts=budget)

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == 0


def test_queued_cancellation_is_idempotent_and_creates_no_attempt(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    queued = service.enqueue("cancel", request(), max_attempts=3)

    assert service.cancel(queued.job_id)["outcome"] == "acknowledged"
    assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "acknowledged"
    assert service.work()["status"] == "idle"
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled" and snapshot["attempts"] == []
    with pytest.raises(GenerationError):
        service.retry(queued.job_id)


def test_active_cancellation_fences_publication_until_adapter_stops(tmp_path: Path) -> None:
    entered, resume = threading.Event(), threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            entered.set()
            assert resume.wait(10)
            return super().generate(plan, stream)

    service = service_at(tmp_path, adapter=PausedAdapter())
    queued = service.enqueue("paused", request(), max_attempts=2)
    with ThreadPoolExecutor() as pool:
        running = pool.submit(service.work)
        try:
            assert entered.wait(5)
            other = service_at(tmp_path)
            assert other.cancel(queued.job_id)["outcome"] == "accepted"
            assert other.work()["status"] == "resource_busy"
            assert other.recover()["status"] == "resource_busy"
            assert other.get_job(queued.job_id).artifact_id is None
        finally:
            resume.set()
        running.result(timeout=10)

    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["attempts"][0]["termination_proven"] is True
    assert snapshot["artifact"] is None


def test_synchronous_contention_is_explicit_and_reuses_admitted_job(tmp_path: Path) -> None:
    entered, resume = threading.Event(), threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            entered.set()
            assert resume.wait(10)
            return super().generate(plan, stream)

    worker = service_at(tmp_path, adapter=PausedAdapter())
    worker.enqueue("occupy", request())
    with ThreadPoolExecutor() as pool:
        running = pool.submit(worker.work)
        try:
            assert entered.wait(5)
            synchronous = service_at(tmp_path)
            with pytest.raises(ResourceBusyError) as failure:
                synchronous.submit("contended", request())
            job_id = failure.value.job_id
            assert synchronous.get_job(job_id).execution_status == "queued"
        finally:
            resume.set()
        running.result(timeout=10)

    result = service_at(tmp_path).submit("contended", request())
    assert result.job_id == job_id and result.status == "succeeded"


def test_synchronous_inspection_and_postcommit_cancellation_remain_compatible(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    first = service.submit("synchronous", request())
    assert first.status == "succeeded"
    snapshot = service.get_provenance(first.job_id)
    assert snapshot["attempts"][0]["attempt_id"] == snapshot["attempt"]["attempt_id"]
    assert service.cancel(first.job_id)["outcome"] == "too_late"


def test_independent_cli_processes_enqueue_execute_and_inspect(tmp_path: Path) -> None:
    admitted = cli(
        tmp_path,
        "enqueue",
        "--output-dir",
        str(tmp_path / "images"),
        "--idempotency-key",
        "cli",
        "--request-json",
        json.dumps(request().to_dict()),
    )
    assert admitted.returncode == 0, admitted.stderr
    job_id = json.loads(admitted.stdout)["job_id"]

    executed = cli(
        tmp_path,
        "worker",
        "--output-dir",
        str(tmp_path / "images"),
    )
    assert executed.returncode == 0, executed.stderr
    assert json.loads(executed.stdout)["processed"] == 1

    inspected = cli(tmp_path, "provenance", "--job-id", job_id)
    assert inspected.returncode == 0, inspected.stderr
    snapshot = json.loads(inspected.stdout)
    assert snapshot["status"] == "succeeded"
    assert snapshot["attempt"]["attempt_number"] == 1
    assert snapshot["artifact"]["job_id"] == job_id


def test_retry_cli_requeues_same_job_then_worker_creates_next_attempt(tmp_path: Path) -> None:
    """The public retry operation is idempotent while a bounded retry is queued."""

    class RetryOnceAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def __init__(self) -> None:
            self.calls = 0

        def generate(self, plan, stream):
            self.calls += 1
            if self.calls == 1:
                raise RetryableGenerationError("known transient adapter failure")
            return super().generate(plan, stream)

    output = tmp_path / "images"
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=RetryOnceAdapter(),
    )
    queued = service.enqueue("retry-once", request(), max_attempts=2)
    assert service.work()["status"] == "complete"
    retry_state = service.get_provenance(queued.job_id)
    assert retry_state["status"] == "queued"
    assert retry_state["execution"]["retry_eligible"] == 1
    assert len(retry_state["attempts"]) == 1

    for _ in range(2):
        retried = cli(tmp_path, "retry", "--job-id", queued.job_id)
        assert retried.returncode == 0, retried.stderr
        response = json.loads(retried.stdout)
        assert response["job_id"] == queued.job_id
        assert response["output_slot_id"] == queued.output_slot_id
        assert response["status"] == "queued"
        assert len(service.get_provenance(queued.job_id)["attempts"]) == 1
        assert service.get_job(queued.job_id).max_attempts == 2

    executed = cli(
        tmp_path,
        "worker",
        "--output-dir",
        str(output),
        "--limit",
        "1",
    )
    assert executed.returncode == 0, executed.stderr
    assert json.loads(executed.stdout)["processed"] == 1
    final = service.get_provenance(queued.job_id)
    assert final["status"] == "succeeded"
    assert final["artifact"] is not None
    assert [attempt["attempt_number"] for attempt in final["attempts"]] == [1, 2]
    assert service.get_job(queued.job_id).max_attempts == 2


@pytest.mark.parametrize("checkpoint", PREPUBLICATION_CHECKPOINTS)
def test_cancel_at_publication_checkpoint_prevents_logical_artifact(
    tmp_path: Path, checkpoint: str
) -> None:
    canceled = []

    def cancel_at(name):
        if name == checkpoint and not canceled:
            canceled.append(service_at(tmp_path).cancel(job.job_id))

    service = service_at(tmp_path, publication_checkpoint=cancel_at)
    job = service.enqueue("checkpoint", request(), max_attempts=2)
    service.work()

    assert canceled[0]["outcome"] == "accepted"
    restarted = service_at(tmp_path)
    restarted.recover()
    restarted.recover()
    assert restarted.get_job(job.job_id).execution_status == "canceled"
    assert restarted.get_job(job.job_id).artifact_id is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone()[0] == 0


@pytest.mark.parametrize("checkpoint", POSTCOMMIT_CHECKPOINTS)
def test_cancel_after_publication_commit_is_too_late(tmp_path: Path, checkpoint: str) -> None:
    outcomes = []

    def cancel_at(name):
        if name == checkpoint:
            outcomes.append(service_at(tmp_path).cancel(job.job_id)["outcome"])

    service = service_at(tmp_path, publication_checkpoint=cancel_at)
    job = service.enqueue("committed", request())
    service.work()

    assert outcomes == ["too_late"]
    final = service_at(tmp_path)
    assert final.get_job(job.job_id).status == "succeeded"
    snapshot = final.get_provenance(job.job_id)
    assert snapshot["artifact"] is not None
    assert Path(snapshot["artifact"]["path"]).read_bytes()


def test_expired_lease_does_not_reclaim_a_live_process(tmp_path: Path) -> None:
    entered, resume = threading.Event(), threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            entered.set()
            assert resume.wait(10)
            return super().generate(plan, stream)

    service = service_at(tmp_path, adapter=PausedAdapter())
    job = service.enqueue("lease", request(), max_attempts=3)
    with ThreadPoolExecutor() as pool:
        running = pool.submit(service.work)
        try:
            assert entered.wait(5)
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.execute(
                    "UPDATE execution_attempts SET lease_expires_at = '2000-01-01T00:00:00+00:00'"
                )
            restarted = service_at(tmp_path)
            assert restarted.recover()["status"] == "resource_busy"
            assert restarted.work()["status"] == "resource_busy"
            assert len(restarted.get_provenance(job.job_id)["attempts"]) == 1
        finally:
            resume.set()
        running.result(timeout=10)
    assert len(service_at(tmp_path).get_provenance(job.job_id)["attempts"]) == 1


@pytest.mark.parametrize(
    "checkpoint",
    (
        "ready_committed",
        "before_publish",
        "file_published",
        "before_directory_sync",
        "directory_synced",
        "before_commit",
    ),
)
def test_stale_epoch_cannot_finalize_or_reconcile(tmp_path: Path, checkpoint: str) -> None:
    revoked = []

    def revoke_at(name):
        if name == checkpoint and not revoked:
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.execute(
                    "UPDATE execution_jobs SET fence_epoch = fence_epoch + 1 WHERE job_id = ?",
                    (job.job_id,),
                )
            revoked.append(True)

    service = service_at(tmp_path, publication_checkpoint=revoke_at)
    job = service.enqueue("stale", request(), max_attempts=3)
    service.work()

    assert revoked
    restarted = service_at(tmp_path)
    restarted.recover()
    restarted.recover()
    assert restarted.get_job(job.job_id).artifact_id is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0


def test_worker_only_claims_matching_adapter_and_destination(tmp_path: Path) -> None:
    class ChangedAdapter(DeterministicCpuAdapter):
        @property
        def configuration(self):
            return {**super().configuration, "worker_variant": 2}

    default = service_at(tmp_path)
    job = default.enqueue("matching-context", request())
    assert service_at(tmp_path, adapter=ChangedAdapter()).work()["status"] == "idle"
    other_root = tmp_path / "other-images"
    assert GenerationService(
        tmp_path / "studio.sqlite3", other_root, DeterministicCpuAdapter()
    ).work()["status"] == "idle"
    assert default.get_job(job.job_id).execution_status == "queued"
    assert default.work()["status"] == "complete"


def test_parallel_cli_workers_each_report_progress_or_specific_resource_busy(
    tmp_path: Path,
) -> None:
    service = service_at(tmp_path)
    jobs = [service.enqueue(f"parallel-{index}", request()) for index in range(5)]
    args = [
        sys.executable,
        "-m",
        "media_generation",
        "worker",
        "--db",
        str(tmp_path / "studio.sqlite3"),
        "--output-dir",
        str(tmp_path / "images"),
        "--limit",
        "5",
    ]
    processes = [
        subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(3)
    ]
    progress = 0
    for process in processes:
        output, error = process.communicate(timeout=20)
        if process.returncode == 0:
            progress += int(json.loads(output)["processed"])
        else:
            assert process.returncode == 1, (output, error)
            assert json.loads(error)["error"]["code"] == "resource_busy"
    assert progress > 0

    service.work(limit=5)
    for job in jobs:
        snapshot = service.get_provenance(job.job_id)
        assert snapshot["status"] == "succeeded"
        assert len(snapshot["attempts"]) == 1


def test_process_containment_and_attempt_authority_are_persisted_before_dispatch(
    tmp_path: Path,
) -> None:
    observed = []

    class ObservingAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.row_factory = sqlite3.Row
                observed.append(
                    dict(
                        connection.execute(
                            "SELECT * FROM execution_attempts WHERE attempt_id = ?",
                            (plan.attempt_id,),
                        ).fetchone()
                    )
                )
            return super().generate(plan, stream)

    result = service_at(tmp_path, adapter=ObservingAdapter()).submit("contained", request())
    assert result.status == "succeeded"
    assert len(observed) == 1
    attempt = observed[0]
    assert attempt["process_contained"] == 1
    assert attempt["owner_id"]
    assert attempt["claim_epoch"] >= 1
    assert attempt["heartbeat_at"] and attempt["lease_expires_at"]


def test_canceled_referenced_child_preserves_parent_bytes_and_lineage(tmp_path: Path) -> None:
    service = service_at(tmp_path)
    parent = service.submit("parent", request("A parent image"))
    parent_artifact = service.get_artifact(parent.artifact_id)
    parent_bytes = Path(parent_artifact.path).read_bytes()
    parent_lineage = service.get_lineage(parent_artifact.artifact_id)

    canceled = []

    def cancel_at(name):
        if name == "before_commit" and not canceled:
            canceled.append(service_at(tmp_path).cancel(child.job_id))

    child_service = service_at(tmp_path, publication_checkpoint=cancel_at)
    child_request = GenerationRequest(
        "A child image",
        seed=91,
        width=12,
        height=9,
        reference_ids=(parent_artifact.artifact_id,),
    )
    child = child_service.enqueue("child", child_request)
    child_service.work()
    assert canceled[0]["outcome"] == "accepted"
    service_at(tmp_path).recover()

    current = service_at(tmp_path)
    assert current.get_job(child.job_id).artifact_id is None
    assert current.get_artifact(parent_artifact.artifact_id).to_dict() == parent_artifact.to_dict()
    assert Path(parent_artifact.path).read_bytes() == parent_bytes
    assert current.get_lineage(parent_artifact.artifact_id) == parent_lineage
    assert current.get_lineage(parent_artifact.artifact_id)["children"] == []
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone()[0] == 0


def test_recover_cli_reports_resource_contention_as_failure(tmp_path: Path) -> None:
    """A lock winner must make recovery visibly incomplete, not successful."""
    service = service_at(tmp_path)
    with service._resource_lock() as locked:
        assert locked
        result = cli(
            tmp_path,
            "recover",
            "--output-dir",
            str(tmp_path / "images"),
        )

    assert result.returncode == 1
    error = json.loads(result.stderr)
    assert error["error"]["code"] == "resource_busy"
    assert result.stdout == ""


def test_job_snapshot_preserves_generation_status_and_execution_status(tmp_path: Path) -> None:
    """The legacy flat status remains distinct from durable execution state."""
    service = service_at(tmp_path)
    queued = service.enqueue("status-compatibility", request())

    job = service.get_job(queued.job_id)
    snapshot = job.to_dict()
    provenance = service.get_provenance(queued.job_id)

    assert job.status == "running"
    assert job.execution_status == "queued"
    assert snapshot["status"] == "running"
    assert snapshot["execution_status"] == "queued"
    assert provenance["status"] == "queued"

    assert service.cancel(queued.job_id)["outcome"] == "acknowledged"
    canceled = service.get_job(queued.job_id)
    canceled_snapshot = canceled.to_dict()
    canceled_provenance = service.get_provenance(queued.job_id)

    assert canceled.status == "failed"
    assert canceled.execution_status == "canceled"
    assert canceled_snapshot["status"] == "failed"
    assert canceled_snapshot["execution_status"] == "canceled"
    assert canceled_provenance["status"] == "canceled"


def test_queued_job_does_not_report_another_jobs_resource_state(tmp_path: Path) -> None:
    """Resource occupancy belongs to provenance, with explicit ownership."""

    entered = threading.Event()
    release = threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        def generate(
            self, plan: GenerationPlan, destination: BinaryIO
        ) -> tuple[str, int, int]:
            entered.set()
            if not release.wait(timeout=10):
                raise RuntimeError("paused adapter was not released")
            return super().generate(plan, destination)

    service = service_at(tmp_path, adapter=PausedAdapter())
    owner = service.enqueue("resource-owner", request("resource owner"))
    other = service.enqueue("resource-other", request("resource other"))

    with ThreadPoolExecutor(max_workers=1) as executor:
        working = executor.submit(service.work)
        assert entered.wait(timeout=10)
        try:
            queued = service.get_job(other.job_id)
            snapshot = service.get_provenance(other.job_id)

            assert not hasattr(queued, "resource_state")
            assert "resource_state" not in queued.to_dict()
            assert snapshot["execution"]["resource_state"] == "claimed"
            assert snapshot["execution"]["resource_job_id"] == owner.job_id
            assert snapshot["execution"]["resource_attempt_id"].startswith("att_")
            assert snapshot["execution"]["resource_owner_id"].startswith("worker_")
        finally:
            release.set()

    assert working.result(timeout=10)["status"] == "complete"


def test_idempotency_rejects_different_non_null_containment_contract(
    tmp_path: Path,
) -> None:
    """A trusted contract recorded at admission cannot later be replaced."""

    class DifferentContainedAdapter(DeterministicCpuAdapter):
        containment_contract = "different-contained/v1"

    service_at(tmp_path).enqueue("contract-identity", request())
    with pytest.raises(IdempotencyConflictError, match="containment contract"):
        service_at(tmp_path, adapter=DifferentContainedAdapter()).enqueue(
            "contract-identity", request()
        )


def test_idempotency_rejects_contract_for_existing_queued_null_job(
    tmp_path: Path,
) -> None:
    """The legacy NULL exception is limited to persisted terminal failure."""

    class ExternalAdapter(DeterministicCpuAdapter):
        containment_contract = None

    service_at(tmp_path, adapter=ExternalAdapter()).enqueue("external-queued", request())
    with pytest.raises(IdempotencyConflictError, match="containment contract"):
        service_at(tmp_path).enqueue("external-queued", request())


def test_succeeded_reuse_ignores_incoming_budget_without_rewriting_policy(tmp_path: Path) -> None:
    """An existing image is reusable without changing its first admission budget."""
    service = service_at(tmp_path)
    queued = service.enqueue("succeeded-budget", request(), max_attempts=2)
    service.work()
    before = service.get_provenance(queued.job_id)

    reused = service.enqueue("succeeded-budget", request(), max_attempts=99)

    assert reused.job_id == queued.job_id
    assert reused.artifact_id == before["artifact"]["artifact_id"]
    assert reused.status == "succeeded"
    assert service.get_provenance(queued.job_id) == before
    with pytest.raises(IdempotencyConflictError, match="request intent"):
        service.enqueue("succeeded-budget", request("different"), max_attempts=99)
    service.enqueue("queued-budget", request(), max_attempts=2)
    with pytest.raises(IdempotencyConflictError, match="attempt budget"):
        service.enqueue("queued-budget", request(), max_attempts=99)


def test_worker_report_preserves_each_claim_outcome_after_retry_success(tmp_path: Path) -> None:
    """Loop completion cannot erase a failed attempt when its retry succeeds."""
    class RetryOnce(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def __init__(self):
            self.calls = 0

        def generate(self, plan, stream):
            self.calls += 1
            if self.calls == 1:
                raise RetryableGenerationError("retry once")
            return super().generate(plan, stream)

    service = service_at(tmp_path, adapter=RetryOnce())
    job = service.enqueue("outcome-retry", request(), max_attempts=2)
    report = service.work(limit=2)
    assert report["status"] == "complete"
    assert report["processed"] == 2
    assert [item["status"] for item in report["outcomes"]] == ["failed", "succeeded"]
    assert [item["execution_status"] for item in report["outcomes"]] == ["queued", "succeeded"]
    assert all(item["job_id"] == job.job_id for item in report["outcomes"])
    assert len({item["attempt_id"] for item in report["outcomes"]}) == 2


@pytest.mark.parametrize("mode", ("success", "failed", "retry", "external", "canceled"))
def test_worker_cli_exit_reflects_claim_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, mode: str
) -> None:
    """A completed worker loop reports failed generation with a nonzero exit."""
    from media_generation.cli import main

    class Adapter(DeterministicCpuAdapter):
        containment_contract = None if mode == "external" else PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            if mode == "failed":
                raise RuntimeError("terminal generation failure")
            if mode == "retry":
                raise RetryableGenerationError("retry queued")
            if mode == "canceled":
                service.cancel(plan.job_id)
            return super().generate(plan, stream)

    service = service_at(tmp_path, adapter=Adapter())
    job = service.enqueue("outcome-cli", request(), max_attempts=2)
    monkeypatch.setattr("media_generation.cli.GenerationService", lambda *args, **kwargs: service)
    exit_code = main(["worker", "--db", str(tmp_path / "studio.sqlite3"), "--output-dir", str(tmp_path / "images")])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == (0 if mode == "success" else 1)
    assert report["outcomes"][0]["job_id"] == job.job_id
    assert report["outcomes"][0]["status"] == {
        "success": "succeeded", "external": "succeeded", "failed": "failed",
        "retry": "failed", "canceled": "canceled",
    }[mode]

    assert report["outcomes"][0]["execution_status"] == {
        "success": "succeeded", "external": "succeeded", "failed": "failed",
        "retry": "queued", "canceled": "canceled",
    }[mode]


def test_worker_contention_preserves_already_processed_claim_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """A later quarantine stop must not hide an earlier batch outcome."""
    from media_generation.cli import main

    class External(DeterministicCpuAdapter):
        containment_contract = None

    service = service_at(tmp_path, adapter=External())
    job = service.enqueue("batch-quarantine", request())
    monkeypatch.setattr("media_generation.cli.GenerationService", lambda *args, **kwargs: service)
    code = main(["worker", "--db", str(tmp_path / "studio.sqlite3"), "--output-dir", str(tmp_path / "images"), "--limit", "2"])
    result = json.loads(capsys.readouterr().err)
    assert code == 1
    assert result["error"]["code"] == "resource_busy"
    assert result["error"]["outcomes"][0]["job_id"] == job.job_id
