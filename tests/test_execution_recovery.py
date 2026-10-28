"""Execution failures must not turn uncertain work into authorized replay."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import os
import sqlite3
import subprocess
import sys
import threading

import pytest

from media_generation.adapters import DeterministicCpuAdapter, PROCESS_CONTAINED_CONTRACT
from media_generation.domain import GenerationArtifact, GenerationRequest
from media_generation.errors import GenerationError, RetryableGenerationError
from media_generation.service import GenerationService
from test_durable_execution import (
    ALL_PUBLICATION_CHECKPOINTS,
    POSTCOMMIT_CHECKPOINTS,
    PREPUBLICATION_CHECKPOINTS,
    request,
    service_at,
)


def admission_record(service: GenerationService, job_id: str):
    """Return typed admission evidence from one consistent inspection."""
    inspection = service.inspect_admission(job_id)
    assert inspection is not None
    return inspection.admission


def crash_worker(root: Path, *, checkpoint: str | None = None, external: bool = False) -> None:
    """Abruptly end a real worker without executing its cleanup handlers."""
    code = '''
import os, sys
from pathlib import Path
from media_generation.adapters import DeterministicCpuAdapter, PROCESS_CONTAINED_CONTRACT
from media_generation.service import GenerationService

class CrashAdapter(DeterministicCpuAdapter):
    containment_contract = (
        PROCESS_CONTAINED_CONTRACT if not bool(int(sys.argv[3])) else None
    )
    def generate(self, plan, stream):
        if sys.argv[2] == 'adapter':
            os._exit(71)
        return super().generate(plan, stream)

def checkpoint(name):
    if name == sys.argv[2]:
        os._exit(71)

root = Path(sys.argv[1])
service = GenerationService(
    root / 'studio.sqlite3',
    root / 'images',
    CrashAdapter(),
    publication_checkpoint=checkpoint,
)
service.work()
'''
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            str(root),
            checkpoint or "adapter",
            str(int(external)),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 71, result.stderr


def test_crashed_contained_execution_uses_same_job_and_persisted_budget(tmp_path: Path) -> None:
    queued = service_at(tmp_path).enqueue("recover", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint="before_stage_write")

    restarted = service_at(tmp_path)
    restarted.recover()
    first = restarted.get_provenance(queued.job_id)
    assert queued.job_id == first["job_id"]
    assert first["status"] == "queued"
    assert first["attempts"][0]["termination_proven"] is True
    assert first["artifact"] is None

    restarted.work()
    snapshot = restarted.get_provenance(queued.job_id)
    assert snapshot["status"] == "succeeded"
    assert [attempt["attempt_number"] for attempt in snapshot["attempts"]] == [1, 2]


def test_crashed_external_execution_remains_quarantined_after_lock_release(
    tmp_path: Path,
) -> None:
    class ExternalAdapter(DeterministicCpuAdapter):
        containment_contract = None

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from test_resource_admission import GIB, inventory_report, workload_demand

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    service = service_at(
        tmp_path, adapter=ExternalAdapter(), admission_profile=profile
    )
    queued = service.enqueue(
        "external",
        request(),
        max_attempts=3,
        workload_demand=parse_workload_demand(workload_demand()),
    )
    crash_worker(tmp_path, external=True)

    report = service_at(tmp_path, adapter=ExternalAdapter()).recover()
    assert report["status"] == "attention_required"
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "ambiguous"
    assert snapshot["execution"]["resource_state"] == "quarantined"
    assert snapshot["attempts"][0]["termination_proven"] is False
    admission = admission_record(service_at(tmp_path), queued.job_id)
    assert admission.decision == "quarantined"
    assert admission.reserved_bytes == {"system_ram": 48 * GIB}
    service_at(tmp_path).enqueue("other", request())
    assert service_at(tmp_path).work()["status"] == "resource_busy"
    with pytest.raises(GenerationError):
        service_at(tmp_path).retry(queued.job_id)


@pytest.mark.parametrize("checkpoint", ALL_PUBLICATION_CHECKPOINTS)
def test_every_publication_crash_checkpoint_converges_safely(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    queued = service_at(tmp_path).enqueue("journal", request(), max_attempts=3)
    crash_worker(tmp_path, checkpoint=checkpoint)

    restarted = service_at(tmp_path)
    restarted.recover()
    restarted.recover()
    prepared = restarted.get_provenance(queued.job_id)
    assert prepared["artifact"] is None or checkpoint in PREPUBLICATION_CHECKPOINTS[8:] + POSTCOMMIT_CHECKPOINTS

    if checkpoint in PREPUBLICATION_CHECKPOINTS[:8]:
        assert prepared["status"] == "queued"
        restarted.work()
    else:
        assert prepared["status"] == "succeeded"

    snapshot = restarted.get_provenance(queued.job_id)
    assert snapshot["status"] == "succeeded"
    assert snapshot["artifact"]["attempt_id"] == snapshot["attempt"]["attempt_id"]
    files = list((tmp_path / "images").glob("*.png"))
    assert len(files) == 1
    assert snapshot["artifact"]["sha256"] == hashlib.sha256(files[0].read_bytes()).hexdigest()


@pytest.mark.parametrize("checkpoint", ("ready_committed", "before_publish", "before_commit"))
def test_crash_then_cancel_before_reconcile_converges_without_artifact(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    queued = service_at(tmp_path).enqueue("crash-cancel", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint=checkpoint)

    preserved = None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        state, final_name = connection.execute(
            "SELECT state, final_name FROM artifact_publications"
        ).fetchone()
        if state == "ready" and final_name is not None:
            final = tmp_path / "images" / final_name
            if checkpoint == "before_commit":
                assert final.is_file()
            if final.exists():
                preserved = (final, final.stat().st_dev, final.stat().st_ino, final.read_bytes())

    canceled = service_at(tmp_path).cancel(queued.job_id)
    assert canceled["outcome"] == "accepted"
    service_at(tmp_path).recover()
    service_at(tmp_path).recover()
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["artifact"] is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM artifact_publications"
        ).fetchone()[0] == "abandoned"
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()[0] == "available"
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE status = 'running'"
        ).fetchone()[0] == 0
    if preserved is not None:
        final, device, inode, content = preserved
        assert final.exists()
        assert (final.stat().st_dev, final.stat().st_ino) == (device, inode)
        assert final.read_bytes() == content


@pytest.mark.parametrize("checkpoint", ("ready_committed", "file_published", "before_commit"))
def test_crash_then_persisted_fence_revoke_prevents_reconcile_commit(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    queued = service_at(tmp_path).enqueue("crash-fence", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint=checkpoint)
    preserved = None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        state, final_name = connection.execute(
            "SELECT state, final_name FROM artifact_publications"
        ).fetchone()
        if state == "ready" and final_name is not None:
            final = tmp_path / "images" / final_name
            if final.exists():
                preserved = (final, final.stat().st_dev, final.stat().st_ino, final.read_bytes())
        connection.execute(
            "UPDATE execution_jobs SET fence_epoch = fence_epoch + 1 WHERE job_id = ?",
            (queued.job_id,),
        )

    service_at(tmp_path).recover()
    service_at(tmp_path).recover()
    assert service_at(tmp_path).get_job(queued.job_id).artifact_id is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM artifact_publications"
        ).fetchone()[0] == "abandoned"
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()[0] == "available"
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE status = 'running'"
        ).fetchone()[0] == 0
    if preserved is not None:
        final, device, inode, content = preserved
        assert final.exists()
        assert (final.stat().st_dev, final.stat().st_ino) == (device, inode)
        assert final.read_bytes() == content


def test_retry_budget_is_not_reset_by_restart(tmp_path: Path) -> None:
    class RetryableAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            raise RetryableGenerationError("known local transient failure")

    queued = service_at(tmp_path).enqueue("bounded", request(), max_attempts=2)
    for _ in range(3):
        service_at(tmp_path, adapter=RetryableAdapter()).work()

    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "failed"
    assert len(snapshot["attempts"]) == 2
    assert all(attempt["failure_class"] == "retryable" for attempt in snapshot["attempts"])
    assert snapshot["execution"]["retry_eligible"] is False
    with pytest.raises(GenerationError):
        service_at(tmp_path).retry(queued.job_id)


def test_unknown_failure_is_terminal_and_never_automatically_retried(tmp_path: Path) -> None:
    class FailedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, stream):
            raise RuntimeError("unclassified failure")

    service = service_at(tmp_path, adapter=FailedAdapter())
    queued = service.enqueue("unknown", request(), max_attempts=3)
    service.work(limit=3)
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "failed"
    assert len(snapshot["attempts"]) == 1
    assert snapshot["attempts"][0]["failure_class"] == "terminal"
    with pytest.raises(GenerationError):
        service.retry(queued.job_id)


def test_failed_external_invocation_quarantines_resource(tmp_path: Path) -> None:
    class ExternalFailure(DeterministicCpuAdapter):
        containment_contract = None

        def generate(self, plan, stream):
            raise RuntimeError("external response lost")

    service = service_at(tmp_path, adapter=ExternalFailure())
    queued = service.enqueue("unknown-external", request(), max_attempts=3)
    service.work()
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "ambiguous"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    with pytest.raises(GenerationError):
        service_at(tmp_path).retry(queued.job_id)


def test_budget_one_crash_never_replays(tmp_path: Path) -> None:
    queued = service_at(tmp_path).enqueue("one", request())
    crash_worker(tmp_path, checkpoint="before_stage_write")
    restarted = service_at(tmp_path)
    restarted.recover()
    assert restarted.work()["status"] == "idle"
    snapshot = restarted.get_provenance(queued.job_id)
    assert snapshot["status"] == "failed"
    assert len(snapshot["attempts"]) == 1


def test_stale_identity_cannot_fail_or_complete_successor_attempt(tmp_path: Path) -> None:
    entered, resume = threading.Event(), threading.Event()

    class FailThenPause(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT
        calls = 0

        def generate(self, plan, stream):
            self.calls += 1
            if self.calls == 1:
                raise RetryableGenerationError("retry once")
            entered.set()
            assert resume.wait(10)
            return super().generate(plan, stream)

    adapter = FailThenPause()
    service = service_at(tmp_path, adapter=adapter)
    queued = service.enqueue("stale-successor", request(), max_attempts=2)
    service.work()
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        old = dict(connection.execute("SELECT * FROM execution_attempts ORDER BY attempt_number").fetchone())
        slot_id = connection.execute(
            "SELECT output_slot_id FROM generation_jobs WHERE job_id = ?", (queued.job_id,)
        ).fetchone()[0]

    with ThreadPoolExecutor() as pool:
        running = pool.submit(service.work)
        try:
            assert entered.wait(5)
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                connection.row_factory = sqlite3.Row
                before = {
                    "job": tuple(connection.execute("SELECT * FROM execution_jobs").fetchone()),
                    "attempt": tuple(connection.execute(
                        "SELECT * FROM execution_attempts WHERE status = 'running'"
                    ).fetchone()),
                }
            timestamp = "2026-10-24T00:00:00+00:00"
            stale_artifact = GenerationArtifact(
                artifact_id="art_" + "1" * 32,
                job_id=queued.job_id,
                attempt_id=old["attempt_id"],
                output_slot_id=slot_id,
                path=str(tmp_path / "images" / ("art_" + "1" * 32 + ".png")),
                media_type="image/png",
                image_format="PNG",
                width=12,
                height=9,
                file_size=1,
                sha256="0" * 64,
                created_at=timestamp,
            )
            with pytest.raises(RuntimeError):
                service._store.complete_execution(
                    stale_artifact,
                    timestamp,
                    attempt_owner_id=old["owner_id"],
                    claim_epoch=old["claim_epoch"],
                )
            assert service._store.fail_execution(
                queued.job_id,
                old["attempt_id"],
                "stale failure",
                timestamp,
                attempt_owner_id=old["owner_id"],
                claim_epoch=old["claim_epoch"],
            ) is False
            with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
                assert tuple(connection.execute("SELECT * FROM execution_jobs").fetchone()) == before["job"]
                assert tuple(connection.execute(
                    "SELECT * FROM execution_attempts WHERE status = 'running'"
                ).fetchone()) == before["attempt"]
                assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0
        finally:
            resume.set()
        running.result(timeout=10)
    assert service.get_job(queued.job_id).status == "succeeded"


def test_lost_commit_reply_cannot_be_canceled_and_preserves_reference_lineage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service = service_at(tmp_path)
    parent = service.submit("lineage-parent", request("A lineage parent"))
    parent_artifact = service.get_artifact(parent.artifact_id)
    parent_bytes = Path(parent_artifact.path).read_bytes()

    child_service = service_at(tmp_path)
    child = child_service.enqueue(
        "lineage-child",
        GenerationRequest(
            "A lineage child",
            seed=55,
            width=12,
            height=9,
            reference_ids=(parent_artifact.artifact_id,),
        ),
    )
    complete = child_service._store.complete_execution
    lost = False

    def commit_then_raise(*args, **kwargs):
        nonlocal lost
        complete(*args, **kwargs)
        if not lost:
            lost = True
            raise sqlite3.OperationalError("commit acknowledgement lost")

    monkeypatch.setattr(child_service._store, "complete_execution", commit_then_raise)
    child_service.work()
    assert lost
    assert service_at(tmp_path).cancel(child.job_id)["outcome"] == "too_late"

    current = service_at(tmp_path)
    snapshot = current.get_provenance(child.job_id)
    assert snapshot["status"] == "succeeded"
    assert snapshot["artifact"] is not None
    assert current.get_artifact(parent_artifact.artifact_id).to_dict() == parent_artifact.to_dict()
    assert Path(parent_artifact.path).read_bytes() == parent_bytes
    child_artifact_id = snapshot["artifact"]["artifact_id"]
    assert current.get_lineage(child_artifact_id)["parents"] == [
        {
            "source_id": parent_artifact.artifact_id,
            "target_id": child_artifact_id,
            "role": "reference",
            "position": 0,
        }
    ]


def test_canceled_external_publication_without_termination_proof_quarantines_resource(
    tmp_path: Path,
) -> None:
    canceled = []

    class ExternalAdapter(DeterministicCpuAdapter):
        containment_contract = None

    def cancel_at(name: str) -> None:
        if name == "before_commit" and not canceled:
            canceled.append(service_at(tmp_path).cancel(queued.job_id))

    service = service_at(
        tmp_path,
        adapter=ExternalAdapter(),
        publication_checkpoint=cancel_at,
    )
    queued = service.enqueue("external-cancel", request(), max_attempts=2)
    service.work()

    assert canceled[0]["outcome"] == "accepted"
    assert service_at(tmp_path).recover()["status"] == "attention_required"
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    assert service_at(tmp_path).recover() == {"status": "attention_required"}
    assert service_at(tmp_path).get_job(queued.job_id).artifact_id is None


def test_undeclared_containment_does_not_authorize_retry_after_dispatch(
    tmp_path: Path,
) -> None:
    """A retryable classification cannot inherit a trusted containment proof."""

    class UndeclaredRetryableAdapter(DeterministicCpuAdapter):
        def generate(self, plan, stream):
            raise RetryableGenerationError("retry only if termination is proven")

    service = service_at(tmp_path, adapter=UndeclaredRetryableAdapter())
    queued = service.enqueue("undeclared-containment", request(), max_attempts=2)
    assert service.work()["status"] == "complete"

    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "ambiguous"
    assert len(snapshot["attempts"]) == 1
    assert snapshot["attempts"][0]["failure_class"] == "retryable"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    assert service.work()["status"] == "resource_busy"
    assert len(service.get_provenance(queued.job_id)["attempts"]) == 1


def test_unqualified_success_preserves_artifact_but_quarantines_resource(
    tmp_path: Path,
) -> None:
    """A committed artifact remains authoritative without inventing termination."""
    parent_service = service_at(tmp_path)
    parent = parent_service.submit("qualified-parent", request("a qualified parent"))
    parent_artifact = parent_service.get_artifact(parent.artifact_id)
    parent_bytes = Path(parent_artifact.path).read_bytes()

    class ExplicitExternalAdapter(DeterministicCpuAdapter):
        containment_contract = None

    child_request = GenerationRequest(
        prompt="an externally qualified child",
        seed=44,
        width=12,
        height=9,
        reference_ids=(parent_artifact.artifact_id,),
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from test_resource_admission import GIB, inventory_report, workload_demand

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    child_service = service_at(
        tmp_path, adapter=ExplicitExternalAdapter(), admission_profile=profile
    )
    child = child_service.submit(
        "unqualified-success",
        child_request,
        workload_demand=parse_workload_demand(workload_demand()),
    )
    child_artifact = child_service.get_artifact(child.artifact_id)
    snapshot = child_service.get_provenance(child.job_id)

    assert snapshot["status"] == "succeeded"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    admission = admission_record(child_service, child.job_id)
    assert admission.decision == "quarantined"
    assert admission.reserved_bytes == {"system_ram": 48 * GIB}
    assert Path(child_artifact.path).read_bytes()
    assert Path(parent_artifact.path).read_bytes() == parent_bytes
    lineage = child_service.get_lineage(child_artifact.artifact_id)
    assert lineage["parents"][0]["source_id"] == parent_artifact.artifact_id
    assert service_at(tmp_path).recover() == {"status": "attention_required"}


def test_unproven_retryable_failure_is_quarantined_without_replay_authority(
    tmp_path: Path,
) -> None:
    queued = service_at(tmp_path).enqueue("unknown-outcome", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint="before_validation")
    service = service_at(tmp_path)
    attempt = service._store.current_attempt(queued.job_id)
    assert attempt is not None

    assert service._store.fail_execution(
        queued.job_id,
        str(attempt["attempt_id"]),
        "failure classification exists, but termination is unknown",
        "2026-10-24T23:00:00+00:00",
        attempt_owner_id=str(attempt["owner_id"]),
        claim_epoch=int(attempt["claim_epoch"]),
        failure_class="retryable",
        termination_proven=False,
    )

    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "ambiguous"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    with pytest.raises(GenerationError):
        service.retry(queued.job_id)


@pytest.mark.parametrize("checkpoint", POSTCOMMIT_CHECKPOINTS)
def test_postcommit_cleanup_failure_preserves_success(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    failed = []

    def fail_at(name):
        if name == checkpoint and not failed:
            failed.append(name)
            raise OSError("injected postcommit failure")

    service = service_at(tmp_path, publication_checkpoint=fail_at)
    queued = service.enqueue("postcommit-failure", request())
    service.work()
    assert failed == [checkpoint]
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "succeeded"
    assert snapshot["artifact"] is not None


def test_canceled_ready_publication_reports_retained_final_as_orphan(
    tmp_path: Path,
) -> None:
    queued = service_at(tmp_path).enqueue("retained-final", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint="before_commit")
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        state, final_name = connection.execute(
            "SELECT state, final_name FROM artifact_publications"
        ).fetchone()
    assert state == "ready"
    assert final_name is not None
    retained = tmp_path / "images" / final_name
    retained_stat = retained.stat()
    retained_bytes = retained.read_bytes()

    assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "accepted"
    assert service_at(tmp_path).recover()["status"] == "canceled"
    report = service_at(tmp_path).recover()

    assert report["status"] == "attention_required"
    assert final_name in report["publications"]["orphan_files"]
    assert retained.exists()
    assert (retained.stat().st_dev, retained.stat().st_ino) == (
        retained_stat.st_dev,
        retained_stat.st_ino,
    )
    assert retained.read_bytes() == retained_bytes
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["artifact"] is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute(
            "SELECT state FROM artifact_publications"
        ).fetchone()[0] == "abandoned"
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()[0] == "available"
        assert connection.execute(
            "SELECT count(*) FROM generation_artifacts"
        ).fetchone()[0] == 0


@pytest.mark.parametrize(
    ("external", "expected_resource_state"),
    ((False, "available"), (True, "quarantined")),
)
def test_canceled_allocated_attempt_reconciliation_finalizes_attempt_and_resource(
    tmp_path: Path,
    external: bool,
    expected_resource_state: str,
) -> None:
    """Reconciliation must not report success while a canceled claim is live."""
    adapter: DeterministicCpuAdapter
    if external:

        class ExternalAdapter(DeterministicCpuAdapter):
            containment_contract = None

        adapter = ExternalAdapter()
    else:
        adapter = DeterministicCpuAdapter()

    queued = service_at(tmp_path, adapter=adapter).enqueue(
        "canceled-allocation", request(), max_attempts=2
    )
    crash_worker(tmp_path, checkpoint="stage_written", external=external)
    assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "accepted"

    report = service_at(tmp_path).reconcile()

    assert report["status"] == "complete"
    snapshot = service_at(tmp_path).get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["attempts"][0]["status"] == "canceled"
    assert snapshot["attempts"][0]["failure_class"] == "canceled"
    assert snapshot["execution"]["resource_state"] == expected_resource_state
    resource = service_at(tmp_path)._store.resource_snapshot()
    assert resource["state"] == expected_resource_state
    if external:
        assert resource["job_id"] == queued.job_id
    else:
        assert resource["job_id"] is None


def test_canceled_allocated_attempt_reconciliation_reports_failed_finalization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A false finalization result must surface as incomplete reconciliation."""
    queued = service_at(tmp_path).enqueue(
        "canceled-finalization-failure", request(), max_attempts=2
    )
    crash_worker(tmp_path, checkpoint="stage_written")
    assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "accepted"

    service = service_at(tmp_path)
    monkeypatch.setattr(service._store, "fail_execution", lambda *args, **kwargs: False)
    report = service.reconcile()

    assert report["status"] == "attention_required"
    assert report["publications"][0]["error"]
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["attempts"][0]["status"] == "running"
    assert snapshot["execution"]["resource_state"] == "claimed"


def test_contained_recovery_reports_attention_when_finalization_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A contained crash is recovered only after durable attempt finalization."""
    queued = service_at(tmp_path).enqueue("finalization-failure", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint="stage_written")

    service = service_at(tmp_path)
    monkeypatch.setattr(service._store, "fail_execution", lambda *args, **kwargs: False)
    report = service.recover()

    assert report == {"status": "attention_required"}
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["attempts"][0]["status"] == "running"
    assert snapshot["execution"]["resource_state"] == "claimed"


@pytest.mark.parametrize("checkpoint", ("ready_committed", "file_published", "before_commit"))
@pytest.mark.parametrize("external", (False, True))
def test_live_ready_cancellation_finalizes_before_recovery(
    tmp_path: Path, checkpoint: str, external: bool
) -> None:
    """A returned worker cannot leave its canceled ready journal owning a claim."""
    class Adapter(DeterministicCpuAdapter):
        containment_contract = None if external else PROCESS_CONTAINED_CONTRACT

    preserved = []

    def cancel_at(name):
        if name != checkpoint:
            return
        if name != "ready_committed":
            final = next((tmp_path / "images").glob("*.png"))
            preserved.append((final, final.stat().st_ino, final.read_bytes()))
        assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "accepted"

    service = service_at(tmp_path, adapter=Adapter(), publication_checkpoint=cancel_at)
    queued = service.enqueue("live-ready-cancel", request(), max_attempts=2)
    service.work()

    # These assertions intentionally precede every explicit recovery call.
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "canceled"
    assert snapshot["artifact"] is None
    assert snapshot["attempt"]["status"] == "canceled"
    assert snapshot["attempt"]["termination_proven"] is (not external)
    assert snapshot["execution"]["resource_state"] == (
        "quarantined" if external else "available"
    )
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT state FROM artifact_publications").fetchone() == ("abandoned",)
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone() == (0,)

    service.recover()
    service.recover()
    assert service.get_provenance(queued.job_id)["attempts"] == snapshot["attempts"]
    for final, inode, content in preserved:
        assert final.stat().st_ino == inode
        assert final.read_bytes() == content


def test_recovered_external_artifact_reports_quarantine_immediately(tmp_path: Path) -> None:
    """Recovering image bytes cannot report the execution resource as reusable."""
    class ExternalAdapter(DeterministicCpuAdapter):
        containment_contract = None

    service = service_at(tmp_path, adapter=ExternalAdapter())
    queued = service.enqueue("external-ready", request())
    crash_worker(tmp_path, checkpoint="ready_committed", external=True)

    report = service.recover()

    assert report["status"] == "attention_required"
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "succeeded"
    assert snapshot["artifact"] is not None
    assert snapshot["attempt"]["termination_proven"] is False
    assert snapshot["execution"]["resource_state"] == "quarantined"
    assert service.recover()["status"] == "attention_required"


def test_cancellation_does_not_authorize_a_different_attempt_owner(tmp_path: Path) -> None:
    """Canceled state cannot turn arbitrary credentials into a finalization claim."""
    service = service_at(tmp_path)
    queued = service.enqueue("wrong-cancel-owner", request())
    crash_worker(tmp_path, checkpoint="before_stage_write")
    attempt = service._store.current_attempt(queued.job_id)
    service.cancel(queued.job_id)
    publication = service._store.publications(str(tmp_path / "images"))[0]
    service._store.abandon_publication(publication["publication_id"], "canceled")
    before = service.get_provenance(queued.job_id)

    assert service._store.fail_execution(
        queued.job_id, attempt["attempt_id"], "wrong owner", "2026-10-25T00:00:00+00:00",
        attempt_owner_id="worker_wrong", claim_epoch=attempt["claim_epoch"],
        failure_class="canceled", termination_proven=True,
    ) is False
    assert service.get_provenance(queued.job_id) == before


@pytest.mark.parametrize("external", (False, True))
@pytest.mark.parametrize("max_attempts", (1, 2))
def test_cancel_after_reconciliation_snapshot_cannot_restore_retry(
    tmp_path: Path, monkeypatch, external: bool, max_attempts: int,
) -> None:
    """A committed cancellation outranks an earlier crash-recovery snapshot."""
    class CrashAdapter(DeterministicCpuAdapter):
        containment_contract = None if external else PROCESS_CONTAINED_CONTRACT

    service = service_at(tmp_path, adapter=CrashAdapter())
    queued = service.enqueue("snapshot-cancel-race", request(), max_attempts=max_attempts)
    crash_worker(tmp_path, checkpoint="stage_written", external=external)
    snapshot_read = threading.Event()
    resume_finalization = threading.Event()
    finalize = service._store.fail_execution

    def pause_after_snapshot(*args, **kwargs):
        # Reconciliation has already selected its classification from the real
        # running attempt. Pause before the finalization transaction starts.
        assert kwargs["failure_class"] == ("ambiguous" if external else "crash")
        assert kwargs["_revoked_publication_id"]
        snapshot_read.set()
        assert resume_finalization.wait(10), "cancellation did not resume finalization"
        return finalize(*args, **kwargs)

    monkeypatch.setattr(service._store, "fail_execution", pause_after_snapshot)
    with ThreadPoolExecutor(max_workers=1) as pool:
        reconciliation = pool.submit(service.reconcile)
        try:
            assert snapshot_read.wait(10), "reconciliation did not reach finalization"
            assert service_at(tmp_path).cancel(queued.job_id)["outcome"] == "accepted"
            canceled = service.get_provenance(queued.job_id)
            assert canceled["status"] == "canceled"
            assert canceled["execution"]["retry_eligible"] is False
            assert canceled["execution"]["resource_state"] == "claimed"
        finally:
            resume_finalization.set()
        report = reconciliation.result(timeout=10)

    # Check the stale finalization result before any further recovery can hide
    # an overwritten cancellation or an incorrectly released reservation.
    after_finalization = service.get_provenance(queued.job_id)
    assert after_finalization["status"] == "canceled"
    assert after_finalization == canceled
    assert report["status"] == "attention_required"
    assert canceled["attempt"]["status"] == "running"
    assert canceled["artifact"] is None
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone() == (0,)

    monkeypatch.setattr(service._store, "fail_execution", finalize)
    service.recover()
    finalized = service.get_provenance(queued.job_id)
    assert finalized["status"] == "canceled"
    assert finalized["attempt"]["status"] == "canceled"
    assert finalized["attempt"]["termination_proven"] is (not external)
    assert finalized["execution"]["retry_eligible"] is False
    assert finalized["execution"]["resource_state"] == (
        "quarantined" if external else "available"
    )
    service.recover()
    assert service.get_provenance(queued.job_id) == finalized
    assert service.work()["status"] == ("resource_busy" if external else "idle")
    assert len(service.get_provenance(queued.job_id)["attempts"]) == 1


@pytest.mark.parametrize(("epoch_advance", "failure_class"), ((2, "crash"), (1, "canceled")))
def test_abandoned_journal_requires_matching_job_fence_and_classification(
    tmp_path: Path, epoch_advance: int, failure_class: str,
) -> None:
    """A journal cannot grant finalization across unrelated fencing or status."""
    service = service_at(tmp_path)
    queued = service.enqueue("revoked-fence-relation", request(), max_attempts=2)
    crash_worker(tmp_path, checkpoint="stage_written")
    attempt = service._store.current_attempt(queued.job_id)
    publication = service._store.publications(str(tmp_path / "images"))[0]
    service._store.abandon_publication(publication["publication_id"], "revoked")
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        connection.execute(
            "UPDATE execution_jobs SET fence_epoch = fence_epoch + ? WHERE job_id = ?",
            (epoch_advance, queued.job_id),
        )
    before = service.get_provenance(queued.job_id)

    assert service._store.fail_execution(
        queued.job_id, attempt["attempt_id"], "stale recovery", "2026-10-25T00:00:00+00:00",
        attempt_owner_id=attempt["owner_id"], claim_epoch=attempt["claim_epoch"],
        failure_class=failure_class, termination_proven=True,
        _revoked_publication_id=publication["publication_id"],
    ) is False
    assert service.get_provenance(queued.job_id) == before
