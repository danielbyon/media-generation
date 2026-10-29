"""Contracts for typed admission inspection and persistence."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest


def test_inspection_exposes_a_typed_admission_record(tmp_path: Path) -> None:
    """Inspection exposes one typed record instead of a loose dictionary."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import AdmissionRecord
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue("typed-inspection", request(), workload_demand=demand)

    inspection = service.inspect_admission(queued.job_id)

    assert inspection is not None
    assert isinstance(inspection.admission, AdmissionRecord)
    assert inspection.admission.decision == "queued"
    assert inspection.admission.reason == "capacity_fit"
    assert inspection.to_dict()["admission"]["decision"] == "queued"
    assert not hasattr(service, "get_admission")
    assert not hasattr(service._store, "admission_snapshot")


def test_pending_admission_is_validated_at_the_persistence_boundary(
    tmp_path: Path,
) -> None:
    """Persistence rejects values outside the cohesive admission contract."""
    from media_generation.admission_store import (
        AdmissionPersistence,
        PendingAdmission,
    )
    from media_generation.store import SQLiteStore

    with pytest.raises(ValueError, match="non-negative byte counts"):
        PendingAdmission(
            profile=None,
            demand=None,
            decision="not_required",
            reason="lightweight_deterministic_cpu",
            required_bytes={"system_ram": True},
        )

    store = SQLiteStore(tmp_path / "studio.sqlite3")
    with store._connection(transaction=True) as connection:
        with pytest.raises(
            ValueError, match="admission evidence must be a PendingAdmission"
        ):
            AdmissionPersistence.insert(
                connection,
                job_id="missing",
                admission=cast(PendingAdmission, object()),
                timestamp="2026-10-27T00:00:00Z",
            )


def test_queued_pending_admission_requires_pinned_capacity_evidence() -> None:
    """A dispatchable decision cannot be constructed without both documents."""
    from media_generation.admission_store import PendingAdmission

    with pytest.raises(ValueError, match="capacity profile and workload demand"):
        PendingAdmission(
            profile=None,
            demand=None,
            decision="queued",
            reason="capacity_fit",
        )


def test_create_rejects_forged_typed_profile_fingerprint(tmp_path: Path) -> None:
    """Create validation cannot trust a fingerprint carried by a typed object."""
    import json
    from dataclasses import replace

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import PendingAdmission
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    generation_request = request()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    forged_profile = replace(profile, fingerprint="sha256:" + "0" * 64)

    with pytest.raises(ValueError, match="profile fingerprint"):
        service._store.create_queued_execution(
            request=generation_request,
            request_digest=generation_request.digest(),
            idempotency_key="forged-profile-fingerprint",
            request_id="req_forged_profile_fingerprint",
            job_id="job_forged_profile_fingerprint",
            output_slot_id="slot_forged_profile_fingerprint",
            resolved_seed=1,
            adapter_id=service.adapter.adapter_id,
            adapter_configuration_json=adapter_configuration_json,
            privacy_compliance_json=privacy_compliance_json,
            effective_parameters_json=json.dumps(
                {"width": generation_request.width, "height": generation_request.height}
            ),
            resolved_output_directory=str(service.output_directory),
            max_attempts=1,
            containment_contract=None,
            timestamp="2026-10-28T00:00:00Z",
            admission=PendingAdmission(
                profile=forged_profile,
                demand=demand,
                decision="queued",
                reason="capacity_fit",
                required_bytes={"system_ram": 20 * GIB},
            ),
            allow_not_required=False,
        )

    with service._store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM execution_attempts").fetchone()[0] == 0


def test_create_rejects_queued_evidence_that_is_over_budget(tmp_path: Path) -> None:
    """A typed queued decision cannot contradict recomputed capacity."""
    import json

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import PendingAdmission
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=60 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    generation_request = request()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )

    with pytest.raises(ValueError, match="capacity decision"):
        service._store.create_queued_execution(
            request=generation_request,
            request_digest=generation_request.digest(),
            idempotency_key="forged-over-budget-decision",
            request_id="req_forged_over_budget_decision",
            job_id="job_forged_over_budget_decision",
            output_slot_id="slot_forged_over_budget_decision",
            resolved_seed=1,
            adapter_id=service.adapter.adapter_id,
            adapter_configuration_json=adapter_configuration_json,
            privacy_compliance_json=privacy_compliance_json,
            effective_parameters_json=json.dumps(
                {"width": generation_request.width, "height": generation_request.height}
            ),
            resolved_output_directory=str(service.output_directory),
            max_attempts=1,
            containment_contract=None,
            timestamp="2026-10-28T00:00:00Z",
            admission=PendingAdmission(
                profile=profile,
                demand=demand,
                decision="queued",
                reason="capacity_fit",
                required_bytes={"system_ram": 80 * GIB},
            ),
            allow_not_required=False,
        )

    with service._store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM execution_attempts").fetchone()[0] == 0


def test_store_rejects_not_required_for_non_cpu_adapter(tmp_path: Path) -> None:
    """The persistence boundary enforces the exact lightweight producer."""
    import json

    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation.admission_store import PendingAdmission
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class NonCpuAdapter(DeterministicCpuAdapter):
        adapter_id = "heavyweight-test-adapter"

    generation_request = request()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=NonCpuAdapter(),
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )

    with pytest.raises(ValueError, match="exact lightweight CPU adapter"):
        service._store.create_queued_execution(
            request=generation_request,
            request_digest=generation_request.digest(),
            idempotency_key="forged-exemption",
            request_id="req_forged_exemption",
            job_id="job_forged_exemption",
            output_slot_id="slot_forged_exemption",
            resolved_seed=1,
            adapter_id=service.adapter.adapter_id,
            adapter_configuration_json=adapter_configuration_json,
            privacy_compliance_json=privacy_compliance_json,
            effective_parameters_json=json.dumps(
                {"width": generation_request.width, "height": generation_request.height}
            ),
            resolved_output_directory=str(service.output_directory),
            max_attempts=1,
            containment_contract=None,
            timestamp="2026-10-28T00:00:00Z",
            admission=PendingAdmission.not_required(),
            allow_not_required=False,
        )

    with service._store._connection() as connection:
        assert connection.execute(
            "SELECT count(*) FROM generation_jobs"
        ).fetchone()[0] == 0


def test_queued_admission_transition_requires_queued_execution(
    tmp_path: Path,
) -> None:
    """Admission cannot become claimable while execution remains failed."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import AdmissionPersistence
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "failed-execution-transition",
        request(),
        workload_demand=parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
        ),
    )

    with service._store._connection(transaction=True) as connection:
        connection.execute(
            "UPDATE execution_jobs SET status = 'failed' WHERE job_id = ?",
            (queued.job_id,),
        )
        connection.execute(
            """UPDATE execution_admissions
               SET decision = 'released', decision_reason = 'safe_retry_eligible'
               WHERE job_id = ?""",
            (queued.job_id,),
        )

        requeued = AdmissionPersistence.finish(
            connection,
            queued.job_id,
            decision="queued",
            reason="safe_retry_eligible",
            timestamp="2026-10-27T00:00:00Z",
        )

        assert requeued is False
        admission = AdmissionPersistence.snapshot(connection, queued.job_id)
        assert admission is not None
        assert admission.decision == "released"

    assert service.get_provenance(queued.job_id)["status"] == "failed"


def test_failed_admission_transition_rolls_back_execution_finalization(
    tmp_path: Path,
) -> None:
    """A rejected admission update cannot leave a partially finalized attempt."""
    from media_generation.adapters import PROCESS_CONTAINED_CONTRACT
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "rejected-admission-finish",
        request(),
        max_attempts=2,
        workload_demand=parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
        ),
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    claim = service._store.claim_next_execution(
        attempt_id="att_0123456789abcdef0123456789abcdef",
        owner_id="worker_rejected_finish",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "images"),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )
    assert claim is not None

    with service._store._connection(transaction=True) as connection:
        connection.execute(
            """UPDATE execution_admissions
               SET decision = 'blocked', decision_reason = 'inconsistent fixture'
               WHERE job_id = ?""",
            (queued.job_id,),
        )

    with pytest.raises(RuntimeError, match="admission failure transition was rejected"):
        service._store.fail_execution(
            queued.job_id,
            claim.attempt_id,
            "known transient failure",
            "2026-10-27T00:00:02Z",
            attempt_owner_id=claim.owner_id,
            claim_epoch=claim.claim_epoch,
            failure_class="retryable",
            termination_proven=True,
        )

    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "running"
    assert snapshot["attempts"][0]["status"] == "running"
    assert snapshot["execution"]["retry_eligible"] is False
    assert snapshot["execution"]["resource_state"] == "claimed"
    inspection = service.inspect_admission(queued.job_id)
    assert inspection is not None
    assert inspection.admission.decision == "blocked"


def test_successful_admission_transition_rolls_back_execution_finalization(
    tmp_path: Path, monkeypatch
) -> None:
    """A rejected successful transition cannot partially commit the job."""
    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import AdmissionPersistence
    from media_generation.domain import GenerationArtifact, GenerationPlan
    from media_generation.publication import PublicationError
    from media_generation.service import GenerationService
    from test_durable_execution import request
    from test_resource_admission import GIB, inventory_report, workload_demand

    class ProcessContainedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

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
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=ProcessContainedAdapter(),
        admission_profile=profile,
    )
    queued = service.enqueue(
        "rejected-successful-finish",
        request(),
        max_attempts=1,
        workload_demand=parse_workload_demand(
            workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
        ),
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    claim = service._store.claim_next_execution(
        attempt_id="att_fedcba9876543210fedcba9876543210",
        owner_id="worker_rejected_success",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "images"),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )
    assert claim is not None
    plan = GenerationPlan(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        resolved_prompt=claim.resolved_prompt,
        seed=claim.resolved_seed,
        width=claim.width,
        height=claim.height,
        references=claim.references,
        output_slot=claim.output_slot,
        output_slot_id=claim.output_slot_id,
    )
    publication_calls = []

    def write_image(destination, staged) -> None:
        service.adapter.generate(plan, staged)

    def make_artifact(info, destination) -> GenerationArtifact:
        return GenerationArtifact(
            artifact_id="art_0123456789abcdef0123456789abcdef",
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            output_slot_id=claim.output_slot_id,
            path=str(destination),
            media_type=info.media_type,
            image_format=info.image_format,
            width=info.width,
            height=info.height,
            file_size=info.file_size,
            sha256=info.sha256,
            created_at="2026-10-27T00:00:01Z",
        )

    def reject_successful_finish(connection, job_id, *, decision, reason, timestamp):
        publication_calls.append((job_id, decision, reason, timestamp))
        return False

    monkeypatch.setattr(
        AdmissionPersistence,
        "finish",
        staticmethod(reject_successful_finish),
    )
    with pytest.raises(PublicationError) as rejected:
        service._publication.publish(
            write_image,
            make_artifact,
            artifact_id="art_0123456789abcdef0123456789abcdef",
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            attempt_owner_id=claim.owner_id,
            claim_epoch=claim.claim_epoch,
        )

    assert len(publication_calls) == 1
    job_id, decision, reason, _ = publication_calls[0]
    assert job_id == queued.job_id
    assert decision == "released"
    assert reason == "termination_and_publication_reconciled"
    assert isinstance(rejected.value.__cause__, RuntimeError)
    assert "admission completion transition was rejected" in str(
        rejected.value.__cause__
    )
    snapshot = service.get_provenance(queued.job_id)
    assert snapshot["status"] == "running"
    assert snapshot["artifact"] is None
    assert snapshot["attempts"][0]["status"] == "running"
    assert snapshot["execution"]["resource_state"] == "claimed"
    resource = service._store.resource_snapshot()
    assert resource["state"] == "claimed"
    assert resource["job_id"] == queued.job_id
    assert resource["attempt_id"] == claim.attempt_id
    assert resource["owner_id"] == claim.owner_id
    inspection = service.inspect_admission(queued.job_id)
    assert inspection is not None
    assert inspection.admission.decision == "reserved"
    assert inspection.admission.reason == "resource_reserved"


def test_inspection_reads_a_consistent_snapshot_without_blocking_a_writer(
    tmp_path: Path,
) -> None:
    """Admission inspection uses a deferred read transaction, not a write lock."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from unittest.mock import patch

    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import AdmissionPersistence
    from media_generation.service import GenerationService
    from test_durable_execution import request
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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue("concurrent-inspection", request(), workload_demand=demand)
    snapshot_loaded = Event()
    release_snapshot = Event()
    writer_done = Event()
    original_snapshot = AdmissionPersistence.snapshot

    def paused_snapshot(connection, job_id):
        record = original_snapshot(connection, job_id)
        snapshot_loaded.set()
        assert release_snapshot.wait(5)
        return record

    def write_admission() -> None:
        with service._store._connection(transaction=True) as connection:
            connection.execute(
                """UPDATE execution_admissions
                   SET decision = 'released', decision_reason = 'concurrent_write',
                       updated_at = ?
                   WHERE job_id = ?""",
                ("2026-10-27T00:00:00Z", queued.job_id),
            )
            writer_done.set()

    with patch.object(AdmissionPersistence, "snapshot", side_effect=paused_snapshot):
        with ThreadPoolExecutor(max_workers=2) as pool:
            inspection_future = pool.submit(service.inspect_admission, queued.job_id)
            assert snapshot_loaded.wait(5)
            writer_future = pool.submit(write_admission)
            try:
                assert writer_done.wait(2)
                assert not inspection_future.done()
            finally:
                release_snapshot.set()
                inspection = inspection_future.result(timeout=5)
                writer_future.result(timeout=5)

    assert inspection is not None
    assert inspection.admission.decision == "queued"


def test_submit_uses_one_typed_inspection_after_execution(tmp_path: Path) -> None:
    """A failed submission reads admission evidence once, with no duplicate query."""
    from unittest.mock import patch

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import GenerationExecutionError
    from media_generation.service import GenerationService
    from test_durable_execution import request
    from test_resource_admission import GIB, inventory_report, workload_demand

    class FailingAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, destination):
            raise RuntimeError("fixture adapter failure")

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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=FailingAdapter(),
        admission_profile=profile,
    )

    with patch.object(
        service,
        "inspect_admission",
        wraps=service.inspect_admission,
    ) as inspect_admission:
        with pytest.raises(GenerationExecutionError):
            service.submit(
                "single-inspection",
                request(),
                workload_demand=demand,
            )

    assert inspect_admission.call_count == 1


def test_unconfigured_heavyweight_enqueue_fails_before_persistence(
    tmp_path: Path,
) -> None:
    """Missing heavyweight evidence is rejected without orphaned queued work."""
    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation.errors import InputValidationError
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class HeavyweightAdapter(DeterministicCpuAdapter):
        adapter_id = "heavyweight-test-adapter"

    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=HeavyweightAdapter(),
    )

    with pytest.raises(
        InputValidationError,
        match="heavyweight execution requires explicit profile and demand evidence",
    ):
        service.enqueue("unconfigured-heavyweight", request())

    with service._store._connection() as connection:
        for table in (
            "generation_requests",
            "generation_jobs",
            "execution_jobs",
            "execution_admissions",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0

    from media_generation.admission import evaluate_admission

    exempt = evaluate_admission(None, None, allow_not_required=True)
    assert exempt.status == "not_required"
    assert exempt.reason == "lightweight_deterministic_cpu"


def test_store_rejects_blocked_heavyweight_admission_without_persisting(
    tmp_path: Path,
) -> None:
    """Persistence cannot accept an incomplete blocked heavyweight record."""
    import json

    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation.admission_store import PendingAdmission
    from media_generation.service import GenerationService
    from test_durable_execution import request

    class HeavyweightAdapter(DeterministicCpuAdapter):
        adapter_id = "heavyweight-test-adapter"

    generation_request = request()
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=HeavyweightAdapter(),
    )
    _, configuration_json, _, privacy_json = service._current_privacy_snapshot()

    with pytest.raises(ValueError, match="blocked heavyweight admission"):
        service._store.create_queued_execution(
            request=generation_request,
            request_digest=generation_request.digest(),
            idempotency_key="blocked-without-evidence",
            request_id="req_blocked_without_evidence",
            job_id="job_blocked_without_evidence",
            output_slot_id="slot_blocked_without_evidence",
            resolved_seed=1,
            adapter_id=service.adapter.adapter_id,
            adapter_configuration_json=configuration_json,
            privacy_compliance_json=privacy_json,
            effective_parameters_json=json.dumps(
                {"width": generation_request.width, "height": generation_request.height}
            ),
            resolved_output_directory=str(service.output_directory),
            max_attempts=1,
            containment_contract=None,
            timestamp="2026-10-28T00:00:00Z",
            admission=PendingAdmission(
                profile=None,
                demand=None,
                decision="blocked",
                reason="resource_admission_required",
                unknown_reasons=("admission:required",),
            ),
            allow_not_required=False,
        )

    with service._store._connection() as connection:
        for table in (
            "generation_requests",
            "generation_jobs",
            "execution_jobs",
            "execution_admissions",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


def test_lightweight_cpu_exemption_uses_exact_class_and_adapter_identity() -> None:
    """Central exemption helpers retain exact-class and persistence identity."""
    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation.admission import (
        is_lightweight_cpu_adapter,
        is_lightweight_cpu_adapter_id,
    )

    class CpuSubclass(DeterministicCpuAdapter):
        adapter_id = "cpu-subclass-v1"

    exact = DeterministicCpuAdapter()
    subclass = CpuSubclass()

    assert is_lightweight_cpu_adapter(exact)
    assert is_lightweight_cpu_adapter_id(exact.adapter_id)
    assert not is_lightweight_cpu_adapter(subclass)
    assert not is_lightweight_cpu_adapter_id(subclass.adapter_id)


def test_capacity_reason_is_not_reported_as_an_execution_failure(
    tmp_path: Path,
) -> None:
    """CLI-safe failure text describes execution, not a successful capacity fit."""
    from unittest.mock import patch

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.admission_store import (
        AdmissionInspection,
        AdmissionRecord,
    )
    from media_generation.errors import GenerationExecutionError
    from media_generation.service import GenerationService
    from test_durable_execution import request
    from test_resource_admission import GIB, inventory_report, workload_demand

    class FailingAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, destination):
            raise RuntimeError("fixture adapter failure")

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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=FailingAdapter(),
        admission_profile=profile,
    )
    stale_capacity_inspection = AdmissionInspection(
        admission=AdmissionRecord(
            job_id="fixture-job",
            decision="queued",
            reason="capacity_fit",
            profile_fingerprint=profile.fingerprint,
            profile=profile.to_dict(),
            demand=demand.to_dict(),
            required_bytes={"system_ram": 40 * GIB},
            unknown_reasons=(),
            reserved_bytes=None,
            created_at="2026-10-27T00:00:00Z",
            updated_at="2026-10-27T00:00:00Z",
        ),
        resource=None,
    )

    with patch.object(
        service,
        "inspect_admission",
        return_value=stale_capacity_inspection,
    ):
        with pytest.raises(GenerationExecutionError) as raised:
            service.submit(
                "capacity-reason-failure",
                request(),
                workload_demand=demand,
            )

    assert raised.value.safe_message == "execution_failed"
