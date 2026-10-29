"""Focused tests for immutable intent and failed adapter execution state."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import BinaryIO
from threading import Barrier, Event

import pytest

from media_generation.adapters import (
    PROCESS_CONTAINED_CONTRACT,
    AdapterCapabilities,
    DeterministicCpuAdapter,
)
from media_generation.domain import (
    GenerationArtifact,
    GenerationJob,
    GenerationPlan,
    GenerationRequest,
)
from media_generation.errors import (
    GenerationError,
    IdempotencyConflictError,
    PrivacyComplianceError,
    UnsupportedCapabilityError,
)
from media_generation.service import GenerationExecutionError, GenerationService
from media_generation.admission import (
    build_admission_profile,
    parse_admission_policy,
    parse_workload_demand,
)
from test_resource_admission import GIB, inventory_report, workload_demand


def _heavyweight_profile():
    """Return deterministic capacity evidence for adapter subclasses."""
    return build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )


def _heavyweight_demand():
    """Return explicit demand that fits the deterministic test profile."""
    return parse_workload_demand(workload_demand())


@pytest.mark.parametrize(
    ("profile_supplied", "demand_supplied"),
    ((False, False), (True, False), (False, True)),
    ids=("missing-both", "missing-demand", "missing-profile"),
)
def test_heavyweight_enqueue_rejects_incomplete_admission_without_persisting(
    tmp_path: Path,
    profile_supplied: bool,
    demand_supplied: bool,
) -> None:
    """Reject absent capacity evidence before creating undispatchable work."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(
        database,
        tmp_path / "images",
        adapter=_VariantCpuAdapter(),
        admission_profile=_heavyweight_profile() if profile_supplied else None,
    )

    with pytest.raises(
        GenerationError,
        match="heavyweight execution requires explicit profile and demand evidence",
    ):
        service.enqueue(
            "incomplete-admission",
            GenerationRequest(prompt="A red fox", width=32, height=32),
            workload_demand=_heavyweight_demand() if demand_supplied else None,
        )

    with service._store._connection() as connection:
        for table in (
            "generation_requests",
            "generation_jobs",
            "execution_jobs",
            "execution_admissions",
        ):
            assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0


class _VariantCpuAdapter(DeterministicCpuAdapter):
    """Run the real CPU adapter with controlled identity, config, or limits."""

    def __init__(
        self,
        *,
        adapter_id: str = "deterministic-cpu-png-v1",
        configuration: dict[str, object] | None = None,
        capabilities: AdapterCapabilities | None = None,
    ) -> None:
        self.adapter_id = adapter_id
        self._configuration = (
            super().configuration if configuration is None else configuration
        )
        if capabilities is not None:
            self.capabilities = capabilities

    @property
    def configuration(self) -> dict[str, object]:
        """Return the configuration variant used by this test adapter."""
        return dict(self._configuration)


@pytest.mark.parametrize(
    "unsupported_value",
    ({"set-member"}, float("nan"), object()),
    ids=("set", "nan", "custom-object"),
)
def test_non_json_adapter_configuration_fails_before_admission_without_leaking_values(
    tmp_path: Path,
    unsupported_value: object,
) -> None:
    """Non-JSON settings fail with redacted privacy evidence and persist no job."""
    configuration = {"configuration_version": 1}
    adapter = _VariantCpuAdapter(configuration=configuration)
    database_path = tmp_path / "studio.sqlite3"
    service = GenerationService(
        database_path,
        tmp_path / "artifacts",
        adapter=adapter,
    )
    sensitive_value = "private-configuration-value"
    configuration.update(
        {
            "api_key": sensitive_value,
            "unsupported": unsupported_value,
        }
    )

    with pytest.raises(
        PrivacyComplianceError,
        match=(
            r"^adapter privacy configuration is unverified; "
            r"configuration-only compliance did not admit this execution$"
        ),
    ) as raised:
        service.enqueue(
            "non-json-adapter-configuration",
            GenerationRequest("A non-JSON configuration", seed=19),
        )

    evidence = raised.value.result.to_dict()
    assert evidence["reasons"] == [
        {
            "code": "configuration_not_json",
            "detail": "Configuration is not valid JSON.",
        }
    ]
    assert sensitive_value not in str(raised.value)
    assert sensitive_value not in json.dumps(evidence, sort_keys=True)
    assert "RecursionError" not in str(raised.value)
    with sqlite3.connect(database_path) as connection:
        for table in (
            "generation_requests",
            "generation_jobs",
            "generation_attempts",
            "execution_jobs",
            "execution_attempts",
        ):
            assert connection.execute(
                f"SELECT count(*) FROM {table}"
            ).fetchone() == (0,)


@pytest.mark.parametrize("cycle_kind", ("mapping", "list"))
def test_cyclic_adapter_configuration_fails_before_admission_without_recursion(
    tmp_path: Path,
    cycle_kind: str,
) -> None:
    """Cyclic settings fail with redacted evidence before persistence."""
    configuration: dict[str, object] = {"configuration_version": 1}
    adapter = _VariantCpuAdapter(configuration=configuration)
    database_path = tmp_path / "studio.sqlite3"
    service = GenerationService(
        database_path,
        tmp_path / "artifacts",
        adapter=adapter,
    )

    sensitive_value = "private-cyclic-configuration-value"
    configuration["api_key"] = sensitive_value
    if cycle_kind == "mapping":
        configuration["cycle"] = configuration
    else:
        recursive_list: list[object] = []
        recursive_list.append(recursive_list)
        configuration["cycle"] = recursive_list

    with pytest.raises(
        PrivacyComplianceError,
        match=(
            r"^adapter privacy configuration is unverified; "
            r"configuration-only compliance did not admit this execution$"
        ),
    ) as raised:
        service.enqueue(
            "cyclic-adapter-configuration",
            GenerationRequest("A cyclic configuration", seed=19),
        )

    evidence = raised.value.result.to_dict()
    assert evidence["reasons"] == [
        {
            "code": "configuration_not_json",
            "detail": "Configuration is not valid JSON.",
        }
    ]
    assert sensitive_value not in str(raised.value)
    assert sensitive_value not in json.dumps(evidence, sort_keys=True)
    assert "RecursionError" not in str(raised.value)

    with sqlite3.connect(database_path) as connection:
        for table in (
            "generation_requests",
            "generation_jobs",
            "generation_attempts",
            "execution_jobs",
            "execution_attempts",
        ):
            assert connection.execute(
                f"SELECT count(*) FROM {table}"
            ).fetchone() == (0,)


def test_nested_adapter_configuration_with_credential_fails_before_admission_without_leak(
    tmp_path: Path,
) -> None:
    """Nested credential settings fail redacted without persisting admission."""
    sensitive_value = "private-deep-configuration-value"
    nested: dict[str, object] = {"api_key": sensitive_value}
    for _ in range(64):
        nested = {"nested": nested}

    configuration: dict[str, object] = {
        "configuration_version": 1,
        "nested": nested,
    }
    adapter = _VariantCpuAdapter(configuration=configuration)
    database_path = tmp_path / "studio.sqlite3"
    with pytest.raises(
        PrivacyComplianceError,
        match=(
            r"^adapter privacy configuration is fail; "
            r"configuration-only compliance did not admit this execution$"
        ),
    ) as raised:
        GenerationService(
            database_path,
            tmp_path / "artifacts",
            adapter=adapter,
        )

    evidence = raised.value.result.to_dict()
    assert evidence["status"] == "fail"
    assert evidence["reasons"] == [
        {
            "code": "credential_material_present",
            "detail": "Credentials must remain outside runtime inference settings.",
        },
        {
            "code": "unqualified_configuration",
            "detail": "This profile cannot establish real inference-tool privacy.",
        },
    ]
    assert raised.value.__cause__ is None
    assert sensitive_value not in str(raised.value)
    assert sensitive_value not in json.dumps(evidence, sort_keys=True)
    assert not database_path.exists()


def test_raw_configuration_serialization_recursion_fails_before_admission_without_leak(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Simulated raw settings recursion fails redacted before admission."""
    sensitive_value = "private-serialization-recursion-value"
    serialization_probe = object()
    configuration: dict[str, object] = {
        "configuration_version": 1,
        "serialization_probe": serialization_probe,
        "credential": {"api_key": sensitive_value},
    }
    adapter = _VariantCpuAdapter(configuration=configuration)
    database_path = tmp_path / "studio.sqlite3"
    original_dumps = json.dumps
    rejected_raw_configuration = False

    def reject_raw_configuration(value, *args, **kwargs):
        nonlocal rejected_raw_configuration
        if (
            isinstance(value, dict)
            and value.get("serialization_probe") is serialization_probe
        ):
            rejected_raw_configuration = True
            raise RecursionError("simulated raw configuration serialization depth")
        return original_dumps(value, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(
            json,
            "dumps",
            reject_raw_configuration,
        )
        with pytest.raises(
            PrivacyComplianceError,
            match=(
                r"^adapter privacy configuration is unverified; "
                r"configuration-only compliance did not admit this execution$"
            ),
        ) as raised:
            GenerationService(
                database_path,
                tmp_path / "artifacts",
                adapter=adapter,
            )

    assert rejected_raw_configuration
    evidence = raised.value.result.to_dict()
    assert evidence["status"] == "unverified"
    assert evidence["reasons"] == [
        {
            "code": "configuration_not_json",
            "detail": "Configuration is not valid JSON.",
        }
    ]
    assert raised.value.__cause__ is None
    assert sensitive_value not in str(raised.value)
    assert sensitive_value not in json.dumps(evidence, sort_keys=True)
    assert "RecursionError" not in str(raised.value)
    assert not database_path.exists()


def test_generation_request_intent_cannot_be_mutated() -> None:
    """A request remains stable after it has been constructed."""
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
        reference_ids=("art_0123456789abcdef0123456789abcdef",),
        output_slot="cover",
    )

    with pytest.raises(FrozenInstanceError):
        request.prompt = "A different scene"

    assert request.reference_ids == ("art_0123456789abcdef0123456789abcdef",)


def test_generation_job_defensively_freezes_nested_configuration() -> None:
    """Nested input and returned mappings cannot mutate a persisted job snapshot."""
    source_configuration = {"nested": {"items": ["original"]}}
    source_parameters = {"nested": [{"enabled": True}]}
    job = GenerationJob(
        job_id="job_0123456789abcdef0123456789abcdef",
        request_id="req_0123456789abcdef0123456789abcdef",
        status="running",
        adapter_id="test-adapter",
        adapter_configuration=source_configuration,
        resolved_prompt="A stable prompt",
        resolved_seed=7,
        validated_reference_ids=(),
        output_slot="primary",
        output_slot_id="slot_0123456789abcdef0123456789abcdef",
        effective_parameters=source_parameters,
        created_at="2026-10-21T00:00:00+00:00",
        updated_at="2026-10-21T00:00:00+00:00",
    )

    source_configuration["nested"]["items"].append("changed")
    source_parameters["nested"][0]["enabled"] = False
    assert job.adapter_configuration["nested"]["items"] == ("original",)
    assert job.effective_parameters["nested"][0]["enabled"] is True

    with pytest.raises(TypeError):
        job.adapter_configuration["nested"]["new"] = "value"
    with pytest.raises(TypeError):
        job.effective_parameters["nested"][0]["enabled"] = False

    snapshot = job.to_dict()
    snapshot["adapter_configuration"]["nested"]["items"].append("snapshot edit")
    assert job.adapter_configuration["nested"]["items"] == ("original",)


def test_idempotent_replay_accepts_nested_adapter_configuration(
    tmp_path: Path,
) -> None:
    """Frozen nested configuration remains comparable during same-key replay."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    configuration = {"nested": {"enabled": True}}
    service = GenerationService(
        database,
        output_directory,
        adapter=_VariantCpuAdapter(configuration=configuration),
        admission_profile=_heavyweight_profile(),
    )
    request = GenerationRequest(prompt="A glass greenhouse", seed=19)

    original = service.submit(
        "nested-config-retry", request, workload_demand=_heavyweight_demand()
    )
    replay = service.submit(
        "nested-config-retry", request, workload_demand=_heavyweight_demand()
    )

    assert replay == original


def test_provenance_with_nested_adapter_configuration_is_json_serializable(
    tmp_path: Path,
) -> None:
    """Provenance exposes detached JSON values for recursively frozen config."""
    configuration = {"nested": {"enabled": True}}
    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "artifacts",
        adapter=_VariantCpuAdapter(configuration=configuration),
        admission_profile=_heavyweight_profile(),
    )
    submitted = service.submit(
        "nested-config-provenance",
        GenerationRequest(prompt="A glass greenhouse", seed=19),
        workload_demand=_heavyweight_demand(),
    )

    encoded = json.dumps(service.get_provenance(submitted.job_id))

    assert json.loads(encoded)["adapter_configuration"] == configuration


def test_retired_pending_admission_cannot_create_sidecarless_jobs(tmp_path: Path) -> None:
    """Unsupported legacy admission must fail before changing the database."""
    service = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "artifacts")
    request = GenerationRequest("retired pending", seed=9)
    with pytest.raises(RuntimeError, match="queued admission"):
        service._store.create_pending_execution(
            request=request, request_digest=request.digest(), idempotency_key="retired",
            request_id="req_" + "a" * 32, job_id="job_" + "a" * 32,
            attempt_id="att_" + "a" * 32, output_slot_id="slot_" + "a" * 32,
            resolved_seed=9, adapter_id="retired", adapter_configuration_json="{}",
            effective_parameters_json='{"width":64,"height":64}',
            resolved_output_directory=str(tmp_path / "artifacts"),
            timestamp="2026-10-25T00:00:00+00:00",
        )
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM generation_requests").fetchone() == (0,)
    GenerationService(tmp_path / "studio.sqlite3", tmp_path / "artifacts")


@pytest.mark.parametrize("evidence", ("omitted", "none"))
def test_direct_claim_without_privacy_evidence_rejects_protected_execution(
    tmp_path: Path,
    evidence: str,
) -> None:
    """Omitted or null evidence cannot claim without durable execution authority."""
    service = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "artifacts")
    queued = service.enqueue(
        "legacy-direct-claim", GenerationRequest("Legacy direct claim", seed=9)
    )
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    claim_kwargs = {
        "attempt_id": "att_fedcba9876543210fedcba9876543210",
        "owner_id": "worker_legacy",
        "adapter_id": service.adapter.adapter_id,
        "adapter_configuration_json": adapter_configuration_json,
        "resolved_output_directory": str(tmp_path / "artifacts"),
        "process_contained": True,
        "containment_contract": PROCESS_CONTAINED_CONTRACT,
        "timestamp": "2026-10-26T00:00:00+00:00",
        "lease_expires_at": "2026-10-26T00:01:00+00:00",
        "job_id": queued.job_id,
        "allow_not_required": True,
    }
    if evidence == "none":
        claim_kwargs["privacy_compliance_json"] = None

    with pytest.raises(
        GenerationError,
        match=f"^protected execution claim requires exact privacy-compliance evidence: {queued.job_id}$",
    ):
        service._store.claim_next_execution(**claim_kwargs)

    with service._store._connection() as connection:
        execution = connection.execute(
            "SELECT status, current_attempt_id FROM execution_jobs WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone()
        attempts = connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone()[0]
        resource = connection.execute(
            "SELECT state, job_id, attempt_id FROM execution_resource WHERE id = 1"
        ).fetchone()
    assert execution is not None
    assert execution["status"] == "queued"
    assert execution["current_attempt_id"] is None
    assert attempts == 0
    assert resource is not None
    assert tuple(resource) == ("available", None, None)

    claim_kwargs.pop("privacy_compliance_json", None)
    claim = service._store.claim_next_execution(
        **claim_kwargs,
        privacy_compliance_json=privacy_compliance_json,
    )
    assert claim is not None
    assert claim.job_id == queued.job_id


def test_artifact_attempt_must_belong_to_the_job_being_completed(
    tmp_path: Path,
) -> None:
    """A cross-job attempt cannot publish an artifact or transition either job."""
    service = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "artifacts")

    first = service.enqueue("first", GenerationRequest("Request first", seed=9))
    second = service.enqueue("second", GenerationRequest("Request second", seed=9))
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    first_claim = service._store.claim_next_execution(
        attempt_id="att_0123456789abcdef0123456789abcdef",
        owner_id="worker_first", adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(tmp_path / "artifacts"),
        process_contained=True, containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-21T00:00:00+00:00",
        lease_expires_at="2026-10-21T00:01:00+00:00", job_id=first.job_id,
        allow_not_required=True,
    )
    assert first_claim is not None
    artifact = GenerationArtifact(
        artifact_id="art_0123456789abcdef0123456789abcdef",
        job_id=second.job_id,
        attempt_id=first_claim.attempt_id,
        output_slot_id=second.output_slot_id,
        path=str(tmp_path / "artifacts" / "cross-job.png"),
        media_type="image/png",
        image_format="PNG",
        width=64,
        height=64,
        file_size=1,
        sha256="0" * 64,
        created_at="2026-10-21T00:00:01+00:00",
    )

    with pytest.raises(RuntimeError, match="attempt.*job"):
        service._store.complete_execution(artifact, "2026-10-21T00:00:01+00:00")

    assert service.get_provenance(first.job_id)["attempt"]["status"] == "running"
    assert service.get_provenance(second.job_id)["status"] == "queued"
    assert service.get_provenance(second.job_id)["attempt"] is None
    for job_id in (first.job_id, second.job_id):
        assert service.get_provenance(job_id)["artifact"] is None


def test_idempotent_reuse_checks_current_adapter_capabilities(tmp_path: Path) -> None:
    """A retry is rejected if the current adapter cannot handle its request."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    original_service = GenerationService(
        database,
        output_directory,
        adapter=_VariantCpuAdapter(),
        admission_profile=_heavyweight_profile(),
    )
    original = original_service.submit(
        "adapter-capability-retry", request, workload_demand=_heavyweight_demand()
    )
    limited_adapter = _VariantCpuAdapter(
        capabilities=AdapterCapabilities(
            max_width=32,
            max_height=256,
            supports_references=True,
            max_references=4,
        )
    )
    retry_service = GenerationService(
        database,
        output_directory,
        adapter=limited_adapter,
        admission_profile=_heavyweight_profile(),
    )

    with pytest.raises(UnsupportedCapabilityError, match="supports width"):
        retry_service.submit(
            "adapter-capability-retry", request, workload_demand=_heavyweight_demand()
        )

    assert original_service.get_job(original.job_id).status == "succeeded"


@pytest.mark.parametrize(
    "adapter_overrides",
    [
        {"adapter_id": "alternate-cpu-png-v1"},
        {"configuration": {"configuration_version": 2}},
    ],
    ids=("adapter-identity", "adapter-configuration"),
)
def test_idempotent_reuse_rejects_changed_adapter_configuration(
    tmp_path: Path,
    adapter_overrides: dict[str, object],
) -> None:
    """A key cannot silently reuse a job resolved with another adapter config."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    original_service = GenerationService(
        database,
        output_directory,
        adapter=_VariantCpuAdapter(),
        admission_profile=_heavyweight_profile(),
    )
    original_service.submit(
        "adapter-config-retry", request, workload_demand=_heavyweight_demand()
    )
    current_adapter = _VariantCpuAdapter(**adapter_overrides)
    retry_service = GenerationService(
        database,
        output_directory,
        adapter=current_adapter,
        admission_profile=_heavyweight_profile(),
    )

    with pytest.raises(IdempotencyConflictError, match="adapter identity or configuration"):
        retry_service.submit(
            "adapter-config-retry", request, workload_demand=_heavyweight_demand()
        )


def test_idempotent_reuse_rejects_changed_output_directory(tmp_path: Path) -> None:
    """A retry reuses its artifact only in the original resolved directory."""
    database = tmp_path / "studio.sqlite3"
    original_output_directory = tmp_path / "original-artifacts"
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    original_service = GenerationService(database, original_output_directory)
    original = original_service.submit("output-directory-retry", request)

    same_directory_retry = GenerationService(database, original_output_directory).submit(
        "output-directory-retry", request
    )
    assert same_directory_retry == original

    different_directory_retry = GenerationService(database, tmp_path / "other-artifacts")
    with pytest.raises(IdempotencyConflictError, match="output directory"):
        different_directory_retry.submit("output-directory-retry", request)


@pytest.mark.parametrize(
    ("second_adapter_overrides", "expect_conflict"),
    [
        ({}, False),
        ({"adapter_id": "alternate-cpu-png-v1"}, True),
        ({"configuration": {"configuration_version": 2}}, True),
    ],
    ids=("same-adapter", "different-identity", "different-configuration"),
)
def test_concurrent_same_key_submissions_check_persisted_adapter_configuration(
    tmp_path: Path,
    second_adapter_overrides: dict[str, object],
    expect_conflict: bool,
) -> None:
    """The transaction loser reuses only a job with the same adapter config."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    services = (
        GenerationService(
            database,
            output_directory,
            adapter=_VariantCpuAdapter(),
            admission_profile=_heavyweight_profile(),
        ),
        GenerationService(
            database,
            output_directory,
            adapter=_VariantCpuAdapter(**second_adapter_overrides),
            admission_profile=_heavyweight_profile(),
        ),
    )
    initial_lookup_barrier = Barrier(2)

    for service in services:
        find_idempotency_key = service._store.find_idempotency_key

        def find_after_both_submissions_check(key: str) -> tuple[str, str] | None:
            existing = find_idempotency_key(key)
            initial_lookup_barrier.wait(timeout=10)
            return existing

        service._store.find_idempotency_key = find_after_both_submissions_check

    def submit(service: GenerationService) -> object:
        try:
            return service.submit(
                "concurrent-adapter-retry",
                request,
                workload_demand=_heavyweight_demand(),
            )
        except IdempotencyConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(submit, service) for service in services]
        outcomes = [future.result(timeout=20) for future in futures]

    conflicts = [outcome for outcome in outcomes if isinstance(outcome, IdempotencyConflictError)]
    submissions = [outcome for outcome in outcomes if not isinstance(outcome, IdempotencyConflictError)]
    assert len(conflicts) == int(expect_conflict)
    assert len(submissions) == 2 - int(expect_conflict)
    if expect_conflict:
        assert "adapter identity or configuration" in str(conflicts[0])
    else:
        assert submissions[0].job_id == submissions[1].job_id  # type: ignore[union-attr]
        assert submissions[0].request_id == submissions[1].request_id  # type: ignore[union-attr]
        snapshot = GenerationService(database, output_directory).get_provenance(
            submissions[0].job_id  # type: ignore[union-attr]
        )
        assert len(snapshot["attempts"]) == 1
        assert snapshot["artifact"] is not None


def test_matching_submit_while_adapter_is_paused_returns_existing_running_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-key reuse reports the active job without claiming a second attempt."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    request = GenerationRequest(
        prompt="A paused glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    entered = Event()
    release = Event()

    class PausedAdapter(DeterministicCpuAdapter):
        def generate(self, plan: GenerationPlan, destination: BinaryIO):
            entered.set()
            if not release.wait(timeout=10):
                raise RuntimeError("paused adapter was not released")
            return super().generate(plan, destination)

    first_service = GenerationService(
        database,
        output_directory,
        adapter=PausedAdapter(),
        admission_profile=_heavyweight_profile(),
    )
    matching_service = GenerationService(
        database,
        output_directory,
        adapter=PausedAdapter(),
        admission_profile=_heavyweight_profile(),
    )
    monkeypatch.setattr(first_service._store, "renew_attempt", lambda *args, **kwargs: False)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            first_service.submit,
            "paused-reuse",
            request,
            workload_demand=_heavyweight_demand(),
        )
        assert entered.wait(timeout=10)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE execution_attempts "
                "SET lease_expires_at = '1970-01-01T00:00:00+00:00' "
                "WHERE status = 'running'"
            )
        try:
            matching = executor.submit(
                matching_service.submit,
                "paused-reuse",
                request,
            workload_demand=_heavyweight_demand(),
            )
            reused = matching.result(timeout=2)
            snapshot = matching_service.get_provenance(reused.job_id)

            assert reused.status == "running"
            assert reused.artifact_id is None
            assert snapshot["status"] == "running"
            assert len(snapshot["attempts"]) == 1
            assert snapshot["execution"]["resource_state"] == "claimed"
        finally:
            release.set()
        completed = first.result(timeout=10)

    final = matching_service.get_provenance(completed.job_id)
    assert completed.status == "succeeded"
    assert completed.job_id == reused.job_id
    assert len(final["attempts"]) == 1
    assert final["artifact"] is not None


def test_failed_job_replay_binds_resolved_output_directory(tmp_path: Path) -> None:
    """A failed job reuses only when retried with its original destination."""
    database = tmp_path / "studio.sqlite3"
    original_output_directory = tmp_path / "original-artifacts"
    request = GenerationRequest(
        prompt="A glass greenhouse",
        seed=19,
        width=48,
        height=48,
    )
    adapter = _FailAfterWritingAdapter()
    original_service = GenerationService(
        database,
        original_output_directory,
        adapter=adapter,
        admission_profile=_heavyweight_profile(),
    )
    adapter.service = original_service

    with pytest.raises(GenerationExecutionError) as failure:
        original_service.submit(
            "failed-output-directory-retry", request, workload_demand=_heavyweight_demand()
        )
    original_job = original_service.get_job(failure.value.job_id)

    same_directory_retry = original_service.submit(
        "failed-output-directory-retry",
        request,
        workload_demand=_heavyweight_demand(),
    )
    assert same_directory_retry.job_id == original_job.job_id
    assert same_directory_retry.status == "failed"

    different_directory_service = GenerationService(
        database,
        tmp_path / "other-artifacts",
        adapter=_FailAfterWritingAdapter(),
        admission_profile=_heavyweight_profile(),
    )
    with pytest.raises(IdempotencyConflictError, match="output directory"):
        different_directory_service.submit(
            "failed-output-directory-retry", request, workload_demand=_heavyweight_demand()
        )


class _FailAfterWritingAdapter:

    containment_contract = PROCESS_CONTAINED_CONTRACT
    """Leave a partial file to verify service cleanup and durable failure state."""

    adapter_id = "test-failure-adapter"
    configuration = {"version": 1}
    capabilities = AdapterCapabilities(
        max_width=256,
        max_height=256,
        supports_references=True,
        max_references=4,
    )

    def __init__(self) -> None:
        self.service: GenerationService | None = None
        self.persisted_job = None
        self.persisted_request = None
        self.persisted_attempt = None
        self.persisted_output_directory: str | None = None

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> object:
        assert self.service is not None
        self.persisted_job = self.service.get_job(plan.job_id)
        self.persisted_output_directory = self.service._store.get_resolved_output_directory(
            plan.job_id
        )
        self.persisted_request = self.service.get_request(self.persisted_job.request_id)
        self.persisted_attempt = self.service.get_provenance(plan.job_id)["attempt"]
        destination.write(b"partial image that must not become an artifact")
        raise RuntimeError("controlled adapter failure")


class _TrackingCpuAdapter(DeterministicCpuAdapter):
    """Count adapter calls while retaining deterministic CPU behavior."""

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> object:
        self.calls += 1
        return super().generate(plan, destination)


class _FalseyTrackingCpuAdapter(_TrackingCpuAdapter):
    """Expose false truthiness while retaining valid CPU adapter behavior."""

    adapter_id = "falsey-tracking-cpu-v1"

    @property
    def configuration(self) -> dict[str, object]:
        """Return configuration that distinguishes this adapter from the default."""
        return {"configuration_version": 1, "profile": "falsey-tracking"}

    def __bool__(self) -> bool:
        return False


def test_falsey_adapter_is_selected_and_used(tmp_path: Path) -> None:
    """Adapter selection distinguishes a supplied falsey adapter from omission."""
    adapter = _FalseyTrackingCpuAdapter()
    service = GenerationService(
        database_path=tmp_path / "studio.sqlite3",
        output_directory=tmp_path / "artifacts",
        adapter=adapter,
        admission_profile=_heavyweight_profile(),
    )

    assert service.adapter is adapter
    assert service.adapter.adapter_id == "falsey-tracking-cpu-v1"
    assert service.adapter.configuration == {
        "configuration_version": 1,
        "profile": "falsey-tracking",
    }

    submission = service.submit(
        idempotency_key="falsey-adapter",
        request=GenerationRequest(
            prompt="A falsey tracking adapter",
            seed=19,
            width=48,
            height=48,
            output_slot="cover",
        ),
        workload_demand=_heavyweight_demand(),
    )
    job = service.get_job(submission.job_id)

    assert adapter.calls == 1
    assert job.adapter_id == "falsey-tracking-cpu-v1"
    assert job.adapter_configuration == {
        "configuration_version": 1,
        "profile": "falsey-tracking",
    }


def test_omitted_adapter_uses_deterministic_cpu_default(tmp_path: Path) -> None:
    """Omitting the adapter selects the deterministic CPU implementation."""
    service = GenerationService(
        database_path=tmp_path / "studio.sqlite3",
        output_directory=tmp_path / "artifacts",
    )

    assert type(service.adapter) is DeterministicCpuAdapter


def test_adapter_failure_leaves_inspectable_attempt_and_no_artifact(
    tmp_path: Path,
) -> None:
    """Resolved execution state is durable before invocation and failure is visible."""
    adapter = _FailAfterWritingAdapter()
    service = GenerationService(
        database_path=tmp_path / "studio.sqlite3",
        output_directory=tmp_path / "artifacts",
        adapter=adapter,
        admission_profile=_heavyweight_profile(),
    )
    adapter.service = service

    with pytest.raises(GenerationExecutionError) as failure:
        service.submit(
            idempotency_key="adapter-failure",
            request=GenerationRequest(
                prompt="A glass greenhouse",
                seed=19,
                width=48,
                height=48,
                output_slot="cover",
            ),
        workload_demand=_heavyweight_demand(),
        )

    job = service.get_job(failure.value.job_id)
    provenance = service.get_provenance(job.job_id)

    assert adapter.persisted_job is not None
    assert adapter.persisted_output_directory == str(service.output_directory)
    assert adapter.persisted_job.status == "running"
    assert adapter.persisted_job.adapter_id == "test-failure-adapter"
    assert adapter.persisted_job.adapter_configuration == {"version": 1}
    assert adapter.persisted_job.resolved_prompt == "A glass greenhouse"
    assert adapter.persisted_job.resolved_seed == 19
    assert adapter.persisted_job.output_slot == "cover"
    assert adapter.persisted_job.output_slot_id.startswith("slot_")
    assert adapter.persisted_job.effective_parameters == {
        "width": 48,
        "height": 48,
    }
    assert adapter.persisted_request["prompt"] == "A glass greenhouse"
    assert adapter.persisted_attempt["status"] == "running"
    assert job.status == "failed"
    assert provenance["attempt"]["status"] == "failed"
    assert provenance["artifact"] is None
    # The permanent storage mutex survives cleanup so another process cannot
    # lock a different inode while reconciliation is active.
    assert {path.name for path in (tmp_path / "artifacts").iterdir()} == {
        ".artifact-publication.lock", ".artifact-cleanup"
    }


def test_output_directory_file_does_not_mask_durable_execution_failure(
    tmp_path: Path,
) -> None:
    """Cleanup failure leaves the job and attempt durably marked as failed."""
    output_file = tmp_path / "not-a-directory"
    output_file.write_text("preserve this file", encoding="utf-8")
    service = GenerationService(tmp_path / "studio.sqlite3", output_file)

    with pytest.raises(GenerationExecutionError) as failure:
        service.submit(
            "output-directory-is-file",
            GenerationRequest(prompt="A quiet harbor", seed=11),
        )

    job = service.get_job(failure.value.job_id)
    provenance = service.get_provenance(job.job_id)
    assert job.status == "failed"
    assert provenance["attempt"]["status"] == "failed"
    assert provenance["artifact"] is None
    assert output_file.read_text(encoding="utf-8") == "preserve this file"


@pytest.mark.parametrize("corruption", ["deleted", "tampered"])
def test_corrupt_reference_is_rejected_before_adapter_execution(
    tmp_path: Path, corruption: str
) -> None:
    """Missing or changed reference bytes cannot be consumed as the saved artifact."""
    database = tmp_path / "studio.sqlite3"
    source_service = GenerationService(database, tmp_path / "source-artifacts")
    source = source_service.submit(
        "reference-source",
        GenerationRequest(prompt="An original source image", seed=13, width=32, height=32),
    )
    source_artifact = source_service.get_artifact(source.artifact_id or "")
    reference_path = Path(source_artifact.path)
    if corruption == "deleted":
        reference_path.unlink()
    else:
        reference_path.write_bytes(b"different bytes than the saved SHA-256")

    adapter = _TrackingCpuAdapter()
    consumer_service = GenerationService(
        database,
        tmp_path / "consumer-artifacts",
        adapter=adapter,
        admission_profile=_heavyweight_profile(),
    )
    with pytest.raises(GenerationExecutionError) as failure:
        consumer_service.submit(
            f"reference-{corruption}",
            GenerationRequest(
                prompt="Use this reference",
                seed=14,
                width=32,
                height=32,
                reference_ids=(source_artifact.artifact_id,),
            ),
        workload_demand=_heavyweight_demand(),
        )

    job = consumer_service.get_job(failure.value.job_id)
    provenance = consumer_service.get_provenance(job.job_id)
    assert adapter.calls == 0
    assert job.status == "failed"
    assert provenance["attempt"]["status"] == "failed"
    assert provenance["artifact"] is None
    assert "reference artifact" in str(failure.value).lower()
