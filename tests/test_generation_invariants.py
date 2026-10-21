"""Focused tests for immutable intent and failed adapter execution state."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier

import pytest

from media_generation.adapters import AdapterCapabilities, DeterministicCpuAdapter
from media_generation.domain import GenerationPlan, GenerationRequest
from media_generation.errors import IdempotencyConflictError, UnsupportedCapabilityError
from media_generation.service import GenerationExecutionError, GenerationService


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
    )
    original = original_service.submit("adapter-capability-retry", request)
    limited_adapter = _VariantCpuAdapter(
        capabilities=AdapterCapabilities(
            max_width=32,
            max_height=256,
            supports_references=True,
            max_references=4,
        )
    )
    retry_service = GenerationService(database, output_directory, adapter=limited_adapter)

    with pytest.raises(UnsupportedCapabilityError, match="supports width"):
        retry_service.submit("adapter-capability-retry", request)

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
    )
    original_service.submit("adapter-config-retry", request)
    current_adapter = _VariantCpuAdapter(**adapter_overrides)
    retry_service = GenerationService(database, output_directory, adapter=current_adapter)

    with pytest.raises(IdempotencyConflictError, match="adapter identity or configuration"):
        retry_service.submit("adapter-config-retry", request)


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
        GenerationService(database, output_directory, adapter=_VariantCpuAdapter()),
        GenerationService(
            database,
            output_directory,
            adapter=_VariantCpuAdapter(**second_adapter_overrides),
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
            return service.submit("concurrent-adapter-retry", request)
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
    )
    adapter.service = original_service

    with pytest.raises(GenerationExecutionError) as failure:
        original_service.submit("failed-output-directory-retry", request)
    original_job = original_service.get_job(failure.value.job_id)

    same_directory_retry = original_service.submit(
        "failed-output-directory-retry", request
    )
    assert same_directory_retry.job_id == original_job.job_id
    assert same_directory_retry.status == "failed"

    different_directory_service = GenerationService(
        database,
        tmp_path / "other-artifacts",
        adapter=_FailAfterWritingAdapter(),
    )
    with pytest.raises(IdempotencyConflictError, match="output directory"):
        different_directory_service.submit("failed-output-directory-retry", request)


class _FailAfterWritingAdapter:
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

    def generate(self, plan: GenerationPlan, destination: Path) -> object:
        assert self.service is not None
        self.persisted_job = self.service.get_job(plan.job_id)
        self.persisted_output_directory = self.service._store.get_resolved_output_directory(
            plan.job_id
        )
        self.persisted_request = self.service.get_request(self.persisted_job.request_id)
        self.persisted_attempt = self.service.get_provenance(plan.job_id)["attempt"]
        destination.write_bytes(b"partial image that must not become an artifact")
        raise RuntimeError("controlled adapter failure")


def test_adapter_failure_leaves_inspectable_attempt_and_no_artifact(
    tmp_path: Path,
) -> None:
    """Resolved execution state is durable before invocation and failure is visible."""
    adapter = _FailAfterWritingAdapter()
    service = GenerationService(
        database_path=tmp_path / "studio.sqlite3",
        output_directory=tmp_path / "artifacts",
        adapter=adapter,
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
    assert list((tmp_path / "artifacts").iterdir()) == []
