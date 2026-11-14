"""Synchronous application service for durable local image generation."""

from __future__ import annotations

import hashlib
import json
import os
import fcntl
import threading
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from .adapters import (
    DeterministicCpuAdapter,
    GenerationAdapter,
    backend_execution_contract,
    trusted_containment_contract,
)
from .admission import (
    AdmissionProfile,
    WorkloadDemand,
    evaluate_admission,
    is_lightweight_cpu_adapter,
)
from .admission_store import AdmissionInspection, PendingAdmission
from .domain import (
    GenerationArtifact,
    ImportedArtifact,
    ArtifactSource,
    GenerationJob,
    GenerationPlan,
    GenerationRequest,
    ResolvedReference,
)
from .engine import StableDiffusionCppAdapter
from .errors import (
    AmbiguousBackendOutcome,
    BackendEvidenceError,
    BackendPreparationError,
    GenerationExecutionError,
    GenerationError,
    ArtifactIntegrityError,
    IdempotencyConflictError,
    InputValidationError,
    PublicationIncompleteError,
    PrivacyComplianceError,
    RecordNotFoundError,
    ResourceBusyError,
    RetryableGenerationError,
    UnsupportedCapabilityError,
)
from .privacy import (
    DEFAULT_PRIVACY_POLICY,
    PrivacyComplianceResult,
    PrivacyCompliancePolicy,
    PrivacyComplianceStatus,
    application_privacy_profile,
    application_privacy_policy,
    application_privacy_registration,
    comfyui_invocation_privacy_settings,
    comfyui_resolved_privacy_evidence,
    invocation_privacy_settings,
)
from .backend_provenance import (
    COMFYUI_RESOLVED_BACKEND_KIND,
    COMFYUI_RESOLVED_CLI_CONTRACT,
    COMFYUI_RESOLVED_INVOCATION_CONTRACT,
    COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS,
    RECORD_SCHEMA_VERSION,
    RESOLVED_RECORD_SCHEMA_VERSION,
    environment_record,
)
from .store import ExecutionClaim, QueuedExecution, SQLiteStore
from .supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)
from .images import ImageInfo, open_approved_source, copy_source
from .publication import PublicationManager, Checkpoint
from .systemd_attempts import (
    SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
    SystemdAttemptCompletion,
    SystemdAttemptRunner,
)


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """Stable identities and current state returned from a submit operation."""

    request_id: str
    job_id: str
    status: str
    output_slot_id: str
    artifact_id: str | None
    resource_state: str = "available"
    resource_reason: str | None = None

    @property
    def attention_required(self) -> bool:
        """Whether successful publication left heavyweight capacity quarantined."""
        return self.resource_state == "quarantined"

    def to_dict(self) -> dict[str, object]:
        """Return a CLI-ready result without exposing storage implementation details."""
        return {
            "request_id": self.request_id,
            "job_id": self.job_id,
            "status": self.status,
            "output_slot_id": self.output_slot_id,
            "artifact_id": self.artifact_id,
            "resource_state": self.resource_state,
            "resource_reason": self.resource_reason,
        }


# Strict JSON validation must finish before privacy evaluation inspects caller
# data. This non-serializable marker lets the policy return its canonical,
# redacted configuration_not_json evidence without traversing a cyclic adapter
# configuration.
_NON_JSON_PRIVACY_CONFIGURATION: dict[str, object] = {"marker": object()}

_RESOLVED_EXECUTION_MISMATCH = "resolved_execution_mismatch"
_EXECUTABLE_HASH_CHUNK_BYTES = 1024 * 1024


def _resolved_execution_mismatch(detail: str) -> BackendPreparationError:
    """Return one fail-closed refusal for a substituted resolution."""
    return BackendPreparationError(_RESOLVED_EXECUTION_MISMATCH, detail)


def _require_selected_value(
    observed: object, selected: object, *, label: str
) -> None:
    """Require one resolved value to equal the admission selection."""
    if observed != selected:
        raise _resolved_execution_mismatch(
            f"resolved execution {label} does not match the selected candidate"
        )


def _require_selected_field(
    record: Mapping[str, object],
    selected: Mapping[str, object],
    name: str,
    *,
    label: str | None = None,
) -> None:
    """Compare one scalar field whose name is shared by both mappings."""
    _require_selected_value(
        record.get(name), selected.get(name), label=label or name
    )


def _sha256_regular_file(path: str) -> str:
    """Hash one executable the supervisor will start, in bounded chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(_EXECUTABLE_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _selected_components(
    configuration: Mapping[str, object], reference_roles: tuple[str, ...]
) -> list[dict[str, object]]:
    """Return the component rows the selected operation requires, in order."""
    operations = configuration.get("operations")
    if not isinstance(operations, Mapping):
        raise _resolved_execution_mismatch(
            "selected candidate has no operation contract"
        )
    operation_name = "edit" if "source" in reference_roles else "generate"
    operation = operations.get(operation_name)
    if not isinstance(operation, Mapping):
        raise _resolved_execution_mismatch(
            f"selected candidate does not declare the {operation_name} operation"
        )
    required_roles = operation.get("required_roles")
    if not isinstance(required_roles, list) or not all(
        isinstance(role, str) for role in required_roles
    ):
        raise _resolved_execution_mismatch(
            "selected candidate has an invalid required-role contract"
        )
    declared = configuration.get("components")
    if not isinstance(declared, list):
        raise _resolved_execution_mismatch("selected candidate has no components")
    by_role: dict[str, dict[str, object]] = {}
    for component in declared:
        if not isinstance(component, Mapping):
            raise _resolved_execution_mismatch(
                "selected candidate has an invalid component"
            )
        role = component.get("role")
        if not isinstance(role, str) or role in by_role:
            raise _resolved_execution_mismatch(
                "selected candidate has an ambiguous component role"
            )
        by_role[role] = dict(component)
    selected: list[dict[str, object]] = []
    for role in required_roles:
        component = by_role.get(role)
        if component is None:
            raise _resolved_execution_mismatch(
                f"selected candidate is missing required component role {role!r}"
            )
        selected.append(component)
    return selected


def _record_reference_roles(record: Mapping[str, object]) -> tuple[str, ...]:
    """Return the conditioning roles the resolved record describes."""
    conditioning = record.get("conditioning")
    if not isinstance(conditioning, list):
        raise _resolved_execution_mismatch(
            "resolved execution conditioning is missing"
        )
    roles: list[str] = []
    for entry in conditioning:
        if not isinstance(entry, Mapping):
            raise _resolved_execution_mismatch(
                "resolved execution conditioning is invalid"
            )
        role = entry.get("role")
        if not isinstance(role, str):
            raise _resolved_execution_mismatch(
                "resolved execution conditioning role is invalid"
            )
        roles.append(role)
    return tuple(roles)


class _StoreExecutionAuthority(ExecutionEvidenceAuthority):
    """Persist application-supervised facts for one claimed attempt."""

    def __init__(self, store: SQLiteStore, claim: ExecutionClaim) -> None:
        self._store = store
        self._claim = claim

    @property
    def attempt_id(self) -> str:
        return self._claim.attempt_id

    def verify_current(self) -> bool:
        """Return whether the bound claim still has execution authority."""
        return self._store.assert_attempt_authority(
            self._claim.job_id,
            self._claim.attempt_id,
            self._claim.owner_id,
            self._claim.claim_epoch,
        )

    def record_launch(self, fact: LaunchFact) -> None:
        """Record the launch fact only after a successful spawn."""
        if not isinstance(fact, LaunchFact):
            raise TypeError("launch fact must be a LaunchFact")
        self._store.mark_execution_launched(
            job_id=self._claim.job_id,
            attempt_id=self._claim.attempt_id,
            owner_id=self._claim.owner_id,
            claim_epoch=self._claim.claim_epoch,
            record=fact.to_mapping(),
            timestamp=_now(),
        )

    def record_observation(self, fact: ProcessObservation) -> None:
        """Record reaped direct-child facts for the current attempt."""
        if not isinstance(fact, ProcessObservation):
            raise TypeError("observation fact must be a ProcessObservation")
        self._store.mark_execution_observed(
            job_id=self._claim.job_id,
            attempt_id=self._claim.attempt_id,
            owner_id=self._claim.owner_id,
            claim_epoch=self._claim.claim_epoch,
            record=fact.to_mapping(),
            timestamp=_now(),
        )


class GenerationService:
    """Validate, persist, execute, and expose one local generation request.

    The service captures adapter configuration, evaluates it against an
    application-owned privacy profile, and persists redacted evidence with the
    queued job. Execution is synchronous in the submitting process; SQLite and
    artifact files remain available to later CLI processes.
    """

    def __init__(
        self,
        database_path: Path,
        output_directory: Path,
        adapter: GenerationAdapter | None = None,
        *,
        publication_checkpoint: Checkpoint | None = None,
        lease_seconds: float = 30.0,
        heartbeat_seconds: float = 5.0,
        privacy_policy: PrivacyCompliancePolicy | None = None,
        require_privacy_pass: bool = False,
        admission_profile: AdmissionProfile | None = None,
        attempt_runner: SystemdAttemptRunner | None = None,
    ) -> None:
        if lease_seconds <= 0 or heartbeat_seconds <= 0 or heartbeat_seconds >= lease_seconds:
            raise ValueError("heartbeat interval must be positive and shorter than the lease")
        self.adapter: GenerationAdapter = (
            adapter if adapter is not None else DeterministicCpuAdapter()
        )
        if attempt_runner is not None and not isinstance(
            attempt_runner, SystemdAttemptRunner
        ):
            raise ValueError("attempt_runner must be a SystemdAttemptRunner")
        if attempt_runner is not None and adapter is not None and not isinstance(
            self.adapter, StableDiffusionCppAdapter
        ):
            raise ValueError(
                "systemd attempt runner requires a StableDiffusionCppAdapter"
            )
        if (
            attempt_runner is not None
            and adapter is not None
            and backend_execution_contract(self.adapter) is None
        ):
            raise ValueError(
                "systemd attempt runner requires a backend execution adapter"
            )
        self._attempt_runner = attempt_runner
        self._containment_contract = (
            SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            if attempt_runner is not None
            else trusted_containment_contract(self.adapter)
        )
        self._backend_execution_contract = backend_execution_contract(self.adapter)
        if self._backend_execution_contract is not None and (
            not callable(getattr(self.adapter, "resolve_execution", None))
            or not callable(getattr(self.adapter, "execute", None))
        ):
            raise ValueError(
                "backend execution adapter must declare resolve_execution and execute"
            )
        if not isinstance(require_privacy_pass, bool):
            raise ValueError("require_privacy_pass must be a boolean")
        if privacy_policy is not None and not isinstance(
            privacy_policy, PrivacyCompliancePolicy
        ):
            raise ValueError("privacy_policy must be a PrivacyCompliancePolicy")
        if admission_profile is not None and not isinstance(
            admission_profile, AdmissionProfile
        ):
            raise ValueError("admission_profile must be an AdmissionProfile")
        self._admission_profile = admission_profile
        if self._backend_execution_contract is not None:
            if privacy_policy is not None:
                raise ValueError(
                    "an explicit privacy policy cannot replace the "
                    "application-owned policy for a backend execution adapter"
                )
            self._privacy_policy = application_privacy_policy(self.adapter)
            self._require_privacy_pass = True
        else:
            self._privacy_policy = privacy_policy or DEFAULT_PRIVACY_POLICY
            self._require_privacy_pass = require_privacy_pass
        self._current_privacy_snapshot()
        self._store = SQLiteStore(database_path)
        self.output_directory = output_directory.expanduser().resolve()
        self._lease = timedelta(seconds=lease_seconds)
        self._heartbeat_seconds = heartbeat_seconds
        self._publication = PublicationManager(self._store, self.output_directory, publication_checkpoint)

    @property
    def database_path(self) -> Path:
        """Return the resolved SQLite database used by this service."""
        return self._store.database_path

    @property
    def admission_profile(self) -> AdmissionProfile | None:
        """Return the validated capacity profile selected for new jobs."""
        return self._admission_profile

    @property
    def execution_identity(self) -> dict[str, object]:
        """Return the exact current adapter, privacy, and output-root identity."""
        configuration, configuration_json, _, privacy_json = (
            self._current_privacy_snapshot()
        )
        return {
            "adapter_id": self.adapter.adapter_id,
            "adapter_configuration": configuration,
            "adapter_configuration_json": configuration_json,
            "privacy_compliance": json.loads(privacy_json),
            "output_directory": str(self.output_directory),
        }

    def enqueue(
        self,
        idempotency_key: str,
        request: GenerationRequest,
        *,
        max_attempts: int | None = None,
        workload_demand: WorkloadDemand | None = None,
    ) -> SubmissionResult:
        """Admit new work or reuse the existing persisted execution policy.

        ``None`` means the caller did not request a policy. New jobs default to
        one total attempt; reused jobs retain their original persisted budget.
        An explicitly supplied positive budget must match unfinished work.
        Succeeded reuse ignores it without changing the persisted policy.
        """
        queued = self._admit(
            idempotency_key,
            request,
            max_attempts=max_attempts,
            workload_demand=workload_demand,
        )
        return self._submission_for_job(queued.job_id)

    def _current_privacy_snapshot(
        self,
    ) -> tuple[dict[str, object], str, PrivacyComplianceResult, str]:
        """Evaluate current adapter settings and reject an inadmissible state.

        Configuration values that cannot be represented as strict JSON are
        rejected with redacted privacy evidence before admission is persisted.
        """
        raw_adapter_configuration = self.adapter.configuration
        try:
            adapter_configuration_json = _canonical_json(raw_adapter_configuration)
            adapter_configuration = json.loads(adapter_configuration_json)
        except (TypeError, ValueError, RecursionError):
            privacy_compliance = self._privacy_policy.evaluate(
                self.adapter.adapter_id,
                _NON_JSON_PRIVACY_CONFIGURATION,
            )
            raise PrivacyComplianceError(privacy_compliance) from None
        if not isinstance(adapter_configuration, dict):
            privacy_compliance = self._privacy_policy.evaluate(
                self.adapter.adapter_id,
                raw_adapter_configuration,
            )
            raise PrivacyComplianceError(privacy_compliance) from None
        if self._backend_execution_contract is not None:
            application_privacy_profile(
                self.adapter.adapter_id, adapter_configuration
            )
        privacy_compliance = self._privacy_policy.evaluate(
            self.adapter.adapter_id,
            adapter_configuration,
        )
        if (
            privacy_compliance.status is PrivacyComplianceStatus.FAIL
            or (
                (
                    self._require_privacy_pass
                    or privacy_compliance.supports_configuration_compliance
                )
                and privacy_compliance.status is not PrivacyComplianceStatus.PASS
            )
        ):
            raise PrivacyComplianceError(privacy_compliance)
        return (
            adapter_configuration,
            adapter_configuration_json,
            privacy_compliance,
            _canonical_json(privacy_compliance.to_dict()),
        )

    def _admit(
        self,
        idempotency_key: str,
        request: GenerationRequest,
        *,
        max_attempts: int | None,
        workload_demand: WorkloadDemand | None = None,
    ) -> QueuedExecution:
        """Atomically admit or reuse one request and report whether it is new."""
        _, adapter_configuration_json, _, privacy_compliance_json = (
            self._current_privacy_snapshot()
        )
        requested_max_attempts = max_attempts
        if max_attempts is None:
            max_attempts = 1
        if max_attempts is not None and (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
            or max_attempts < 1
        ):
            raise InputValidationError("max_attempts must be a positive integer")
        key = _validate_idempotency_key(idempotency_key)
        self._validate_capabilities(request)
        request_digest = request.digest()
        resolved_seed = request.seed
        if resolved_seed is None:
            resolved_seed = int(request_digest[:8], 16)
        if workload_demand is not None and not isinstance(
            workload_demand, WorkloadDemand
        ):
            raise InputValidationError("workload_demand must be a WorkloadDemand")
        admission_missing = (
            self._admission_profile is None or workload_demand is None
        )
        if admission_missing and not is_lightweight_cpu_adapter(self.adapter):
            raise InputValidationError(
                "heavyweight execution requires explicit profile and demand evidence"
            )
        if admission_missing and (
            self._admission_profile is not None or workload_demand is not None
        ):
            raise InputValidationError(
                "admission profile and workload demand must be supplied together"
            )
        decision = evaluate_admission(
            self._admission_profile,
            workload_demand,
            allow_not_required=is_lightweight_cpu_adapter(self.adapter),
        )
        pending_admission = PendingAdmission(
            profile=self._admission_profile,
            demand=workload_demand,
            decision=decision.status,
            reason=decision.reason,
            required_bytes=dict(decision.required_bytes),
            unknown_reasons=decision.unknown_reasons,
        )
        queued = self._store.create_queued_execution(
            request=request,
            request_digest=request_digest,
            idempotency_key=key,
            request_id=_new_id("req"),
            job_id=_new_id("job"),
            output_slot_id=_new_id("slot"),
            resolved_seed=resolved_seed,
            adapter_id=self.adapter.adapter_id,
            adapter_configuration_json=adapter_configuration_json,
            privacy_compliance_json=privacy_compliance_json,
            effective_parameters_json=_canonical_json(
                {"width": request.width, "height": request.height}
            ),
            resolved_output_directory=str(self.output_directory),
            max_attempts=requested_max_attempts,
            containment_contract=self._containment_contract,
            timestamp=_now(),
            admission=pending_admission,
            allow_not_required=is_lightweight_cpu_adapter(self.adapter),
        )
        return queued

    def submit(
        self,
        idempotency_key: str,
        request: GenerationRequest,
        *,
        workload_demand: WorkloadDemand | None = None,
    ) -> SubmissionResult:
        """Admit work, then synchronously execute one matching local attempt.

        Existing successful jobs remain directly inspectable and reusable. An
        occupied or quarantined heavyweight resource returns a specific error
        while leaving the newly admitted job queued for a later worker or
        submit call. A blocked or denied capacity decision returns the queued
        submission without creating an attempt; inspect it with
        ``inspect_admission``.
        A process-contained retryable failure remains durably queued for its
        next bounded attempt and raises ``GenerationExecutionError`` with the
        ``execution_retryable`` safe message.
        Safe CLI messages remain generic for ambiguous, retryable, and canceled
        executions. With a capacity profile, terminal failures use
        ``execution_failed``. The exact lightweight deterministic CPU path may
        retain a local diagnostic only when the adapter supplies a trusted
        containment contract. Incomplete publications also retain their
        diagnostic and recovery context.
        """
        self._require_systemd_execution_adapter()
        queued = self._admit(
            idempotency_key,
            request,
            max_attempts=None,
            workload_demand=workload_demand,
        )
        admitted = self._submission_for_job(queued.job_id)
        if admitted.status in {"succeeded", "running"}:
            return admitted
        if not queued.created and admitted.status in {"failed", "ambiguous", "canceled"}:
            return admitted
        failures: list[Exception] = []
        report = self._run_jobs(
            limit=1, job_id=admitted.job_id, _failures=failures
        )
        if report["status"] == "resource_busy" or (
            report["status"] == "attention_required"
            and report.get("processed") == 0
        ):
            if not self._observe_same_job_resource(admitted.job_id):
                raise ResourceBusyError(admitted.job_id)
            return self._submission_for_job(admitted.job_id)
        submission = self._submission_for_job(admitted.job_id)
        if submission.status == "succeeded":
            return submission
        inspection = self.inspect_admission(admitted.job_id)
        admission = None if inspection is None else inspection.admission
        if admission is not None and admission.decision in {"blocked", "denied"}:
            return admitted
        cause = failures[-1] if failures else None
        job = self._store.get_job(admitted.job_id)
        message = str(cause) if cause is not None else (
            job.failure_message or f"job is {submission.status}"
        )
        admission_enabled = admission is not None and bool(admission.profile)
        if job.execution_status == "queued":
            error_type = GenerationExecutionError
            safe_message = "execution_retryable"
            if admission_enabled:
                message = job.failure_message or "execution_retryable"
        elif job.execution_status == "ambiguous":
            error_type = GenerationExecutionError
            safe_message = "execution_ambiguous"
        elif job.execution_status == "canceled":
            error_type = GenerationExecutionError
            safe_message = "execution_canceled"
        elif submission.status in {"queued", "running"}:
            error_type = PublicationIncompleteError
            safe_message = message
        else:
            error_type = GenerationExecutionError
            safe_message = (
                message
                if not admission_enabled
                and self._containment_contract is not None
                else "execution_failed"
            )
        error = error_type(
            admitted.job_id,
            message,
            safe_message=safe_message,
        )
        if cause is not None:
            raise error from cause
        raise error

    def _observe_same_job_resource(self, job_id: str) -> bool:
        """Distinguish same-job reuse from another job's resource ownership.

        A concurrent synchronous submission can lose the filesystem lock after
        atomically reusing the first caller's queued job. The lock winner can
        claim that job a moment later, so observe only that bounded handoff. A
        resource already owned by this job is returned immediately; expiry and
        recovery never transfer ownership from an unknown external execution.
        """
        deadline = datetime.now(timezone.utc) + timedelta(seconds=1)
        while True:
            snapshot = self._store.get_provenance(job_id)
            if snapshot["status"] in {"succeeded", "failed", "ambiguous", "canceled"}:
                return True
            resource = self._store.resource_snapshot()
            owner = resource.get("job_id")
            if owner == job_id:
                return True
            if owner is not None or resource["state"] != "available":
                return False
            if datetime.now(timezone.utc) >= deadline:
                return False
            threading.Event().wait(0.01)

    def work(self, *, limit: int = 1) -> dict[str, object]:
        """Run one or more FIFO-compatible jobs in this local worker process."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise InputValidationError("worker limit must be a positive integer")
        return self._run_jobs(limit=limit, job_id=None)

    def cancel(self, job_id: str) -> dict[str, object]:
        """Fence publication, then ask the broker to stop the exact attempt."""
        outcome = self._store.cancel_execution(job_id, _now())
        if outcome == "requested" and self._attempt_runner is not None:
            attempt = self._store.current_attempt(job_id)
            claim_epoch = None if attempt is None else attempt.get("claim_epoch")
            if (
                attempt is not None
                and isinstance(attempt.get("owner_id"), str)
                and isinstance(attempt.get("attempt_id"), str)
                and type(claim_epoch) is int
                and claim_epoch > 0
            ):
                try:
                    outcome = self._attempt_runner.cancel_attempt(
                        job_id=job_id,
                        attempt_id=attempt["attempt_id"],
                        owner_id=attempt["owner_id"],
                        claim_epoch=claim_epoch,
                    )
                except (OSError, RuntimeError):
                    # The durable fence remains in force. Recovery retries
                    # the exact stop and quarantines capacity without proof.
                    outcome = "requested"
        return {"job_id": job_id, "outcome": outcome}

    def retry(self, job_id: str) -> SubmissionResult:
        """Acknowledge or requeue only a bounded, already-authorized retry."""
        if not self._store.retry_execution(job_id, _now()):
            raise GenerationError("job is not eligible for retry")
        return self._submission_for_job(job_id)

    def recover(self) -> dict[str, object]:
        """Reconcile a crashed journal or classify an interrupted invocation."""
        with self._resource_lock() as locked:
            if not locked:
                return {"status": "resource_busy"}
            resource = self._store.resource_snapshot()
            state = str(resource["state"])
            if state == "quarantined":
                job_id = resource.get("job_id")
                attempt_id = resource.get("attempt_id")
                if isinstance(job_id, str) and isinstance(attempt_id, str):
                    return self._recover_quarantined_attempt(job_id, attempt_id)
                return self._resource_result("attention_required")
            if state == "available":
                report = self._publication.reconcile()
                result = self._resource_result(
                    "attention_required"
                    if report.get("status") == "attention_required"
                    else "complete"
                )
                result["publications"] = report
                # Cleanup rows only enter the queue after their exact attempt
                # outcome is durable. An unrelated orphan must not starve it.
                result["scratch_cleanups"] = (
                    self._retry_pending_systemd_output_cleanups(limit=16)
                )
                return result
            job_id = resource.get("job_id")
            attempt_id = resource.get("attempt_id")
            if not isinstance(job_id, str) or not isinstance(attempt_id, str):
                return self._resource_result("attention_required")
            return self._recover_attempt(job_id, attempt_id)

    def _recover_quarantined_attempt(
        self, job_id: str, attempt_id: str
    ) -> dict[str, object]:
        """Release a quarantined systemd attempt only after late proof and reconciliation."""
        attempt = self._store.current_attempt(job_id)
        if attempt is None or attempt["attempt_id"] != attempt_id:
            return self._resource_result("attention_required")
        if attempt.get("containment_contract") != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT:
            return self._resource_result("attention_required")
        if not self._store.attempt_termination_proven(job_id, attempt_id):
            claim_epoch = attempt.get("claim_epoch")
            if (
                self._attempt_runner is None
                or not isinstance(attempt.get("owner_id"), str)
                or not isinstance(attempt.get("attempt_id"), str)
                or type(claim_epoch) is not int
                or claim_epoch < 1
            ):
                return self._resource_result("attention_required")
            try:
                self._attempt_runner.cancel_attempt(
                    job_id=job_id,
                    attempt_id=attempt_id,
                    owner_id=attempt["owner_id"],
                    claim_epoch=claim_epoch,
                )
            except (OSError, RuntimeError, ValueError):
                return self._resource_result("attention_required")
            if not self._store.attempt_termination_proven(job_id, attempt_id):
                return self._resource_result("attention_required")
        records = [
            record
            for record in self._store.publications(str(self.output_directory))
            if record.get("job_id") == job_id
            and record.get("attempt_id") == attempt_id
        ]
        for record in records:
            publication_id = str(record["publication_id"])
            state = str(record["state"])
            if state == "ready":
                if self._store.publication_authority_current(publication_id):
                    return self._resource_result("attention_required")
                self._store.revoke_ready_publication(
                    publication_id,
                    "fenced worker-loss attempt was recovered after cgroup proof",
                )
            elif state == "allocated":
                self._store.abandon_publication(
                    publication_id,
                    "fenced worker-loss attempt was recovered before validation",
                )
        report = self._publication.reconcile()
        if report.get("status") == "attention_required":
            return self._resource_result("attention_required")
        identity = self._store.attempt_containment_identity(job_id, attempt_id)
        if identity is None or self._attempt_runner is None:
            return self._resource_result("attention_required")
        try:
            self._attempt_runner.cleanup_after_recovery(identity)
        except (OSError, RuntimeError, ValueError):
            return self._resource_result("attention_required")
        try:
            self._store.mark_systemd_output_cleanup_complete(
                identity,
                validated=False,
                timestamp=_now(),
            )
        except Exception:
            return self._resource_result("attention_required")
        if not self._store.release_quarantined_attempt(
            job_id, attempt_id, timestamp=_now()
        ):
            return self._resource_result("attention_required")
        return self._resource_result("recovered")

    def _resource_result(self, outcome: str) -> dict[str, object]:
        """Return a recovery outcome whose clean status requires released capacity."""
        resource = self._store.resource_snapshot()
        state = str(resource["state"])
        reason = resource.get("reason")
        return {
            "status": "attention_required" if state != "available" else outcome,
            "resource_state": state,
            "resource_reason": None if reason is None else str(reason),
        }

    def _recover_attempt(self, job_id: str, attempt_id: str) -> dict[str, object]:
        attempt = self._store.current_attempt(job_id)
        if attempt is None or attempt["attempt_id"] != attempt_id:
            return self._resource_result("complete")
        recovery_fenced = False
        if (
            attempt.get("containment_contract")
            == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            and attempt.get("job_status") == "running"
        ):
            if self._store.fence_attempt_for_recovery(
                job_id, attempt_id, timestamp=_now()
            ) is None:
                return self._resource_result("attention_required")
            recovery_fenced = True
            attempt = self._store.current_attempt(job_id)
            if attempt is None:
                return self._resource_result("attention_required")
        if (
            attempt.get("containment_contract")
            == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            and not self._store.attempt_termination_proven(job_id, attempt_id)
            and self._attempt_runner is not None
        ):
            owner_id = attempt.get("owner_id")
            claim_epoch = attempt.get("claim_epoch")
            if isinstance(owner_id, str) and type(claim_epoch) is int and claim_epoch > 0:
                try:
                    self._attempt_runner.cancel_attempt(
                        job_id=job_id,
                        attempt_id=attempt_id,
                        owner_id=owner_id,
                        claim_epoch=claim_epoch,
                    )
                except (OSError, RuntimeError, ValueError):
                    # The recovery fence is durable; missing broker evidence
                    # leaves the resource quarantined below.
                    pass
        publication = next(
            (
                record
                for record in self._store.publications(str(self.output_directory))
                if record.get("job_id") == job_id
                and record.get("attempt_id") == attempt_id
            ),
            None,
        )
        publication_was_fenced = False
        if publication is not None and publication["state"] == "ready":
            publication_id = str(publication["publication_id"])
            if self._store.publication_authority_current(publication_id):
                self._publication.reconcile()
                snapshot = self._store.get_provenance(job_id)
                if snapshot["status"] == "succeeded":
                    return self._resource_result("recovered")
                return self._resource_result("attention_required")
            self._store.revoke_ready_publication(
                publication_id,
                "attempt ownership or cancellation fenced ready publication",
            )
            publication_was_fenced = True
        elif publication is not None and publication["state"] == "allocated":
            self._store.abandon_publication(
                str(publication["publication_id"]),
                "interrupted before validation",
            )

        attempt = self._store.current_attempt(job_id)
        if attempt is None or attempt["attempt_id"] != attempt_id:
            return self._resource_result("complete")
        owner_id = None if attempt["owner_id"] is None else str(attempt["owner_id"])
        epoch = int(attempt["claim_epoch"])
        contained = self._store.attempt_termination_proven(job_id, attempt_id)
        recovery_cleanup_identity = None
        if (
            contained
            and attempt.get("containment_contract")
            == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
        ):
            if self._attempt_runner is None:
                return self._resource_result("attention_required")
            identity = self._store.attempt_containment_identity(job_id, attempt_id)
            if identity is None:
                return self._resource_result("attention_required")
            try:
                self._attempt_runner.cleanup_after_recovery(identity)
            except (OSError, RuntimeError, ValueError):
                return self._resource_result("attention_required")
            recovery_cleanup_identity = identity
        timestamp = _now()
        if attempt["job_status"] == "canceled":
            finalized = self._store.fail_execution(
                job_id,
                attempt_id,
                "adapter invocation ended after cancellation",
                timestamp,
                attempt_owner_id=owner_id,
                claim_epoch=epoch,
                failure_class="canceled",
                termination_proven=contained,
                _revoked_publication_id=str(publication["publication_id"]) if publication_was_fenced else None,
            )
            if not finalized:
                return self._resource_result("attention_required")
            if recovery_cleanup_identity is not None:
                try:
                    self._store.mark_systemd_output_cleanup_complete(
                        recovery_cleanup_identity,
                        validated=False,
                        timestamp=_now(),
                    )
                except Exception:
                    return self._resource_result("attention_required")
            return self._resource_result("canceled")
        if publication_was_fenced:
            finalized = self._store.fail_execution(
                job_id,
                attempt_id,
                (
                    "ready publication was revoked after attempt authority was fenced"
                    if contained
                    else "fenced attempt has no trusted process-termination proof"
                ),
                timestamp,
                attempt_owner_id=owner_id,
                claim_epoch=epoch,
                failure_class="terminal" if contained else "ambiguous",
                termination_proven=contained,
                _revoked_publication_id=str(publication["publication_id"]),
                _recovery_fenced=recovery_fenced,
            )
            if not finalized:
                return self._resource_result("attention_required")
            if recovery_cleanup_identity is not None:
                try:
                    self._store.mark_systemd_output_cleanup_complete(
                        recovery_cleanup_identity,
                        validated=False,
                        timestamp=_now(),
                    )
                except Exception:
                    return self._resource_result("attention_required")
            return self._resource_result("attention_required")
        if contained:
            finalized = self._store.fail_execution(
                job_id,
                attempt_id,
                "worker process ended after adapter termination evidence was validated",
                timestamp,
                attempt_owner_id=owner_id,
                claim_epoch=epoch,
                failure_class="crash",
                termination_proven=True,
                _recovery_fenced=recovery_fenced,
            )
            if not finalized:
                return self._resource_result("attention_required")
            if recovery_cleanup_identity is not None:
                try:
                    self._store.mark_systemd_output_cleanup_complete(
                        recovery_cleanup_identity,
                        validated=False,
                        timestamp=_now(),
                    )
                except Exception:
                    return self._resource_result("attention_required")
            return self._resource_result("complete")
        self._store.fail_execution(
            job_id,
            attempt_id,
            "worker process ended without trusted containment contract",
            timestamp,
            attempt_owner_id=owner_id,
            claim_epoch=epoch,
            failure_class="ambiguous",
            termination_proven=False,
            _recovery_fenced=recovery_fenced,
        )
        return self._resource_result("attention_required")

    def _run_jobs(
        self,
        *,
        limit: int,
        job_id: str | None,
        _failures: list[Exception] | None = None,
    ) -> dict[str, object]:
        self._require_systemd_execution_adapter()
        with self._resource_lock() as locked:
            if not locked:
                return {"status": "resource_busy", "processed": 0}
            processed = 0
            outcomes: list[dict[str, object]] = []
            processed_claims: set[tuple[str, str, str]] = set()
            for _ in range(limit):
                resource = self._store.resource_snapshot()
                if resource["state"] != "available":
                    state = str(resource["state"])
                    return {
                        "status": (
                            "attention_required"
                            if state == "quarantined"
                            else "resource_busy"
                        ),
                        "processed": processed,
                        "outcomes": outcomes,
                        "resource_state": state,
                        "resource_reason": resource.get("reason"),
                    }
                (
                    _,
                    adapter_configuration_json,
                    privacy_compliance,
                    privacy_compliance_json,
                ) = self._current_privacy_snapshot()
                timestamp = _now()
                claim = self._store.claim_next_execution(
                    attempt_id=_new_id("att"),
                    owner_id=_new_id("worker"),
                    adapter_id=self.adapter.adapter_id,
                    adapter_configuration_json=adapter_configuration_json,
                    privacy_compliance_json=privacy_compliance_json,
                    resolved_output_directory=str(self.output_directory),
                    process_contained=self._containment_contract is not None,
                    containment_contract=self._containment_contract,
                    timestamp=timestamp,
                    lease_expires_at=_lease_deadline(self._lease),
                    job_id=job_id,
                    allow_not_required=is_lightweight_cpu_adapter(self.adapter),
                )
                if claim is None:
                    break
                processed += 1
                processed_claims.add(
                    (claim.job_id, claim.attempt_id, claim.owner_id)
                )
                failure = self._execute_claim(claim)
                if failure is not None and _failures is not None:
                    _failures.append(failure)
                # Snapshot each claim before another retry can replace the
                # current job state. A later success must not erase a failed
                # attempt from the worker's observable batch outcome.
                snapshot = self._store.get_provenance(claim.job_id)
                attempt = next(
                    item for item in snapshot["attempts"]
                    if item["attempt_id"] == claim.attempt_id
                )
                resource = self._store.resource_snapshot()
                outcome = {
                    "job_id": claim.job_id,
                    "attempt_id": claim.attempt_id,
                    "status": attempt["status"],
                    "execution_status": snapshot["status"],
                    "failure_class": attempt["failure_class"],
                    "termination_proven": attempt["termination_proven"],
                }
                if (
                    resource.get("job_id") == claim.job_id
                    and resource.get("attempt_id") == claim.attempt_id
                    and resource.get("owner_id") == claim.owner_id
                ):
                    outcome["resource_state"] = resource["state"]
                    outcome["resource_reason"] = resource["reason"]
                outcomes.append(outcome)
            if processed == 0:
                return {"status": "idle", "processed": 0}
            resource = self._store.resource_snapshot()
            state = str(resource["state"])
            reason = resource.get("reason")
            if state == "available":
                return {
                    "status": "complete",
                    "processed": processed,
                    "outcomes": outcomes,
                }
            if state == "quarantined" or (
                resource.get("job_id"),
                resource.get("attempt_id"),
                resource.get("owner_id"),
            ) in processed_claims:
                return {
                    "status": "attention_required",
                    "processed": processed,
                    "outcomes": outcomes,
                    "resource_state": state,
                    "resource_reason": (
                        reason
                        if reason is not None
                        else "processed execution claim remains unreleased"
                    ),
                }
            return {
                "status": "resource_busy",
                "processed": processed,
                "outcomes": outcomes,
                "resource_state": state,
                "resource_reason": reason,
            }

    def _require_systemd_execution_adapter(self) -> None:
        """Keep control-only broker clients from claiming engine work."""
        if self._attempt_runner is not None and not isinstance(
            self.adapter, StableDiffusionCppAdapter
        ):
            raise ValueError(
                "systemd execution requires a StableDiffusionCppAdapter"
            )

    def _execute_claim(self, claim: ExecutionClaim) -> Exception | None:
        stop_heartbeat = threading.Event()

        def heartbeat() -> None:
            while not stop_heartbeat.wait(self._heartbeat_seconds):
                renewed = self._store.renew_attempt(
                    claim.job_id,
                    claim.attempt_id,
                    claim.owner_id,
                    claim.claim_epoch,
                    _now(),
                    _lease_deadline(self._lease),
                )
                if not renewed:
                    return

        heartbeat_thread = threading.Thread(
            target=heartbeat,
            name=f"generation-heartbeat-{claim.attempt_id}",
            daemon=True,
        )
        heartbeat_thread.start()
        metadata = None
        adapter_dispatched = False
        execute_entered = False
        executed = False
        prepared_execution = None
        supervisor: ProcessSupervisor | None = None
        systemd_completion: SystemdAttemptCompletion | None = None
        systemd_output_fd_consumed = False
        try:
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
            self._validate_reference_artifacts(claim.references)
            if self._backend_execution_contract is not None:
                if self._attempt_runner is not None:
                    scratch_directory = self._attempt_runner.prepare_attempt(claim)
                    prepared_execution = self.adapter.resolve_execution(
                        plan, scratch_directory=scratch_directory
                    )
                else:
                    prepared_execution = self.adapter.resolve_execution(plan)
                self._require_execution_privacy(prepared_execution, claim=claim)
                self._store.insert_resolved_execution(
                    job_id=claim.job_id,
                    attempt_id=claim.attempt_id,
                    owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    record=prepared_execution.resolved_record,
                    timestamp=_now(),
                )
            generated_artifact_id = _new_id("art")

            def write_image(destination: Path, staged: BinaryIO) -> None:
                nonlocal metadata, adapter_dispatched, execute_entered, executed
                nonlocal supervisor, systemd_completion
                nonlocal systemd_output_fd_consumed
                if prepared_execution is not None:
                    execute_entered = True
                    if self._attempt_runner is None:
                        supervisor = ProcessSupervisor(
                            _StoreExecutionAuthority(self._store, claim),
                            expected_argv=prepared_execution.argv,
                            expected_environment=prepared_execution.environment,
                        )
                        metadata = self.adapter.execute(
                            plan,
                            staged,
                            supervisor=supervisor,
                        )
                    else:
                        systemd_completion = self._attempt_runner.execute_attempt(
                            claim, prepared_execution
                        )
                        if systemd_completion.termination_evidence is None:
                            raise AmbiguousBackendOutcome(
                                "systemd attempt completed without whole-cgroup proof"
                            )
                        if (
                            systemd_completion.launcher_exit_code != 0
                            or systemd_completion.runner_exit_code != 0
                            or systemd_completion.runner_exit_signal is not None
                            or systemd_completion.unit_result != "success"
                            or not systemd_completion.stream_complete
                        ):
                            raise BackendEvidenceError(
                                "systemd runner, unit, or control stream did not complete cleanly"
                            )
                        observation = systemd_completion.engine_observation
                        if not isinstance(observation, Mapping):
                            raise BackendEvidenceError(
                                "systemd runner omitted the engine observation"
                            )
                        durable_execution = self._store.get_backend_execution(
                            claim.job_id, claim.attempt_id
                        )
                        # A completion packet may drive success only when it
                        # repeats the observation persisted under this claim.
                        if (
                            durable_execution is None
                            or durable_execution.get("state") != "observed"
                            or durable_execution.get("observed") != dict(observation)
                        ):
                            raise BackendEvidenceError(
                                "systemd completion observation does not match durable engine evidence"
                            )
                        if (
                            type(observation.get("exit_code")) is not int
                            or observation.get("exit_code") != 0
                            or observation.get("signal") is not None
                        ):
                            code = observation.get("exit_code")
                            signum = observation.get("signal")
                            detail = f"signal {signum}" if signum is not None else f"exit code {code}"
                            raise GenerationError(f"declared engine failed with {detail}")
                        if not self._store.attempt_termination_proven(
                            claim.job_id, claim.attempt_id
                        ):
                            raise BackendEvidenceError(
                                "broker completion has no durable whole-cgroup proof"
                            )
                        self._verify_execution_evidence(claim, prepared_execution)
                        if systemd_completion.output_fd is None:
                            raise BackendEvidenceError(
                                "systemd broker omitted the pinned output descriptor"
                            )
                        output_source = os.fdopen(
                            systemd_completion.output_fd, "rb", closefd=True
                        )
                        systemd_output_fd_consumed = True
                        with output_source:
                            metadata = self.adapter.stream_systemd_execution(
                                prepared_execution, staged, output_source
                            )
                        self._store.record_systemd_stream_complete(
                            systemd_completion.identity,
                            owner_id=claim.owner_id,
                            claim_epoch=claim.claim_epoch,
                            timestamp=_now(),
                        )
                    executed = True
                    if self._attempt_runner is None:
                        self._verify_execution_evidence(claim, prepared_execution)
                else:
                    adapter_dispatched = True
                    metadata = self.adapter.generate(plan, staged)

            def make_artifact(info: ImageInfo, destination: Path) -> GenerationArtifact:
                if metadata is None or (
                    metadata.width != claim.width
                    or metadata.height != claim.height
                    or info.width != claim.width
                    or info.height != claim.height
                    or metadata.image_format != info.image_format
                    or metadata.media_type != info.media_type
                ):
                    raise RuntimeError(
                        "adapter image metadata does not match decoded image and persisted plan"
                    )
                return GenerationArtifact(
                    job_id=claim.job_id,
                    attempt_id=claim.attempt_id,
                    output_slot_id=claim.output_slot_id,
                    artifact_id=generated_artifact_id,
                    path=str(destination),
                    media_type=info.media_type,
                    image_format=info.image_format,
                    width=info.width,
                    height=info.height,
                    file_size=info.file_size,
                    sha256=info.sha256,
                    created_at=_now(),
                )

            self._publication.publish(
                write_image,
                make_artifact,
                artifact_id=generated_artifact_id,
                job_id=claim.job_id,
                attempt_id=claim.attempt_id,
                sources=tuple(
                    ArtifactSource(reference.artifact_id, reference.role)
                    for reference in claim.references
                ),
                attempt_owner_id=claim.owner_id,
                claim_epoch=claim.claim_epoch,
            )
            return None
        except Exception as error:
            snapshot = self._store.get_provenance(claim.job_id)
            if snapshot["artifact"] is not None and snapshot["status"] == "succeeded":
                return None
            if snapshot["status"] == "canceled":
                prelaunch_refusal = (
                    not adapter_dispatched
                    and not executed
                    and (
                        not execute_entered
                        or (
                            supervisor is not None
                            and not supervisor.process_started
                        )
                    )
                )
                canceled_termination = (
                    self._store.attempt_termination_proven(
                        claim.job_id, claim.attempt_id
                    )
                    or prelaunch_refusal
                )
                finalized = self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    "execution_canceled",
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="canceled",
                    termination_proven=canceled_termination,
                    prelaunch_refusal=prelaunch_refusal,
                )
                if not finalized:
                    return PublicationIncompleteError(
                        claim.job_id, "canceled attempt could not be durably finalized"
                    )
                return error
            process_started = supervisor is not None and supervisor.process_started
            preparation_error: BackendPreparationError | None = None
            cursor: BaseException | None = error
            while cursor is not None:
                if isinstance(cursor, BackendPreparationError):
                    preparation_error = cursor
                    break
                cursor = cursor.__cause__
            if not adapter_dispatched and (
                not execute_entered
                or (
                    not process_started
                    and supervisor is not None
                    and not executed
                    and isinstance(error, GenerationError)
                    and not isinstance(error, AmbiguousBackendOutcome)
                )
            ):
                preparation_message = "execution_preparation_failed"
                if preparation_error is not None:
                    preparation_message = (
                        f"execution_preparation_failed: {preparation_error.code}"
                    )
                self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    preparation_message,
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="terminal",
                    termination_proven=True,
                    prelaunch_refusal=True,
                )
                return error
            retryable_failure = False
            cursor: BaseException | None = error
            while cursor is not None:
                if isinstance(cursor, RetryableGenerationError):
                    retryable_failure = True
                    break
                cursor = cursor.__cause__
            termination_proven = self._store.attempt_termination_proven(
                claim.job_id, claim.attempt_id
            )
            ambiguous_acceptance = False
            cursor = error
            while cursor is not None:
                if isinstance(cursor, AmbiguousBackendOutcome):
                    ambiguous_acceptance = True
                    break
                cursor = cursor.__cause__
            if not termination_proven or ambiguous_acceptance:
                self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    "execution_retryable"
                    if retryable_failure and not ambiguous_acceptance
                    else "execution_ambiguous",
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="retryable"
                    if retryable_failure and not ambiguous_acceptance
                    else "ambiguous",
                    termination_proven=termination_proven,
                )
                return error
            failure_class = "retryable" if retryable_failure else "terminal"
            self._store.fail_execution(
                claim.job_id,
                claim.attempt_id,
                "execution_retryable" if retryable_failure else "execution_failed",
                _now(),
                attempt_owner_id=claim.owner_id,
                claim_epoch=claim.claim_epoch,
                failure_class=failure_class,
                termination_proven=True,
            )
            return error
        finally:
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=max(0.1, self._heartbeat_seconds * 2))
            self._retry_pending_systemd_output_cleanups(
                limit=1, attempt_id=claim.attempt_id
            )
            if (
                systemd_completion is not None
                and systemd_completion.output_fd is not None
                and not systemd_output_fd_consumed
            ):
                os.close(systemd_completion.output_fd)
            cleanup = getattr(self.adapter, "cleanup_execution", None)
            if prepared_execution is not None and callable(cleanup):
                cleanup(prepared_execution)

    def _retry_pending_systemd_output_cleanups(
        self, *, limit: int = 16, attempt_id: str | None = None
    ) -> int:
        """Retry a bounded set of broker cleanups after durable outcome checks."""
        if self._attempt_runner is None:
            return 0
        try:
            pending = self._store.pending_systemd_output_cleanups(
                limit=limit, attempt_id=attempt_id
            )
        except Exception:
            return 0
        completed = 0
        for cleanup in pending:
            try:
                self._attempt_runner.acknowledge_output(
                    cleanup.identity, validated=cleanup.validated
                )
                self._store.mark_systemd_output_cleanup_complete(
                    cleanup.identity,
                    validated=cleanup.validated,
                    timestamp=_now(),
                )
            except Exception:
                # The attempt outcome remains durable; failed deletion stays
                # pending for the next bounded recovery pass.
                continue
            completed += 1
        return completed

    def _require_selected_candidate_binding(
        self,
        configuration: Mapping[str, object],
        reference_roles: tuple[str, ...],
        prepared: object,
    ) -> None:
        """Require resolved fields to match the candidate claimed by admission.

        Resolution performs the T07 evaluation and builds the resolved record.
        The record cannot be its own authority: every field that selects a
        candidate, engine, recipe, or component must match the restart-stable
        configuration selected for the attempt. The pinned backend executable
        must also appear at its contract-defined argv position, so an adapter
        cannot obtain a privacy pass for a different program.
        """
        record = getattr(prepared, "resolved_record", None)
        if not isinstance(record, dict):
            raise _resolved_execution_mismatch("resolved execution record missing")
        for name in (
            "candidate_id",
            "declaration_sha256",
            "backend_kind",
            "invocation_contract",
            "cli_contract",
        ):
            _require_selected_field(record, configuration, name)
        record_engine = record.get("engine")
        selected_engine = configuration.get("engine")
        if not isinstance(record_engine, Mapping) or not isinstance(
            selected_engine, Mapping
        ):
            raise _resolved_execution_mismatch(
                "resolved execution engine identity missing"
            )
        for name in ("id", "version", "build", "executable_sha256"):
            _require_selected_field(
                record_engine, selected_engine, name, label=f"engine.{name}"
            )
        record_recipe = record.get("recipe")
        selected_recipe = configuration.get("recipe")
        if not isinstance(record_recipe, Mapping) or not isinstance(
            selected_recipe, Mapping
        ):
            raise _resolved_execution_mismatch(
                "resolved execution recipe identity missing"
            )
        for name in ("id", "document_sha256"):
            _require_selected_field(
                record_recipe, selected_recipe, name, label=f"recipe.{name}"
            )
        _require_selected_value(
            record.get("components"),
            _selected_components(configuration, reference_roles),
            label="components",
        )
        _require_selected_value(
            record.get("adapters"),
            configuration.get("adapters"),
            label="adapters",
        )
        self._require_selected_executable(
            record_engine,
            selected_engine,
            prepared,
            backend_kind=record.get("backend_kind"),
        )

    def _require_selected_executable(
        self,
        record_engine: Mapping[str, object],
        selected_engine: Mapping[str, object],
        prepared: object,
        *,
        backend_kind: object,
    ) -> None:
        """Require the backend executable pin at its contract-defined argv index."""
        pin = selected_engine.get("executable")
        if not isinstance(pin, Mapping):
            raise _resolved_execution_mismatch(
                "selected candidate has no executable pin"
            )
        relative_path = pin.get("path")
        selected_digest = pin.get("sha256")
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or not isinstance(selected_digest, str)
        ):
            raise _resolved_execution_mismatch(
                "selected candidate has an invalid executable pin"
            )
        _require_selected_value(
            record_engine.get("executable_sha256"),
            selected_digest,
            label="engine.executable_sha256",
        )
        argv = tuple(getattr(prepared, "argv", ()))
        if backend_kind == COMFYUI_RESOLVED_BACKEND_KIND:
            try:
                executable_index = argv.index("--") + 1
            except ValueError as error:
                raise _resolved_execution_mismatch(
                    "resolved ComfyUI argv is missing its bootstrap delimiter"
                ) from error
        else:
            executable_index = 0
        if (
            len(argv) <= executable_index
            or not isinstance(argv[executable_index], str)
            or not os.path.isabs(argv[executable_index])
        ):
            raise _resolved_execution_mismatch(
                f"resolved argv[{executable_index}] is not an absolute executable path"
            )
        executable_path = argv[executable_index]
        parts = Path(relative_path).parts
        if not parts or tuple(Path(executable_path).parts[-len(parts) :]) != parts:
            raise _resolved_execution_mismatch(
                f"resolved argv[{executable_index}] does not match the selected executable path"
            )
        try:
            observed_digest = _sha256_regular_file(executable_path)
        except OSError as error:
            raise _resolved_execution_mismatch(
                f"resolved argv[{executable_index}] cannot be read for executable verification"
            ) from error
        if observed_digest != selected_digest:
            raise _resolved_execution_mismatch(
                f"resolved argv[{executable_index}] bytes do not match the selected executable"
            )

    def _require_execution_privacy(
        self, prepared: object, *, claim: ExecutionClaim | None = None
    ) -> None:
        """Require PASS for the exact resolved invocation before any spawn.

        The service does not trust the record's privacy map. It recomputes the
        settings from the argv and environment it is about to spawn, requires
        that the record matches that recomputation, and requires the
        application-owned policy to return PASS. The profile is selected by
        the application-owned registry from the exact adapter identity, engine
        identity, engine version, and configuration version; a policy object
        exposed by the adapter is never consulted. A caller-supplied policy
        cannot relax this gate, and ``require_privacy_pass=False`` does not
        apply to backend execution adapters.

        The resolved candidate and executable are also bound to the
        configuration selected at admission. A direct caller without a claim
        uses the adapter's current configuration.
        """
        record = getattr(prepared, "resolved_record", None)
        if not isinstance(record, dict):
            raise BackendEvidenceError("resolved execution record is missing")
        schema_version = record.get("schema_version")
        if type(schema_version) is not int:
            raise BackendEvidenceError(
                "resolved execution record has an unsupported schema"
            )
        if claim is None:
            configuration = self.adapter.configuration
            reference_roles = _record_reference_roles(record)
        else:
            try:
                configuration = json.loads(claim.adapter_configuration_json)
            except (TypeError, ValueError) as error:
                raise _resolved_execution_mismatch(
                    "claimed adapter configuration is not valid JSON"
                ) from error
            reference_roles = tuple(
                reference.role for reference in claim.references
            )
        if not isinstance(configuration, Mapping):
            raise _resolved_execution_mismatch(
                "adapter configuration is not an object"
            )
        argv = tuple(getattr(prepared, "argv"))
        environment = dict(getattr(prepared, "environment"))
        if record.get("argv") != list(argv):
            raise BackendEvidenceError(
                "resolved argv record does not match the prepared invocation"
            )
        if schema_version in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS:
            expected_environment_record: Mapping[str, object] = {
                "names": sorted(environment),
                "values": environment,
            }
        else:
            expected_environment_record = environment_record(environment)
        if record.get("environment") != expected_environment_record:
            raise BackendEvidenceError(
                "resolved environment record does not match the prepared invocation"
            )
        registration = application_privacy_registration(self.adapter.adapter_id)
        engine = record.get("engine")
        if not isinstance(engine, Mapping):
            raise BackendEvidenceError(
                "resolved execution engine identity missing"
            )
        is_comfyui_record = (
            schema_version in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS
            and record.get("backend_kind") == COMFYUI_RESOLVED_BACKEND_KIND
            and record.get("invocation_contract")
            == COMFYUI_RESOLVED_INVOCATION_CONTRACT
            and record.get("cli_contract") == COMFYUI_RESOLVED_CLI_CONTRACT
        )
        if schema_version == RECORD_SCHEMA_VERSION:
            if "effective_execution" in record:
                raise BackendEvidenceError(
                    "resolved v2 execution record unexpectedly contains effective ComfyUI evidence"
                )
            privacy = invocation_privacy_settings(argv, environment)
        elif is_comfyui_record:
            effective_execution = record.get("effective_execution")
            if not isinstance(effective_execution, Mapping):
                raise BackendEvidenceError(
                    "resolved effective execution evidence is not an object"
                )
            privacy = comfyui_invocation_privacy_settings(
                argv, environment, effective_execution
            )
        else:
            raise BackendEvidenceError(
                "resolved record does not identify a supported privacy backend contract"
            )
        configuration_version = configuration.get("configuration_version")
        result = self._privacy_policy.evaluate(
            self.adapter.adapter_id,
            {"configuration_version": configuration_version, "privacy": privacy},
        )
        if schema_version == RESOLVED_RECORD_SCHEMA_VERSION:
            try:
                expected_privacy_evidence = comfyui_resolved_privacy_evidence(
                result,
                effective_execution,
                configuration_version=configuration_version,
                ).to_dict()
            except ValueError:
                expected_privacy_evidence = None
            if record.get("privacy_evidence") != expected_privacy_evidence:
                raise PrivacyComplianceError(
                    replace(
                        result,
                        status=PrivacyComplianceStatus.FAIL,
                        reasons=(
                            *result.reasons,
                            {
                                "code": "resolved_privacy_mismatch",
                                "detail": (
                                    "Resolved privacy evidence does not match "
                                    "recomputed invocation."
                                ),
                            },
                        ),
                    )
                )
        if (
            engine.get("id") != registration.tool_id
            or engine.get("version") != registration.tool_version
        ):
            raise PrivacyComplianceError(
                replace(
                    result,
                    status=PrivacyComplianceStatus.FAIL,
                    reasons=(
                        *result.reasons,
                        {
                            "code": "resolved_engine_mismatch",
                            "detail": (
                                "Resolved engine identity does not match "
                                "the application-owned privacy registration."
                            ),
                        },
                    ),
                )
            )
        self._require_selected_candidate_binding(
            configuration, reference_roles, prepared
        )
        if record.get("privacy") != privacy:
            raise PrivacyComplianceError(
                replace(
                    result,
                    status=PrivacyComplianceStatus.FAIL,
                    reasons=(
                        *result.reasons,
                        {
                            "code": "resolved_privacy_mismatch",
                            "detail": (
                                "Resolved privacy settings do not match the "
                                "recomputed invocation."
                            ),
                        },
                    ),
                )
            )
        if result.status is not PrivacyComplianceStatus.PASS:
            raise PrivacyComplianceError(result)

    def _verify_execution_evidence(self, claim: ExecutionClaim, prepared: object) -> None:
        """Reject publication unless persisted launch facts match resolution.

        The supervisor records the exact argv and environment it spawned. A
        mismatch with the resolved plan, a missing launch record, or a missing
        reaped-child observation fails closed before the publisher commits.
        """
        record = self._store.get_backend_execution(claim.job_id, claim.attempt_id)
        if record is None:
            raise BackendEvidenceError(
                "backend execution evidence is missing after execution"
            )
        state = record.get("state")
        if state not in {"launched", "observed"}:
            raise BackendEvidenceError(
                "backend execution did not persist launch evidence"
            )
        resolved = record.get("resolved")
        if not isinstance(resolved, dict):
            raise BackendEvidenceError("backend execution resolved evidence is missing")
        resolved_schema_version = resolved.get("schema_version")
        if type(resolved_schema_version) is not int:
            raise BackendEvidenceError(
                "persisted resolved record has an unsupported schema"
            )
        expected_argv = list(getattr(prepared, "argv"))
        if resolved.get("argv") != expected_argv:
            raise BackendEvidenceError(
                "persisted resolved argv does not match the resolved invocation"
            )
        expected_environment = dict(getattr(prepared, "environment"))
        if resolved_schema_version in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS:
            expected_environment_record: Mapping[str, object] = {
                "names": sorted(expected_environment),
                "values": expected_environment,
            }
        else:
            expected_environment_record = environment_record(expected_environment)
        if resolved.get("environment") != expected_environment_record:
            raise BackendEvidenceError(
                "persisted resolved environment does not match the resolved invocation"
            )
        launch = record.get("launch")
        if not isinstance(launch, dict):
            raise BackendEvidenceError("backend execution launch evidence is missing")
        recorded_argv = launch.get("argv")
        if recorded_argv != expected_argv:
            raise BackendEvidenceError(
                "persisted launch argv does not match the resolved invocation"
            )
        recorded_environment = launch.get("environment")
        if recorded_environment != expected_environment:
            raise BackendEvidenceError(
                "persisted launch environment does not match the resolved invocation"
            )
        if state != "observed" or not isinstance(record.get("observed"), dict):
            raise BackendEvidenceError(
                "backend execution did not persist a reaped-child observation"
            )

    @contextmanager
    def _resource_lock(self) -> Iterator[bool]:
        """Hold the permanent per-database heavyweight resource lock."""
        lock_path = self._store.database_path.with_name(
            self._store.database_path.name + ".resource.lock"
        )
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            yield True
        finally:
            os.close(descriptor)

    def _validate_reference_artifacts(self, references: tuple[ResolvedReference, ...]) -> None:
        """Require current authoritative bytes to match the immutable artifact."""
        for reference in references:
            observation = self._publication.integrity(reference.artifact_id)
            if observation["status"] != "ok":
                raise ArtifactIntegrityError(
                    f"reference artifact {reference.artifact_id!r} is missing or failed SHA-256/image validation: "
                    f"{observation['detail']}"
                )

    def import_image(self, approved_root: Path, relative_path: str, *,
                     sources: tuple[ArtifactSource, ...] = ()) -> ImportedArtifact:
        """Import a local image under an explicit operator-granted source root.

        This administrative boundary accepts a relative filename beneath the
        approved root. GenerationRequest continues to accept only artifact IDs.
        Each invocation creates a new identity, even for identical image bytes.
        """
        sources = tuple(sources)
        if len({(source.artifact_id, source.role) for source in sources}) != len(sources):
            raise InputValidationError("lineage sources cannot repeat an artifact/role pair")
        for source in sources:
            self._store.get_artifact(source.artifact_id)
            if source.role in {"reference", "source"}:
                if self.get_integrity(source.artifact_id)["status"] != "ok":
                    raise ArtifactIntegrityError("lineage input is not a trusted image")
        artifact_id = _new_id("art")
        # Keep every operator-supplied component intact. The source opener pins
        # each directory with O_NOFOLLOW before provenance is recorded.
        approved_path = approved_root.expanduser()
        with open_approved_source(approved_path, relative_path) as source_file:
            source_stat = os.fstat(source_file.fileno())
            provenance = {
                "approved_root": str(approved_path),
                "relative_path": relative_path,
                "source_device": source_stat.st_dev, "source_inode": source_stat.st_ino,
                "source_size": source_stat.st_size, "source_mtime_ns": source_stat.st_mtime_ns,
                "source_ctime_ns": source_stat.st_ctime_ns,
                "imported_at": _now(),
            }

            def copy_image(destination: Path, staged: BinaryIO) -> None:
                # Copy into the publisher's pinned descriptor without reopening
                # either side through a caller-controlled path.
                copy_source(source_file, staged)
                after = os.fstat(source_file.fileno())
                if any(getattr(source_stat, field) != getattr(after, field) for field in (
                    "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
                )):
                    raise InputValidationError("source changed after import approval")

            def make_artifact(info: ImageInfo, destination: Path) -> ImportedArtifact:
                return ImportedArtifact(
                    artifact_id=artifact_id, path=str(destination), media_type=info.media_type,
                    image_format=info.image_format, width=info.width, height=info.height,
                    file_size=info.file_size, sha256=info.sha256, created_at=_now(),
                    import_provenance=provenance)

            artifact = self._publication.publish(copy_image, make_artifact,
                artifact_id=artifact_id, sources=sources)
        assert isinstance(artifact, ImportedArtifact)
        return artifact

    def get_integrity(self, artifact_id: str) -> dict[str, object]:
        """Verify current stored bytes while preserving immutable metadata."""
        return self._publication.integrity(artifact_id)

    def inspect_integrity(self, artifact_id: str) -> dict[str, object]:
        """Verify current artifact bytes without recording an observation."""
        return self._publication.inspect_integrity(artifact_id)

    def get_lineage(self, artifact_id: str) -> dict[str, object]:
        """Inspect ordered parents and children of a logical artifact."""
        return self._store.get_lineage(artifact_id)

    def reconcile(self) -> dict[str, object]:
        """Recover owned publications and report unresolved storage conditions."""
        return self._publication.reconcile()

    @staticmethod
    def lookup_existing_idempotency_key(
        database_path: Path, idempotency_key: str
    ) -> tuple[str, str] | None:
        """Read an accepted job identity without constructing an adapter.

        Reconciliation must be able to find work accepted under an earlier
        privacy, capability, or admission snapshot. This method only validates
        the current store schema and performs the existing idempotency lookup;
        it never creates a database or admits, recovers, or executes work.
        """
        key = _validate_idempotency_key(idempotency_key)
        return SQLiteStore.find_idempotency_key_readonly(database_path, key)

    def get_request(self, request_id: str) -> dict[str, object]:
        """Retrieve one immutable request snapshot by ID."""
        return self._store.get_request(request_id).to_dict()

    def get_job(self, job_id: str) -> GenerationJob:
        """Retrieve durable job state by ID."""
        return self._store.get_job(job_id)

    def get_artifact(self, artifact_id: str) -> GenerationArtifact | ImportedArtifact:
        """Retrieve a logical artifact and its persisted image metadata."""
        return self._store.get_artifact(artifact_id)

    def get_provenance(self, job_id: str) -> dict[str, object]:
        """Retrieve the request, adapter attempt, and output provenance snapshot."""
        return self._store.get_provenance(job_id)

    def get_execution(
        self, job_id: str, attempt_id: str | None = None
    ) -> dict[str, object]:
        """Return full validated backend execution records for one attempt."""
        record = self._store.get_backend_execution(job_id, attempt_id)
        if record is None:
            raise RecordNotFoundError(
                f"backend execution evidence not found for job {job_id}"
            )
        return record

    def inspect_admission(self, job_id: str) -> AdmissionInspection | None:
        """Return one consistent job-scoped admission and reservation view."""
        return self._store.inspect_admission(job_id)

    def get_resource_reservation(self, job_id: str) -> dict[str, object] | None:
        """Return the singleton reservation only when this job owns it."""
        reservation = self._store.resource_snapshot()
        return reservation if reservation.get("job_id") == job_id else None

    def _validate_capabilities(self, request: GenerationRequest) -> None:
        capabilities = self.adapter.capabilities
        multiple = capabilities.dimension_multiple
        if multiple < 1:
            raise ValueError("adapter dimension_multiple must be positive")
        if request.width < capabilities.min_width:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports width from "
                f"{capabilities.min_width}"
            )
        if request.height < capabilities.min_height:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports height from "
                f"{capabilities.min_height}"
            )
        if request.width % multiple or request.height % multiple:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} requires dimensions that "
                f"are multiples of {multiple}"
            )
        if request.width > capabilities.max_width:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports width up to {capabilities.max_width}"
            )
        if request.height > capabilities.max_height:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports height up to {capabilities.max_height}"
            )
        if request.reference_ids and not capabilities.supports_references:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} does not support reference images"
            )
        if len(request.reference_ids) > capabilities.max_references:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports at most "
                f"{capabilities.max_references} reference images"
            )
        roles = request.reference_roles or ("reference",) * len(request.reference_ids)
        source_count = roles.count("source")
        operation = "edit" if source_count else "generate"
        if operation not in capabilities.supported_operations:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} does not support "
                f"{operation} requests"
            )
        if capabilities.operation_reference_roles is not None:
            expected_roles = capabilities.operation_reference_roles.get(operation)
            if expected_roles is not None and roles != expected_roles:
                raise UnsupportedCapabilityError(
                    f"adapter {self.adapter.adapter_id!r} requires reference "
                    f"roles {expected_roles!r} for {operation} requests"
                )
        if source_count and not capabilities.supports_editing:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} does not support editing "
                "a source image"
            )
        if source_count > capabilities.max_source_images:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports at most "
                f"{capabilities.max_source_images} source images"
            )

    def _submission_for_job(self, job_id: str) -> SubmissionResult:
        job = self._store.get_job(job_id)
        resource = self._store.resource_snapshot()
        owned = resource.get("job_id") == job_id
        return SubmissionResult(
            request_id=job.request_id,
            job_id=job.job_id,
            status=job.execution_status or job.status,
            output_slot_id=job.output_slot_id,
            artifact_id=job.artifact_id,
            resource_state=str(resource["state"]) if owned else "available",
            resource_reason=(
                None
                if not owned or resource.get("reason") is None
                else str(resource["reason"])
            ),
        )


def _validate_idempotency_key(value: str) -> str:
    """Reject blank and oversized idempotency keys before opening a job."""
    if not isinstance(value, str):
        raise InputValidationError("idempotency key must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 200:
        raise InputValidationError("idempotency key must contain 1-200 characters")
    return normalized


def _new_id(prefix: str) -> str:
    """Create a unique, visibly typed logical record identity."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _now() -> str:
    """Return a timezone-aware UTC timestamp suitable for persisted snapshots."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _lease_deadline(lease: timedelta) -> str:
    """Return the UTC lease deadline used by worker ownership records."""
    return (datetime.now(timezone.utc) + lease).isoformat(timespec="microseconds")


def _canonical_json(value: object) -> str:
    """Serialize values deterministically as strict JSON.

    Non-finite numbers and unsupported object types are rejected so admission
    can fail before writing partial persisted state.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
