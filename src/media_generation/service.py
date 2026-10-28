"""Synchronous application service for durable local image generation."""

from __future__ import annotations

import json
import os
import fcntl
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from .adapters import (
    DeterministicCpuAdapter,
    GenerationAdapter,
    trusted_containment_contract,
)
from .admission import (
    AdmissionProfile,
    WorkloadDemand,
    evaluate_admission,
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
from .errors import (
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
)
from .store import ExecutionClaim, QueuedExecution, SQLiteStore
from .images import ImageInfo, open_approved_source, copy_source
from .publication import PublicationManager, Checkpoint


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """Stable identities and current state returned from a submit operation."""

    request_id: str
    job_id: str
    status: str
    output_slot_id: str
    artifact_id: str | None

    def to_dict(self) -> dict[str, object]:
        """Return a CLI-ready result without exposing storage implementation details."""
        return {
            "request_id": self.request_id,
            "job_id": self.job_id,
            "status": self.status,
            "output_slot_id": self.output_slot_id,
            "artifact_id": self.artifact_id,
        }


# Strict JSON validation must finish before privacy evaluation inspects caller
# data. This non-serializable marker lets the policy return its canonical,
# redacted configuration_not_json evidence without traversing a cyclic adapter
# configuration.
_NON_JSON_PRIVACY_CONFIGURATION: dict[str, object] = {"marker": object()}


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
    ) -> None:
        if lease_seconds <= 0 or heartbeat_seconds <= 0 or heartbeat_seconds >= lease_seconds:
            raise ValueError("heartbeat interval must be positive and shorter than the lease")
        self.adapter: GenerationAdapter = (
            adapter if adapter is not None else DeterministicCpuAdapter()
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
        self._privacy_policy = privacy_policy or DEFAULT_PRIVACY_POLICY
        self._require_privacy_pass = require_privacy_pass
        self._current_privacy_snapshot()
        self._store = SQLiteStore(database_path)
        self.output_directory = output_directory.expanduser().resolve()
        self._lease = timedelta(seconds=lease_seconds)
        self._heartbeat_seconds = heartbeat_seconds
        self._publication = PublicationManager(self._store, self.output_directory, publication_checkpoint)

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
        decision = evaluate_admission(self._admission_profile, workload_demand)
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
            containment_contract=trusted_containment_contract(self.adapter),
            timestamp=_now(),
            admission=pending_admission,
            validate_admission_reuse=(
                self._admission_profile is not None or workload_demand is not None
            ),
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
        occupied heavyweight resource returns a specific error while leaving
        the newly admitted job queued for a later worker or submit call. A
        blocked or denied capacity decision returns the queued submission
        without creating an attempt; inspect it with ``inspect_admission``.
        A process-contained retryable failure remains durably queued for its
        next bounded attempt and raises ``GenerationExecutionError`` with the
        ``execution_retryable`` safe message.
        Safe CLI messages remain generic for ambiguous, retryable, and canceled
        executions. With an admission profile, terminal failures use
        ``execution_failed``; an admission-disabled contained terminal failure
        retains the established local diagnostic. Incomplete publications also
        retain their diagnostic and recovery context.
        """
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
        if report["status"] == "resource_busy":
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
                and trusted_containment_contract(self.adapter) is not None
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
        """Fence queued or active work and report whether it can continue."""
        outcome = self._store.cancel_execution(job_id, _now())
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
                return {"status": "attention_required"}
            if state == "available":
                report = self._publication.reconcile()
                return {
                    "status": "attention_required" if report.get("status") == "attention_required" else "complete",
                    "publications": report,
                }
            job_id = resource.get("job_id")
            attempt_id = resource.get("attempt_id")
            if not isinstance(job_id, str) or not isinstance(attempt_id, str):
                return {"status": "attention_required"}
            return self._recover_attempt(job_id, attempt_id)

    def _recover_attempt(self, job_id: str, attempt_id: str) -> dict[str, object]:
        attempt = self._store.current_attempt(job_id)
        if attempt is None or attempt["attempt_id"] != attempt_id:
            return {"status": "complete"}
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
                    resource = self._store.resource_snapshot()
                    return {
                        "status": "attention_required"
                        if resource["state"] == "quarantined" else "recovered"
                    }
                return {"status": "attention_required"}
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
            return {"status": "complete"}
        owner_id = None if attempt["owner_id"] is None else str(attempt["owner_id"])
        epoch = int(attempt["claim_epoch"])
        contained = (
            attempt["containment_contract"] is not None
            and bool(attempt["process_contained"])
        )
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
                return {"status": "attention_required"}
            return {"status": "canceled"}
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
            )
            if not finalized:
                return {"status": "attention_required"}
            return {"status": "attention_required"}
        if contained:
            finalized = self._store.fail_execution(
                job_id,
                attempt_id,
                "worker process ended; process-contained adapter invocation terminated",
                timestamp,
                attempt_owner_id=owner_id,
                claim_epoch=epoch,
                failure_class="crash",
                termination_proven=True,
            )
            if not finalized:
                return {"status": "attention_required"}
            return {"status": "complete"}
        self._store.fail_execution(
            job_id,
            attempt_id,
            "worker process ended without trusted containment contract",
            timestamp,
            attempt_owner_id=owner_id,
            claim_epoch=epoch,
            failure_class="ambiguous",
            termination_proven=False,
        )
        return {"status": "attention_required"}
    def _run_jobs(
        self,
        *,
        limit: int,
        job_id: str | None,
        _failures: list[Exception] | None = None,
    ) -> dict[str, object]:
        with self._resource_lock() as locked:
            if not locked:
                return {"status": "resource_busy", "processed": 0}
            processed = 0
            outcomes: list[dict[str, object]] = []
            for _ in range(limit):
                resource = self._store.resource_snapshot()
                if resource["state"] != "available":
                    return {
                        "status": "resource_busy",
                        "processed": processed,
                        "outcomes": outcomes,
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
                    allow_unrecorded_privacy=(
                        privacy_compliance.status
                        is PrivacyComplianceStatus.UNVERIFIED
                    ),
                    resolved_output_directory=str(self.output_directory),
                    process_contained=trusted_containment_contract(self.adapter) is not None,
                    containment_contract=trusted_containment_contract(self.adapter),
                    timestamp=timestamp,
                    lease_expires_at=_lease_deadline(self._lease),
                    job_id=job_id,
                )
                if claim is None:
                    break
                processed += 1
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
                outcomes.append({
                    "job_id": claim.job_id,
                    "attempt_id": claim.attempt_id,
                    "status": attempt["status"],
                    "execution_status": snapshot["status"],
                    "failure_class": attempt["failure_class"],
                    "termination_proven": attempt["termination_proven"],
                })
            if processed == 0:
                return {"status": "idle", "processed": 0}
            return {"status": "complete", "processed": processed, "outcomes": outcomes}

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
            generated_artifact_id = _new_id("art")

            def write_image(destination: Path, staged: BinaryIO) -> None:
                nonlocal metadata, adapter_dispatched
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
                sources=tuple(ArtifactSource(reference.artifact_id) for reference in claim.references),
                attempt_owner_id=claim.owner_id,
                claim_epoch=claim.claim_epoch,
            )
            return None
        except Exception as error:
            snapshot = self._store.get_provenance(claim.job_id)
            if snapshot["artifact"] is not None and snapshot["status"] == "succeeded":
                return None
            if snapshot["status"] == "canceled":
                finalized = self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    "execution_canceled",
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="canceled",
                    termination_proven=claim.containment_contract is not None,
                )
                if not finalized:
                    return PublicationIncompleteError(
                        claim.job_id, "canceled attempt could not be durably finalized"
                    )
                return error
            if not adapter_dispatched:
                self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    "execution_preparation_failed",
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="terminal",
                    termination_proven=True,
                )
                return error
            retryable_failure = False
            cursor: BaseException | None = error
            while cursor is not None:
                if isinstance(cursor, RetryableGenerationError):
                    retryable_failure = True
                    break
                cursor = cursor.__cause__
            if claim.containment_contract is None:
                self._store.fail_execution(
                    claim.job_id,
                    claim.attempt_id,
                    "execution_retryable" if retryable_failure else "execution_ambiguous",
                    _now(),
                    attempt_owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    failure_class="retryable" if retryable_failure else "ambiguous",
                    termination_proven=False,
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

    def get_lineage(self, artifact_id: str) -> dict[str, object]:
        """Inspect ordered parents and children of a logical artifact."""
        return self._store.get_lineage(artifact_id)

    def reconcile(self) -> dict[str, object]:
        """Recover owned publications and report unresolved storage conditions."""
        return self._publication.reconcile()

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

    def inspect_admission(self, job_id: str) -> AdmissionInspection | None:
        """Return one consistent job-scoped admission and reservation view."""
        return self._store.inspect_admission(job_id)

    def get_resource_reservation(self, job_id: str) -> dict[str, object] | None:
        """Return the singleton reservation only when this job owns it."""
        reservation = self._store.resource_snapshot()
        return reservation if reservation.get("job_id") == job_id else None

    def _validate_capabilities(self, request: GenerationRequest) -> None:
        capabilities = self.adapter.capabilities
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

    def _submission_for_job(self, job_id: str) -> SubmissionResult:
        job = self._store.get_job(job_id)
        return SubmissionResult(
            request_id=job.request_id,
            job_id=job.job_id,
            status=job.execution_status or job.status,
            output_slot_id=job.output_slot_id,
            artifact_id=job.artifact_id,
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
