"""Advance one screening case through recovery and GenerationService gates."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Mapping

from .domain import GenerationRequest
from .errors import (
    GenerationExecutionError,
    IdempotencyConflictError,
    InputValidationError,
    PrivacyComplianceError,
    RecordNotFoundError,
    UnsupportedCapabilityError,
    UnknownReferenceError,
)
from .publication import PublicationManager
from .screening_manifest import (
    ScreeningConfigurationError,
    ScreeningManifestError,
    _canonical_json,
)
from .screening_report import _TERMINAL_JOB_STATES
from .screening_store import (
    CaseClaim,
    ScreeningClaimLostError,
    ScreeningLedger,
    ScreeningStoreError,
)
from .service import GenerationService
from .store import SQLiteStore


class ScreeningCaseExecutor:
    """Reconcile or advance one claimed case with durable service state."""

    def __init__(
        self,
        *,
        ledger: ScreeningLedger,
        service_database: Path,
        output_directory: Path,
        execution_identity: Mapping[str, object] | None,
        service_factory: Callable[[], GenerationService] | None,
        workload_demand: object | None,
        clock: Callable[[], float],
    ) -> None:
        self.ledger = ledger
        self.service_database = service_database
        self.output_directory = output_directory
        self.execution_identity = execution_identity
        self.service_factory = service_factory
        self.workload_demand = workload_demand
        self.clock = clock
        self._service: GenerationService | None = None

    def advance_case(
        self,
        run: Mapping[str, object],
        case: Mapping[str, object],
        claim: CaseClaim,
        *,
        execution_compatible: bool,
    ) -> None:
        definition = case.get("definition")
        definition = definition if isinstance(definition, dict) else {}
        request_data = case["request"]
        assert isinstance(request_data, dict)
        request = GenerationRequest(
            **request_data, operation=str(case["operation_intent"])
        )
        if request.digest() != case["request_digest"]:
            self._set_blocked(
                claim,
                "request_digest_mismatch",
                "frozen request snapshot does not match its canonical GenerationRequest digest",
            )
            return

        try:
            existing = GenerationService.lookup_existing_idempotency_key(
                self.service_database, str(case["idempotency_key"])
            )
        except Exception as error:
            self._set_blocked(
                claim,
                "service_lookup_unavailable",
                f"read-only service lookup failed: {type(error).__name__}",
            )
            return
        if existing is not None:
            job_id, request_digest = existing
            if request_digest != case["request_digest"]:
                self._set_blocked(
                    claim,
                    "idempotency_digest_conflict",
                    "persisted idempotency key belongs to a different canonical request digest",
                    job_id=job_id,
                )
                return
            state = self.inspect_job(job_id)
            self._save_job_state(claim, state)
            if state["status"] in _TERMINAL_JOB_STATES:
                return
            if not execution_compatible:
                self._set_blocked(
                    claim,
                    "resume_configuration_mismatch",
                    "existing work was reconciled, but changed or unavailable inputs block further execution",
                    job_id=job_id,
                    execution_status=str(state["execution_status"]),
                    request_id=state.get("request_id"),
                    attempt_ids=state.get("attempt_ids", []),
                    service_evidence=state.get("service_evidence"),
                    admission=state.get("admission"),
                )
                return
            if self.service_factory is None or self.execution_identity is None:
                self._set_blocked(
                    claim,
                    "current_execution_configuration_unavailable",
                    "existing work was found, but current execution gates were not supplied for continuation",
                    job_id=job_id,
                    execution_status=str(state["status"]),
                    request_id=state.get("request_id"),
                    attempt_ids=state.get("attempt_ids", []),
                    service_evidence=state.get("service_evidence"),
                    admission=state.get("admission"),
                )
                return
        elif case.get("job_id"):
            self._set_blocked(
                claim,
                "persisted_job_missing",
                "ledger references a service job that is absent from the configured service database",
                job_id=str(case["job_id"]),
            )
            return
        elif not execution_compatible:
            self._set_blocked(
                claim,
                "resume_configuration_mismatch",
                "changed or unavailable run inputs block new service admission; start a new run for changed inputs",
            )
            return
        elif definition.get("fixture_preflight", {}).get("status") != "ready":
            fixture = definition.get("fixture_preflight")
            self._set_blocked(
                claim,
                "fixture_fingerprint_unverified",
                "conditioning artifacts are missing or do not match the frozen fixture fingerprints",
                service_evidence={"fixture_preflight": fixture},
            )
            return
        elif self.service_factory is None or self.execution_identity is None:
            self._set_blocked(
                claim,
                "current_execution_configuration_unavailable",
                "no current pinned GenerationService configuration is available for new execution",
            )
            return

        try:
            service = self._get_service()
            self.ledger.mark_submission_started(claim, now=self.clock())
            result = service.submit(
                str(case["idempotency_key"]),
                request,
                workload_demand=self._workload_demand(),
            )
        except Exception as error:
            try:
                accepted = GenerationService.lookup_existing_idempotency_key(
                    self.service_database, str(case["idempotency_key"])
                )
            except Exception:
                accepted = None
            if accepted is not None:
                job_id, persisted_digest = accepted
                if persisted_digest != case["request_digest"]:
                    self._set_blocked(
                        claim,
                        "idempotency_digest_conflict",
                        "persisted idempotency key belongs to a different canonical request digest",
                        job_id=job_id,
                    )
                    return
                self._save_job_state(claim, self.inspect_job(job_id))
                return
            self.record_error(claim, error)
            return

        accepted = GenerationService.lookup_existing_idempotency_key(
            self.service_database, str(case["idempotency_key"])
        )
        if accepted is None:
            self._set_blocked(
                claim,
                "service_acceptance_not_persisted",
                "GenerationService returned without a durable idempotency record",
            )
            return
        job_id, persisted_digest = accepted
        if persisted_digest != case["request_digest"]:
            self._set_blocked(
                claim,
                "idempotency_digest_conflict",
                "persisted idempotency key belongs to a different canonical request digest",
                job_id=job_id,
            )
            return
        if result.job_id != job_id:
            self._set_blocked(
                claim,
                "service_identity_conflict",
                "GenerationService returned a job that differs from its persisted idempotency record",
                job_id=job_id,
            )
            return
        self._save_job_state(claim, self.inspect_job(job_id))


    def inspect_job(self, job_id: str) -> dict[str, object]:
        store = SQLiteStore(self.service_database, read_only=True)
        job = store.get_job(job_id)
        provenance = store.get_provenance(job_id)
        execution = provenance.get("execution")
        execution = execution if isinstance(execution, dict) else {}
        admission = provenance.get("admission")
        admission = admission if isinstance(admission, dict) else None
        status = str(provenance.get("status", job.execution_status or job.status))
        if admission is not None and admission.get("decision") in {"blocked", "denied"}:
            case_status = "blocked"
        else:
            case_status = _case_status_for_job(status)
        artifact_payload = provenance.get("artifact")
        artifact_id: str | None = None
        integrity: dict[str, object] | None = None
        if isinstance(artifact_payload, dict):
            artifact_id = str(artifact_payload.get("artifact_id", "")) or None
            try:
                integrity = PublicationManager(store, self.output_directory).inspect_integrity(
                    str(artifact_payload["artifact_id"])
                )
            except Exception as error:
                integrity = {
                    "artifact_id": artifact_id,
                    "status": "unverified",
                    "detail": f"integrity inspection failed: {type(error).__name__}",
                }
        elif status == "succeeded":
            integrity = {
                "artifact_id": None,
                "status": "missing",
                "detail": "successful service job has no published artifact record",
            }
        attempts = provenance.get("attempts")
        attempts = attempts if isinstance(attempts, list) else []
        attempt_ids = [
            str(attempt["attempt_id"])
            for attempt in attempts
            if isinstance(attempt, dict) and attempt.get("attempt_id")
        ]
        service_evidence = {
            key: provenance.get(key)
            for key in (
                "job_id",
                "request",
                "status",
                "adapter_id",
                "adapter_configuration",
                "attempts",
                "artifact",
                "backend_execution",
                "execution",
            )
        }
        return {
            "status": case_status,
            "execution_status": status,
            "execution_succeeded": status == "succeeded",
            "request_id": job.request_id,
            "job_id": job.job_id,
            "attempt_ids": attempt_ids,
            "artifact_id": artifact_id,
            "artifact_integrity": integrity,
            "service_evidence": service_evidence,
            "admission": admission,
            "error_code": None if status == "succeeded" else str(status),
            "reason": execution.get("failure_message"),
        }


    def preflight_fixtures(
        self, cases: list[dict[str, object]]
    ) -> dict[str, dict[str, object]]:
        """Compare frozen fixture hashes with persisted artifact metadata read-only."""
        expected: dict[str, str] = {}
        for case in cases:
            inputs = case["conditioning_inputs"]
            assert isinstance(inputs, list)
            for item in inputs:
                assert isinstance(item, dict)
                artifact_id = str(item["artifact_id"])
                digest = item.get("sha256")
                if digest is None:
                    expected[artifact_id] = ""
                elif artifact_id in expected and expected[artifact_id] != digest:
                    raise ScreeningManifestError(
                        "one artifact ID cannot have different frozen fixture fingerprints"
                    )
                else:
                    expected[artifact_id] = str(digest)
        if not expected:
            return {}
        database = self.service_database
        if not database.is_file() or database.stat().st_size == 0:
            return {
                artifact_id: {
                    "artifact_id": artifact_id,
                    "expected_sha256": digest or None,
                    "status": "unavailable",
                    "reason": "GenerationService database has no persisted fixture metadata",
                }
                for artifact_id, digest in expected.items()
            }
        try:
            store = SQLiteStore(database)
        except Exception as error:
            return {
                artifact_id: {
                    "artifact_id": artifact_id,
                    "expected_sha256": digest or None,
                    "status": "unavailable",
                    "reason": f"GenerationService fixture database could not be read: {type(error).__name__}",
                }
                for artifact_id, digest in expected.items()
            }
        result: dict[str, dict[str, object]] = {}
        for artifact_id, digest in expected.items():
            try:
                artifact = store.get_artifact(artifact_id)
            except RecordNotFoundError:
                result[artifact_id] = {
                    "artifact_id": artifact_id,
                    "expected_sha256": digest or None,
                    "actual_sha256": None,
                    "status": "missing",
                }
                continue
            actual_digest = str(artifact.sha256)
            status = "metadata_match" if digest and actual_digest == digest else "mismatch"
            result[artifact_id] = {
                "artifact_id": artifact_id,
                "expected_sha256": digest or None,
                "actual_sha256": actual_digest,
                "status": status,
            }
        return result


    def _save_job_state(self, claim: CaseClaim, state: Mapping[str, object]) -> None:
        self.ledger.set_case_status(
            claim,
            str(state["status"]),
            now=self.clock(),
            execution_status=str(state["execution_status"]),
            execution_succeeded=bool(state["execution_succeeded"]),
            request_id=state.get("request_id"),
            job_id=state.get("job_id"),
            attempt_ids=list(state.get("attempt_ids", [])),
            artifact_id=state.get("artifact_id"),
            artifact_integrity=state.get("artifact_integrity"),
            service_evidence=state.get("service_evidence"),
            admission=state.get("admission"),
            error_code=state.get("error_code"),
            reason=state.get("reason"),
        )


    def record_error(self, claim: CaseClaim, error: Exception) -> None:
        if isinstance(error, UnsupportedCapabilityError):
            status, code = "unsupported", "unsupported_capability"
        elif isinstance(error, GenerationExecutionError):
            safe_message = getattr(error, "safe_message", "")
            if safe_message == "execution_ambiguous":
                status, code = "ambiguous", "execution_ambiguous"
            elif safe_message == "execution_canceled":
                status, code = "canceled", "execution_canceled"
            elif safe_message == "execution_retryable":
                status, code = "queued", "execution_retryable"
            else:
                status, code = "failed", "execution_failed"
        elif isinstance(error, IdempotencyConflictError):
            status, code = "blocked", "idempotency_conflict"
        elif isinstance(error, (PrivacyComplianceError, InputValidationError, UnknownReferenceError)):
            status, code = "blocked", _error_code(error)
        else:
            status, code = "blocked", _error_code(error)
        self.ledger.set_case_status(
            claim,
            status,
            now=self.clock(),
            error_code=code,
            reason=_safe_reason(error),
        )
        self.ledger.release_claim(claim, now=self.clock())


    def _set_blocked(
        self,
        claim: CaseClaim,
        error_code: str,
        reason: str,
        *,
        job_id: str | None = None,
        execution_status: str | None = None,
        request_id: str | None = None,
        attempt_ids: list[str] | None = None,
        service_evidence: Mapping[str, object] | None = None,
        admission: Mapping[str, object] | None = None,
    ) -> None:
        self.ledger.set_case_status(
            claim,
            "blocked",
            now=self.clock(),
            execution_status=execution_status,
            execution_succeeded=None,
            request_id=request_id,
            job_id=job_id,
            attempt_ids=attempt_ids,
            service_evidence=service_evidence,
            admission=admission,
            error_code=error_code,
            reason=reason,
        )


    def _get_service(self) -> GenerationService:
        if self._service is not None:
            return self._service
        if self.service_factory is None:
            raise ScreeningConfigurationError("no current GenerationService factory is available")
        service = self.service_factory()
        actual = {
            "adapter_id": service.adapter.adapter_id,
            "adapter_configuration": service.adapter.configuration,
            "service_database": str(service.database_path),
            "output_directory": str(service.output_directory),
        }
        assert self.execution_identity is not None
        expected = self.execution_identity
        for key in ("adapter_id", "adapter_configuration", "service_database", "output_directory"):
            if _canonical_json(actual[key]) != _canonical_json(expected.get(key)):
                raise ScreeningConfigurationError(
                    f"GenerationService {key} differs from the frozen run identity"
                )
        self._service = service
        return service


    def _workload_demand(self) -> object | None:
        return self.workload_demand


def _case_status_for_job(status: str) -> str:
    if status in {
        "queued",
        "running",
        "succeeded",
        "failed",
        "unsupported",
        "ambiguous",
        "canceled",
    }:
        return status
    return "blocked"

def _error_code(error: Exception) -> str:
    if isinstance(error, UnknownReferenceError):
        return "reference_unavailable"
    if isinstance(error, PrivacyComplianceError):
        return "privacy_blocked"
    if isinstance(error, InputValidationError):
        return "input_refused"
    name = type(error).__name__
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()

def _safe_reason(error: Exception) -> str:
    safe = getattr(error, "safe_message", None)
    if isinstance(safe, str) and safe:
        return safe[:512]
    message = str(error).replace("\n", " ").strip()
    if not message:
        return type(error).__name__
    return message[:512]
