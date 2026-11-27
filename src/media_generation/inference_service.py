"""Queue and supervise local text and vision inference requests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import uuid

from ._candidate_evaluation import LLAMA_CPP_BACKEND_KIND
from ._candidate_contract import CandidateDeclaration, TrustedEvidence
from .admission import AdmissionProfile, WorkloadDemand, evaluate_admission
from .admission_store import AdmissionEvidenceMismatchError, PendingAdmission
from .candidate import parse_candidate, verify_candidate
from .errors import IdempotencyConflictError, RecordNotFoundError
from .images import copy_source, open_regular, validate_image
from .inference import (
    InferenceKind,
    ResponseCategory,
    ResponseResult,
    render_prompt,
    response_contract,
)
from .llama_cpp import (
    LLAMA_CPP_SOURCE_VERSION,
    MAX_CONTEXT_TOKENS,
    MAX_INFERENCE_IMAGE_PIXELS,
    DispatchQualificationReceipt,
    LlamaCppConfiguration,
    LlamaCppOutcome,
    LlamaCppRequest,
    PreparedInvocation,
    RuntimeQualification,
    RuntimeQualificationError,
    execute_invocation,
    prepare_invocation,
    private_workspace,
    restore_response_prefix,
)
from .privacy import (
    LLAMA_CPP_ADAPTER_ID,
    PrivacyComplianceResult,
    PrivacyComplianceStatus,
    application_privacy_policy,
)
from .store import InferenceExecutionClaim, InferenceRequestPeek, SQLiteStore
from .supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)


_REQUEST_SCHEMA = "media-generation.inference-request"
_REQUEST_SCHEMA_VERSION = 1
_CONTAINMENT_CONTRACT = "process-contained/v1"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_MAX_DEADLINE_SECONDS = 300.0


class _PreflightBlocked(Exception):
    """Carry a stable reason code without retaining request data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class _PreparedRequest:
    """Hold validated dispatch inputs that are safe to persist or inspect."""

    request: LlamaCppRequest
    invocation: PreparedInvocation
    qualification: RuntimeQualification
    privacy: PrivacyComplianceResult
    admission: PendingAdmission


@dataclass(frozen=True, slots=True)
class _AttemptResult:
    """Describe a finalized attempt without exposing captured stdout."""

    outcome: str
    category: ResponseCategory
    value: object | None
    needs_attention: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is malformed")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _request_digest(document: Mapping[str, object]) -> str:
    """Hash request intent without its moving absolute deadline."""
    identity = {
        key: value for key, value in document.items() if key != "deadline_at"
    }
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


def _decode_repair_response(response_bytes: bytes) -> str:
    """Keep malformed UTF-8 representable in the bounded repair prompt."""
    return response_bytes.decode("utf-8", errors="replace")


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate request field")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> object:
    raise ValueError("non-finite request number")


def _kind_key(value: object) -> InferenceKind:
    if isinstance(value, InferenceKind):
        return value
    if isinstance(value, str):
        return InferenceKind(value)
    raise ValueError("inference kind key is invalid")


def _normalize_qualifications(
    value: RuntimeQualification
    | Mapping[InferenceKind | str, RuntimeQualification]
    | None,
) -> dict[InferenceKind, RuntimeQualification]:
    if value is None:
        return {}
    if isinstance(value, RuntimeQualification):
        return {value.response_stream.inference_kind: value}
    if not isinstance(value, Mapping):
        raise TypeError("runtime_qualification must be a record or kind mapping")
    result: dict[InferenceKind, RuntimeQualification] = {}
    for raw_kind, qualification in value.items():
        kind = _kind_key(raw_kind)
        if not isinstance(qualification, RuntimeQualification):
            raise TypeError("each runtime qualification must be a RuntimeQualification")
        result[kind] = qualification
    return result


def _normalize_demands(
    value: WorkloadDemand | Mapping[InferenceKind | str, WorkloadDemand] | None,
) -> dict[InferenceKind, WorkloadDemand]:
    if value is None:
        return {}
    if isinstance(value, WorkloadDemand):
        try:
            return {InferenceKind(value.kind): value}
        except ValueError as error:
            raise ValueError(
                "workload_demand.kind must be text or vision"
            ) from error
    if not isinstance(value, Mapping):
        raise TypeError("workload_demand must be a record or kind mapping")
    result: dict[InferenceKind, WorkloadDemand] = {}
    for raw_kind, demand in value.items():
        kind = _kind_key(raw_kind)
        if not isinstance(demand, WorkloadDemand):
            raise TypeError("each workload demand must be a WorkloadDemand")
        result[kind] = demand
    return result


def _normal_fingerprint(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.removeprefix("sha256:")
    if (
        len(normalized) != 64
        or any(character not in "0123456789abcdef" for character in normalized)
    ):
        return None
    return normalized


def _hash_regular_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open_regular(path) as source:
        while True:
            block = source.read(64 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


class _InferenceExecutionAuthority(ExecutionEvidenceAuthority):
    """Route supervisor facts to the current inference attempt record."""

    def __init__(self, store: SQLiteStore, claim: InferenceExecutionClaim) -> None:
        self._store = store
        self._claim = claim

    @property
    def attempt_id(self) -> str:
        """Return the attempt identifier bound to this worker claim."""
        return self._claim.attempt_id

    def verify_current(self) -> bool:
        """Check the shared owner and fence before the supervisor acts."""
        return self._store.assert_attempt_authority(
            self._claim.job_id,
            self._claim.attempt_id,
            self._claim.owner_id,
            self._claim.claim_epoch,
        )

    def record_launch(self, fact: LaunchFact) -> None:
        """Persist the direct launch fact on the inference attempt."""
        self._store.mark_inference_execution_launched(
            job_id=self._claim.job_id,
            attempt_id=self._claim.attempt_id,
            owner_id=self._claim.owner_id,
            claim_epoch=self._claim.claim_epoch,
            record=fact.to_mapping(),
            timestamp=_timestamp(_utc_now()),
        )

    def record_observation(self, fact: ProcessObservation) -> None:
        """Persist the reaped-child observation on the inference attempt."""
        self._store.mark_inference_execution_observed(
            job_id=self._claim.job_id,
            attempt_id=self._claim.attempt_id,
            owner_id=self._claim.owner_id,
            claim_epoch=self._claim.claim_epoch,
            record=fact.to_mapping(),
            timestamp=_timestamp(_utc_now()),
        )


class InferenceService:
    """Queue local text and vision requests behind shared execution evidence."""

    def __init__(
        self,
        *,
        database_path: Path,
        output_directory: Path,
        configuration: LlamaCppConfiguration | None = None,
        runtime_qualification: RuntimeQualification
        | Mapping[InferenceKind | str, RuntimeQualification]
        | None = None,
        candidate_declaration_path: Path | None = None,
        candidate_trusted_evidence: Iterable[TrustedEvidence] = (),
        admission_profile: AdmissionProfile | None = None,
        workload_demand: WorkloadDemand
        | Mapping[InferenceKind | str, WorkloadDemand]
        | None = None,
    ) -> None:
        """Bind persistence, runtime identity, and per-kind dispatch evidence."""
        if configuration is not None and not isinstance(
            configuration, LlamaCppConfiguration
        ):
            raise TypeError("configuration must be a LlamaCppConfiguration or None")
        if admission_profile is not None and not isinstance(
            admission_profile, AdmissionProfile
        ):
            raise TypeError("admission_profile must be an AdmissionProfile or None")
        self.database_path = Path(database_path).expanduser()
        self.output_directory = Path(output_directory).expanduser()
        self.output_directory.mkdir(parents=True, exist_ok=True)
        self.configuration = configuration
        self.runtime_qualifications = _normalize_qualifications(runtime_qualification)
        self.candidate_declaration_path = (
            None
            if candidate_declaration_path is None
            else Path(candidate_declaration_path).expanduser()
        )
        self.candidate_trusted_evidence = tuple(candidate_trusted_evidence)
        if any(
            not isinstance(item, TrustedEvidence)
            for item in self.candidate_trusted_evidence
        ):
            raise TypeError("candidate_trusted_evidence must contain TrustedEvidence records")
        self.admission_profile = admission_profile
        self.workload_demands = _normalize_demands(workload_demand)
        self._store = SQLiteStore(self.database_path)

    def enqueue(
        self,
        idempotency_key: str,
        request: LlamaCppRequest,
        deadline_seconds: float = 300.0,
    ) -> dict[str, object]:
        """Persist a request with an absolute deadline and stable retry identity."""
        if self.configuration is None:
            return {
                "status": "preflight_blocked",
                "reason": "runtime_configuration_missing",
            }
        if not isinstance(request, LlamaCppRequest):
            return {"status": "preflight_blocked", "reason": "request_type_invalid"}
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, (int, float))
            or not math.isfinite(float(deadline_seconds))
            or not 0 < float(deadline_seconds) <= _MAX_DEADLINE_SECONDS
        ):
            return {"status": "preflight_blocked", "reason": "deadline_invalid"}
        try:
            now = _utc_now()
            deadline_at = _timestamp(now + timedelta(seconds=float(deadline_seconds)))
            request_value = self._request_document(
                request, deadline_at, float(deadline_seconds)
            )
            request_json = _canonical_json(request_value)
            request_digest = _request_digest(request_value)
            with private_workspace(self.output_directory) as workspace:
                prepared = prepare_invocation(
                    self.configuration,
                    self._execution_request(request, request_value),
                    workspace=workspace,
                )
                privacy = self._privacy_result(prepared)
                configuration_json = _canonical_json(prepared.configuration)
            pending = self._admission_for(request.kind, privacy)
            if pending is None:
                return {
                    "status": "preflight_blocked",
                    "reason": "admission_evidence_missing",
                }
            privacy_json = _canonical_json(privacy.to_dict())
            queued = self._store.create_queued_inference(
                request_json=request_json,
                request_digest=request_digest,
                idempotency_key=idempotency_key,
                job_id=f"inf_{uuid.uuid4().hex}",
                adapter_id=prepared.adapter_id,
                adapter_configuration_json=configuration_json,
                resolved_working_directory=str(self.output_directory.resolve()),
                privacy_compliance_json=privacy_json,
                containment_contract=_CONTAINMENT_CONTRACT,
                deadline_at=deadline_at,
                timestamp=_timestamp(now),
                admission=pending,
            )
        except IdempotencyConflictError:
            return {"status": "preflight_blocked", "reason": "idempotency_conflict"}
        except Exception:
            return {"status": "preflight_blocked", "reason": "request_validation_failed"}
        if queued.created:
            status = "queued" if pending.decision == "queued" else "blocked"
            reason = pending.reason
        else:
            status = queued.status
            reason = None
            if queued.status == "queued":
                inspection = self._store.inspect_admission(queued.job_id)
                if inspection is not None:
                    persisted_admission = inspection.admission
                    reason = persisted_admission.reason
                    if persisted_admission.decision in {"blocked", "denied"}:
                        status = "blocked"
        return {
            "job_id": queued.job_id,
            "status": status,
            "reason": reason,
            "created": queued.created,
        }

    def work(self, limit: int = 1, job_id: str | None = None) -> dict[str, object]:
        """Preflight queued requests, then claim and supervise eligible work."""
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or (job_id is not None and (not isinstance(job_id, str) or not job_id))
        ):
            return {"status": "preflight_blocked", "reason": "worker_request_invalid"}
        with self._store.resource_lock() as locked:
            if not locked:
                return {"status": "resource_busy", "jobs": []}
            now = _timestamp(_utc_now())
            references = self._queued_request_references(job_id)
            if not references:
                if job_id is not None:
                    return self._job_not_claimable(job_id)
                return {"status": "idle", "jobs": []}
            completed: list[dict[str, object]] = []
            blocked: list[dict[str, object]] = []
            for candidate_job_id, request_digest in references:
                peek = self._store.peek_next_inference_request(
                    adapter_id=LLAMA_CPP_ADAPTER_ID,
                    containment_contract=_CONTAINMENT_CONTRACT,
                    timestamp=now,
                    job_id=candidate_job_id,
                )
                if peek is None:
                    unclaimable = self._job_not_claimable(candidate_job_id)
                    if job_id == candidate_job_id:
                        return unclaimable
                    if unclaimable.get("status") == "preflight_blocked":
                        blocked.append(unclaimable)
                    continue
                result = self._run_job(peek, request_digest)
                if result.get("status") == "preflight_blocked":
                    blocked.append(result)
                    if job_id is not None:
                        return result
                    continue
                if result.get("status") == "not_claimed":
                    if job_id is not None:
                        return result
                    continue
                completed.append(result)
                if result.get("status") in {"attention_required", "resource_busy"}:
                    break
                if len(completed) >= limit:
                    break
            if completed:
                status = (
                    "attention_required"
                    if any(item.get("status") == "attention_required" for item in completed)
                    else "complete"
                )
                return {"status": status, "jobs": completed, "preflight_blocked": blocked}
            if blocked:
                return {
                    "status": "preflight_blocked",
                    "job_id": blocked[0].get("job_id"),
                    "reason": blocked[0].get("reason"),
                    "jobs": blocked,
                }
            return {"status": "idle", "jobs": []}

    def cancel(self, job_id: str) -> dict[str, object]:
        """Request cancellation through the shared execution fence."""
        if not isinstance(job_id, str) or not job_id:
            return {"status": "preflight_blocked", "reason": "job_id_invalid"}
        try:
            outcome = self._store.cancel_execution(job_id, _timestamp(_utc_now()))
        except RecordNotFoundError:
            return {"job_id": job_id, "status": "not_found"}
        return {"job_id": job_id, "status": outcome}

    def recover(self) -> dict[str, object]:
        """Fail interrupted attempts only when persisted ownership evidence permits it."""
        with self._store.resource_lock() as locked:
            if not locked:
                return {"status": "resource_busy"}
            resource = self._store.resource_snapshot()
            state = "available" if resource is None else str(resource.get("state"))
            if state == "available":
                return {"status": "complete", "resource_state": state}
            if state == "quarantined":
                return {
                    "status": "attention_required",
                    "resource_state": state,
                    "reason": "shared_attempt_requires_supervised_recovery",
                }
            job_id = resource.get("job_id")
            attempt_id = resource.get("attempt_id")
            if not isinstance(job_id, str) or not isinstance(attempt_id, str):
                return {
                    "status": "attention_required",
                    "resource_state": state,
                    "reason": "claimed_resource_identity_missing",
                }
            attempt = self._store.current_attempt(job_id)
            if (
                attempt is None
                or attempt.get("attempt_id") != attempt_id
                or attempt.get("status") != "running"
                or not isinstance(attempt.get("owner_id"), str)
            ):
                return {
                    "status": "attention_required",
                    "resource_state": state,
                    "reason": "claimed_attempt_identity_mismatch",
                }
            termination_proven = self._store.attempt_termination_proven(
                job_id, attempt_id
            )
            canceled = attempt.get("job_status") == "canceled"
            failure_class = (
                "canceled"
                if canceled
                else "terminal"
                if termination_proven
                else "ambiguous"
            )
            try:
                finalized = self._store.fail_execution(
                    job_id,
                    attempt_id,
                    "interrupted inference worker recovered",
                    _timestamp(_utc_now()),
                    attempt_owner_id=str(attempt["owner_id"]),
                    claim_epoch=int(attempt["claim_epoch"]),
                    failure_class=failure_class,
                    termination_proven=termination_proven,
                )
            except Exception:
                finalized = False
            updated_resource = self._store.resource_snapshot()
            updated_state = str(updated_resource.get("state", "unknown"))
            if not finalized or updated_state != "available":
                return {
                    "status": "attention_required",
                    "resource_state": updated_state,
                    "reason": (
                        "shared_attempt_requires_supervised_recovery"
                        if updated_state == "quarantined"
                        else "interrupted_attempt_requires_owner_attention"
                    ),
                }
            return {
                "status": "canceled" if canceled else "complete",
                "resource_state": updated_state,
            }

    def provenance(self, job_id: str) -> dict[str, object]:
        """Return durable outcomes without prompts, filesystem paths, or response content."""
        try:
            return self._store.get_public_inference_provenance(job_id)
        except RecordNotFoundError:
            return {"job_id": job_id, "status": "not_found"}

    def _request_document(
        self,
        request: LlamaCppRequest,
        deadline_at: str,
        deadline_seconds: float = _MAX_DEADLINE_SECONDS,
    ) -> dict[str, object]:
        if not request.prompt.strip():
            raise ValueError("prompt is empty")
        render_prompt(request.kind, request.prompt)
        image: dict[str, object] | None = None
        if request.kind is InferenceKind.VISION:
            if request.image_path is None:
                raise ValueError("vision request has no image")
            identity = self._authoritative_image_path(Path(request.image_path))
            with open_regular(Path(identity)) as source:
                info = validate_image(
                    source, max_pixels=MAX_INFERENCE_IMAGE_PIXELS
                )
            image = {
                "identity": identity,
                "sha256": info.sha256,
                "size_bytes": info.file_size,
                "media_type": info.media_type,
                "image_format": info.image_format,
                "width": info.width,
                "height": info.height,
            }
        elif request.image_path is not None:
            raise ValueError("text request contains an image")
        return {
            "schema": _REQUEST_SCHEMA,
            "schema_version": _REQUEST_SCHEMA_VERSION,
            "kind": request.kind.value,
            "prompt": request.prompt,
            "image": image,
            "response_contract": response_contract(request.kind),
            "deadline_at": deadline_at,
            "deadline_seconds": float(deadline_seconds),
        }

    @staticmethod
    def _authoritative_image_path(path: Path) -> str:
        expanded = path.expanduser()
        if ".." in expanded.parts:
            raise ValueError("image path contains parent traversal")
        if expanded.is_absolute():
            return str(expanded)
        return str(Path.cwd() / expanded)

    def _execution_request(
        self,
        request: LlamaCppRequest,
        document: Mapping[str, object],
        *,
        image_path_override: Path | None = None,
        repair_category: ResponseCategory | None = None,
        prior_response: str | None = None,
    ) -> LlamaCppRequest:
        image = document.get("image")
        image_path = image_path_override
        if image_path is None and isinstance(image, Mapping):
            image_path = Path(str(image["identity"]))
        prompt = render_prompt(
            request.kind,
            request.prompt,
            repair_category=repair_category,
            prior_response=prior_response,
        )
        source_text = request.source_text
        if source_text is None:
            source_text = request.prompt
        return LlamaCppRequest(
            request.kind,
            prompt,
            image_path,
            source_text=source_text,
        )

    def _privacy_result(self, prepared: PreparedInvocation) -> PrivacyComplianceResult:
        policy = application_privacy_policy(prepared)
        return policy.evaluate(prepared.adapter_id, prepared.configuration)

    def _admission_for(
        self, kind: InferenceKind, privacy: PrivacyComplianceResult
    ) -> PendingAdmission | None:
        profile = self.admission_profile
        demand = self.workload_demands.get(kind)
        if profile is None or demand is None:
            return None
        configuration = self.configuration
        if configuration is None:
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="runtime_configuration_missing",
                unknown_reasons=("runtime_configuration_missing",),
            )
        if demand.kind != kind.value:
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="workload_demand_kind_mismatch",
                unknown_reasons=("workload_demand_kind_mismatch",),
            )
        configured = _normal_fingerprint(configuration.hardware_fingerprint_sha256)
        admitted = _normal_fingerprint(profile.environment_fingerprint)
        if configured is None or admitted is None or configured != admitted:
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="hardware_fingerprint_mismatch",
                unknown_reasons=("hardware_fingerprint_mismatch",),
            )
        decision = evaluate_admission(profile, demand)
        if (
            demand.context.status != "known"
            or demand.context.value != MAX_CONTEXT_TOKENS
        ):
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="workload_context_mismatch",
                required_bytes=decision.required_bytes,
                unknown_reasons=("workload_context_mismatch",),
            )
        if profile.apex_qualification != "ready" or profile.apex_evidence is not True:
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="apex_evidence_missing",
                required_bytes=decision.required_bytes,
                unknown_reasons=("apex_evidence_missing",),
            )
        if privacy.status is not PrivacyComplianceStatus.PASS:
            return PendingAdmission(
                profile=profile,
                demand=demand,
                decision="blocked",
                reason="privacy_compliance_not_pass",
                required_bytes=decision.required_bytes,
                unknown_reasons=decision.unknown_reasons,
            )
        return PendingAdmission(
            profile=profile,
            demand=demand,
            decision=decision.status,
            reason=decision.reason,
            required_bytes=decision.required_bytes,
            unknown_reasons=decision.unknown_reasons,
        )

    def _queued_request_references(
        self, job_id: str | None
    ) -> list[tuple[str, str]]:
        # SQLiteStore exposes a single-head peek. Enumerating job identities
        # lets the worker skip an unsupported request kind and then use the
        # store's authoritative eligibility checks for each candidate.
        query = """SELECT requests.job_id, requests.request_digest
                   FROM inference_requests AS requests
                   JOIN execution_jobs AS jobs ON jobs.job_id = requests.job_id
                   WHERE jobs.workload_kind = 'inference'
                     AND jobs.status = 'queued' AND requests.adapter_id = ?"""
        parameters: list[object] = [LLAMA_CPP_ADAPTER_ID]
        if job_id is not None:
            query += " AND jobs.job_id = ?"
            parameters.append(job_id)
        query += " ORDER BY jobs.created_at, jobs.job_id"
        with self._store._connection() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        return [(str(row["job_id"]), str(row["request_digest"])) for row in rows]

    def _run_job(
        self, peek: InferenceRequestPeek, request_digest: str
    ) -> dict[str, object]:
        try:
            document = json.loads(
                peek.request_json,
                object_pairs_hook=_strict_object_pairs,
                parse_constant=_reject_json_constant,
            )
            if not isinstance(document, dict):
                raise _PreflightBlocked("request_shape_invalid")
            if _canonical_json(document) != peek.request_json:
                raise _PreflightBlocked("request_not_canonical")
            actual_digest = _request_digest(document)
            if actual_digest != request_digest:
                raise _PreflightBlocked("request_digest_mismatch")
            request = self._request_from_document(document)
            if document.get("deadline_at") != peek.deadline_at:
                raise _PreflightBlocked("request_deadline_mismatch")
            deadline = _parse_timestamp(peek.deadline_at)
            if _utc_now() >= deadline:
                raise _PreflightBlocked("request_deadline_expired")
        except _PreflightBlocked as error:
            return {
                "job_id": peek.job_id,
                "status": "preflight_blocked",
                "reason": error.reason,
            }
        except Exception:
            return {
                "job_id": peek.job_id,
                "status": "preflight_blocked",
                "reason": "request_parse_failed",
            }

        repair: tuple[ResponseCategory, str] | None = None
        first_attempt = 1
        try:
            persisted_repair = self._store.get_inference_repair_context(peek.job_id)
        except Exception:
            return {
                "job_id": peek.job_id,
                "status": "preflight_blocked",
                "reason": "repair_context_invalid",
            }
        if persisted_repair is not None:
            if _utc_now() >= deadline:
                return {
                    "job_id": peek.job_id,
                    "status": "preflight_blocked",
                    "reason": "request_deadline_expired",
                }
            try:
                prior_bytes = persisted_repair.response_bytes
                prior_response = restore_response_prefix(
                    prior_bytes,
                    response_size=len(prior_bytes),
                    response_sha256=hashlib.sha256(prior_bytes).hexdigest(),
                )
                prior_response = _decode_repair_response(prior_response)
                repair = (ResponseCategory(persisted_repair.category), prior_response)
            except (TypeError, ValueError, UnicodeError):
                return {
                    "job_id": peek.job_id,
                    "status": "preflight_blocked",
                    "reason": "repair_context_invalid",
                }
            first_attempt = 2
        final_result: _AttemptResult | None = None
        for attempt_number in range(first_attempt, 3):
            now = _timestamp(_utc_now())
            peek = self._store.peek_next_inference_request(
                adapter_id=LLAMA_CPP_ADAPTER_ID,
                containment_contract=_CONTAINMENT_CONTRACT,
                timestamp=now,
                job_id=peek.job_id,
            )
            if peek is None:
                break
            with private_workspace(self.output_directory) as workspace:
                try:
                    prepared = self._preflight(
                        peek,
                        request_digest,
                        document,
                        request,
                        workspace,
                        repair=repair,
                    )
                except _PreflightBlocked as error:
                    return {
                        "job_id": peek.job_id,
                        "status": "preflight_blocked",
                        "reason": error.reason,
                    }
                claim_time = _utc_now()
                if claim_time >= deadline:
                    return {
                        "job_id": peek.job_id,
                        "status": "preflight_blocked",
                        "reason": "request_deadline_expired",
                    }
                now = _timestamp(claim_time)
                owner_id = f"inference-worker-{uuid.uuid4().hex}"
                attempt_id = f"attempt-{uuid.uuid4().hex}"
                try:
                    claim = self._store.claim_next_inference_execution(
                        attempt_id=attempt_id,
                        owner_id=owner_id,
                        adapter_id=prepared.invocation.adapter_id,
                        adapter_configuration_json=_canonical_json(
                            prepared.invocation.configuration
                        ),
                        resolved_working_directory=str(self.output_directory.resolve()),
                        privacy_compliance_json=_canonical_json(
                            prepared.privacy.to_dict()
                        ),
                        containment_contract=_CONTAINMENT_CONTRACT,
                        timestamp=now,
                        lease_expires_at=peek.deadline_at,
                        expected_admission=prepared.admission,
                        job_id=peek.job_id,
                    )
                except AdmissionEvidenceMismatchError:
                    return {
                        "job_id": peek.job_id,
                        "status": "preflight_blocked",
                        "reason": "admission_evidence_mismatch",
                    }
                if claim is None:
                    return {
                        "job_id": peek.job_id,
                        "status": "not_claimed",
                        "reason": "shared_resource_unavailable",
                    }
                final_result = self._invoke_and_finalize(
                    claim, prepared, deadline, request.kind
                )
            if attempt_number != 1 or final_result.outcome != "invalid_output":
                break
            repair_context = self._store.get_inference_repair_context(peek.job_id)
            if repair_context is None:
                break
            if _utc_now() >= deadline:
                break
            try:
                response_bytes = repair_context.response_bytes
                repair = (
                    ResponseCategory(repair_context.category),
                    _decode_repair_response(
                        restore_response_prefix(
                            response_bytes,
                            response_size=len(response_bytes),
                            response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                        )
                    ),
                )
            except (TypeError, ValueError, UnicodeError):
                break
        if final_result is None:
            return {
                "job_id": peek.job_id,
                "status": "not_claimed",
                "reason": "request_no_longer_claimable",
            }
        provenance = self.provenance(peek.job_id)
        execution = provenance.get("execution")
        resource_state = (
            execution.get("resource_state")
            if isinstance(execution, Mapping)
            else "unknown"
        )
        status = (
            "attention_required"
            if final_result.needs_attention or resource_state != "available"
            else "complete"
        )
        return {
            "job_id": peek.job_id,
            "status": status,
            "outcome": final_result.outcome,
            "category": final_result.category.value,
            "attempts": len(provenance.get("attempts", []))
            if isinstance(provenance.get("attempts"), list)
            else 0,
            "resource_state": resource_state,
            "result": final_result.value,
        }

    def _request_from_document(self, document: Mapping[str, object]) -> LlamaCppRequest:
        if set(document) != {
            "schema",
            "schema_version",
            "kind",
            "prompt",
            "image",
            "response_contract",
            "deadline_at",
            "deadline_seconds",
        }:
            raise _PreflightBlocked("request_shape_invalid")
        if (
            document.get("schema") != _REQUEST_SCHEMA
            or type(document.get("schema_version")) is not int
            or document.get("schema_version") != _REQUEST_SCHEMA_VERSION
        ):
            raise _PreflightBlocked("request_schema_unsupported")
        try:
            kind = InferenceKind(document.get("kind"))
        except (TypeError, ValueError) as error:
            raise _PreflightBlocked("request_kind_unsupported") from error
        prompt = document.get("prompt")
        if not isinstance(prompt, str):
            raise _PreflightBlocked("request_prompt_invalid")
        deadline_seconds = document.get("deadline_seconds")
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, (int, float))
            or not math.isfinite(float(deadline_seconds))
            or not 0 < float(deadline_seconds) <= _MAX_DEADLINE_SECONDS
        ):
            raise _PreflightBlocked("request_deadline_invalid")
        image = document.get("image")
        image_path: Path | None = None
        if kind is InferenceKind.VISION:
            if not isinstance(image, Mapping):
                raise _PreflightBlocked("request_image_missing")
            if not isinstance(image.get("identity"), str):
                raise _PreflightBlocked("request_image_invalid")
            image_path = Path(image["identity"])
        elif image is not None:
            raise _PreflightBlocked("text_request_contains_image")
        return LlamaCppRequest(kind, prompt, image_path)

    def _preflight(
        self,
        peek: InferenceRequestPeek,
        request_digest: str,
        document: Mapping[str, object],
        request: LlamaCppRequest,
        workspace: Path,
        *,
        repair: tuple[ResponseCategory, str] | None,
    ) -> _PreparedRequest:
        kind = request.kind
        configuration = self.configuration
        if configuration is None:
            raise _PreflightBlocked("runtime_configuration_missing")
        contract = response_contract(kind)
        if document.get("response_contract") != contract:
            raise _PreflightBlocked("response_contract_mismatch")
        qualification = self.runtime_qualifications.get(kind)
        if qualification is None:
            raise _PreflightBlocked("runtime_qualification_missing")
        if qualification.response_stream.inference_kind is not kind:
            raise _PreflightBlocked("runtime_qualification_kind_mismatch")
        demand = self.workload_demands.get(kind)
        profile = self.admission_profile
        if profile is None or demand is None:
            raise _PreflightBlocked("admission_evidence_missing")
        if demand.kind != kind.value:
            raise _PreflightBlocked("workload_demand_kind_mismatch")
        if (
            demand.context.status != "known"
            or demand.context.value != MAX_CONTEXT_TOKENS
        ):
            raise _PreflightBlocked("workload_context_mismatch")
        if profile.status != "ready":
            raise _PreflightBlocked("admission_profile_not_ready")
        if profile.apex_qualification != "ready" or profile.apex_evidence is not True:
            raise _PreflightBlocked("apex_evidence_missing")
        configuration_fingerprint = _normal_fingerprint(
            configuration.hardware_fingerprint_sha256
        )
        profile_fingerprint = _normal_fingerprint(profile.environment_fingerprint)
        if (
            configuration_fingerprint is None
            or profile_fingerprint is None
            or configuration_fingerprint != profile_fingerprint
        ):
            raise _PreflightBlocked("hardware_fingerprint_mismatch")
        decision = evaluate_admission(profile, demand)
        if decision.status != "queued":
            raise _PreflightBlocked("admission_not_ready")
        if (
            demand.system_ram_bytes + demand.accelerator_memory_bytes
            < qualification.resources.measured_peak_bytes
        ):
            raise _PreflightBlocked("workload_demand_below_qualified_peak")
        if self.candidate_declaration_path is None:
            raise _PreflightBlocked("candidate_missing")
        try:
            declaration = parse_candidate(self.candidate_declaration_path)
            report = verify_candidate(
                self.candidate_declaration_path,
                trusted_evidence=self.candidate_trusted_evidence,
                selected_backend_kind=LLAMA_CPP_BACKEND_KIND,
            )
        except Exception as error:
            raise _PreflightBlocked("candidate_verification_failed") from error
        if not isinstance(report, Mapping):
            raise _PreflightBlocked("candidate_verification_failed")
        evidence = report.get("evidence")
        if (
            report.get("status") != "ready"
            or not isinstance(evidence, Mapping)
            or evidence.get("independent_evidence_authority") != "ready"
        ):
            raise _PreflightBlocked("candidate_not_ready")
        if not self._candidate_matches_configuration(declaration):
            raise _PreflightBlocked("candidate_runtime_binding_mismatch")
        image_path = self._revalidate_image(document, kind, workspace)
        execution_request = self._execution_request(
            request,
            document,
            image_path_override=image_path,
            repair_category=None if repair is None else repair[0],
            prior_response=None if repair is None else repair[1],
        )
        try:
            invocation = prepare_invocation(
                configuration, execution_request, workspace=workspace
            )
            qualification.require_for(configuration, invocation)
        except (RuntimeQualificationError, OSError, ValueError, TypeError) as error:
            raise _PreflightBlocked("runtime_qualification_mismatch") from error
        if image_path is not None and invocation.request.image_path != image_path:
            raise _PreflightBlocked("request_image_identity_mismatch")
        privacy = self._privacy_result(invocation)
        if privacy.status is not PrivacyComplianceStatus.PASS:
            raise _PreflightBlocked("privacy_compliance_not_pass")
        admission = PendingAdmission(
            profile=profile,
            demand=demand,
            decision=decision.status,
            reason=decision.reason,
            required_bytes=decision.required_bytes,
            unknown_reasons=decision.unknown_reasons,
        )
        return _PreparedRequest(
            request=execution_request,
            invocation=invocation,
            qualification=qualification,
            privacy=privacy,
            admission=admission,
        )

    def _revalidate_image(
        self, document: Mapping[str, object], kind: InferenceKind, workspace: Path
    ) -> Path | None:
        """Snapshot and validate the exact image bytes passed to the runtime."""
        image = document.get("image")
        if kind is InferenceKind.TEXT:
            if image is not None:
                raise _PreflightBlocked("text_request_contains_image")
            return None
        expected_keys = {
            "identity",
            "sha256",
            "size_bytes",
            "media_type",
            "image_format",
            "width",
            "height",
        }
        if not isinstance(image, Mapping) or set(image) != expected_keys:
            raise _PreflightBlocked("request_image_invalid")
        identity = image.get("identity")
        if not isinstance(identity, str):
            raise _PreflightBlocked("request_image_invalid")
        path = Path(identity)
        snapshot_path = workspace / "inference-image"
        try:
            with open_regular(path) as source:
                descriptor = os.open(
                    snapshot_path,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as snapshot:
                    copy_source(source, snapshot)
            with open_regular(snapshot_path) as snapshot:
                info = validate_image(
                    snapshot, max_pixels=MAX_INFERENCE_IMAGE_PIXELS
                )
        except Exception as error:
            raise _PreflightBlocked("request_image_unavailable") from error
        observed = {
            "sha256": info.sha256,
            "size_bytes": info.file_size,
            "media_type": info.media_type,
            "image_format": info.image_format,
            "width": info.width,
            "height": info.height,
        }
        if any(image.get(key) != value for key, value in observed.items()):
            raise _PreflightBlocked("request_image_changed")
        return snapshot_path

    def _candidate_matches_configuration(
        self, declaration: CandidateDeclaration
    ) -> bool:
        configuration = self.configuration
        if configuration is None:
            return False
        engine = declaration.engine
        if (
            engine.id != "llama.cpp"
            or engine.version != LLAMA_CPP_SOURCE_VERSION
        ):
            return False
        try:
            executable = engine.executable.resolved_path(declaration.root_index)
            executable_size, executable_digest = _hash_regular_file(executable)
        except (OSError, ValueError):
            return False
        if (
            executable != configuration.executable_path
            or executable_size != engine.executable.size_bytes
            or executable_digest != engine.executable.sha256
        ):
            return False
        for component in (
            configuration.model_component,
            configuration.projector_component,
        ):
            matches = [
                item for item in declaration.components if item.role == component.role
            ]
            if len(matches) != 1:
                return False
            declared = matches[0].artifact
            try:
                path = declared.resolved_path(declaration.root_index)
                size, digest = _hash_regular_file(path)
            except (OSError, ValueError):
                return False
            if (
                path != component.path
                or digest != component.sha256
                or digest != declared.sha256
                or size != declared.size_bytes
            ):
                return False
        return True

    def _invoke_and_finalize(
        self,
        claim: InferenceExecutionClaim,
        prepared: _PreparedRequest,
        deadline: datetime,
        kind: InferenceKind,
    ) -> _AttemptResult:
        """Supervise one invocation and return only its persisted outcome."""
        authority = _InferenceExecutionAuthority(self._store, claim)
        stop_reason: list[str | None] = [None]

        def stop_requested() -> bool:
            if _utc_now() >= deadline:
                stop_reason[0] = "timeout"
                return True
            if not authority.verify_current():
                try:
                    current = self._store.get_inference_provenance(claim.job_id)
                    stop_reason[0] = (
                        "cancelled" if current.get("status") == "canceled" else "authority_lost"
                    )
                except Exception:
                    stop_reason[0] = "authority_lost"
                return True
            return False

        supervisor = ProcessSupervisor(
            authority,
            expected_argv=prepared.invocation.argv,
            expected_environment=prepared.invocation.environment,
            stop_requested=stop_requested,
        )
        outcome: LlamaCppOutcome | None = None
        error: Exception | None = None
        try:
            outcome = execute_invocation(
                prepared.invocation,
                supervisor,
                qualification=prepared.qualification,
            )
        except Exception as caught:
            error = caught
        if outcome is not None:
            response = outcome.response
            if stop_reason[0] == "timeout":
                response = ResponseResult(ResponseCategory.TIMEOUT)
            elif stop_reason[0] == "cancelled":
                response = ResponseResult(ResponseCategory.CANCELLED)
            capture = outcome.capture_record
            response_bytes = capture["response_bytes"]
            response_size = capture["response_size"]
            response_sha256 = capture["response_sha256"]
            observation = outcome.observation
            termination_proven = self._store.attempt_termination_proven(
                claim.job_id, claim.attempt_id
            )
            prelaunch_refusal = False
        else:
            response = ResponseResult(
                ResponseCategory.TIMEOUT
                if stop_reason[0] == "timeout"
                else ResponseCategory.CANCELLED
                if stop_reason[0] == "cancelled"
                else ResponseCategory.RUNTIME_FAILURE
            )
            response_bytes = b""
            response_size = 0
            response_sha256 = _EMPTY_SHA256
            observation = None
            prelaunch_refusal = not supervisor.process_started
            termination_proven = (
                True
                if prelaunch_refusal
                else self._store.attempt_termination_proven(
                    claim.job_id, claim.attempt_id
                )
            )

        inference_outcome = self._outcome_name(response.category)
        result_json = (
            _canonical_json(response.value)
            if inference_outcome in {"succeeded", "refused"}
            else None
        )
        qualification_receipt: dict[str, str] | None = None
        if outcome is not None and isinstance(
            outcome.qualification, DispatchQualificationReceipt
        ):
            receipt = outcome.qualification
            qualification_receipt = {
                "attempt_id": claim.attempt_id,
                "configuration_sha256": hashlib.sha256(
                    _canonical_json(prepared.invocation.configuration).encode("utf-8")
                ).hexdigest(),
                "source_version": receipt.source_version,
                "build_id_sha256": hashlib.sha256(
                    receipt.build_id.encode("utf-8")
                ).hexdigest(),
                "executable_sha256": receipt.executable_sha256,
                "model_sha256": receipt.model_sha256,
                "projector_sha256": receipt.projector_sha256,
                "hardware_fingerprint_sha256": (
                    receipt.hardware_fingerprint_sha256
                ),
                "stream_evidence_sha256": receipt.stream_evidence_sha256,
                "build_evidence_sha256": receipt.build_evidence_sha256,
                "hardware_evidence_sha256": receipt.hardware_evidence_sha256,
                "resource_evidence_sha256": receipt.resource_evidence_sha256,
            }
        validation_json = _canonical_json(
            {
                "category": response.category.value,
                "kind": kind.value,
                "schema_sha256": response_contract(kind)["schema_sha256"],
                "repair_eligible": response.repair_eligible,
                "qualification_receipt": qualification_receipt,
            }
        )
        if inference_outcome in {"succeeded", "refused"}:
            failure_class = None
        elif inference_outcome == "canceled":
            failure_class = "canceled"
        elif inference_outcome == "invalid_output":
            failure_class = "terminal"
        elif prelaunch_refusal:
            failure_class = "terminal"
        elif observation is not None and observation.signal is not None:
            failure_class = "crash"
        elif not termination_proven:
            failure_class = "ambiguous"
        else:
            failure_class = "terminal"
        try:
            finalized = self._store.finalize_inference_attempt(
                job_id=claim.job_id,
                attempt_id=claim.attempt_id,
                outcome=inference_outcome,
                completion_reason="unknown",
                response_bytes=response_bytes,
                response_size=response_size,
                response_sha256=response_sha256,
                validation_json=validation_json,
                result_json=result_json,
                timestamp=_timestamp(_utc_now()),
                attempt_owner_id=claim.owner_id,
                claim_epoch=claim.claim_epoch,
                termination_proven=termination_proven,
                failure_class=failure_class,
                prelaunch_refusal=prelaunch_refusal,
            )
        except Exception:
            return _AttemptResult(
                outcome="runtime_failure",
                category=ResponseCategory.RUNTIME_FAILURE,
                value=None,
                needs_attention=True,
            )
        if not finalized:
            return _AttemptResult(
                outcome="runtime_failure",
                category=ResponseCategory.RUNTIME_FAILURE,
                value=None,
                needs_attention=True,
            )
        try:
            provenance = self._store.get_inference_provenance(claim.job_id)
            attempts = provenance.get("attempts")
            persisted_attempt = next(
                (
                    item
                    for item in attempts
                    if isinstance(item, Mapping)
                    and item.get("attempt_id") == claim.attempt_id
                ),
                None,
            ) if isinstance(attempts, list) else None
            persisted_result = (
                persisted_attempt.get("result")
                if isinstance(persisted_attempt, Mapping)
                else None
            )
            validation = (
                persisted_result.get("validation")
                if isinstance(persisted_result, Mapping)
                else None
            )
            if (
                not isinstance(persisted_result, Mapping)
                or not isinstance(validation, Mapping)
                or not isinstance(persisted_result.get("outcome"), str)
            ):
                raise ValueError("finalized inference result is unavailable")
            persisted_outcome = str(persisted_result["outcome"])
            persisted_category = ResponseCategory(str(validation["category"]))
            persisted_value = (
                persisted_result.get("value")
                if persisted_outcome in {"succeeded", "refused"}
                else None
            )
            execution = provenance.get("execution")
            resource_state = (
                execution.get("resource_state")
                if isinstance(execution, Mapping)
                else "unknown"
            )
            needs_attention = bool(
                resource_state != "available"
                or provenance.get("status") == "ambiguous"
                or (
                    error is not None
                    and (not supervisor.process_started or not termination_proven)
                )
            )
            return _AttemptResult(
                outcome=persisted_outcome,
                category=persisted_category,
                value=persisted_value,
                needs_attention=needs_attention,
            )
        except Exception:
            return _AttemptResult(
                outcome="runtime_failure",
                category=ResponseCategory.RUNTIME_FAILURE,
                value=None,
                needs_attention=True,
            )

    @staticmethod
    def _outcome_name(category: ResponseCategory) -> str:
        if category is ResponseCategory.VALID_OUTPUT:
            return "succeeded"
        if category is ResponseCategory.REFUSAL:
            return "refused"
        if category is ResponseCategory.RESPONSE_CAPTURE_OVERFLOW:
            return "response_cap_exceeded"
        if category is ResponseCategory.RUNTIME_FAILURE:
            return "runtime_failure"
        if category is ResponseCategory.TIMEOUT:
            return "timeout"
        if category is ResponseCategory.CANCELLED:
            return "canceled"
        return "invalid_output"

    def _job_not_claimable(self, job_id: str) -> dict[str, object]:
        try:
            provenance = self._store.get_inference_provenance(job_id)
        except RecordNotFoundError:
            return {"job_id": job_id, "status": "not_found"}
        admission = provenance.get("admission")
        reason = (
            admission.get("reason")
            if isinstance(admission, Mapping)
            else "request_not_queued"
        )
        return {
            "job_id": job_id,
            "status": "preflight_blocked",
            "reason": str(reason),
        }
