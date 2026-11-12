"""Durable sequential batches coordinated through the existing T04 service."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .admission import WorkloadDemand, is_lightweight_cpu_adapter
from .domain import GenerationRequest
from .errors import (
    IdempotencyConflictError,
    InputValidationError,
    RecordNotFoundError,
    ResourceBusyError,
)
from .publication import PublicationManager
from .service import GenerationService
from .store import SQLiteStore


_BATCH_SCHEMA = "media-generation.batch-manifest"
_BATCH_SCHEMA_VERSION = 1
_DEFAULT_CLAIM_SECONDS = 60
_TERMINAL_EXECUTION_STATES = {"succeeded", "failed", "canceled"}
_SAFE_RETRY_FAILURES = {"retryable", "crash"}
_RETRY_ADMISSION_DECISIONS = {"queued", "released", "not_required"}
_SAFE_ATTEMPT_STATUSES = {"running", "succeeded", "failed", "canceled", "ambiguous"}
_SAFE_ATTEMPT_FAILURE_CLASSES = {
    "retryable",
    "terminal",
    "canceled",
    "ambiguous",
    "crash",
}


def _canonical_json(value: object) -> str:
    """Serialize identity documents into a stable, compact representation."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _now() -> datetime:
    """Return one timezone-aware coordinator timestamp."""
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    """Render timestamps in lexically sortable UTC form for SQLite claims."""
    return value.isoformat(timespec="microseconds")


def _positive_integer(value: object, *, label: str) -> int:
    """Validate an integer budget without accepting Python booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InputValidationError(f"{label} must be a positive integer")
    return value


def _profile_document(service: GenerationService) -> dict[str, object] | None:
    profile = service.admission_profile
    return None if profile is None else profile.to_dict()


def _demand_document(demand: WorkloadDemand | None) -> dict[str, object] | None:
    return None if demand is None else demand.to_dict()


def _request_document(request: GenerationRequest) -> dict[str, object]:
    if not isinstance(request, GenerationRequest):
        raise InputValidationError("batch requests must be GenerationRequest values")
    try:
        return json.loads(_canonical_json(asdict(request)))
    except (TypeError, ValueError, RecursionError) as error:
        raise InputValidationError("batch request is not strict JSON") from error


def _validate_batch_key(batch_key: object) -> str:
    if not isinstance(batch_key, str) or not batch_key.strip():
        raise InputValidationError("batch key must be a non-empty string")
    if len(batch_key) > 512:
        raise InputValidationError("batch key must be at most 512 characters")
    return batch_key


def _slot_id(batch_key: str, ordinal: int) -> str:
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"media-generation-batch:{batch_key}:{ordinal}")
    )


def _service_idempotency_key(batch_key: str, ordinal: int) -> str:
    digest = hashlib.sha256(batch_key.encode("utf-8")).hexdigest()
    return f"batch-{digest}-{ordinal}"


class GenerationBatchService:
    """Coordinate durable ordered slots without replacing T04 execution."""

    def __init__(
        self,
        generation_service: GenerationService,
        *,
        claim_lease_seconds: int = _DEFAULT_CLAIM_SECONDS,
    ) -> None:
        if not isinstance(generation_service, GenerationService):
            raise TypeError("generation_service must be a GenerationService")
        if (
            isinstance(claim_lease_seconds, bool)
            or not isinstance(claim_lease_seconds, int)
            or claim_lease_seconds < 1
        ):
            raise ValueError("claim_lease_seconds must be a positive integer")
        self.generation_service = generation_service
        self.database_path = generation_service.database_path
        self._store = SQLiteStore(self.database_path)
        self._claim_lease = timedelta(seconds=claim_lease_seconds)
        self._claim_renewal_interval = min(
            1.0, max(0.01, self._claim_lease.total_seconds() / 3)
        )

    def submit(
        self,
        batch_key: str,
        requests: Sequence[GenerationRequest],
        *,
        workload_demands: Mapping[str, WorkloadDemand] | None = None,
        max_attempts: int = 1,
    ) -> dict[str, object]:
        """Persist a complete batch manifest, then run its slots in order."""
        batch_key = _validate_batch_key(batch_key)
        max_attempts = _positive_integer(max_attempts, label="max_attempts")
        request_list = tuple(requests)
        if not request_list:
            raise InputValidationError("a batch must contain at least one request")
        request_documents = [_request_document(request) for request in request_list]
        output_slots = [str(document.get("output_slot", "")) for document in request_documents]
        if any(not output_slot for output_slot in output_slots):
            raise InputValidationError("every batch request must have an output slot")
        if len(set(output_slots)) != len(output_slots):
            raise InputValidationError("batch output slots must be unique")

        demands = self._validated_demands(output_slots, workload_demands)
        execution_identity = self.generation_service.execution_identity
        profile = _profile_document(self.generation_service)
        is_lightweight = is_lightweight_cpu_adapter(self.generation_service.adapter)
        if not is_lightweight and (profile is None or any(demand is None for demand in demands)):
            raise InputValidationError(
                "heavyweight batch execution requires an admission profile and demand for every slot"
            )
        if (profile is None) != all(demand is None for demand in demands):
            raise InputValidationError(
                "admission profile and every slot workload demand must be supplied together"
            )

        slots: list[dict[str, object]] = []
        manifest_slots: list[dict[str, object]] = []
        for ordinal, (request, request_document, demand) in enumerate(
            zip(request_list, request_documents, demands, strict=True)
        ):
            slot_id = _slot_id(batch_key, ordinal)
            idempotency_key = _service_idempotency_key(batch_key, ordinal)
            request_json = _canonical_json(request_document)
            request_digest = request.digest()
            demand_document = _demand_document(demand)
            profile_json = None if profile is None else _canonical_json(profile)
            demand_json = (
                None if demand_document is None else _canonical_json(demand_document)
            )
            slots.append(
                {
                    "slot_id": slot_id,
                    "ordinal": ordinal,
                    "output_slot": output_slots[ordinal],
                    "request_json": request_json,
                    "request_digest": request_digest,
                    "idempotency_key": idempotency_key,
                    "admission_profile_json": profile_json,
                    "workload_demand_json": demand_json,
                }
            )
            manifest_slots.append(
                {
                    "slot_id": slot_id,
                    "ordinal": ordinal,
                    "output_slot": output_slots[ordinal],
                    "request": request_document,
                    "request_digest": request_digest,
                    "idempotency_key": idempotency_key,
                    "admission_profile": profile,
                    "workload_demand": demand_document,
                }
            )

        manifest = {
            "schema": _BATCH_SCHEMA,
            "schema_version": _BATCH_SCHEMA_VERSION,
            "batch_key": batch_key,
            "max_attempts": max_attempts,
            "execution_identity": execution_identity,
            "slots": manifest_slots,
        }
        manifest_json = _canonical_json(manifest)
        manifest_digest = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        execution_identity_json = _canonical_json(execution_identity)
        batch_id, _ = self._store.persist_generation_batch(
            batch_id=str(uuid.uuid4()),
            batch_key=batch_key,
            manifest_json=manifest_json,
            manifest_digest=manifest_digest,
            execution_identity_json=execution_identity_json,
            max_attempts=max_attempts,
            slots=slots,
            timestamp=_timestamp(_now()),
        )
        return self._run(
            batch_id,
            {
                str(slot["slot_id"]): demands[index]
                for index, slot in enumerate(slots)
            },
            allow_retry=False,
        )

    def resume(
        self,
        batch_id: str,
        *,
        workload_demands: Mapping[str, WorkloadDemand] | None = None,
    ) -> dict[str, object]:
        """Resume only when current execution and admission inputs still match."""
        batch = self._store.get_generation_batch(batch_id)
        slots = self._store.get_generation_batch_slots(str(batch["batch_id"]))
        demands = self._validate_resume_inputs(batch, slots, workload_demands)
        self._verify_manifest(batch, slots)
        self._verify_execution_identity(batch)
        return self._run(str(batch["batch_id"]), demands, allow_retry=True)

    def report(self, batch_id: str) -> dict[str, object]:
        """Return a read-only execution, publication, integrity, and coordinator view."""
        return self.report_database(self.database_path, batch_id)

    @classmethod
    def report_database(cls, database_path: Path, batch_id: str) -> dict[str, object]:
        """Report from an existing database without constructing an executor."""
        database_path = Path(database_path).expanduser().resolve()
        if not database_path.is_file():
            raise RecordNotFoundError(f"database not found: {database_path}")
        store = SQLiteStore(database_path, read_only=True)
        batch = store.get_generation_batch(batch_id)
        slots = store.get_generation_batch_slots(str(batch["batch_id"]))
        try:
            cls._verify_manifest(batch, slots)
            manifest_integrity = "ok"
        except (RuntimeError, TypeError, ValueError, KeyError):
            manifest_integrity = "inconsistent"
        output_root: str | None = None
        try:
            execution_identity = json.loads(str(batch["execution_identity_json"]))
            candidate_root = (
                execution_identity.get("output_directory")
                if isinstance(execution_identity, Mapping)
                else None
            )
            if (
                isinstance(candidate_root, str)
                and candidate_root.strip()
                and "\x00" not in candidate_root
            ):
                output_root = candidate_root
            else:
                manifest_integrity = "inconsistent"
        except (TypeError, ValueError, RecursionError):
            manifest_integrity = "inconsistent"
        if manifest_integrity != "ok":
            output_root = None
        integrity_manager = (
            None
            if output_root is None
            else PublicationManager(store, Path(output_root))
        )
        now = _timestamp(_now())
        lease_expiry = batch["claim_expires_at"]
        if batch["claim_owner"] is None:
            claim_state = "unclaimed"
        elif lease_expiry is not None and str(lease_expiry) > now:
            claim_state = "held"
        else:
            claim_state = "expired"

        slot_reports: list[dict[str, object]] = []
        requires_attention = manifest_integrity != "ok"
        for slot in slots:
            report = cls._report_slot(
                store, integrity_manager, output_root, batch, slot
            )
            slot_reports.append(report)
            requires_attention |= bool(report["requires_attention"])

        persisted_state = str(batch["coordinator_state"])
        effective_state = (
            "attention_required"
            if requires_attention
            else persisted_state
        )
        return {
            "batch_id": str(batch["batch_id"]),
            "batch_key": str(batch["batch_key"]),
            "coordinator_state": persisted_state,
            "report_state": effective_state,
            "coordinator_claim_state": claim_state,
            "coordinator_claim_epoch": int(batch["claim_epoch"]),
            "coordinator_claim_expires_at": lease_expiry,
            "manifest_integrity": manifest_integrity,
            "requires_attention": requires_attention,
            "slots": slot_reports,
        }

    def _validated_demands(
        self,
        output_slots: list[str],
        workload_demands: Mapping[str, WorkloadDemand] | None,
    ) -> list[WorkloadDemand | None]:
        if workload_demands is None:
            return [None] * len(output_slots)
        if not isinstance(workload_demands, Mapping):
            raise InputValidationError("workload_demands must map output slots to demands")
        if set(workload_demands) != set(output_slots):
            raise InputValidationError(
                "workload_demands must contain exactly one demand for every output slot"
            )
        values: list[WorkloadDemand | None] = []
        for output_slot in output_slots:
            demand = workload_demands[output_slot]
            if not isinstance(demand, WorkloadDemand):
                raise InputValidationError(
                    f"workload demand for slot {output_slot!r} must be WorkloadDemand"
                )
            values.append(demand)
        return values

    def _validate_resume_inputs(
        self,
        batch: Mapping[str, object],
        slots: list[dict[str, object]],
        workload_demands: Mapping[str, WorkloadDemand] | None,
    ) -> dict[str, WorkloadDemand | None]:
        current_profile = _profile_document(self.generation_service)
        current_profile_json = (
            None if current_profile is None else _canonical_json(current_profile)
        )
        slot_names = [str(slot["output_slot"]) for slot in slots]
        demands = self._validated_demands(slot_names, workload_demands)
        demand_by_slot = dict(zip(slot_names, demands, strict=True))
        result: dict[str, WorkloadDemand | None] = {}
        for slot in slots:
            slot_name = str(slot["output_slot"])
            if slot["admission_profile_json"] != current_profile_json:
                raise InputValidationError(
                    "admission profile changed since this batch was persisted"
                )
            stored_demand_json = slot["workload_demand_json"]
            demand = demand_by_slot[slot_name]
            current_demand_json = (
                None if demand is None else _canonical_json(demand.to_dict())
            )
            if stored_demand_json != current_demand_json:
                raise InputValidationError(
                    f"workload demand changed for batch slot {slot_name!r}"
                )
            result[str(slot["slot_id"])] = demand
        if not is_lightweight_cpu_adapter(self.generation_service.adapter):
            if current_profile is None or any(value is None for value in result.values()):
                raise InputValidationError(
                    "heavyweight batch resumption requires unchanged admission evidence"
                )
        if (current_profile is None) != all(value is None for value in result.values()):
            raise InputValidationError(
                "admission profile and every slot workload demand must be supplied together"
            )
        return result

    def _verify_execution_identity(self, batch: Mapping[str, object]) -> None:
        stored = str(batch["execution_identity_json"])
        current = _canonical_json(self.generation_service.execution_identity)
        if stored != current:
            raise InputValidationError(
                "adapter, privacy, or output destination changed since this batch was persisted"
            )

    @staticmethod
    def _verify_manifest(
        batch: Mapping[str, object], slots: list[dict[str, object]]
    ) -> None:
        manifest_json = str(batch["manifest_json"])
        digest = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        if digest != str(batch["manifest_digest"]):
            raise RuntimeError("persisted batch manifest digest is inconsistent")
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, ValueError) as error:
            raise RuntimeError("persisted batch manifest is invalid") from error
        if not isinstance(manifest, Mapping):
            raise RuntimeError("persisted batch manifest is inconsistent")
        manifest_slots = manifest.get("slots")
        if (
            manifest.get("schema") != _BATCH_SCHEMA
            or manifest.get("schema_version") != _BATCH_SCHEMA_VERSION
            or not isinstance(manifest_slots, list)
            or len(manifest_slots) != len(slots)
            or manifest.get("batch_key") != batch["batch_key"]
            or manifest.get("max_attempts") != batch["max_attempts"]
            or manifest.get("execution_identity")
            != json.loads(str(batch["execution_identity_json"]))
            or _canonical_json(manifest) != manifest_json
        ):
            raise RuntimeError("persisted batch manifest is inconsistent")
        for item, slot in zip(manifest_slots, slots, strict=True):
            if (
                not isinstance(item, Mapping)
                or item.get("ordinal") != slot["ordinal"]
                or item.get("output_slot") != slot["output_slot"]
                or item.get("slot_id") != slot["slot_id"]
                or item.get("slot_id")
                != _slot_id(str(batch["batch_key"]), int(slot["ordinal"]))
                or item.get("idempotency_key")
                != _service_idempotency_key(
                    str(batch["batch_key"]), int(slot["ordinal"])
                )
                or item.get("request_digest") != slot["request_digest"]
                or item.get("idempotency_key") != slot["idempotency_key"]
                or item.get("request")
                is None
                or _canonical_json(item.get("request"))
                != str(slot["request_json"])
                or item.get("admission_profile")
                != (
                    None
                    if slot["admission_profile_json"] is None
                    else json.loads(str(slot["admission_profile_json"]))
                )
                or item.get("workload_demand")
                != (
                    None
                    if slot["workload_demand_json"] is None
                    else json.loads(str(slot["workload_demand_json"]))
                )
                or int(slot["max_attempts"]) != int(batch["max_attempts"])
            ):
                raise RuntimeError("persisted batch slot identity is inconsistent")
            try:
                request = GenerationRequest(**item["request"])
            except (TypeError, ValueError) as error:
                raise RuntimeError("persisted batch request is invalid") from error
            if request.digest() != str(slot["request_digest"]):
                raise RuntimeError("persisted batch request digest is inconsistent")

    def _run(
        self,
        batch_id: str,
        demands: Mapping[str, WorkloadDemand | None],
        *,
        allow_retry: bool,
    ) -> dict[str, object]:
        owner = str(uuid.uuid4())
        now = _now()
        claimed = self._store.claim_generation_batch(
            batch_id,
            owner,
            _timestamp(now),
            _timestamp(now + self._claim_lease),
        )
        if claimed is None:
            return self.report(batch_id)
        epoch = int(claimed["claim_epoch"])
        lost_claim = threading.Event()
        stop_heartbeat = threading.Event()
        heartbeat = threading.Thread(
            target=self._renew_claim_while_running,
            args=(batch_id, owner, epoch, stop_heartbeat, lost_claim),
            name=f"generation-batch-claim-heartbeat-{batch_id}",
            daemon=True,
        )
        heartbeat.start()
        try:
            for slot in self._store.get_generation_batch_slots(batch_id):
                if not self._renew_claim(batch_id, owner, epoch, lost_claim):
                    break
                if str(slot["coordinator_state"]) in {
                    "succeeded",
                    "canceled",
                }:
                    continue
                request = GenerationRequest(**json.loads(str(slot["request_json"])))
                stop_after_current = self._run_slot(
                    batch_id,
                    slot,
                    request,
                    demands.get(str(slot["slot_id"])),
                    owner,
                    epoch,
                    allow_retry,
                    lost_claim,
                )
                if lost_claim.is_set():
                    break
                if stop_after_current:
                    break

            if not lost_claim.is_set():
                interim = self.report(batch_id)
                target_state = self._coordinator_state(interim)
                self._store.set_generation_batch_state(
                    batch_id, owner, epoch, _timestamp(_now()), target_state
                )
        finally:
            stop_heartbeat.set()
            heartbeat.join()
            self._store.release_generation_batch_claim(
                batch_id, owner, epoch, _timestamp(_now())
            )
        return self.report(batch_id)

    def _renew_claim(
        self,
        batch_id: str,
        owner: str,
        epoch: int,
        lost_claim: threading.Event,
    ) -> bool:
        """Renew only the current coordinator epoch, failing closed on errors."""
        if lost_claim.is_set():
            return False
        now = _now()
        try:
            renewed = self._store.renew_generation_batch_claim(
                batch_id,
                owner,
                epoch,
                _timestamp(now),
                _timestamp(now + self._claim_lease),
            )
        except Exception:
            renewed = False
        if not renewed:
            lost_claim.set()
        return renewed

    def _renew_claim_while_running(
        self,
        batch_id: str,
        owner: str,
        epoch: int,
        stop: threading.Event,
        lost_claim: threading.Event,
    ) -> None:
        """Keep a coordinator lease alive without controlling T04 execution."""
        while not stop.wait(self._claim_renewal_interval):
            if not self._renew_claim(batch_id, owner, epoch, lost_claim):
                return

    def _ensure_claim_current(
        self,
        batch_id: str,
        owner: str,
        epoch: int,
        lost_claim: threading.Event,
    ) -> bool:
        """Fence a new coordinator operation against the current claim epoch."""
        return self._renew_claim(batch_id, owner, epoch, lost_claim)

    def _run_slot(
        self,
        batch_id: str,
        slot: Mapping[str, object],
        request: GenerationRequest,
        workload_demand: WorkloadDemand | None,
        owner: str,
        epoch: int,
        allow_retry: bool,
        lost_claim: threading.Event,
    ) -> bool:
        """Resolve one accepted T04 job and execute only its eligible state."""
        slot_id = str(slot["slot_id"])
        idempotency_key = str(slot["idempotency_key"])
        known_job_id = (
            None if slot["service_job_id"] is None else str(slot["service_job_id"])
        )
        accepted: tuple[str, str] | None = None
        try:
            accepted = self.generation_service.lookup_existing_idempotency_key(
                self.database_path, idempotency_key
            )
            if known_job_id is not None and (
                accepted is None or accepted[0] != known_job_id
            ):
                return self._checkpoint_attention(
                    batch_id, slot_id, owner, epoch, "batch_service_job_mapping_mismatch"
                )
            if accepted is not None:
                if accepted[1] != str(slot["request_digest"]):
                    return self._checkpoint_attention(
                        batch_id,
                        slot_id,
                        owner,
                        epoch,
                        "batch_service_request_digest_mismatch",
                        service_job_id=(
                            accepted[0] if known_job_id == accepted[0] else None
                        ),
                    )

            # T04 remains the sole admission authority. Its idempotency check
            # also verifies the accepted job's frozen adapter, output, privacy,
            # admission evidence, and attempt budget.
            if not self._ensure_claim_current(batch_id, owner, epoch, lost_claim):
                return True
            try:
                submitted = self.generation_service.enqueue(
                    idempotency_key,
                    request,
                    max_attempts=int(slot["max_attempts"]),
                    workload_demand=workload_demand,
                )
            except Exception:
                if accepted is not None:
                    return self._checkpoint_attention(
                        batch_id,
                        slot_id,
                        owner,
                        epoch,
                        "t04_reuse_rejected_frozen_identity",
                        service_job_id=accepted[0],
                    )
                raise
            job_id = submitted.job_id
            if accepted is not None and accepted[0] != job_id:
                raise IdempotencyConflictError(
                    "T04 reused a different service job for the batch slot"
                )
            if not self._checkpoint_slot(
                batch_id,
                slot_id,
                owner,
                epoch,
                "accepted",
                service_job_id=job_id,
                service_request_id=submitted.request_id,
                output_slot_id=submitted.output_slot_id,
                detail=None,
            ):
                return True
            return self._advance_service_job(
                batch_id,
                slot,
                request,
                workload_demand,
                job_id,
                owner,
                epoch,
                allow_retry,
                lost_claim,
            )
        except ResourceBusyError:
            if lost_claim.is_set():
                return True
            job_id = known_job_id
            if job_id is None:
                match = self.generation_service.lookup_existing_idempotency_key(
                    self.database_path, idempotency_key
                )
                job_id = None if match is None else match[0]
            if job_id is None:
                self._checkpoint_attention(
                    batch_id, slot_id, owner, epoch, "service_resource_busy"
                )
                return True
            self._checkpoint_slot(
                batch_id,
                slot_id,
                owner,
                epoch,
                "accepted",
                service_job_id=job_id,
                detail="service_resource_busy",
            )
            return True
        except Exception as error:
            if lost_claim.is_set():
                return True
            job_id = known_job_id
            if job_id is None:
                match = self.generation_service.lookup_existing_idempotency_key(
                    self.database_path, idempotency_key
                )
                job_id = None if match is None else match[0]
            if job_id is not None:
                return self._observe_after_error(
                    batch_id,
                    slot,
                    job_id,
                    owner,
                    epoch,
                    type(error).__name__,
                    lost_claim,
                )
            self._checkpoint_attention(
                batch_id,
                slot_id,
                owner,
                epoch,
                "service_admission_refused",
            )
            return False

    def _advance_service_job(
        self,
        batch_id: str,
        slot: Mapping[str, object],
        request: GenerationRequest,
        workload_demand: WorkloadDemand | None,
        job_id: str,
        owner: str,
        epoch: int,
        allow_retry: bool,
        lost_claim: threading.Event,
    ) -> bool:
        """Apply T04 submit, retry, or recover only to a proven service state."""
        batch_id_value = batch_id
        slot_id = str(slot["slot_id"])
        idempotency_key = str(slot["idempotency_key"])
        max_attempts = int(slot["max_attempts"])
        for _ in range(max_attempts + 2):
            provenance = self.generation_service.get_provenance(job_id)
            execution = provenance["execution"]
            if not isinstance(execution, Mapping):
                return self._checkpoint_attention(
                    batch_id_value, slot_id, owner, epoch, "service_execution_state_missing"
                )
            status = str(execution.get("status", provenance.get("status", "unknown")))
            attempts = provenance.get("attempts", [])
            if not isinstance(attempts, list):
                attempts = []
            attempt_count = len(attempts)
            retry_eligible = (
                bool(execution.get("retry_eligible", False))
                if isinstance(execution, Mapping)
                else False
            )
            admission_inspection = self.generation_service.inspect_admission(job_id)
            admission_decision = (
                None
                if admission_inspection is None
                else admission_inspection.admission.decision
            )
            admission_allowed = admission_decision in _RETRY_ADMISSION_DECISIONS

            if status == "succeeded":
                self._checkpoint_slot(
                    batch_id_value,
                    slot_id,
                    owner,
                    epoch,
                    "succeeded",
                    service_job_id=job_id,
                    output_slot_id=str(provenance["output_slot_id"]),
                    artifact_id=(
                        None
                        if not isinstance(provenance.get("artifact"), Mapping)
                        else str(provenance["artifact"].get("artifact_id"))
                    ),
                    detail=None,
                )
                return False

            if status == "failed":
                if retry_eligible and attempt_count < max_attempts:
                    if not self._retry_was_proven(attempts) or not admission_allowed:
                        self._checkpoint_attention(
                            batch_id_value,
                            slot_id,
                            owner,
                            epoch,
                            "retry_authority_not_verified",
                            service_job_id=job_id,
                        )
                        return True
                    if not allow_retry:
                        self._checkpoint_slot(
                            batch_id_value,
                            slot_id,
                            owner,
                            epoch,
                            "accepted",
                            service_job_id=job_id,
                            detail="retry_pending",
                        )
                        return False
                    if not self._ensure_claim_current(
                        batch_id_value, owner, epoch, lost_claim
                    ):
                        return True
                    self.generation_service.retry(job_id)
                    if not self._ensure_claim_current(
                        batch_id_value, owner, epoch, lost_claim
                    ):
                        return True
                    self.generation_service.submit(
                        idempotency_key, request, workload_demand=workload_demand
                    )
                    if lost_claim.is_set():
                        return True
                    continue
                self._checkpoint_slot(
                    batch_id_value,
                    slot_id,
                    owner,
                    epoch,
                    "failed",
                    service_job_id=job_id,
                    detail=(
                        "retry_denied_or_exhausted"
                        if retry_eligible or attempt_count >= max_attempts
                        else "terminal_service_failure"
                    ),
                )
                return False

            if status == "queued":
                if not admission_allowed:
                    self._checkpoint_attention(
                        batch_id_value,
                        slot_id,
                        owner,
                        epoch,
                        "heavyweight_admission_blocked_or_denied",
                        service_job_id=job_id,
                    )
                    return False
                if attempt_count == 0:
                    if not self._ensure_claim_current(
                        batch_id_value, owner, epoch, lost_claim
                    ):
                        return True
                    self.generation_service.submit(
                        idempotency_key, request, workload_demand=workload_demand
                    )
                    if lost_claim.is_set():
                        return True
                    continue
                if attempt_count < max_attempts and self._retry_was_proven(attempts):
                    if not retry_eligible and admission_decision not in {
                        "queued",
                        "not_required",
                    }:
                        self._checkpoint_attention(
                            batch_id_value,
                            slot_id,
                            owner,
                            epoch,
                            "queued_retry_lacks_t04_authorization",
                            service_job_id=job_id,
                        )
                        return False
                    if not allow_retry:
                        self._checkpoint_slot(
                            batch_id_value,
                            slot_id,
                            owner,
                            epoch,
                            "accepted",
                            service_job_id=job_id,
                            detail="retry_pending",
                        )
                        return False
                    if retry_eligible:
                        if not self._ensure_claim_current(
                            batch_id_value, owner, epoch, lost_claim
                        ):
                            return True
                        self.generation_service.retry(job_id)
                        if not self._ensure_claim_current(
                            batch_id_value, owner, epoch, lost_claim
                        ):
                            return True
                    # A failed-to-queued T04 retry transition clears
                    # retry_eligible and leaves admission queued. That persisted
                    # state is the durable retry authorization. Only resume
                    # dispatches that existing job after a restart.
                    if not self._ensure_claim_current(
                        batch_id_value, owner, epoch, lost_claim
                    ):
                        return True
                    self.generation_service.submit(
                        idempotency_key, request, workload_demand=workload_demand
                    )
                    if lost_claim.is_set():
                        return True
                    continue
                self._checkpoint_attention(
                    batch_id_value,
                    slot_id,
                    owner,
                    epoch,
                    "queued_job_has_no_verified_attempt_authority",
                    service_job_id=job_id,
                )
                return False

            if status == "canceled":
                batch = self._store.get_generation_batch(batch_id_value)
                output_root = str(
                    json.loads(str(batch["execution_identity_json"]))[
                        "output_directory"
                    ]
                )
                publication = next(
                    (
                        record
                        for record in self._store.publications(output_root)
                        if record.get("job_id") == job_id
                    ),
                    None,
                )
                if self._cancellation_has_unresolved_authority(
                    self._store, job_id, provenance, publication
                ):
                    self._checkpoint_attention(
                        batch_id_value,
                        slot_id,
                        owner,
                        epoch,
                        "service_canceled_authority_unresolved",
                        service_job_id=job_id,
                    )
                    return True
                self._checkpoint_slot(
                    batch_id_value,
                    slot_id,
                    owner,
                    epoch,
                    "canceled",
                    service_job_id=job_id,
                    detail=None,
                )
                return False

            if status in {"running", "ambiguous"}:
                reservation = self.generation_service.get_resource_reservation(job_id)
                if reservation is None:
                    self._checkpoint_attention(
                        batch_id_value,
                        slot_id,
                        owner,
                        epoch,
                        "service_state_requires_authoritative_reconciliation",
                        service_job_id=job_id,
                    )
                    return True
                current_attempt = provenance.get("attempt")
                current_attempt_id = (
                    None
                    if not isinstance(current_attempt, Mapping)
                    or current_attempt.get("attempt_id") is None
                    else str(current_attempt.get("attempt_id"))
                )
                if (
                    str(reservation.get("job_id")) != job_id
                    or current_attempt_id is None
                    or str(reservation.get("attempt_id")) != current_attempt_id
                ):
                    self._checkpoint_attention(
                        batch_id_value,
                        slot_id,
                        owner,
                        epoch,
                        "service_resource_identity_mismatch",
                        service_job_id=job_id,
                    )
                    return True
                if not self._ensure_claim_current(
                    batch_id_value, owner, epoch, lost_claim
                ):
                    return True
                recovery = self.generation_service.recover()
                if lost_claim.is_set():
                    return True
                refreshed = self.generation_service.get_provenance(job_id)
                refreshed_execution = refreshed.get("execution")
                refreshed_status = (
                    str(refreshed_execution.get("status", "unknown"))
                    if isinstance(refreshed_execution, Mapping)
                    else "unknown"
                )
                if recovery.get("status") == "resource_busy" or refreshed_status == status:
                    self._checkpoint_slot(
                        batch_id_value,
                        slot_id,
                        owner,
                        epoch,
                        "accepted" if status == "running" else "attention_required",
                        service_job_id=job_id,
                        detail=(
                            "service_attempt_active"
                            if status == "running"
                            else "service_recovery_unresolved"
                        ),
                    )
                    return True
                continue

            self._checkpoint_attention(
                batch_id_value,
                slot_id,
                owner,
                epoch,
                "unknown_or_unresolved_service_state",
                service_job_id=job_id,
            )
            return True

        self._checkpoint_attention(
            batch_id_value,
            slot_id,
            owner,
            epoch,
            "service_attempt_budget_loop_exhausted",
            service_job_id=job_id,
        )
        return False

    @staticmethod
    def _retry_was_proven(attempts: list[object]) -> bool:
        if not attempts or not isinstance(attempts[-1], Mapping):
            return False
        attempt = attempts[-1]
        return (
            attempt.get("failure_class") in _SAFE_RETRY_FAILURES
            and attempt.get("termination_proven") is True
            and attempt.get("status") == "failed"
        )

    @staticmethod
    def _safe_attempt_history(
        attempts: object,
    ) -> tuple[list[dict[str, object]], bool]:
        """Project authoritative T04 attempts through a strict public allowlist."""
        if not isinstance(attempts, list):
            return [], False
        history: list[dict[str, object]] = []
        valid = True
        previous_number = 0
        observed_ids: set[str] = set()
        for attempt in attempts:
            if not isinstance(attempt, Mapping):
                valid = False
                continue
            attempt_id = attempt.get("attempt_id")
            attempt_number = attempt.get("attempt_number")
            status = attempt.get("status")
            failure_class = attempt.get("failure_class")
            termination_proven = attempt.get("termination_proven")
            if not isinstance(attempt_id, str) or not attempt_id or len(attempt_id) > 128:
                valid = False
                attempt_id = None
            elif not attempt_id.isascii() or not all(
                character.isalnum() or character in "-_" for character in attempt_id
            ):
                valid = False
                attempt_id = None
            if (
                isinstance(attempt_number, bool)
                or not isinstance(attempt_number, int)
                or attempt_number < 1
            ):
                valid = False
                attempt_number = None
            elif attempt_number <= previous_number:
                valid = False
            else:
                previous_number = attempt_number
            if isinstance(attempt_id, str):
                if attempt_id in observed_ids:
                    valid = False
                observed_ids.add(attempt_id)
            if not isinstance(status, str) or status not in _SAFE_ATTEMPT_STATUSES:
                valid = False
                status = "unknown"
            if failure_class is not None and (
                not isinstance(failure_class, str)
                or failure_class not in _SAFE_ATTEMPT_FAILURE_CLASSES
            ):
                valid = False
                failure_class = None
            if not isinstance(termination_proven, bool):
                valid = False
                termination_proven = None
            history.append(
                {
                    "attempt_id": attempt_id,
                    "attempt_number": attempt_number,
                    "status": status,
                    "failure_class": failure_class,
                    "termination_proven": termination_proven,
                }
            )
        return history, valid

    @staticmethod
    def _cancellation_has_unresolved_authority(
        store: SQLiteStore,
        job_id: str,
        provenance: Mapping[str, object],
        publication: Mapping[str, object] | None,
    ) -> bool:
        """Keep cancellation visible only when T04 has no live authority."""
        try:
            resource = store.resource_snapshot()
        except Exception:
            return True
        if (
            resource.get("job_id") == job_id
            and resource.get("state") != "available"
        ):
            return True
        if publication is not None and publication.get("state") != "abandoned":
            return True
        artifact = provenance.get("artifact")
        if isinstance(artifact, Mapping) and artifact.get("artifact_id") is not None:
            return True
        attempts = provenance.get("attempts")
        if not isinstance(attempts, list):
            return True
        for attempt in attempts:
            if not isinstance(attempt, Mapping):
                return True
            status = attempt.get("status")
            if not isinstance(status, str):
                return True
            if status in {"running", "ambiguous", "succeeded"}:
                return True
            if status not in {"failed", "canceled"}:
                return True
            if attempt.get("termination_proven") is not True:
                return True
        return False

    def _observe_after_error(
        self,
        batch_id: str,
        slot: Mapping[str, object],
        job_id: str,
        owner: str,
        epoch: int,
        error_type: str,
        lost_claim: threading.Event,
    ) -> bool:
        if lost_claim.is_set():
            return True
        try:
            provenance = self.generation_service.get_provenance(job_id)
        except Exception:
            self._checkpoint_attention(
                batch_id,
                str(slot["slot_id"]),
                owner,
                epoch,
                "service_job_unreadable_after_operation",
                service_job_id=job_id,
            )
            return True
        execution = provenance.get("execution")
        status = (
            str(execution.get("status", "unknown"))
            if isinstance(execution, Mapping)
            else "unknown"
        )
        attempts = provenance.get("attempts", [])
        attempts = attempts if isinstance(attempts, list) else []
        attempt_count = len(attempts)
        retry_eligible = (
            bool(execution.get("retry_eligible", False))
            if isinstance(execution, Mapping)
            else False
        )
        admission = provenance.get("admission")
        admission_decision = (
            str(admission.get("decision")) if isinstance(admission, Mapping) else None
        )
        admission_allows_retry = admission_decision in _RETRY_ADMISSION_DECISIONS
        retry_proven = self._retry_was_proven(attempts)
        has_budget = attempt_count < int(slot["max_attempts"])
        if status == "succeeded":
            self._checkpoint_slot(
                batch_id,
                str(slot["slot_id"]),
                owner,
                epoch,
                "succeeded",
                service_job_id=job_id,
                output_slot_id=str(provenance["output_slot_id"]),
                artifact_id=(
                    None
                    if not isinstance(provenance.get("artifact"), Mapping)
                    else str(provenance["artifact"].get("artifact_id"))
                ),
                detail=None,
            )
            return False
        if status == "queued" and attempt_count == 0 and admission_allows_retry:
            self._checkpoint_slot(
                batch_id,
                str(slot["slot_id"]),
                owner,
                epoch,
                "accepted",
                service_job_id=job_id,
                detail="queued_before_first_attempt_after_service_error",
            )
            return False
        if status in {"queued", "failed"}:
            retry_authorized = retry_eligible or (
                status == "queued"
                and admission_decision in {"queued", "not_required"}
            )
            if (
                retry_authorized
                and has_budget
                and retry_proven
                and admission_allows_retry
            ):
                self._checkpoint_slot(
                    batch_id,
                    str(slot["slot_id"]),
                    owner,
                    epoch,
                    "accepted",
                    service_job_id=job_id,
                    detail="retry_pending_after_service_error",
                )
                return False
            if has_budget and (
                retry_eligible
                or (status == "queued" and attempt_count > 0 and retry_proven)
            ):
                self._checkpoint_attention(
                    batch_id,
                    str(slot["slot_id"]),
                    owner,
                    epoch,
                    "retry_authority_not_verified",
                    service_job_id=job_id,
                )
                return True
        if status == "failed":
            self._checkpoint_slot(
                batch_id,
                str(slot["slot_id"]),
                owner,
                epoch,
                "failed",
                service_job_id=job_id,
                detail=f"service_operation_failed_{error_type}",
            )
            return False
        self._checkpoint_attention(
            batch_id,
            str(slot["slot_id"]),
            owner,
            epoch,
            f"service_operation_failed_{error_type}",
            service_job_id=job_id,
        )
        return status in {"running", "ambiguous"}

    def _checkpoint_slot(
        self,
        batch_id: str,
        slot_id: str,
        owner: str,
        epoch: int,
        coordinator_state: str,
        **values: Any,
    ) -> bool:
        return self._store.checkpoint_generation_batch_slot(
            batch_id=batch_id,
            slot_id=slot_id,
            owner=owner,
            epoch=epoch,
            now=_timestamp(_now()),
            coordinator_state=coordinator_state,
            **values,
        )

    def _checkpoint_attention(
        self,
        batch_id: str,
        slot_id: str,
        owner: str,
        epoch: int,
        detail: str,
        *,
        service_job_id: str | None = None,
    ) -> bool:
        self._checkpoint_slot(
            batch_id,
            slot_id,
            owner,
            epoch,
            "attention_required",
            service_job_id=service_job_id,
            detail=detail,
        )
        return False

    @staticmethod
    def _coordinator_state(report: Mapping[str, object]) -> str:
        if report.get("requires_attention"):
            return "attention_required"
        slots = [
            slot
            for slot in report.get("slots", [])
            if isinstance(slot, Mapping)
        ]
        if any(slot.get("retry_pending") is True for slot in slots):
            return "running"
        statuses = [str(slot.get("execution_status", "unknown")) for slot in slots]
        if statuses and all(status == "succeeded" for status in statuses):
            return "complete"
        if statuses and all(status in _TERMINAL_EXECUTION_STATES for status in statuses):
            return "partial" if "succeeded" in statuses else "failed"
        return "running"

    @staticmethod
    def _report_slot(
        store: SQLiteStore,
        integrity_manager: PublicationManager | None,
        output_root: str | None,
        batch: Mapping[str, object],
        slot: Mapping[str, object],
    ) -> dict[str, object]:
        idempotency_key = str(slot["idempotency_key"])
        accepted = store.find_idempotency_key(idempotency_key)
        recorded_job_id = (
            None if slot["service_job_id"] is None else str(slot["service_job_id"])
        )
        issue: str | None = (
            "coordinator_slot_requires_attention"
            if slot["coordinator_state"] == "attention_required"
            else None
        )
        if output_root is None:
            issue = issue or "batch_execution_identity_invalid"
        if accepted is not None and accepted[1] != str(slot["request_digest"]):
            issue = issue or "batch_service_request_digest_mismatch"
        if recorded_job_id is not None and (
            accepted is None or accepted[0] != recorded_job_id
        ):
            issue = "batch_service_job_mapping_mismatch"
        job_id = recorded_job_id if recorded_job_id is not None else (
            None if accepted is None else accepted[0]
        )
        provenance: Mapping[str, object] | None = None
        if job_id is not None:
            try:
                observed = store.get_provenance(job_id)
                if isinstance(observed, Mapping):
                    provenance = observed
            except Exception:
                issue = issue or "service_provenance_unreadable"

        execution = (
            provenance.get("execution")
            if isinstance(provenance, Mapping)
            else None
        )
        execution_status = (
            str(execution.get("status", provenance.get("status", "unknown")))
            if isinstance(execution, Mapping)
            else "not_accepted"
        )
        if execution_status == "ambiguous":
            issue = issue or f"service_execution_{execution_status}"
        elif job_id is not None and execution_status == "unknown":
            issue = issue or "service_execution_state_unresolved"
        artifact = provenance.get("artifact") if isinstance(provenance, Mapping) else None
        artifact_id = (
            str(artifact.get("artifact_id"))
            if isinstance(artifact, Mapping) and artifact.get("artifact_id") is not None
            else None
        )
        output_slot_id = (
            str(provenance.get("output_slot_id"))
            if isinstance(provenance, Mapping)
            else None
        )
        attempt = provenance.get("attempt") if isinstance(provenance, Mapping) else None
        attempt_id = (
            str(attempt.get("attempt_id"))
            if isinstance(attempt, Mapping) and attempt.get("attempt_id") is not None
            else None
        )
        publication: Mapping[str, object] | None = None
        if artifact_id is not None:
            publication = store.publication_for_artifact(artifact_id)
        if publication is None and job_id is not None and output_root is not None:
            publication = next(
                (
                    record
                    for record in store.publications(output_root)
                    if record.get("job_id") == job_id
                    and (attempt_id is None or record.get("attempt_id") == attempt_id)
                ),
                None,
            )
        if (
            execution_status == "canceled"
            and isinstance(provenance, Mapping)
            and job_id is not None
            and GenerationBatchService._cancellation_has_unresolved_authority(
                store, job_id, provenance, publication
            )
        ):
            issue = issue or "service_canceled_authority_unresolved"
        publication_state = (
            "not_published"
            if publication is None
            else str(publication.get("state", "unknown"))
        )
        integrity_state = "not_applicable"
        lineage_state = "not_applicable"

        if execution_status == "succeeded":
            if not isinstance(artifact, Mapping) or artifact_id is None:
                issue = issue or "success_without_authoritative_artifact"
                integrity_state = "missing"
                lineage_state = "missing"
                publication_state = (
                    "missing" if publication is None else publication_state
                )
            else:
                expected_job_id = str(provenance.get("job_id"))
                expected_output_slot_id = str(provenance.get("output_slot_id"))
                if (
                    str(artifact.get("job_id")) != expected_job_id
                    or str(artifact.get("output_slot_id")) != expected_output_slot_id
                    or (attempt_id is not None and str(artifact.get("attempt_id")) != attempt_id)
                ):
                    issue = issue or "artifact_execution_identity_mismatch"
                    integrity_state = "inconsistent"
                if (
                    publication is None
                    or publication_state != "committed"
                    or output_root is None
                    or str(publication.get("root")) != output_root
                    or str(publication.get("job_id")) != expected_job_id
                    or (
                        attempt_id is not None
                        and str(publication.get("attempt_id")) != attempt_id
                    )
                    or str(publication.get("final_name"))
                    != Path(str(artifact.get("path", ""))).name
                ):
                    issue = issue or "publication_evidence_inconsistent"
                try:
                    lineage = store.get_lineage(artifact_id)
                    expected_parents = [
                        str(item)
                        for item in provenance.get("validated_reference_ids", [])
                    ]
                    observed_parents = [
                        str(edge.get("source_id"))
                        for edge in lineage.get("parents", [])
                        if isinstance(edge, Mapping)
                    ]
                    if observed_parents != expected_parents:
                        lineage_state = "inconsistent"
                        issue = issue or "artifact_lineage_inconsistent"
                    else:
                        lineage_state = "ok"
                except Exception:
                    lineage_state = "missing"
                    issue = issue or "artifact_lineage_missing"
                if publication is None:
                    publication_state = "missing"
                if integrity_manager is None:
                    integrity_state = "unknown"
                    issue = issue or "batch_execution_identity_invalid"
                else:
                    try:
                        inspection = integrity_manager.inspect_integrity(artifact_id)
                        integrity_state = str(inspection.get("status", "unknown"))
                        if integrity_state != "ok":
                            issue = issue or f"artifact_integrity_{integrity_state}"
                    except Exception:
                        integrity_state = "unknown"
                        issue = issue or "artifact_integrity_unavailable"
                if integrity_state == "ok" and lineage_state == "inconsistent":
                    integrity_state = "inconsistent"

        admission = (
            provenance.get("admission")
            if isinstance(provenance, Mapping)
            else None
        )
        admission_decision = (
            str(admission.get("decision"))
            if isinstance(admission, Mapping)
            else None
        )
        if admission_decision in {"quarantined", "blocked", "denied"} or (
            admission_decision == "canceled" and execution_status != "canceled"
        ):
            issue = issue or f"service_admission_{admission_decision}"
        retry_eligible = (
            bool(execution.get("retry_eligible", False))
            if isinstance(execution, Mapping)
            else False
        )
        attempts = provenance.get("attempts", []) if isinstance(provenance, Mapping) else []
        attempt_count = len(attempts) if isinstance(attempts, list) else 0
        attempt_history, attempt_history_valid = (
            GenerationBatchService._safe_attempt_history(attempts)
        )
        if not attempt_history_valid:
            issue = issue or "service_attempt_history_invalid"
        max_attempts = int(slot["max_attempts"])
        retry_proven = (
            isinstance(attempts, list)
            and GenerationBatchService._retry_was_proven(attempts)
        )
        retry_authorized = retry_eligible or (
            execution_status == "queued"
            and admission_decision in {"queued", "not_required"}
        )
        retry_pending = (
            execution_status in {"queued", "failed"}
            and attempt_count < max_attempts
            and isinstance(attempts, list)
            and retry_proven
            and retry_authorized
            and admission_decision in _RETRY_ADMISSION_DECISIONS
        )
        if (
            execution_status in {"queued", "failed"}
            and attempt_count < max_attempts
            and (retry_eligible or retry_proven)
            and not retry_pending
        ):
            issue = issue or "retry_authority_not_verified"
        if execution_status == "queued" and attempt_count >= max_attempts:
            issue = issue or "queued_job_attempt_budget_exhausted"
        return {
            "slot_id": str(slot["slot_id"]),
            "ordinal": int(slot["ordinal"]),
            "output_slot": str(slot["output_slot"]),
            "coordinator_state": str(slot["coordinator_state"]),
            "execution_status": execution_status,
            "retry_eligible": retry_eligible,
            "retry_pending": retry_pending,
            "attempt_count": attempt_count,
            "attempt_history": attempt_history,
            "max_attempts": max_attempts,
            "admission_decision": (
                admission_decision
            ),
            "job_id": job_id,
            "request_id": (
                None
                if not isinstance(provenance, Mapping)
                else provenance.get("request", {}).get("request_id")
            ),
            "output_slot_id": output_slot_id,
            "artifact_id": artifact_id,
            "publication_state": publication_state,
            "artifact_integrity": integrity_state,
            "lineage_state": lineage_state,
            "requires_attention": issue is not None,
            "issue": issue,
        }
