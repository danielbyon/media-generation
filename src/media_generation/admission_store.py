"""Transactional persistence for capacity-admission evidence.

The execution store owns the shared SQLite connection and heavyweight resource
claim. This module keeps admission rows and their allowed lifecycle transitions
behind a small interface used inside those existing transactions.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from .admission import (
    AdmissionProfile,
    WorkloadDemand,
    evaluate_admission,
    is_lightweight_cpu_adapter_id,
    parse_admission_profile,
    parse_workload_demand,
)
from .inventory.schema import InventoryValidationError


_TRANSITION_SOURCES: dict[str, tuple[str, ...]] = {
    "reserved": ("queued", "not_required"),
    "not_required": ("reserved", "released"),
    "canceled": ("queued", "not_required", "blocked", "denied"),
    "queued": ("reserved", "released"),
    "released": ("reserved",),
    "quarantined": ("reserved",),
}

_MAX_SQLITE_BYTE_COUNT = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class PendingAdmission:
    """Validated admission evidence supplied when creating a queued job."""

    profile: AdmissionProfile | None
    demand: WorkloadDemand | None
    decision: str
    reason: str
    required_bytes: dict[str, int] = field(default_factory=dict)
    unknown_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed evidence before any execution row is written."""
        if self.profile is not None and not isinstance(self.profile, AdmissionProfile):
            raise ValueError("admission profile must be an AdmissionProfile or None")
        if self.demand is not None and not isinstance(self.demand, WorkloadDemand):
            raise ValueError("workload demand must be a WorkloadDemand or None")
        if self.decision not in {
            "queued",
            "not_required",
            "blocked",
            "denied",
        }:
            raise ValueError("new execution admission decision is invalid")
        if self.decision == "queued" and (
            self.profile is None or self.demand is None
        ):
            raise ValueError(
                "queued admission requires both a capacity profile and workload demand"
            )
        if self.decision == "not_required" and (
            self.profile is not None or self.demand is not None
        ):
            raise ValueError(
                "not_required admission cannot include capacity evidence"
            )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("admission reason must be a non-empty string")
        if not isinstance(self.required_bytes, dict) or any(
            not isinstance(pool_id, str)
            or not pool_id
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for pool_id, value in self.required_bytes.items()
        ):
            raise ValueError(
                "required bytes must map pool IDs to non-negative byte counts"
            )
        if any(
            not isinstance(reason, str) or not reason.strip()
            for reason in self.unknown_reasons
        ):
            raise ValueError("unknown reasons must contain non-empty strings")

    @classmethod
    def not_required(cls) -> "PendingAdmission":
        """Return the exemption for the trusted deterministic CPU adapter."""
        return cls(
            profile=None,
            demand=None,
            decision="not_required",
            reason="lightweight_deterministic_cpu",
        )

    @property
    def profile_fingerprint(self) -> str | None:
        """Return the pinned profile identity when one was supplied."""
        return None if self.profile is None else self.profile.fingerprint

    def with_decision(self, decision: str, reason: str) -> "PendingAdmission":
        """Return the same pinned evidence with a store-resolved decision reason."""
        return PendingAdmission(
            profile=self.profile,
            demand=self.demand,
            decision=decision,
            reason=reason,
            required_bytes=self.required_bytes,
            unknown_reasons=self.unknown_reasons,
        )

    def persisted_values(self) -> tuple[str, str, str, str]:
        """Serialize cohesive evidence for the execution-admission row."""
        profile_json = _canonical_json(
            None if self.profile is None else self.profile.to_dict()
        )
        demand_json = _canonical_json(
            None if self.demand is None else self.demand.to_dict()
        )
        required_bytes_json = _canonical_json(self.required_bytes)
        unknown_reasons_json = _canonical_json(list(self.unknown_reasons))
        return profile_json, demand_json, required_bytes_json, unknown_reasons_json


@dataclass(frozen=True, slots=True)
class AdmissionRecord:
    """Typed snapshot of one job's persisted admission evidence."""

    job_id: str
    decision: str
    reason: str
    profile_fingerprint: str | None
    profile: dict[str, object] | None
    demand: dict[str, object] | None
    required_bytes: dict[str, int]
    unknown_reasons: tuple[str, ...]
    reserved_bytes: dict[str, int] | None
    created_at: str
    updated_at: str

    @property
    def has_capacity_evidence(self) -> bool:
        """Return whether a capacity profile or workload demand was pinned."""
        return self.profile is not None or self.demand is not None

    def to_dict(self) -> dict[str, object]:
        """Return the stable public JSON representation of this evidence."""
        return {
            "job_id": self.job_id,
            "decision": self.decision,
            "reason": self.reason,
            "profile_fingerprint": self.profile_fingerprint,
            "profile": self.profile,
            "demand": self.demand,
            "required_bytes": dict(self.required_bytes),
            "unknown_reasons": list(self.unknown_reasons),
            "reserved_bytes": (
                None
                if self.reserved_bytes is None
                else dict(self.reserved_bytes)
            ),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class AdmissionInspection:
    """One consistent admission-and-reservation view for a persisted job."""

    admission: AdmissionRecord
    resource: dict[str, object] | None

    def to_dict(self) -> dict[str, object]:
        """Return the stable CLI response shape."""
        return {"admission": self.admission.to_dict(), "resource": self.resource}


class AdmissionPersistence:
    """Insert, transition, and project admission evidence on one transaction."""

    @staticmethod
    def validate_new(
        admission: PendingAdmission,
        adapter_id: str,
        *,
        allow_not_required: bool,
    ) -> None:
        """Reject producer and evidence combinations that cannot be dispatched."""
        if admission.decision == "queued":
            AdmissionPersistence.validate_pending_evidence(admission)
        if (
            admission.decision == "not_required"
            and (
                not allow_not_required
                or not is_lightweight_cpu_adapter_id(adapter_id)
            )
        ):
            raise ValueError(
                "not_required admission is reserved for the exact lightweight CPU adapter"
            )

    @staticmethod
    def validate_pending_evidence(admission: PendingAdmission) -> None:
        """Validate typed queued evidence before an execution row is created."""
        if admission.decision != "queued":
            return
        profile = admission.profile
        demand = admission.demand
        if profile is None or demand is None:
            raise ValueError(
                "queued admission requires both a capacity profile and workload demand"
            )
        AdmissionPersistence.validate_claim_evidence(
            _canonical_json(profile.to_dict()),
            _canonical_json(demand.to_dict()),
            admission.profile_fingerprint,
            _canonical_json(admission.required_bytes),
            "new admission",
        )

    @staticmethod
    def validate_claim_evidence(
        profile_json: object,
        demand_json: object,
        profile_fingerprint: object,
        required_bytes_json: object,
        job_id: object,
    ) -> None:
        """Validate typed pinned evidence and identity before dispatch."""
        try:
            raw_profile = _optional_object(profile_json)
            raw_demand = _optional_object(demand_json)
        except (TypeError, ValueError) as error:
            raise ValueError("queued admission evidence is malformed") from error
        if raw_profile is None or raw_demand is None:
            raise ValueError(
                "queued admission lacks pinned profile and workload demand: "
                f"{job_id}"
            )
        try:
            profile = parse_admission_profile(raw_profile)
            demand = parse_workload_demand(raw_demand)
        except (InventoryValidationError, ValueError) as error:
            raise ValueError(f"queued admission evidence is invalid: {error}") from error
        if profile.status != "ready" or demand.unknown_reasons:
            raise ValueError(
                f"queued admission evidence is not dispatchable: {job_id}"
            )
        if profile_fingerprint != profile.fingerprint:
            raise ValueError(
                "queued admission profile fingerprint does not match pinned "
                f"evidence: {job_id}"
            )
        decision = evaluate_admission(profile, demand)
        if decision.status != "queued":
            raise ValueError(
                "queued admission capacity decision does not match pinned "
                f"evidence: {job_id}"
            )
        required_bytes = _required_bytes(required_bytes_json, job_id=job_id)
        if required_bytes != decision.required_bytes:
            raise ValueError(
                "queued admission required bytes do not match the capacity "
                f"decision: {job_id}"
            )

    @staticmethod
    def validate_persisted(connection: sqlite3.Connection) -> None:
        """Validate queued evidence and capacity-exempt adapter identity."""
        rows = connection.execute(
            """SELECT admission.job_id, admission.decision,
                      admission.admission_profile_json,
                      admission.workload_demand_json,
                      admission.profile_fingerprint,
                      admission.required_bytes_json,
                      jobs.adapter_id
               FROM execution_admissions AS admission
               JOIN generation_jobs AS jobs ON jobs.job_id = admission.job_id"""
        ).fetchall()
        for row in rows:
            decision = str(row["decision"])
            if decision == "queued":
                AdmissionPersistence.validate_claim_evidence(
                    row["admission_profile_json"],
                    row["workload_demand_json"],
                    row["profile_fingerprint"],
                    row["required_bytes_json"],
                    row["job_id"],
                )
            if decision == "not_required":
                if not is_lightweight_cpu_adapter_id(str(row["adapter_id"])):
                    raise ValueError(
                        "not_required admission is not limited to the lightweight "
                        f"CPU adapter: {row['job_id']}"
                    )
                if (
                    _optional_object(row["admission_profile_json"]) is not None
                    or _optional_object(row["workload_demand_json"]) is not None
                ):
                    raise ValueError(
                        "not_required admission cannot include capacity evidence: "
                        f"{row['job_id']}"
                    )
            # Reservation and terminal transitions replace ``not_required``;
            # absent capacity evidence preserves its CPU-bound lineage.
            if (
                decision in {"reserved", "released", "quarantined"}
                and _optional_object(row["admission_profile_json"]) is None
                and _optional_object(row["workload_demand_json"]) is None
                and not is_lightweight_cpu_adapter_id(str(row["adapter_id"]))
            ):
                raise ValueError(
                    "not_required admission is not limited to the lightweight "
                    f"CPU adapter: {row['job_id']}"
                )

    @staticmethod
    def insert(
        connection: sqlite3.Connection,
        *,
        job_id: str,
        admission: PendingAdmission,
        timestamp: str,
    ) -> None:
        """Insert the pinned decision while its execution job is created."""
        if not isinstance(admission, PendingAdmission):
            raise ValueError("admission evidence must be a PendingAdmission")
        AdmissionPersistence.validate_pending_evidence(admission)
        profile_json, demand_json, required_bytes_json, unknown_reasons_json = (
            admission.persisted_values()
        )
        connection.execute(
            """INSERT INTO execution_admissions (
                job_id, admission_profile_json, workload_demand_json,
                decision, decision_reason, profile_fingerprint,
                required_bytes_json, unknown_reasons_json,
                reserved_bytes_json, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,NULL,?,?)""",
            (
                job_id,
                profile_json,
                demand_json,
                admission.decision,
                admission.reason,
                admission.profile_fingerprint,
                required_bytes_json,
                unknown_reasons_json,
                timestamp,
                timestamp,
            ),
        )

    @staticmethod
    def reserve(
        connection: sqlite3.Connection,
        job_id: str,
        *,
        source_decision: str,
        required_bytes_json: str,
        timestamp: str,
    ) -> bool:
        """Bind the admitted bytes to the atomic singleton claim."""
        reason = (
            "resource_reserved"
            if source_decision == "queued"
            else "lightweight_admission_not_required"
        )
        return AdmissionPersistence._transition(
            connection,
            job_id,
            decision="reserved",
            reason=reason,
            timestamp=timestamp,
            reserved_bytes_json=required_bytes_json,
        )

    @staticmethod
    def cancel_before_dispatch(
        connection: sqlite3.Connection, job_id: str, timestamp: str
    ) -> bool:
        """Close an undispatched admission without changing its reservation."""
        return AdmissionPersistence._transition(
            connection,
            job_id,
            decision="canceled",
            reason="canceled before dispatch",
            timestamp=timestamp,
        )

    @staticmethod
    def requeue_after_safe_retry(
        connection: sqlite3.Connection, job_id: str, timestamp: str
    ) -> bool:
        """Return a reconciled retry to the dispatch queue."""
        return AdmissionPersistence._transition(
            connection,
            job_id,
            decision="queued",
            reason="safe_retry_eligible",
            timestamp=timestamp,
        )

    @staticmethod
    def finish(
        connection: sqlite3.Connection,
        job_id: str,
        *,
        decision: str,
        reason: str,
        timestamp: str,
    ) -> bool:
        """Record a completed, quarantined, or safely retryable claim outcome."""
        return AdmissionPersistence._transition(
            connection,
            job_id,
            decision=decision,
            reason=reason,
            timestamp=timestamp,
        )

    @staticmethod
    def snapshot(
        connection: sqlite3.Connection, job_id: str
    ) -> AdmissionRecord | None:
        """Project one current admission row, or None when it is absent."""
        row = connection.execute(
            "SELECT * FROM execution_admissions WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        reserved_bytes_json = row["reserved_bytes_json"]
        return AdmissionRecord(
            job_id=str(row["job_id"]),
            decision=str(row["decision"]),
            reason=str(row["decision_reason"]),
            profile_fingerprint=row["profile_fingerprint"],
            profile=_optional_object(row["admission_profile_json"]),
            demand=_optional_object(row["workload_demand_json"]),
            required_bytes=json.loads(str(row["required_bytes_json"])),
            unknown_reasons=tuple(json.loads(str(row["unknown_reasons_json"]))),
            reserved_bytes=(
                None
                if reserved_bytes_json is None
                else json.loads(str(reserved_bytes_json))
            ),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    @staticmethod
    def resource_snapshot(connection: sqlite3.Connection) -> dict[str, object] | None:
        """Project the singleton resource and current attempt claim evidence."""
        row = connection.execute(
            """SELECT resource.*, attempt.claim_epoch AS claim_epoch,
                      attempt.lease_expires_at AS lease_expires_at,
                      admission.decision AS admission_decision,
                      admission.decision_reason AS admission_reason,
                      admission.profile_fingerprint AS admission_profile_fingerprint,
                      admission.workload_demand_json AS admission_demand_json,
                      admission.reserved_bytes_json AS admission_reserved_bytes_json
               FROM execution_resource AS resource
               LEFT JOIN execution_attempts AS attempt
                 ON attempt.job_id = resource.job_id
                AND attempt.attempt_id = resource.attempt_id
               LEFT JOIN execution_admissions AS admission
                 ON admission.job_id = resource.job_id
               WHERE resource.id = 1"""
        ).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def inspect(
        connection: sqlite3.Connection, job_id: str
    ) -> AdmissionInspection | None:
        """Read one job's admission and owned reservation from one transaction."""
        admission = AdmissionPersistence.snapshot(connection, job_id)
        if admission is None:
            return None
        resource = AdmissionPersistence.resource_snapshot(connection)
        if resource is not None and resource.get("job_id") != job_id:
            resource = None
        return AdmissionInspection(admission=admission, resource=resource)

    @staticmethod
    def _transition(
        connection: sqlite3.Connection,
        job_id: str,
        *,
        decision: str,
        reason: str,
        timestamp: str,
        reserved_bytes_json: str | None = None,
    ) -> bool:
        """Apply one allowed state change inside the caller's transaction.

        A queued admission requires its execution row to be queued in the same
        transaction. This prevents admission evidence from exposing work as
        claimable while execution still reports a failed retry boundary.
        """
        sources = _TRANSITION_SOURCES.get(decision)
        if sources is None:
            raise ValueError(f"unsupported admission transition: {decision}")
        assignments = ["decision = ?", "decision_reason = ?", "updated_at = ?"]
        parameters: list[object] = [decision, reason, timestamp]
        if reserved_bytes_json is not None:
            assignments.append("reserved_bytes_json = ?")
            parameters.append(reserved_bytes_json)
        execution_status_guard = ""
        if decision == "queued":
            execution_status_guard = (
                " AND EXISTS ("
                "SELECT 1 FROM execution_jobs AS execution "
                "WHERE execution.job_id = execution_admissions.job_id "
                "AND execution.status = 'queued'"
                ")"
            )
        placeholders = ", ".join("?" for _ in sources)
        parameters.extend((job_id, *sources))
        updated = connection.execute(
            f"""UPDATE execution_admissions
                SET {', '.join(assignments)}
                WHERE job_id = ? AND decision IN ({placeholders})
                {execution_status_guard}""",
            tuple(parameters),
        )
        return updated.rowcount == 1


def _canonical_json(value: object) -> str:
    """Serialize admission persistence values deterministically."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _optional_object(raw: object) -> dict[str, object] | None:
    """Decode optional capacity evidence and normalize an empty object to None."""
    decoded = json.loads(str(raw))
    if decoded is None or decoded == {}:
        return None
    if not isinstance(decoded, dict):
        raise ValueError("stored admission evidence must be an object or null")
    return decoded


def _required_bytes(raw: object, *, job_id: object) -> dict[str, int]:
    """Decode one pinned pool-to-byte reservation without coercion."""
    try:
        decoded = json.loads(str(raw))
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"queued admission required bytes are malformed: {job_id}"
        ) from error
    if not isinstance(decoded, dict):
        raise ValueError(
            f"queued admission required bytes are malformed: {job_id}"
        )
    result: dict[str, int] = {}
    for pool_id, value in decoded.items():
        if (
            not isinstance(pool_id, str)
            or not pool_id
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > _MAX_SQLITE_BYTE_COUNT
        ):
            raise ValueError(
                f"queued admission required bytes are malformed: {job_id}"
            )
        result[pool_id] = value
    return result
