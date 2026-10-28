"""Transactional persistence for capacity-admission evidence.

The execution store owns the shared SQLite connection and heavyweight resource
claim. This module keeps admission rows and their allowed lifecycle transitions
behind a small interface used inside those existing transactions.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from .admission import AdmissionProfile, WorkloadDemand


_TRANSITION_SOURCES: dict[str, tuple[str, ...]] = {
    "reserved": ("queued", "legacy"),
    "canceled": ("queued", "blocked", "denied", "legacy"),
    "queued": ("reserved", "released"),
    "released": ("reserved",),
    "quarantined": ("reserved",),
}


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
        if self.decision not in {"queued", "blocked", "denied", "legacy"}:
            raise ValueError("new execution admission decision is invalid")
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
    def legacy(cls) -> "PendingAdmission":
        """Return the explicit evidence used when admission is not configured."""
        return cls(
            profile=None,
            demand=None,
            decision="legacy",
            reason="admission_not_configured",
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
            {} if self.profile is None else self.profile.to_dict()
        )
        demand_json = _canonical_json(
            {} if self.demand is None else self.demand.to_dict()
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
            else "legacy_admission_not_configured"
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
        """Project current evidence or identify a pre-schema historical job."""
        row = connection.execute(
            "SELECT * FROM execution_admissions WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            job = connection.execute(
                "SELECT created_at, updated_at FROM generation_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if job is None:
                return None
            return AdmissionRecord(
                job_id=job_id,
                decision="unrecorded",
                reason="legacy_admission_not_recorded",
                profile_fingerprint=None,
                profile=None,
                demand=None,
                required_bytes={},
                unknown_reasons=(),
                reserved_bytes=None,
                created_at=str(job["created_at"]),
                updated_at=str(job["updated_at"]),
            )
        return AdmissionRecord(
            job_id=str(row["job_id"]),
            decision=str(row["decision"]),
            reason=str(row["decision_reason"]),
            profile_fingerprint=row["profile_fingerprint"],
            profile=json.loads(str(row["admission_profile_json"])),
            demand=json.loads(str(row["workload_demand_json"])),
            required_bytes=json.loads(str(row["required_bytes_json"])),
            unknown_reasons=tuple(json.loads(str(row["unknown_reasons_json"]))),
            reserved_bytes=(
                None
                if row["reserved_bytes_json"] is None
                else json.loads(str(row["reserved_bytes_json"]))
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
