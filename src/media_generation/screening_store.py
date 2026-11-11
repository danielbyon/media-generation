"""Durable, versioned storage for character-screening runs and case leases."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Mapping


_SCHEMA_VERSION = 1
_TERMINAL_CASE_STATUSES = frozenset(
    {"succeeded", "failed", "unsupported", "ambiguous", "canceled"}
)
_CASE_STATUSES = frozenset(
    {
        "pending",
        "in_progress",
        "queued",
        "running",
        "succeeded",
        "failed",
        "unsupported",
        "blocked",
        "interrupted",
        "ambiguous",
        "canceled",
    }
)


class ScreeningStoreError(RuntimeError):
    """The benchmark ledger is missing, incompatible, or internally invalid."""


class ScreeningRunNotFoundError(ScreeningStoreError):
    """A requested benchmark run does not exist in the ledger."""


class ScreeningClaimLostError(ScreeningStoreError):
    """A case update was attempted by an expired or superseded runner claim."""


@dataclass(frozen=True, slots=True)
class CaseClaim:
    """A temporary, durable lease that fences one runner's case updates."""

    run_id: str
    case_id: str
    owner_id: str
    claim_epoch: int


class ScreeningLedger:
    """Store frozen benchmark inputs separately from GenerationService state.

    Transactions cover only ledger reads and writes. A runner releases the
    transaction before it invokes GenerationService, while a renewable lease
    and claim epoch prevent another process from advancing that case.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self, *, transaction: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            str(self.database_path), timeout=30, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        if transaction:
            connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            if transaction:
                connection.commit()
        except BaseException:
            if transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection(transaction=True) as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if version == 0 and not tables:
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                return
            if version != _SCHEMA_VERSION:
                raise ScreeningStoreError(
                    f"unsupported screening ledger schema version: {version}"
                )
            if tables != {"screening_runs", "screening_cases"}:
                raise ScreeningStoreError("screening ledger tables do not match schema version 1")

    def create_run(
        self,
        *,
        run_id: str,
        manifest_json: str,
        manifest_sha256: str,
        execution_identity_json: str,
        execution_identity_sha256: str,
        fixture_fingerprint: str,
        profile_fingerprint: str,
        selected_variant_json: str,
        protocol_id: str,
        cases: list[Mapping[str, object]],
        now: float,
    ) -> None:
        """Commit the run snapshot and every request before any admission."""
        case_ids = [str(case["case_id"]) for case in cases]
        keys = [str(case["idempotency_key"]) for case in cases]
        if len(case_ids) != len(set(case_ids)) or len(keys) != len(set(keys)):
            raise ScreeningStoreError("run contains duplicate case identities or idempotency keys")
        with self._connection(transaction=True) as connection:
            connection.execute(
                """INSERT INTO screening_runs (
                    run_id, schema_version, protocol_id, manifest_json,
                    manifest_sha256, execution_identity_json,
                    execution_identity_sha256, fixture_fingerprint,
                    profile_fingerprint, selected_variant_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    _SCHEMA_VERSION,
                    protocol_id,
                    manifest_json,
                    manifest_sha256,
                    execution_identity_json,
                    execution_identity_sha256,
                    fixture_fingerprint,
                    profile_fingerprint,
                    selected_variant_json,
                    now,
                ),
            )
            for position, case in enumerate(cases):
                connection.execute(
                    """INSERT INTO screening_cases (
                        run_id, position, case_id, source_case_id, kind, label,
                        definition_json, request_json, request_digest,
                        operation_intent, idempotency_key, status, created_at,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)""",
                    (
                        run_id,
                        position,
                        str(case["case_id"]),
                        str(case["source_case_id"]),
                        str(case["kind"]),
                        str(case["label"]),
                        _json(case),
                        _json(case["request"]),
                        str(case["request_digest"]),
                        str(case["operation_intent"]),
                        str(case["idempotency_key"]),
                        now,
                        now,
                    ),
                )

    def get_run(self, run_id: str) -> dict[str, object]:
        """Return one immutable run definition and its identity fingerprints."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM screening_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise ScreeningRunNotFoundError(f"screening run not found: {run_id}")
        result = dict(row)
        for source, target in (
            ("manifest_json", "manifest"),
            ("execution_identity_json", "execution_identity"),
            ("selected_variant_json", "selected_model_variant"),
        ):
            result[target] = json.loads(str(result[source]))
        return result

    def list_cases(self, run_id: str) -> list[dict[str, object]]:
        """Return the frozen case inputs and latest durable observations."""
        self.get_run(run_id)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM screening_cases WHERE run_id = ? ORDER BY position",
                (run_id,),
            ).fetchall()
        return [self._decode_case(row) for row in rows]

    def claim_case(
        self,
        run_id: str,
        case_id: str,
        owner_id: str,
        *,
        now: float,
        lease_seconds: float,
    ) -> CaseClaim | None:
        """Acquire or recover one case using a durable SQLite fencing epoch."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT status, claim_owner, claim_epoch, lease_expires_at
                FROM screening_cases WHERE run_id = ? AND case_id = ?""",
                (run_id, case_id),
            ).fetchone()
            if row is None:
                raise ScreeningStoreError(f"screening case not found: {case_id}")
            if str(row["status"]) in _TERMINAL_CASE_STATUSES:
                return None
            lease_expires_at = row["lease_expires_at"]
            if lease_expires_at is not None and float(lease_expires_at) > now:
                return None
            epoch = int(row["claim_epoch"]) + 1
            connection.execute(
                """UPDATE screening_cases
                SET claim_owner = ?, claim_epoch = ?, lease_expires_at = ?,
                    status = 'in_progress', updated_at = ?
                WHERE run_id = ? AND case_id = ?""",
                (owner_id, epoch, now + lease_seconds, now, run_id, case_id),
            )
            return CaseClaim(run_id, case_id, owner_id, epoch)

    def renew_claim(
        self, claim: CaseClaim, *, now: float, lease_seconds: float
    ) -> bool:
        """Renew a live claim without keeping a transaction open afterward."""
        with self._connection(transaction=True) as connection:
            result = connection.execute(
                """UPDATE screening_cases SET lease_expires_at = ?, updated_at = ?
                WHERE run_id = ? AND case_id = ? AND claim_owner = ?
                    AND claim_epoch = ? AND lease_expires_at > ?""",
                (
                    now + lease_seconds,
                    now,
                    claim.run_id,
                    claim.case_id,
                    claim.owner_id,
                    claim.claim_epoch,
                    now,
                ),
            )
            return result.rowcount == 1

    def mark_submission_started(self, claim: CaseClaim, *, now: float) -> None:
        """Persist the admission boundary before calling GenerationService."""
        self._update_claimed(
            claim,
            now,
            """UPDATE screening_cases SET status = 'in_progress',
                submission_started = 1, started_at = COALESCE(started_at, ?),
                updated_at = ?
            WHERE run_id = ? AND case_id = ? AND claim_owner = ? AND claim_epoch = ?
                AND lease_expires_at > ?""",
            (now, now, claim.run_id, claim.case_id, claim.owner_id, claim.claim_epoch, now),
        )

    def set_case_status(
        self,
        claim: CaseClaim,
        status: str,
        *,
        now: float,
        execution_status: str | None = None,
        execution_succeeded: bool | None = None,
        request_id: str | None = None,
        job_id: str | None = None,
        attempt_ids: list[str] | None = None,
        artifact_id: str | None = None,
        artifact_integrity: Mapping[str, object] | None = None,
        service_evidence: Mapping[str, object] | None = None,
        admission: Mapping[str, object] | None = None,
        error_code: str | None = None,
        reason: str | None = None,
    ) -> None:
        """Record one outcome only while the runner still owns the live claim."""
        if status not in _CASE_STATUSES:
            raise ScreeningStoreError(f"unsupported screening case status: {status}")
        if execution_succeeded not in {None, True, False}:
            raise ScreeningStoreError("execution_succeeded must be boolean or null")
        values = (
            status,
            execution_status,
            None if execution_succeeded is None else int(execution_succeeded),
            request_id,
            job_id,
            _json(attempt_ids) if attempt_ids is not None else None,
            artifact_id,
            _json(artifact_integrity) if artifact_integrity is not None else None,
            _json(service_evidence) if service_evidence is not None else None,
            _json(admission) if admission is not None else None,
            error_code,
            reason,
            now,
            claim.run_id,
            claim.case_id,
            claim.owner_id,
            claim.claim_epoch,
            now,
        )
        self._update_claimed(
            claim,
            now,
            """UPDATE screening_cases SET status = ?, execution_status = ?,
                execution_succeeded = ?, request_id = COALESCE(?, request_id),
                job_id = COALESCE(?, job_id), attempt_ids_json = COALESCE(?, attempt_ids_json),
                artifact_id = COALESCE(?, artifact_id),
                artifact_integrity_json = COALESCE(?, artifact_integrity_json),
                service_evidence_json = COALESCE(?, service_evidence_json),
                admission_json = COALESCE(?, admission_json), error_code = ?,
                reason = ?, updated_at = ?
            WHERE run_id = ? AND case_id = ? AND claim_owner = ? AND claim_epoch = ?
                AND lease_expires_at > ?""",
            values,
        )

    def update_artifact_integrity(
        self, run_id: str, case_id: str, observation: Mapping[str, object], *, now: float
    ) -> None:
        """Refresh integrity evidence without changing execution outcome."""
        with self._connection(transaction=True) as connection:
            result = connection.execute(
                """UPDATE screening_cases SET artifact_integrity_json = ?, updated_at = ?
                WHERE run_id = ? AND case_id = ?""",
                (_json(observation), now, run_id, case_id),
            )
            if result.rowcount != 1:
                raise ScreeningStoreError(f"screening case not found: {case_id}")

    def release_claim(self, claim: CaseClaim, *, now: float) -> None:
        """Release one current claim after execution or a handled refusal."""
        with self._connection(transaction=True) as connection:
            connection.execute(
                """UPDATE screening_cases SET claim_owner = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE run_id = ? AND case_id = ? AND claim_owner = ? AND claim_epoch = ?""",
                (now, claim.run_id, claim.case_id, claim.owner_id, claim.claim_epoch),
            )

    def _update_claimed(
        self,
        claim: CaseClaim,
        now: float,
        statement: str,
        values: tuple[object, ...],
    ) -> None:
        with self._connection(transaction=True) as connection:
            result = connection.execute(statement, values)
            if result.rowcount != 1:
                raise ScreeningClaimLostError(
                    f"screening case claim was lost: {claim.case_id}"
                )

    @staticmethod
    def _decode_case(row: sqlite3.Row) -> dict[str, object]:
        result = dict(row)
        result["definition"] = json.loads(str(result["definition_json"]))
        result["request"] = json.loads(str(result["request_json"]))
        for source, target in (
            ("attempt_ids_json", "attempt_ids"),
            ("artifact_integrity_json", "artifact_integrity"),
            ("service_evidence_json", "service_evidence"),
            ("admission_json", "admission"),
        ):
            raw = result.get(source)
            result[target] = None if raw is None else json.loads(str(raw))
        return result


def _json(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as error:
        raise ScreeningStoreError("screening ledger values must be finite JSON") from error


_SCHEMA = (
    """CREATE TABLE screening_runs (
        run_id TEXT PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        protocol_id TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        manifest_sha256 TEXT NOT NULL,
        execution_identity_json TEXT NOT NULL,
        execution_identity_sha256 TEXT NOT NULL,
        fixture_fingerprint TEXT NOT NULL,
        profile_fingerprint TEXT NOT NULL,
        selected_variant_json TEXT NOT NULL,
        created_at REAL NOT NULL
    )""",
    """CREATE TABLE screening_cases (
        run_id TEXT NOT NULL REFERENCES screening_runs(run_id),
        position INTEGER NOT NULL,
        case_id TEXT NOT NULL,
        source_case_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        label TEXT NOT NULL,
        definition_json TEXT NOT NULL,
        request_json TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        operation_intent TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK (status IN (
            'pending','in_progress','queued','running','succeeded','failed',
            'unsupported','blocked','interrupted','ambiguous','canceled'
        )),
        execution_status TEXT,
        execution_succeeded INTEGER CHECK (execution_succeeded IN (0,1) OR execution_succeeded IS NULL),
        request_id TEXT,
        job_id TEXT,
        attempt_ids_json TEXT,
        artifact_id TEXT,
        artifact_integrity_json TEXT,
        service_evidence_json TEXT,
        admission_json TEXT,
        error_code TEXT,
        reason TEXT,
        submission_started INTEGER NOT NULL DEFAULT 0 CHECK (submission_started IN (0,1)),
        started_at REAL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        claim_owner TEXT,
        claim_epoch INTEGER NOT NULL DEFAULT 0,
        lease_expires_at REAL,
        PRIMARY KEY (run_id, case_id),
        UNIQUE (run_id, position)
    )""",
    """CREATE TRIGGER screening_runs_identity_immutable
    BEFORE UPDATE OF run_id, schema_version, protocol_id, manifest_json,
        manifest_sha256, execution_identity_json, execution_identity_sha256,
        fixture_fingerprint, profile_fingerprint, selected_variant_json
    ON screening_runs BEGIN
        SELECT RAISE(ABORT, 'screening run identity is immutable');
    END""",
    """CREATE TRIGGER screening_cases_identity_immutable
    BEFORE UPDATE OF run_id, position, case_id, source_case_id, kind, label,
        definition_json, request_json, request_digest, operation_intent,
        idempotency_key
    ON screening_cases BEGIN
        SELECT RAISE(ABORT, 'screening case identity is immutable');
    END""",
)
