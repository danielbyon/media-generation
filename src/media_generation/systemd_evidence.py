"""Root-owned durable identity and cgroup-proof ledger for systemd attempts."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

from .backend_provenance import canonical_json as backend_canonical_json
from .errors import BackendEvidenceError
from .systemd_attempts import (
    AttemptUnitIdentity,
    CgroupTerminationEvidence,
    identity_digest,
)


_SCHEMA_VERSION = 1
_TABLE_SQL = """CREATE TABLE IF NOT EXISTS systemd_attempt_evidence (
    job_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    identity_json TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    termination_json TEXT,
    termination_at TEXT,
    PRIMARY KEY (job_id, attempt_id)
)"""


class SystemdEvidenceLedger:
    """Keep broker-authored facts outside the worker-writable job database."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().absolute()

    @staticmethod
    def path_for(database_path: Path) -> Path:
        database = Path(database_path).expanduser().absolute()
        evidence_directory = database.parent.parent / "systemd-evidence"
        ledger_name = (
            f"{database.parent.name}-{database.name}.systemd-evidence.sqlite3"
        )
        return evidence_directory / ledger_name

    def _validate_parent(self, *, require_root: bool = True) -> None:
        try:
            info = self.path.parent.lstat()
        except OSError as error:
            raise PermissionError(
                "systemd evidence ledger directory is unavailable"
            ) from error
        self._require_trusted_directory(info, require_root=require_root)

    def initialize(self, *, worker_gid: int | None = None) -> None:
        """Create or validate the root-owned, worker-readable evidence file."""
        self._require_root()
        self._validate_parent()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.close(descriptor)
            info = self.path.lstat()
        self._require_trusted_file(info, require_root=True)
        with sqlite3.connect(self.path, timeout=30, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_TABLE_SQL)
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise BackendEvidenceError("systemd evidence ledger version is unsupported")
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.commit()
        if worker_gid is None:
            os.chmod(self.path, 0o600)
        else:
            os.chown(self.path, 0, worker_gid)
            os.chmod(self.path, 0o640)
        self._require_trusted_file(self.path.lstat(), require_root=True)

    def validate_worker_access(self, worker_gid: int) -> None:
        """Require an existing ledger to be readable by the worker group."""
        self._validate_parent()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return
        self._require_trusted_file(info, require_root=True)
        if info.st_gid != worker_gid or not (info.st_mode & 0o040):
            raise PermissionError(
                "systemd evidence ledger must be readable by the worker group"
            )

    def bind_identity(self, identity: AttemptUnitIdentity) -> None:
        """Pin one unit incarnation before the broker reports it to the worker."""
        self._require_root()
        if not self.path.exists():
            self.initialize()
        self._validate_parent()
        identity_json = backend_canonical_json(identity.to_mapping())
        digest = identity_digest(identity)
        with sqlite3.connect(self.path, timeout=30, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT identity_json, identity_digest
                   FROM systemd_attempt_evidence WHERE job_id = ? AND attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if row is not None:
                if row != (identity_json, digest):
                    raise BackendEvidenceError(
                        "systemd ledger attempt is already bound to another unit"
                    )
                connection.commit()
                return
            connection.execute(
                """INSERT INTO systemd_attempt_evidence
                   (job_id, attempt_id, identity_json, identity_digest)
                   VALUES (?, ?, ?, ?)""",
                (identity.job_id, identity.attempt_id, identity_json, digest),
            )
            connection.commit()

    def record_termination(
        self,
        identity: AttemptUnitIdentity,
        evidence: CgroupTerminationEvidence,
        *,
        timestamp: str,
    ) -> None:
        """Persist only a proof matching the already-pinned root identity."""
        self._require_root()
        self._validate_parent()
        if evidence.identity != identity:
            raise BackendEvidenceError("cgroup proof identity differs from broker ledger")
        identity_json = backend_canonical_json(identity.to_mapping())
        proof_json = backend_canonical_json(evidence.to_mapping())
        with sqlite3.connect(self.path, timeout=30, isolation_level=None) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT identity_json, identity_digest, termination_json
                   FROM systemd_attempt_evidence WHERE job_id = ? AND attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if row is None or row[0] != identity_json or row[1] != identity_digest(identity):
                raise BackendEvidenceError("cgroup proof has no matching root-pinned identity")
            if row[2] is not None:
                if row[2] != proof_json:
                    raise BackendEvidenceError("systemd ledger already contains different proof")
                connection.commit()
                return
            connection.execute(
                """UPDATE systemd_attempt_evidence
                   SET termination_json = ?, termination_at = ?
                   WHERE job_id = ? AND attempt_id = ? AND termination_json IS NULL""",
                (proof_json, timestamp, identity.job_id, identity.attempt_id),
            )
            connection.commit()

    def read_identity(self, job_id: str, attempt_id: str) -> AttemptUnitIdentity | None:
        """Read a root-owned attempt identity without granting write access."""
        row = self._read_row(job_id, attempt_id)
        if row is None:
            return None
        return self._decode_identity(row[0], row[1], job_id, attempt_id)

    def read_termination(
        self, identity: AttemptUnitIdentity
    ) -> CgroupTerminationEvidence | None:
        """Return proof only when identity and proof both match the root ledger."""
        row = self._read_row(identity.job_id, identity.attempt_id)
        if row is None:
            return None
        ledger_identity = self._decode_identity(
            row[0], row[1], identity.job_id, identity.attempt_id
        )
        if ledger_identity != identity or row[2] is None:
            return None
        try:
            proof = CgroupTerminationEvidence.from_mapping(json.loads(row[2]))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError("root systemd termination proof is malformed") from error
        if proof.identity != identity:
            raise BackendEvidenceError("root systemd termination proof identity changed")
        return proof

    def _read_row(
        self, job_id: str, attempt_id: str
    ) -> tuple[str, str, str | None] | None:
        self._validate_parent()
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return None
        self._require_trusted_file(info, require_root=True)
        uri = self.path.as_uri() + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=30) as connection:
                row = connection.execute(
                    """SELECT identity_json, identity_digest, termination_json
                       FROM systemd_attempt_evidence WHERE job_id = ? AND attempt_id = ?""",
                    (job_id, attempt_id),
                ).fetchone()
        except sqlite3.Error as error:
            raise BackendEvidenceError("root systemd evidence ledger is unreadable") from error
        if row is None:
            return None
        return str(row[0]), str(row[1]), None if row[2] is None else str(row[2])

    @staticmethod
    def _decode_identity(
        raw_identity: str, digest: str, job_id: str, attempt_id: str
    ) -> AttemptUnitIdentity:
        try:
            identity = AttemptUnitIdentity.from_mapping(json.loads(raw_identity))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError("root systemd attempt identity is malformed") from error
        if (
            identity.job_id != job_id
            or identity.attempt_id != attempt_id
            or identity_digest(identity) != digest
            or backend_canonical_json(identity.to_mapping()) != raw_identity
        ):
            raise BackendEvidenceError("root systemd attempt identity digest changed")
        return identity

    @staticmethod
    def _require_root() -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise PermissionError("systemd evidence ledger is broker-owned")

    @staticmethod
    def _require_trusted_directory(
        info: os.stat_result, *, require_root: bool = True
    ) -> None:
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or (require_root and info.st_uid != 0)
            or info.st_mode & 0o022
        ):
            raise PermissionError(
                "systemd evidence ledger directory must be root-owned and non-writable"
            )

    @staticmethod
    def _require_trusted_file(info: os.stat_result, *, require_root: bool) -> None:
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or (require_root and info.st_uid != 0)
            or info.st_mode & 0o022
        ):
            raise PermissionError("systemd evidence ledger must be root-owned and non-writable")
