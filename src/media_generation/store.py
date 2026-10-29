"""SQLite persistence for immutable requests and durable execution records."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .admission import is_lightweight_cpu_adapter_id
from .admission_store import (
    AdmissionInspection,
    AdmissionPersistence,
    PendingAdmission,
)
from .domain import (
    GenerationArtifact,
    ImportedArtifact,
    ArtifactSource,
    GenerationAttempt,
    GenerationJob,
    GenerationRequest,
    GenerationRequestRecord,
    ResolvedReference,
)
from .errors import (
    GenerationError,
    IdempotencyConflictError,
    RecordNotFoundError,
    UnknownReferenceError,
)
from .privacy import is_privacy_compliance_record

_RESOLVED_OUTPUT_DIRECTORY_KEY = "_resolved_output_directory"
_MALFORMED_STORED_PRIVACY_EVIDENCE = "stored privacy-compliance evidence is malformed"
_PRIVACY_CLAIM_EVIDENCE_REQUIRED = (
    "protected execution claim requires exact privacy-compliance evidence"
)
_PRIVACY_CLAIM_CONFIGURATION_REQUIRED = (
    "protected execution claim requires exact adapter-configuration evidence"
)
_WRITER_EPOCH = 5
_WRITER_EPOCH_FUNCTION = "media_generation_writer_epoch"
_CURRENT_SCHEMA_VERSION = 5
_WRITER_GUARDS = (
    ("generation_requests", "INSERT"),
    ("generation_jobs", "INSERT"),
    ("generation_jobs", "UPDATE"),
    ("generation_attempts", "INSERT"),
    ("generation_attempts", "UPDATE"),
    ("generation_artifacts", "INSERT"),
    ("artifact_edges", "INSERT"),
    ("artifact_publications", "INSERT"),
    ("artifact_publications", "UPDATE"),
    ("artifact_integrity", "INSERT"),
    ("artifact_integrity", "UPDATE"),
    ("execution_admissions", "INSERT"),
    ("execution_admissions", "UPDATE"),
)


_EXECUTION_JOBS_DDL = """CREATE TABLE execution_jobs (
    job_id TEXT PRIMARY KEY REFERENCES generation_jobs(job_id),
    status TEXT NOT NULL CHECK (status IN (
        'queued','running','succeeded','failed','canceled','ambiguous')),
    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
    containment_contract TEXT,
    privacy_compliance_json TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
    current_attempt_id TEXT REFERENCES generation_attempts(attempt_id),
    retry_eligible INTEGER NOT NULL DEFAULT 0 CHECK (retry_eligible IN (0,1)),
    failure_message TEXT,
    resolved_plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_EXECUTION_ATTEMPTS_DDL = """CREATE TABLE execution_attempts (
    attempt_id TEXT PRIMARY KEY REFERENCES generation_attempts(attempt_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    status TEXT NOT NULL CHECK (status IN (
        'running','succeeded','failed','canceled','ambiguous')),
    owner_id TEXT,
    claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    heartbeat_at TEXT,
    lease_expires_at TEXT,
    process_contained INTEGER
        CHECK (process_contained IS NULL OR process_contained IN (0,1)),
    containment_contract TEXT,
    failure_class TEXT CHECK (failure_class IS NULL OR failure_class IN (
        'retryable','terminal','canceled','ambiguous','crash')),
    termination_proven INTEGER NOT NULL DEFAULT 0
        CHECK (termination_proven IN (0,1)),
    plan_json TEXT,
    completed_at TEXT,
    UNIQUE (job_id, attempt_number)
)"""

_EXECUTION_RESOURCE_DDL = """CREATE TABLE execution_resource (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN ('available','claimed','quarantined')),
    job_id TEXT,
    attempt_id TEXT,
    owner_id TEXT,
    reason TEXT,
    updated_at TEXT NOT NULL
)"""

_ARTIFACT_PUBLICATION_AUTHORITY_DDL = """CREATE TABLE artifact_publication_authority (
    publication_id TEXT PRIMARY KEY REFERENCES artifact_publications(publication_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    attempt_id TEXT NOT NULL REFERENCES execution_attempts(attempt_id),
    owner_id TEXT,
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 0),
    created_at TEXT NOT NULL
)"""

_EXECUTION_ADMISSIONS_DDL = """CREATE TABLE execution_admissions (
    job_id TEXT PRIMARY KEY REFERENCES execution_jobs(job_id),
    admission_profile_json TEXT NOT NULL,
    workload_demand_json TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN (
'queued','not_required','blocked','denied','reserved','released','quarantined','canceled'
    )),
    decision_reason TEXT NOT NULL,
    profile_fingerprint TEXT,
    required_bytes_json TEXT NOT NULL,
    unknown_reasons_json TEXT NOT NULL,
    reserved_bytes_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_EXECUTION_JOBS_QUEUED_INDEX_DDL = """CREATE INDEX execution_jobs_queued_idx
    ON execution_jobs(status, created_at, job_id)"""

_EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL = """CREATE INDEX execution_attempts_running_idx
    ON execution_attempts(job_id, status)"""

_EXECUTION_ADMISSIONS_DISPATCH_INDEX_DDL = """CREATE INDEX execution_admissions_dispatch_idx
    ON execution_admissions(decision, created_at, job_id)"""

_GENERATION_REQUESTS_DDL = """CREATE TABLE generation_requests (
    request_id TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
)"""

_GENERATION_JOBS_DDL = """CREATE TABLE generation_jobs (
    job_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES generation_requests(request_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    adapter_id TEXT NOT NULL,
    adapter_configuration_json TEXT NOT NULL,
    resolved_prompt TEXT NOT NULL,
    resolved_seed INTEGER NOT NULL,
    validated_reference_ids_json TEXT NOT NULL,
    output_slot TEXT NOT NULL,
    output_slot_id TEXT NOT NULL UNIQUE,
    effective_parameters_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_GENERATION_ATTEMPTS_DDL = """CREATE TABLE generation_attempts (
    attempt_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES generation_jobs(job_id),
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    adapter_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error_message TEXT,
    UNIQUE (job_id, attempt_number),
    UNIQUE (job_id, attempt_id)
)"""

_GENERATION_ARTIFACTS_DDL = """CREATE TABLE generation_artifacts (
    artifact_id TEXT PRIMARY KEY,
    job_id TEXT REFERENCES generation_jobs(job_id),
    attempt_id TEXT REFERENCES generation_attempts(attempt_id),
    output_slot_id TEXT,
    path TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    image_format TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('generated', 'imported')),
    import_provenance_json TEXT,
    CHECK ((origin = 'generated' AND job_id IS NOT NULL
        AND attempt_id IS NOT NULL AND output_slot_id IS NOT NULL
        AND import_provenance_json IS NULL)
        OR (origin = 'imported' AND job_id IS NULL
        AND attempt_id IS NULL AND output_slot_id IS NULL
        AND import_provenance_json IS NOT NULL)),
    UNIQUE (job_id, output_slot_id),
    FOREIGN KEY (job_id, attempt_id)
        REFERENCES generation_attempts(job_id, attempt_id)
)"""

_ARTIFACT_EDGES_DDL = """CREATE TABLE artifact_edges (
    source_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
    target_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
    role TEXT NOT NULL CHECK (
        role IN ('reference','source','derivation','inspiration')),
    position INTEGER NOT NULL CHECK (position >= 0),
    CHECK (source_id != target_id),
    PRIMARY KEY (target_id, position),
    UNIQUE (source_id, target_id, role)
)"""

_ARTIFACT_PUBLICATIONS_DDL = """CREATE TABLE artifact_publications (
    publication_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL UNIQUE,
    root TEXT NOT NULL,
    root_dev INTEGER NOT NULL,
    root_ino INTEGER NOT NULL,
    root_token TEXT NOT NULL,
    stage_name TEXT NOT NULL UNIQUE,
    stage_dev INTEGER,
    stage_ino INTEGER,
    final_name TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('allocated','ready','committed','abandoned')),
    job_id TEXT,
    attempt_id TEXT,
    artifact_json TEXT,
    sources_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    error TEXT
)"""

_ARTIFACT_INTEGRITY_DDL = """CREATE TABLE artifact_integrity (
    artifact_id TEXT PRIMARY KEY REFERENCES generation_artifacts(artifact_id),
    status TEXT NOT NULL CHECK (status IN ('ok','missing','corrupt')),
    checked_at TEXT NOT NULL,
    detail TEXT
)"""

_GENERATION_ARTIFACTS_JOB_INDEX_DDL = """CREATE INDEX generation_artifacts_job_idx
    ON generation_artifacts(job_id)"""

_GENERATION_REQUESTS_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER generation_requests_immutable_update
BEFORE UPDATE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END"""

_GENERATION_REQUESTS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_requests_immutable_delete
BEFORE DELETE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END"""

_GENERATION_ARTIFACTS_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER generation_artifacts_immutable_update
BEFORE UPDATE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END"""

_GENERATION_ARTIFACTS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_artifacts_immutable_delete
BEFORE DELETE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END"""

_ARTIFACT_EDGES_ACYCLIC_DDL = """CREATE TRIGGER artifact_edges_acyclic
BEFORE INSERT ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact lineage cycle') WHERE EXISTS (
        WITH RECURSIVE descendants(id) AS (
            SELECT target_id FROM artifact_edges
            WHERE source_id = NEW.target_id
            UNION
            SELECT e.target_id FROM artifact_edges e JOIN descendants d
                ON e.source_id = d.id
        )
        SELECT 1 FROM descendants WHERE id = NEW.source_id
    );
END"""

_ARTIFACT_EDGES_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER artifact_edges_immutable_update
BEFORE UPDATE ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact edges are immutable');
END"""

_ARTIFACT_EDGES_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER artifact_edges_immutable_delete
BEFORE DELETE ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact edges are immutable');
END"""

_ARTIFACT_EDGES_SEALED_DDL = """CREATE TRIGGER artifact_edges_sealed
BEFORE INSERT ON artifact_edges
WHEN NOT EXISTS (
    SELECT 1 FROM artifact_publications
    WHERE artifact_id = NEW.target_id AND state = 'ready'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact lineage is sealed');
END"""

_EXECUTION_TABLE_DDL: dict[str, str] = {
    "execution_jobs": _EXECUTION_JOBS_DDL,
    "execution_attempts": _EXECUTION_ATTEMPTS_DDL,
    "execution_resource": _EXECUTION_RESOURCE_DDL,
    "artifact_publication_authority": _ARTIFACT_PUBLICATION_AUTHORITY_DDL,
    "execution_admissions": _EXECUTION_ADMISSIONS_DDL,
}


_CURRENT_TABLE_DDL: dict[str, str] = {
    "generation_requests": _GENERATION_REQUESTS_DDL,
    "generation_jobs": _GENERATION_JOBS_DDL,
    "generation_attempts": _GENERATION_ATTEMPTS_DDL,
    "generation_artifacts": _GENERATION_ARTIFACTS_DDL,
    "artifact_edges": _ARTIFACT_EDGES_DDL,
    "artifact_publications": _ARTIFACT_PUBLICATIONS_DDL,
    "artifact_integrity": _ARTIFACT_INTEGRITY_DDL,
    **_EXECUTION_TABLE_DDL,
}

_CURRENT_TABLES = frozenset(_CURRENT_TABLE_DDL)

_CURRENT_INDEX_DDL: dict[str, str] = {
    "generation_artifacts_job_idx": _GENERATION_ARTIFACTS_JOB_INDEX_DDL,
    "execution_jobs_queued_idx": _EXECUTION_JOBS_QUEUED_INDEX_DDL,
    "execution_attempts_running_idx": _EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL,
    "execution_admissions_dispatch_idx": _EXECUTION_ADMISSIONS_DISPATCH_INDEX_DDL,
}

_STATIC_TRIGGER_DDL: dict[str, str] = {
    "generation_requests_immutable_update": (
        _GENERATION_REQUESTS_IMMUTABLE_UPDATE_DDL
    ),
    "generation_requests_immutable_delete": (
        _GENERATION_REQUESTS_IMMUTABLE_DELETE_DDL
    ),
    "generation_artifacts_immutable_update": (
        _GENERATION_ARTIFACTS_IMMUTABLE_UPDATE_DDL
    ),
    "generation_artifacts_immutable_delete": (
        _GENERATION_ARTIFACTS_IMMUTABLE_DELETE_DDL
    ),
    "artifact_edges_acyclic": _ARTIFACT_EDGES_ACYCLIC_DDL,
    "artifact_edges_immutable_update": _ARTIFACT_EDGES_IMMUTABLE_UPDATE_DDL,
    "artifact_edges_immutable_delete": _ARTIFACT_EDGES_IMMUTABLE_DELETE_DDL,
    "artifact_edges_sealed": _ARTIFACT_EDGES_SEALED_DDL,
}


@dataclass(frozen=True, slots=True)
class PendingExecution:
    """Identifiers and resolved references returned after a job is committed."""

    created: bool
    request_id: str
    job_id: str
    attempt_id: str
    output_slot_id: str
    references: tuple[ResolvedReference, ...]


@dataclass(frozen=True, slots=True)
class QueuedExecution:
    """One idempotent admission result before any attempt has been claimed."""

    created: bool
    request_id: str
    job_id: str
    status: str
    output_slot_id: str
    max_attempts: int
    references: tuple[ResolvedReference, ...]


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    """Private worker capability returned by one atomic queue claim."""

    job_id: str
    attempt_id: str
    attempt_number: int
    owner_id: str
    claim_epoch: int
    max_attempts: int
    resolved_prompt: str
    resolved_seed: int
    width: int
    height: int
    output_slot: str
    output_slot_id: str
    references: tuple[ResolvedReference, ...]
    adapter_id: str
    adapter_configuration_json: str
    resolved_output_directory: str
    process_contained: bool
    containment_contract: str | None
    lease_expires_at: str


class SQLiteStore:
    """Store generation records in a local SQLite database.

    New databases use the complete current schema. Existing databases are
    opened only after read-only structural validation confirms that exact
    schema; incompatible databases are rejected without mutation. Each
    operation owns a short-lived connection.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.database_path.exists() and self.database_path.stat().st_size:
            self._validate_existing_database()
        else:
            self._initialize()

    @contextmanager
    def _connection(
        self,
        transaction: bool = False,
        *,
        read_transaction: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        if transaction and read_transaction:
            raise ValueError(
                "a connection cannot be both a read and a write transaction"
            )
        connection = sqlite3.connect(str(self.database_path), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        if transaction:
            connection.execute("BEGIN IMMEDIATE")
        elif read_transaction:
            connection.execute("BEGIN DEFERRED")
        try:
            yield connection
            if transaction or read_transaction:
                connection.commit()
        except BaseException:
            if transaction or read_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        """Create the complete current schema in one SQLite transaction."""
        with self._connection(transaction=True) as connection:
            existing_objects = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if existing_objects is not None or version:
                self._validate_current_schema(connection)
                return

            for definition in _CURRENT_TABLE_DDL.values():
                connection.execute(definition)
            for definition in _CURRENT_INDEX_DDL.values():
                connection.execute(definition)
            connection.execute(
                "INSERT INTO execution_resource "
                "(id, state, job_id, attempt_id, owner_id, reason, updated_at) "
                "VALUES (1, 'available', NULL, NULL, NULL, NULL, ?)",
                ("1970-01-01T00:00:00+00:00",),
            )
            for definition in _STATIC_TRIGGER_DDL.values():
                connection.execute(definition)
            self._install_writer_guards(connection)
            connection.execute(f"PRAGMA user_version = {_CURRENT_SCHEMA_VERSION}")
            self._validate_current_schema(connection)

    def _validate_existing_database(self) -> None:
        """Validate an existing database through a read-only connection."""
        connection = sqlite3.connect(
            f"{self.database_path.as_uri()}?mode=ro",
            timeout=30,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            self._validate_current_schema(connection)
        except sqlite3.DatabaseError as error:
            raise RuntimeError(
                "database cannot be opened as a current media-generation "
                "schema; no changes were made"
            ) from error
        finally:
            connection.close()

    @staticmethod
    def _incomplete_schema(detail: str) -> RuntimeError:
        """Build an actionable error for a non-current database layout."""
        return RuntimeError(
            "database schema is incompatible with the current media-generation "
            f"schema: {detail}; no changes were made"
        )

    @staticmethod
    def _normalized_schema_sql(sql: str) -> str:
        """Normalize one complete DDL statement while preserving literals."""
        compact: list[str] = []
        index = 0
        closing_quote: str | None = None

        while index < len(sql):
            character = sql[index]
            if closing_quote is not None:
                compact.append(character)
                if character == closing_quote:
                    if (
                        closing_quote != "]"
                        and index + 1 < len(sql)
                        and sql[index + 1] == closing_quote
                    ):
                        compact.append(sql[index + 1])
                        index += 2
                        continue
                    closing_quote = None
                index += 1
                continue

            if sql.startswith("--", index):
                newline = sql.find("\n", index + 2)
                index = len(sql) if newline < 0 else newline + 1
                continue
            if sql.startswith("/*", index):
                comment_end = sql.find("*/", index + 2)
                if comment_end < 0:
                    raise ValueError("unterminated SQL comment")
                index = comment_end + 2
                continue
            if character in {"'", '"', "`", "["}:
                closing_quote = "]" if character == "[" else character
                compact.append(character)
                index += 1
                continue
            if character.isspace():
                index += 1
                continue
            compact.append(character.lower())
            index += 1

        if closing_quote is not None:
            raise ValueError("unterminated quoted SQL")
        return "".join(compact)

    @staticmethod
    def _validate_current_schema(connection: sqlite3.Connection) -> None:
        """Require the exact supported schema without changing the database."""
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != _CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"unsupported database schema version {version}; "
                f"expected {_CURRENT_SCHEMA_VERSION}; no changes were made"
            )

        objects = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        by_type: dict[str, dict[str, str]] = {
            "table": {},
            "index": {},
            "trigger": {},
            "view": {},
        }
        for row in objects:
            object_type = str(row["type"])
            if object_type in by_type:
                by_type[object_type][str(row["name"])] = str(row["sql"] or "")

        if by_type["view"]:
            raise SQLiteStore._incomplete_schema(
                "unexpected views: " + ", ".join(sorted(by_type["view"]))
            )

        tables = frozenset(by_type["table"])
        missing_tables = sorted(_CURRENT_TABLES - tables)
        unexpected_tables = sorted(tables - _CURRENT_TABLES)
        if missing_tables or unexpected_tables:
            details: list[str] = []
            if missing_tables:
                details.append("missing tables: " + ", ".join(missing_tables))
            if unexpected_tables:
                details.append(
                    "unexpected tables: " + ", ".join(unexpected_tables)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))

        for table, expected_sql in _CURRENT_TABLE_DDL.items():
            try:
                actual_sql = SQLiteStore._normalized_schema_sql(
                    by_type["table"][table]
                )
                normalized_expected = SQLiteStore._normalized_schema_sql(
                    expected_sql
                )
            except ValueError as error:
                raise SQLiteStore._incomplete_schema(
                    f"{table} malformed table definition"
                ) from error
            if actual_sql != normalized_expected:
                raise SQLiteStore._incomplete_schema(
                    f"{table} divergent table definition"
                )

        named_indexes = frozenset(by_type["index"])
        missing_indexes = sorted(
            frozenset(_CURRENT_INDEX_DDL) - named_indexes
        )
        unexpected_indexes = sorted(
            named_indexes - frozenset(_CURRENT_INDEX_DDL)
        )
        if missing_indexes or unexpected_indexes:
            details = []
            if missing_indexes:
                details.append("missing indexes: " + ", ".join(missing_indexes))
            if unexpected_indexes:
                details.append(
                    "unexpected indexes: " + ", ".join(unexpected_indexes)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))
        for index_name, expected_sql in _CURRENT_INDEX_DDL.items():
            actual_sql = SQLiteStore._normalized_schema_sql(
                by_type["index"][index_name]
            )
            if actual_sql != SQLiteStore._normalized_schema_sql(expected_sql):
                raise SQLiteStore._incomplete_schema(
                    f"index {index_name} divergent definition"
                )

        expected_triggers = dict(_STATIC_TRIGGER_DDL)
        for table, operation in _WRITER_GUARDS:
            guard_name, guard_sql = SQLiteStore._writer_guard_sql(
                table, operation
            )
            expected_triggers[guard_name] = guard_sql
        actual_triggers = frozenset(by_type["trigger"])
        missing_triggers = sorted(frozenset(expected_triggers) - actual_triggers)
        unexpected_triggers = sorted(actual_triggers - frozenset(expected_triggers))
        if missing_triggers or unexpected_triggers:
            details = []
            if missing_triggers:
                details.append(
                    "missing triggers: " + ", ".join(missing_triggers)
                )
            if unexpected_triggers:
                details.append(
                    "unexpected triggers: " + ", ".join(unexpected_triggers)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))
        for trigger_name, expected_sql in expected_triggers.items():
            actual_sql = SQLiteStore._normalized_schema_sql(
                by_type["trigger"][trigger_name]
            )
            if actual_sql != SQLiteStore._normalized_schema_sql(expected_sql):
                raise SQLiteStore._incomplete_schema(
                    f"trigger {trigger_name} divergent definition"
                )

        resources = connection.execute(
            "SELECT id, state FROM execution_resource ORDER BY id"
        ).fetchall()
        if (
            len(resources) != 1
            or int(resources[0]["id"]) != 1
            or str(resources[0]["state"])
            not in {"available", "claimed", "quarantined"}
        ):
            raise SQLiteStore._incomplete_schema(
                "execution_resource singleton row missing or invalid"
            )

        missing_execution = connection.execute(
            """SELECT jobs.job_id
               FROM generation_jobs AS jobs
               LEFT JOIN execution_jobs AS execution
                 ON execution.job_id = jobs.job_id
               WHERE execution.job_id IS NULL
               LIMIT 1"""
        ).fetchone()
        if missing_execution is not None:
            raise SQLiteStore._incomplete_schema(
                "generation job lacks execution state: "
                f"{missing_execution['job_id']}"
            )

        missing_admission = connection.execute(
            """SELECT execution.job_id
               FROM execution_jobs AS execution
            LEFT JOIN execution_admissions AS admission
                 ON admission.job_id = execution.job_id
               WHERE admission.job_id IS NULL
               LIMIT 1"""
        ).fetchone()
        if missing_admission is not None:
            raise SQLiteStore._incomplete_schema(
                "execution job lacks admission evidence: "
                f"{missing_admission['job_id']}"
            )

        try:
            AdmissionPersistence.validate_persisted(connection)
        except ValueError as error:
            raise SQLiteStore._incomplete_schema(str(error)) from error

    @staticmethod
    def _writer_guard_sql(table: str, operation: str) -> tuple[str, str]:
        """Return the trigger name and definition for one guarded write."""
        name = f"t04_writer_guard_{table}_{operation.lower()}"
        sql = f"""CREATE TRIGGER {name}
BEFORE {operation} ON {table}
WHEN {_WRITER_EPOCH_FUNCTION}() != {_WRITER_EPOCH}
BEGIN
    SELECT RAISE(ABORT, 'stale media-generation writer');
END"""
        return name, sql

    @classmethod
    def _install_writer_guards(cls, connection: sqlite3.Connection) -> None:
        """Create current writer guards for a newly initialized database."""
        for table, operation in _WRITER_GUARDS:
            name, expected_sql = cls._writer_guard_sql(table, operation)
            existing = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'trigger' AND name = ?",
                (name,),
            ).fetchone()
            if existing is not None:
                raise cls._incomplete_schema(
                    f"writer guard already exists during initialization: {name}"
                )
            connection.execute(expected_sql)

    @staticmethod
    def _insert_sources(connection, artifact_id: str, sources: tuple[ArtifactSource, ...]) -> None:
        for position, source in enumerate(sources):
            connection.execute("INSERT INTO artifact_edges VALUES (?, ?, ?, ?)",
                (source.artifact_id, artifact_id, source.role, position))

    @staticmethod
    def _references_for_job(
        connection: sqlite3.Connection, job_id: str
    ) -> tuple[ResolvedReference, ...]:
        """Reconstruct the ordered reference identities frozen on a job."""
        row = connection.execute(
            "SELECT validated_reference_ids_json FROM generation_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"job not found: {job_id}")
        references: list[ResolvedReference] = []
        for artifact_id in json.loads(str(row["validated_reference_ids_json"])):
            artifact = connection.execute(
                "SELECT artifact_id, sha256, path FROM generation_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if artifact is None:
                raise UnknownReferenceError(f"unknown reference artifact ID: {artifact_id}")
            references.append(
                ResolvedReference(
                    artifact_id=str(artifact["artifact_id"]),
                    content_sha256=str(artifact["sha256"]),
                    path=Path(str(artifact["path"])),
                )
            )
        return tuple(references)

    @staticmethod
    def _resolved_plan_json(
        row: sqlite3.Row,
        references: tuple[ResolvedReference, ...],
    ) -> str:
        """Serialize every run input that must remain frozen before claim."""
        parameters = json.loads(str(row["effective_parameters_json"]))
        return _json(
            {
                "resolved_prompt": str(row["resolved_prompt"]),
                "resolved_seed": int(row["resolved_seed"]),
                "width": int(parameters["width"]),
                "height": int(parameters["height"]),
                "output_slot": str(row["output_slot"]),
                "output_slot_id": str(row["output_slot_id"]),
                "references": [
                    {
                        "artifact_id": reference.artifact_id,
                        "content_sha256": reference.content_sha256,
                        "path": str(reference.path),
                    }
                    for reference in references
                ],
                "resolved_output_directory": (
                    str(Path(parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY]).expanduser().resolve())
                    if isinstance(parameters.get(_RESOLVED_OUTPUT_DIRECTORY_KEY), str)
                    else ""
                ),
            }
        )

    def find_idempotency_key(self, idempotency_key: str) -> tuple[str, str] | None:
        """Return the existing job ID and digest for an idempotency key."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT job_id, request_digest FROM generation_jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return None if row is None else (str(row["job_id"]), str(row["request_digest"]))

    def create_queued_execution(
        self,
        *,
        request: GenerationRequest,
        request_digest: str,
        idempotency_key: str,
        request_id: str,
        job_id: str,
        output_slot_id: str,
        resolved_seed: int,
        adapter_id: str,
        adapter_configuration_json: str,
        privacy_compliance_json: str,
        effective_parameters_json: str,
        resolved_output_directory: str,
        max_attempts: int | None,
        containment_contract: str | None,
        timestamp: str,
        admission: PendingAdmission,
        allow_not_required: bool,
    ) -> QueuedExecution:
        """Atomically persist or reuse a queued job and its admission evidence.

        A new job requires validated ``PendingAdmission`` evidence. Only the
        exact bundled deterministic CPU adapter may receive ``not_required``;
        every other queued job must carry explicit capacity evidence. Reusing
        an existing job preserves the admission and attempt budget recorded
        when that job was created.
        """
        effective_max_attempts = 1 if max_attempts is None else max_attempts
        if (
            isinstance(effective_max_attempts, bool)
            or not isinstance(effective_max_attempts, int)
            or effective_max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        requested_privacy = json.loads(privacy_compliance_json)
        if (
            not is_privacy_compliance_record(requested_privacy)
            or requested_privacy.get("adapter_id") != adapter_id
        ):
            raise ValueError("privacy compliance evidence is malformed")
        if not isinstance(admission, PendingAdmission):
            raise ValueError("admission evidence must be a PendingAdmission")
        AdmissionPersistence.validate_new(
            admission,
            adapter_id,
            allow_not_required=allow_not_required,
        )
        if (
            admission.decision in {"blocked", "denied"}
            and (admission.profile is None or admission.demand is None)
        ):
            raise ValueError(
                "blocked heavyweight admission requires explicit profile and demand evidence"
            )
        with self._connection(transaction=True) as connection:
            existing = connection.execute(
                """SELECT jobs.*, execution.status AS execution_status,
                          execution.max_attempts AS execution_max_attempts,
                          execution.containment_contract,
                          execution.privacy_compliance_json,
                          execution.retry_eligible AS execution_retry_eligible
                   FROM generation_jobs AS jobs
                   JOIN execution_jobs AS execution ON execution.job_id = jobs.job_id
                   WHERE jobs.idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different canonical request intent"
                    )
                if existing["adapter_id"] != adapter_id or json.loads(
                    str(existing["adapter_configuration_json"])
                ) != json.loads(adapter_configuration_json):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different adapter identity or configuration"
                    )
                stored_privacy = _decode_stored_privacy_compliance(
                    existing["privacy_compliance_json"], adapter_id
                )
                if stored_privacy != requested_privacy:
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different privacy-compliance evidence"
                    )
                if (
                    max_attempts is not None
                    and existing["execution_status"] != "succeeded"
                    and int(existing["execution_max_attempts"]) != max_attempts
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different attempt budget"
                    )
                if (
                    existing["containment_contract"] != containment_contract
                    and existing["execution_status"] != "succeeded"
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different containment contract"
                    )
                existing_directory = self._output_directory_for_job(
                    connection,
                    str(existing["job_id"]),
                    str(existing["effective_parameters_json"]),
                )
                if existing_directory != str(
                    Path(resolved_output_directory).expanduser().resolve()
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different or unknown output directory"
                    )
                pinned_admission = AdmissionPersistence.snapshot(
                    connection, str(existing["job_id"])
                )
                proposed_demand = (
                    None if admission.demand is None else admission.demand.to_dict()
                )
                if (
                    pinned_admission is None
                    or pinned_admission.profile_fingerprint
                    != admission.profile_fingerprint
                    or _json(pinned_admission.demand) != _json(proposed_demand)
                    or pinned_admission.required_bytes != admission.required_bytes
                    or pinned_admission.unknown_reasons != admission.unknown_reasons
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different admission evidence"
                    )
                return QueuedExecution(
                    False,
                    str(existing["request_id"]),
                    str(existing["job_id"]),
                    str(existing["execution_status"]),
                    str(existing["output_slot_id"]),
                    int(existing["execution_max_attempts"]),
                    self._references_for_job(connection, str(existing["job_id"])),
                )

            references = self._resolve_references(connection, request.reference_ids)
            parameters = json.loads(effective_parameters_json)
            parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY] = str(
                Path(resolved_output_directory).expanduser().resolve()
            )
            frozen_parameters_json = _json(parameters)
            connection.execute(
                "INSERT INTO generation_requests "
                "(request_id, canonical_json, request_digest, created_at) VALUES (?, ?, ?, ?)",
                (request_id, request.canonical_json(), request_digest, timestamp),
            )
            connection.execute(
                """INSERT INTO generation_jobs (
                    job_id, request_id, idempotency_key, request_digest, status,
                    adapter_id, adapter_configuration_json, resolved_prompt, resolved_seed,
                    validated_reference_ids_json, output_slot, output_slot_id,
                    effective_parameters_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    request_id,
                    idempotency_key,
                    request_digest,
                    adapter_id,
                    adapter_configuration_json,
                    request.prompt,
                    resolved_seed,
                    _json(request.reference_ids),
                    request.output_slot,
                    output_slot_id,
                    frozen_parameters_json,
                    timestamp,
                    timestamp,
                ),
            )
            job_row = connection.execute(
                "SELECT * FROM generation_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            assert job_row is not None
            connection.execute(
                """INSERT INTO execution_jobs
                    (job_id,status,max_attempts,containment_contract,privacy_compliance_json,
                    fence_epoch,current_attempt_id,
                    retry_eligible,failure_message,resolved_plan_json,created_at,updated_at)
                   VALUES (?,'queued',?,?,?,0,NULL,0,NULL,?,?,?)""",
                (
                    job_id,
                    effective_max_attempts,
                    containment_contract,
                    privacy_compliance_json,
                    self._resolved_plan_json(job_row, references),
                    timestamp,
                    timestamp,
                ),
            )
            AdmissionPersistence.insert(
                connection,
                job_id=job_id,
                admission=admission,
                timestamp=timestamp,
            )
            return QueuedExecution(
                True,
                request_id,
                job_id,
                "queued",
                output_slot_id,
                effective_max_attempts,
                references,
            )

    @staticmethod
    def _resolve_references(
        connection: sqlite3.Connection,
        artifact_ids: tuple[str, ...],
    ) -> tuple[ResolvedReference, ...]:
        references: list[ResolvedReference] = []
        for artifact_id in artifact_ids:
            row = connection.execute(
                "SELECT artifact_id, sha256, path FROM generation_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise UnknownReferenceError(f"unknown reference artifact ID: {artifact_id}")
            references.append(
                ResolvedReference(
                    artifact_id=str(row["artifact_id"]),
                    content_sha256=str(row["sha256"]),
                    path=Path(str(row["path"])),
                )
            )
        return tuple(references)

    def create_pending_execution(
        self,
        *,
        request: GenerationRequest,
        request_digest: str,
        idempotency_key: str,
        request_id: str,
        job_id: str,
        attempt_id: str,
        output_slot_id: str,
        resolved_seed: int,
        adapter_id: str,
        adapter_configuration_json: str,
        effective_parameters_json: str,
        resolved_output_directory: str,
        timestamp: str,
    ) -> PendingExecution:
        """Reject the retired pre-queue admission path before it changes rows.

        Callers must use queued admission and a resource-owning claim so that
        every running attempt has durable sidecars and publication authority.
        """
        raise RuntimeError("use queued admission and claim_next_execution")

    def claim_next_execution(
        self,
        *,
        attempt_id: str,
        owner_id: str,
        adapter_id: str,
        resolved_output_directory: str,
        process_contained: bool,
        containment_contract: str | None,
        timestamp: str,
        lease_expires_at: str,
        privacy_compliance_json: str | None = None,
        job_id: str | None = None,
        adapter_configuration_json: str | None = None,
        allow_not_required: bool = False,
    ) -> ExecutionClaim | None:
        """Atomically create one attempt from explicitly admitted queued work.

        The selected row must have current privacy-compliance evidence and an
        admission decision of queued or not_required. Missing admission evidence
        is never treated as an implicit execution grant. Only callers that have
        verified the adapter's exact concrete type may enable ``not_required``.
        """
        requested_directory = str(Path(resolved_output_directory).expanduser().resolve())
        if not isinstance(privacy_compliance_json, str):
            suffix = "" if job_id is None else f": {job_id}"
            raise GenerationError(
                f"{_PRIVACY_CLAIM_EVIDENCE_REQUIRED}{suffix}"
            )
        requested_privacy = json.loads(privacy_compliance_json)
        if (
            not is_privacy_compliance_record(requested_privacy)
            or requested_privacy.get("adapter_id") != adapter_id
        ):
            raise ValueError("privacy compliance evidence malformed")
        with self._connection(transaction=True) as connection:
            resource = connection.execute(
                "SELECT state FROM execution_resource WHERE id = 1"
            ).fetchone()
            if resource is None or resource["state"] != "available":
                return None

            query = """SELECT jobs.*, execution.status AS execution_status,
                execution.max_attempts, execution.fence_epoch,
                execution.containment_contract,
                execution.resolved_plan_json,
                execution.privacy_compliance_json,
                admission.decision AS admission_decision,
                admission.decision_reason AS admission_reason,
        admission.admission_profile_json AS admission_profile_json,
        admission.workload_demand_json AS admission_demand_json,
               admission.profile_fingerprint AS admission_profile_fingerprint,
                admission.required_bytes_json AS admission_required_bytes_json
                FROM generation_jobs AS jobs
                JOIN execution_jobs AS execution
                  ON execution.job_id = jobs.job_id
                JOIN execution_admissions AS admission
                  ON admission.job_id = execution.job_id
                WHERE execution.status = 'queued'
                  AND jobs.adapter_id = ?
                  AND execution.containment_contract IS ?
        AND (
            admission.decision = 'queued'
            OR (? AND admission.decision = 'not_required')
        )
                  AND admission.decision_reason != 'resource_busy'"""
            parameters: list[object] = [
                adapter_id,
                containment_contract,
                int(allow_not_required),
            ]
            if job_id is not None:
                query += " AND jobs.job_id = ?"
                parameters.append(job_id)
            query += " ORDER BY execution.created_at, jobs.job_id"
            candidate = None
            privacy_rejection_job_id: str | None = None
            for row in connection.execute(query, tuple(parameters)).fetchall():
                if str(row["admission_decision"]) == "queued":
                    try:
                        AdmissionPersistence.validate_claim_evidence(
                            row["admission_profile_json"],
                            row["admission_demand_json"],
                    row["admission_profile_fingerprint"],
                row["admission_required_bytes_json"],
                            row["job_id"],
                        )
                    except ValueError as error:
                        raise RuntimeError(str(error)) from error
                if (
                    self._output_directory_for_job(
                        connection,
                        str(row["job_id"]),
                        str(row["effective_parameters_json"]),
                    )
                    != requested_directory
                ):
                    continue
                stored_privacy_json = row["privacy_compliance_json"]
                _decode_stored_privacy_compliance(stored_privacy_json, adapter_id)
                if (
                    adapter_configuration_json is None
                    or str(row["adapter_configuration_json"])
                    != adapter_configuration_json
                ):
                    raise GenerationError(
                        f"{_PRIVACY_CLAIM_CONFIGURATION_REQUIRED}: "
                        f"{row['job_id']}"
                    )
                if stored_privacy_json != privacy_compliance_json:
                    privacy_rejection_job_id = str(row["job_id"])
                    continue
                candidate = row
                break
            if candidate is None:
                if privacy_rejection_job_id is not None:
                    raise GenerationError(
                        f"{_PRIVACY_CLAIM_EVIDENCE_REQUIRED}: "
                        f"{privacy_rejection_job_id}"
                    )
                return None

            last_number = connection.execute(
                "SELECT max(attempt_number) FROM generation_attempts WHERE job_id = ?",
                (candidate["job_id"],),
            ).fetchone()[0] or 0
            attempt_number = int(last_number) + 1
            if attempt_number > int(candidate["max_attempts"]):
                connection.execute(
                    "UPDATE execution_jobs SET status = 'failed', retry_eligible = 0, "
                    "failure_message = 'attempt budget exhausted', updated_at = ? WHERE job_id = ?",
                    (timestamp, candidate["job_id"]),
                )
                return None
            claim_epoch = int(candidate["fence_epoch"]) + 1
            connection.execute(
                "UPDATE generation_jobs SET updated_at = ? WHERE job_id = ?",
                (timestamp, candidate["job_id"]),
            )
            connection.execute(
                """INSERT INTO generation_attempts
                   (attempt_id,job_id,attempt_number,status,adapter_id,
                    started_at,finished_at,error_message)
                   VALUES (?,?,?,'running',?,?,NULL,NULL)""",
                (
                    attempt_id,
                    candidate["job_id"],
                    attempt_number,
                    candidate["adapter_id"],
                    timestamp,
                ),
            )
            plan_json = str(candidate["resolved_plan_json"])
            connection.execute(
                """INSERT INTO execution_attempts
                   (attempt_id,job_id,attempt_number,status,owner_id,claim_epoch,
                    heartbeat_at,lease_expires_at,process_contained,containment_contract,failure_class,
                    termination_proven,plan_json,completed_at)
                   VALUES (?,?,?,'running',?,?,?,?,?,?,NULL,0,?,NULL)""",
                (
                    attempt_id,
                    candidate["job_id"],
                    attempt_number,
                    owner_id,
                    claim_epoch,
                    timestamp,
                    lease_expires_at,
                    int(process_contained),
                    containment_contract,
                    plan_json,
                ),
            )
            connection.execute(
                "UPDATE execution_jobs SET status = 'running', fence_epoch = ?, "
                "current_attempt_id = ?, retry_eligible = 0, failure_message = NULL, "
                "updated_at = ? WHERE job_id = ? AND status = 'queued'",
                (claim_epoch, attempt_id, timestamp, candidate["job_id"]),
            )
            connection.execute(
                """UPDATE execution_resource
                   SET state = 'claimed', job_id = ?, attempt_id = ?, owner_id = ?,
                       reason = NULL, updated_at = ? WHERE id = 1""",
                (candidate["job_id"], attempt_id, owner_id, timestamp),
            )
            if not AdmissionPersistence.reserve(
                connection,
                str(candidate["job_id"]),
                source_decision=str(candidate["admission_decision"]),
                timestamp=timestamp,
                required_bytes_json=str(candidate["admission_required_bytes_json"]),
            ):
                raise RuntimeError("admission reservation transition was rejected")
            plan = json.loads(plan_json)
            references = tuple(
                ResolvedReference(
                    artifact_id=str(item["artifact_id"]),
                    content_sha256=str(item["content_sha256"]),
                    path=Path(str(item["path"])),
                )
                for item in plan["references"]
            )
            return ExecutionClaim(
                job_id=str(candidate["job_id"]),
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                owner_id=owner_id,
                claim_epoch=claim_epoch,
                max_attempts=int(candidate["max_attempts"]),
                resolved_prompt=str(plan["resolved_prompt"]),
                resolved_seed=int(plan["resolved_seed"]),
                width=int(plan["width"]),
                height=int(plan["height"]),
                output_slot=str(plan["output_slot"]),
                output_slot_id=str(plan["output_slot_id"]),
                references=references,
                adapter_id=str(candidate["adapter_id"]),
                adapter_configuration_json=str(candidate["adapter_configuration_json"]),
                resolved_output_directory=str(plan["resolved_output_directory"]),
                process_contained=process_contained,
                containment_contract=containment_contract,
                lease_expires_at=lease_expires_at,
            )

    def cancel_execution(self, job_id: str, timestamp: str) -> str:
        """Durably fence a queued or running execution and report its outcome."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT execution.status AS execution_status,
                          execution.current_attempt_id,
                          resource.state AS resource_state,
                          attempts.status AS attempt_status
                   FROM execution_jobs AS execution
                   JOIN execution_resource AS resource ON resource.id = 1
                   LEFT JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = execution.current_attempt_id
                   WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            if row["execution_status"] in {"succeeded"}:
                return "too_late"
            if row["execution_status"] == "canceled":
                if (
                    row["resource_state"] == "claimed"
                    and row["attempt_status"] == "running"
                ):
                    return "accepted"
                return "acknowledged"
            if row["execution_status"] == "queued":
                connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'canceled', retry_eligible = 0,
                           failure_message = 'canceled before dispatch', updated_at = ?
                       WHERE job_id = ? AND status = 'queued'""",
                    (timestamp, job_id),
                )
                connection.execute(
                    "UPDATE generation_jobs SET status = 'failed', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                AdmissionPersistence.cancel_before_dispatch(connection, job_id, timestamp)
                return "acknowledged"
            if row["execution_status"] == "running":
                connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'canceled', fence_epoch = fence_epoch + 1,
                           retry_eligible = 0,
                           failure_message = 'canceled during adapter invocation',
                           updated_at = ? WHERE job_id = ? AND status = 'running'""",
                    (timestamp, job_id),
                )
                connection.execute(
                    "UPDATE generation_jobs SET status = 'failed', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                return "accepted"
            return "too_late"

    def retry_execution(self, job_id: str, timestamp: str) -> bool:
        """Acknowledge an eligible bounded retry, requeueing it only if needed."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT execution.status, execution.retry_eligible,
                          execution.max_attempts, resource.state AS resource_state,
                          admission.decision AS admission_decision,
                          (SELECT count(*) FROM execution_attempts
                           WHERE job_id = ?) AS attempt_count
                   FROM execution_jobs AS execution
                   JOIN execution_resource AS resource ON resource.id = 1
                JOIN execution_admissions AS admission
                     ON admission.job_id = execution.job_id
                   WHERE execution.job_id = ?""",
                (job_id, job_id),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            if (
                row["status"] not in {"failed", "queued"}
                or not bool(row["retry_eligible"])
                or row["resource_state"] != "available"
                or int(row["attempt_count"]) >= int(row["max_attempts"])
                or row["admission_decision"] is None
            ):
                return False
            if row["status"] == "failed":
                updated = connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'queued', retry_eligible = 0,
                           failure_message = NULL, updated_at = ?
                       WHERE job_id = ? AND status = 'failed'""",
                    (timestamp, job_id),
                )
                if updated.rowcount != 1:
                    return False
                connection.execute(
                    "UPDATE generation_jobs SET status = 'running', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                if row["admission_decision"] != "not_required" and not AdmissionPersistence.requeue_after_safe_retry(
                    connection, job_id, timestamp
                ):
                    raise RuntimeError("admission retry transition was rejected")
            else:
                admission = AdmissionPersistence.snapshot(connection, job_id)
                if admission is None or admission.decision not in {
                "queued",
                "not_required",
            }:
                    return False
            return True

    def resource_snapshot(self) -> dict[str, object]:
        """Return the persisted heavyweight-resource reservation."""
        with self._connection() as connection:
            row = AdmissionPersistence.resource_snapshot(connection)
            if row is None:
                raise RuntimeError("execution resource reservation row is missing")
            return row

    def inspect_admission(self, job_id: str) -> AdmissionInspection | None:
        """Read admission and its owned reservation from one transaction."""
        with self._connection(read_transaction=True) as connection:
            return AdmissionPersistence.inspect(connection, job_id)

    def current_attempt(self, job_id: str) -> dict[str, object] | None:
        """Return private recovery metadata for the current attempt."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT attempts.*, execution.status AS job_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.containment_contract AS job_containment_contract
                   FROM execution_jobs AS execution
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = execution.current_attempt_id
                   WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            return None if row is None else dict(row)

    def assert_attempt_authority(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
    ) -> bool:
        """Read whether a claim is still the job's current publication authority."""
        with self._connection() as connection:
            return self._attempt_authorized(connection, job_id, attempt_id, owner_id, claim_epoch)

    @staticmethod
    def _attempt_authorized(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
    ) -> bool:
        if owner_id is None or claim_epoch is None:
            return False
        return connection.execute(
            """SELECT 1 FROM execution_jobs AS jobs
               JOIN execution_attempts AS attempts
                 ON attempts.attempt_id = jobs.current_attempt_id
               WHERE jobs.job_id = ? AND jobs.current_attempt_id = ?
                 AND jobs.fence_epoch = ? AND attempts.owner_id = ?
                 AND attempts.claim_epoch = ? AND attempts.status = 'running'""",
            (job_id, attempt_id, claim_epoch, owner_id, claim_epoch),
        ).fetchone() is not None

    def renew_attempt(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        claim_epoch: int,
        heartbeat_at: str,
        lease_expires_at: str,
    ) -> bool:
        """Extend one still-current lease and report whether authority remains."""
        with self._connection(transaction=True) as connection:
            if not self._attempt_authorized(
                connection, job_id, attempt_id, owner_id, claim_epoch
            ):
                return False
            updated = connection.execute(
                """UPDATE execution_attempts
                   SET heartbeat_at = ?, lease_expires_at = ?
                   WHERE attempt_id = ? AND job_id = ? AND owner_id = ?
                     AND claim_epoch = ? AND status = 'running'""",
                (heartbeat_at, lease_expires_at, attempt_id, job_id, owner_id, claim_epoch),
            )
            return updated.rowcount == 1

    def complete_execution(
        self, artifact: GenerationArtifact, timestamp: str, *,
        publication_id: str | None = None, sources: tuple[ArtifactSource, ...] = (),
        attempt_owner_id: str | None = None, claim_epoch: int | None = None,
    ) -> None:
        """Commit an artifact and release work only with trusted termination proof.

        A rejected admission completion transition raises before the transaction
        commits, so execution, publication, and resource finalization are atomic.
        """
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                "SELECT status, output_slot_id FROM generation_jobs WHERE job_id = ?", (artifact.job_id,)
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {artifact.job_id}")
            if row["status"] != "running":
                raise RuntimeError(f"job {artifact.job_id} is not running")
            if row["output_slot_id"] != artifact.output_slot_id:
                raise RuntimeError("artifact output slot does not belong to job")
            attempt = connection.execute(
                """SELECT status, containment_contract, owner_id
                   FROM execution_attempts
                   WHERE job_id = ? AND attempt_id = ?""",
                (artifact.job_id, artifact.attempt_id),
            ).fetchone()
            if attempt is None:
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} does not belong to job {artifact.job_id}"
                )
            if attempt["status"] != "running":
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} for job {artifact.job_id} is not running"
                )
            if publication_id is None:
                raise RuntimeError(
                    "generated artifact completion requires a publication journal row"
                )
            if not self._attempt_authorized(
                connection, artifact.job_id, artifact.attempt_id,
                attempt_owner_id, claim_epoch,
            ):
                raise RuntimeError("attempt ownership, epoch, or current-job authority is stale")
            connection.execute(
                """INSERT INTO generation_artifacts (
                    artifact_id, job_id, attempt_id, output_slot_id, path, media_type,
                    image_format, width, height, file_size, sha256, created_at, origin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated')""",
                (
                    artifact.artifact_id,
                    artifact.job_id,
                    artifact.attempt_id,
                    artifact.output_slot_id,
                    artifact.path,
                    artifact.media_type,
                    artifact.image_format,
                    artifact.width,
                    artifact.height,
                    artifact.file_size,
                    artifact.sha256,
                    artifact.created_at,
                ),
            )
            updated_job = connection.execute(
                """UPDATE generation_jobs SET status = 'succeeded', updated_at = ?
                   WHERE job_id = ? AND status = 'running'""",
                (timestamp, artifact.job_id),
            )
            if updated_job.rowcount != 1:
                raise RuntimeError(f"job {artifact.job_id} could not be marked succeeded")
            updated_attempt = connection.execute(
                """UPDATE generation_attempts
                   SET status = 'succeeded', finished_at = ?, error_message = NULL
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (timestamp, artifact.attempt_id, artifact.job_id),
            )
            if updated_attempt.rowcount != 1:
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} for job {artifact.job_id} "
                    "could not be marked succeeded"
                )

            self._insert_sources(connection, artifact.artifact_id, sources)
            if publication_id is not None:
                self._commit_publication_row(
                    connection,
                    publication_id,
                    artifact.artifact_id,
                    attempt_id=artifact.attempt_id,
                    attempt_owner_id=attempt_owner_id,
                    claim_epoch=claim_epoch,
                )
            termination_proven = attempt["containment_contract"] is not None
            connection.execute(
                """UPDATE execution_attempts
                   SET status = 'succeeded', completed_at = ?, failure_class = NULL,
                   termination_proven = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (
                    timestamp,
                    int(termination_proven),
                    artifact.attempt_id,
                    artifact.job_id,
                ),
            )
            connection.execute(
                """UPDATE execution_jobs
                   SET status = 'succeeded', retry_eligible = 0,
                   failure_message = NULL, updated_at = ?
                   WHERE job_id = ? AND status = 'running'""",
                (timestamp, artifact.job_id),
            )
            if termination_proven:
                connection.execute(
                    """UPDATE execution_resource
                       SET state = 'available', job_id = NULL, attempt_id = NULL,
                       owner_id = NULL, reason = NULL, updated_at = ? WHERE id = 1""",
                    (timestamp,),
                )
                admission_state = "released"
                admission_reason = "termination_and_publication_reconciled"
            else:
                connection.execute(
                    """UPDATE execution_resource
                       SET state = 'quarantined', job_id = ?, attempt_id = ?,
                       owner_id = ?, reason = ?, updated_at = ? WHERE id = 1""",
                    (
                        artifact.job_id,
                        artifact.attempt_id,
                        attempt["owner_id"],
                        "successful publication has no trusted process-termination proof",
                        timestamp,
                    ),
                )
                admission_state = "quarantined"
                admission_reason = (
                    "successful publication has no trusted process-termination proof"
                )
            admission_finished = AdmissionPersistence.finish(
                connection,
                artifact.job_id,
                decision=admission_state,
                reason=admission_reason,
                timestamp=timestamp,
            )
            if not admission_finished:
                raise RuntimeError("admission completion transition was rejected")

    @staticmethod
    def _commit_publication_row(
        connection,
        publication_id: str,
        artifact_id: str,
        *,
        attempt_id: str | None = None,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
    ) -> None:
        if attempt_id is not None:
            authority = connection.execute(
                """SELECT job_id, attempt_id, owner_id, claim_epoch
                   FROM artifact_publication_authority WHERE publication_id = ?""",
                (publication_id,),
            ).fetchone()
            if authority is None or authority["attempt_id"] != attempt_id:
                raise RuntimeError("publication authority does not identify this attempt")
            if attempt_owner_id is not None or claim_epoch is not None:
                if (
                    authority["owner_id"] != attempt_owner_id
                    or int(authority["claim_epoch"]) != claim_epoch
                ):
                    raise RuntimeError("publication authority is stale")
        updated = connection.execute(
            "UPDATE artifact_publications SET state = 'committed', error = NULL "
            "WHERE publication_id = ? AND artifact_id = ? AND state = 'ready'",
            (publication_id, artifact_id),
        )
        if updated.rowcount != 1:
            raise RuntimeError("publication is not ready for this artifact")

    def complete_import(self, artifact: ImportedArtifact, publication_id: str,
                        sources: tuple[ArtifactSource, ...]) -> None:
        """Expose an import and all of its lineage in one durable transaction."""
        with self._connection(transaction=True) as connection:
            connection.execute("""INSERT INTO generation_artifacts
                (artifact_id, path, media_type, image_format, width, height, file_size,
                 sha256, created_at, origin, import_provenance_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported', ?)""",
                (artifact.artifact_id, artifact.path, artifact.media_type, artifact.image_format,
                 artifact.width, artifact.height, artifact.file_size, artifact.sha256,
                 artifact.created_at, _json(artifact.to_dict()["import_provenance"])))
            self._insert_sources(connection, artifact.artifact_id, sources)
            self._commit_publication_row(connection, publication_id, artifact.artifact_id)

    def create_publication(
        self,
        record: dict[str, object],
        *,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
    ) -> None:
        """Commit allocation intent before the publisher creates private content."""
        with self._connection(transaction=True) as connection:
            job_id = record.get("job_id")
            attempt_id = record.get("attempt_id")
            if job_id is not None and attempt_id is not None:
                if attempt_owner_id is None or claim_epoch is None:
                    raise RuntimeError("generated publication requires attempt authority")
                if not self._attempt_authorized(
                    connection,
                    str(job_id),
                    str(attempt_id),
                    attempt_owner_id,
                    claim_epoch,
                ):
                    raise RuntimeError("publication intent belongs to a stale attempt")
            fields = tuple(record)
            connection.execute(
                f"INSERT INTO artifact_publications ({','.join(fields)}) "
                f"VALUES ({','.join('?' for _ in fields)})", tuple(record.values()))
            if job_id is not None and attempt_id is not None:
                connection.execute(
                    """INSERT INTO artifact_publication_authority
                       (publication_id,job_id,attempt_id,owner_id,claim_epoch,created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        record["publication_id"],
                        job_id,
                        attempt_id,
                        attempt_owner_id,
                        claim_epoch,
                        record["created_at"],
                    ),
                )

    def update_publication(self, publication_id: str, **values: object) -> None:
        """Update journal metadata without changing its publication lifecycle state."""
        allowed = {"stage_dev", "stage_ino", "final_name", "artifact_json", "error"}
        if not values or not set(values) <= allowed:
            raise ValueError("unsupported publication update")
        with self._connection(transaction=True) as connection:
            self._require_publication_authority(connection, publication_id)
            connection.execute(
                f"UPDATE artifact_publications SET {','.join(key+' = ?' for key in values)} "
                "WHERE publication_id = ? AND state != 'committed'",
                (*values.values(), publication_id))

    def mark_publication_ready(self, publication_id: str, final_name: str,
                               artifact_json: str) -> None:
        """Record validated publication metadata through an allocated-to-ready transition."""
        with self._connection(transaction=True) as connection:
            self._require_publication_authority(connection, publication_id)
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'ready', final_name = ?, "
                "artifact_json = ? WHERE publication_id = ? AND state = 'allocated'",
                (final_name, artifact_json, publication_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("publication is not allocated for the ready transition")

    def abandon_publication(self, publication_id: str, error: str) -> None:
        """Terminally revoke an allocated publication idempotently."""
        with self._connection(transaction=True) as connection:
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'abandoned', error = ? "
                "WHERE publication_id = ? AND state = 'allocated'",
                (error, publication_id),
            )
            if updated.rowcount == 0:
                current = connection.execute(
                    "SELECT state FROM artifact_publications WHERE publication_id = ?",
                    (publication_id,),
                ).fetchone()
                if current is None or current["state"] != "abandoned":
                    raise RuntimeError("publication is not allocated for abandonment")

    def revoke_ready_publication(self, publication_id: str, error: str) -> None:
        """Revoke a ready journal only after its attempt authority has gone stale.

        Recovery uses this transition after cancellation or a fence change has
        made the journal unauthorized but before finalizing the attempt and
        releasing or quarantining the heavyweight resource. It changes only
        SQLite state. Final and staging files remain for the existing T03
        preservation and reconciliation path.
        """
        with self._connection(transaction=True) as connection:
            publication = connection.execute(
                "SELECT state, job_id, artifact_id FROM artifact_publications "
                "WHERE publication_id = ?",
                (publication_id,),
            ).fetchone()
            if publication is None:
                raise RecordNotFoundError(f"publication not found: {publication_id}")
            if publication["state"] == "abandoned":
                return
            if publication["state"] != "ready":
                raise RuntimeError(
                    "publication is not ready for authority-fenced revocation"
                )
            if connection.execute(
                "SELECT 1 FROM generation_artifacts WHERE artifact_id = ?",
                (publication["artifact_id"],),
            ).fetchone() is not None:
                raise RuntimeError("publication already has a committed artifact")

            authority = self._publication_authority(connection, publication_id)
            if authority is None:
                current = publication["job_id"] is None
            else:
                owner_id = (
                    None
                    if authority["owner_id"] is None
                    else str(authority["owner_id"])
                )
                current = self._attempt_authorized(
                    connection,
                    str(authority["job_id"]),
                    str(authority["attempt_id"]),
                    owner_id,
                    int(authority["claim_epoch"]),
                )
            if current:
                raise RuntimeError("publication authority is still current")

            connection.execute(
                "UPDATE artifact_publications SET state = 'abandoned', error = ? "
                "WHERE publication_id = ? AND state = 'ready'",
                (error, publication_id),
            )

    @staticmethod
    def _publication_authority(
        connection: sqlite3.Connection, publication_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM artifact_publication_authority WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()

    def _require_publication_authority(
        self, connection: sqlite3.Connection, publication_id: str
    ) -> None:
        authority = self._publication_authority(connection, publication_id)
        if authority is None:
            return
        owner_id = None if authority["owner_id"] is None else str(authority["owner_id"])
        if not self._attempt_authorized(
            connection,
            str(authority["job_id"]),
            str(authority["attempt_id"]),
            owner_id,
            int(authority["claim_epoch"]),
        ):
            raise RuntimeError("publication attempt authority is stale or canceled")

    def publication_authority_current(self, publication_id: str) -> bool:
        """Report whether a journal's stored attempt still has publication authority."""
        with self._connection() as connection:
            publication = connection.execute(
                "SELECT job_id FROM artifact_publications WHERE publication_id = ?",
                (publication_id,),
            ).fetchone()
            if publication is None:
                return False
            authority = self._publication_authority(connection, publication_id)
            if authority is None:
                # Imports have no generation attempt. A generated journal
                # without authority is historical or incomplete and must be
                # reconciled explicitly before it can publish.
                return publication["job_id"] is None
            owner_id = None if authority["owner_id"] is None else str(authority["owner_id"])
            return self._attempt_authorized(
                connection,
                str(authority["job_id"]),
                str(authority["attempt_id"]),
                owner_id,
                int(authority["claim_epoch"]),
            )

    def publications(self, root: str) -> list[dict[str, object]]:
        """List durable publication decisions for an exact authoritative root."""
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.root = ? ORDER BY publications.created_at""",
                (root,),
            )]

    def publication_for_artifact(self, artifact_id: str) -> dict[str, object] | None:
        """Read the publication journal that owns an artifact, if one exists."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.artifact_id = ?""",
                (artifact_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def publication(self, publication_id: str) -> dict[str, object]:
        """Read the durable decision, including after lost commit acknowledgement."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.publication_id = ?""",
                (publication_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"publication not found: {publication_id}")
        return dict(row)

    def artifacts(self) -> list[GenerationArtifact | ImportedArtifact]:
        """List committed artifact metadata for integrity reconciliation."""
        with self._connection() as connection:
            return [self._artifact_from_row(row) for row in connection.execute(
                "SELECT * FROM generation_artifacts ORDER BY created_at, artifact_id")]

    def record_integrity(self, artifact_id: str, status: str, timestamp: str, detail: str | None) -> None:
        """Keep current observations separately from immutable provenance."""
        with self._connection(transaction=True) as connection:
            connection.execute("""INSERT INTO artifact_integrity VALUES (?, ?, ?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET status=excluded.status,
                checked_at=excluded.checked_at, detail=excluded.detail""",
                (artifact_id, status, timestamp, detail))

    def get_lineage(self, artifact_id: str) -> dict[str, object]:
        """Read directed relationships without changing their historical membership."""
        self.get_artifact(artifact_id)
        with self._connection() as connection:
            parents = [dict(row) for row in connection.execute(
                "SELECT * FROM artifact_edges WHERE target_id = ? ORDER BY position", (artifact_id,))]
            children = [dict(row) for row in connection.execute(
                "SELECT * FROM artifact_edges WHERE source_id = ? ORDER BY target_id, position", (artifact_id,))]
        return {"artifact_id": artifact_id, "parents": parents, "children": children}

    def fail_execution(
        self,
        job_id: str,
        attempt_id: str,
        message: str,
        timestamp: str,
        *,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
        failure_class: str = "terminal",
        termination_proven: bool = False,
        _revoked_publication_id: str | None = None,
    ) -> bool:
        """Finalize one current attempt and apply the durable outcome.

        Stale ownership is a no-op so an old adapter cannot fail a successor.
        A noncanceled attempt without trusted termination proof is reported as
        ambiguous at job level, retains its failure classification, quarantines
        the sole resource, and is never made retryable by this method.
        A rejected admission transition raises before the transaction commits,
        rolling back both execution and resource finalization.
        """
        if failure_class not in {
            "retryable",
            "terminal",
            "canceled",
            "ambiguous",
            "crash",
        }:
            raise ValueError(f"unsupported failure class: {failure_class}")
        with self._connection(transaction=True) as connection:
            current = self._attempt_authorized(
                connection, job_id, attempt_id, attempt_owner_id, claim_epoch
            )
            if not current:
                # Finalization of a canceled or durably revoked journal is a
                # narrower capability than publication. It still requires the
                # actual persisted claim and reservation, never ownerless data.
                if attempt_owner_id is None or claim_epoch is None:
                    return False
                canceled_claim = failure_class == "canceled" and connection.execute(
                    """SELECT 1 FROM execution_jobs AS jobs
                       JOIN execution_attempts AS attempts ON attempts.attempt_id = jobs.current_attempt_id
                       JOIN execution_resource AS resource ON resource.id = 1
                       WHERE jobs.job_id = ? AND jobs.status = 'canceled'
                         AND jobs.fence_epoch = ? + 1 AND attempts.attempt_id = ?
                         AND attempts.owner_id = ? AND attempts.claim_epoch = ?
                         AND resource.job_id = jobs.job_id AND resource.attempt_id = attempts.attempt_id
                         AND resource.owner_id = attempts.owner_id AND resource.state = 'claimed'""",
                    (job_id, claim_epoch, attempt_id, attempt_owner_id, claim_epoch),
                ).fetchone() is not None
                # A revoked journal can finalize only the immediately fenced,
                # still-running job. A newer cancellation must use the explicit
                # canceled capability above, never a stale crash classification.
                revoked_claim = failure_class != "canceled" and _revoked_publication_id is not None and connection.execute(
                    """SELECT 1 FROM artifact_publications AS publications
                       JOIN artifact_publication_authority AS authority USING (publication_id)
                       JOIN execution_jobs AS jobs ON jobs.job_id = authority.job_id
                       JOIN execution_attempts AS attempts ON attempts.attempt_id = jobs.current_attempt_id
                       JOIN execution_resource AS resource ON resource.id = 1
                       WHERE publications.publication_id = ? AND publications.state = 'abandoned'
                         AND authority.job_id = ? AND authority.attempt_id = ?
                         AND authority.owner_id = ? AND authority.claim_epoch = ?
                         AND jobs.status = 'running'
                         AND jobs.fence_epoch = authority.claim_epoch + 1
                         AND attempts.attempt_id = authority.attempt_id
                         AND attempts.owner_id = authority.owner_id AND attempts.claim_epoch = authority.claim_epoch
                         AND resource.job_id = jobs.job_id AND resource.attempt_id = attempts.attempt_id
                         AND resource.owner_id = attempts.owner_id AND resource.state = 'claimed'""",
                    (_revoked_publication_id, job_id, attempt_id, attempt_owner_id, claim_epoch),
                ).fetchone() is not None
                if not canceled_claim and not revoked_claim:
                    return False
            if connection.execute(
                "SELECT 1 FROM artifact_publications WHERE job_id = ? "
                "AND state IN ('ready', 'committed')",
                (job_id,),
            ).fetchone() is not None:
                return False
            attempt = connection.execute(
                """SELECT status FROM execution_attempts
                   WHERE attempt_id = ? AND job_id = ?""",
                (attempt_id, job_id),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                return False
            job = connection.execute(
            """SELECT execution.max_attempts, execution.current_attempt_id,
                      execution.fence_epoch, jobs.adapter_id
               FROM execution_jobs AS execution
               JOIN generation_jobs AS jobs
                 ON jobs.job_id = execution.job_id
               WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            if job is None or job["current_attempt_id"] != attempt_id:
                return False
            number = connection.execute(
                "SELECT attempt_number FROM execution_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()[0]
            retry = (
                termination_proven
                and failure_class in {"retryable", "crash"}
                and int(number) < int(job["max_attempts"])
            )
            execution_status = (
                "canceled"
                if failure_class == "canceled"
                else "ambiguous"
                if failure_class == "ambiguous" or not termination_proven
                else "queued"
                if retry
                else "failed"
            )
            attempt_status = "canceled" if failure_class == "canceled" else "failed"
            connection.execute(
                """UPDATE generation_attempts
                   SET status = 'failed', finished_at = ?, error_message = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (timestamp, message, attempt_id, job_id),
            )
            connection.execute(
                """UPDATE execution_attempts
                   SET status = ?, failure_class = ?, termination_proven = ?,
                       completed_at = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (
                    attempt_status,
                    failure_class,
                    int(termination_proven),
                    timestamp,
                    attempt_id,
                    job_id,
                ),
            )
            connection.execute(
                "UPDATE generation_jobs SET status = ?, updated_at = ? WHERE job_id = ?",
                ("running" if retry else "failed", timestamp, job_id),
            )
            connection.execute(
                """UPDATE execution_jobs
                   SET status = ?, retry_eligible = ?, failure_message = ?,
                       current_attempt_id = ?, updated_at = ?
                   WHERE job_id = ?""",
                (
                    execution_status,
                    int(retry),
                    message,
                    attempt_id,
                    timestamp,
                    job_id,
                ),
            )
            resource_state = (
                "quarantined"
                if failure_class == "ambiguous" or not termination_proven
                else "available"
            )
            connection.execute(
                """UPDATE execution_resource
                   SET state = ?, job_id = ?, attempt_id = ?, owner_id = ?,
                       reason = ?, updated_at = ? WHERE id = 1
                     AND job_id = ? AND attempt_id = ?""",
                (
                    resource_state,
                    job_id if resource_state == "quarantined" else None,
                    attempt_id if resource_state == "quarantined" else None,
                    attempt_owner_id if resource_state == "quarantined" else None,
                    message if resource_state == "quarantined" else None,
                    timestamp,
                    job_id,
                    attempt_id,
                ),
            )
            admission_before_finalize = AdmissionPersistence.snapshot(connection, job_id)
            if admission_before_finalize is None:
                raise RuntimeError("admission failure transition lacks current evidence")
            if resource_state == "quarantined":
                admission_state = "quarantined"
            elif retry:
                admission_state = (
                    "not_required"
                    if is_lightweight_cpu_adapter_id(job["adapter_id"])
                    and not admission_before_finalize.has_capacity_evidence
                    else "queued"
                )
            else:
                admission_state = "released"
            admission_finished = AdmissionPersistence.finish(
                connection,
                job_id,
                decision=admission_state,
                reason=message,
                timestamp=timestamp,
            )
            if not admission_finished:
                raise RuntimeError("admission failure transition was rejected")
            return True

    def get_request(self, request_id: str) -> GenerationRequestRecord:
        """Load an immutable request snapshot by its persisted identity."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM generation_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"request not found: {request_id}")
        payload = json.loads(str(row["canonical_json"]))
        return GenerationRequestRecord(
            request_id=str(row["request_id"]),
            request=GenerationRequest(**payload),
            request_digest=str(row["request_digest"]),
            created_at=str(row["created_at"]),
        )

    def get_job(self, job_id: str) -> GenerationJob:
        """Load job state and its associated artifact identity, if successful."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id,
                          execution.status AS execution_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.retry_eligible, execution.failure_message
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts
                     ON artifacts.job_id = jobs.job_id
                   LEFT JOIN execution_jobs AS execution
                     ON execution.job_id = jobs.job_id
                   WHERE jobs.job_id = ?""",
                (job_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"job not found: {job_id}")
        return self._job_from_row(row)

    def get_resolved_output_directory(self, job_id: str) -> str | None:
        """Return the output directory captured by current job intent."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT effective_parameters_json FROM generation_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            return self._output_directory_for_job(
                connection,
                job_id,
                str(row["effective_parameters_json"]),
            )

    def get_artifact(self, artifact_id: str) -> GenerationArtifact | ImportedArtifact:
        """Load one logical artifact and its persisted file metadata."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM generation_artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"artifact not found: {artifact_id}")
        return self._artifact_from_row(row)

    def get_provenance(self, job_id: str) -> dict[str, object]:
        """Return request, job, attempt history, artifact, and execution state."""
        with self._connection() as connection:
            job_row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id,
                          execution.status AS execution_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.retry_eligible, execution.failure_message,
                          execution.containment_contract,
                          execution.privacy_compliance_json,
                          resource.state AS resource_state,
                          resource.job_id AS resource_job_id,
                          resource.attempt_id AS resource_attempt_id,
                          resource.owner_id AS resource_owner_id
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts
                     ON artifacts.job_id = jobs.job_id
                   LEFT JOIN execution_jobs AS execution
                     ON execution.job_id = jobs.job_id
                   LEFT JOIN execution_resource AS resource ON resource.id = 1
                   WHERE jobs.job_id = ?""",
                (job_id,),
            ).fetchone()
            if job_row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            request_row = connection.execute(
                "SELECT * FROM generation_requests WHERE request_id = ?",
                (job_row["request_id"],),
            ).fetchone()
            assert request_row is not None
            attempt_rows = connection.execute(
                """SELECT attempts.*, execution.status AS execution_status,
                          execution.owner_id, execution.claim_epoch,
                          execution.heartbeat_at, execution.lease_expires_at,
                          execution.process_contained,
                          execution.containment_contract,
                          execution.failure_class, execution.termination_proven
                   FROM generation_attempts AS attempts
                   LEFT JOIN execution_attempts AS execution
                     ON execution.attempt_id = attempts.attempt_id
                   WHERE attempts.job_id = ? ORDER BY attempts.attempt_number""",
                (job_id,),
            ).fetchall()
            artifact_row = connection.execute(
                "SELECT * FROM generation_artifacts WHERE job_id = ?", (job_id,)
            ).fetchone()
            request_payload = json.loads(str(request_row["canonical_json"]))
            request = GenerationRequestRecord(
                request_id=str(request_row["request_id"]),
                request=GenerationRequest(**request_payload),
                request_digest=str(request_row["request_digest"]),
                created_at=str(request_row["created_at"]),
            )
            job = self._job_from_row(job_row)
            job_payload = job.to_dict()
            attempts = tuple(self._attempt_from_row(row) for row in attempt_rows)
            artifact = None if artifact_row is None else self._artifact_from_row(artifact_row)
            execution_status = (
                str(job_row["execution_status"])
                if "execution_status" in job_row.keys() and job_row["execution_status"] is not None
                else job.status
            )
            privacy_compliance = _stored_privacy_compliance(job_row, job.adapter_id)
            admission_record = AdmissionPersistence.snapshot(connection, job_id)
            return {
                "job_id": job.job_id,
                "request": request.to_dict(),
                "status": execution_status,
                "adapter_id": job.adapter_id,
                "adapter_configuration": job_payload["adapter_configuration"],
                "privacy_compliance": privacy_compliance,
                "resolved_prompt": job.resolved_prompt,
                "resolved_seed": job.resolved_seed,
                "validated_reference_ids": list(job.validated_reference_ids),
                "output_slot": job.output_slot,
                "output_slot_id": job.output_slot_id,
                "effective_parameters": job_payload["effective_parameters"],
                "attempt": None if not attempts else attempts[-1].to_dict(),
                "attempts": [attempt.to_dict() for attempt in attempts],
                "artifact": None if artifact is None else artifact.to_dict(),
                "admission": (
                    None if admission_record is None else admission_record.to_dict()
                ),
                "execution": {
                    "status": execution_status,
                    "max_attempts": int(job_row["max_attempts"] or 1),
                    "fence_epoch": int(job_row["fence_epoch"] or 0),
                    "retry_eligible": bool(job_row["retry_eligible"] or 0),
                    "failure_message": job_row["failure_message"],
                    "containment_contract": job_row["containment_contract"],
                    "resource_state": str(job_row["resource_state"] or "available"),
                    "resource_job_id": job_row["resource_job_id"],
                    "resource_attempt_id": job_row["resource_attempt_id"],
                    "resource_owner_id": job_row["resource_owner_id"],
                },
            }

    @staticmethod
    def _output_directory_for_job(
        connection: sqlite3.Connection,
        job_id: str,
        effective_parameters_json: str,
    ) -> str | None:
        """Return the output directory captured in current job intent."""
        del connection, job_id
        effective_parameters = json.loads(effective_parameters_json)
        output_directory = effective_parameters.get(_RESOLVED_OUTPUT_DIRECTORY_KEY)
        if not isinstance(output_directory, str) or not output_directory:
            return None
        return str(Path(output_directory).expanduser().resolve())

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> GenerationJob:
        effective_parameters = json.loads(str(row["effective_parameters_json"]))
        effective_parameters.pop(_RESOLVED_OUTPUT_DIRECTORY_KEY, None)
        columns = row.keys()
        execution_status = (
            str(row["execution_status"])
            if "execution_status" in columns and row["execution_status"] is not None
            else str(row["status"])
        )
        return GenerationJob(
            job_id=str(row["job_id"]),
            request_id=str(row["request_id"]),
            status=str(row["status"]),
            adapter_id=str(row["adapter_id"]),
            adapter_configuration=json.loads(str(row["adapter_configuration_json"])),
            resolved_prompt=str(row["resolved_prompt"]),
            resolved_seed=int(row["resolved_seed"]),
            validated_reference_ids=tuple(json.loads(str(row["validated_reference_ids_json"]))),
            output_slot=str(row["output_slot"]),
            output_slot_id=str(row["output_slot_id"]),
            effective_parameters=effective_parameters,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            artifact_id=None if row["artifact_id"] is None else str(row["artifact_id"]),
            max_attempts=int(row["max_attempts"] or 1) if "max_attempts" in columns else 1,
            fence_epoch=int(row["fence_epoch"] or 0) if "fence_epoch" in columns else 0,
            execution_status=execution_status,
            retry_eligible=(
                bool(row["retry_eligible"])
                if "retry_eligible" in columns and row["retry_eligible"] is not None
                else False
            ),
            failure_message=(
                str(row["failure_message"])
                if "failure_message" in columns and row["failure_message"] is not None
                else None
            ),
        )

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> GenerationAttempt:
        columns = row.keys()
        return GenerationAttempt(
            attempt_id=str(row["attempt_id"]),
            job_id=str(row["job_id"]),
            attempt_number=int(row["attempt_number"]),
            status=(
                str(row["execution_status"])
                if "execution_status" in columns and row["execution_status"] is not None
                else str(row["status"])
            ),
            adapter_id=str(row["adapter_id"]),
            started_at=str(row["started_at"]),
            finished_at=None if row["finished_at"] is None else str(row["finished_at"]),
            error_message=None if row["error_message"] is None else str(row["error_message"]),
            owner_id=(
                str(row["owner_id"])
                if "owner_id" in columns and row["owner_id"] is not None
                else None
            ),
            claim_epoch=(
                int(row["claim_epoch"])
                if "claim_epoch" in columns and row["claim_epoch"] is not None
                else 0
            ),
            heartbeat_at=(
                str(row["heartbeat_at"])
                if "heartbeat_at" in columns and row["heartbeat_at"] is not None
                else None
            ),
            lease_expires_at=(
                str(row["lease_expires_at"])
                if "lease_expires_at" in columns and row["lease_expires_at"] is not None
                else None
            ),
            process_contained=(
                bool(row["process_contained"])
                if "process_contained" in columns and row["process_contained"] is not None
                else None
            ),
            containment_contract=(
                str(row["containment_contract"])
                if "containment_contract" in columns and row["containment_contract"] is not None
                else None
            ),
            failure_class=(
                str(row["failure_class"])
                if "failure_class" in columns and row["failure_class"] is not None
                else None
            ),
            termination_proven=(
                bool(row["termination_proven"])
                if "termination_proven" in columns and row["termination_proven"] is not None
                else False
            ),
        )

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> GenerationArtifact | ImportedArtifact:
        if row["origin"] == "imported":
            return ImportedArtifact(
                artifact_id=row["artifact_id"], path=row["path"], media_type=row["media_type"],
                image_format=row["image_format"], width=row["width"], height=row["height"],
                file_size=row["file_size"], sha256=row["sha256"], created_at=row["created_at"],
                import_provenance=json.loads(row["import_provenance_json"]))
        return GenerationArtifact(
            artifact_id=str(row["artifact_id"]),
            job_id=str(row["job_id"]),
            attempt_id=str(row["attempt_id"]),
            output_slot_id=str(row["output_slot_id"]),
            path=str(row["path"]),
            media_type=str(row["media_type"]),
            image_format=str(row["image_format"]),
            width=int(row["width"]),
            height=int(row["height"]),
            file_size=int(row["file_size"]),
            sha256=str(row["sha256"]),
            created_at=str(row["created_at"]),
        )


def _decode_stored_privacy_compliance(
    raw: object,
    adapter_id: str,
) -> dict[str, object]:
    """Decode non-NULL durable evidence or reject it as malformed."""
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError) as error:
        raise GenerationError(_MALFORMED_STORED_PRIVACY_EVIDENCE) from error
    if not is_privacy_compliance_record(payload) or payload.get("adapter_id") != adapter_id:
            raise GenerationError(_MALFORMED_STORED_PRIVACY_EVIDENCE)
    return payload


def _stored_privacy_compliance(
    row: sqlite3.Row,
    adapter_id: str,
) -> dict[str, object]:
    """Decode the required durable privacy evidence for a current job."""
    return _decode_stored_privacy_compliance(
        row["privacy_compliance_json"], adapter_id
    )


def _json(value: object) -> str:
    """Serialize a stored value using the canonical JSON conventions."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
