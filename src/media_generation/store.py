"""SQLite persistence for immutable requests and durable execution records."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

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
from .errors import IdempotencyConflictError, RecordNotFoundError, UnknownReferenceError

_RESOLVED_OUTPUT_DIRECTORY_KEY = "_resolved_output_directory"
_WRITER_EPOCH = 3
_WRITER_EPOCH_FUNCTION = "media_generation_writer_epoch"
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
)


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

    Each operation owns a short-lived connection. A pending job and its first
    attempt commit together before the service invokes an adapter.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self, transaction: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.database_path), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
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
        """Create or upgrade the complete schema in one transaction."""
        with self._connection(transaction=True) as connection:
            self._execute_script(
                connection,
                """
                CREATE TABLE IF NOT EXISTS generation_requests (
                    request_id TEXT PRIMARY KEY,
                    canonical_json TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS generation_jobs (
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
                );

                CREATE TABLE IF NOT EXISTS generation_attempts (
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
                );

                CREATE TABLE IF NOT EXISTS generation_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES generation_jobs(job_id),
                    attempt_id TEXT NOT NULL REFERENCES generation_attempts(attempt_id),
                    output_slot_id TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    media_type TEXT NOT NULL,
                    image_format TEXT NOT NULL,
                    width INTEGER NOT NULL,
                    height INTEGER NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (job_id, output_slot_id),
                    FOREIGN KEY (job_id, attempt_id)
                        REFERENCES generation_attempts(job_id, attempt_id)
                );

                CREATE INDEX IF NOT EXISTS generation_artifacts_job_idx
                    ON generation_artifacts(job_id);

                CREATE TRIGGER IF NOT EXISTS generation_requests_immutable_update
                BEFORE UPDATE ON generation_requests
                BEGIN
                    SELECT RAISE(ABORT, 'generation requests are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS generation_requests_immutable_delete
                BEFORE DELETE ON generation_requests
                BEGIN
                    SELECT RAISE(ABORT, 'generation requests are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS generation_artifacts_immutable_update
                BEFORE UPDATE ON generation_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'generation artifacts are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS generation_artifacts_immutable_delete
                BEFORE DELETE ON generation_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'generation artifacts are immutable');
                END;
                """
            )

            self._migrate_artifacts(connection)

    @staticmethod
    def _execute_script(connection: sqlite3.Connection, script: str) -> None:
        """Execute a SQL script without SQLite's implicit transaction commit."""
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                if statement.strip():
                    connection.execute(statement)
                statement = ""
        if statement.strip():
            connection.execute(statement)

    def _migrate_artifacts(self, connection: sqlite3.Connection) -> None:
        """Upgrade the original T01 schema atomically without rewriting its records.

        Imported artifacts share the same identity namespace and file metadata,
        but have no generation job or attempt. Existing generated JSON stays
        unchanged; the discriminator is a persistence detail for those records.
        """
        with nullcontext(connection) as connection:
            columns = {row["name"] for row in connection.execute(
                "PRAGMA table_info(generation_artifacts)"
            )}
            if "origin" not in columns:
                connection.execute("""CREATE TABLE generation_artifacts_v2 (
                    artifact_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES generation_jobs(job_id),
                    attempt_id TEXT REFERENCES generation_attempts(attempt_id),
                    output_slot_id TEXT,
                    path TEXT NOT NULL UNIQUE,
                    media_type TEXT NOT NULL, image_format TEXT NOT NULL,
                    width INTEGER NOT NULL, height INTEGER NOT NULL,
                    file_size INTEGER NOT NULL, sha256 TEXT NOT NULL,
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
                )""")
                connection.execute("""INSERT INTO generation_artifacts_v2
                    SELECT *, 'generated', NULL FROM generation_artifacts""")
                connection.execute("DROP TABLE generation_artifacts")
                connection.execute("ALTER TABLE generation_artifacts_v2 RENAME TO generation_artifacts")
            connection.execute("""CREATE INDEX IF NOT EXISTS generation_artifacts_job_idx
                ON generation_artifacts(job_id)""")
            for operation in ("UPDATE", "DELETE"):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS
                    generation_artifacts_immutable_{operation.lower()}
                    BEFORE {operation} ON generation_artifacts BEGIN
                    SELECT RAISE(ABORT, 'generation artifacts are immutable'); END""")
            connection.execute("""CREATE TABLE IF NOT EXISTS artifact_edges (
                source_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
                target_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
                role TEXT NOT NULL CHECK (role IN ('reference','source','derivation','inspiration')),
                position INTEGER NOT NULL CHECK (position >= 0),
                CHECK (source_id != target_id),
                PRIMARY KEY (target_id, position),
                UNIQUE (source_id, target_id, role)
            )""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS artifact_edges_acyclic
                BEFORE INSERT ON artifact_edges BEGIN
                SELECT RAISE(ABORT, 'artifact lineage cycle') WHERE EXISTS (
                    WITH RECURSIVE descendants(id) AS (
                        SELECT target_id FROM artifact_edges WHERE source_id = NEW.target_id
                        UNION SELECT e.target_id FROM artifact_edges e JOIN descendants d
                        ON e.source_id = d.id
                    ) SELECT 1 FROM descendants WHERE id = NEW.source_id
                ); END""")
            for operation in ("UPDATE", "DELETE"):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS
                    artifact_edges_immutable_{operation.lower()}
                    BEFORE {operation} ON artifact_edges BEGIN
                    SELECT RAISE(ABORT, 'artifact edges are immutable'); END""")
            connection.execute("""CREATE TABLE IF NOT EXISTS artifact_publications (
                publication_id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL UNIQUE,
                root TEXT NOT NULL, root_dev INTEGER NOT NULL, root_ino INTEGER NOT NULL,
                root_token TEXT NOT NULL,
                stage_name TEXT NOT NULL UNIQUE, stage_dev INTEGER, stage_ino INTEGER,
                final_name TEXT, state TEXT NOT NULL
                    CHECK (state IN ('allocated','ready','committed','abandoned')),
                job_id TEXT, attempt_id TEXT, artifact_json TEXT, sources_json TEXT NOT NULL,
                created_at TEXT NOT NULL, error TEXT
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS artifact_integrity (
                artifact_id TEXT PRIMARY KEY REFERENCES generation_artifacts(artifact_id),
                status TEXT NOT NULL CHECK (status IN ('ok','missing','corrupt')),
                checked_at TEXT NOT NULL, detail TEXT
            )""")
            # T01 already froze reference membership and order in each job.
            # Backfill these historical relationships once, in the migration.
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version < 2:
                for row in connection.execute("""SELECT a.artifact_id,
                    j.validated_reference_ids_json FROM generation_artifacts a
                    JOIN generation_jobs j ON j.job_id = a.job_id""").fetchall():
                    self._insert_sources(connection, row["artifact_id"], tuple(
                        ArtifactSource(item) for item in json.loads(row["validated_reference_ids_json"])
                    ))
                connection.execute("PRAGMA user_version = 2")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS artifact_edges_sealed
                BEFORE INSERT ON artifact_edges
                WHEN NOT EXISTS (SELECT 1 FROM artifact_publications
                    WHERE artifact_id = NEW.target_id AND state = 'ready')
                BEGIN SELECT RAISE(ABORT, 'artifact lineage is sealed'); END""")
            self._migrate_execution(connection)

    def _migrate_execution(self, connection: sqlite3.Connection) -> None:
        """Add version-3 execution sidecars without rewriting historical rows.

        T01 and T03 tables retain their original columns, row identities, JSON,
        and image bytes. Runtime queue state, attempt ownership, and publication
        authority live in dependent tables so historical ``SELECT *`` behavior
        remains compatible.
        """
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version > 3:
            raise RuntimeError(f"unsupported database schema version: {version}")
        if version == 3:
            required = {
                "execution_jobs",
                "execution_attempts",
                "execution_resource",
                "artifact_publication_authority",
            }
            present = {
                str(row["name"])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            missing = sorted(required - present)
            if missing:
                raise RuntimeError(
                    "database schema version 3 is incomplete; missing: "
                    + ", ".join(missing)
                )
            resource = connection.execute(
                "SELECT state FROM execution_resource WHERE id = 1"
            ).fetchone()
            if resource is None or resource["state"] not in {
                "available",
                "claimed",
                "quarantined",
            }:
                raise RuntimeError(
                    "database schema version 3 incomplete; "
                    "execution_resource singleton row is missing or invalid"
                )
            self._install_writer_guards(connection)
            self._assert_all_jobs_have_execution_state(connection)
            return

        statements = (
            """CREATE TABLE execution_jobs (
                job_id TEXT PRIMARY KEY REFERENCES generation_jobs(job_id),
                status TEXT NOT NULL CHECK (status IN (
                    'queued','running','succeeded','failed','canceled','ambiguous')),
                max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
                containment_contract TEXT,
                fence_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
                current_attempt_id TEXT REFERENCES generation_attempts(attempt_id),
                retry_eligible INTEGER NOT NULL DEFAULT 0 CHECK (retry_eligible IN (0,1)),
                failure_message TEXT,
                resolved_plan_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE INDEX execution_jobs_queued_idx
                ON execution_jobs(status, created_at, job_id)""",
            """CREATE TABLE execution_attempts (
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
            )""",
            """CREATE INDEX execution_attempts_running_idx
                ON execution_attempts(job_id, status)""",
            """CREATE TABLE execution_resource (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                state TEXT NOT NULL CHECK (state IN ('available','claimed','quarantined')),
                job_id TEXT,
                attempt_id TEXT,
                owner_id TEXT,
                reason TEXT,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE artifact_publication_authority (
                publication_id TEXT PRIMARY KEY REFERENCES artifact_publications(publication_id),
                job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
                attempt_id TEXT NOT NULL REFERENCES execution_attempts(attempt_id),
                owner_id TEXT,
                claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 0),
                created_at TEXT NOT NULL
            )""",
        )
        for statement in statements:
            connection.execute(statement)

        timestamp = connection.execute(
            "SELECT min(created_at) FROM generation_jobs"
        ).fetchone()[0] or "1970-01-01T00:00:00+00:00"
        jobs = connection.execute("SELECT * FROM generation_jobs ORDER BY created_at, job_id").fetchall()
        quarantined = False
        for job in jobs:
            references = self._references_for_job(connection, job["job_id"])
            plan_json = self._resolved_plan_json(job, references)
            current = connection.execute(
                """SELECT attempt_id FROM generation_attempts
                   WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1""",
                (job["job_id"],),
            ).fetchone()
            connection.execute(
                """INSERT INTO execution_jobs
                   (job_id,status,max_attempts,fence_epoch,current_attempt_id,
                    retry_eligible,failure_message,resolved_plan_json,created_at,updated_at)
                   VALUES (?,?,1,0,?,0,NULL,?,?,?)""",
                (
                    job["job_id"],
                    job["status"],
                    None if current is None else current["attempt_id"],
                    plan_json,
                    job["created_at"],
                    job["updated_at"],
                ),
            )
            attempts = connection.execute(
                "SELECT * FROM generation_attempts WHERE job_id = ? ORDER BY attempt_number",
                (job["job_id"],),
            ).fetchall()
            for attempt in attempts:
                running = attempt["status"] == "running"
                quarantined = quarantined or running
                connection.execute(
                    """INSERT INTO execution_attempts
                       (attempt_id,job_id,attempt_number,status,owner_id,claim_epoch,
                        heartbeat_at,lease_expires_at,process_contained,failure_class,
                        termination_proven,plan_json,completed_at)
                       VALUES (?,?,?,?,NULL,0,NULL,NULL,NULL,?,?,?,?)""",
                    (
                        attempt["attempt_id"],
                        attempt["job_id"],
                        attempt["attempt_number"],
                        attempt["status"],
                        "ambiguous" if running else (None if attempt["status"] == "succeeded" else "terminal"),
                        0,
                        plan_json,
                        attempt["finished_at"],
                    ),
                )

        connection.execute(
            """INSERT INTO execution_resource
               (id,state,job_id,attempt_id,owner_id,reason,updated_at)
               VALUES (1,?,NULL,NULL,NULL,?,?)""",
            (
                "quarantined" if quarantined else "available",
                "historical unfinished attempt has no trusted containment proof"
                if quarantined else None,
                timestamp,
            ),
        )
        connection.execute(
            """INSERT INTO artifact_publication_authority
               (publication_id,job_id,attempt_id,owner_id,claim_epoch,created_at)
               SELECT publication_id,job_id,attempt_id,NULL,0,created_at
               FROM artifact_publications
               WHERE state = 'committed'
                 AND job_id IS NOT NULL AND attempt_id IS NOT NULL"""
        )
        self._install_writer_guards(connection)
        self._assert_all_jobs_have_execution_state(connection)
        connection.execute("PRAGMA user_version = 3")

    @staticmethod
    def _writer_guard_sql(table: str, operation: str) -> tuple[str, str]:
        """Return the stable trigger name and definition for one table write."""
        name = f"t04_writer_guard_{table}_{operation.lower()}"
        sql = f"""CREATE TRIGGER {name}
BEFORE {operation} ON {table}
WHEN {_WRITER_EPOCH_FUNCTION}() != {_WRITER_EPOCH}
BEGIN SELECT RAISE(ABORT, 'stale media-generation writer'); END"""
        return name, sql

    @classmethod
    def _install_writer_guards(cls, connection: sqlite3.Connection) -> None:
        """Ensure every legacy mutation requires a current writer connection.

        Version 3 sidecars do not prevent an older T01 or T03 process from
        writing the legacy tables. Historical binaries open SQLite connections
        without registering ``media_generation_writer_epoch``. The triggers
        therefore abort their first data mutation while allowing connections
        opened by this store. A missing trigger is recreated; a same-name
        trigger with a different definition fails closed.
        """
        for table, operation in _WRITER_GUARDS:
            name, expected_sql = cls._writer_guard_sql(table, operation)
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (name,),
            ).fetchone()
            if row is None:
                connection.execute(expected_sql)
                continue
            current_sql = " ".join(str(row["sql"]).split()).rstrip(";")
            normalized_expected = " ".join(expected_sql.split()).rstrip(";")
            if current_sql != normalized_expected:
                raise RuntimeError(f"database version 3 writer guard is divergent: {name}")

    @staticmethod
    def _assert_all_jobs_have_execution_state(connection: sqlite3.Connection) -> None:
        """Reject rows admitted through the legacy tables without T04 sidecars."""
        rows = connection.execute(
            """SELECT jobs.job_id
               FROM generation_jobs AS jobs
               LEFT JOIN execution_jobs AS execution
                 ON execution.job_id = jobs.job_id
               WHERE execution.job_id IS NULL
               ORDER BY jobs.created_at, jobs.job_id"""
        ).fetchall()
        if rows:
            job_ids = ", ".join(str(row["job_id"]) for row in rows)
            raise RuntimeError(
                "database schema version 3 contains generation jobs without execution state: "
                f"{job_ids}; stop older writers and restore or repair from a pre-migration backup"
            )

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
        effective_parameters_json: str,
        resolved_output_directory: str,
        max_attempts: int | None,
        containment_contract: str | None,
        timestamp: str,
    ) -> QueuedExecution:
        """Atomically admit or reuse a queued job without creating an attempt.

        ``max_attempts=None`` means the caller omitted an admission policy.
        It defaults to one only while creating a job. Reusing an existing job
        preserves the policy chosen by the first admission.
        """
        effective_max_attempts = 1 if max_attempts is None else max_attempts
        if (
            isinstance(effective_max_attempts, bool)
            or not isinstance(effective_max_attempts, int)
            or effective_max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        with self._connection(transaction=True) as connection:
            existing = connection.execute(
                """SELECT jobs.*, execution.status AS execution_status,
                          execution.max_attempts AS execution_max_attempts,
                          execution.containment_contract,
                          execution.retry_eligible AS execution_retry_eligible
                   FROM generation_jobs AS jobs
                   JOIN execution_jobs AS execution ON execution.job_id = jobs.job_id
                   WHERE jobs.idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to different canonical request intent"
                    )
                if existing["adapter_id"] != adapter_id or json.loads(
                    str(existing["adapter_configuration_json"])
                ) != json.loads(adapter_configuration_json):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different adapter identity or configuration"
                    )
                if (
                    max_attempts is not None
                    and existing["execution_status"] != "succeeded"
                    and int(existing["execution_max_attempts"]) != max_attempts
                ):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different attempt budget"
                    )
                legacy_failed_without_contract = (
                    existing["containment_contract"] is None
                    and existing["execution_status"] == "failed"
                    and not bool(existing["execution_retry_eligible"])
                )
                if (
                    existing["containment_contract"] != containment_contract
                    and existing["execution_status"] != "succeeded"
                    and not legacy_failed_without_contract
                ):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different containment contract"
                    )
                existing_directory = self._output_directory_for_job(
                    connection,
                    str(existing["job_id"]),
                    str(existing["effective_parameters_json"]),
                )
                if existing_directory != str(Path(resolved_output_directory).expanduser().resolve()):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different or unknown output directory"
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
                    (job_id,status,max_attempts,containment_contract,fence_epoch,current_attempt_id,
                    retry_eligible,failure_message,resolved_plan_json,created_at,updated_at)
                   VALUES (?,'queued',?,?,0,NULL,0,NULL,?,?,?)""",
                (
                    job_id,
                    effective_max_attempts,
                    containment_contract,
                    self._resolved_plan_json(job_row, references),
                    timestamp,
                    timestamp,
                ),
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
        adapter_configuration_json: str,
        resolved_output_directory: str,
        process_contained: bool,
        containment_contract: str | None,
        timestamp: str,
        lease_expires_at: str,
        job_id: str | None = None,
    ) -> ExecutionClaim | None:
        """Atomically create one attempt for the oldest matching queued job."""
        requested_directory = str(Path(resolved_output_directory).expanduser().resolve())
        with self._connection(transaction=True) as connection:
            resource = connection.execute(
                "SELECT state FROM execution_resource WHERE id = 1"
            ).fetchone()
            if resource is None or resource["state"] != "available":
                return None

            query = """SELECT jobs.*, execution.status AS execution_status,
                                execution.max_attempts, execution.fence_epoch,
                                execution.containment_contract,
                                execution.resolved_plan_json
                         FROM generation_jobs AS jobs
                         JOIN execution_jobs AS execution ON execution.job_id = jobs.job_id
                         WHERE execution.status = 'queued'
                           AND jobs.adapter_id = ?
                           AND jobs.adapter_configuration_json = ?
                           AND execution.containment_contract IS ?"""
            parameters: list[object] = [
                adapter_id,
                adapter_configuration_json,
                containment_contract,
            ]
            if job_id is not None:
                query += " AND jobs.job_id = ?"
                parameters.append(job_id)
            query += " ORDER BY execution.created_at, jobs.job_id"
            candidate = None
            for row in connection.execute(query, tuple(parameters)).fetchall():
                if self._output_directory_for_job(
                    connection, str(row["job_id"]), str(row["effective_parameters_json"])
                ) == requested_directory:
                    candidate = row
                    break
            if candidate is None:
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
                          (SELECT count(*) FROM execution_attempts
                           WHERE job_id = ?) AS attempt_count
                   FROM execution_jobs AS execution
                   JOIN execution_resource AS resource ON resource.id = 1
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
            ):
                return False
            connection.execute(
                """UPDATE execution_jobs
                   SET status = 'queued', retry_eligible = 0,
                       failure_message = NULL, updated_at = ?
                   WHERE job_id = ? AND status = 'failed'""",
                (timestamp, job_id),
            )
            connection.execute(
                "UPDATE generation_jobs SET status = 'running', updated_at = ? WHERE job_id = ?",
                (timestamp, job_id),
            )
            return True

    def resource_snapshot(self) -> dict[str, object]:
        """Return the persisted heavyweight-resource reservation."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM execution_resource WHERE id = 1").fetchone()
            if row is None:
                raise RuntimeError("execution resource reservation row is missing")
            return dict(row)

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
        """Commit an artifact and release work only with trusted termination proof."""
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

    def _legacy_fail_execution(
        self, job_id: str, attempt_id: str, message: str, timestamp: str
    ) -> None:
        """Fail only an execution with no recoverable or committed publication."""
        with self._connection(transaction=True) as connection:
            if connection.execute(
                "SELECT 1 FROM artifact_publications WHERE job_id = ? "
                "AND state IN ('ready', 'committed')", (job_id,)
            ).fetchone() is not None:
                return
            connection.execute(
                "UPDATE generation_jobs SET status = 'failed', updated_at = ? "
                "WHERE job_id = ? AND status = 'running'",
                (timestamp, job_id),
            )
            connection.execute(
                """UPDATE generation_attempts
                   SET status = 'failed', finished_at = ?, error_message = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (timestamp, message, attempt_id, job_id),
            )

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
                """SELECT max_attempts, current_attempt_id, fence_epoch
                   FROM execution_jobs WHERE job_id = ?""",
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
        """Return the saved destination, inferring it for legacy artifact rows."""
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

    def _legacy_get_provenance(self, job_id: str) -> dict[str, object]:
        """Return request, resolved job, attempt, and optional artifact snapshots."""
        with self._connection() as connection:
            job_row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts ON artifacts.job_id = jobs.job_id
                   WHERE jobs.job_id = ?""",
                (job_id,),
            ).fetchone()
            if job_row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            request_row = connection.execute(
                "SELECT * FROM generation_requests WHERE request_id = ?",
                (job_row["request_id"],),
            ).fetchone()
            attempt_row = connection.execute(
                "SELECT * FROM generation_attempts WHERE job_id = ? ORDER BY attempt_number DESC LIMIT 1",
                (job_id,),
            ).fetchone()
            artifact_row = connection.execute(
                "SELECT * FROM generation_artifacts WHERE job_id = ?", (job_id,)
            ).fetchone()

        assert request_row is not None
        assert attempt_row is not None
        request_payload = json.loads(str(request_row["canonical_json"]))
        request = GenerationRequestRecord(
            request_id=str(request_row["request_id"]),
            request=GenerationRequest(**request_payload),
            request_digest=str(request_row["request_digest"]),
            created_at=str(request_row["created_at"]),
        )
        job = self._job_from_row(job_row)
        job_payload = job.to_dict()
        attempt = self._attempt_from_row(attempt_row)
        artifact = None if artifact_row is None else self._artifact_from_row(artifact_row)
        return {
            "job_id": job.job_id,
            "request": request.to_dict(),
            "status": job.execution_status or job.status,
            "adapter_id": job.adapter_id,
            "adapter_configuration": job_payload["adapter_configuration"],
            "resolved_prompt": job.resolved_prompt,
            "resolved_seed": job.resolved_seed,
            "validated_reference_ids": list(job.validated_reference_ids),
            "output_slot": job.output_slot,
            "output_slot_id": job.output_slot_id,
            "effective_parameters": job_payload["effective_parameters"],
            "attempt": attempt.to_dict(),
            "artifact": None if artifact is None else artifact.to_dict(),
        }

    def get_provenance(self, job_id: str) -> dict[str, object]:
        """Return request, job, attempt history, artifact, and execution state."""
        with self._connection() as connection:
            job_row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id,
                          execution.status AS execution_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.retry_eligible, execution.failure_message,
                          execution.containment_contract,
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
            return {
                "job_id": job.job_id,
                "request": request.to_dict(),
                "status": execution_status,
                "adapter_id": job.adapter_id,
                "adapter_configuration": job_payload["adapter_configuration"],
                "resolved_prompt": job.resolved_prompt,
                "resolved_seed": job.resolved_seed,
                "validated_reference_ids": list(job.validated_reference_ids),
                "output_slot": job.output_slot,
                "output_slot_id": job.output_slot_id,
                "effective_parameters": job_payload["effective_parameters"],
                "attempt": None if not attempts else attempts[-1].to_dict(),
                "attempts": [attempt.to_dict() for attempt in attempts],
                "artifact": None if artifact is None else artifact.to_dict(),
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
        """Load a job's saved destination or infer it from a legacy artifact."""
        effective_parameters = json.loads(effective_parameters_json)
        output_directory = effective_parameters.get(_RESOLVED_OUTPUT_DIRECTORY_KEY)
        if isinstance(output_directory, str) and output_directory:
            return str(Path(output_directory).expanduser().resolve())

        artifact = connection.execute(
            "SELECT path FROM generation_artifacts WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        if artifact is None:
            return None
        return str(Path(str(artifact["path"])).parent.resolve())

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


def _json(value: object) -> str:
    """Serialize a stored value using the canonical JSON conventions."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
