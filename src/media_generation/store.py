"""SQLite persistence for immutable requests and durable execution records."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
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


@dataclass(frozen=True, slots=True)
class PendingExecution:
    """Identifiers and resolved references returned after a job is committed."""

    created: bool
    request_id: str
    job_id: str
    attempt_id: str
    output_slot_id: str
    references: tuple[ResolvedReference, ...]


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
        with self._connection() as connection:
            connection.executescript(
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

        self._migrate_artifacts()

    def _migrate_artifacts(self) -> None:
        """Upgrade the original T01 schema atomically without rewriting its records.

        Imported artifacts share the same identity namespace and file metadata,
        but have no generation job or attempt. Existing generated JSON stays
        unchanged; the discriminator is a persistence detail for those records.
        """
        with self._connection(transaction=True) as connection:
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

    @staticmethod
    def _insert_sources(connection, artifact_id: str, sources: tuple[ArtifactSource, ...]) -> None:
        for position, source in enumerate(sources):
            connection.execute("INSERT INTO artifact_edges VALUES (?, ?, ?, ?)",
                (source.artifact_id, artifact_id, source.role, position))

    def find_idempotency_key(self, idempotency_key: str) -> tuple[str, str] | None:
        """Return the existing job ID and digest for an idempotency key."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT job_id, request_digest FROM generation_jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        return None if row is None else (str(row["job_id"]), str(row["request_digest"]))

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
        """Persist or reuse a matching execution, including its output directory."""
        with self._connection(transaction=True) as connection:
            existing = connection.execute(
                "SELECT job_id, request_id, request_digest, output_slot_id, "
                "adapter_id, adapter_configuration_json, effective_parameters_json "
                "FROM generation_jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to different canonical request intent"
                    )
                if (
                    existing["adapter_id"] != adapter_id
                    or existing["adapter_configuration_json"] != adapter_configuration_json
                ):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different adapter identity "
                        "or configuration"
                    )
                existing_output_directory = self._output_directory_for_job(
                    connection,
                    str(existing["job_id"]),
                    str(existing["effective_parameters_json"]),
                )
                if existing_output_directory != str(
                    Path(resolved_output_directory).expanduser().resolve()
                ):
                    raise IdempotencyConflictError(
                        "idempotency key is already bound to a different or unknown "
                        "output directory"
                    )
                return PendingExecution(
                    False,
                    str(existing["request_id"]),
                    str(existing["job_id"]),
                    "",
                    str(existing["output_slot_id"]),
                    (),
                )

            references: list[ResolvedReference] = []
            for artifact_id in request.reference_ids:
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

            effective_parameters = json.loads(effective_parameters_json)
            effective_parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY] = str(
                Path(resolved_output_directory).expanduser().resolve()
            )
            effective_parameters_json = _json(effective_parameters)

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
                    effective_parameters_json,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """INSERT INTO generation_attempts (
                    attempt_id, job_id, attempt_number, status, adapter_id,
                    started_at, finished_at, error_message
                ) VALUES (?, ?, 1, 'running', ?, ?, NULL, NULL)""",
                (attempt_id, job_id, adapter_id, timestamp),
            )

        return PendingExecution(
            True,
            request_id,
            job_id,
            attempt_id,
            output_slot_id,
            tuple(references),
        )

    def complete_execution(
        self, artifact: GenerationArtifact, timestamp: str, *,
        publication_id: str | None = None, sources: tuple[ArtifactSource, ...] = (),
    ) -> None:
        """Persist the artifact and successful job/attempt transition together."""
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
                """SELECT status FROM generation_attempts
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
                self._commit_publication_row(connection, publication_id, artifact.artifact_id)

    @staticmethod
    def _commit_publication_row(connection, publication_id: str, artifact_id: str) -> None:
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

    def create_publication(self, record: dict[str, object]) -> None:
        """Commit allocation intent before the publisher creates private content."""
        with self._connection(transaction=True) as connection:
            fields = tuple(record)
            connection.execute(
                f"INSERT INTO artifact_publications ({','.join(fields)}) "
                f"VALUES ({','.join('?' for _ in fields)})", tuple(record.values()))

    def update_publication(self, publication_id: str, **values: object) -> None:
        """Update journal metadata without changing its publication lifecycle state."""
        allowed = {"stage_dev", "stage_ino", "final_name", "artifact_json", "error"}
        if not values or not set(values) <= allowed:
            raise ValueError("unsupported publication update")
        with self._connection(transaction=True) as connection:
            connection.execute(
                f"UPDATE artifact_publications SET {','.join(key+' = ?' for key in values)} "
                "WHERE publication_id = ? AND state != 'committed'",
                (*values.values(), publication_id))

    def mark_publication_ready(self, publication_id: str, final_name: str,
                               artifact_json: str) -> None:
        """Record validated publication metadata through an allocated-to-ready transition."""
        with self._connection(transaction=True) as connection:
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'ready', final_name = ?, "
                "artifact_json = ? WHERE publication_id = ? AND state = 'allocated'",
                (final_name, artifact_json, publication_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("publication is not allocated for the ready transition")

    def abandon_publication(self, publication_id: str, error: str) -> None:
        """Abandon an allocated publication through its explicit lifecycle transition."""
        with self._connection(transaction=True) as connection:
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'abandoned', error = ? "
                "WHERE publication_id = ? AND state = 'allocated'",
                (error, publication_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("publication is not allocated for abandonment")

    def publications(self, root: str) -> list[dict[str, object]]:
        """List durable publication decisions for an exact authoritative root."""
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM artifact_publications WHERE root = ? ORDER BY created_at", (root,))]

    def publication_for_artifact(self, artifact_id: str) -> dict[str, object] | None:
        """Read the publication journal that owns an artifact, if one exists."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM artifact_publications WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        return None if row is None else dict(row)

    def publication(self, publication_id: str) -> dict[str, object]:
        """Read the durable decision, including after lost commit acknowledgement."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM artifact_publications WHERE publication_id = ?",
                                     (publication_id,)).fetchone()
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

    def fail_execution(self, job_id: str, attempt_id: str, message: str, timestamp: str) -> None:
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
                """SELECT jobs.*, artifacts.artifact_id
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts ON artifacts.job_id = jobs.job_id
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

    def get_provenance(self, job_id: str) -> dict[str, object]:
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
            "status": job.status,
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
        )

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> GenerationAttempt:
        return GenerationAttempt(
            attempt_id=str(row["attempt_id"]),
            job_id=str(row["job_id"]),
            attempt_number=int(row["attempt_number"]),
            status=str(row["status"]),
            adapter_id=str(row["adapter_id"]),
            started_at=str(row["started_at"]),
            finished_at=None if row["finished_at"] is None else str(row["finished_at"]),
            error_message=None if row["error_message"] is None else str(row["error_message"]),
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
