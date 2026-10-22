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

    def complete_execution(self, artifact: GenerationArtifact, timestamp: str) -> None:
        """Persist the artifact and successful job/attempt transition together."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                "SELECT status FROM generation_jobs WHERE job_id = ?", (artifact.job_id,)
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {artifact.job_id}")
            if row["status"] != "running":
                raise RuntimeError(f"job {artifact.job_id} is not running")
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
                    image_format, width, height, file_size, sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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

    def fail_execution(self, job_id: str, attempt_id: str, message: str, timestamp: str) -> None:
        """Record adapter failure without creating an artifact record."""
        with self._connection(transaction=True) as connection:
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

    def get_artifact(self, artifact_id: str) -> GenerationArtifact:
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
    def _artifact_from_row(row: sqlite3.Row) -> GenerationArtifact:
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
