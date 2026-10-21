"""Synchronous application service for durable local image generation."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .adapters import DeterministicCpuAdapter, GenerationAdapter
from .domain import GenerationArtifact, GenerationJob, GenerationPlan, GenerationRequest
from .errors import (
    GenerationExecutionError,
    IdempotencyConflictError,
    InputValidationError,
    RecordNotFoundError,
    UnsupportedCapabilityError,
)
from .store import SQLiteStore


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """Stable identities and current state returned from a submit operation."""

    request_id: str
    job_id: str
    status: str
    output_slot_id: str
    artifact_id: str | None

    def to_dict(self) -> dict[str, object]:
        """Return a CLI-ready result without exposing storage implementation details."""
        return {
            "request_id": self.request_id,
            "job_id": self.job_id,
            "status": self.status,
            "output_slot_id": self.output_slot_id,
            "artifact_id": self.artifact_id,
        }


class GenerationService:
    """Validate, persist, execute, and expose one local generation request.

    A job and its first attempt are committed before calling the configured
    adapter. Execution is synchronous in the submitting process; SQLite and
    artifact files remain available to later CLI processes.
    """

    def __init__(
        self,
        database_path: Path,
        output_directory: Path,
        adapter: GenerationAdapter | None = None,
    ) -> None:
        self._store = SQLiteStore(database_path)
        self.output_directory = output_directory.expanduser().resolve()
        self.adapter: GenerationAdapter = adapter or DeterministicCpuAdapter()

    def submit(self, idempotency_key: str, request: GenerationRequest) -> SubmissionResult:
        """Create or reuse a job under the current adapter's resolved configuration.

        A retry reuses a matching job only when the current adapter supports the
        request and matches the persisted adapter identity, configuration, and
        resolved output directory.
        New jobs are committed before their adapter executes synchronously.
        """
        key = _validate_idempotency_key(idempotency_key)
        request_digest = request.digest()
        existing = self._store.find_idempotency_key(key)
        if existing is not None:
            if existing[1] != request_digest:
                raise IdempotencyConflictError(
                    "idempotency key is already bound to different canonical request intent"
                )
            self._validate_capabilities(request)
            existing_job = self._store.get_job(existing[0])
            if (
                existing_job.adapter_id != self.adapter.adapter_id
                or _canonical_json(dict(existing_job.adapter_configuration))
                != _canonical_json(self.adapter.configuration)
            ):
                raise IdempotencyConflictError(
                    "idempotency key is already bound to a different adapter identity "
                    "or configuration"
                )
            if (
                self._store.get_resolved_output_directory(existing_job.job_id)
                != str(self.output_directory)
            ):
                raise IdempotencyConflictError(
                    "idempotency key is already bound to a different or unknown "
                    "output directory"
                )
            return self._submission_for_job(existing[0])

        self._validate_capabilities(request)
        resolved_seed = request.seed
        if resolved_seed is None:
            resolved_seed = int(request_digest[:8], 16)

        request_id = _new_id("req")
        job_id = _new_id("job")
        attempt_id = _new_id("att")
        output_slot_id = _new_id("slot")
        adapter_configuration_json = _canonical_json(self.adapter.configuration)
        effective_parameters_json = _canonical_json(
            {"width": request.width, "height": request.height}
        )
        timestamp = _now()
        pending = self._store.create_pending_execution(
            request=request,
            request_digest=request_digest,
            idempotency_key=key,
            request_id=request_id,
            job_id=job_id,
            attempt_id=attempt_id,
            output_slot_id=output_slot_id,
            resolved_seed=resolved_seed,
            adapter_id=self.adapter.adapter_id,
            adapter_configuration_json=adapter_configuration_json,
            effective_parameters_json=effective_parameters_json,
            resolved_output_directory=str(self.output_directory),
            timestamp=timestamp,
        )
        if not pending.created:
            return self._submission_for_job(pending.job_id)

        plan = GenerationPlan(
            job_id=pending.job_id,
            attempt_id=pending.attempt_id,
            resolved_prompt=request.prompt,
            seed=resolved_seed,
            width=request.width,
            height=request.height,
            references=pending.references,
            output_slot=request.output_slot,
            output_slot_id=pending.output_slot_id,
        )
        artifact_id = _new_id("art")
        destination = self.output_directory / f"{artifact_id}.png"
        try:
            self.output_directory.mkdir(parents=True, exist_ok=True)
            metadata = self.adapter.generate(plan, destination)
            if not destination.is_file():
                raise RuntimeError("adapter returned without writing an image file")
            if metadata.width != request.width or metadata.height != request.height:
                raise RuntimeError("adapter image dimensions do not match the persisted request")
            size = destination.stat().st_size
            if size <= 0:
                raise RuntimeError("adapter wrote an empty image file")
            artifact = GenerationArtifact(
                artifact_id=artifact_id,
                job_id=pending.job_id,
                attempt_id=pending.attempt_id,
                output_slot_id=pending.output_slot_id,
                path=str(destination),
                media_type=metadata.media_type,
                image_format=metadata.image_format,
                width=metadata.width,
                height=metadata.height,
                file_size=size,
                sha256=_sha256_file(destination),
                created_at=_now(),
            )
            self._store.complete_execution(artifact, _now())
        except Exception as error:
            destination.unlink(missing_ok=True)
            message = f"adapter {self.adapter.adapter_id!r} failed: {error}"
            self._store.fail_execution(pending.job_id, pending.attempt_id, message, _now())
            raise GenerationExecutionError(pending.job_id, message) from error

        return SubmissionResult(
            request_id=pending.request_id,
            job_id=pending.job_id,
            status="succeeded",
            output_slot_id=pending.output_slot_id,
            artifact_id=artifact_id,
        )

    def get_request(self, request_id: str) -> dict[str, object]:
        """Retrieve one immutable request snapshot by ID."""
        return self._store.get_request(request_id).to_dict()

    def get_job(self, job_id: str) -> GenerationJob:
        """Retrieve durable job state by ID."""
        return self._store.get_job(job_id)

    def get_artifact(self, artifact_id: str) -> GenerationArtifact:
        """Retrieve a logical artifact and its persisted image metadata."""
        return self._store.get_artifact(artifact_id)

    def get_provenance(self, job_id: str) -> dict[str, object]:
        """Retrieve the request, adapter attempt, and output provenance snapshot."""
        return self._store.get_provenance(job_id)

    def _validate_capabilities(self, request: GenerationRequest) -> None:
        capabilities = self.adapter.capabilities
        if request.width > capabilities.max_width:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports width up to {capabilities.max_width}"
            )
        if request.height > capabilities.max_height:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports height up to {capabilities.max_height}"
            )
        if request.reference_ids and not capabilities.supports_references:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} does not support reference images"
            )
        if len(request.reference_ids) > capabilities.max_references:
            raise UnsupportedCapabilityError(
                f"adapter {self.adapter.adapter_id!r} supports at most "
                f"{capabilities.max_references} reference images"
            )

    def _submission_for_job(self, job_id: str) -> SubmissionResult:
        job = self._store.get_job(job_id)
        return SubmissionResult(
            request_id=job.request_id,
            job_id=job.job_id,
            status=job.status,
            output_slot_id=job.output_slot_id,
            artifact_id=job.artifact_id,
        )


def _validate_idempotency_key(value: str) -> str:
    """Reject blank and oversized idempotency keys before opening a job."""
    if not isinstance(value, str):
        raise InputValidationError("idempotency key must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 200:
        raise InputValidationError("idempotency key must contain 1-200 characters")
    return normalized


def _new_id(prefix: str) -> str:
    """Create a unique, visibly typed logical record identity."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _now() -> str:
    """Return a timezone-aware UTC timestamp suitable for persisted snapshots."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _canonical_json(value: object) -> str:
    """Serialize adapter settings and effective parameters deterministically."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_file(path: Path) -> str:
    """Hash a generated file without loading the full image into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as image_file:
        for block in iter(lambda: image_file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
