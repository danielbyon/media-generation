"""Synchronous application service for durable local image generation."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from .adapters import DeterministicCpuAdapter, GenerationAdapter
from .domain import (
    GenerationArtifact,
    ImportedArtifact,
    ArtifactSource,
    GenerationJob,
    GenerationPlan,
    GenerationRequest,
    ResolvedReference,
)
from .errors import (
    GenerationExecutionError,
    ArtifactIntegrityError,
    IdempotencyConflictError,
    InputValidationError,
    PublicationIncompleteError,
    RecordNotFoundError,
    UnsupportedCapabilityError,
)
from .store import SQLiteStore
from .images import ImageInfo, open_approved_source, copy_source
from .publication import PublicationManager, Checkpoint


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
        *, publication_checkpoint: Checkpoint | None = None,
    ) -> None:
        self._store = SQLiteStore(database_path)
        self.output_directory = Path(os.path.abspath(output_directory.expanduser()))
        self.adapter: GenerationAdapter = adapter or DeterministicCpuAdapter()
        self._publication = PublicationManager(self._store, self.output_directory, publication_checkpoint)

    def submit(self, idempotency_key: str, request: GenerationRequest) -> SubmissionResult:
        """Create or reuse a job under the current adapter's resolved configuration.

        A retry reuses a matching job only when the current adapter supports the
        request and matches the persisted adapter identity, configuration, and
        resolved output directory.
        New jobs are committed before their adapter executes synchronously.
        Recoverable publication errors identify a still-running job and require
        reconciliation; only terminal failures raise GenerationExecutionError.
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
                or _canonical_json(
                    existing_job.to_dict()["adapter_configuration"]
                )
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
        try:
            self._validate_reference_artifacts(pending.references)
        except Exception as error:
            message = f"adapter {self.adapter.adapter_id!r} failed: {error}"
            self._store.fail_execution(pending.job_id, pending.attempt_id, message, _now())
            raise GenerationExecutionError(pending.job_id, message) from error

        metadata = None

        def write_image(destination: Path, staged: BinaryIO) -> None:
            nonlocal metadata
            metadata = self.adapter.generate(plan, staged)

        def make_artifact(info: ImageInfo, destination: Path) -> GenerationArtifact:
            if metadata is None or (
                metadata.width != request.width or metadata.height != request.height
                or info.width != request.width or info.height != request.height
                or metadata.image_format != info.image_format or metadata.media_type != info.media_type
            ):
                raise RuntimeError("adapter image metadata does not match the decoded image and persisted request")
            return GenerationArtifact(
                artifact_id=artifact_id, job_id=pending.job_id, attempt_id=pending.attempt_id,
                output_slot_id=pending.output_slot_id, path=str(destination),
                media_type=info.media_type, image_format=info.image_format,
                width=info.width, height=info.height, file_size=info.file_size,
                sha256=info.sha256, created_at=_now())

        try:
            self._publication.publish(write_image, make_artifact, artifact_id=artifact_id,
                job_id=pending.job_id, attempt_id=pending.attempt_id,
                sources=tuple(ArtifactSource(ref.artifact_id) for ref in pending.references))
        except Exception as error:
            # The store refuses to fail ready or committed publications. This
            # also records errors opening the destination before journaling.
            self._store.fail_execution(pending.job_id, pending.attempt_id, str(error), _now())
            # A reconciler may commit after the publisher releases its lock.
            # Classify the durable job outcome rather than the earlier exception.
            submission = self._submission_for_job(pending.job_id)
            if submission.status == "succeeded":
                return submission
            if submission.status == "running":
                raise PublicationIncompleteError(pending.job_id, str(error)) from error
            message = f"adapter {self.adapter.adapter_id!r} failed: {error}"
            raise GenerationExecutionError(pending.job_id, message) from error

        return self._submission_for_job(pending.job_id)

    def _validate_reference_artifacts(self, references: tuple[ResolvedReference, ...]) -> None:
        """Require current authoritative bytes to match the immutable artifact."""
        for reference in references:
            observation = self._publication.integrity(reference.artifact_id)
            if observation["status"] != "ok":
                raise ArtifactIntegrityError(
                    f"reference artifact {reference.artifact_id!r} is missing or failed SHA-256/image validation: "
                    f"{observation['detail']}"
                )

    def import_image(self, approved_root: Path, relative_path: str, *,
                     sources: tuple[ArtifactSource, ...] = ()) -> ImportedArtifact:
        """Import a local image under an explicit operator-granted source root.

        This administrative boundary accepts a relative filename beneath the
        approved root. GenerationRequest continues to accept only artifact IDs.
        Each invocation creates a new identity, even for identical image bytes.
        """
        sources = tuple(sources)
        if len({(source.artifact_id, source.role) for source in sources}) != len(sources):
            raise InputValidationError("lineage sources cannot repeat an artifact/role pair")
        for source in sources:
            self._store.get_artifact(source.artifact_id)
            if source.role in {"reference", "source"}:
                if self.get_integrity(source.artifact_id)["status"] != "ok":
                    raise ArtifactIntegrityError("lineage input is not a trusted image")
        artifact_id = _new_id("art")
        with open_approved_source(approved_root.expanduser(), relative_path) as source_file:
            source_stat = os.fstat(source_file.fileno())
            provenance = {
                "approved_root": str(Path(os.path.abspath(approved_root.expanduser()))),
                "relative_path": relative_path,
                "source_device": source_stat.st_dev, "source_inode": source_stat.st_ino,
                "source_size": source_stat.st_size, "source_mtime_ns": source_stat.st_mtime_ns,
                "source_ctime_ns": source_stat.st_ctime_ns,
                "imported_at": _now(),
            }

            def copy_image(destination: Path, staged: BinaryIO) -> None:
                # Copy into the publisher's pinned descriptor without reopening
                # either side through a caller-controlled path.
                copy_source(source_file, staged)
                after = os.fstat(source_file.fileno())
                if any(getattr(source_stat, field) != getattr(after, field) for field in (
                    "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
                )):
                    raise InputValidationError("source changed after import approval")

            def make_artifact(info: ImageInfo, destination: Path) -> ImportedArtifact:
                return ImportedArtifact(
                    artifact_id=artifact_id, path=str(destination), media_type=info.media_type,
                    image_format=info.image_format, width=info.width, height=info.height,
                    file_size=info.file_size, sha256=info.sha256, created_at=_now(),
                    import_provenance=provenance)

            artifact = self._publication.publish(copy_image, make_artifact,
                artifact_id=artifact_id, sources=sources)
        assert isinstance(artifact, ImportedArtifact)
        return artifact

    def get_integrity(self, artifact_id: str) -> dict[str, object]:
        """Verify current stored bytes while preserving immutable metadata."""
        return self._publication.integrity(artifact_id)

    def get_lineage(self, artifact_id: str) -> dict[str, object]:
        """Inspect ordered parents and children of a logical artifact."""
        return self._store.get_lineage(artifact_id)

    def reconcile(self) -> dict[str, object]:
        """Recover owned publications and report unresolved storage conditions."""
        return self._publication.reconcile()

    def get_request(self, request_id: str) -> dict[str, object]:
        """Retrieve one immutable request snapshot by ID."""
        return self._store.get_request(request_id).to_dict()

    def get_job(self, job_id: str) -> GenerationJob:
        """Retrieve durable job state by ID."""
        return self._store.get_job(job_id)

    def get_artifact(self, artifact_id: str) -> GenerationArtifact | ImportedArtifact:
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
