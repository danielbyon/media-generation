"""Immutable intent and execution records shared by the CLI and adapters."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .errors import InputValidationError


_ARTIFACT_ID = re.compile(r"^art_[0-9a-f]{32}$")
_OUTPUT_SLOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _freeze(value: object) -> object:
    """Copy nested JSON-like values into recursively immutable containers."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    """Return detached JSON-compatible containers from immutable values."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    """Canonical engine-neutral image intent supplied to the service.

    Request fields deliberately describe the desired image and stable logical
    references. They never accept adapter syntax or caller-provided file paths.
    """

    prompt: str
    seed: int | None = None
    width: int = 64
    height: int = 64
    reference_ids: tuple[str, ...] = ()
    output_slot: str = "primary"

    def __post_init__(self) -> None:
        if not isinstance(self.prompt, str):
            raise InputValidationError("prompt must be a string")
        normalized_prompt = unicodedata.normalize(
            "NFC", self.prompt.replace("\r\n", "\n").replace("\r", "\n").strip()
        )
        if not normalized_prompt:
            raise InputValidationError("prompt must not be empty")
        object.__setattr__(self, "prompt", normalized_prompt)

        if self.seed is not None and (
            isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or not 0 <= self.seed <= 4_294_967_295
        ):
            raise InputValidationError("seed must be an integer from 0 to 4294967295")
        for name, dimension in (("width", self.width), ("height", self.height)):
            if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension < 1:
                raise InputValidationError(f"{name} must be a positive integer")

        if not isinstance(self.reference_ids, (tuple, list)):
            raise InputValidationError("reference_ids must be a list of artifact IDs")
        references = tuple(self.reference_ids)
        if any(not isinstance(value, str) or not _ARTIFACT_ID.fullmatch(value) for value in references):
            raise InputValidationError(
                "reference_ids must contain stable artifact IDs such as art_<32 lowercase hex characters>"
            )
        if len(set(references)) != len(references):
            raise InputValidationError("reference_ids must not contain duplicates")
        object.__setattr__(self, "reference_ids", references)

        if not isinstance(self.output_slot, str) or not _OUTPUT_SLOT.fullmatch(self.output_slot):
            raise InputValidationError(
                "output_slot must be 1-64 ASCII letters, numbers, dots, underscores, or hyphens"
            )

    def to_dict(self) -> dict[str, object]:
        """Return the stable, JSON-compatible representation used for hashing."""
        return {
            "prompt": self.prompt,
            "seed": self.seed,
            "width": self.width,
            "height": self.height,
            "reference_ids": list(self.reference_ids),
            "output_slot": self.output_slot,
        }

    def canonical_json(self) -> str:
        """Serialize intent with stable key ordering and no insignificant space."""
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Return the SHA-256 digest bound to an idempotency key."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GenerationRequestRecord:
    """Persisted identity and creation time for one immutable request value."""

    request_id: str
    request: GenerationRequest
    request_digest: str
    created_at: str

    def to_dict(self) -> dict[str, object]:
        """Return the request snapshot exposed by the local CLI."""
        return {
            "request_id": self.request_id,
            **self.request.to_dict(),
            "request_digest": self.request_digest,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class ResolvedReference:
    """A caller-supplied artifact ID resolved against persisted artifact data."""

    artifact_id: str
    content_sha256: str
    path: Path


@dataclass(frozen=True, slots=True)
class GenerationPlan:
    """Fully resolved, persisted inputs passed across the adapter boundary."""

    job_id: str
    attempt_id: str
    resolved_prompt: str
    seed: int
    width: int
    height: int
    references: tuple[ResolvedReference, ...]
    output_slot: str
    output_slot_id: str


@dataclass(frozen=True, slots=True)
class GenerationJob:
    """Durable execution state derived from an immutable request."""

    job_id: str
    request_id: str
    status: str
    adapter_id: str
    adapter_configuration: Mapping[str, object]
    resolved_prompt: str
    resolved_seed: int
    validated_reference_ids: tuple[str, ...]
    output_slot: str
    output_slot_id: str
    effective_parameters: Mapping[str, object]
    created_at: str
    updated_at: str
    artifact_id: str | None = None
    max_attempts: int = 1
    fence_epoch: int = 0
    execution_status: str | None = None
    resource_state: str = "available"
    retry_eligible: bool = False
    failure_message: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter_configuration", _freeze(self.adapter_configuration))
        object.__setattr__(self, "effective_parameters", _freeze(self.effective_parameters))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible snapshot of the durable job."""
        return {
            "job_id": self.job_id,
            "request_id": self.request_id,
            "status": self.status,
            "adapter_id": self.adapter_id,
            "adapter_configuration": _thaw(self.adapter_configuration),
            "resolved_prompt": self.resolved_prompt,
            "resolved_seed": self.resolved_seed,
            "validated_reference_ids": list(self.validated_reference_ids),
            "output_slot": self.output_slot,
            "output_slot_id": self.output_slot_id,
            "effective_parameters": _thaw(self.effective_parameters),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "artifact_id": self.artifact_id,
            "max_attempts": self.max_attempts,
            "fence_epoch": self.fence_epoch,
            "execution_status": self.execution_status or self.status,
            "resource_state": self.resource_state,
            "retry_eligible": self.retry_eligible,
            "failure_message": self.failure_message,
        }


@dataclass(frozen=True, slots=True)
class GenerationAttempt:
    """One concrete adapter invocation belonging to a durable generation job."""

    attempt_id: str
    job_id: str
    attempt_number: int
    status: str
    adapter_id: str
    started_at: str
    finished_at: str | None
    error_message: str | None
    owner_id: str | None = None
    claim_epoch: int = 0
    heartbeat_at: str | None = None
    lease_expires_at: str | None = None
    process_contained: bool | None = None
    containment_contract: str | None = None
    failure_class: str | None = None
    termination_proven: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return an inspectable execution-attempt snapshot."""
        return {
            "attempt_id": self.attempt_id,
            "job_id": self.job_id,
            "attempt_number": self.attempt_number,
            "status": self.status,
            "adapter_id": self.adapter_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error_message": self.error_message,
            "owner_id": self.owner_id,
            "claim_epoch": self.claim_epoch,
            "heartbeat_at": self.heartbeat_at,
            "lease_expires_at": self.lease_expires_at,
            "process_contained": self.process_contained,
            "containment_contract": self.containment_contract,
            "failure_class": self.failure_class,
            "termination_proven": self.termination_proven,
        }


@dataclass(frozen=True, slots=True)
class GenerationArtifact:
    """A logical output identity and the metadata of its stored image file."""

    artifact_id: str
    job_id: str
    attempt_id: str
    output_slot_id: str
    path: str
    media_type: str
    image_format: str
    width: int
    height: int
    file_size: int
    sha256: str
    created_at: str

    def to_dict(self) -> dict[str, object]:
        """Return artifact identity and accessible image metadata."""
        return {
            "artifact_id": self.artifact_id,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "output_slot_id": self.output_slot_id,
            "path": self.path,
            "media_type": self.media_type,
            "format": self.image_format,
            "width": self.width,
            "height": self.height,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class ImportedArtifact:
    """An independent image identity with operator-approved import provenance."""

    artifact_id: str
    path: str
    media_type: str
    image_format: str
    width: int
    height: int
    file_size: int
    sha256: str
    created_at: str
    import_provenance: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "import_provenance", _freeze(self.import_provenance))

    def to_dict(self) -> dict[str, object]:
        """Return import metadata without inventing generation identifiers."""
        return {
            "artifact_id": self.artifact_id, "origin": "imported", "path": self.path,
            "media_type": self.media_type, "format": self.image_format,
            "width": self.width, "height": self.height, "file_size": self.file_size,
            "sha256": self.sha256, "created_at": self.created_at,
            "import_provenance": _thaw(self.import_provenance),
        }


@dataclass(frozen=True, slots=True)
class ArtifactSource:
    """An ordered parent of a new artifact; reference means actual conditioning.

    Source denotes an input image being edited, derivation denotes a related
    rendition, and inspiration records creative origin without conditioning.
    Order is the source's position in the publication's source tuple.
    """

    artifact_id: str
    role: str = "reference"

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_id, str) or not _ARTIFACT_ID.fullmatch(self.artifact_id):
            raise InputValidationError("lineage sources require stable artifact IDs")
        if not isinstance(self.role, str) or self.role not in {"reference", "source", "derivation", "inspiration"}:
            raise InputValidationError("unsupported artifact lineage role")

    def to_dict(self) -> dict[str, str]:
        """Serialize the parent identity and its declared relationship."""
        return {"artifact_id": self.artifact_id, "role": self.role}
