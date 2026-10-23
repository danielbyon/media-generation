"""Schema constants, shared value types, and canonical JSON helpers.

The inventory schema is deliberately versioned independently from the T01
generation contract.  Every field written by the collector is JSON-compatible
so the report can be archived, diffed, or inspected without the Python package.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


SCHEMA_NAME = "media-generation.inventory"
SCHEMA_VERSION = 1
MANIFEST_SCHEMA_NAME = "media-generation.inventory-manifest"
MANIFEST_SCHEMA_VERSION = 1
REPLAY_SCHEMA_NAME = "media-generation.inventory-replay"
REPLAY_SCHEMA_VERSION = 1
FINGERPRINT_ALGORITHM = "environment-fingerprint/v1"
FINGERPRINT_INPUT_VERSION = 1


class InventoryError(Exception):
    """Base class for expected inventory failures."""


class InventoryValidationError(InventoryError):
    """A manifest, replay file, or command option is invalid."""


class InventoryOutputError(InventoryError):
    """Inventory output files could not be written."""


class ProbeStatus(str, Enum):
    """Outcome of one bounded observation or command execution."""

    OK = "ok"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ERROR = "error"
    MALFORMED = "malformed"


class InventoryStatus(str, Enum):
    """Overall completeness of one inventory collection."""

    OK = "ok"
    PARTIAL = "partial"
    BLOCKED = "blocked"


class Severity(str, Enum):
    """Finding severity used to explain status without hiding detail."""

    INFO = "info"
    WARNING = "warning"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class Observation:
    """Raw result of one file read, directory listing, stat, or command.

    ``text`` is intentionally raw for parsers.  Reports only retain bounded,
    sanitized excerpts in the human transcript; the JSON report contains
    structured parsed values and probe metadata instead of full command output.
    """

    status: str
    text: str = ""
    reason: str | None = None
    detail: str | None = None
    exit_code: int | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        """Return whether the observation completed successfully."""
        return self.status == ProbeStatus.OK.value


@dataclass(frozen=True, slots=True)
class ProbeRecord:
    """Auditable provenance for one attempted observation."""

    probe_id: str
    category: str
    status: str
    criticality: str
    source: str
    started_at: str
    duration_ms: int
    command: tuple[str, ...] | None
    exit_code: int | None
    output_bytes: int
    truncated: bool
    reason: str | None
    detail: str | None
    excerpt: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible probe record."""
        return {
            "probe_id": self.probe_id,
            "category": self.category,
            "status": self.status,
            "criticality": self.criticality,
            "source": self.source,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "command": list(self.command) if self.command is not None else None,
            "exit_code": self.exit_code,
            "output_bytes": self.output_bytes,
            "truncated": self.truncated,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A human-readable explanation attached to the report."""

    code: str
    severity: str
    subject: str
    message: str

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible finding."""
        return {
            "code": self.code,
            "severity": self.severity,
            "subject": self.subject,
            "message": self.message,
        }


def canonical_json(value: object) -> str:
    """Serialize a value with sorted keys and no insignificant whitespace."""
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest_value(value: object) -> str:
    """Return a prefixed SHA-256 digest over canonical JSON."""
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def digest_bytes(value: bytes) -> str:
    """Return a prefixed SHA-256 digest over raw bytes."""
    return "sha256:" + hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    """Return the current UTC time in an ISO-8601 form with milliseconds."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _unique_object_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys so declarations cannot be ambiguous."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> object:
    """Reject JSON constants that standard JSON does not define."""
    raise InventoryValidationError(f"non-finite JSON number is not allowed: {value}")


def _strict_float(value: str) -> float:
    """Reject decimal or exponent literals that overflow to infinity."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise InventoryValidationError(f"non-finite JSON number is not allowed: {value}")
    return parsed


def load_strict_json(
    path: Path, *, label: str, max_bytes: int | None = None
) -> object:
    """Read bounded UTF-8 JSON, rejecting duplicate object keys."""
    try:
        if max_bytes is None:
            raw_bytes = path.read_bytes()
        else:
            with path.open("rb") as handle:
                raw_bytes = handle.read(max_bytes + 1)
            if len(raw_bytes) > max_bytes:
                raise InventoryValidationError(
                    f"{label} is too large: exceeds {max_bytes} bytes"
                )
    except OSError as error:
        raise InventoryValidationError(f"{label} is not readable: {path}") from error
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryValidationError(f"{label} is not valid UTF-8: {error}") from error
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_non_finite,
            parse_float=_strict_float,
        )
    except json.JSONDecodeError as error:
        raise InventoryValidationError(f"{label} is not valid JSON: {error}") from error


def require_mapping(value: object, *, label: str) -> dict[str, Any]:
    """Return a JSON object or raise a validation error naming the field."""
    if not isinstance(value, dict):
        raise InventoryValidationError(f"{label} must be a JSON object")
    return value


def require_list(value: object, *, label: str) -> list[Any]:
    """Return a JSON array or raise a validation error naming the field."""
    if not isinstance(value, list):
        raise InventoryValidationError(f"{label} must be a JSON array")
    return value


def require_string(value: object, *, label: str) -> str:
    """Return a non-empty string or raise a validation error."""
    if not isinstance(value, str) or not value.strip():
        raise InventoryValidationError(f"{label} must be a non-empty string")
    return value


def reject_unknown_keys(value: dict[str, Any], allowed: set[str], *, label: str) -> None:
    """Reject unexpected declaration fields so typos cannot be ignored."""
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise InventoryValidationError(f"{label} contains unsupported fields: {', '.join(unknown)}")
