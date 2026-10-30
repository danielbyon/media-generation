"""Strict T07 declarations, evidence contracts, and transport configuration."""

from __future__ import annotations
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit
from .inventory.schema import (
    InventoryValidationError,
    digest_value,
    require_list,
    require_mapping,
    require_string,
    reject_unknown_keys,
)


CANDIDATE_SCHEMA = "media-generation.candidate-declaration"
CANDIDATE_SCHEMA_VERSION = 1
PREPARATION_MANIFEST_SCHEMA = "media-generation.candidate-preparation-manifest"
ACQUISITION_JOURNAL_SCHEMA = "media-generation.candidate-acquisition-journal"
ACQUISITION_CONFIG_SCHEMA = "media-generation.candidate-acquisition-config"
TRUSTED_EVIDENCE_SCHEMA = "media-generation.candidate-trusted-evidence"
COMPATIBILITY_EVIDENCE_SCHEMA = "media-generation.candidate-compatibility-evidence"
LICENSE_EVIDENCE_SCHEMA = "media-generation.candidate-license-evidence"
PROVENANCE_EVIDENCE_SCHEMA = "media-generation.candidate-provenance-evidence"
CONVERSION_EVIDENCE_SCHEMA = "media-generation.candidate-conversion-evidence"
SCHEMA_VERSION = 1
MAX_DECLARATION_BYTES = 1024 * 1024
MAX_ACQUISITION_CONFIG_BYTES = 64 * 1024
MAX_TRUSTED_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024 * 1024
MAX_REMOTE_TRANSFER_BYTES = 512 * 1024 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_JSON_NESTING_DEPTH = 128
COMPONENT_ROLES = frozenset(
    {
        "checkpoint",
        "diffusion_model",
        "text_encoder",
        "vision_encoder",
        "tokenizer",
        "processor",
        "vae",
        "lora",
        "adapter",
        "controlnet",
        "projector",
        "other",
    }
)
READY = "ready"
MISSING = "missing"
CORRUPT = "corrupt"
INCOMPATIBLE = "incompatible"
UNVERIFIED = "unverified"
_STATUS_RANK = {READY: 0, UNVERIFIED: 1, MISSING: 2, CORRUPT: 3, INCOMPATIBLE: 4}
_UNAVAILABLE_PRECISION = frozenset({"", "auto", "default", "unknown", "unverified"})
_PLACEHOLDER_IDENTITY = _UNAVAILABLE_PRECISION | frozenset(
    {
        "current",
        "latest",
        "main",
        "master",
        "n/a",
        "na",
        "none",
        "not applicable",
        "not-applicable",
        "not available",
        "null",
        "placeholder",
        "tbd",
        "todo",
        "unspecified",
    }
)
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_STANDARD_SPDX_IDENTIFIERS = frozenset(
    {
        "0BSD",
        "AFL-3.0",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-1.1",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-Clear",
        "BSD-4-Clause",
        "BSL-1.0",
        "CC-BY-3.0",
        "CC-BY-4.0",
        "CC-BY-NC-4.0",
        "CC-BY-ND-4.0",
        "CC-BY-SA-3.0",
        "CC-BY-SA-4.0",
        "CC0-1.0",
        "CDDL-1.0",
        "CDDL-1.1",
        "EPL-1.0",
        "EPL-2.0",
        "EUPL-1.1",
        "EUPL-1.2",
        "GFDL-1.3-only",
        "GFDL-1.3-or-later",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "MS-PL",
        "NCSA",
        "ODbL-1.0",
        "OFL-1.1",
        "OpenSSL",
        "PostgreSQL",
        "Python-2.0",
        "Unlicense",
        "UPL-1.0",
        "WTFPL",
        "Zlib",
        "ZPL-2.1",
    }
)
_LICENSE_REF = re.compile(r"\ALicenseRef-[A-Za-z0-9][A-Za-z0-9.-]{0,119}\Z")
class CandidateError(Exception):
    """Base class for errors that have a safe, structured CLI representation."""
class CandidateValidationError(CandidateError):
    """The declaration or the separately authorized transport config is invalid."""
class CandidateOutputError(CandidateError):
    """A requested manifest or journal could not be published safely."""
class CandidateAcquisitionError(CandidateError):
    """An explicitly authorized transfer or its staging operation failed."""
@dataclass(frozen=True, slots=True)
class DeclaredRoot:
    """A trusted directory boundary used for descriptor-relative file access."""

    id: str
    path: Path
@dataclass(frozen=True, slots=True)
class ArtifactPin:
    """An exact regular file identity beneath one declared root."""

    root: str
    path: str
    size_bytes: int
    sha256: str

    def identity(self) -> dict[str, object]:
        return {
            "root": self.root,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    def resolved_path(self, roots: Mapping[str, DeclaredRoot]) -> Path:
        return roots[self.root].path / Path(self.path)
@dataclass(frozen=True, slots=True)
class Provenance:
    """Attribution for the exact upstream software or model artifact."""

    publisher: str
    revision: str
    canonical_url: str
    evidence: ArtifactPin

    def identity(self) -> dict[str, object]:
        return {
            "publisher": self.publisher,
            "revision": self.revision,
            "canonical_url": self.canonical_url,
            "evidence": self.evidence.identity(),
        }
@dataclass(frozen=True, slots=True)
class LicenseDeclaration:
    """Named terms and an independently pinned evidence document."""

    name: str
    spdx: str
    terms_url: str
    evidence: ArtifactPin

    def identity(self) -> dict[str, object]:
        return {
            "name": self.name,
            "spdx": self.spdx,
            "terms_url": self.terms_url,
            "evidence": self.evidence.identity(),
        }
@dataclass(frozen=True, slots=True)
class ConversionDeclaration:
    """Conversion lineage and supporting evidence for one component."""

    lineage: str
    tool_name: str | None
    tool_version: str | None
    evidence: ArtifactPin

    def identity(self) -> dict[str, object]:
        return {
            "lineage": self.lineage,
            "tool": (
                None
                if self.tool_name is None
                else {"name": self.tool_name, "version": self.tool_version}
            ),
            "evidence": self.evidence.identity(),
        }
@dataclass(frozen=True, slots=True)
class EngineDeclaration:
    """Exact local engine executable and software identity."""

    id: str
    version: str
    build: str
    executable: ArtifactPin
    provenance: Provenance
    license: LicenseDeclaration
    architecture_flags: tuple[tuple[str, object], ...]

    def identity(self) -> dict[str, object]:
        return {
            "id": self.id,
            "version": self.version,
            "build": self.build,
            "executable": self.executable.identity(),
            "provenance": self.provenance.identity(),
            "license": self.license.identity(),
            "architecture_flags": dict(self.architecture_flags),
        }
@dataclass(frozen=True, slots=True)
class CompatibilityEvidence:
    """Pinned document covering one or more exact compatibility claims."""

    claims: tuple[str, ...]
    document: ArtifactPin

    def identity(self) -> dict[str, object]:
        return {"claims": list(self.claims), "document": self.document.identity()}
@dataclass(frozen=True, slots=True)
class RecipeDeclaration:
    """Bounded recipe identity and its documented compatibility claims."""

    id: str
    document: ArtifactPin
    required_roles: tuple[str, ...]
    engine_id: str
    engine_version: str
    pipeline_version: str
    template_version: str
    architecture_flags: tuple[tuple[str, object], ...]
    evidence: tuple[CompatibilityEvidence, ...]

    def identity(self) -> dict[str, object]:
        return {
            "id": self.id,
            "document": self.document.identity(),
            "required_roles": list(self.required_roles),
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "pipeline_version": self.pipeline_version,
            "template_version": self.template_version,
            "architecture_flags": dict(self.architecture_flags),
            "evidence": [item.identity() for item in self.evidence],
        }
@dataclass(frozen=True, slots=True)
class ComponentDeclaration:
    """One exact model component and its lifecycle metadata."""

    id: str
    role: str
    artifact: ArtifactPin
    provenance: Provenance
    license: LicenseDeclaration
    precision: str
    quantization: str
    conversion: ConversionDeclaration

    def identity(self) -> dict[str, object]:
        return {
            "id": self.id,
            "role": self.role,
            "artifact": self.artifact.identity(),
            "provenance": self.provenance.identity(),
            "license": self.license.identity(),
            "precision": self.precision,
            "quantization": self.quantization,
            "conversion": self.conversion.identity(),
        }
@dataclass(frozen=True, slots=True)
class AdapterDeclaration:
    """Stable application order and strength for one adapter component."""

    component_id: str
    order: int
    strength: float

    def to_dict(self) -> dict[str, object]:
        return {
            "component_id": self.component_id,
            "order": self.order,
            "strength": self.strength,
        }
@dataclass(frozen=True, slots=True)
class AcquisitionSource:
    """Exact explicit remote source for one missing engine/recipe/component pin."""

    artifact: str
    url: str

    def identity(self) -> dict[str, str]:
        return {"artifact": self.artifact, "url": self.url}
@dataclass(frozen=True, slots=True)
class InventoryEvidence:
    """A pinned T02 report and the exact bundle it supplements."""

    document: ArtifactPin
    bundle_id: str

    def identity(self) -> dict[str, object]:
        return {
            "document": self.document.identity(),
            "bundle_id": self.bundle_id,
        }
@dataclass(frozen=True, slots=True)
class CandidateDeclaration:
    """Validated, normalized T07 declaration and its raw file identity."""

    path: Path
    declaration_sha256: str
    id: str
    roots: tuple[DeclaredRoot, ...]
    engine: EngineDeclaration
    recipe: RecipeDeclaration
    components: tuple[ComponentDeclaration, ...]
    adapters: tuple[AdapterDeclaration, ...]
    acquisition_sources: tuple[AcquisitionSource, ...]
    inventory_evidence: InventoryEvidence | None

    @property
    def root_index(self) -> dict[str, DeclaredRoot]:
        return {root.id: root for root in self.roots}

    @property
    def component_index(self) -> dict[str, ComponentDeclaration]:
        return {component.id: component for component in self.components}

    def identity(self) -> dict[str, object]:
        return {
            "schema": CANDIDATE_SCHEMA,
            "schema_version": CANDIDATE_SCHEMA_VERSION,
            "id": self.id,
            "root_ids": [root.id for root in self.roots],
            "engine": self.engine.identity(),
            "recipe": self.recipe.identity(),
            "components": [component.identity() for component in self.components],
            "adapters": [adapter.to_dict() for adapter in self.adapters],
            "inventory_evidence": (
                None
                if self.inventory_evidence is None
                else self.inventory_evidence.identity()
            ),
        }

    def stable_candidate_id(self) -> str:
        """Return identity of declared expectations, excluding observations."""
        return digest_value(self.identity())

    def artifact_targets(self) -> dict[str, ArtifactPin]:
        """Return the explicit acquisition targets; evidence docs stay local."""
        targets = {
            "engine": self.engine.executable,
            "recipe": self.recipe.document,
        }
        for component in self.components:
            targets[f"component:{component.id}"] = component.artifact
        return targets
@dataclass(frozen=True, slots=True)
class StatusItem:
    """One independently actionable static verification result."""

    artifact: str
    status: str
    code: str
    message: str
    expected: dict[str, object] | None = None
    observed: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "artifact": self.artifact,
            "status": self.status,
            "code": self.code,
            "message": self.message,
        }
        if self.expected is not None:
            payload["expected"] = self.expected
        if self.observed is not None:
            payload["observed"] = self.observed
        return payload
@dataclass(frozen=True, slots=True)
class ObservedArtifact:
    """Stable observation of one complete regular file."""

    status: str
    code: str
    size_bytes: int | None
    sha256: str | None
    content: bytes | None = field(default=None, compare=False, repr=False)
    physical_identity: tuple[int, int] | None = field(
        default=None, compare=False, repr=False
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "code": self.code,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }
@dataclass(frozen=True, slots=True)
class TrustedEvidence:
    """Host-owned independent expectation for one exact evidence file.

    Candidate declarations cannot create these records. Production callers
    leave the authority collection empty until reviewed upstream pins are
    packaged; synthetic tests may supply explicitly labeled literal records.
    """

    authority_id: str
    document_size_bytes: int
    document_sha256: str
    expected: dict[str, object]

    def __post_init__(self) -> None:
        _identifier(self.authority_id, label="trusted_evidence.authority_id")
        _positive_int(
            self.document_size_bytes,
            label="trusted_evidence.document_size_bytes",
            maximum=MAX_EVIDENCE_BYTES,
        )
        _sha256(self.document_sha256, label="trusted_evidence.document_sha256")
        require_mapping(self.expected, label="trusted_evidence.expected")
@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    """The single authoritative result reused by inspect, verify, and prepare."""

    declaration: CandidateDeclaration
    items: tuple[StatusItem, ...]
    candidate_id: str
    verification_id: str
    observations: dict[str, ObservedArtifact]

    @property
    def status(self) -> str:
        return max((item.status for item in self.items), key=_STATUS_RANK.__getitem__)

    @property
    def evidence_authority_status(self) -> str:
        """Return whether every evidence contract has independent authority."""
        authority_items = tuple(
            item
            for item in self.items
            if item.artifact.endswith(
                (".provenance.evidence", ".license.evidence", ".conversion.evidence")
            )
            or item.artifact.startswith("recipe.compatibility.evidence[")
        )
        if authority_items and all(item.status == READY for item in authority_items):
            return READY
        return UNVERIFIED

    def report(self, operation: str) -> dict[str, object]:
        reasons = [
            {"artifact": item.artifact, "code": item.code, "message": item.message}
            for item in self.items
            if item.status != READY
        ]
        return {
            "schema": "media-generation.candidate-verification",
            "schema_version": SCHEMA_VERSION,
            "operation": operation,
            "candidate_id": self.candidate_id,
            "verification_id": self.verification_id,
            "declared_id": self.declaration.id,
            "status": self.status,
            "items": [item.to_dict() for item in self.items],
            "reasons": reasons,
            "evidence": {
                "static_preparation": self.status,
                "independent_evidence_authority": self.evidence_authority_status,
                "apex_execution": UNVERIFIED,
                "apex_execution_reason": "model_loading_and_inference_not_performed",
                "t08_execution": "required",
                "t19_qualification": UNVERIFIED,
            },
        }

    def manifest(self) -> dict[str, object]:
        declaration = self.declaration
        roots = declaration.root_index
        return {
            "schema": PREPARATION_MANIFEST_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "candidate_id": self.candidate_id,
            "verification_id": self.verification_id,
            "declared_id": declaration.id,
            "declaration_sha256": declaration.declaration_sha256,
            "status": self.status,
            "identity": declaration.identity(),
            "engine": {
                **declaration.engine.identity(),
                "executable_path": str(
                    declaration.engine.executable.resolved_path(roots)
                ),
            },
            "recipe": {
                **declaration.recipe.identity(),
                "document_path": str(declaration.recipe.document.resolved_path(roots)),
            },
            "components": [
                {
                    **component.identity(),
                    "path": str(component.artifact.resolved_path(roots)),
                }
                for component in declaration.components
            ],
            "adapters": [adapter.to_dict() for adapter in declaration.adapters],
            "verification": {
                "items": [item.to_dict() for item in self.items],
                "observations": {
                    key: value.to_dict()
                    for key, value in sorted(self.observations.items())
                },
            },
            "evidence": {
                "static_preparation": self.status,
                "independent_evidence_authority": self.evidence_authority_status,
                "apex_execution": UNVERIFIED,
                "apex_execution_reason": "model_loading_and_inference_not_performed",
                "t08_execution": "required",
                "t19_qualification": UNVERIFIED,
            },
        }
@dataclass(slots=True)
class AcquisitionConfig:
    """Validated transport-only settings; this object is never serialized."""

    allowed_origins: frozenset[str]
    credentials: dict[str, dict[str, str]]
    timeout_seconds: float
    max_redirects: int
    max_attempts: int
    max_total_bytes: int
    path: Path
def _candidate_error(error: Exception) -> CandidateValidationError:
    return CandidateValidationError(str(error))
def _control_file_snapshot(facts: os.stat_result) -> tuple[int, ...]:
    """Return metadata that must remain stable for a control-file snapshot."""
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_mode,
        facts.st_nlink,
        facts.st_uid,
        facts.st_gid,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
    )


def _read_bounded_file(path: Path, *, maximum: int, label: str) -> bytes:
    """Read one stable, bounded snapshot of a control JSON file.

    The opened descriptor identifies the bytes being parsed. The helper checks
    its metadata before and after the read and confirms the path still resolves
    to that same object. A symlink to a regular file is accepted while the
    link target is stable.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CandidateValidationError(f"{label} not readable: {path}") from error

    try:
        try:
            before = os.fstat(descriptor)
        except OSError as error:
            raise CandidateValidationError(
                f"{label} metadata not readable: {path}"
            ) from error
        if not stat.S_ISREG(before.st_mode):
            raise CandidateValidationError(f"{label} must be a regular file")
        if before.st_size > maximum:
            raise CandidateValidationError(f"{label} exceeds {maximum} bytes")

        try:
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(maximum + 1)
        except OSError as error:
            raise CandidateValidationError(f"{label} not readable: {path}") from error

        try:
            after = os.fstat(descriptor)
            current = os.stat(path)
        except OSError as error:
            raise CandidateValidationError(
                f"{label} changed while being read: {path}"
            ) from error
        stable_snapshot = _control_file_snapshot(before)
        if (
            _control_file_snapshot(after) != stable_snapshot
            or _control_file_snapshot(current) != stable_snapshot
        ):
            raise CandidateValidationError(
                f"{label} changed while being read: {path}"
            )
    finally:
        os.close(descriptor)

    if len(data) > maximum:
        raise CandidateValidationError(f"{label} exceeds {maximum} bytes")
    return data

def _require_bounded_json_nesting(text: str, *, label: str) -> None:
    """Reject pathological JSON container nesting before recursive decoding.

    The caller has already enforced the byte limit. This lexical scan counts
    only unescaped ``{`` and ``[`` characters outside JSON strings, so braces
    and brackets in keys and values do not contribute to the depth. Syntax
    validation remains the responsibility of :func:`json.loads`.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise CandidateValidationError(
                    f"{label} exceeds maximum JSON nesting depth "
                    f"{MAX_JSON_NESTING_DEPTH}"
                )
        elif char in "}]":
            depth -= 1


def _load_strict_bytes(data: bytes, *, label: str) -> object:
    """Parse strict JSON from the exact bytes used for declaration identity."""
    def unique_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CandidateValidationError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise CandidateValidationError(f"{label} contains non-finite value {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise CandidateValidationError(f"{label} contains a non-finite number")
        return parsed

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CandidateValidationError(f"{label} is not valid UTF-8") from error
    _require_bounded_json_nesting(text, label=label)
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
            parse_float=finite_float,
        )
    except json.JSONDecodeError as error:
        raise CandidateValidationError(
            f"{label} is not valid JSON at line {error.lineno} column {error.colno}"
        ) from error
    except ValueError as error:
        raise CandidateValidationError(
            f"{label} contains a number outside supported limits"
        ) from error
    except RecursionError as error:
        raise CandidateValidationError(
            f"{label} exceeds maximum JSON nesting depth {MAX_JSON_NESTING_DEPTH}"
        ) from error
def _identifier(value: object, *, label: str) -> str:
    text = require_string(value, label=label)
    if not _IDENTIFIER.fullmatch(text):
        raise CandidateValidationError(f"{label} is not a valid identifier")
    return text


def _known_identifier(value: object, *, label: str) -> str:
    """Return an identifier that cannot be a placeholder identity."""

    text = _identifier(value, label=label)
    normalized = " ".join(text.casefold().split())
    if normalized in _PLACEHOLDER_IDENTITY:
        raise CandidateValidationError(f"{label} must be exact and known")
    return text
def _bounded_string(value: object, *, label: str, limit: int = 1024) -> str:
    text = require_string(value, label=label)
    if len(text) > limit:
        raise CandidateValidationError(f"{label} must be at most {limit} characters")
    if "\x00" in text:
        raise CandidateValidationError(f"{label} must not contain NUL")
    return text


def _known_identity(value: object, *, label: str, limit: int = 1024) -> str:
    """Return one nonplaceholder identity value with surrounding whitespace removed."""
    text = _bounded_string(value, label=label, limit=limit).strip()
    normalized = " ".join(text.casefold().split())
    if not normalized or normalized in _PLACEHOLDER_IDENTITY:
        raise CandidateValidationError(f"{label} must be exact and known")
    return text
def _positive_int(value: object, *, label: str, maximum: int, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CandidateValidationError(f"{label} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum or value > maximum:
        raise CandidateValidationError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return value


def _schema_version(value: object, *, label: str, expected: int) -> int:
    """Require a supported JSON integer schema version without coercion."""
    if type(value) is not int or value != expected:
        raise CandidateValidationError(f"{label} must be {expected}")
    return value
def _sha256(value: object, *, label: str) -> str:
    text = require_string(value, label=label)
    if not _SHA256.fullmatch(text):
        raise CandidateValidationError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )
    return text
def _https_url(value: object, *, label: str) -> str:
    text = _bounded_string(value, label=label, limit=4096)
    try:
        parsed = urlsplit(text)
    except ValueError as error:
        raise CandidateValidationError(
            f"{label} must be an absolute HTTPS URL"
        ) from error
    if parsed.scheme != "https" or not parsed.hostname:
        raise CandidateValidationError(f"{label} must be an absolute HTTPS URL")
    try:
        parsed.port
    except ValueError as error:
        raise CandidateValidationError(f"{label} contains an invalid port") from error
    if parsed.username is not None or parsed.password is not None:
        raise CandidateValidationError(f"{label} must not contain user information")
    if parsed.fragment:
        raise CandidateValidationError(f"{label} must not contain a fragment")
    return text


def _credential_header_name(value: object, *, label: str) -> str:
    """Validate and normalize one credential-bearing HTTP header name."""

    name = _bounded_string(value, label=label, limit=128)
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
        raise CandidateValidationError(f"{label} is not a valid HTTP header name")
    if name.lower() in {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "transfer-encoding",
    }:
        raise CandidateValidationError(
            f"{label} is not an allowed credential header"
        )
    return name


def _acquisition_origin(value: str, *, label: str) -> str:
    """Validate and normalize one credential-bearing HTTPS origin."""
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise CandidateValidationError(f"{label} must be an HTTPS origin") from error
    if parsed.scheme != "https" or not parsed.hostname:
        raise CandidateValidationError(f"{label} must be an HTTPS origin")
    if parsed.username is not None or parsed.password is not None:
        raise CandidateValidationError(f"{label} must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise CandidateValidationError(
            f"{label} must contain only a scheme, host, and port"
        )
    try:
        port = parsed.port
    except ValueError as error:
        raise CandidateValidationError(f"{label} contains an invalid port") from error
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port is not None else "")
def _acquisition_asset_url(value: object, *, label: str) -> str:
    text = _https_url(value, label=label)
    parsed = urlsplit(text)
    if parsed.query or parsed.fragment:
        raise CandidateValidationError(
            f"{label} must not contain a query string or fragment"
        )
    return text
def _relative_artifact_path(value: object, *, label: str) -> str:
    text = _bounded_string(value, label=label, limit=1024)
    if text.startswith("/") or "\\" in text:
        raise CandidateValidationError(f"{label} must be a POSIX relative path")
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CandidateValidationError(f"{label} contains an unsafe path component")
    return text
def _root_path(value: object, *, base: Path, label: str) -> Path:
    text = _bounded_string(value, label=label, limit=4096)
    candidate = _expand_user_path(text, label=label)
    if not candidate.is_absolute():
        candidate = base / candidate
    return Path(os.path.abspath(candidate))


def _expand_user_path(
    value: str | Path,
    *,
    label: str,
    error_type: type[CandidateError] = CandidateValidationError,
) -> Path:
    """Expand one user path and normalize unknown-user lookup failures."""
    try:
        return Path(value).expanduser()
    except RuntimeError as error:
        raise error_type(f"{label} path cannot be expanded") from error


def _physical_path(path: Path) -> Path:
    """Return a canonical path that follows every symlink that currently exists."""
    return Path(os.path.normcase(os.path.realpath(path)))
def _scalar(value: object, *, label: str) -> object:
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CandidateValidationError(f"{label} must be finite")
        return value
    if isinstance(value, str):
        return _known_identity(value, label=label, limit=512)
    raise CandidateValidationError(f"{label} must be a JSON string, number, or boolean")
def _parse_flags(value: object, *, label: str) -> tuple[tuple[str, object], ...]:
    mapping = require_mapping(value, label=label)
    flags: list[tuple[str, object]] = []
    for name, raw_value in mapping.items():
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", name
        ):
            raise CandidateValidationError(f"{label} contains an invalid flag name")
        if " ".join(name.casefold().split()) in _PLACEHOLDER_IDENTITY:
            raise CandidateValidationError(f"{label} contains a placeholder flag name")
        flags.append((name, _scalar(raw_value, label=f"{label}.{name}")))
    return tuple(sorted(flags))
def _parse_roots(value: object, *, base: Path) -> tuple[DeclaredRoot, ...]:
    raw_roots = require_list(value, label="roots")
    if not raw_roots or len(raw_roots) > 16:
        raise CandidateValidationError("roots must contain between 1 and 16 entries")
    roots: list[DeclaredRoot] = []
    for index, raw in enumerate(raw_roots):
        label = f"roots[{index}]"
        item = require_mapping(raw, label=label)
        reject_unknown_keys(item, {"id", "path"}, label=label)
        roots.append(
            DeclaredRoot(
                id=_identifier(item.get("id"), label=f"{label}.id"),
                path=_root_path(item.get("path"), base=base, label=f"{label}.path"),
            )
        )
    ids = [root.id for root in roots]
    if len(ids) != len(set(ids)):
        raise CandidateValidationError("root ids must be unique")
    paths = [str(root.path) for root in roots]
    if len(paths) != len(set(paths)):
        raise CandidateValidationError("root paths must be unique")
    physical_paths = [_physical_path(root.path) for root in roots]
    if len(physical_paths) != len(set(physical_paths)):
        raise CandidateValidationError("root physical paths must be unique")
    for index, physical_path in enumerate(physical_paths):
        for other in physical_paths[index + 1 :]:
            try:
                common = os.path.commonpath((physical_path, other))
            except ValueError:
                continue
            if Path(common) in {physical_path, other}:
                raise CandidateValidationError(
                    "root physical paths must not contain nested roots or aliases"
                )
    return tuple(roots)
def _parse_pin(
    value: object,
    *,
    label: str,
    root_ids: frozenset[str],
    maximum: int = MAX_ARTIFACT_BYTES,
) -> ArtifactPin:
    item = require_mapping(value, label=label)
    reject_unknown_keys(item, {"root", "path", "size_bytes", "sha256"}, label=label)
    root = _identifier(item.get("root"), label=f"{label}.root")
    if root not in root_ids:
        raise CandidateValidationError(f"{label}.root does not name a declared root")
    return ArtifactPin(
        root=root,
        path=_relative_artifact_path(item.get("path"), label=f"{label}.path"),
        size_bytes=_positive_int(
            item.get("size_bytes"), label=f"{label}.size_bytes", maximum=maximum
        ),
        sha256=_sha256(item.get("sha256"), label=f"{label}.sha256"),
    )
def _spdx_identifier(value: object, *, label: str) -> str:
    """Return one exact standard SPDX identifier or a valid LicenseRef."""
    text = _bounded_string(value, label=label, limit=128)
    if text in _STANDARD_SPDX_IDENTIFIERS or _LICENSE_REF.fullmatch(text):
        return text
    raise CandidateValidationError(
        f"{label} must be a supported SPDX identifier or LicenseRef identifier"
    )
def _parse_provenance(
    value: object,
    *,
    label: str,
    root_ids: frozenset[str],
) -> Provenance:
    item = require_mapping(value, label=label)
    reject_unknown_keys(
        item,
        {"publisher", "revision", "canonical_url", "evidence"},
        label=label,
    )
    return Provenance(
        publisher=_known_identity(
            item.get("publisher"), label=f"{label}.publisher"
        ),
        revision=_known_identity(item.get("revision"), label=f"{label}.revision"),
        canonical_url=_https_url(
            item.get("canonical_url"), label=f"{label}.canonical_url"
        ),
        evidence=_parse_pin(
            item.get("evidence"),
            label=f"{label}.evidence",
            root_ids=root_ids,
            maximum=MAX_EVIDENCE_BYTES,
        ),
    )
def _parse_license(
    value: object, *, label: str, root_ids: frozenset[str]
) -> LicenseDeclaration:
    item = require_mapping(value, label=label)
    reject_unknown_keys(
        item, {"name", "spdx", "terms_url", "evidence"}, label=label
    )
    return LicenseDeclaration(
        name=_known_identity(item.get("name"), label=f"{label}.name"),
        spdx=_spdx_identifier(item.get("spdx"), label=f"{label}.spdx"),
        terms_url=_https_url(item.get("terms_url"), label=f"{label}.terms_url"),
        evidence=_parse_pin(
            item.get("evidence"),
            label=f"{label}.evidence",
            root_ids=root_ids,
            maximum=MAX_EVIDENCE_BYTES,
        ),
    )
def _parse_conversion(
    value: object, *, label: str, root_ids: frozenset[str]
) -> ConversionDeclaration:
    item = require_mapping(value, label=label)
    reject_unknown_keys(item, {"lineage", "tool", "evidence"}, label=label)
    lineage = _known_identity(
        item.get("lineage"), label=f"{label}.lineage", limit=256
    )
    tool_name: str | None = None
    tool_version: str | None = None
    raw_tool = item.get("tool")
    if raw_tool is not None:
        tool = require_mapping(raw_tool, label=f"{label}.tool")
        reject_unknown_keys(tool, {"name", "version"}, label=f"{label}.tool")
        tool_name = _known_identity(tool.get("name"), label=f"{label}.tool.name")
        tool_version = _known_identity(
            tool.get("version"), label=f"{label}.tool.version"
        )
    return ConversionDeclaration(
        lineage=lineage,
        tool_name=tool_name,
        tool_version=tool_version,
        evidence=_parse_pin(
            item.get("evidence"),
            label=f"{label}.evidence",
            root_ids=root_ids,
            maximum=MAX_EVIDENCE_BYTES,
        ),
    )
def _known_metric(
    value: object, *, label: str, allow_none: bool = False
) -> str:
    """Return one explicit metric value, permitting ``none`` only when stated.

    Quantization uses the literal value ``none`` to mean that no quantization
    transform applies. Precision does not have that meaning, so its parser
    continues to reject the otherwise ambiguous word.
    """
    text = _bounded_string(value, label=label, limit=128).strip()
    if allow_none and text.casefold() == "none":
        return "none"
    return _known_identity(text, label=label, limit=128).casefold()
def _known_version(value: object, *, label: str) -> str:
    """Return one explicit non-placeholder version or configuration value."""
    return _known_identity(value, label=label, limit=256)
def _parse_engine(value: object, *, root_ids: frozenset[str]) -> EngineDeclaration:
    item = require_mapping(value, label="engine")
    reject_unknown_keys(
        item,
        {
            "id",
            "version",
            "build",
            "executable",
            "provenance",
            "license",
            "architecture_flags",
        },
        label="engine",
    )
    return EngineDeclaration(
        id=_known_identifier(item.get("id"), label="engine.id"),
        version=_known_identity(item.get("version"), label="engine.version", limit=256),
        build=_known_identity(item.get("build"), label="engine.build", limit=256),
        executable=_parse_pin(
            item.get("executable"), label="engine.executable", root_ids=root_ids
        ),
        provenance=_parse_provenance(
            item.get("provenance"),
            label="engine.provenance",
            root_ids=root_ids,
        ),
        license=_parse_license(
            item.get("license"), label="engine.license", root_ids=root_ids
        ),
        architecture_flags=_parse_flags(
            item.get("architecture_flags"), label="engine.architecture_flags"
        ),
    )
def _allowed_claims(required_roles: Iterable[str], flag_names: Iterable[str]) -> set[str]:
    claims = {"engine", "version", "recipe"}
    claims.update(f"role:{role}" for role in required_roles)
    claims.update(f"flag:{name}" for name in flag_names)
    return claims
def _parse_recipe(
    value: object, *, root_ids: frozenset[str]
) -> RecipeDeclaration:
    item = require_mapping(value, label="recipe")
    reject_unknown_keys(
        item,
        {
            "id",
            "document",
            "required_component_roles",
            "engine_id",
            "engine_version",
            "pipeline_version",
            "template_version",
            "architecture_flags",
            "compatibility_evidence",
        },
        label="recipe",
    )
    raw_roles = require_list(
        item.get("required_component_roles"),
        label="recipe.required_component_roles",
    )
    roles = tuple(
        _identifier(role, label=f"recipe.required_component_roles[{index}]")
        for index, role in enumerate(raw_roles)
    )
    if not roles or len(roles) > 32:
        raise CandidateValidationError(
            "recipe.required_component_roles must contain between 1 and 32 roles"
        )
    if len(roles) != len(set(roles)):
        raise CandidateValidationError("recipe.required_component_roles must be unique")
    unknown_roles = sorted(set(roles) - COMPONENT_ROLES)
    if unknown_roles:
        raise CandidateValidationError(
            "recipe.required_component_roles contains unsupported roles: "
            + ", ".join(unknown_roles)
        )
    flags = _parse_flags(
        item.get("architecture_flags"), label="recipe.architecture_flags"
    )
    allowed_claims = _allowed_claims(roles, (name for name, _ in flags))
    raw_evidence = require_list(
        item.get("compatibility_evidence"),
        label="recipe.compatibility_evidence",
    )
    if not raw_evidence or len(raw_evidence) > 64:
        raise CandidateValidationError(
            "recipe.compatibility_evidence must contain between 1 and 64 entries"
        )
    evidence: list[CompatibilityEvidence] = []
    for index, raw in enumerate(raw_evidence):
        label = f"recipe.compatibility_evidence[{index}]"
        entry = require_mapping(raw, label=label)
        reject_unknown_keys(entry, {"claims", "document"}, label=label)
        raw_claims = require_list(entry.get("claims"), label=f"{label}.claims")
        claims = tuple(
            _bounded_string(claim, label=f"{label}.claims[{claim_index}]", limit=160)
            for claim_index, claim in enumerate(raw_claims)
        )
        if not claims or len(claims) != len(set(claims)):
            raise CandidateValidationError(f"{label}.claims must be non-empty and unique")
        unknown_claims = sorted(set(claims) - allowed_claims)
        if unknown_claims:
            raise CandidateValidationError(
                f"{label}.claims contains unsupported claims: "
                + ", ".join(unknown_claims)
            )
        evidence.append(
            CompatibilityEvidence(
                claims=claims,
                document=_parse_pin(
                    entry.get("document"),
                    label=f"{label}.document",
                    root_ids=root_ids,
                    maximum=MAX_EVIDENCE_BYTES,
                ),
            )
        )
    return RecipeDeclaration(
        id=_known_identifier(item.get("id"), label="recipe.id"),
        document=_parse_pin(
            item.get("document"),
            label="recipe.document",
            root_ids=root_ids,
            maximum=MAX_EVIDENCE_BYTES,
        ),
        required_roles=roles,
        engine_id=_known_identifier(
            item.get("engine_id"), label="recipe.engine_id"
        ),
        engine_version=_known_identity(
            item.get("engine_version"), label="recipe.engine_version", limit=256
        ),
        pipeline_version=_known_version(
            item.get("pipeline_version"), label="recipe.pipeline_version"
        ),
        template_version=_known_version(
            item.get("template_version"), label="recipe.template_version"
        ),
        architecture_flags=flags,
        evidence=tuple(evidence),
    )
def _parse_component(
    value: object, *, index: int, root_ids: frozenset[str]
) -> ComponentDeclaration:
    label = f"components[{index}]"
    item = require_mapping(value, label=label)
    reject_unknown_keys(
        item,
        {
            "id",
            "role",
            "artifact",
            "provenance",
            "license",
            "precision",
            "quantization",
            "conversion",
        },
        label=label,
    )
    role = _identifier(item.get("role"), label=f"{label}.role")
    if role not in COMPONENT_ROLES:
        raise CandidateValidationError(f"{label}.role is unsupported")
    return ComponentDeclaration(
        id=_known_identifier(item.get("id"), label=f"{label}.id"),
        role=role,
        artifact=_parse_pin(
            item.get("artifact"), label=f"{label}.artifact", root_ids=root_ids
        ),
        provenance=_parse_provenance(
            item.get("provenance"),
            label=f"{label}.provenance",
            root_ids=root_ids,
        ),
        license=_parse_license(
            item.get("license"), label=f"{label}.license", root_ids=root_ids
        ),
        precision=_known_metric(item.get("precision"), label=f"{label}.precision"),
        quantization=_known_metric(
            item.get("quantization"),
            label=f"{label}.quantization",
            allow_none=True,
        ),
        conversion=_parse_conversion(
            item.get("conversion"), label=f"{label}.conversion", root_ids=root_ids
        ),
    )
def _parse_adapters(
    value: object, *, components: tuple[ComponentDeclaration, ...]
) -> tuple[AdapterDeclaration, ...]:
    """Normalize one ordered entry for every adapter- or LoRA-role component."""
    raw_adapters = require_list(value, label="adapters")
    if len(raw_adapters) > 64:
        raise CandidateValidationError("adapters must contain at most 64 entries")
    by_id = {component.id: component for component in components}
    adapters: list[AdapterDeclaration] = []
    for index, raw in enumerate(raw_adapters):
        label = f"adapters[{index}]"
        item = require_mapping(raw, label=label)
        reject_unknown_keys(
            item, {"component_id", "order", "strength"}, label=label
        )
        component_id = _identifier(
            item.get("component_id"), label=f"{label}.component_id"
        )
        component = by_id.get(component_id)
        if component is None:
            raise CandidateValidationError(
                f"{label}.component_id does not name a declared component"
            )
        if component.role not in {"adapter", "lora"}:
            raise CandidateValidationError(
                f"{label}.component_id must name an adapter- or lora-role component"
            )
        order = _positive_int(item.get("order"), label=f"{label}.order", maximum=64)
        strength_raw = item.get("strength")
        if isinstance(strength_raw, bool) or not isinstance(strength_raw, (int, float)):
            raise CandidateValidationError(f"{label}.strength must be a number")
        if isinstance(strength_raw, int) and not -10 <= strength_raw <= 10:
            raise CandidateValidationError(
                f"{label}.strength must be between -10 and 10"
            )
        strength = float(strength_raw)
        if not math.isfinite(strength) or strength < -10 or strength > 10:
            raise CandidateValidationError(f"{label}.strength must be between -10 and 10")
        adapters.append(
            AdapterDeclaration(
                component_id=component_id,
                order=order,
                strength=strength,
            )
        )
    ids = [adapter.component_id for adapter in adapters]
    if len(ids) != len(set(ids)):
        raise CandidateValidationError("adapter component ids must be unique")
    orders = sorted(adapter.order for adapter in adapters)
    if orders != list(range(1, len(adapters) + 1)):
        raise CandidateValidationError("adapter order values must be contiguous from 1")
    adapter_components = {
        item.id for item in components if item.role in {"adapter", "lora"}
    }
    if adapter_components != set(ids):
        raise CandidateValidationError(
            "every adapter- or lora-role component must have exactly one adapter declaration"
        )
    return tuple(sorted(adapters, key=lambda item: item.order))
def _parse_acquisition_sources(
    value: object | None, *, targets: Mapping[str, ArtifactPin]
) -> tuple[AcquisitionSource, ...]:
    if value is None:
        return ()
    item = require_mapping(value, label="acquisition")
    reject_unknown_keys(item, {"sources"}, label="acquisition")
    raw_sources = require_list(item.get("sources"), label="acquisition.sources")
    if len(raw_sources) > 256:
        raise CandidateValidationError("acquisition.sources must contain at most 256 entries")
    sources: list[AcquisitionSource] = []
    for index, raw in enumerate(raw_sources):
        label = f"acquisition.sources[{index}]"
        entry = require_mapping(raw, label=label)
        reject_unknown_keys(entry, {"artifact", "url"}, label=label)
        artifact = _bounded_string(
            entry.get("artifact"), label=f"{label}.artifact", limit=160
        )
        if artifact not in targets:
            raise CandidateValidationError(
                f"{label}.artifact is not an acquirable engine, recipe, or component"
            )
        sources.append(
            AcquisitionSource(
                artifact=artifact,
                url=_acquisition_asset_url(
                    entry.get("url"), label=f"{label}.url"
                ),
            )
        )
    artifacts = [source.artifact for source in sources]
    if len(artifacts) != len(set(artifacts)):
        raise CandidateValidationError("acquisition source artifacts must be unique")
    urls = [source.url for source in sources]
    if len(urls) != len(set(urls)):
        raise CandidateValidationError("acquisition source URLs must be unique")
    return tuple(sources)
def parse_candidate(path: Path) -> CandidateDeclaration:
    """Load one strict, bounded candidate declaration."""
    declaration_path = _expand_user_path(path, label="candidate declaration")
    raw_bytes = _read_bounded_file(
        declaration_path, maximum=MAX_DECLARATION_BYTES, label="candidate declaration"
    )
    try:
        value = _load_strict_bytes(
            raw_bytes, label="candidate declaration"
        )
    except CandidateValidationError:
        raise
    try:
        item = require_mapping(value, label="candidate declaration")
        reject_unknown_keys(
            item,
            {
                "schema",
                "schema_version",
                "id",
                "roots",
                "engine",
                "recipe",
                "components",
                "adapters",
                "acquisition",
                "inventory_evidence",
            },
            label="candidate declaration",
        )
        if item.get("schema") != CANDIDATE_SCHEMA:
            raise CandidateValidationError(
                f"schema must be {CANDIDATE_SCHEMA!r}"
            )
        _schema_version(
            item.get("schema_version"),
            label="schema_version",
            expected=CANDIDATE_SCHEMA_VERSION,
        )
        base = Path(os.path.abspath(declaration_path.parent))
        roots = _parse_roots(item.get("roots"), base=base)
        root_ids = frozenset(root.id for root in roots)
        engine = _parse_engine(item.get("engine"), root_ids=root_ids)
        recipe = _parse_recipe(item.get("recipe"), root_ids=root_ids)
        raw_components = require_list(item.get("components"), label="components")
        if not raw_components or len(raw_components) > 256:
            raise CandidateValidationError(
                "components must contain between 1 and 256 entries"
            )
        components = tuple(
            _parse_component(raw, index=index, root_ids=root_ids)
            for index, raw in enumerate(raw_components)
        )
        component_ids = [component.id for component in components]
        if len(component_ids) != len(set(component_ids)):
            raise CandidateValidationError("component ids must be unique")
        artifact_locations = [
            (engine.executable.root, engine.executable.path),
            (recipe.document.root, recipe.document.path),
            *((component.artifact.root, component.artifact.path) for component in components),
        ]
        if len(artifact_locations) != len(set(artifact_locations)):
            raise CandidateValidationError("engine, recipe, and component paths must be unique")
        root_paths = {root.id: root.path for root in roots}
        physical_locations = [
            _physical_path(root_paths[root_id] / Path(relative_path))
            for root_id, relative_path in artifact_locations
        ]
        if len(physical_locations) != len(set(physical_locations)):
            raise CandidateValidationError(
                "engine, recipe, and component physical paths must be unique"
            )
        file_identities: list[tuple[int, int]] = []
        for physical_path in physical_locations:
            try:
                facts = physical_path.stat()
            except OSError:
                continue
            if stat.S_ISREG(facts.st_mode):
                file_identities.append((facts.st_dev, facts.st_ino))
        if len(file_identities) != len(set(file_identities)):
            raise CandidateValidationError(
                "engine, recipe, and component physical files must be unique"
            )
        adapters = _parse_adapters(item.get("adapters"), components=components)
        targets = {
            "engine": engine.executable,
            "recipe": recipe.document,
            **{f"component:{component.id}": component.artifact for component in components},
        }
        acquisition_sources = _parse_acquisition_sources(
            item.get("acquisition"), targets=targets
        )
        inventory_evidence = None
        if item.get("inventory_evidence") is not None:
            raw_inventory = require_mapping(
                item.get("inventory_evidence"), label="inventory_evidence"
            )
            reject_unknown_keys(
                raw_inventory,
                {"document", "bundle_id"},
                label="inventory_evidence",
            )
            inventory_evidence = InventoryEvidence(
                document=_parse_pin(
                    raw_inventory.get("document"),
                    label="inventory_evidence.document",
                    root_ids=root_ids,
                    maximum=MAX_EVIDENCE_BYTES,
                ),
                bundle_id=_identifier(
                    raw_inventory.get("bundle_id"),
                    label="inventory_evidence.bundle_id",
                ),
            )
        total_expected = sum(
            pin.size_bytes
            for pin in (
                engine.executable,
                recipe.document,
                *(component.artifact for component in components),
            )
        )
        if total_expected > MAX_TOTAL_ARTIFACT_BYTES:
            raise CandidateValidationError(
                f"total declared artifact bytes exceed {MAX_TOTAL_ARTIFACT_BYTES}"
            )
        return CandidateDeclaration(
            path=Path(os.path.abspath(declaration_path)),
            declaration_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            id=_identifier(item.get("id"), label="id"),
            roots=roots,
            engine=engine,
            recipe=recipe,
            components=components,
            adapters=adapters,
            acquisition_sources=acquisition_sources,
            inventory_evidence=inventory_evidence,
        )
    except InventoryValidationError as error:
        raise _candidate_error(error) from error
def parse_trusted_evidence(path: Path) -> tuple[TrustedEvidence, ...]:
    """Load host-owned evidence expectations from a separate strict file."""
    authority_path = _expand_user_path(path, label="trusted evidence")
    raw_bytes = _read_bounded_file(
        authority_path,
        maximum=MAX_TRUSTED_EVIDENCE_BYTES,
        label="trusted evidence",
    )
    try:
        value = _load_strict_bytes(raw_bytes, label="trusted evidence")
        item = require_mapping(value, label="trusted evidence")
        reject_unknown_keys(
            item,
            {"schema", "schema_version", "records"},
            label="trusted evidence",
        )
        if item.get("schema") != TRUSTED_EVIDENCE_SCHEMA:
            raise CandidateValidationError(
                f"trusted evidence schema must be {TRUSTED_EVIDENCE_SCHEMA!r}"
            )
        _schema_version(
            item.get("schema_version"),
            label="trusted evidence schema_version",
            expected=SCHEMA_VERSION,
        )
        raw_records = require_list(
            item.get("records"), label="trusted evidence.records"
        )
        if not raw_records or len(raw_records) > 4096:
            raise CandidateValidationError(
                "trusted evidence.records must contain between 1 and 4096 entries"
            )
        records: list[TrustedEvidence] = []
        for index, raw in enumerate(raw_records):
            label = f"trusted evidence.records[{index}]"
            entry = require_mapping(raw, label=label)
            reject_unknown_keys(
                entry,
                {
                    "authority_id",
                    "document_size_bytes",
                    "document_sha256",
                    "expected",
                },
                label=label,
            )
            records.append(
                TrustedEvidence(
                    authority_id=_identifier(
                        entry.get("authority_id"),
                        label=f"{label}.authority_id",
                    ),
                    document_size_bytes=_positive_int(
                        entry.get("document_size_bytes"),
                        label=f"{label}.document_size_bytes",
                        maximum=MAX_EVIDENCE_BYTES,
                    ),
                    document_sha256=_sha256(
                        entry.get("document_sha256"),
                        label=f"{label}.document_sha256",
                    ),
                    expected=require_mapping(
                        entry.get("expected"), label=f"{label}.expected"
                    ),
                )
            )
        authority_ids = [record.authority_id for record in records]
        if len(authority_ids) != len(set(authority_ids)):
            raise CandidateValidationError(
                "trusted evidence authority ids must be unique"
            )
        return tuple(records)
    except InventoryValidationError as error:
        raise _candidate_error(error) from error


def parse_acquisition_config(path: Path) -> AcquisitionConfig:
    """Load the separate transport opt-in without retaining or serializing secrets."""
    config_path = _expand_user_path(path, label="acquisition config")
    raw_bytes = _read_bounded_file(
        config_path,
        maximum=MAX_ACQUISITION_CONFIG_BYTES,
        label="acquisition config",
    )
    try:
        value = _load_strict_bytes(raw_bytes, label="acquisition config")
        item = require_mapping(value, label="acquisition config")
        reject_unknown_keys(
            item,
            {
                "schema",
                "schema_version",
                "authorized",
                "allowed_origins",
                "credentials",
                "timeout_seconds",
                "max_redirects",
                "max_attempts",
                "max_total_bytes",
            },
            label="acquisition config",
        )
        if item.get("schema") != ACQUISITION_CONFIG_SCHEMA:
            raise CandidateValidationError(
                f"acquisition config schema must be {ACQUISITION_CONFIG_SCHEMA!r}"
            )
        _schema_version(
            item.get("schema_version"),
            label="acquisition config schema_version",
            expected=SCHEMA_VERSION,
        )
        if item.get("authorized") is not True:
            raise CandidateValidationError(
                "acquisition config must contain exactly \"authorized\": true"
            )
        raw_origins = require_list(
            item.get("allowed_origins"), label="acquisition config.allowed_origins"
        )
        if not raw_origins or len(raw_origins) > 32:
            raise CandidateValidationError(
                "acquisition config.allowed_origins must contain 1 to 32 origins"
            )
        allowed_origins = frozenset(
            _acquisition_origin(
                _bounded_string(origin, label=f"allowed_origins[{index}]", limit=2048),
                label=f"allowed_origins[{index}]",
            )
            for index, origin in enumerate(raw_origins)
        )
        if len(allowed_origins) != len(raw_origins):
            raise CandidateValidationError(
                "acquisition config.allowed_origins must be unique"
            )
        timeout_raw = item.get("timeout_seconds")
        if isinstance(timeout_raw, bool) or not isinstance(timeout_raw, (int, float)):
            raise CandidateValidationError(
                "acquisition config.timeout_seconds must be a number"
            )
        if isinstance(timeout_raw, int) and not 0.1 <= timeout_raw <= 300:
            raise CandidateValidationError(
                "acquisition config.timeout_seconds must be between 0.1 and 300"
            )
        timeout_seconds = float(timeout_raw)
        if (
            not math.isfinite(timeout_seconds)
            or timeout_seconds < 0.1
            or timeout_seconds > 300
        ):
            raise CandidateValidationError(
                "acquisition config.timeout_seconds must be between 0.1 and 300"
            )
        max_redirects = _positive_int(
            item.get("max_redirects"),
            label="acquisition config.max_redirects",
            maximum=5,
            allow_zero=True,
        )
        max_attempts = _positive_int(
            item.get("max_attempts"),
            label="acquisition config.max_attempts",
            maximum=5,
        )
        max_total_bytes = _positive_int(
            item.get("max_total_bytes"),
            label="acquisition config.max_total_bytes",
            maximum=MAX_REMOTE_TRANSFER_BYTES,
        )
        raw_credentials = require_list(
            item.get("credentials"), label="acquisition config.credentials"
        )
        if len(raw_credentials) > 32:
            raise CandidateValidationError(
                "acquisition config.credentials must contain at most 32 entries"
            )
        credentials: dict[str, dict[str, str]] = {}
        for index, raw in enumerate(raw_credentials):
            label = f"acquisition config.credentials[{index}]"
            entry = require_mapping(raw, label=label)
            reject_unknown_keys(entry, {"origin", "headers"}, label=label)
            origin = _acquisition_origin(
                _bounded_string(entry.get("origin"), label=f"{label}.origin", limit=2048),
                label=f"{label}.origin",
            )
            if origin not in allowed_origins:
                raise CandidateValidationError(
                    f"{label}.origin must also appear in allowed_origins"
                )
            if origin in credentials:
                raise CandidateValidationError(
                    "acquisition credentials must name each origin once"
                )
            raw_headers = require_mapping(entry.get("headers"), label=f"{label}.headers")
            if not raw_headers or len(raw_headers) > 16:
                raise CandidateValidationError(
                    f"{label}.headers must contain 1 to 16 values"
                )
            headers: dict[str, str] = {}
            for raw_name, raw_value in raw_headers.items():
                name = _credential_header_name(
                    raw_name, label=f"{label}.headers name"
                )
                if name.lower() in {item.lower() for item in headers}:
                    raise CandidateValidationError(
                        f"{label}.headers contains duplicate names"
                    )
                value_text = _bounded_string(
                    raw_value, label=f"{label}.headers.{name}", limit=8192
                )
                if "\r" in value_text or "\n" in value_text:
                    raise CandidateValidationError(
                        f"{label}.headers.{name} must not contain line breaks"
                    )
                headers[name] = value_text
            credentials[origin] = headers
        return AcquisitionConfig(
            allowed_origins=allowed_origins,
            credentials=credentials,
            timeout_seconds=timeout_seconds,
            max_redirects=max_redirects,
            max_attempts=max_attempts,
            max_total_bytes=max_total_bytes,
            path=Path(os.path.abspath(config_path)),
        )
    except InventoryValidationError as error:
        raise _candidate_error(error) from error

__all__ = [name for name in globals() if not name.startswith("__")]
