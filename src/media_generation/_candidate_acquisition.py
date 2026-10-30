"""Bounded T07 acquisition, durable journal, and non-clobbering publication."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import http.client
import os
import secrets
import stat
import sys
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Mapping
from urllib.error import URLError
from urllib.parse import urljoin, urlsplit

from ._candidate_transport import open_response

from ._candidate_contract import (
    ACQUISITION_JOURNAL_SCHEMA,
    HASH_CHUNK_BYTES,
    MAX_REMOTE_TRANSFER_BYTES,
    MISSING,
    PREPARATION_MANIFEST_SCHEMA,
    READY,
    SCHEMA_VERSION,
    UNVERIFIED,
    _REDIRECT_STATUSES,
    _RETRYABLE_STATUSES,
    _SHA256,
    _STATUS_RANK,
    _bounded_string,
    _credential_header_name,
    _expand_user_path,
    _load_strict_bytes,
    _physical_path,
    AcquisitionConfig,
    AcquisitionSource,
    ArtifactPin,
    CandidateAcquisitionError,
    CandidateDeclaration,
    CandidateOutputError,
    CandidateValidationError,
    DeclaredRoot,
    TrustedEvidence,
    parse_acquisition_config,
    parse_candidate,
    reject_unknown_keys,
    require_list,
    require_mapping,
)
from ._candidate_evaluation import _observe_target, evaluate_candidate
from .inventory.probes import LocalObservationSource
from .inventory.schema import InventoryValidationError, canonical_json


_JOURNAL_LOCK_TIMEOUT_SECONDS = 30.0
_JOURNAL_LOCK_POLL_SECONDS = 0.01
_MAX_JOURNAL_EVENTS = 10_000


@dataclass(slots=True)
class _StagingFile:
    """One unnamed mode-0600 inode, owned exclusively through its descriptor."""

    descriptor: int


@dataclass(slots=True)
class _StagedArtifact:
    """Verified unnamed content and its retained destination directory."""

    parent_fd: int
    verified_fd: int
    final_name: str
    path: Path
    pin: ArtifactPin


@dataclass(slots=True)
class _TransferBudget:
    """Track durable transfer reservations across every source and retry."""

    limit: int
    used: int = 0

    def __post_init__(self) -> None:
        if self.limit < 1 or self.used < 0 or self.used > self.limit:
            raise CandidateAcquisitionError(
                "journal transfer byte usage exceeds the configured total limit"
            )

    def reserve(self, byte_count: int) -> None:
        """Reserve one attempt's maximum bytes before any network write."""
        if byte_count < 0 or self.used + byte_count > self.limit:
            raise CandidateAcquisitionError(
                "transfer exceeds the configured total byte limit"
            )
        self.used += byte_count


@dataclass(slots=True)
class _OutputTarget:
    """One output file whose parent directory is held open for publication."""

    path: Path
    parent_fd: int
    name: str
    protected_paths: tuple[Path, ...]
    replaceable_identity: tuple[int, int, int, int, int] | None = None

    def close(self) -> None:
        if self.parent_fd >= 0:
            descriptor = self.parent_fd
            self.parent_fd = -1
            os.close(descriptor)

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


class _RetryableRemoteError(Exception):
    """A bounded network failure that may be retried without changing identity."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _PublicationSyncError(CandidateAcquisitionError):
    """A published artifact exists, but its durable storage state is unknown."""


@dataclass(slots=True)
class _JournalLock:
    """Lock one acquisition journal transaction across threads and processes."""

    parent_fd: int
    name: str
    descriptor: int = -1

    @classmethod
    def acquire(cls, target: _OutputTarget) -> _JournalLock:
        name = f".{target.name}.lock"
        flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=target.parent_fd,
            )
        except FileExistsError:
            try:
                descriptor = os.open(name, flags, dir_fd=target.parent_fd)
            except OSError as error:
                raise CandidateOutputError(
                    "acquisition journal lock cannot be opened safely"
                ) from error
        except OSError as error:
            raise CandidateOutputError(
                "acquisition journal lock cannot be opened safely"
            ) from error
        try:
            try:
                lock_facts = os.fstat(descriptor)
            except OSError as error:
                raise CandidateOutputError(
                    "acquisition journal lock cannot be inspected safely"
                ) from error
            if not stat.S_ISREG(lock_facts.st_mode):
                raise CandidateOutputError(
                    "acquisition journal lock must be a regular file"
                )
            deadline = time.monotonic() + _JOURNAL_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as error:
                    if time.monotonic() >= deadline:
                        raise CandidateOutputError(
                            "acquisition journal lock timed out"
                        ) from error
                    time.sleep(_JOURNAL_LOCK_POLL_SECONDS)
                except OSError as error:
                    raise CandidateOutputError(
                        "acquisition journal lock cannot be acquired safely"
                    ) from error
        except BaseException:
            os.close(descriptor)
            raise
        return cls(parent_fd=target.parent_fd, name=name, descriptor=descriptor)

    def close(self) -> None:
        if self.descriptor < 0:
            return
        try:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        finally:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass(slots=True)
class _TransferDeadline:
    """One monotonic deadline shared by every phase of an acquisition attempt."""

    expires_at: float

    @classmethod
    def start(cls, timeout_seconds: float) -> _TransferDeadline:
        """Start the deadline immediately before the first network operation."""
        return cls(time.monotonic() + timeout_seconds)

    def remaining(self) -> float:
        """Return time left for the next operation, or raise on expiry."""
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise _RetryableRemoteError("transfer_timeout")
        return remaining


def _url_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise CandidateAcquisitionError("acquisition URL is malformed") from error
    if parsed.scheme != "https" or not parsed.hostname:
        raise CandidateAcquisitionError("acquisition URL is not an HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise CandidateAcquisitionError("acquisition URL contains user information")
    if parsed.query or parsed.fragment:
        raise CandidateAcquisitionError(
            "acquisition URLs must not contain query strings or fragments"
        )
    try:
        port = parsed.port
    except ValueError as error:
        raise CandidateAcquisitionError("acquisition URL contains an invalid port") from error
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port is not None else "")
def _all_declared_pins(declaration: CandidateDeclaration) -> tuple[ArtifactPin, ...]:
    pins: list[ArtifactPin] = [
        declaration.engine.executable,
        declaration.engine.provenance.evidence,
        declaration.engine.license.evidence,
        declaration.recipe.document,
    ]
    for evidence in declaration.recipe.evidence:
        pins.append(evidence.document)
    for component in declaration.components:
        pins.extend(
            (
                component.artifact,
                component.provenance.evidence,
                component.license.evidence,
                component.conversion.evidence,
            )
        )
    if declaration.inventory_evidence is not None:
        pins.append(declaration.inventory_evidence.document)
    return tuple(pins)


def _path_is_within(path: Path, ancestor: Path) -> bool:
    """Return whether normalized physical paths have an ancestor relationship."""

    normalized_path = os.path.normcase(os.path.realpath(path))
    normalized_ancestor = os.path.normcase(os.path.realpath(ancestor))
    try:
        return os.path.commonpath((normalized_path, normalized_ancestor)) == (
            normalized_ancestor
        )
    except ValueError:
        return False


def _stat_identity(facts: os.stat_result) -> tuple[int, int]:
    return facts.st_dev, facts.st_ino


def _stat_snapshot(facts: os.stat_result) -> tuple[int, int, int, int, int]:
    """Bind file durability to identity, size, and nanosecond modification times."""
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
    )


def _path_matches_snapshot(
    path: Path,
    parent_fd: int,
    snapshot: tuple[int, int, int, int, int] | None,
    *,
    root: Path,
    root_may_be_symlink: bool = True,
) -> bool:
    """Revalidate an observed entry and its directory chain at one checkpoint.

    Retain each directory during traversal, inspect the entry, then check the
    chain back to the declared root. A parent opened before replacement can
    otherwise keep reporting displaced bytes. Declared artifact roots may be
    symlinks; output parents may not. This observation does not pin pathnames
    against mutations after the checkpoint.
    """
    parts = path.parent.relative_to(root).parts
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if parts and (
        not nofollow
        or not directory_flag
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise OSError(errno.ENOTSUP, "directory identity chain unavailable")
    with ExitStack() as directories:
        current_fd = os.open(
            root, os.O_RDONLY | directory_flag | (0 if root_may_be_symlink else nofollow),
        )
        directories.callback(os.close, current_fd)
        chain = [(root, current_fd)]
        for part in parts:
            current_fd = os.open(part, os.O_RDONLY | directory_flag | nofollow, dir_fd=current_fd)
            directories.callback(os.close, current_fd)
            chain.append((Path(part), current_fd))
        try:
            entry = os.stat(path.name, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            current_snapshot = None
        else:
            if not stat.S_ISREG(entry.st_mode):
                return False
            current_snapshot = _stat_snapshot(entry)
        if (
            current_snapshot != snapshot
            or _stat_identity(os.fstat(current_fd)) != _stat_identity(os.fstat(parent_fd))
        ):
            return False
        for index in range(len(chain) - 1, -1, -1):
            name, descriptor = chain[index]
            current = (
                os.stat(name, follow_symlinks=root_may_be_symlink)
                if index == 0
                else os.stat(name, dir_fd=chain[index - 1][1], follow_symlinks=False)
            )
            if _stat_identity(current) != _stat_identity(os.fstat(descriptor)):
                return False
    return True


def _destination_identity(
    target: _OutputTarget,
) -> tuple[int, int, int, int, int] | None:
    """Read a destination only while its declared parent still names the owner.

    Re-open the parent pathname and compare it with the retained descriptor
    before reading the entry through the current parent. Revalidate the path
    after inspecting the entry so a replacement immediately after open cannot
    bind journal reconciliation or the manifest guard to a displaced directory.
    """

    try:
        current_parent_fd = os.open(
            target.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise CandidateOutputError(
            "output destination parent changed or is unavailable"
        ) from error
    try:
        try:
            if _stat_identity(os.fstat(current_parent_fd)) != _stat_identity(
                os.fstat(target.parent_fd)
            ):
                raise CandidateOutputError("output destination parent changed")
            try:
                facts = os.stat(
                    target.name,
                    dir_fd=current_parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                facts = None
            if not _path_matches_snapshot(
                target.path,
                target.parent_fd,
                _stat_snapshot(facts) if facts is not None else None,
                root=target.path.parent,
                root_may_be_symlink=False,
            ):
                raise CandidateOutputError("output destination parent or entry changed")
        except OSError as error:
            raise CandidateOutputError("output destination cannot be inspected") from error
    finally:
        primary_error = sys.exception()
        try:
            os.close(current_parent_fd)
        except OSError as error:
            if primary_error is None:
                raise CandidateOutputError(
                    "output destination parent descriptor cleanup failed"
                ) from error
            primary_error.add_note("output destination parent descriptor cleanup failed")
    if facts is None:
        return None
    if stat.S_ISLNK(facts.st_mode):
        raise CandidateOutputError("output destination must not be a symbolic link")
    if not stat.S_ISREG(facts.st_mode):
        raise CandidateOutputError("output destination must be a regular file")
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
    )


def _protected_file_identities(paths: Iterable[Path]) -> set[tuple[int, int]]:
    """Return physical identities for paths and any symlink referents."""
    identities: set[tuple[int, int]] = set()
    for path in paths:
        try:
            facts = path.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(facts.st_mode) or stat.S_ISLNK(facts.st_mode):
            identities.add(_stat_identity(facts))
        if stat.S_ISLNK(facts.st_mode):
            try:
                referent = path.stat()
            except OSError:
                continue
            if stat.S_ISREG(referent.st_mode):
                identities.add(_stat_identity(referent))
    return identities


def _git_worktree_root(
    path: Path,
    *,
    boundary: Path | None = None,
) -> Path | None:
    """Return the nearest Git worktree containing *path*, within *boundary*."""
    physical = Path(os.path.realpath(path))
    physical_boundary = (
        None if boundary is None else Path(os.path.realpath(boundary))
    )
    if physical_boundary is not None:
        try:
            physical.relative_to(physical_boundary)
        except ValueError:
            return None
    for ancestor in (physical, *physical.parents):
        if os.path.lexists(ancestor / ".git"):
            return ancestor
        if ancestor == physical_boundary:
            break
    return None


def _validate_acquisition_roots(declaration: CandidateDeclaration) -> None:
    """Reject acquisition targets that could publish into a Git worktree."""
    source_root_ids = {source.artifact for source in declaration.acquisition_sources}
    targets = declaration.artifact_targets()
    for artifact in sorted(source_root_ids):
        pin = targets.get(artifact)
        if pin is None:
            continue
        root = declaration.root_index[pin.root]
        if _git_worktree_root(root.path) is not None:
            raise CandidateValidationError(
                f"acquisition root {root.id!r} must be outside Git worktrees"
            )
        destination = pin.resolved_path(declaration.root_index)
        if (
            _git_worktree_root(destination.parent, boundary=root.path)
            is not None
        ):
            raise CandidateValidationError(
                f"acquisition destination for {artifact!r} beneath root "
                f"{root.id!r} must be outside Git worktrees"
            )


def _open_output_target(
    path: Path,
    *,
    label: str,
    protected_paths: Iterable[Path] = (),
    allow_existing: bool = False,
) -> _OutputTarget:
    """Pin an output parent and reject physical aliases of protected files."""

    output = Path(
        os.path.abspath(
            _expand_user_path(path, label=label, error_type=CandidateOutputError)
        )
    )
    protected = tuple(Path(item) for item in protected_paths)
    parent = output.parent
    if not os.path.isdir(parent):
        raise CandidateOutputError(f"{label} parent directory does not exist")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(parent, flags)
    except OSError as error:
        raise CandidateOutputError(f"{label} parent cannot be opened safely") from error
    target = _OutputTarget(
        path=output,
        parent_fd=parent_fd,
        name=output.name,
        protected_paths=protected,
    )
    try:
        physical_parent = Path(os.path.realpath(parent))
        resolved_facts = physical_parent.stat()
        opened_facts = os.fstat(parent_fd)
        if _stat_identity(resolved_facts) != _stat_identity(opened_facts):
            raise CandidateOutputError(f"{label} parent changed during validation")
        if _git_worktree_root(physical_parent) is not None:
            raise CandidateOutputError(f"{label} must be outside Git worktrees")
        output_physical = _physical_path(output)
        if any(output_physical == _physical_path(item) for item in protected):
            raise CandidateOutputError(
                f"{label} must not replace a protected declaration file"
            )
        destination_identity = _destination_identity(target)
        if destination_identity is not None:
            if not allow_existing:
                raise CandidateOutputError(f"{label} already exists")
            if destination_identity[:2] in _protected_file_identities(protected):
                raise CandidateOutputError(
                    f"{label} must not replace a protected declaration file"
                )
            target.replaceable_identity = destination_identity
        return target
    except BaseException:
        target.close()
        raise


def _validate_output_path(
    path: Path,
    *,
    label: str,
    declaration: CandidateDeclaration,
    protected_paths: Iterable[Path] = (),
    allow_existing: bool = False,
) -> _OutputTarget:
    all_protected = (
        declaration.path,
        *(
            pin.resolved_path(declaration.root_index)
            for pin in _all_declared_pins(declaration)
        ),
        *protected_paths,
    )
    output = Path(
        os.path.abspath(
            _expand_user_path(path, label=label, error_type=CandidateOutputError)
        )
    )
    output_physical = _physical_path(output)
    if output_physical == _physical_path(declaration.path):
        raise CandidateOutputError(f"{label} must not replace candidate declaration")
    if any(output_physical == _physical_path(item) for item in all_protected):
        raise CandidateOutputError(
            f"{label} must not replace protected declaration file"
        )
    for root in declaration.roots:
        if _path_is_within(output.parent, root.path):
            raise CandidateOutputError(
                f"{label} must be outside declared model roots"
            )
    return _open_output_target(
        output,
        label=label,
        protected_paths=all_protected,
        allow_existing=allow_existing,
    )
def _write_json_atomic(
    target_or_path: _OutputTarget | Path,
    value: object,
    *,
    label: str,
    publication_guard: Callable[[], None] | None = None,
) -> None:
    """Publish JSON, retaining its descriptor through optional final validation.

    A guarded publication is revoked on failure by truncating only the newly
    created inode through its retained descriptor. Replaced names and parents
    never redirect that invalidation to an existing or substituted artifact.
    This is a final observation, not an atomic transaction across two paths;
    host permissions must prevent mutation after validation or process death.
    """

    data = (canonical_json(value) + "\n").encode("utf-8")
    owns_target = isinstance(target_or_path, Path)
    target = (
        _open_output_target(target_or_path, label=label, allow_existing=True)
        if owns_target
        else target_or_path
    )
    temporary_name: str | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = _temporary_file(
            target.parent_fd, f".{target.name}."
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        current_identity = _destination_identity(target)
        if target.replaceable_identity is None:
            if current_identity is not None:
                raise CandidateOutputError(
                    "output destination appeared before publication"
                )
            try:
                os.link(
                    temporary_name,
                    target.name,
                    src_dir_fd=target.parent_fd,
                    dst_dir_fd=target.parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise CandidateOutputError(
                    "output destination appeared before publication"
                ) from error
            os.unlink(temporary_name, dir_fd=target.parent_fd)
            temporary_name = None
        else:
            if current_identity != target.replaceable_identity:
                raise CandidateOutputError(
                    "owned output destination changed before publication"
                )
            os.replace(
                temporary_name,
                target.name,
                src_dir_fd=target.parent_fd,
                dst_dir_fd=target.parent_fd,
            )
            temporary_name = None
        published_identity = _destination_identity(target)
        if published_identity is None:
            raise CandidateOutputError("published output disappeared")
        if published_identity != _stat_snapshot(os.fstat(descriptor)):
            raise CandidateOutputError("published output changed during publication")
        if published_identity[:2] in _protected_file_identities(
            target.protected_paths
        ):
            raise CandidateOutputError(
                "output publication resolves to a protected declaration file"
            )
        target.replaceable_identity = published_identity
        _fsync_directory(target.parent_fd)
        if publication_guard is not None:
            publication_guard()
    except BaseException as error:
        if publication_guard is not None and descriptor is not None:
            try:
                os.ftruncate(descriptor, 0)
                os.fsync(descriptor)
            except OSError:
                error.add_note("published manifest descriptor invalidation failed")
        if isinstance(error, OSError):
            raise CandidateOutputError(f"{label} could not be published") from error
        raise
    finally:
        primary_error = sys.exception()
        cleanup_errors: list[Exception] = []
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=target.parent_fd)
            except OSError:
                pass
        if descriptor is not None:
            try:
                os.close(descriptor)
            except Exception as error:
                cleanup_errors.append(error)
        if owns_target:
            try:
                target.close()
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary_error is None:
                raise cleanup_errors[0]
            for _cleanup_error in cleanup_errors:
                primary_error.add_note("atomic output descriptor cleanup failed")


def _temporary_file(parent_fd: int, prefix: str) -> tuple[int, str]:
    for _ in range(16):
        candidate = f"{prefix}{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            continue
        except OSError as error:
            raise CandidateOutputError("temporary output could not be created") from error
        return descriptor, candidate
    raise CandidateOutputError("temporary output name could not be allocated")


def _fsync_directory(descriptor: int) -> None:
    os.fsync(descriptor)


def _invalidated_manifest(declaration: CandidateDeclaration) -> dict[str, object]:
    """Return a non-ready manifest without observations from an earlier run."""
    roots = declaration.root_index
    return {
        "schema": PREPARATION_MANIFEST_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "candidate_id": declaration.stable_candidate_id(),
        "verification_id": None,
        "declared_id": declaration.id,
        "declaration_sha256": declaration.declaration_sha256,
        "status": UNVERIFIED,
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
        "verification": {"items": [], "observations": {}},
        "evidence": {
            "static_preparation": UNVERIFIED,
            "independent_evidence_authority": UNVERIFIED,
            "apex_execution": UNVERIFIED,
            "apex_execution_reason": "model_loading_and_inference_not_performed",
            "t08_execution": "required",
            "t19_qualification": UNVERIFIED,
        },
    }


def _invalidate_manifest(
    target: _OutputTarget, declaration: CandidateDeclaration
) -> None:
    """Replace an old manifest before journal state or acquisition can change."""
    if _destination_identity(target) is None:
        return
    _write_json_atomic(
        target,
        _invalidated_manifest(declaration),
        label="preparation manifest",
    )


def _journal_initial(declaration: CandidateDeclaration) -> dict[str, object]:
    return {
        "schema": ACQUISITION_JOURNAL_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "declaration_sha256": declaration.declaration_sha256,
        "declared_id": declaration.id,
        "candidate_id": declaration.stable_candidate_id(),
        "status": MISSING,
        "transfer_bytes": 0,
        "events": [],
    }


_JOURNAL_EVENT_CODES = {
    "attempted": frozenset({"transfer_started"}),
    "succeeded": frozenset(
        {"published_and_verified", "recovered_verified_publication"}
    ),
    "failed": frozenset(
        {
            "acquisition_failed",
            "interrupted_attempt",
            "network_error",
            "publication_sync_failed",
            "response_body_failed",
            "transfer_timeout",
        }
    ),
    "skipped": frozenset(
        {
            "acquisition_not_requested",
            "already_present",
            "existing_artifact_not_replaced",
            "transfer_budget_exhausted",
        }
    ),
}


def _validate_journal_events(
    events: list[object], declaration: CandidateDeclaration
) -> int:
    """Validate artifact transitions and return reserved transfer bytes."""
    targets = declaration.artifact_targets()
    source_pins = {
        source.artifact: targets[source.artifact]
        for source in declaration.acquisition_sources
    }
    pending_attempts: dict[str, int] = {}
    # A terminal transfer event resolves its reservation, but only a verified
    # success discharges durability still owed by an earlier publication.
    recovery_attempts: dict[str, int] = {}
    transfer_reserved_bytes = 0
    if len(events) > _MAX_JOURNAL_EVENTS:
        raise CandidateOutputError("acquisition journal contains too many events")
    for index, raw_event in enumerate(events):
        label = f"acquisition journal.events[{index}]"
        event = require_mapping(raw_event, label=label)
        reject_unknown_keys(
            event,
            {
                "sequence",
                "artifact",
                "state",
                "attempt",
                "bytes",
                "reserved_bytes",
                "sha256",
                "code",
                "message",
            },
            label=label,
        )
        if type(event.get("sequence")) is not int or event["sequence"] != index + 1:
            raise CandidateOutputError("acquisition journal event order is invalid")
        state = event.get("state")
        if not isinstance(state, str) or state not in _JOURNAL_EVENT_CODES:
            raise CandidateOutputError("acquisition journal contains an unknown state")
        artifact = event.get("artifact")
        if not isinstance(artifact, str) or artifact not in source_pins:
            raise CandidateOutputError(
                "acquisition journal artifact is not a declared acquisition source"
            )
        pin = source_pins[artifact]
        attempt = event.get("attempt")
        if type(attempt) is not int or attempt < 0 or attempt > 10_000:
            raise CandidateOutputError("acquisition journal attempt is invalid")
        event_bytes = event.get("bytes")
        if event_bytes is not None and (
            type(event_bytes) is not int or event_bytes < 0
        ):
            raise CandidateOutputError("acquisition journal byte count is invalid")
        reserved_bytes = event.get("reserved_bytes")
        if reserved_bytes is not None and (
            type(reserved_bytes) is not int or reserved_bytes < 0
        ):
            raise CandidateOutputError(
                "acquisition journal reserved byte count is invalid"
            )
        event_sha = event.get("sha256")
        if event_sha is not None and (
            not isinstance(event_sha, str) or not _SHA256.fullmatch(event_sha)
        ):
            raise CandidateOutputError("acquisition journal digest is invalid")
        code = event.get("code")
        message = event.get("message")
        retryable_http_code = (
            state == "failed"
            and isinstance(code, str)
            and code.startswith("http_")
            and code[5:].isdigit()
            and len(code) == 8
            and 100 <= int(code[5:]) <= 599
        )
        if (
            not isinstance(code, str)
            or (code not in _JOURNAL_EVENT_CODES[state] and not retryable_http_code)
            or not isinstance(message, str)
            or not message
            or len(message) > 512
        ):
            raise CandidateOutputError("acquisition journal event reason is invalid")

        pending_attempt = pending_attempts.get(artifact)
        recovery_attempt = recovery_attempts.get(artifact)
        if state == "attempted":
            if pending_attempt is not None or attempt < 1:
                raise CandidateOutputError(
                    "acquisition journal attempted event follows an unresolved attempt"
                )
            if (
                reserved_bytes != pin.size_bytes
                or event_bytes is not None
                or event_sha is not None
            ):
                raise CandidateOutputError(
                    "acquisition journal attempted event has invalid reservation or proof"
                )
            pending_attempts[artifact] = attempt
            transfer_reserved_bytes += reserved_bytes
        elif state == "succeeded":
            if pending_attempt is not None:
                expected_attempt = pending_attempt
            elif recovery_attempt is not None:
                expected_attempt = recovery_attempt
            else:
                raise CandidateOutputError(
                    "acquisition journal succeeded event lacks a matching attempted event"
                )
            if attempt != expected_attempt:
                raise CandidateOutputError(
                    "acquisition journal succeeded event attempt does not match"
                )
            if (
                event_bytes != pin.size_bytes
                or event_sha != pin.sha256
                or reserved_bytes is not None
            ):
                raise CandidateOutputError(
                    "acquisition journal succeeded event lacks exact success proof"
                )
            pending_attempts.pop(artifact, None)
            recovery_attempts.pop(artifact, None)
        elif state == "failed":
            if pending_attempt is not None:
                if attempt != pending_attempt:
                    raise CandidateOutputError(
                        "acquisition journal failed event attempt does not match"
                    )
            elif not (
                recovery_attempt is not None
                and code == "publication_sync_failed"
                and attempt == recovery_attempt
            ):
                raise CandidateOutputError(
                    "acquisition journal failed event lacks a matching attempted event"
                )
            if (
                event_bytes is not None
                or reserved_bytes is not None
                or event_sha is not None
            ):
                raise CandidateOutputError(
                    "acquisition journal failed event contains invalid proof"
                )
            pending_attempts.pop(artifact, None)
            if code in {"publication_sync_failed", "interrupted_attempt"}:
                recovery_attempts[artifact] = attempt
        else:
            if pending_attempt is not None or attempt != 0 or reserved_bytes is not None:
                raise CandidateOutputError(
                    "acquisition journal skipped event has an invalid attempt state"
                )
            if (event_bytes is None) != (event_sha is None):
                raise CandidateOutputError(
                    "acquisition journal skipped event has incomplete proof"
                )
            if event_bytes is not None and (
                event_bytes != pin.size_bytes or event_sha != pin.sha256
            ):
                raise CandidateOutputError(
                    "acquisition journal skipped event has nonmatching proof"
                )
    return transfer_reserved_bytes


def _load_journal(
    target_or_path: _OutputTarget | Path,
    *,
    declaration: CandidateDeclaration,
) -> dict[str, object]:
    """Read and validate a journal bound to its retained parent and filename.

    Entry snapshots must match the descriptor before and after reading and
    after field validation. Each snapshot revalidates the declared parent path;
    only that unchanged parent and entry can become replaceable.
    """
    owns_target = isinstance(target_or_path, Path)
    target = (
        _open_output_target(
            target_or_path,
            label="acquisition journal",
            allow_existing=True,
        )
        if owns_target
        else target_or_path
    )
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                target.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=target.parent_fd,
            )
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode):
                raise CandidateOutputError("acquisition journal must be a regular file")
            before_identity = _stat_snapshot(facts)
            if _destination_identity(target) != before_identity:
                raise CandidateOutputError("acquisition journal changed while read")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                raw_bytes = handle.read(16 * 1024 * 1024 + 1)
            if len(raw_bytes) > 16 * 1024 * 1024:
                raise CandidateOutputError("acquisition journal exceeds its byte limit")
            after = os.fstat(descriptor)
            after_identity = _stat_snapshot(after)
            if (
                after_identity != before_identity
                or len(raw_bytes) != after.st_size
                or _destination_identity(target) != before_identity
            ):
                raise CandidateOutputError("acquisition journal changed while read")
            raw = _load_strict_bytes(raw_bytes, label="acquisition journal")
            journal_identity = after_identity
        except (OSError, CandidateValidationError) as error:
            raise CandidateOutputError(
                "acquisition journal is not readable or valid"
            ) from error

        try:
            item = require_mapping(raw, label="acquisition journal")
            reject_unknown_keys(
                item,
                {
                    "schema",
                    "schema_version",
                    "declaration_sha256",
                    "declared_id",
                    "candidate_id",
                    "status",
                    "transfer_bytes",
                    "events",
                },
                label="acquisition journal",
            )
            if item.get("schema") != ACQUISITION_JOURNAL_SCHEMA:
                raise CandidateOutputError("acquisition journal schema is unsupported")
            if (
                type(item.get("schema_version")) is not int
                or item.get("schema_version") != SCHEMA_VERSION
            ):
                raise CandidateOutputError(
                    "acquisition journal schema_version is unsupported"
                )
            if item.get("declaration_sha256") != declaration.declaration_sha256:
                raise CandidateOutputError(
                    "acquisition journal belongs to a different declaration"
                )
            if item.get("declared_id") != declaration.id:
                raise CandidateOutputError(
                    "acquisition journal declared_id does not match the declaration"
                )
            candidate_id = item.get("candidate_id")
            if candidate_id is not None and (
                not isinstance(candidate_id, str)
                or not candidate_id.startswith("sha256:")
                or not _SHA256.fullmatch(candidate_id.removeprefix("sha256:"))
            ):
                raise CandidateOutputError("acquisition journal candidate_id is invalid")
            if candidate_id != declaration.stable_candidate_id():
                raise CandidateOutputError(
                    "acquisition journal candidate_id does not match declared identity"
                )
            status = item.get("status")
            if not isinstance(status, str) or status not in _STATUS_RANK:
                raise CandidateOutputError("acquisition journal status is invalid")
            transfer_bytes = item.get("transfer_bytes")
            if (
                isinstance(transfer_bytes, bool)
                or not isinstance(transfer_bytes, int)
                or transfer_bytes < 0
                or transfer_bytes > MAX_REMOTE_TRANSFER_BYTES
            ):
                raise CandidateOutputError(
                    "acquisition journal transfer_bytes is invalid"
                )
            events = require_list(item.get("events"), label="acquisition journal.events")
            transfer_reserved_bytes = _validate_journal_events(events, declaration)
            if transfer_reserved_bytes != transfer_bytes:
                raise CandidateOutputError(
                    "acquisition journal transfer_bytes does not match attempted reservations"
                )
            if _destination_identity(target) != journal_identity:
                raise CandidateOutputError("acquisition journal changed while validated")
            target.replaceable_identity = journal_identity
            return item
        except (InventoryValidationError, CandidateValidationError) as error:
            raise CandidateOutputError(
                "acquisition journal fields are invalid"
            ) from error
    finally:
        primary_error = sys.exception()
        cleanup_errors: list[Exception] = []
        if descriptor is not None:
            owned_descriptor = descriptor
            descriptor = None
            try:
                os.close(owned_descriptor)
            except Exception as error:
                cleanup_errors.append(error)
        if owns_target:
            try:
                target.close()
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary_error is None:
                raise cleanup_errors[0]
            for _cleanup_error in cleanup_errors:
                primary_error.add_note("acquisition journal cleanup failed")


def _reload_owned_journal(
    target: _OutputTarget, *, declaration: CandidateDeclaration
) -> dict[str, object]:
    """Reconcile the owned journal only while its declared path is unchanged."""
    expected_identity = target.replaceable_identity
    journal = _load_journal(target, declaration=declaration)
    if (
        target.replaceable_identity != expected_identity
        or _destination_identity(target) != expected_identity
    ):
        raise CandidateOutputError(
            "acquisition journal changed during final reconciliation"
        )
    return journal


def _write_journal(target: _OutputTarget, journal: dict[str, object]) -> None:
    _write_json_atomic(target, journal, label="acquisition journal")


def _require_journal_capacity(
    journal: Mapping[str, object], additional_events: int
) -> list[object]:
    """Return the event list only when the requested additions fit its limit."""
    events = journal.get("events")
    if not isinstance(events, list):
        raise CandidateOutputError("acquisition journal events are invalid")
    if len(events) + additional_events > _MAX_JOURNAL_EVENTS:
        raise CandidateOutputError("acquisition journal event capacity is exhausted")
    return events


def _append_journal_event(
    target: _OutputTarget,
    journal: dict[str, object],
    *,
    artifact: str,
    state: str,
    attempt: int,
    bytes_written: int | None = None,
    reserved_bytes: int | None = None,
    sha256: str | None = None,
    code: str,
    message: str,
) -> None:
    events = _require_journal_capacity(journal, 1)
    event: dict[str, object] = {
        "sequence": len(events) + 1,
        "artifact": artifact,
        "state": state,
        "attempt": attempt,
        "code": code,
        "message": message,
    }
    if bytes_written is not None:
        event["bytes"] = bytes_written
    if reserved_bytes is not None:
        event["reserved_bytes"] = reserved_bytes
    if sha256 is not None:
        event["sha256"] = sha256
    events.append(event)
    _write_journal(target, journal)
def _journal_has(
    journal: Mapping[str, object],
    *,
    artifact: str,
    state: str,
) -> bool:
    events = journal.get("events")
    if not isinstance(events, list):
        return False
    return any(
        isinstance(event, dict)
        and event.get("artifact") == artifact
        and event.get("state") == state
        for event in events
    )
def _journal_has_unresolved_attempt(
    journal: Mapping[str, object], *, artifact: str
) -> bool:
    events = journal.get("events")
    if not isinstance(events, list):
        return False
    artifact_events = [
        event
        for event in events
        if isinstance(event, dict) and event.get("artifact") == artifact
    ]
    return bool(artifact_events) and artifact_events[-1].get("state") == "attempted"


def _journal_pending_attempt(
    journal: Mapping[str, object], *, artifact: str
) -> int | None:
    """Retain publication recovery across later failed transfers and skips.

    An interrupted attempt may have published before its terminal event was
    lost. Observing absence and failing a replacement cannot prove otherwise;
    only a synchronized, verified success clears that durability obligation.
    """
    events = journal.get("events")
    if not isinstance(events, list):
        return None
    pending_attempt = None
    recovery_attempt = None
    for event in events:
        if not isinstance(event, dict) or event.get("artifact") != artifact:
            continue
        state = event.get("state")
        if state == "attempted":
            pending_attempt = event.get("attempt")
        elif state == "succeeded":
            pending_attempt = recovery_attempt = None
        elif state == "failed":
            pending_attempt = None
            if event.get("code") in {"publication_sync_failed", "interrupted_attempt"}:
                recovery_attempt = event.get("attempt")
    attempt = pending_attempt if pending_attempt is not None else recovery_attempt
    return attempt if type(attempt) is int else None
def _open_remote(
    url: str,
    *,
    headers: Mapping[str, str],
    timeout_seconds: float,
    deadline: _TransferDeadline | None = None,
) -> Any:
    """Open one supervised HTTPS response under the artifact's shared deadline."""
    expires_at = (
        deadline.expires_at if deadline is not None
        else time.monotonic() + timeout_seconds
    )
    return open_response(url, headers=headers, expires_at=expires_at)
def _response_status(response: object) -> int:
    status_value = getattr(response, "status", None)
    if status_value is None:
        status_value = getattr(response, "code", 200)
    return int(status_value)
def _response_headers(response: object) -> Mapping[str, str]:
    headers = getattr(response, "headers", None)
    if headers is None:
        headers = getattr(response, "msg", {})
    return headers
def _request_headers(config: AcquisitionConfig, origin: str) -> dict[str, str]:
    headers = {
        "Accept": "application/octet-stream",
        "Accept-Encoding": "identity",
        "User-Agent": "media-generation-t07/1",
    }
    headers.update(config.credentials.get(origin, {}))
    return headers
def _safe_acquisition_message(
    error: BaseException,
    config: AcquisitionConfig,
) -> str:
    """Return a bounded error message with every configured secret removed."""
    message = str(error)
    secrets_to_remove = sorted(
        {
            candidate_value
            for headers in config.credentials.values()
            for value in headers.values()
            if value
            for candidate_value in (value, *value.split())
            if candidate_value
        },
        key=len,
        reverse=True,
    )
    for secret_value in secrets_to_remove:
        message = message.replace(secret_value, "[redacted]")
    return message[:512] or "acquisition operation failed"
_AT_FDCWD = -100
_AT_SYMLINK_FOLLOW = 0x400
_AT_EMPTY_PATH = 0x1000
_PUBLICATION_UNSUPPORTED_ERRNOS = frozenset(
    {
        errno.ENOSYS,
        errno.EOPNOTSUPP,
        errno.ENOTSUP,
        errno.EXDEV,
        errno.EINVAL,
    }
)


def _publication_unsupported(reason: str) -> CandidateAcquisitionError:
    """Return one structured unsupported-publication acquisition failure."""
    return CandidateAcquisitionError(
        f"descriptor-bound publication unsupported: {reason}"
    )


def _require_linux_staging() -> int:
    """Reject acquisition where unnamed, descriptor-owned staging is unavailable."""
    if not sys.platform.startswith("linux"):
        raise _publication_unsupported(
            f"platform {sys.platform!r} requires Linux O_TMPFILE for acquisition"
        )
    tmpfile = getattr(os, "O_TMPFILE", 0)
    if not tmpfile or not getattr(os, "O_NOFOLLOW", 0):
        raise _publication_unsupported("Linux O_TMPFILE/no-follow open unavailable")
    return tmpfile


def _open_staging_file(parent_fd: int) -> _StagingFile:
    """Allocate and preflight an unnamed inode on the destination filesystem.

    O_EXCL is deliberately absent: with O_TMPFILE it would prohibit linking the
    verified inode. The only cleanup operation is close, including failures
    before the first fstat. No directory entry can be adopted or unlinked.

    Linking to the already-existing '.' entry must return EEXIST. This probe
    creates no visible file, but cannot establish that a link to an absent name
    is supported or permitted, even if the filesystem policy does not change.
    """
    tmpfile = _require_linux_staging()
    try:
        descriptor = os.open(
            ".", os.O_RDWR | tmpfile | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600, dir_fd=parent_fd,
        )
    except OSError as error:
        raise _publication_unsupported("destination filesystem rejected O_TMPFILE") from error
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_nlink != 0
            or facts.st_dev != os.fstat(parent_fd).st_dev
        ):
            raise _publication_unsupported("O_TMPFILE did not return an unnamed local inode")
        try:
            _descriptor_bound_publish(descriptor, parent_fd, ".")
        except FileExistsError:
            pass
        except OSError as error:
            raise _publication_unsupported(
                "filesystem rejected the atomic publication primitive"
            ) from error
        else:
            raise _publication_unsupported("descriptor publication preflight did not reject '.'")
        return _StagingFile(descriptor=descriptor)
    except BaseException as error:
        try:
            os.close(descriptor)
        except Exception:
            error.add_note("staging descriptor cleanup failed")
        raise


def _preflight_acquisition(declaration: CandidateDeclaration) -> None:
    """Check detectable capabilities before network or output mutation.

    Empty unnamed inodes are closed immediately. No artifact content, probe
    pathname, journal, manifest, or lock file is written during this check.
    Each transfer repeats the check on its retained parent before networking.
    """
    _require_linux_staging()
    targets = declaration.artifact_targets()
    for source in declaration.acquisition_sources:
        pin = targets[source.artifact]
        root = declaration.root_index[pin.root]
        parent = (root.path / Path(pin.path)).parent
        try:
            parent_fd = LocalObservationSource._open_beneath_fd(parent, root.path, directory=True)
        except OSError as error:
            raise CandidateAcquisitionError("acquisition destination parent unavailable or unsafe") from error
        try:
            stage = _open_staging_file(parent_fd)
            os.close(stage.descriptor)
        finally:
            primary_error = sys.exception()
            try:
                os.close(parent_fd)
            except OSError:
                if primary_error is None:
                    raise
                primary_error.add_note("destination parent descriptor cleanup failed")


def _set_response_read_timeout(response: object, timeout_seconds: float) -> None:
    """Apply the remaining transfer time to a live HTTP response socket."""
    stream = getattr(response, "fp", None)
    raw_stream = getattr(stream, "raw", None)
    socket_object = getattr(raw_stream, "_sock", None)
    if socket_object is None:
        socket_object = getattr(stream, "_sock", None)
    set_timeout = getattr(socket_object, "settimeout", None)
    if callable(set_timeout):
        set_timeout(timeout_seconds)


def _download_to_staging(
    *,
    source: AcquisitionSource,
    pin: ArtifactPin,
    root: DeclaredRoot,
    config: AcquisitionConfig,
    executable: bool,
    budget: _TransferBudget,
    deadline: _TransferDeadline,
) -> _StagedArtifact:
    """Resolve a bounded redirect chain and retain one verified file snapshot."""
    parent = (root.path / Path(pin.path)).parent
    try:
        parent_fd = LocalObservationSource._open_beneath_fd(parent, root.path, directory=True)
    except OSError as error:
        raise CandidateAcquisitionError("acquisition destination parent unavailable or unsafe") from error
    staging_fd: int | None = None
    response: Any = None
    try:
        staging_fd = _open_staging_file(parent_fd).descriptor
        written_identity = _stat_identity(os.fstat(staging_fd))
        current_url = source.url
        redirects = 0
        while True:
            origin = _url_origin(current_url)
            if origin not in config.allowed_origins:
                raise CandidateAcquisitionError(
                    "acquisition origin is not explicitly allowed"
                )
            timeout_seconds = deadline.remaining()
            try:
                response = _open_remote(
                    current_url,
                    headers=_request_headers(config, origin),
                    timeout_seconds=timeout_seconds,
                    deadline=deadline,
                )
            except TimeoutError as error:
                raise _RetryableRemoteError("transfer_timeout") from error
            except (URLError, http.client.HTTPException, OSError) as error:
                raise _RetryableRemoteError("network_error") from error
            status_code = _response_status(response)
            if status_code in _REDIRECT_STATUSES:
                location = _response_headers(response).get("Location")
                _close_response(response)
                response = None
                if not location:
                    raise CandidateAcquisitionError("redirect response has no Location")
                redirects += 1
                if redirects > config.max_redirects:
                    raise CandidateAcquisitionError("redirect limit exceeded")
                try:
                    redirected_url = urljoin(current_url, location)
                    redirect_scheme = urlsplit(redirected_url).scheme
                except ValueError as error:
                    raise CandidateAcquisitionError(
                        "redirect target is malformed"
                    ) from error
                current_url = redirected_url
                if redirect_scheme != "https":
                    raise CandidateAcquisitionError("redirect must remain HTTPS")
                continue
            if status_code in _RETRYABLE_STATUSES:
                _close_response(response)
                raise _RetryableRemoteError(f"http_{status_code}")
            if status_code != 200:
                _close_response(response)
                raise CandidateAcquisitionError(f"acquisition returned HTTP {status_code}")
            break
        assert response is not None

        content_length = _response_headers(response).get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError) as error:
                raise CandidateAcquisitionError(
                    "response content length invalid"
                ) from error
            if declared_length != pin.size_bytes:
                raise CandidateAcquisitionError(
                    "response content length differs pinned size"
                )

        hasher = hashlib.sha256()
        total = 0
        # The supervised response enforces expiry while its worker is blocked
        # in network or framing operations. Bounded reads also retain the
        # caller's pinned-size and aggregate transfer checks.
        read_chunk = getattr(response, "read1", response.read)
        with os.fdopen(staging_fd, "w+b", closefd=False) as handle:
            while True:
                read_timeout = deadline.remaining()
                remaining = pin.size_bytes - total
                _set_response_read_timeout(response, read_timeout)
                try:
                    chunk = read_chunk(min(HASH_CHUNK_BYTES, remaining + 1))
                except TimeoutError as error:
                    raise _RetryableRemoteError("transfer_timeout") from error
                except (OSError, http.client.HTTPException) as error:
                    raise _RetryableRemoteError("response_body_failed") from error
                deadline.remaining()
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    raise CandidateAcquisitionError("response body is not bytes")
                total += len(chunk)
                if total > pin.size_bytes:
                    raise CandidateAcquisitionError("response exceeds pinned size")
                if total > config.max_total_bytes:
                    raise CandidateAcquisitionError(
                        "response exceeds configured byte limit"
                    )
                hasher.update(chunk)
                handle.write(chunk)
            handle.flush()
            if executable:
                os.fchmod(staging_fd, 0o700)
        if total != pin.size_bytes:
            raise CandidateAcquisitionError("response size differs from pinned size")
        if hasher.hexdigest() != pin.sha256:
            raise CandidateAcquisitionError(
                "response SHA-256 differs from the pinned digest"
            )
        _verify_staged_descriptor(
            staging_fd,
            pin,
            expected_identity=written_identity,
        )

        os.fsync(staging_fd)
        # Release the response before transferring descriptor ownership. A
        # failing close must not strand an inode in an unreturned result.
        completed_response, response = response, None
        _close_response(completed_response)
        return _StagedArtifact(
            parent_fd=parent_fd,
            verified_fd=staging_fd,
            final_name=Path(pin.path).name,
            path=root.path / Path(pin.path),
            pin=pin,
        )
    except BaseException as error:
        # A failed close must neither mask the primary failure nor skip another
        # descriptor. Never retry close: the descriptor number may be reused.
        for descriptor, label in ((staging_fd, "staging"), (parent_fd, "destination parent")):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except Exception:
                    error.add_note(f"{label} descriptor cleanup failed")
        raise
    finally:
        primary_error = sys.exception()
        try:
            _close_response(response)
        except Exception as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"response cleanup failed: {error!r}")


def _entry_identity(
    parent_fd: int, name: str
) -> tuple[int, int] | None:
    """Return one directory entry's identity without following a link."""

    try:
        facts = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return _stat_identity(facts)


def _verify_staged_descriptor(
    descriptor: int,
    pin: ArtifactPin,
    *,
    expected_identity: tuple[int, int],
) -> None:
    """Verify exact bytes without releasing or renaming the staged descriptor."""
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or _stat_identity(before) != expected_identity
        or before.st_size != pin.size_bytes
    ):
        raise CandidateAcquisitionError("staged file identity invalid")

    os.lseek(descriptor, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            hasher.update(chunk)
    after = os.fstat(descriptor)
    if (
        _stat_identity(after) != expected_identity
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
    ):
        raise CandidateAcquisitionError("staged file changed during verification")
    if hasher.hexdigest() != pin.sha256:
        raise CandidateAcquisitionError(
            "staged file SHA-256 differs from pinned digest"
        )
def _close_response(response: object | None) -> None:
    if response is None:
        return
    close = getattr(response, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass


def _descriptor_bound_publish(source_fd: int, parent_fd: int, final_name: str) -> None:
    """Link the retained inode atomically without replacing any destination.

    AT_EMPTY_PATH may require CAP_DAC_READ_SEARCH. Linux's documented procfs
    descriptor link is the unprivileged alternative; it follows the kernel's
    descriptor reference, never an acquisition staging pathname.
    """
    _require_linux_staging()
    try:
        link_at = ctypes.CDLL(None, use_errno=True).linkat
    except (AttributeError, OSError) as error:
        raise _publication_unsupported("linkat unavailable") from error
    link_at.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    link_at.restype = ctypes.c_int
    destination = os.fsencode(final_name)
    ctypes.set_errno(0)
    result = link_at(source_fd, b"", parent_fd, destination, _AT_EMPTY_PATH)
    error_number = ctypes.get_errno() or errno.EIO
    if result != 0 and error_number in {errno.EPERM, errno.EACCES, errno.ENOENT, errno.EINVAL}:
        ctypes.set_errno(0)
        result = link_at(
            _AT_FDCWD, os.fsencode(f"/proc/self/fd/{source_fd}"),
            parent_fd, destination, _AT_SYMLINK_FOLLOW,
        )
        error_number = ctypes.get_errno() or errno.EIO
    if result != 0:
        raise OSError(error_number, os.strerror(error_number), final_name)


def _sync_published_file(
    parent_fd: int,
    final_name: str,
    pin: ArtifactPin,
    *,
    expected_identity: tuple[int, int],
) -> tuple[int, int, int, int, int]:
    """Bind pinned bytes to durability without masking verification on close."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(
        final_name,
        os.O_RDONLY | nofollow | cloexec | getattr(os, "O_NONBLOCK", 0),
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        identity = _stat_identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or identity != expected_identity
            or before.st_size != pin.size_bytes
        ):
            raise CandidateAcquisitionError(
                "published entry does not identify the verified regular file"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(HASH_CHUNK_BYTES):
                total += len(chunk)
                if total > pin.size_bytes:
                    raise CandidateAcquisitionError(
                        "published entry exceeds the verified size"
                    )
                hasher.update(chunk)
        after = os.fstat(descriptor)
        if (
            _stat_snapshot(after) != _stat_snapshot(before)
            or total != pin.size_bytes
        ):
            raise CandidateAcquisitionError(
                "published entry changed during synchronization"
            )
        if hasher.hexdigest() != pin.sha256:
            raise CandidateAcquisitionError(
                "published entry SHA-256 differs from the pinned digest"
            )
        os.fsync(descriptor)
        synced = os.fstat(descriptor)
        snapshot = _stat_snapshot(synced)
        if snapshot != _stat_snapshot(before):
            raise CandidateAcquisitionError(
                "published entry changed while being synchronized"
            )
        if _entry_identity(parent_fd, final_name) != identity:
            raise CandidateAcquisitionError(
                "published entry changed before synchronization completed"
            )
    finally:
        primary_error = sys.exception()
        try:
            os.close(descriptor)
        except OSError:
            if primary_error is None:
                raise
            primary_error.add_note("published file descriptor cleanup failed")
    _fsync_directory(parent_fd)
    final = os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(final.st_mode) or _stat_snapshot(final) != snapshot:
        raise CandidateAcquisitionError(
            "published entry changed during directory synchronization"
        )
    return snapshot


def _publish_staged(staged: _StagedArtifact) -> tuple[int, int, int, int, int]:
    """Publish the synchronized inode, retaining ownership through verification."""
    published = False
    try:
        expected_identity = _stat_identity(os.fstat(staged.verified_fd))
        _verify_staged_descriptor(staged.verified_fd, staged.pin, expected_identity=expected_identity)
        os.fsync(staged.verified_fd)
        try:
            _descriptor_bound_publish(staged.verified_fd, staged.parent_fd, staged.final_name)
        except FileExistsError as error:
            raise CandidateAcquisitionError("destination exists and was not replaced") from error
        published = True
        try:
            # Match the retained inode, not whatever a competing writer places
            # at the final name after linkat. Failures never remove that name.
            return _sync_published_file(
                staged.parent_fd, staged.final_name, staged.pin,
                expected_identity=expected_identity,
            )
        except (CandidateAcquisitionError, OSError) as error:
            raise _PublicationSyncError("published artifact could not be synchronized") from error
    except CandidateAcquisitionError:
        raise
    except OSError as error:
        if error.errno in _PUBLICATION_UNSUPPORTED_ERRNOS:
            raise _publication_unsupported("filesystem rejected atomic publication primitive") from error
        raise CandidateAcquisitionError("descriptor-bound publication failed") from error
    finally:
        publication_error = sys.exception()
        cleanup_errors: list[Exception] = []
        for attribute in ("verified_fd", "parent_fd"):
            descriptor = getattr(staged, attribute)
            setattr(staged, attribute, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)
        if cleanup_errors:
            if publication_error is None:
                error_type = _PublicationSyncError if published else CandidateAcquisitionError
                raise error_type("publication descriptor cleanup failed") from cleanup_errors[0]
            for cleanup_error in cleanup_errors:
                publication_error.add_note(f"publication cleanup failed: {cleanup_error!r}")


def _sync_published_destination(
    declaration: CandidateDeclaration,
    pin: ArtifactPin,
    *,
    expected_identity: tuple[int, int],
) -> tuple[int, int, int, int, int]:
    """Recover an exact publication; descriptor close errors retain recovery.

    A close error after successful synchronization still prevents a success
    event. If synchronization already failed, retain that failure and attach
    the cleanup error as a note. Never retry a descriptor close.
    """
    root = declaration.root_index[pin.root]
    target = root.path / Path(pin.path)
    try:
        parent_fd = LocalObservationSource._open_beneath_fd(
            target.parent,
            root.path,
            directory=True,
        )
    except OSError as error:
        raise _PublicationSyncError(
            "published artifact parent unavailable for synchronization"
        ) from error
    try:
        return _sync_published_file(
            parent_fd,
            target.name,
            pin,
            expected_identity=expected_identity,
        )
    except (CandidateAcquisitionError, OSError) as error:
        raise _PublicationSyncError(
            "published artifact could not be synchronized"
        ) from error
    finally:
        primary_error = sys.exception()
        try:
            os.close(parent_fd)
        except OSError as error:
            if primary_error is None:
                raise _PublicationSyncError(
                    "published artifact parent descriptor cleanup failed"
                ) from error
            primary_error.add_note("destination parent descriptor cleanup failed")


def _verify_synchronized_destination(
    declaration: CandidateDeclaration,
    artifact: str,
    pin: ArtifactPin,
    snapshot: tuple[int, int, int, int, int],
) -> None:
    """Reject changes between synchronization and the final full-file check.

    Equal bytes in the same inode do not establish durability after another
    write. Recheck size and nanosecond mtime/ctime against the fsynced snapshot
    after hashing, using a parent descriptor opened beneath the declared root.
    After metadata observation, revalidate the entry and directory chain against
    that descriptor and snapshot. This is a checkpoint, not continuous pathname
    pinning after the check returns.
    """
    verified = _observe_target(declaration, artifact, pin)
    if verified.status != READY or verified.physical_identity != snapshot[:2]:
        raise _PublicationSyncError(
            "published artifact failed verification after synchronization"
        )
    root = declaration.root_index[pin.root]
    target = root.path / Path(pin.path)
    try:
        parent_fd = LocalObservationSource._open_beneath_fd(
            target.parent, root.path, directory=True,
        )
        try:
            facts = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(facts.st_mode) or _stat_snapshot(facts) != snapshot:
                raise _PublicationSyncError(
                    "published artifact changed after synchronization"
                )
            if not _path_matches_snapshot(target, parent_fd, snapshot, root=root.path):
                raise _PublicationSyncError(
                    "published artifact path changed after synchronization"
                )
        finally:
            os.close(parent_fd)
    except OSError as error:
        raise _PublicationSyncError(
            "published artifact unavailable after synchronization"
        ) from error


def _journal_has_publication_sync_failure(
    journal: Mapping[str, object],
    *,
    artifact: str,
) -> bool:
    """Return whether the latest artifact event records a failed sync."""
    events = journal.get("events")
    if not isinstance(events, list):
        return False
    artifact_events = [
        event
        for event in events
        if isinstance(event, dict) and event.get("artifact") == artifact
    ]
    return bool(artifact_events) and (
        artifact_events[-1].get("state") == "failed"
        and artifact_events[-1].get("code") == "publication_sync_failed"
    )


def _journal_has_pending_publication_recovery(
    journal: Mapping[str, object],
    *,
    artifact: str,
) -> bool:
    """Return whether publication recovery must precede a ready result."""
    return _journal_pending_attempt(journal, artifact=artifact) is not None


def _acquire_source(
    *,
    declaration: CandidateDeclaration,
    source: AcquisitionSource,
    pin: ArtifactPin,
    config: AcquisitionConfig,
    journal_path: _OutputTarget,
    journal: dict[str, object],
    budget: _TransferBudget,
) -> bool:
    """Acquire or idempotently reconcile one exact missing artifact."""
    initial = _observe_target(declaration, source.artifact, pin)
    pending_attempt = _journal_pending_attempt(journal, artifact=source.artifact)
    pending_recovery = pending_attempt is not None
    unresolved = _journal_has_unresolved_attempt(journal, artifact=source.artifact)
    if pending_recovery and initial.status != MISSING:
        _require_journal_capacity(journal, 1)
        try:
            # An unavailable or corrupt observation cannot establish that a
            # previously published file is durable or end its recovery state.
            if initial.status != READY:
                raise _PublicationSyncError(
                    "pending published artifact could not be verified for synchronization"
                )
            if initial.physical_identity is None:
                raise _PublicationSyncError(
                    "recovered published artifact identity unavailable"
                )
            synchronized_snapshot = _sync_published_destination(
                declaration,
                pin,
                expected_identity=initial.physical_identity,
            )
            _verify_synchronized_destination(
                declaration, source.artifact, pin, synchronized_snapshot,
            )
        except _PublicationSyncError as error:
            safe_message = _safe_acquisition_message(error, config)
            journal["status"] = UNVERIFIED
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="failed",
                attempt=pending_attempt,
                code="publication_sync_failed",
                message=safe_message,
            )
            raise CandidateAcquisitionError(safe_message) from None
        _append_journal_event(
            journal_path,
            journal,
            artifact=source.artifact,
            state="succeeded",
            attempt=pending_attempt,
            bytes_written=pin.size_bytes,
            sha256=pin.sha256,
            code="recovered_verified_publication",
            message="verified destination recovered after an interrupted journal update",
        )
    elif unresolved:
        _append_journal_event(
            journal_path,
            journal,
            artifact=source.artifact,
            state="failed",
            attempt=pending_attempt,
            code="interrupted_attempt",
            message="previous attempt ended before publication or journal completion",
        )
    if initial.status == READY:
        if not _journal_has(journal, artifact=source.artifact, state="succeeded"):
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="skipped",
                attempt=0,
                bytes_written=pin.size_bytes,
                sha256=pin.sha256,
                code="already_present",
                message="verified destination already exists",
            )
        return True
    if initial.status != MISSING:
        _append_journal_event(
            journal_path,
            journal,
            artifact=source.artifact,
            state="skipped",
            attempt=0,
            code="existing_artifact_not_replaced",
            message="existing destination did not verify and was left untouched",
        )
        return False
    deadline = _TransferDeadline.start(config.timeout_seconds)
    for attempt in range(1, config.max_attempts + 1):
        # Both the reservation and its outcome must fit before transfer or
        # publication starts. The journal lock keeps these slots available.
        _require_journal_capacity(journal, 2)
        try:
            budget.reserve(pin.size_bytes)
        except CandidateAcquisitionError as error:
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
            state="skipped",
            attempt=0,
                code="transfer_budget_exhausted",
                message="durable transfer byte budget is exhausted",
            )
            raise CandidateAcquisitionError(
                "durable transfer byte budget is exhausted"
            ) from error
        journal["transfer_bytes"] = budget.used
        _append_journal_event(
            journal_path,
            journal,
            artifact=source.artifact,
            state="attempted",
            attempt=attempt,
            reserved_bytes=pin.size_bytes,
            code="transfer_started",
            message="bounded transfer started",
        )
        try:
            staged = _download_to_staging(
                source=source,
                pin=pin,
                root=declaration.root_index[pin.root],
                config=config,
                executable=source.artifact == "engine",
                budget=budget,
            deadline=deadline,
            )
            synchronized_snapshot = _publish_staged(staged)
            _verify_synchronized_destination(
                declaration, source.artifact, pin, synchronized_snapshot,
            )
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="succeeded",
                attempt=attempt,
                bytes_written=pin.size_bytes,
                sha256=pin.sha256,
                code="published_and_verified",
                message="artifact was staged, published without clobbering, and verified",
            )
            return True
        except _RetryableRemoteError as error:
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="failed",
                attempt=attempt,
                code=error.code,
                message="bounded transfer failed and remains retryable",
            )
            # Persisting any failure can exhaust the shared deadline. Check
            # expiry independently before reserving bytes for another attempt.
            deadline_expired = time.monotonic() >= deadline.expires_at
            if attempt == config.max_attempts or deadline_expired:
                code = "transfer_timeout" if deadline_expired else error.code
                raise CandidateAcquisitionError(
                    f"bounded acquisition failed: {code}"
                ) from error
        except _PublicationSyncError as error:
            safe_message = _safe_acquisition_message(error, config)
            journal["status"] = UNVERIFIED
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="failed",
                attempt=attempt,
                code="publication_sync_failed",
                message=safe_message,
            )
            raise CandidateAcquisitionError(safe_message) from None
        except OSError:
            safe_message = "acquisition staging operation failed"
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="failed",
                attempt=attempt,
                code="acquisition_failed",
                message=safe_message,
            )
            raise CandidateAcquisitionError(safe_message) from None
        except CandidateAcquisitionError as error:
            safe_message = _safe_acquisition_message(error, config)
            _append_journal_event(
                journal_path,
                journal,
                artifact=source.artifact,
                state="failed",
                attempt=attempt,
                code="acquisition_failed",
            message=safe_message,
            )
            raise CandidateAcquisitionError(safe_message) from None
def prepare_candidate(
    declaration_path: Path,
    *,
    manifest_output: Path,
    journal_output: Path | None = None,
    acquire: bool = False,
    acquisition_config: Path | None = None,
    trusted_evidence_path: Path | None = None,
    trusted_evidence: Iterable[TrustedEvidence] = (),
) -> dict[str, object]:
    """Prepare a manifest, preserving every supplied control file identity.

    ``trusted_evidence_path`` identifies the original host-owned evidence file
    when its parsed records are supplied through ``trusted_evidence``. Manifest
    and journal publication reject direct, hard-linked, or symbolic aliases of
    that file. Manifest output also cannot alias the journal lock path or its
    existing file identity.

    Output parents and the journal lock are closed independently. Cleanup
    failures are attached as notes when preparation already raised an error.
    """
    trusted_evidence_records = tuple(trusted_evidence)
    declaration = parse_candidate(declaration_path)
    if acquire:
        _validate_acquisition_roots(declaration)
    if acquisition_config is not None and not acquire:
        raise CandidateValidationError(
            "acquisition config requires acquire=True and an explicit acquisition request"
        )
    config_path = (
        None
        if acquisition_config is None
        else Path(
            os.path.abspath(
                _expand_user_path(
                    acquisition_config,
                    label="acquisition config",
                )
            )
        )
    )
    protected_control_paths: list[Path] = []
    if trusted_evidence_path is not None:
        protected_control_paths.append(
            Path(
                os.path.abspath(
                    _expand_user_path(
                        trusted_evidence_path,
                        label="trusted evidence",
                    )
                )
            )
        )
    if config_path is not None:
        protected_control_paths.append(config_path)
    if config_path is not None:
        config_physical = _physical_path(config_path)
        manifest_requested = Path(
        os.path.abspath(
            _expand_user_path(
                manifest_output,
                label="manifest output",
                error_type=CandidateOutputError,
            )
        )
        )
        journal_requested = Path(
            os.path.abspath(
                    _expand_user_path(
                        journal_output
                        if journal_output is not None
                        else manifest_requested.with_name(
                            f"{manifest_requested.name}.journal.json"
                        ),
                        label="journal output",
                        error_type=CandidateOutputError,
                )
            )
        )
        if _physical_path(manifest_requested) == config_physical:
            raise CandidateOutputError(
                "manifest output must not replace acquisition config"
            )
        if _physical_path(journal_requested) == config_physical:
            raise CandidateOutputError(
                "journal output must not replace acquisition config"
            )
    manifest_target = _validate_output_path(
        manifest_output,
        label="manifest output",
        declaration=declaration,
        protected_paths=protected_control_paths,
        allow_existing=True,
    )
    journal_target: _OutputTarget | None = None
    journal_lock: _JournalLock | None = None
    try:
        journal_target = _validate_output_path(
            journal_output
            or manifest_target.path.with_name(f"{manifest_target.path.name}.journal.json"),
            label="journal output",
            declaration=declaration,
            protected_paths=(
                manifest_target.path,
                *protected_control_paths,
            ),
            allow_existing=True,
        )
        journal_lock_path = journal_target.path.with_name(
            f".{journal_target.name}.lock"
        )
        manifest_identity = _destination_identity(manifest_target)
        if (
            _physical_path(manifest_target.path) == _physical_path(journal_lock_path)
            or (
                manifest_identity is not None
                and manifest_identity[:2]
                in _protected_file_identities((journal_lock_path,))
            )
        ):
            raise CandidateOutputError(
                "manifest output must not replace acquisition journal lock"
            )
        config: AcquisitionConfig | None = None
        if acquire:
            if acquisition_config is None:
                raise CandidateValidationError(
                    "acquire=True requires a separate acquisition config"
                )
            config = parse_acquisition_config(acquisition_config)
            for source in declaration.acquisition_sources:
                origin = _url_origin(source.url)
                if origin not in config.allowed_origins:
                    raise CandidateValidationError(
                        "acquisition source origin is not explicitly allowed"
                    )
        if acquire:
            try:
                _preflight_acquisition(declaration)
            except OSError as error:
                raise CandidateAcquisitionError(
                    "acquisition capability preflight failed"
                ) from error
        journal_lock = _JournalLock.acquire(journal_target)
        _invalidate_manifest(manifest_target, declaration)
        evaluation = evaluate_candidate(
        declaration, trusted_evidence=trusted_evidence_records
        )
        targets = declaration.artifact_targets()
        if acquire:
            assert config is not None
            expected_total = 0
            for source in declaration.acquisition_sources:
                pin = targets[source.artifact]
                if _observe_target(declaration, source.artifact, pin).status == MISSING:
                    expected_total += pin.size_bytes
            if expected_total > config.max_total_bytes:
                raise CandidateValidationError(
                    "declared acquisition bytes exceed the configured total limit"
                )
        journal: dict[str, object]
        if _destination_identity(journal_target) is not None:
            journal = _load_journal(journal_target, declaration=declaration)
        else:
            journal = _journal_initial(declaration)
            _write_journal(journal_target, journal)
        if acquire:
            assert config is not None
            budget = _TransferBudget(
                config.max_total_bytes,
                used=int(journal["transfer_bytes"]),
            )
            journal["status"] = UNVERIFIED
            _write_journal(journal_target, journal)
            for source in declaration.acquisition_sources:
                _acquire_source(
                    declaration=declaration,
                    source=source,
                    pin=targets[source.artifact],
                    config=config,
                    journal_path=journal_target,
                    journal=journal,
                    budget=budget,
                )
            evaluation = evaluate_candidate(
        declaration, trusted_evidence=trusted_evidence_records
            )
        else:
            for source in declaration.acquisition_sources:
                if _journal_has_pending_publication_recovery(
                    journal, artifact=source.artifact
                ):
                    raise CandidateAcquisitionError(
                        "offline preparation requires authorized publication recovery"
                    )
            for source in declaration.acquisition_sources:
                if not any(
                    isinstance(event, dict) and event.get("artifact") == source.artifact
                    for event in journal["events"]  # type: ignore[index]
                ):
                    _append_journal_event(
                    journal_target,
                        journal,
                        artifact=source.artifact,
                        state="skipped",
                        attempt=0,
                        code="acquisition_not_requested",
                        message="offline preparation did not contact a remote source",
                    )
        journal["candidate_id"] = evaluation.candidate_id
        journal["status"] = evaluation.status
        _write_journal(journal_target, journal)
        journal = _reload_owned_journal(journal_target, declaration=declaration)
        evaluation = evaluate_candidate(
        declaration, trusted_evidence=trusted_evidence_records
        )
        if (
            journal.get("candidate_id") != evaluation.candidate_id
            or journal.get("status") != evaluation.status
        ):
            journal["candidate_id"] = evaluation.candidate_id
            journal["status"] = evaluation.status
            _write_journal(journal_target, journal)
            journal = _reload_owned_journal(journal_target, declaration=declaration)
            if (
                journal.get("candidate_id") != evaluation.candidate_id
                or journal.get("status") != evaluation.status
            ):
                raise CandidateOutputError(
                    "acquisition journal changed during final reconciliation"
                )
        manifest = evaluation.manifest()
        journal_identity = journal_target.replaceable_identity

        def require_unchanged_journal() -> None:
            """Bind manifest publication to the reconciled journal parent and entry."""
            if _destination_identity(journal_target) != journal_identity:
                raise CandidateOutputError(
                    "acquisition journal changed during manifest publication"
                )

        require_unchanged_journal()
        _write_json_atomic(
            manifest_target,
            manifest,
            label="preparation manifest",
            publication_guard=require_unchanged_journal,
        )
        report = evaluation.report("prepare")
        publication = {
            "manifest_path": str(manifest_target.path),
            "journal_path": str(journal_target.path),
        }
        report["publication"] = publication
        return report
    finally:
        primary_error = sys.exception()
        cleanup_errors: list[Exception] = []
        for resource in (manifest_target, journal_target, journal_lock):
            if resource is None:
                continue
            try:
                resource.close()
            except Exception as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary_error is None:
                raise cleanup_errors[0]
            for _cleanup_error in cleanup_errors:
                primary_error.add_note("preparation cleanup failed")

__all__ = [name for name in globals() if not name.startswith("__")]
