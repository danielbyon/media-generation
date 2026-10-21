"""Relocate the T01 evidence database and regenerate portable snapshots.

The SQLite service stores resolved runtime artifact paths. This utility repairs
those paths for the current checkout, verifies every artifact against its saved
SHA-256 digest, and rewrites the committed JSON snapshots with repository-relative
paths so the evidence remains inspectable after a checkout moves.

The transaction runs under an exclusive lock for the evidence directory:
1. Recover any earlier journal before starting a new relocation.
2. Build the database and refreshed snapshots in a sibling staging directory.
3. Persist a journal with tree identities and manifests before either rename.
4. Move the original tree to a backup, install the staged tree, and verify both.
5. Persist the cleanup phase before removing the backup, then remove the journal.

Recovery validates the recorded phase, identities, and tree contents before it
resumes installation or restores the original. Ambiguous states fail closed.
Directory-entry changes are synced when the platform supports directory fsync.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import sysconfig
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from media_generation.store import SQLiteStore


_SNAPSHOTS = (
    ("request.json", "request", "request_id"),
    ("job.json", "job", "job_id"),
    ("artifact.json", "artifact", "artifact_id"),
    ("provenance.json", "provenance", "job_id"),
    ("reference_request.json", "request", "request_id"),
    ("reference_job.json", "job", "job_id"),
    ("reference_artifact.json", "artifact", "artifact_id"),
    ("reference_provenance.json", "provenance", "job_id"),
)
_RESOLVED_OUTPUT_DIRECTORY_KEY = "_resolved_output_directory"
_RECOVERY_STATE_VERSION = 4
_PREVIOUS_RECOVERY_STATE_VERSION = 3
_UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS = {
    errno.EACCES,
    errno.EBADF,
    errno.EINVAL,
    errno.ENOSYS,
    errno.EPERM,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


# Process locking and directory durability
@contextmanager
def _relocation_lock(evidence_dir: Path) -> Iterator[None]:
    """Hold an OS-managed, process-wide lock for one evidence directory."""
    lock_path = evidence_dir.parent / f".{evidence_dir.name}.relocation.lock"
    try:
        lock_file = lock_path.open("a+b")
    except OSError as error:
        raise OSError(f"cannot open relocation lock for {evidence_dir}: {error}") from error

    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as error:
                if error.errno not in {
                    errno.EACCES,
                    errno.EAGAIN,
                    getattr(errno, "EDEADLK", errno.EACCES),
                }:
                    raise
                raise RuntimeError(
                    f"another relocation is already running for {evidence_dir}"
                ) from error
            acquired = True
        else:
            import fcntl

            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {
                    errno.EACCES,
                    errno.EAGAIN,
                    getattr(errno, "EDEADLK", errno.EACCES),
                }:
                    raise
                raise RuntimeError(
                    f"another relocation is already running for {evidence_dir}"
                ) from error
            acquired = True

        try:
            yield
        finally:
            if acquired:
                if os.name == "nt":
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    finally:
        lock_file.close()


def _fsync_directory(directory: Path) -> bool:
    """Sync a directory entry table, returning false when the OS cannot do so.

    A false result means the platform, filesystem, or process permissions do
    not support opening and syncing this directory. Callers must not infer
    crash-durable namespace changes from that result.
    """
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
    except OSError as error:
        if error.errno in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            return False
        raise

    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
                return False
            raise
        return True
    finally:
        os.close(descriptor)


def _console_script() -> Path:
    """Locate the installed CLI beside the Python interpreter running this tool."""
    suffix = ".exe" if os.name == "nt" else ""
    return Path(sysconfig.get_path("scripts")) / f"media-generation{suffix}"


def _read_snapshot_id(evidence_dir: Path, filename: str, key: str) -> str:
    """Read a stable record identity from the existing portable snapshot."""
    try:
        payload = json.loads((evidence_dir / filename).read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{filename} is not valid JSON: {error.msg}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"{filename} must contain a JSON object")
    identity = payload.get(key)
    if (
        not isinstance(identity, str)
        or not identity.strip()
        or identity != identity.strip()
    ):
        raise ValueError(f"{filename} does not contain a non-empty {key}")
    return identity


def _run_cli(
    entry_point: Path,
    repository_root: Path,
    database_path: Path,
    command: str,
    identity: str,
) -> dict[str, Any]:
    """Retrieve one record through the installed black-box CLI."""
    if command == "provenance":
        arguments = ["provenance", "--db", str(database_path), "--job-id", identity]
    else:
        arguments = [command, "--db", str(database_path), "--id", identity]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    process = subprocess.run(
        [str(entry_point), *arguments],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"installed CLI failed for {command} {identity}: {process.stderr.strip()}"
        )
    response = json.loads(process.stdout)
    if not isinstance(response, dict):
        raise ValueError(f"installed CLI returned a non-object for {command} {identity}")
    return response


def _portable_paths(value: Any, repository_root: Path) -> Any:
    """Replace absolute artifact paths in snapshots with repository-relative paths."""
    if isinstance(value, dict):
        return {
            key: _portable_paths(item, repository_root)
            if key != "path"
            else _portable_path(item, repository_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_portable_paths(item, repository_root) for item in value]
    return value


def _portable_path(value: Any, repository_root: Path) -> Any:
    if not isinstance(value, str):
        return value
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        return path.resolve().relative_to(repository_root).as_posix()
    except ValueError as error:
        raise ValueError(f"artifact path is outside the checkout: {value}") from error


# Journal validation and persistence
def _recovery_state_path(evidence_dir: Path) -> Path:
    """Return the transaction journal path beside, rather than inside, the evidence tree."""
    return evidence_dir.parent / f".{evidence_dir.name}.relocation-state.json"


def _directory_identity(directory: Path) -> tuple[int, int] | None:
    """Return a directory's device and inode, rejecting files and symbolic links."""
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"relocation recovery path is not a directory: {directory}")
    return metadata.st_dev, metadata.st_ino


def _tree_manifest(directory: Path) -> dict[str, Any]:
    """Describe every tree entry without following symbolic links."""
    root_metadata = directory.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"relocation recovery path is not a directory: {directory}")

    entries: list[dict[str, Any]] = []
    pending: list[tuple[Path, str]] = [(directory, "")]
    while pending:
        current, relative_parent = pending.pop()
        with os.scandir(current) as children:
            ordered_children = sorted(children, key=lambda child: child.name)
        for child in ordered_children:
            path = Path(child.path)
            relative_path = (
                f"{relative_parent}/{child.name}" if relative_parent else child.name
            )
            metadata = child.stat(follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    {"path": relative_path, "kind": "directory", "mode": mode}
                )
                pending.append((path, relative_path))
            elif stat.S_ISREG(metadata.st_mode):
                content_hash = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(128 * 1024), b""):
                        content_hash.update(chunk)
                entries.append(
                    {
                        "path": relative_path,
                        "kind": "file",
                        "mode": mode,
                        "size": metadata.st_size,
                        "sha256": content_hash.hexdigest(),
                    }
                )
            elif stat.S_ISLNK(metadata.st_mode):
                entries.append(
                    {
                        "path": relative_path,
                        "kind": "symlink",
                        "target": os.readlink(path),
                    }
                )
            else:
                raise ValueError(
                    f"unsupported entry in relocation recovery tree: {path}"
                )

    return {
        "root_mode": stat.S_IMODE(root_metadata.st_mode),
        "entries": sorted(entries, key=lambda entry: entry["path"]),
    }


def _manifest_digest(manifest: dict[str, Any]) -> str:
    """Return a stable SHA-256 for a normalized directory-tree manifest."""
    serialized = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _tree_digest(directory: Path) -> str:
    """Hash the complete directory tree without following symbolic links."""
    return _manifest_digest(_tree_manifest(directory))


def _read_tree_manifest(value: object, label: str) -> dict[str, Any]:
    """Validate the saved original-tree manifest before using it for cleanup."""
    if not isinstance(value, dict) or set(value) != {"root_mode", "entries"}:
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} manifest")
    root_mode = value["root_mode"]
    entries = value["entries"]
    if type(root_mode) is not int or not 0 <= root_mode <= 0o7777:
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} root mode")
    if not isinstance(entries, list):
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} entries")

    validated_entries: list[dict[str, Any]] = []
    entry_kinds: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"ambiguous relocation recovery state: invalid {label} entry")
        path = entry.get("path")
        kind = entry.get("kind")
        if not isinstance(path, str) or not path:
            raise ValueError(f"ambiguous relocation recovery state: invalid {label} path")
        components = path.split("/")
        if path.startswith("/") or any(part in {"", ".", ".."} for part in components):
            raise ValueError(f"ambiguous relocation recovery state: unsafe {label} path")
        if path in entry_kinds:
            raise ValueError(f"ambiguous relocation recovery state: duplicate {label} path")

        if kind == "directory":
            if set(entry) != {"path", "kind", "mode"}:
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} directory")
            mode = entry["mode"]
            if type(mode) is not int or not 0 <= mode <= 0o7777:
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} mode")
        elif kind == "file":
            if set(entry) != {"path", "kind", "mode", "size", "sha256"}:
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} file")
            mode = entry["mode"]
            size = entry["size"]
            if type(mode) is not int or not 0 <= mode <= 0o7777:
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} mode")
            if type(size) is not int or size < 0:
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} size")
            _read_tree_digest(entry["sha256"], f"{label} file")
        elif kind == "symlink":
            if set(entry) != {"path", "kind", "target"} or not isinstance(
                entry["target"], str
            ):
                raise ValueError(f"ambiguous relocation recovery state: invalid {label} symlink")
        else:
            raise ValueError(f"ambiguous relocation recovery state: invalid {label} kind")
        entry_kinds[path] = kind
        validated_entries.append(dict(entry))

    paths = [entry["path"] for entry in validated_entries]
    if paths != sorted(paths):
        raise ValueError(f"ambiguous relocation recovery state: unsorted {label} entries")
    for path in paths:
        parents = path.split("/")[:-1]
        for index in range(1, len(parents) + 1):
            parent = "/".join(parents[:index])
            if entry_kinds.get(parent) != "directory":
                raise ValueError(
                    f"ambiguous relocation recovery state: invalid {label} hierarchy"
                )
    return {"root_mode": root_mode, "entries": validated_entries}


def _verify_tree_subset(
    directory: Path,
    expected_manifest: dict[str, Any],
    label: str,
) -> None:
    """Accept only entries left by interrupted deletion of an expected tree."""
    try:
        actual_manifest = _tree_manifest(directory)
    except (OSError, ValueError) as error:
        raise ValueError(
            f"ambiguous relocation recovery state: cannot verify {label} tree"
        ) from error
    expected_entries = {
        entry["path"]: entry for entry in expected_manifest["entries"]
    }
    if actual_manifest["root_mode"] != expected_manifest["root_mode"] or any(
        expected_entries.get(entry["path"]) != entry
        for entry in actual_manifest["entries"]
    ):
        raise ValueError(
            f"ambiguous relocation recovery state: {label} tree is not a cleanup subset"
        )


def _identity_record(identity: tuple[int, int]) -> dict[str, int]:
    """Convert a directory identity into the JSON form stored in the journal."""
    return {"device": identity[0], "inode": identity[1]}


def _read_identity_record(value: object, label: str) -> tuple[int, int]:
    """Validate a saved device/inode pair before using recovery paths."""
    if not isinstance(value, dict):
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} identity")
    device = value.get("device")
    inode = value.get("inode")
    if (
        type(device) is not int
        or type(inode) is not int
        or device < 0
        or inode <= 0
    ):
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} identity")
    return device, inode


def _read_tree_digest(value: object, label: str) -> str:
    """Validate a saved SHA-256 digest before comparing a recovery tree."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"ambiguous relocation recovery state: invalid {label} digest")
    return value


def _verify_tree_digest(directory: Path, expected_digest: str, label: str) -> None:
    """Reject a journal-owned directory whose contents no longer match its record."""
    try:
        actual_digest = _tree_digest(directory)
    except (OSError, ValueError) as error:
        raise ValueError(
            f"ambiguous relocation recovery state: cannot verify {label} tree"
        ) from error
    if actual_digest != expected_digest:
        raise ValueError(
            f"ambiguous relocation recovery state: {label} tree content changed"
        )


def _read_recovery_state(evidence_dir: Path, state_path: Path) -> dict[str, Any]:
    """Load and validate the journal before inspecting or changing any tree."""
    try:
        metadata = state_path.lstat()
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"ambiguous relocation recovery state: not a regular file: {state_path}")
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"ambiguous relocation recovery state: cannot read {state_path}") from error
    version = payload.get("version") if isinstance(payload, dict) else None
    if version not in {
        _RECOVERY_STATE_VERSION,
        _PREVIOUS_RECOVERY_STATE_VERSION,
    }:
        raise ValueError(f"ambiguous relocation recovery state: unsupported format: {state_path}")

    if payload.get("evidence_name") != evidence_dir.name:
        raise ValueError(f"ambiguous relocation recovery state: unexpected evidence name: {state_path}")
    allowed_phases = {"prepared", "cleanup_pending"}
    if version == _RECOVERY_STATE_VERSION:
        allowed_phases.add("staging_cleanup_pending")
    if payload.get("phase") not in allowed_phases:
        raise ValueError(f"ambiguous relocation recovery state: invalid phase: {state_path}")
    for field, prefix in (
        ("staging_name", f".{evidence_dir.name}.relocating-"),
        ("backup_name", f".{evidence_dir.name}.previous-"),
    ):
        name = payload.get(field)
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.startswith(prefix)
        ):
            raise ValueError(f"ambiguous relocation recovery state: invalid {field}: {state_path}")

    _read_identity_record(payload.get("original_identity"), "original")
    _read_identity_record(payload.get("staging_identity"), "staging")
    _read_tree_digest(payload.get("original_tree_sha256"), "original tree")
    _read_tree_digest(payload.get("staging_tree_sha256"), "staging tree")
    original_manifest = _read_tree_manifest(
        payload.get("original_tree_manifest"), "original tree"
    )
    if _manifest_digest(original_manifest) != payload["original_tree_sha256"]:
        raise ValueError(
            f"ambiguous relocation recovery state: original tree manifest digest mismatch: {state_path}"
        )
    if version == _RECOVERY_STATE_VERSION:
        staging_manifest = _read_tree_manifest(
            payload.get("staging_tree_manifest"), "staging tree"
        )
        if _manifest_digest(staging_manifest) != payload["staging_tree_sha256"]:
            raise ValueError(
                f"ambiguous relocation recovery state: staging tree manifest digest mismatch: {state_path}"
            )
    return payload


def _persist_recovery_state(
    state_path: Path,
    payload: dict[str, Any],
    *,
    replace_existing: bool,
) -> None:
    """Write a complete journal atomically, either creating or advancing it."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f"{state_path.stem}-",
        suffix=".tmp",
        dir=state_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if replace_existing:
            os.replace(temporary_path, state_path)
            _fsync_directory(state_path.parent)
        else:
            # Linking is atomic and refuses to overwrite another run's journal.
            os.link(temporary_path, state_path)
            _fsync_directory(state_path.parent)
            temporary_path.unlink()
            _fsync_directory(state_path.parent)
    except BaseException:
        try:
            if temporary_path.exists():
                temporary_path.unlink()
                _fsync_directory(state_path.parent)
        except OSError:
            pass
        raise


def _write_recovery_state(
    evidence_dir: Path,
    staging_dir: Path,
    backup_dir: Path,
    original_identity: tuple[int, int],
    staging_identity: tuple[int, int],
) -> dict[str, Any]:
    """Persist a complete journal atomically before either evidence rename begins."""
    state_path = _recovery_state_path(evidence_dir)
    original_manifest = _tree_manifest(evidence_dir)
    staging_manifest = _tree_manifest(staging_dir)
    payload = {
        "version": _RECOVERY_STATE_VERSION,
        "evidence_name": evidence_dir.name,
        "staging_name": staging_dir.name,
        "backup_name": backup_dir.name,
        "original_identity": _identity_record(original_identity),
        "staging_identity": _identity_record(staging_identity),
        "original_tree_sha256": _manifest_digest(original_manifest),
        "staging_tree_sha256": _manifest_digest(staging_manifest),
        "original_tree_manifest": original_manifest,
        "staging_tree_manifest": staging_manifest,
        "phase": "prepared",
    }
    _persist_recovery_state(state_path, payload, replace_existing=False)
    return payload


def _mark_cleanup_pending(state_path: Path, state: dict[str, Any]) -> None:
    """Persist the installed-tree checkpoint before removing the original backup."""
    if state["phase"] == "cleanup_pending":
        return
    updated_state = {**state, "phase": "cleanup_pending"}
    _persist_recovery_state(state_path, updated_state, replace_existing=True)
    state.update(updated_state)


def _mark_staging_cleanup_pending(
    state_path: Path,
    state: dict[str, Any],
    staging_manifest: dict[str, Any],
) -> None:
    """Persist the intact-original checkpoint before removing an unused stage."""
    if state["phase"] == "staging_cleanup_pending":
        return
    if state["phase"] != "prepared":
        raise ValueError(
            "ambiguous relocation recovery state: cannot discard staging in this phase"
        )
    updated_state = {
        **state,
        "version": _RECOVERY_STATE_VERSION,
        "staging_tree_manifest": staging_manifest,
        "phase": "staging_cleanup_pending",
    }
    _persist_recovery_state(state_path, updated_state, replace_existing=True)
    state.update(updated_state)


def _remove_recovery_state(state_path: Path) -> None:
    """Remove the completed journal and sync its parent when supported."""
    state_path.unlink()
    _fsync_directory(state_path.parent)


def _remove_recovery_temporary_files(evidence_dir: Path) -> None:
    """Remove only incomplete journal writes left before any directory rename."""
    pattern = f".{evidence_dir.name}.relocation-state-*.tmp"
    for temporary_path in evidence_dir.parent.glob(pattern):
        try:
            metadata = temporary_path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(
                f"ambiguous relocation recovery state: invalid temporary file {temporary_path}"
            )
        temporary_path.unlink()
        _fsync_directory(evidence_dir.parent)


# Recovery from an interrupted replacement
def _recover_evidence_replacement(evidence_dir: Path) -> None:
    """Recover an interrupted replacement without discarding an unverified original."""
    state_path = _recovery_state_path(evidence_dir)
    try:
        state_metadata = state_path.lstat()
    except FileNotFoundError:
        _remove_recovery_temporary_files(evidence_dir)
        return
    if not stat.S_ISREG(state_metadata.st_mode):
        raise ValueError(f"ambiguous relocation recovery state: not a regular file: {state_path}")

    state = _read_recovery_state(evidence_dir, state_path)
    staging_dir = evidence_dir.parent / state["staging_name"]
    backup_dir = evidence_dir.parent / state["backup_name"]
    original_identity = _read_identity_record(state["original_identity"], "original")
    staging_identity = _read_identity_record(state["staging_identity"], "staging")

    expected_actual = _directory_identity(evidence_dir)
    staging_actual = _directory_identity(staging_dir)
    backup_actual = _directory_identity(backup_dir)
    if staging_actual is not None and staging_actual != staging_identity:
        raise ValueError("ambiguous relocation recovery state: staging identity changed")
    if backup_actual is not None and backup_actual != original_identity:
        raise ValueError("ambiguous relocation recovery state: backup identity changed")
    if expected_actual is not None and expected_actual not in {
        original_identity,
        staging_identity,
    }:
        raise ValueError("ambiguous relocation recovery state: evidence identity changed")

    original_digest = _read_tree_digest(state["original_tree_sha256"], "original tree")
    staging_digest = _read_tree_digest(state["staging_tree_sha256"], "staging tree")
    original_manifest = _read_tree_manifest(
        state["original_tree_manifest"], "original tree"
    )
    staging_manifest = (
        _read_tree_manifest(state["staging_tree_manifest"], "staging tree")
        if state["version"] == _RECOVERY_STATE_VERSION
        else None
    )
    if expected_actual == original_identity:
        _verify_tree_digest(evidence_dir, original_digest, "original")
    elif expected_actual == staging_identity:
        _verify_tree_digest(evidence_dir, staging_digest, "staged")
    if staging_actual is not None:
        if (
            expected_actual == original_identity
            and state["phase"] == "staging_cleanup_pending"
        ):
            assert staging_manifest is not None
            _verify_tree_subset(staging_dir, staging_manifest, "staged cleanup")
        else:
            _verify_tree_digest(staging_dir, staging_digest, "staged")
    if backup_actual is not None:
        if expected_actual == staging_identity and state["phase"] == "cleanup_pending":
            _verify_tree_subset(backup_dir, original_manifest, "original backup")
        else:
            _verify_tree_digest(backup_dir, original_digest, "original")

    if expected_actual == staging_identity:
        if staging_actual is not None:
            raise ValueError("ambiguous relocation recovery state: staged tree has two paths")
        if backup_actual is not None:
            _mark_cleanup_pending(state_path, state)
            shutil.rmtree(backup_dir)
            _fsync_directory(evidence_dir.parent)
        elif state["phase"] != "cleanup_pending":
            raise ValueError(
                "ambiguous relocation recovery state: original backup is missing before cleanup"
            )
        _remove_recovery_state(state_path)
        return

    if expected_actual == original_identity:
        if state["phase"] not in {"prepared", "staging_cleanup_pending"}:
            raise ValueError("ambiguous relocation recovery state: phase conflicts with original tree")
        if backup_actual is not None:
            raise ValueError("ambiguous relocation recovery state: original exists at two paths")
        if staging_actual is not None:
            if state["phase"] == "prepared":
                if staging_manifest is None:
                    staging_manifest = _tree_manifest(staging_dir)
                _mark_staging_cleanup_pending(
                    state_path,
                    state,
                    staging_manifest,
                )
            shutil.rmtree(staging_dir)
            _fsync_directory(evidence_dir.parent)
        _remove_recovery_state(state_path)
        return

    if expected_actual is None and backup_actual == original_identity:
        if staging_actual == staging_identity:
            os.replace(staging_dir, evidence_dir)
            _fsync_directory(evidence_dir.parent)
            if _directory_identity(evidence_dir) != staging_identity:
                raise RuntimeError("relocation recovery installed an unexpected evidence tree")
            _verify_tree_digest(evidence_dir, staging_digest, "staged")
            _mark_cleanup_pending(state_path, state)
            shutil.rmtree(backup_dir)
            _fsync_directory(evidence_dir.parent)
        elif staging_actual is None:
            os.replace(backup_dir, evidence_dir)
            _fsync_directory(evidence_dir.parent)
            if _directory_identity(evidence_dir) != original_identity:
                raise RuntimeError("relocation recovery restored an unexpected original tree")
        else:
            raise ValueError("ambiguous relocation recovery state: staging tree is unavailable")
        _remove_recovery_state(state_path)
        return

    raise ValueError(
        "ambiguous relocation recovery state: no verified original tree is available"
    )


# Evidence-tree replacement
def _replace_evidence_tree(evidence_dir: Path, staging_dir: Path) -> None:
    """Replace the evidence tree using a journal that remains outside both trees."""
    original_identity = _directory_identity(evidence_dir)
    staging_identity = _directory_identity(staging_dir)
    if original_identity is None or staging_identity is None:
        raise ValueError("evidence and staged trees must both exist before replacement")

    backup_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{evidence_dir.name}.previous-",
            dir=evidence_dir.parent,
        )
    )
    backup_dir.rmdir()
    _fsync_directory(evidence_dir.parent)
    state = _write_recovery_state(
        evidence_dir,
        staging_dir,
        backup_dir,
        original_identity,
        staging_identity,
    )
    os.replace(evidence_dir, backup_dir)
    _fsync_directory(evidence_dir.parent)
    os.replace(staging_dir, evidence_dir)
    _fsync_directory(evidence_dir.parent)
    if _directory_identity(evidence_dir) != staging_identity:
        raise RuntimeError("relocation installed an unexpected evidence tree")
    _verify_tree_digest(evidence_dir, state["staging_tree_sha256"], "staged")
    if _directory_identity(backup_dir) != original_identity:
        raise RuntimeError("relocation moved an unexpected original evidence tree")
    _verify_tree_digest(backup_dir, state["original_tree_sha256"], "original")
    _mark_cleanup_pending(_recovery_state_path(evidence_dir), state)
    shutil.rmtree(backup_dir)
    _fsync_directory(evidence_dir.parent)
    _remove_recovery_state(_recovery_state_path(evidence_dir))


# Staged database and snapshot rebuilding
def _relocate_database(
    database_path: Path,
    artifact_source_dir: Path,
    runtime_artifact_dir: Path,
) -> int:
    """Build a staged database with verified files and final runtime paths."""
    temporary_path = database_path.with_name(f".{database_path.name}.relocating")
    temporary_path.unlink(missing_ok=True)
    SQLiteStore(temporary_path)
    tables = (
        "generation_requests",
        "generation_jobs",
        "generation_attempts",
        "generation_artifacts",
    )
    try:
        with sqlite3.connect(database_path) as source, sqlite3.connect(
            temporary_path
        ) as destination:
            destination.execute("PRAGMA foreign_keys = ON")
            destination.execute("BEGIN IMMEDIATE")
            artifact_count = 0
            for table in tables:
                columns = [
                    str(row[1])
                    for row in source.execute(f"PRAGMA table_info({table})").fetchall()
                ]
                if not columns:
                    raise ValueError(f"evidence database is missing table {table}")
                column_list = ", ".join(columns)
                placeholders = ", ".join("?" for _ in columns)
                rows = source.execute(f"SELECT {column_list} FROM {table}").fetchall()
                if table == "generation_jobs":
                    parameters_index = columns.index("effective_parameters_json")
                    for index, original in enumerate(rows):
                        row = list(original)
                        parameters = json.loads(row[parameters_index])
                        if not isinstance(parameters, dict):
                            raise ValueError(
                                "evidence job effective parameters must contain a JSON object"
                            )
                        parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY] = str(
                            runtime_artifact_dir.resolve()
                        )
                        row[parameters_index] = json.dumps(
                            parameters,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        rows[index] = tuple(row)
                elif table == "generation_artifacts":
                    artifact_id_index = columns.index("artifact_id")
                    path_index = columns.index("path")
                    hash_index = columns.index("sha256")
                    for index, original in enumerate(rows):
                        row = list(original)
                        artifact_id = str(row[artifact_id_index])
                        artifact_path = artifact_source_dir / f"{artifact_id}.png"
                        if not artifact_path.is_file():
                            raise FileNotFoundError(
                                f"evidence artifact is missing: {artifact_path}"
                            )
                        actual_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                        if actual_sha256 != row[hash_index]:
                            raise ValueError(
                                f"evidence artifact has an unexpected hash: {artifact_path}"
                            )
                        runtime_path = runtime_artifact_dir / artifact_path.name
                        row[path_index] = str(runtime_path.resolve())
                        rows[index] = tuple(row)
                    artifact_count = len(rows)
                destination.executemany(
                    f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})",
                    rows,
                )
            violations = destination.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise ValueError(f"relocated evidence violates foreign keys: {violations}")
        os.replace(temporary_path, database_path)
        return artifact_count
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def relocate(evidence_dir: Path) -> int:
    """Stage, validate, and atomically replace the relocated evidence tree."""
    evidence_dir = evidence_dir.expanduser().resolve()
    if len(evidence_dir.parents) < 2:
        raise ValueError("evidence directory must be nested as <checkout>/evidence/t01")
    with _relocation_lock(evidence_dir):
        return _relocate_locked(evidence_dir)


def _relocate_locked(evidence_dir: Path) -> int:
    """Run recovery and relocation while holding the directory transaction lock."""
    _recover_evidence_replacement(evidence_dir)
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"evidence directory does not exist: {evidence_dir}")
    repository_root = evidence_dir.parents[1]
    entry_point = _console_script()
    if not entry_point.is_file():
        raise FileNotFoundError(
            f"installed media-generation command not found at {entry_point}; "
            "install with python -m pip install -e '.[test]'"
        )

    identities = [
        (filename, command, identity_key, _read_snapshot_id(evidence_dir, filename, identity_key))
        for filename, command, identity_key in _SNAPSHOTS
    ]
    staging_dir = Path(
        tempfile.mkdtemp(prefix=f".{evidence_dir.name}.relocating-", dir=evidence_dir.parent)
    )
    _fsync_directory(evidence_dir.parent)
    try:
        shutil.copytree(evidence_dir, staging_dir, dirs_exist_ok=True)
        staged_database = staging_dir / "t01.sqlite3"
        artifact_count = _relocate_database(
            staged_database,
            staging_dir / "artifacts",
            evidence_dir / "artifacts",
        )

        for filename, command, identity_key, identity in identities:
            response = _run_cli(
                entry_point,
                repository_root,
                staged_database,
                command,
                identity,
            )
            if response.get(identity_key) != identity:
                raise ValueError(
                    f"installed CLI returned an unexpected identity for {command} {identity}"
                )
            portable_response = _portable_paths(response, repository_root)
            rendered = (
                json.dumps(
                    portable_response,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            (staging_dir / filename).write_text(rendered, encoding="utf-8")

        _replace_evidence_tree(evidence_dir, staging_dir)
    finally:
        if staging_dir.exists() and not os.path.lexists(
            _recovery_state_path(evidence_dir)
        ):
            shutil.rmtree(staging_dir, ignore_errors=True)

    print(
        f"Relocated {artifact_count} artifact paths and refreshed "
        f"{len(_SNAPSHOTS)} snapshots."
    )
    return 0


def main() -> int:
    """Run the T01 evidence relocation command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="T01 evidence directory (defaults to this script's directory)",
    )
    options = parser.parse_args()
    return relocate(options.evidence_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"T01 evidence relocation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
