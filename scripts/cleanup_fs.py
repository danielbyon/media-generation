"""Descriptor-relative candidate discovery, validation, and deletion."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from .cleanup_model import (
    CandidateError,
    CleanupError,
    _EGG_INFO_NAMES,
    _MAX_METADATA_FILE_SIZE,
    _MAX_SCAN_ENTRIES,
    _MAX_TREE_DEPTH,
    _MAX_TREE_ENTRIES,
    _PROTECTED_DIRECTORY_NAMES,
    _PYTEST_CACHE_SIGNATURE,
)

_CAPTURE_PREFIX = ".media-generation-cleanup-"
@dataclass(frozen=True)
class Candidate:
    """A pathname selected by the allowlist but not yet authorized for deletion."""

    path: str
    category: str
    kind: str
    initial_stat: os.stat_result | None
    invalid_reason: str | None = None


@dataclass(frozen=True)
class TreeEntry:
    """Identity and accounting facts captured through a directory descriptor."""

    path: str
    kind: str
    device: int
    inode: int
    mode: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    estimate: int


@dataclass(frozen=True)
class TreeFacts:
    """A complete descriptor-relative snapshot of one candidate tree."""

    entries: Mapping[str, TreeEntry]
    estimate: int


def _same_captured_status(
    expected: os.stat_result,
    current: os.stat_result,
    *,
    include_ctime: bool = True,
) -> bool:
    """Compare identity, content metadata, and link count with optional ctime."""

    fields = (
        expected.st_dev == current.st_dev,
        expected.st_ino == current.st_ino,
        expected.st_mode == current.st_mode,
        expected.st_nlink == current.st_nlink,
        expected.st_size == current.st_size,
        expected.st_mtime_ns == current.st_mtime_ns,
    )
    if include_ctime:
        fields += (expected.st_ctime_ns == current.st_ctime_ns,)
    return all(fields)


def _same_tree_entry(
    current: os.stat_result,
    expected: TreeEntry,
) -> bool:
    """Compare current descriptor metadata with one captured tree entry."""

    return (
        current.st_dev == expected.device
        and current.st_ino == expected.inode
        and current.st_mode == expected.mode
        and current.st_nlink == expected.links
        and current.st_size == expected.size
        and current.st_mtime_ns == expected.mtime_ns
        and current.st_ctime_ns == expected.ctime_ns
    )


@dataclass
class ScanBudget:
    """Bound scanning work so a malformed checkout cannot trigger a crawl."""

    remaining: int = _MAX_SCAN_ENTRIES

    def consume(self, count: int = 1) -> None:
        self.remaining -= count
        if self.remaining < 0:
            raise CleanupError(
                f"cleanup scan exceeded {_MAX_SCAN_ENTRIES} entries; no files were removed"
            )


def _flags_for_directory() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _flags_for_file() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


def _lstat_at(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)


def _open_directory_at(directory_fd: int, name: str) -> tuple[int, os.stat_result]:
    descriptor = os.open(name, _flags_for_directory(), dir_fd=directory_fd)
    status = os.fstat(descriptor)
    if not stat.S_ISDIR(status.st_mode):
        os.close(descriptor)
        raise CandidateError(f"{name!r} is not a directory")
    return descriptor, status


def _open_parent(root_fd: int, relative: Path) -> tuple[int, str]:
    parts = relative.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CandidateError(f"unsafe relative path: {relative!s}")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd, _ = _open_directory_at(current, part)
            os.close(current)
            current = next_fd
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _relative_join(prefix: str, name: str) -> str:
    return f"{prefix}/{name}" if prefix else name


def _scan_candidates(root_fd: int) -> list[Candidate]:
    """Discover candidate-shaped paths without following links or nested repos."""

    candidates: list[Candidate] = []
    budget = ScanBudget()

    def add(path: str, category: str, kind: str, status: os.stat_result | None, reason: str | None = None) -> None:
        candidates.append(Candidate(path, category, kind, status, reason))

    def visit(directory_fd: int, prefix: str, depth: int) -> None:
        if depth > _MAX_TREE_DEPTH:
            add(
                prefix or ".",
                "coordination",
                "directory",
                None,
                f"scan exceeds maximum depth {_MAX_TREE_DEPTH}",
            )
            return
        try:
            entries = sorted(os.scandir(directory_fd), key=lambda entry: entry.name)
        except OSError as error:
            raise CleanupError(f"cannot scan {prefix or '.'}: {error}") from error
        budget.consume(len(entries))
        names = {entry.name for entry in entries}
        if prefix and ".git" in names:
            return
        for entry in entries:
            name = entry.name
            if name.startswith(_CAPTURE_PREFIX):
                continue
            relative = _relative_join(prefix, name)
            try:
                item_status = _lstat_at(directory_fd, name)
            except FileNotFoundError:
                continue
            is_link = stat.S_ISLNK(item_status.st_mode)
            is_directory = stat.S_ISDIR(item_status.st_mode)
            is_regular = stat.S_ISREG(item_status.st_mode)

            if name == ".git":
                continue
            if relative == "src/media_generation.egg-info":
                add(
                    relative,
                    "setuptools-metadata",
                    "directory",
                    None if is_link else item_status,
                    "candidate is a symbolic link" if is_link else None,
                )
                continue
            if relative == ".pytest_cache":
                add(
                    relative,
                    "pytest-cache",
                    "directory",
                    None if is_link else item_status,
                    "candidate is a symbolic link" if is_link else None,
                )
                continue
            if relative == "build":
                add(
                    relative,
                    "setuptools-build",
                    "directory",
                    None if is_link else item_status,
                    "candidate is a symbolic link" if is_link else None,
                )
                continue
            if name == "__pycache__":
                add(
                    relative,
                    "bytecode",
                    "directory",
                    None if is_link else item_status,
                    "candidate is a symbolic link" if is_link else None,
                )
                continue
            if is_regular and (name.endswith(".pyc") or name.endswith(".pyo")):
                add(relative, "bytecode", "file", item_status)
                continue
            if is_link:
                if name.endswith((".pyc", ".pyo")):
                    add(
                        relative,
                        "bytecode",
                        "file",
                        None,
                        "candidate is a symbolic link",
                    )
                continue
            if is_directory:
                if name in _PROTECTED_DIRECTORY_NAMES:
                    continue
                if name == ".pytest_cache" or name.endswith(".egg-info"):
                    continue
                try:
                    child_fd, _ = _open_directory_at(directory_fd, name)
                except (OSError, CandidateError) as error:
                    add(
                        relative,
                        "coordination",
                        "directory",
                        None,
                        f"cannot inspect directory: {error}",
                    )
                    continue
                try:
                    visit(child_fd, relative, depth + 1)
                finally:
                    os.close(child_fd)

    visit(root_fd, "", 0)
    return sorted(candidates, key=lambda candidate: candidate.path)


def _entry_estimate(status: os.stat_result) -> int:
    blocks = getattr(status, "st_blocks", 0)
    return max(0, blocks * 512) if blocks else max(0, status.st_size)


def _read_descriptor(descriptor: int, *, limit: int = _MAX_METADATA_FILE_SIZE) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise CandidateError("metadata file exceeds the safety limit")
    return b"".join(chunks)


def _read_at(directory_fd: int, name: str, *, limit: int = _MAX_METADATA_FILE_SIZE) -> bytes:
    descriptor = os.open(name, _flags_for_file(), dir_fd=directory_fd)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise CandidateError(f"{name!r} is not a regular file")
        return _read_descriptor(descriptor, limit=limit)
    finally:
        os.close(descriptor)


def _read_relative_at(
    directory_fd: int,
    relative: str,
    *,
    limit: int = _MAX_METADATA_FILE_SIZE,
) -> bytes:
    """Read a nested regular file without following any path component."""

    parts = Path(relative).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CandidateError(f"unsafe candidate-relative path: {relative!r}")
    current = os.dup(directory_fd)
    try:
        for part in parts[:-1]:
            next_fd, _ = _open_directory_at(current, part)
            os.close(current)
            current = next_fd
        return _read_at(current, parts[-1], limit=limit)
    finally:
        os.close(current)


def _inspect_tree(
    directory_fd: int,
    *,
    root_device: int,
    tracked: set[str],
    repo_prefix: str,
    allow_symlinks: bool = False,
    prefix: str = "",
    depth: int = 0,
    remaining: list[int] | None = None,
) -> TreeFacts:
    """Capture every candidate entry through no-follow descriptors."""

    if depth > _MAX_TREE_DEPTH:
        raise CandidateError("candidate tree exceeds the maximum depth")
    budget = remaining if remaining is not None else [_MAX_TREE_ENTRIES]
    try:
        entries = sorted(os.scandir(directory_fd), key=lambda entry: entry.name)
    except OSError as error:
        raise CandidateError(f"cannot inspect candidate tree: {error}") from error
    budget[0] -= len(entries)
    if budget[0] < 0:
        raise CandidateError("candidate tree exceeds the entry limit")
    if ".git" in {entry.name for entry in entries}:
        raise CandidateError("candidate contains a nested Git repository")
    names = {entry.name for entry in entries}
    if {"HEAD", "objects", "refs"} <= names:
        # Names only select a possible repository; Git validates its structure.
        previous = os.open(".", _flags_for_directory())
        try:
            os.fchdir(directory_fd)
            result = subprocess.run(
                ["git", "--git-dir=.", "rev-parse", "--is-bare-repository"],
                capture_output=True, text=True,
                env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
            )
        finally:
            os.fchdir(previous)
            os.close(previous)
        if result.returncode == 0 and result.stdout.strip() == "true":
            raise CandidateError("candidate contains a nested Git bare repository")

    facts: dict[str, TreeEntry] = {}
    estimated = 0
    for entry in entries:
        name = entry.name
        relative = _relative_join(prefix, name)
        repo_path = _relative_join(repo_prefix, relative)
        item_status = _lstat_at(directory_fd, name)
        if repo_path in tracked:
            raise CandidateError(f"candidate contains tracked path {repo_path!r}")
        if item_status.st_dev != root_device:
            raise CandidateError("candidate crosses a filesystem boundary")
        estimate = _entry_estimate(item_status)
        if stat.S_ISDIR(item_status.st_mode):
            child_fd, child_status = _open_directory_at(directory_fd, name)
            try:
                if (child_status.st_dev, child_status.st_ino) != (
                    item_status.st_dev,
                    item_status.st_ino,
                ):
                    raise CandidateError("candidate directory changed while being inspected")
                child_facts = _inspect_tree(
                    child_fd,
                    root_device=root_device,
                    tracked=tracked,
                    repo_prefix=repo_prefix,
                    allow_symlinks=allow_symlinks,
                    prefix=relative,
                    depth=depth + 1,
                    remaining=budget,
                )
            finally:
                os.close(child_fd)
            facts.update(child_facts.entries)
            estimated += child_facts.estimate
            kind = "dir"
        elif stat.S_ISREG(item_status.st_mode):
            if item_status.st_nlink != 1:
                raise CandidateError(f"candidate file {relative!r} has multiple hard links")
            kind = "file"
            estimated += estimate
        elif stat.S_ISLNK(item_status.st_mode):
            if not allow_symlinks:
                raise CandidateError(f"candidate contains symbolic link {relative!r}")
            kind = "symlink"
            estimated += estimate
        else:
            raise CandidateError(f"candidate contains unsupported file type {relative!r}")
        facts[relative] = TreeEntry(
            path=relative,
            kind=kind,
            device=item_status.st_dev,
            inode=item_status.st_ino,
            mode=item_status.st_mode,
            links=item_status.st_nlink,
            size=item_status.st_size,
            mtime_ns=item_status.st_mtime_ns,
            ctime_ns=item_status.st_ctime_ns,
            estimate=estimate,
        )
    return TreeFacts(facts, estimated)


def _validate_bytecode_cache(facts: TreeFacts) -> None:
    for entry in facts.entries.values():
        if entry.kind != "file" or not entry.path.endswith((".pyc", ".pyo")):
            raise CandidateError("__pycache__ contains an entry that is not recognized bytecode")


def _validate_pytest_cache(directory_fd: int, facts: TreeFacts) -> None:
    allowed_entries = {
        "CACHEDIR.TAG",
        "README.md",
        ".gitignore",
        "v",
        "v/cache",
        "v/cache/lastfailed",
        "v/cache/nodeids",
    }
    unrecognized = sorted(set(facts.entries) - allowed_entries)
    if unrecognized:
        raise CandidateError(
            f".pytest_cache contains an unrecognized entry: {unrecognized[0]}"
        )
    for required_directory in ("v", "v/cache"):
        entry = facts.entries.get(required_directory)
        if entry is None or entry.kind != "dir":
            raise CandidateError(
                f".pytest_cache requires directory {required_directory!r}"
            )
    direct = {
        entry.path: entry
        for entry in facts.entries.values()
        if "/" not in entry.path
    }
    if "CACHEDIR.TAG" not in direct or direct["CACHEDIR.TAG"].kind != "file":
        raise CandidateError(".pytest_cache has no recognized CACHEDIR.TAG")
    allowed_root = {"CACHEDIR.TAG", "README.md", ".gitignore", "v"}
    if not set(direct).issubset(allowed_root):
        raise CandidateError(".pytest_cache contains unrecognized root entries")
    tag = _read_at(directory_fd, "CACHEDIR.TAG", limit=4096)
    if not tag.startswith(_PYTEST_CACHE_SIGNATURE):
        raise CandidateError(".pytest_cache CACHEDIR.TAG has an unknown signature")
    for entry in facts.entries.values():
        if entry.kind == "dir" and entry.path not in {"v", "v/cache"}:
            raise CandidateError(".pytest_cache contains an unrecognized directory")


def _validate_egg_info(directory_fd: int, facts: TreeFacts) -> None:
    names = {entry.path for entry in facts.entries.values()}
    if any("/" in name for name in names):
        raise CandidateError("setuptools metadata contains unexpected nested entries")
    if not names.issubset(_EGG_INFO_NAMES) or "PKG-INFO" not in names:
        raise CandidateError("setuptools metadata contains unrecognized entries")
    package_info = _read_at(directory_fd, "PKG-INFO")
    if not re.search(rb"(?m)^Name: media-generation\r?$", package_info):
        raise CandidateError("setuptools metadata belongs to a different project")
    if "top_level.txt" in names:
        top_level = _read_at(directory_fd, "top_level.txt", limit=4096)
        if top_level.strip() != b"media_generation":
            raise CandidateError("setuptools metadata declares an unexpected top-level package")
    if "SOURCES.txt" in names:
        sources = _read_at(directory_fd, "SOURCES.txt")
        for raw_line in sources.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            source = Path(os.fsdecode(line))
            if source.is_absolute() or ".." in source.parts:
                raise CandidateError("setuptools SOURCES.txt contains an unsafe path")


def _walk_source_python_files(root_fd: int) -> dict[str, bytes]:
    parent_fd, name = _open_parent(root_fd, Path("src/media_generation"))
    try:
        start_fd, _ = _open_directory_at(parent_fd, name)
    finally:
        os.close(parent_fd)
    files: dict[str, bytes] = {}
    remaining = [_MAX_TREE_ENTRIES]

    def visit(directory_fd: int, prefix: str, depth: int) -> None:
        if depth > _MAX_TREE_DEPTH:
            raise CandidateError(
                f"source exceeds maximum depth {_MAX_TREE_DEPTH}"
            )
        entries = sorted(os.scandir(directory_fd), key=lambda entry: entry.name)
        remaining[0] -= len(entries)
        if remaining[0] < 0:
            raise CandidateError("source package exceeds the inspection limit")
        for entry in entries:
            if entry.name == "__pycache__":
                continue
            item_status = _lstat_at(directory_fd, entry.name)
            relative = _relative_join(prefix, entry.name)
            if stat.S_ISDIR(item_status.st_mode):
                child_fd, _ = _open_directory_at(directory_fd, entry.name)
                try:
                    visit(child_fd, relative, depth + 1)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(item_status.st_mode) and entry.name.endswith(".py"):
                files[relative] = _read_at(directory_fd, entry.name)

    try:
        visit(start_fd, "", 0)
    finally:
        os.close(start_fd)
    return files


def _validate_build(
    root_fd: int,
    directory_fd: int,
    facts: TreeFacts,
) -> None:
    direct = {entry.path: entry for entry in facts.entries.values()}
    if set(path for path in direct if "/" not in path) != {"lib"}:
        raise CandidateError("build/ does not contain exactly the setuptools lib tree")
    if direct["lib"].kind != "dir":
        raise CandidateError("build/lib is not a directory")
    if set(path for path in direct if path.count("/") == 1 and path.startswith("lib/")) != {
        "lib/media_generation"
    }:
        raise CandidateError("build/lib does not contain exactly media_generation")
    if direct["lib/media_generation"].kind != "dir":
        raise CandidateError("build/lib/media_generation is not a directory")

    built: dict[str, bytes] = {}
    for path, entry in direct.items():
        if not path.startswith("lib/media_generation/") or path == "lib/media_generation":
            continue
        suffix = path.removeprefix("lib/media_generation/")
        if entry.kind == "dir":
            if "__pycache__" in Path(suffix).parts and Path(suffix).name != "__pycache__":
                raise CandidateError("build contains unexpected bytecode nesting")
            continue
        if entry.kind != "file":
            raise CandidateError("build contains a non-regular entry")
        if suffix.endswith((".pyc", ".pyo")):
            if "__pycache__" not in Path(suffix).parts:
                raise CandidateError("build contains bytecode outside __pycache__")
            continue
        if not suffix.endswith(".py"):
            raise CandidateError("build contains an unknown file")
        built[suffix] = _read_relative_at(
            directory_fd, path, limit=_MAX_METADATA_FILE_SIZE
        )

    sources = _walk_source_python_files(root_fd)
    if not built or built != sources:
        raise CandidateError("build Python files do not exactly match src/media_generation")


def _capture_active_environment_directories() -> frozenset[tuple[int, int]]:
    """Record active Python environment identities without ancestor-race machinery."""
    identities: set[tuple[int, int]] = set()
    values = [sys.prefix] + [os.environ[k] for k in ("VIRTUAL_ENV", "CONDA_PREFIX") if os.environ.get(k)]
    for value in values:
        try:
            directory = Path(value).resolve(strict=True)
            for ancestor in (directory, *directory.parents):
                status = ancestor.stat()
                identities.add((status.st_dev, status.st_ino))
        except OSError as error:
            raise CleanupError("active Python environment cannot be identified") from error
    return frozenset(identities)


def _validate_virtualenv(
    directory_fd: int,
    facts: TreeFacts,
    active_directories: frozenset[tuple[int, int]],
    venv_path: str,
) -> None:
    direct_names = {
        entry.path for entry in facts.entries.values() if "/" not in entry.path
    }
    if "pyvenv.cfg" not in direct_names:
        raise CandidateError(".venv has no pyvenv.cfg")
    configuration = _read_at(directory_fd, "pyvenv.cfg", limit=65536).decode(
        "utf-8", errors="strict"
    )
    values: dict[str, str] = {}
    for line in configuration.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip().lower()] = value.strip().lower()
    if not values.get("home"):
        raise CandidateError(".venv pyvenv.cfg has no Python home")
    if values.get("include-system-site-packages") != "false":
        raise CandidateError(".venv enables shared system site packages")

    candidate = os.fstat(directory_fd)
    if (candidate.st_dev, candidate.st_ino) in active_directories:
        raise CandidateError(".venv is the active Python environment")


def _validate_candidate(
    root_fd: int,
    root_path: str,
    candidate: Candidate,
    tracked: set[str],
    active_directories: frozenset[tuple[int, int]],
) -> tuple[int, os.stat_result, TreeFacts | None, int]:
    """Authorize one candidate and return its pinned parent and identity."""

    if candidate.invalid_reason:
        raise CandidateError(candidate.invalid_reason)
    if candidate.initial_stat is None:
        raise CandidateError("candidate identity was not captured")
    relative = Path(candidate.path)
    parent_fd, name = _open_parent(root_fd, relative)
    try:
        initial = _lstat_at(parent_fd, name)
        if not _same_captured_status(candidate.initial_stat, initial):
            raise CandidateError("candidate changed before validation")
        root_status = os.fstat(root_fd)
        if initial.st_dev != root_status.st_dev:
            raise CandidateError("candidate crosses a filesystem boundary")
        if candidate.path in tracked:
            raise CandidateError("candidate is tracked in Git")
        if (initial.st_dev, initial.st_ino) in active_directories:
            raise CandidateError("candidate overlaps the active Python environment")

        facts: TreeFacts | None = None
        if candidate.kind == "file":
            if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
                raise CandidateError("bytecode candidate is not a single regular file")
            estimate = _entry_estimate(initial)
        else:
            directory_fd, opened = _open_directory_at(parent_fd, name)
            try:
                if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
                    raise CandidateError("candidate directory identity changed during validation")
                facts = _inspect_tree(
                    directory_fd,
                    root_device=root_status.st_dev,
                    tracked=tracked,
                    repo_prefix=candidate.path,
                    allow_symlinks=candidate.category == "virtual-environment",
                )
                if candidate.category == "bytecode":
                    _validate_bytecode_cache(facts)
                elif candidate.category == "pytest-cache":
                    _validate_pytest_cache(directory_fd, facts)
                elif candidate.category == "setuptools-metadata":
                    _validate_egg_info(directory_fd, facts)
                elif candidate.category == "setuptools-build":
                    _validate_build(root_fd, directory_fd, facts)
                elif candidate.category == "virtual-environment":
                    _validate_virtualenv(
                        directory_fd,
                        facts,
                        active_directories,
                        str(Path(root_path) / candidate.path),
                    )
                else:
                    raise CandidateError("candidate has an unsupported category")
                estimate = facts.estimate
            finally:
                os.close(directory_fd)
        return parent_fd, initial, facts, estimate
    except BaseException:
        os.close(parent_fd)
        raise


def _remove_file_at(parent_fd: int, name: str, expected: os.stat_result) -> None:
    """Remove one validated entry relative to its pinned parent in an idle checkout."""
    current = _lstat_at(parent_fd, name)
    if not _same_captured_status(expected, current):
        raise CandidateError("candidate file changed before removal")
    os.unlink(name, dir_fd=parent_fd)


def _remove_directory_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    facts: TreeFacts,
    *,
    allow_symlinks: bool,
    prefix: str = "",
    removed_children: list[int] | None = None,
) -> None:
    """Remove a prevalidated tree without following directory symlinks.

    The operator must keep the checkout idle. This is not a security boundary
    against a process deliberately changing names during removal.
    """
    progress = removed_children if removed_children is not None else [0]
    directory_fd, current = _open_directory_at(parent_fd, name)
    try:
        if not _same_captured_status(expected, current):
            raise CandidateError("candidate directory changed before removal")
        entries = sorted(os.scandir(directory_fd), key=lambda entry: entry.name)
        for entry in entries:
            relative = _relative_join(prefix, entry.name)
            recorded = facts.entries.get(relative)
            status = _lstat_at(directory_fd, entry.name)
            if recorded is None or not _same_tree_entry(status, recorded):
                raise CandidateError("candidate entry changed before removal")
            if stat.S_ISDIR(status.st_mode):
                _remove_directory_at(directory_fd, entry.name, status, facts,
                                     allow_symlinks=allow_symlinks, prefix=relative,
                                     removed_children=progress)
            else:
                if stat.S_ISLNK(status.st_mode) and not allow_symlinks:
                    raise CandidateError("candidate contains a symbolic link")
                os.unlink(entry.name, dir_fd=directory_fd)
                progress[0] += 1
        os.rmdir(name, dir_fd=parent_fd)
    except (OSError, CandidateError) as error:
        if removed_children is None and progress[0]:
            raise CandidateError(
                f"candidate partially removed: {progress[0]} child entries removed; "
                f"remaining candidate retained at {name!r}: {error}"
            ) from error
        raise
    finally:
        os.close(directory_fd)
