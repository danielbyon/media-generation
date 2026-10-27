"""Prove one Git worktree and coordinate cooperative producers."""

from __future__ import annotations

import fcntl
import os
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .cleanup_fs import (
    _capture_active_environment_directories,
    _flags_for_directory,
)
from .cleanup_model import CleanupError


@dataclass(frozen=True)
class PinnedWorktree:
    """A validated worktree path and the directory descriptor that owns it."""

    path: Path
    root_fd: int
    active_environment_pins: frozenset[tuple[int, int]]


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _assert_path_matches_descriptor(path: Path, descriptor: int) -> None:
    """Fail closed if a mutable path no longer names the pinned directory."""

    pinned = os.fstat(descriptor)
    try:
        current = os.lstat(path)
    except OSError as error:
        raise CleanupError("cleanup root changed while cleanup was starting") from error
    if not stat.S_ISDIR(pinned.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise CleanupError("cleanup root changed while cleanup was starting")
    if not _same_inode(pinned, current):
        raise CleanupError("cleanup root changed while cleanup was starting")


def _assert_symlink_free_path(path: Path) -> None:
    """Reject any symbolic-link component in an invocation path."""

    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            status = os.lstat(current)
        except FileNotFoundError as error:
            raise CleanupError(f"cleanup script path does not exist: {path}") from error
        if stat.S_ISLNK(status.st_mode):
            raise CleanupError(f"cleanup script path contains a symbolic link: {current}")


def _git_environment() -> dict[str, str]:
    """Prevent inherited Git routing variables from changing repository authority."""

    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git_at_directory_fd(root_fd: int, *arguments: str) -> bytes:
    """Run Git from a pinned worktree descriptor instead of a mutable path."""

    previous_directory_fd = os.open(".", _flags_for_directory())
    try:
        os.fchdir(root_fd)
        result = subprocess.run(
            ["git", *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            check=False,
        )
    finally:
        os.fchdir(previous_directory_fd)
        os.close(previous_directory_fd)
    if result.returncode != 0:
        detail = os.fsdecode(result.stderr).strip() or f"git exited {result.returncode}"
        raise CleanupError(f"cannot prove worktree authority: {detail}")
    return result.stdout


def resolve_worktree_pinned(script_path: str | os.PathLike[str]) -> PinnedWorktree:
    """Prove and pin the physical Git worktree that owns a cleanup script.

    The script and root directory descriptors are opened before Git authority
    checks.  All checks compare inode identity with those descriptors so a
    concurrent rename cannot redirect authority to another checkout.
    """

    requested = Path(script_path)
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    requested = Path(os.path.abspath(requested))
    _assert_symlink_free_path(requested)
    physical_script = requested.resolve(strict=True)
    root = physical_script.parent.parent
    allowed_scripts = {
        root / "scripts" / "clean.py",
        root / "scripts" / "with_worktree_lock.py",
    }
    if physical_script not in allowed_scripts:
        raise CleanupError(
            "cleanup support scripts must run from the repository's scripts/ directory"
        )

    active_environment_pins = _capture_active_environment_directories()
    root_fd: int | None = None
    script_fd: int | None = None
    scripts_fd: int | None = None
    rooted_script_fd: int | None = None
    try:
        script_fd = os.open(
            physical_script,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        script_status = os.fstat(script_fd)
        root_fd = os.open(root, _flags_for_directory())
        _assert_path_matches_descriptor(root, root_fd)

        scripts_fd = os.open("scripts", _flags_for_directory(), dir_fd=root_fd)
        rooted_script_fd = os.open(
            physical_script.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=scripts_fd,
        )
        if not _same_inode(script_status, os.fstat(rooted_script_fd)):
            raise CleanupError("cleanup script changed while authority was being proved")

        reported_top = Path(
            os.fsdecode(_git_at_directory_fd(root_fd, "rev-parse", "--show-toplevel").strip())
        )
        if not reported_top.is_absolute():
            raise CleanupError("Git reported a relative worktree root")
        try:
            reported_status = os.lstat(reported_top)
        except OSError as error:
            raise CleanupError("Git reported an unusable worktree root") from error
        if not _same_inode(os.fstat(root_fd), reported_status):
            raise CleanupError("Git top level does not match the cleanup script location")

        inside = os.fsdecode(
            _git_at_directory_fd(root_fd, "rev-parse", "--is-inside-work-tree").strip()
        )
        if inside != "true":
            raise CleanupError("cleanup requires a non-bare Git worktree")
        _assert_path_matches_descriptor(root, root_fd)
    except BaseException:
        if root_fd is not None:
            os.close(root_fd)
        raise
    finally:
        if rooted_script_fd is not None:
            os.close(rooted_script_fd)
        if scripts_fd is not None:
            os.close(scripts_fd)
        if script_fd is not None:
            os.close(script_fd)

    assert root_fd is not None
    return PinnedWorktree(
        path=root,
        root_fd=root_fd,
        active_environment_pins=active_environment_pins,
    )


def resolve_worktree(script_path: str | os.PathLike[str]) -> Path:
    """Return the physical worktree path after proving Git authority."""

    pinned = resolve_worktree_pinned(script_path)
    try:
        return pinned.path
    finally:
        os.close(pinned.root_fd)


def _tracked_paths(root_fd: int) -> set[str]:
    raw = _git_at_directory_fd(root_fd, "ls-files", "-z", "--cached")
    return {os.fsdecode(item) for item in raw.split(b"\0") if item}


@contextmanager
def worktree_lock(
    root: PinnedWorktree | Path | str,
    *,
    blocking: bool,
) -> Iterator[int]:
    """Hold an advisory exclusive lock on the worktree directory itself."""

    # Pinned authority is borrowed; only the path form creates an owned fd.
    owns_descriptor = not isinstance(root, PinnedWorktree)
    if isinstance(root, PinnedWorktree):
        root_path = root.path
        descriptor = root.root_fd
    else:
        root_path = Path(root)
        descriptor = os.open(root_path, _flags_for_directory())
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        _assert_path_matches_descriptor(root_path, descriptor)
        fcntl.flock(descriptor, operation)
        _assert_path_matches_descriptor(root_path, descriptor)
        yield descriptor
    finally:
        if owns_descriptor:
            os.close(descriptor)
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


tracked_paths = _tracked_paths
