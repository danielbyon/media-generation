"""Bounded, read-only observations and auditable probe provenance.

The collector talks to an :class:`ObservationSource` instead of touching the
host directly.  The local source performs read-only filesystem reads and fixed
argv subprocesses; the replay source serves recorded synthetic observations for
deterministic tests.  Neither source accepts shell strings or environment
hooks.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.metadata
import json
import os
import platform as platform_module
import selectors
import shutil
import stat as stat_module
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Protocol, Sequence

from .schema import (
    Observation,
    ProbeRecord,
    ProbeStatus,
    REPLAY_SCHEMA_NAME,
    REPLAY_SCHEMA_VERSION,
    InventoryValidationError,
    load_strict_json,
    require_mapping,
    utc_now,
)


DEFAULT_OUTPUT_LIMIT = 32 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0
TRANSCRIPT_EXCERPT_LIMIT = 8 * 1024
MAX_REPLAY_BYTES = 4 * 1024 * 1024
_READER_POLL_INTERVAL_SECONDS = 0.05
_READER_FINALIZE_SECONDS = 0.1
_IS_WINDOWS = os.name == "nt"


def _windows_pipe_available_bytes(descriptor: int) -> int:
    """Return bytes buffered in an anonymous Windows pipe."""
    import ctypes
    import msvcrt

    handle = ctypes.c_void_p(msvcrt.get_osfhandle(descriptor))
    available = ctypes.c_ulong()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    peek_named_pipe = kernel32.PeekNamedPipe
    peek_named_pipe.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_void_p,
    ]
    peek_named_pipe.restype = ctypes.c_int
    succeeded = peek_named_pipe(
        handle,
        None,
        0,
        None,
        ctypes.byref(available),
        None,
    )
    if not succeeded:
        error = ctypes.get_last_error()
        if error in {109, 232}:
            return 0
        raise OSError(error, ctypes.FormatError(error))
    return int(available.value)


def _wait_for_windows_pipe(descriptor: int, timeout_seconds: float) -> bool:
    """Poll whether Windows has bytes without blocking on an open writer."""
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        if _windows_pipe_available_bytes(descriptor) > 0:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, _READER_POLL_INTERVAL_SECONDS))


class _PipeWaiter:
    """Wait for pipe readiness with a file-descriptor-safe host primitive."""

    def __init__(self, descriptor: int) -> None:
        self._descriptor = descriptor
        self._selector: selectors.BaseSelector | None = None
        if not _IS_WINDOWS:
            selector = selectors.DefaultSelector()
            selector.register(descriptor, selectors.EVENT_READ)
            self._selector = selector

    def wait(self, timeout_seconds: float) -> bool:
        if self._selector is not None:
            return bool(self._selector.select(timeout_seconds))
        return _wait_for_windows_pipe(self._descriptor, timeout_seconds)

    def close(self) -> None:
        if self._selector is not None:
            self._selector.close()


class _ContainmentUnavailable(OSError):
    """Raised when descriptor-relative containment is unavailable."""

    def __init__(self) -> None:
        super().__init__(errno.ENOTSUP, "descriptor containment unavailable")


class ObservationSource(Protocol):
    """Minimal read-only operations used by inventory collectors."""

    def read_text(
        self,
        path: Path,
        *,
        limit: int = DEFAULT_OUTPUT_LIMIT,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> Observation:
        """Read up to ``limit`` bytes of UTF-8 text."""

    def read_prefix(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, bytes]:
        """Read a bounded binary prefix for header inspection."""

    def sha256(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, str | None]:
        """Hash a file in bounded chunks without loading it into memory."""

    def stat(self, path: Path) -> Observation:
        """Return lstat facts as a JSON object without following symlinks."""

    def list_dir(
        self, path: Path, *, limit: int, root: Path | None = None
    ) -> Observation:
        """List one directory level without recursion."""

    def python_distribution(self, name: str) -> Observation:
        """Return installed distribution version and location metadata."""

    def which(self, name: str) -> Observation:
        """Resolve one executable name against the operator's search path."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit: int,
    ) -> Observation:
        """Run one fixed argv vector with no shell and bounded output."""

    def platform_facts(self) -> dict[str, object]:
        """Return process/platform facts without probing the host separately."""


def _error_observation(error: OSError) -> Observation:
    """Map a filesystem failure to an explicit, non-invented status."""
    if isinstance(error, FileNotFoundError):
        return Observation(status=ProbeStatus.UNAVAILABLE.value, reason="file_not_found")
    if isinstance(error, PermissionError):
        return Observation(status=ProbeStatus.UNAVAILABLE.value, reason="permission_denied")
    if isinstance(error, _ContainmentUnavailable):
        return Observation(
            status=ProbeStatus.SKIPPED.value,
            reason="descriptor_containment_unavailable",
        )
    if error.errno == errno.ELOOP:
        return Observation(status=ProbeStatus.SKIPPED.value, reason="symlink_not_followed")
    if error.errno in {errno.ENOTDIR, errno.EXDEV, errno.EINVAL}:
        return Observation(
            status=ProbeStatus.SKIPPED.value,
            reason="containment_path_changed",
        )
    return Observation(
        status=ProbeStatus.ERROR.value,
        reason="os_error",
        detail=str(error),
    )


def _kind(mode: int) -> str:
    """Describe one lstat mode without following it."""
    if stat_module.S_ISLNK(mode):
        return "symlink"
    if stat_module.S_ISDIR(mode):
        return "directory"
    if stat_module.S_ISREG(mode):
        return "file"
    if stat_module.S_ISFIFO(mode):
        return "fifo"
    if stat_module.S_ISSOCK(mode):
        return "socket"
    if stat_module.S_ISCHR(mode) or stat_module.S_ISBLK(mode):
        return "device"
    return "other"


def _sysconf_memory() -> int | None:
    """Return physical memory from ``sysconf`` when that interface exists."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return None
    if pages <= 0 or page_size <= 0:
        return None
    return int(pages) * int(page_size)


def _iso_timestamp(seconds: float) -> str:
    """Convert a filesystem timestamp to UTC ISO-8601 text."""
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


class LocalObservationSource:
    """Read-only access to the local host with explicit size and time bounds."""

    @staticmethod
    def _open_beneath_fd(path: Path, root: Path, *, directory: bool = False) -> int:
        """Open a path beneath a trusted root and return a raw descriptor.

        The declared root may be a symlink and is opened normally. Every path
        component below it is opened relative to the previous directory
        descriptor with ``O_NOFOLLOW``, so a directory replaced by a link after
        validation cannot redirect the open. When descriptor-relative opens are
        unavailable, only a direct child of the root is allowed.
        """
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise OSError(errno.EXDEV, "path outside root", str(path)) from error
        parts = relative.parts
        if any(part in {"", ".", ".."} for part in parts):
            raise OSError(errno.EINVAL, "unsafe relative path", str(path))
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if not parts:
            if not directory or directory_flag == 0:
                raise OSError(errno.EINVAL, "unsafe relative path", str(path))
            return os.open(root, os.O_RDONLY | directory_flag)
        nonblock = getattr(os, "O_NONBLOCK", 0)
        descriptor_support = (
            nofollow != 0
            and directory_flag != 0
            and os.open in getattr(os, "supports_dir_fd", set())
        )
        leaf_flags = os.O_RDONLY | nofollow | nonblock
        if directory:
            leaf_flags |= directory_flag
        if not descriptor_support:
            if len(parts) != 1 or nofollow == 0 or (directory and directory_flag == 0):
                raise _ContainmentUnavailable()
            return os.open(path, leaf_flags)
        root_flags = os.O_RDONLY | directory_flag
        root_fd = os.open(root, root_flags)
        current_fd = root_fd
        try:
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    root_flags | nofollow,
                    dir_fd=current_fd,
                )
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = next_fd
            return os.open(parts[-1], leaf_flags, dir_fd=current_fd)
        finally:
            if current_fd != root_fd:
                os.close(current_fd)
            os.close(root_fd)

    @classmethod
    def _open_beneath(cls, path: Path, root: Path):
        """Open a file beneath a trusted root and return a binary handle."""
        descriptor = cls._open_beneath_fd(path, root)
        try:
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def _open_read(
        cls,
        path: Path,
        *,
        follow_final_symlink: bool,
        root: Path | None = None,
    ):
        """Open for reading, optionally refusing links at the OS layer."""
        if root is not None:
            return cls._open_beneath(path, root)
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        if not follow_final_symlink:
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            flags |= nofollow
            if nofollow == 0 and path.is_symlink():
                raise OSError(errno.ELOOP, "final symlink not followed", str(path))
        return os.fdopen(os.open(path, flags), "rb")

    def read_text(
        self,
        path: Path,
        *,
        limit: int = DEFAULT_OUTPUT_LIMIT,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> Observation:
        """Read up to ``limit`` bytes without decoding beyond a replacement policy."""
        try:
            with self._open_read(
                path,
                follow_final_symlink=follow_final_symlink,
                root=root,
            ) as handle:
                raw = handle.read(limit + 1)
        except OSError as error:
            return _error_observation(error)
        truncated = len(raw) > limit
        text = raw[:limit].decode("utf-8", errors="replace")
        return Observation(
            status=ProbeStatus.OK.value,
            text=text,
            truncated=truncated,
        )

    def read_prefix(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, bytes]:
        """Read at most ``limit`` bytes for a recognized file header."""
        try:
            with self._open_read(
                path,
                follow_final_symlink=follow_final_symlink,
                root=root,
            ) as handle:
                raw = handle.read(limit + 1)
        except OSError as error:
            return _error_observation(error), b""
        truncated = len(raw) > limit
        return (
            Observation(status=ProbeStatus.OK.value, truncated=truncated),
            raw[:limit],
        )

    def sha256(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, str | None]:
        """Stream a bounded SHA-256 digest in 1 MiB chunks."""
        handle: BinaryIO | None = None
        stack = ExitStack()
        try:
            if root is not None:
                handle = stack.enter_context(
                    self._open_read(
                        path,
                        follow_final_symlink=follow_final_symlink,
                        root=root,
                    )
                )
                before = os.fstat(handle.fileno())
            else:
                before = path.stat() if follow_final_symlink else path.lstat()
                if not follow_final_symlink and stat_module.S_ISLNK(before.st_mode):
                    return (
                        Observation(
                            status=ProbeStatus.SKIPPED.value,
                            reason="symlink_not_followed",
                        ),
                        None,
                    )
            if not stat_module.S_ISREG(before.st_mode):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="not_regular_file",
                        detail=f"kind {_kind(before.st_mode)}",
                    ),
                    None,
                )
            if before.st_size > limit:
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="hash_limit_exceeded",
                        detail=f"file size {before.st_size} exceeds limit {limit}",
                    ),
                    None,
                )
            if handle is None:
                handle = stack.enter_context(
                    self._open_read(
                        path,
                        follow_final_symlink=follow_final_symlink,
                        root=root,
                    )
                )
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="file_replaced_during_hash",
                        detail="file identity changed before hashing",
                    ),
                    None,
                )
            if not stat_module.S_ISREG(opened.st_mode):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="not_regular_file",
                        detail=f"kind {_kind(opened.st_mode)}",
                    ),
                    None,
                )
            if opened.st_size > limit:
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="hash_limit_exceeded",
                        detail=f"opened file size {opened.st_size} exceeds limit {limit}",
                    ),
                    None,
                )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    return (
                        Observation(
                            status=ProbeStatus.SKIPPED.value,
                            reason="hash_limit_exceeded",
                            detail=f"file grew beyond limit {limit} during hashing",
                        ),
                        None,
                    )
                digest.update(chunk)
            after = os.fstat(handle.fileno())
            if root is not None:
                with self._open_read(
                    path,
                    follow_final_symlink=follow_final_symlink,
                    root=root,
                ) as final_handle:
                    final = os.fstat(final_handle.fileno())
            else:
                final = path.stat() if follow_final_symlink else path.lstat()
            if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="file_replaced_during_hash",
                        detail="file identity changed during hashing",
                    ),
                    None,
                )
            if after.st_size > limit:
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="hash_limit_exceeded",
                        detail=f"file grew beyond limit {limit} during hashing",
                    ),
                    None,
                )
            if after.st_size != total:
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="file_changed_during_hash",
                        detail=f"read {total} bytes but file reports {after.st_size}",
                    ),
                    None,
                )
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="file_changed_during_hash",
                        detail="file metadata changed while hashing",
                    ),
                    None,
                )
            if (
                final.st_size != after.st_size
                or final.st_mtime_ns != after.st_mtime_ns
                or final.st_ctime_ns != after.st_ctime_ns
            ):
                return (
                    Observation(
                        status=ProbeStatus.SKIPPED.value,
                        reason="file_changed_during_hash",
                        detail="file metadata changed after hashing",
                    ),
                    None,
                )
            return Observation(status=ProbeStatus.OK.value), "sha256:" + digest.hexdigest()
        except OSError as error:
            return _error_observation(error), None
        finally:
            stack.close()

    def stat(self, path: Path) -> Observation:
        """Return lstat facts without following symlinks or reading content."""
        try:
            facts = path.lstat()
        except OSError as error:
            return _error_observation(error)
        payload: dict[str, object] = {
            "exists": True,
            "kind": _kind(facts.st_mode),
            "size_bytes": facts.st_size,
            "mtime": _iso_timestamp(facts.st_mtime),
            "symlink": stat_module.S_ISLNK(facts.st_mode),
            "realpath": os.path.realpath(path),
            "executable": False
            if stat_module.S_ISLNK(facts.st_mode)
            else os.access(path, os.X_OK) and stat_module.S_ISREG(facts.st_mode),
        }
        if stat_module.S_ISLNK(facts.st_mode):
            try:
                payload["link_target"] = os.readlink(path)
            except OSError:
                payload["link_target"] = None
        return Observation(status=ProbeStatus.OK.value, text=json.dumps(payload, sort_keys=True))

    def list_dir(
        self, path: Path, *, limit: int, root: Path | None = None
    ) -> Observation:
        """Return at most ``limit`` entries from one directory level."""
        entries: list[dict[str, object]] = []
        truncated = False
        descriptor: int | None = None
        try:
            if root is not None:
                descriptor = self._open_beneath_fd(path, root, directory=True)
                iterator = os.scandir(descriptor)
            else:
                iterator = os.scandir(path)
            with iterator:
                for entry in iterator:
                    if len(entries) >= limit:
                        truncated = True
                        break
                    try:
                        facts = entry.stat(follow_symlinks=False)
                    except OSError:
                        facts = None
                    entries.append(
                        {
                            "name": entry.name,
                            "kind": (
                                "symlink"
                                if entry.is_symlink()
                                else "directory"
                                if entry.is_dir(follow_symlinks=False)
                                else "file"
                                if entry.is_file(follow_symlinks=False)
                                else "other"
                            ),
                            "size_bytes": (
                                facts.st_size if facts is not None else None
                            ),
                            "symlink": entry.is_symlink(),
                        }
                    )
        except OSError as error:
            return _error_observation(error)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        entries.sort(key=lambda item: str(item["name"]))
        return Observation(
            status=ProbeStatus.OK.value,
            text=json.dumps(entries, sort_keys=True),
            truncated=truncated,
        )

    def which(self, name: str) -> Observation:
        """Resolve ``name`` using the current search path only."""
        resolved = shutil.which(name)
        if resolved is None:
            return Observation(status=ProbeStatus.UNAVAILABLE.value, reason="binary_not_found")
        return Observation(status=ProbeStatus.OK.value, text=resolved)

    def python_distribution(self, name: str) -> Observation:
        """Read distribution metadata without importing the package module."""
        try:
            distribution = importlib.metadata.distribution(name)
            version = distribution.version
            location = str(distribution.locate_file(""))
        except importlib.metadata.PackageNotFoundError:
            return Observation(
                status=ProbeStatus.UNAVAILABLE.value,
                reason="distribution_not_found",
            )
        except (OSError, ValueError) as error:
            return Observation(
                status=ProbeStatus.ERROR.value,
                reason="distribution_metadata_error",
                detail=str(error),
            )
        return Observation(
            status=ProbeStatus.OK.value,
            text=json.dumps(
                {"version": version, "location": location}, sort_keys=True
            ),
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit: int,
    ) -> Observation:
        """Run one fixed argv vector without a shell, environment hooks, or retries."""
        if not argv:
            return Observation(status=ProbeStatus.ERROR.value, reason="empty_command")
        if output_limit < 0:
            return Observation(
                status=ProbeStatus.ERROR.value,
                reason="invalid_output_limit",
            )
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C",
            "LC_ALL": "C",
        }
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
            )
        except FileNotFoundError:
            return Observation(status=ProbeStatus.UNAVAILABLE.value, reason="binary_not_found")
        except OSError as error:
            return _error_observation(error)

        stdout = bytearray()
        stderr = bytearray()
        remaining_output = [output_limit]
        output_lock = threading.Lock()
        truncated = [False]
        reader_stop = threading.Event()
        reader_errors: list[BaseException] = []

        def drain(stream: object, buffer: bytearray) -> None:
            """Drain one pipe without waiting for inherited handles to close.

            A short nonblocking final drain lets the caller join both readers
            before constructing the observation, even when a descendant still
            holds the child's stdout or stderr pipe open.
            """
            finalizing = False
            final_deadline = 0.0
            waiter: _PipeWaiter | None = None
            try:
                descriptor = stream.fileno()  # type: ignore[attr-defined]
                waiter = _PipeWaiter(descriptor)
                while True:
                    now = time.monotonic()
                    if reader_stop.is_set():
                        if not finalizing:
                            finalizing = True
                            final_deadline = now + _READER_FINALIZE_SECONDS
                        if now >= final_deadline:
                            return
                        poll_timeout = 0.0
                    else:
                        poll_timeout = _READER_POLL_INTERVAL_SECONDS
                    if not waiter.wait(poll_timeout):
                        if finalizing:
                            return
                        continue
                    chunk = os.read(descriptor, 8192)
                    if not chunk:
                        return
                    with output_lock:
                        room = max(0, min(len(chunk), remaining_output[0]))
                        buffer.extend(chunk[:room])
                        remaining_output[0] -= room
                        over_limit = len(chunk) > room
                        if over_limit:
                            truncated[0] = True
                    if over_limit:
                        try:
                            process.kill()
                        except OSError:
                            pass
                        return
            except (OSError, ValueError) as error:
                with output_lock:
                    if not reader_errors:
                        reader_errors.append(error)
                try:
                    process.kill()
                except OSError:
                    pass
                return
            finally:
                if waiter is not None:
                    waiter.close()

        assert process.stdout is not None
        assert process.stderr is not None
        readers = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timeout_status = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timeout_status = True
            process.kill()
            process.wait()
        reader_stop.set()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        exit_code = process.returncode
        duration_ms = int((time.monotonic() - started) * 1000)
        if timeout_status:
            return Observation(
                status=ProbeStatus.TIMEOUT.value,
                reason="timeout",
                detail=f"command exceeded {timeout_seconds:g} seconds",
                exit_code=exit_code,
                truncated=truncated[0],
            )
        text = bytes(stdout).decode("utf-8", errors="replace")
        error_text = bytes(stderr).decode("utf-8", errors="replace")
        if reader_errors and not timeout_status:
            error = reader_errors[0]
            return Observation(
                status=ProbeStatus.ERROR.value,
                text=text,
                reason="output_capture_failed",
                detail=f"{type(error).__name__}: {error}"[:500],
                exit_code=exit_code,
                truncated=truncated[0],
            )
        if exit_code != 0:
            return Observation(
                status=ProbeStatus.ERROR.value,
                text=text,
                reason="nonzero_exit",
                detail=error_text.strip()[:500] or None,
                exit_code=exit_code,
                truncated=truncated[0],
            )
        return Observation(
            status=ProbeStatus.OK.value,
            text=text,
            detail=error_text.strip()[:500] or None,
            exit_code=exit_code,
            truncated=truncated[0],
        )

    def platform_facts(self) -> dict[str, object]:
        """Return standard-library platform facts for the running interpreter."""
        system = platform_module.system()
        return {
            "system": system,
            "release": platform_module.release(),
            "machine": platform_module.machine(),
            "hostname": platform_module.node(),
            "processor": platform_module.processor(),
            "cpu_count": os.cpu_count(),
            "physical_memory_bytes": _sysconf_memory(),
            "mac_version": platform_module.mac_ver()[0] if system == "Darwin" else None,
            "python": {
                "implementation": platform_module.python_implementation(),
                "version": platform_module.python_version(),
                "prefix": sys.prefix,
                "base_prefix": sys.base_prefix,
            },
        }


def _require_utf8_strings(value: object, *, label: str) -> None:
    """Reject replay strings that cannot be encoded as UTF-8.

    ``json.loads`` accepts escaped lone UTF-16 surrogates, but later transcript
    rendering encodes replay text as UTF-8. Validate the bounded replay
    document iteratively so malformed text becomes a structured ingestion
    error rather than a runtime encoding failure.
    """
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as error:
                raise InventoryValidationError(
                    f"{label} contains text that cannot be encoded as UTF-8"
                ) from error
        elif isinstance(current, dict):
            for key, item in current.items():
                pending.append(key)
                pending.append(item)
        elif isinstance(current, list):
            pending.extend(current)


class ReplayObservationSource:
    """Serve synthetic recorded observations for deterministic CLI tests.

    A replay document must declare itself synthetic.  It is intentionally a
    test seam, not an evidence path: replay reports always state
    ``collection_mode: replay`` and never claim live host verification.
    """

    def __init__(
        self,
        observations: dict[str, Observation],
        platform_facts: dict[str, object] | None = None,
    ) -> None:
        self._observations = observations
        self._platform_facts = platform_facts or {}

    @classmethod
    def from_path(cls, path: Path) -> "ReplayObservationSource":
        """Load and validate one synthetic replay document."""
        payload = load_strict_json(
            path, label="replay document", max_bytes=MAX_REPLAY_BYTES
        )
        data = require_mapping(payload, label="replay document")
        _require_utf8_strings(data, label="replay document")
        if data.get("schema") != REPLAY_SCHEMA_NAME:
            raise InventoryValidationError(
                f"replay schema must be {REPLAY_SCHEMA_NAME!r}"
            )
        if data.get("schema_version") != REPLAY_SCHEMA_VERSION:
            raise InventoryValidationError(
                f"unsupported replay schema_version: {data.get('schema_version')!r}"
            )
        if data.get("synthetic") is not True:
            raise InventoryValidationError("replay documents must declare synthetic: true")
        entries = require_mapping(data.get("observations"), label="replay observations")
        platform_raw = data.get("platform", {})
        platform_facts = require_mapping(platform_raw, label="replay platform")
        observations: dict[str, Observation] = {}
        allowed = {item.value for item in ProbeStatus}
        for key, raw in entries.items():
            if not isinstance(key, str) or not key:
                raise InventoryValidationError("replay observation keys must be strings")
            item = require_mapping(raw, label=f"replay observation {key!r}")
            status = item.get("status")
            if status not in allowed:
                raise InventoryValidationError(
                    f"replay observation {key!r} has invalid status: {status!r}"
                )
            text = item.get("text", "")
            if not isinstance(text, str):
                raise InventoryValidationError(
                    f"replay observation {key!r} text must be a string"
                )
            detail = item.get("detail")
            if detail is not None and not isinstance(detail, str):
                raise InventoryValidationError(
                    f"replay observation {key!r} detail must be a string or null"
                )
            observations[key] = Observation(
                status=status,
                text=text,
                reason=item.get("reason") if isinstance(item.get("reason"), str) else None,
                detail=detail,
                exit_code=item.get("exit_code")
                if isinstance(item.get("exit_code"), int)
                else None,
                truncated=bool(item.get("truncated", False)),
            )
        return cls(observations, platform_facts)

    def _lookup(self, key: str) -> Observation:
        return self._observations.get(
            key,
            Observation(status=ProbeStatus.UNAVAILABLE.value, reason="not_recorded"),
        )

    def read_text(
        self,
        path: Path,
        *,
        limit: int = DEFAULT_OUTPUT_LIMIT,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> Observation:
        """Return a recorded file read, bounded like a local read."""
        observation = self._lookup(f"read:{path}")
        if not observation.ok:
            return observation
        raw = observation.text.encode("utf-8")
        if len(raw) <= limit:
            return observation
        return Observation(
            status=observation.status,
            text=raw[:limit].decode("utf-8", errors="replace"),
            reason=observation.reason,
            detail=observation.detail,
            exit_code=observation.exit_code,
            truncated=True,
        )

    def read_prefix(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, bytes]:
        """Replay does not fabricate binary model content."""
        return (
            Observation(
                status=ProbeStatus.UNAVAILABLE.value,
                reason="replay_binary_unavailable",
                detail="replay mode does not serve model file bytes",
            ),
            b"",
        )

    def sha256(
        self,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, str | None]:
        """Replay never fabricates a content digest."""
        return (
            Observation(
                status=ProbeStatus.UNAVAILABLE.value,
                reason="replay_digest_unavailable",
                detail="replay mode does not hash model files",
            ),
            None,
        )

    def stat(self, path: Path) -> Observation:
        """Return a recorded lstat result."""
        return self._lookup(f"stat:{path}")

    def list_dir(
        self, path: Path, *, limit: int, root: Path | None = None
    ) -> Observation:
        """Return a recorded one-level directory listing."""
        observation = self._lookup(f"list:{path}")
        if not observation.ok:
            return observation
        try:
            entries = json.loads(observation.text)
        except json.JSONDecodeError:
            return observation
        if not isinstance(entries, list):
            return observation
        return Observation(
            status=observation.status,
            text=json.dumps(entries[:limit], sort_keys=True),
            reason=observation.reason,
            detail=observation.detail,
            exit_code=observation.exit_code,
            truncated=observation.truncated or len(entries) > limit,
        )

    def which(self, name: str) -> Observation:
        """Return a recorded executable lookup."""
        return self._lookup(f"which:{name}")

    def python_distribution(self, name: str) -> Observation:
        """Return recorded distribution metadata without consulting the host."""
        return self._lookup(f"distribution:{name}")

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_seconds: float,
        output_limit: int,
    ) -> Observation:
        """Return a recorded fixed-command result."""
        return self._lookup("run:" + json.dumps(list(argv), separators=(",", ":")))

    def platform_facts(self) -> dict[str, object]:
        """Return only platform facts declared by the synthetic replay document."""
        return dict(self._platform_facts)


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    """Stable identity and criticality for one collection attempt."""

    probe_id: str
    category: str
    criticality: str = "optional"


class ProbeLedger:
    """Record one :class:`ProbeRecord` for every observation attempt."""

    def __init__(self, source: ObservationSource) -> None:
        self.source = source
        self.records: list[ProbeRecord] = []

    def _record(
        self,
        spec: ProbeSpec,
        *,
        source: str,
        command: Sequence[str] | None,
        operation: object,
    ) -> object:
        """Execute one operation and add its provenance to the ledger."""
        started_at = utc_now()
        started = time.monotonic()
        try:
            result = operation()  # type: ignore[operator]
        except Exception as error:  # pragma: no cover - defensive boundary
            result = Observation(
                status=ProbeStatus.ERROR.value,
                reason="unexpected_error",
                detail=str(error),
            )
        duration_ms = int((time.monotonic() - started) * 1000)
        observation = result[0] if isinstance(result, tuple) else result
        assert isinstance(observation, Observation)
        payload = result[1] if isinstance(result, tuple) else None
        output_bytes = 0
        if isinstance(payload, bytes):
            output_bytes = len(payload)
        elif isinstance(payload, str):
            output_bytes = len(payload.encode("utf-8"))
        elif isinstance(observation, Observation):
            output_bytes = len(observation.text.encode("utf-8"))
        self.records.append(
            ProbeRecord(
                probe_id=spec.probe_id,
                category=spec.category,
                status=observation.status,
                criticality=spec.criticality,
                source=source,
                started_at=started_at,
                duration_ms=duration_ms,
                command=tuple(command) if command is not None else None,
                exit_code=observation.exit_code,
                output_bytes=output_bytes,
                truncated=observation.truncated,
                reason=observation.reason,
            detail=(
                sanitize_text(observation.detail, home=Path.home(), limit=1000)
                if observation.detail
                else None
            ),
                excerpt=sanitize_text(
                    observation.text or observation.detail or "",
                    home=Path.home(),
                ),
            )
        )
        return result

    def read(
        self,
        spec: ProbeSpec,
        path: Path,
        *,
        limit: int = DEFAULT_OUTPUT_LIMIT,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> Observation:
        """Read one text file and record the attempt."""
        result = self._record(
            spec,
            source=f"file:{path}",
            command=None,
            operation=lambda: self.source.read_text(
                path,
                limit=limit,
                follow_final_symlink=follow_final_symlink,
                root=root,
            ),
        )
        assert isinstance(result, Observation)
        return result

    def record_observation(
        self, spec: ProbeSpec, *, source: str, observation: Observation
    ) -> Observation:
        """Record a fact produced by the platform rather than by the source.

        This is used for values such as ``os.uname()`` and ``sysconf`` results
        so the transcript still shows what was attempted and where it came from.
        """
        self.records.append(
            ProbeRecord(
                probe_id=spec.probe_id,
                category=spec.category,
                status=observation.status,
                criticality=spec.criticality,
                source=source,
                started_at=utc_now(),
                duration_ms=0,
                command=None,
                exit_code=observation.exit_code,
                output_bytes=len(observation.text.encode("utf-8")),
                truncated=observation.truncated,
                reason=observation.reason,
            detail=(
                sanitize_text(observation.detail, home=Path.home(), limit=1000)
                if observation.detail
                else None
            ),
                excerpt=sanitize_text(
                    observation.text or observation.detail or "",
                    home=Path.home(),
                ),
            )
        )
        return observation

    def platform_facts(self) -> dict[str, object]:
        """Return the source's platform facts without adding a separate probe."""
        return self.source.platform_facts()

    def read_prefix(
        self,
        spec: ProbeSpec,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, bytes]:
        """Read a bounded binary prefix and record the attempt."""
        result = self._record(
            spec,
            source=f"file:{path}",
            command=None,
            operation=lambda: self.source.read_prefix(
                path,
                limit=limit,
                follow_final_symlink=follow_final_symlink,
                root=root,
            ),
        )
        assert isinstance(result, tuple)
        return result

    def sha256(
        self,
        spec: ProbeSpec,
        path: Path,
        *,
        limit: int,
        follow_final_symlink: bool = True,
        root: Path | None = None,
    ) -> tuple[Observation, str | None]:
        """Hash one file in a bounded stream and record the attempt."""
        result = self._record(
            spec,
            source=f"file:{path}",
            command=None,
            operation=lambda: self.source.sha256(
                path,
                limit=limit,
                follow_final_symlink=follow_final_symlink,
                root=root,
            ),
        )
        assert isinstance(result, tuple)
        return result

    def stat(self, spec: ProbeSpec, path: Path) -> Observation:
        """Stat one path without following symlinks and record the attempt."""
        result = self._record(
            spec,
            source=f"stat:{path}",
            command=None,
            operation=lambda: self.source.stat(path),
        )
        assert isinstance(result, Observation)
        return result

    def list_dir(
        self,
        spec: ProbeSpec,
        path: Path,
        *,
        limit: int,
        root: Path | None = None,
    ) -> Observation:
        """List one directory level and record the attempt."""
        result = self._record(
            spec,
            source=f"list:{path}",
            command=None,
            operation=lambda: self.source.list_dir(
                path, limit=limit, root=root
            ),
        )
        assert isinstance(result, Observation)
        return result

    def which(self, spec: ProbeSpec, name: str) -> Observation:
        """Resolve one executable name and record the attempt."""
        result = self._record(
            spec,
            source=f"which:{name}",
            command=None,
            operation=lambda: self.source.which(name),
        )
        assert isinstance(result, Observation)
        return result

    def python_distribution(self, spec: ProbeSpec, name: str) -> Observation:
        """Read one distribution's metadata and record the attempt."""
        result = self._record(
            spec,
            source=f"distribution:{name}",
            command=None,
            operation=lambda: self.source.python_distribution(name),
        )
        assert isinstance(result, Observation)
        return result

    def run(
        self,
        spec: ProbeSpec,
        argv: Sequence[str],
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        output_limit: int = DEFAULT_OUTPUT_LIMIT,
    ) -> Observation:
        """Run one fixed argv vector and record the attempt."""
        result = self._record(
            spec,
            source="command:" + " ".join(argv),
            command=argv,
            operation=lambda: self.source.run(
                argv,
                timeout_seconds=timeout_seconds,
                output_limit=output_limit,
            ),
        )
        assert isinstance(result, Observation)
        return result


def sanitize_text(text: str, *, home: Path | None = None, limit: int = TRANSCRIPT_EXCERPT_LIMIT) -> str:
    """Remove a home-directory prefix and cap text retained in the transcript."""
    if home is not None:
        text = text.replace(str(home), "~")
    text = text.replace("\x00", "\\0")
    if len(text) > limit:
        text = text[:limit].rstrip() + "\n[truncated]"
    return text
