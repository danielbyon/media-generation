"""Inject Linux inode operations on Darwin; this is not native qualification.

The backing links live only in a test-owned directory outside the acquisition
destination. They emulate kernel inode retention, and are never visible to the
production code. All reads, writes, hashes, hard links, and syncs remain real.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from media_generation import _candidate_acquisition as acquisition


def inject_linux_inode_operations(monkeypatch, backing: Path):
    """Return observed syscall events for an explicitly injected Linux run."""
    backing.mkdir()
    real_open, real_close = os.open, os.close
    real_fstat, real_unlink, real_link = os.fstat, os.unlink, os.link
    tmpfile = getattr(os, "O_TMPFILE", (1 << 29) | os.O_DIRECTORY)
    retained: dict[int, Path | tuple[int, bytes]] = {}
    events: list[tuple] = []

    class AnonymousFacts:
        def __init__(self, facts):
            self.facts = facts
            self.st_nlink = facts.st_nlink - 1

        def __getattr__(self, name):
            return getattr(self.facts, name)

    def open_inode(path, flags, mode=0o777, *, dir_fd=None):
        if flags & tmpfile == tmpfile:
            assert path == "."
            assert flags & os.O_RDWR
            assert not flags & (os.O_CREAT | os.O_EXCL)
            assert mode == 0o600
            assert dir_fd is not None
            # Allocation must remain exclusive when concurrent preparations
            # reach this syscall before either has appended its open event.
            descriptor, name = tempfile.mkstemp(dir=backing)
            inode = Path(name)
            retained[descriptor] = inode
            events.append(("open", descriptor, dir_fd))
            return descriptor
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def fstat_inode(descriptor):
        facts = real_fstat(descriptor)
        return AnonymousFacts(facts) if isinstance(retained.get(descriptor), Path) else facts

    def close_inode(descriptor):
        # Retire ownership before close allows another thread to reuse the FD.
        inode = retained.pop(descriptor, None)
        real_close(descriptor)
        if inode is not None:
            if isinstance(inode, Path):
                real_unlink(inode)
            events.append(("close", descriptor))

    class LinkAt:
        argtypes = ()
        restype = ctypes.c_int

        def __call__(self, source_fd, source, parent_fd, destination, flags):
            if source:
                assert source_fd == -100 and flags == 0x400
                assert source.startswith(b"/proc/self/fd/")
                source_fd = int(source.rsplit(b"/", 1)[1])
            else:
                assert flags == 0x1000
            events.append(("link", source_fd, destination, flags))
            try:
                inode = retained[source_fd]
                if isinstance(inode, Path):
                    real_link(inode, destination, dst_dir_fd=parent_fd)
                    real_unlink(inode)
                else:
                    real_link(inode[1], destination, src_dir_fd=inode[0], dst_dir_fd=parent_fd)
                retained[source_fd] = (parent_fd, destination)
            except OSError as error:
                ctypes.set_errno(error.errno)
                return -1
            return 0

    monkeypatch.setattr(acquisition, "sys", SimpleNamespace(platform="linux", exception=sys.exception))
    monkeypatch.setattr(os, "O_TMPFILE", tmpfile, raising=False)
    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, open_inode})
    monkeypatch.setattr(os, "open", open_inode)
    monkeypatch.setattr(os, "fstat", fstat_inode)
    monkeypatch.setattr(os, "close", close_inode)
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(linkat=LinkAt()))
    return events
