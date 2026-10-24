"""Small descriptor-based extended-attribute boundary for Linux and macOS.

Ownership tokens are bounded to 128 bytes and created only when absent. These
functions never follow a pathname, replace a token, or silently substitute
weaker inode-only ownership when a filesystem does not support attributes.
macOS does not expose these descriptor syscalls through Python's os module.
"""
from __future__ import annotations

import ctypes
import errno
import os
import sys
from functools import lru_cache

_MAX_TOKEN_BYTES = 128


@lru_cache(maxsize=1)
def _native():
    """Declare the platform's fgetxattr/fsetxattr ABI exactly once."""
    if sys.platform not in {'linux', 'darwin'}:
        raise OSError(errno.ENOTSUP, 'publication ownership requires Linux or macOS')
    library = ctypes.CDLL(None, use_errno=True)
    arguments = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
    library.fgetxattr.argtypes = arguments + (
        [ctypes.c_uint32, ctypes.c_int] if sys.platform == 'darwin' else [])
    library.fgetxattr.restype = ctypes.c_ssize_t
    library.fsetxattr.argtypes = arguments + (
        [ctypes.c_uint32, ctypes.c_int] if sys.platform == 'darwin' else [ctypes.c_int])
    library.fsetxattr.restype = ctypes.c_int
    return library


def _raise_errno() -> None:
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code))


def read_token(descriptor: int, name: str) -> bytes:
    """Read a bounded token from the already-open filesystem object."""
    buffer = ctypes.create_string_buffer(_MAX_TOKEN_BYTES)
    extra = (0, 0) if sys.platform == 'darwin' else ()
    size = _native().fgetxattr(descriptor, name.encode('utf-8'), buffer, len(buffer), *extra)
    if size < 0:
        _raise_errno()
    return buffer.raw[:size]


def create_token(descriptor: int, name: str, value: bytes) -> None:
    """Create a token without replacing any existing ownership claim.

    sys/xattr.h defines XATTR_CREATE as 2 on Darwin and 1 on Linux. The caller
    must fsync the descriptor before committing a journal that relies on it.
    """
    if not 0 < len(value) <= _MAX_TOKEN_BYTES:
        raise ValueError('ownership token must contain 1-128 bytes')
    buffer = ctypes.create_string_buffer(value)
    extra = (0, 2) if sys.platform == 'darwin' else (1,)
    result = _native().fsetxattr(descriptor, name.encode('utf-8'), buffer, len(value), *extra)
    if result < 0:
        _raise_errno()
