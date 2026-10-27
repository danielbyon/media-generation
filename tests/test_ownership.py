"""Exercise bounded ownership xattrs on real descriptors and isolated fake ABIs.

Real calls use only the host's configured native library. Cross-platform ABI
checks replace the library loader and both native functions with Python fakes;
they never call a foreign signature or alter the cached host library.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import ownership


_ATTRIBUTE = "user.media_generation.test_owner"
_SUPPORTED_HOST = sys.platform in {"linux", "darwin"}


@pytest.fixture(params=["file", "directory"])
def local_descriptor(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[int]:
    """Keep an ordinary temporary file or directory open for native xattr calls."""
    if not _SUPPORTED_HOST:
        pytest.skip("Native ownership attributes require Linux or macOS")
    path = tmp_path / "owned"
    if request.param == "directory":
        path.mkdir()
        flags = os.O_RDONLY | os.O_DIRECTORY
    else:
        path.write_bytes(b"ordinary file contents")
        flags = os.O_RDONLY
    descriptor = os.open(path, flags)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _seed_oversized_attribute(descriptor: int) -> None:
    """Seed 129 bytes through the host ABI to exercise bounded read failure.

    The public create helper deliberately refuses this value. This fixture
    setup bypasses only its length validation and retains create-only flags.
    Neither branch is executed under a simulated platform.
    """
    value = b"x" * 129
    buffer = ctypes.create_string_buffer(value)
    library = ownership._native()
    name = _ATTRIBUTE.encode("utf-8")
    if sys.platform == "darwin":
        result = library.fsetxattr(descriptor, name, buffer, len(value), 0, 2)
    elif sys.platform == "linux":
        result = library.fsetxattr(descriptor, name, buffer, len(value), 1)
    else:
        pytest.fail("Oversized fixture setup requires the host Linux or Darwin ABI")
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


@pytest.mark.parametrize(
    "token",
    [b"x", b"owner-session", b"\x00owner\xff\x00", bytes(range(128))],
    ids=["minimum", "ordinary", "binary", "maximum"],
)
def test_local_token_roundtrip(local_descriptor: int, token: bytes) -> None:
    """The host ABI preserves exact bytes, including NULs and the 128-byte limit."""
    assert ownership.create_token(local_descriptor, _ATTRIBUTE, token) is None
    assert ownership.read_token(local_descriptor, _ATTRIBUTE) == token


@pytest.mark.parametrize("replacement", [b"first owner", b"different owner"])
def test_duplicate_create_does_not_replace_existing_token(
    local_descriptor: int, replacement: bytes
) -> None:
    original = b"first owner"
    ownership.create_token(local_descriptor, _ATTRIBUTE, original)

    with pytest.raises(OSError) as caught:
        ownership.create_token(local_descriptor, _ATTRIBUTE, replacement)

    assert caught.value.errno == errno.EEXIST
    assert ownership.read_token(local_descriptor, _ATTRIBUTE) == original


def test_absent_token_is_an_error(local_descriptor: int) -> None:
    """A missing attribute cannot be mistaken for an empty ownership claim."""
    with pytest.raises(OSError) as caught:
        ownership.read_token(local_descriptor, _ATTRIBUTE)

    missing_codes = {
        getattr(errno, "ENODATA", None),
        getattr(errno, "ENOATTR", None),
    } - {None}
    assert caught.value.errno in missing_codes


@pytest.mark.parametrize(
    "token", [b"", b"x" * 129, b"x" * 1024], ids=["empty", "one-byte-over", "far-over"]
)
def test_invalid_token_length_is_rejected_before_native_access(
    local_descriptor: int, monkeypatch: pytest.MonkeyPatch, token: bytes
) -> None:
    def forbidden_native():
        pytest.fail("Invalid token length reached the native library")

    monkeypatch.setattr(ownership, "_native", forbidden_native)
    with pytest.raises(ValueError, match="1-128 bytes"):
        ownership.create_token(local_descriptor, _ATTRIBUTE, token)


def test_oversized_stored_token_fails_instead_of_truncating(local_descriptor: int) -> None:
    _seed_oversized_attribute(local_descriptor)

    with pytest.raises(OSError) as caught:
        ownership.read_token(local_descriptor, _ATTRIBUTE)

    assert caught.value.errno == errno.ERANGE


@pytest.mark.skipif(not _SUPPORTED_HOST, reason="Requires the host Linux or Darwin ABI")
@pytest.mark.parametrize("operation", ["read", "create"])
def test_bad_descriptor_preserves_native_errno(operation: str) -> None:
    with pytest.raises(OSError) as caught:
        if operation == "read":
            ownership.read_token(-1, _ATTRIBUTE)
        else:
            ownership.create_token(-1, _ATTRIBUTE, b"owner")

    assert caught.value.errno == errno.EBADF


class _FakeNativeFunction:
    """Expose ctypes declaration attributes while calling only Python code."""

    def __init__(self, implementation: Callable[..., int]) -> None:
        self.implementation = implementation
        self.argtypes: list[type] | None = None
        self.restype: type | None = None
        self.calls: list[tuple[object, ...]] = []

    def __call__(self, *arguments: object) -> int:
        self.calls.append(arguments)
        return self.implementation(*arguments)


@pytest.mark.parametrize("platform_name", ["linux", "darwin"])
def test_native_signatures_and_calls_use_the_correct_platform_abi(
    monkeypatch: pytest.MonkeyPatch, platform_name: str
) -> None:
    """Both ABIs are exercised without loading or calling any native symbol."""
    descriptor = 42
    name = "user.media_generation.ownership_\N{SNOWMAN}"
    token = b"\x00binary-owner\xff\x00"
    get_extra = (0, 0) if platform_name == "darwin" else ()
    set_extra = (0, 2) if platform_name == "darwin" else (1,)

    def fake_get(fd, encoded_name, buffer, size, *extra):
        assert fd == descriptor
        assert encoded_name == name.encode("utf-8")
        assert size == 128
        assert len(buffer) == 128
        assert extra == get_extra
        ctypes.memmove(buffer, token, len(token))
        return len(token)

    def fake_set(fd, encoded_name, buffer, size, *extra):
        assert fd == descriptor
        assert encoded_name == name.encode("utf-8")
        assert size == len(token)
        assert ctypes.string_at(buffer, size) == token
        assert extra == set_extra
        return 0

    get_function = _FakeNativeFunction(fake_get)
    set_function = _FakeNativeFunction(fake_set)
    library = SimpleNamespace(fgetxattr=get_function, fsetxattr=set_function)
    loads: list[tuple[object, bool]] = []

    def fake_load(name, *, use_errno):
        loads.append((name, use_errno))
        return library

    # Replace only this module's dependencies, leaving global sys/ctypes and
    # the cached host library untouched. Every platform-specific call is fake.
    fake_ctypes = SimpleNamespace(**vars(ctypes))
    fake_ctypes.CDLL = fake_load
    monkeypatch.setattr(ownership, "ctypes", fake_ctypes)
    monkeypatch.setattr(ownership, "sys", SimpleNamespace(platform=platform_name))
    declared = ownership._native.__wrapped__()
    assert declared is library
    assert loads == [(None, True)]

    common = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
    assert get_function.argtypes == common + (
        [ctypes.c_uint32, ctypes.c_int] if platform_name == "darwin" else []
    )
    assert get_function.restype is ctypes.c_ssize_t
    assert set_function.argtypes == common + (
        [ctypes.c_uint32, ctypes.c_int]
        if platform_name == "darwin"
        else [ctypes.c_int]
    )
    assert set_function.restype is ctypes.c_int

    # Bypass the real cache before exercising the high-level helpers under the
    # simulated platform; a cached host function must never receive these args.
    monkeypatch.setattr(ownership, "_native", lambda: declared)
    ownership.create_token(descriptor, name, token)
    assert ownership.read_token(descriptor, name) == token
    assert len(set_function.calls) == 1
    assert len(get_function.calls) == 1
    assert len(set_function.calls[0]) == (6 if platform_name == "darwin" else 5)
    assert len(get_function.calls[0]) == (6 if platform_name == "darwin" else 4)


@pytest.mark.parametrize("code", [errno.EPERM, errno.ENOTSUP])
@pytest.mark.parametrize("operation", ["read", "create"])
def test_native_failures_preserve_errno_without_fallback(
    monkeypatch: pytest.MonkeyPatch, code: int, operation: str
) -> None:
    """Permission and unsupported-filesystem errors remain explicit failures."""
    def fail(*arguments):
        ctypes.set_errno(code)
        return -1

    function = _FakeNativeFunction(fail)
    library = SimpleNamespace(fgetxattr=function, fsetxattr=function)
    monkeypatch.setattr(ownership, "_native", lambda: library)
    previous_errno = ctypes.get_errno()
    try:
        with pytest.raises(OSError) as caught:
            if operation == "read":
                ownership.read_token(42, _ATTRIBUTE)
            else:
                ownership.create_token(42, _ATTRIBUTE, b"owner")
        assert caught.value.errno == code
        assert caught.value.strerror == os.strerror(code)
        assert len(function.calls) == 1
    finally:
        ctypes.set_errno(previous_errno)


@pytest.mark.parametrize("platform_name", ["win32", "freebsd14"])
def test_unsupported_platform_fails_before_loading_native_symbols(
    monkeypatch: pytest.MonkeyPatch, platform_name: str
) -> None:
    def forbidden_load(*args, **kwargs):
        pytest.fail("Unsupported platform attempted to load native symbols")

    fake_ctypes = SimpleNamespace(**vars(ctypes))
    fake_ctypes.CDLL = forbidden_load
    monkeypatch.setattr(ownership, "ctypes", fake_ctypes)
    monkeypatch.setattr(ownership, "sys", SimpleNamespace(platform=platform_name))
    with pytest.raises(OSError) as caught:
        ownership._native.__wrapped__()
    assert caught.value.errno == errno.ENOTSUP
