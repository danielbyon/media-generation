"""Validate bounded, static images and open local files without following links.

PNG and JPEG are accepted by decoded content, regardless of their filenames.
The encoded file may contain at most 32 MiB, each dimension at most 8192 pixels,
and the image at most 16,777,216 pixels. All limits are inclusive. Validation
preserves the original bytes, metadata, orientation, and color representation;
it does not re-encode or sanitize an image.

These helpers require POSIX descriptor-relative opens and ``O_NOFOLLOW``. A
path is walked from the filesystem root or current directory without resolving
symlinks. Callers own publication, cleanup, and durability of copied files.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import os
import stat
import struct
import warnings
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from PIL import Image, ImageFile

from .errors import InputValidationError


MAX_ENCODED_BYTES = 32 * 1024 * 1024
MAX_DIMENSION = 8192
MAX_PIXELS = 16_777_216
_COPY_CHUNK_BYTES = 64 * 1024
_MEDIA_TYPES = {"PNG": "image/png", "JPEG": "image/jpeg"}
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class ImageInfo:
    """Metadata and a SHA-256 digest of the complete, unchanged encoded file."""

    media_type: str
    image_format: str
    width: int
    height: int
    file_size: int
    sha256: str


def _regular_stat(file: BinaryIO) -> os.stat_result:
    """Require a live descriptor for a regular file, rather than a stream."""
    try:
        result = os.fstat(file.fileno())
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise InputValidationError("A readable regular file is required.") from error
    if not stat.S_ISREG(result.st_mode):
        raise InputValidationError("A regular file is required.")
    return result


def _bounded_stat(file: BinaryIO) -> os.stat_result:
    """Reject oversized encoded inputs before reading any of their contents."""
    result = _regular_stat(file)
    if result.st_size > MAX_ENCODED_BYTES:
        raise InputValidationError("Image exceeds the 32 MiB encoded size limit.")
    return result


def _assert_unchanged(file: BinaryIO, before: os.stat_result) -> None:
    """Compare identity, size, mode, and nanosecond modification/change times.

    Access time is deliberately excluded because reading may update it. This
    detects changes reported by the filesystem; it is not a filesystem lock.
    """
    after = _regular_stat(file)
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise InputValidationError("Source file changed while it was being read.")


def _source_chunks(file: BinaryIO, before: os.stat_result) -> Iterator[bytes]:
    """Read from zero in bounded chunks, allowing only one extra byte for EOF.

    Positional descriptor reads bypass any stale caller-side read buffer and
    preserve the caller's cursor. The caller must consume the iterator to
    completion to perform the final descriptor check. Short nonempty reads are
    valid; premature EOF is not.
    """
    try:
        descriptor = file.fileno()
        offset = 0
        remaining = before.st_size
        while remaining:
            requested = min(remaining, _COPY_CHUNK_BYTES)
            chunk = os.pread(descriptor, requested, offset)
            if not isinstance(chunk, bytes) or not 0 < len(chunk) <= requested:
                raise InputValidationError("Source file changed or could not be read.")
            remaining -= len(chunk)
            offset += len(chunk)
            yield chunk
        if os.pread(descriptor, 1, offset) != b"":
            raise InputValidationError("Source file grew while it was being read.")
    except (OSError, TypeError, ValueError) as error:
        raise InputValidationError("Source file could not be read safely.") from error
    _assert_unchanged(file, before)


def _check_png_container(data: bytes) -> None:
    """Reject animation chunks and incomplete PNG chunk framing.

    Pillow verifies PNG checksums and decodes pixels separately. Its verifier
    stops at IEND before checking that chunk's payload and checksum, so require
    the canonical empty IEND here. Inspect chunk types rather than searching
    arbitrary bytes, which may contain the same text in metadata or pixels.
    """
    offset = 8  # The PNG signature has already been recognized by Pillow.
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + length + 12
        if end > len(data):
            break
        if chunk_type in (b"acTL", b"fcTL", b"fdAT"):
            raise InputValidationError("Animated PNG images are not supported.")
        if chunk_type == b"IEND":
            if data[offset:end] != b"\x00\x00\x00\x00IEND\xaeB`\x82":
                break
            return
        offset = end
    raise InputValidationError("PNG has an incomplete or invalid end chunk.")


def _check_image(image: Image.Image) -> tuple[str, int, int]:
    """Check format, dimensions, and frame count before allocating pixel data."""
    image_format = image.format
    if image_format is None or image_format not in _MEDIA_TYPES:
        raise InputValidationError("Only PNG and JPEG images are supported.")
    width, height = image.size
    if not (0 < width <= MAX_DIMENSION and 0 < height <= MAX_DIMENSION):
        raise InputValidationError("Image dimensions must be between 1 and 8192.")
    if width * height > MAX_PIXELS:
        raise InputValidationError("Image exceeds the 16,777,216 pixel limit.")
    if (
        getattr(image, "n_frames", 1) != 1
        or getattr(image, "is_animated", False)
        or image.get_format_mimetype() != _MEDIA_TYPES[image_format]
        or "mp" in image.info
    ):
        raise InputValidationError("Only static, single-frame PNG and JPEG are supported.")
    return image_format, width, height


def validate_image(file: BinaryIO) -> ImageInfo:
    """Verify and fully decode one bounded, unchanged PNG or JPEG file.

    Read from offset zero without closing the caller's handle or moving its
    cursor. The digest includes all encoded bytes, including metadata
    and trailing bytes accepted by the decoder. APNG and MPO containers are
    rejected even when they expose a single default image. Pillow's permissive
    truncated-image mode must be disabled; this function never changes global
    decoder limits or flags. Invalid content and unsafe input raise
    :class:`InputValidationError`.
    """
    before = _bounded_stat(file)
    data = b"".join(_source_chunks(file, before))
    try:
        if ImageFile.LOAD_TRUNCATED_IMAGES:
            raise InputValidationError("Strict image decoding must be enabled.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            warnings.simplefilter("error", UserWarning)
            with Image.open(io.BytesIO(data), formats=("PNG", "JPEG")) as image:
                image_format, width, height = _check_image(image)
                if image_format == "PNG":
                    _check_png_container(data)
                image.verify()
            # verify() consumes decoder state; reopen the same immutable bytes.
            with Image.open(io.BytesIO(data), formats=("PNG", "JPEG")) as image:
                _check_image(image)
                image.load()
                _check_image(image)
        if ImageFile.LOAD_TRUNCATED_IMAGES:
            raise InputValidationError("Strict image decoding must be enabled.")
    except (
        OSError,
        ValueError,
        SyntaxError,
        EOFError,
        OverflowError,
        IndexError,
        struct.error,
        Image.DecompressionBombError,
        Warning,
    ) as error:
        raise InputValidationError("Image is corrupt, unsafe, or not PNG or JPEG.") from error
    digest = hashlib.sha256(data).hexdigest()
    _assert_unchanged(file, before)
    return ImageInfo(
        media_type=_MEDIA_TYPES[image_format],
        image_format=image_format,
        width=width,
        height=height,
        file_size=len(data),
        sha256=digest,
    )


def _open_at(path: str, flags: int, directory: int | None = None) -> int:
    """Translate refused filesystem opens into input validation failures."""
    try:
        return os.open(path, flags, dir_fd=directory)
    except (OSError, ValueError) as error:
        raise InputValidationError(
            "File path cannot be opened without following links."
        ) from error


@contextmanager
def _open_directory(path: Path) -> Iterator[int]:
    """Pin every directory component, including the supplied root's ancestors."""
    if ".." in path.parts or "\x00" in str(path):
        raise InputValidationError("Directory paths cannot contain '..' or null bytes.")
    with ExitStack() as stack:
        directory = _open_at(path.anchor or ".", _DIRECTORY_FLAGS)
        stack.callback(os.close, directory)
        for component in path.parts[1:] if path.anchor else path.parts:
            directory = _open_at(component, _DIRECTORY_FLAGS, directory)
            stack.callback(os.close, directory)
        yield directory


@contextmanager
def _open_file_at(directory: int, components: tuple[str, ...]) -> Iterator[BinaryIO]:
    """Walk approved relative components and reject nonregular leaf descriptors."""
    with ExitStack() as stack:
        for component in components[:-1]:
            directory = _open_at(component, _DIRECTORY_FLAGS, directory)
            stack.callback(os.close, directory)
        descriptor = _open_at(components[-1], _FILE_FLAGS, directory)
        stack.callback(os.close, descriptor)
        # O_NONBLOCK prevents a FIFO from blocking before fstat can reject it.
        # ExitStack owns the descriptor, including if wrapping it fails.
        try:
            file = os.fdopen(descriptor, "rb", buffering=0, closefd=False)
        except (OSError, ValueError) as error:
            raise InputValidationError("A readable regular file is required.") from error
        with file:
            _regular_stat(file)
            yield file


@contextmanager
def open_approved_source(root: Path, relative_path: str) -> Iterator[BinaryIO]:
    """Open a local source beneath an approved directory without following links.

    Relative names use POSIX separators. Absolute names, URLs, backslashes,
    null bytes, empty components, '.', and '..' are rejected before any open.
    Both the root's ancestors and every relative component are opened with
    ``O_NOFOLLOW``; directories also require ``O_DIRECTORY``. The yielded
    unbuffered regular file is closed when the context exits.
    """
    if not isinstance(relative_path, str) or "\x00" in relative_path or "\\" in relative_path:
        raise InputValidationError("A local relative file path is required.")
    components = tuple(relative_path.split("/"))
    if any(component in ("", ".", "..") for component in components):
        raise InputValidationError("A relative path cannot contain empty, '.' or '..' components.")
    try:
        parsed = urlsplit(relative_path)
    except ValueError as error:
        raise InputValidationError("A local relative file path is required.") from error
    if parsed.scheme or parsed.netloc:
        raise InputValidationError("URLs are not approved source paths.")
    with _open_directory(root) as directory:
        with _open_file_at(directory, components) as file:
            yield file


@contextmanager
def open_regular(path: Path) -> Iterator[BinaryIO]:
    """Open an authoritative local path, rejecting symlinks in every component.

    Absolute and relative paths are supported. Parent traversal is forbidden;
    callers must supply the authoritative spelling rather than resolving an
    untrusted path first. The yielded regular file starts at offset zero.
    A missing file or ancestor raises FileNotFoundError so integrity callers
    can distinguish missing artifacts from unsafe or corrupt ones. Other
    acquisition failures raise InputValidationError.
    """
    if not path.name or path.name == "..":
        raise InputValidationError("A regular file path is required.")
    with ExitStack() as stack:
        try:
            directory = stack.enter_context(_open_directory(path.parent))
            file = stack.enter_context(_open_file_at(directory, (path.name,)))
        except InputValidationError as error:
            if isinstance(error.__cause__, FileNotFoundError):
                raise error.__cause__ from None
            raise
        # Keep acquisition error handling outside the consumer's context body.
        yield file


def copy_source(source: BinaryIO, destination: BinaryIO) -> None:
    """Copy bounded bytes from zero to a caller-created regular destination.

    The source cursor is preserved. The destination may be preallocated; it is
    rewound and truncated to the copied length so stale suffix bytes cannot
    remain. Append mode and copying onto the source inode are rejected before
    writing. Source changes raise
    InputValidationError; destination I/O errors propagate to the caller.
    Either failure may leave a partial destination, which the caller must
    discard. Flush completes buffered writes, but publication and fsync belong
    to the caller. Validate the completed copy before publication: stability
    during this call does not bind it to an earlier validation of the source.
    """
    before = _bounded_stat(source)
    target = _regular_stat(destination)
    if (before.st_dev, before.st_ino) == (target.st_dev, target.st_ino):
        raise InputValidationError("Source and destination must be different files.")
    if fcntl.fcntl(destination.fileno(), fcntl.F_GETFL) & os.O_APPEND:
        raise InputValidationError("The destination cannot be opened in append mode.")
    destination.seek(0)
    for chunk in _source_chunks(source, before):
        pending = memoryview(chunk)
        while pending:
            written = destination.write(pending)
            if not isinstance(written, int) or not 0 < written <= len(pending):
                raise OSError("Destination write did not make progress.")
            pending = pending[written:]
    destination.truncate(before.st_size)
    destination.flush()
    _assert_unchanged(source, before)
