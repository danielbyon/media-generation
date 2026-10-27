"""Generated-file tests for bounded decoding and descriptor-safe image ingestion."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import zlib
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO

import pytest
from PIL import Image, ImageFile, PngImagePlugin

from media_generation import images
from media_generation.errors import InputValidationError
from media_generation.images import (
    ImageInfo,
    copy_source,
    open_approved_source,
    open_regular,
    validate_image,
)


class _FileProbe:
    """Delegate descriptor operations for deterministic destination fault tests."""

    def __init__(self, file: BinaryIO) -> None:
        self.file = file

    def __getattr__(self, name: str):
        return getattr(self.file, name)


def _probe_reads(
    monkeypatch: pytest.MonkeyPatch,
    source_fd: int,
    *,
    after_read: Callable[[], None] | None = None,
    read_limit: int | None = None,
) -> list[int]:
    """Record positional reads and inject a deterministic change after one read."""
    read_sizes: list[int] = []
    original_pread = os.pread

    def probed_read(descriptor: int, size: int, offset: int) -> bytes:
        nonlocal after_read
        if descriptor != source_fd:
            return original_pread(descriptor, size, offset)
        read_sizes.append(size)
        result = original_pread(
            descriptor, size if read_limit is None else min(size, read_limit), offset
        )
        callback, after_read = after_read, None
        if callback is not None:
            callback()
        return result

    monkeypatch.setattr(images.os, "pread", probed_read)
    return read_sizes


def _write_image(
    path: Path,
    image_format: str = "PNG",
    size: tuple[int, int] = (7, 5),
    mode: str = "RGB",
    **options,
) -> bytes:
    """Generate an image in a temporary directory and return its exact bytes."""
    with Image.new(mode, size) as image:
        image.save(path, format=image_format, **options)
    return path.read_bytes()


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    """Build a checksummed chunk for deliberate container/decoder corruption."""
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png(width: int, height: int, compressed_pixels: bytes) -> bytes:
    """Build a small RGB PNG without allocating its declared pixel dimensions."""
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", compressed_pixels)
        + _png_chunk(b"IEND", b"")
    )


@pytest.mark.parametrize("image_format,extension", [("PNG", "jpg"), ("JPEG", "png")])
def test_decoded_format_and_digest_ignore_extension(
    tmp_path: Path, image_format: str, extension: str
) -> None:
    """The decoded format and complete encoded bytes determine metadata."""
    path = tmp_path / f"misnamed.{extension}"
    data = _write_image(path, image_format)
    with path.open("rb") as source:
        source.seek(9)
        info = validate_image(source)
        assert not source.closed
        assert source.tell() == 9
    assert info == ImageInfo(
        media_type={"PNG": "image/png", "JPEG": "image/jpeg"}[image_format],
        image_format=image_format,
        width=7,
        height=5,
        file_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    assert path.read_bytes() == data
    with pytest.raises(FrozenInstanceError):
        info.width = 1


@pytest.mark.parametrize("mode", ["L", "P", "RGBA", "I;16"])
def test_png_color_modes_are_preserved(tmp_path: Path, mode: str) -> None:
    path = tmp_path / "source.png"
    original = _write_image(path, mode=mode)
    with path.open("rb") as source:
        assert validate_image(source).sha256 == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() == original


def test_metadata_and_jpeg_orientation_are_not_rewritten(tmp_path: Path) -> None:
    exif = Image.Exif()
    exif[274] = 6
    path = tmp_path / "rotated.jpg"
    original = _write_image(path, "JPEG", exif=exif)
    with path.open("rb") as source:
        info = validate_image(source)
    assert (info.width, info.height) == (7, 5)
    assert info.sha256 == hashlib.sha256(original).hexdigest()
    assert path.read_bytes() == original


def test_animation_names_inside_png_metadata_are_not_chunk_types(tmp_path: Path) -> None:
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("description", "acTL fcTL fdAT are ordinary text here")
    path = tmp_path / "metadata.png"
    _write_image(path, pnginfo=metadata)
    with path.open("rb") as source:
        assert validate_image(source).image_format == "PNG"


@pytest.mark.parametrize("size", [(1, 1), (8192, 1), (1, 8192), (8192, 2048)])
def test_inclusive_dimension_and_pixel_limits(tmp_path: Path, size: tuple[int, int]) -> None:
    path = tmp_path / "boundary.png"
    _write_image(path, size=size, mode="L")
    with path.open("rb") as source:
        info = validate_image(source)
    assert (info.width, info.height) == size


@pytest.mark.parametrize(
    "size", [(0, 1), (1, 0), (8193, 1), (1, 8193), (4097, 4096), (2**31 - 1, 2**31 - 1)]
)
def test_unsafe_dimensions_are_rejected_before_decode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, size: tuple[int, int]
) -> None:
    path = tmp_path / "oversized.png"
    path.write_bytes(_png(*size, zlib.compress(b"\x00\x00\x00\x00")))

    def forbidden_load(*args, **kwargs):
        pytest.fail("Out-of-bounds dimensions reached pixel decoding")

    monkeypatch.setattr(ImageFile.ImageFile, "load", forbidden_load)
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


def test_encoded_size_limit_is_inclusive_and_hashes_trailing_bytes(tmp_path: Path) -> None:
    """Decoder-accepted trailing bytes count toward both the size and digest."""
    path = tmp_path / "large.png"
    _write_image(path)
    with path.open("r+b") as file:
        file.truncate(32 * 1024 * 1024)
    with path.open("rb") as source:
        info = validate_image(source)
    assert info.file_size == 32 * 1024 * 1024
    with path.open("rb") as source:
        assert info.sha256 == hashlib.file_digest(source, "sha256").hexdigest()


@pytest.mark.parametrize("operation", ["validate", "copy"])
def test_oversized_source_is_rejected_without_reading_or_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    path = tmp_path / "oversized"
    with path.open("wb") as file:
        file.truncate(32 * 1024 * 1024 + 1)
    destination = tmp_path / "destination"
    destination.write_bytes(b"unchanged")
    with path.open("rb") as source, destination.open("r+b") as target:
        read_sizes = _probe_reads(monkeypatch, source.fileno())
        with pytest.raises(InputValidationError, match="32 MiB"):
            if operation == "validate":
                validate_image(source)
            else:
                copy_source(source, target)
        assert read_sizes == []
    assert destination.read_bytes() == b"unchanged"


@pytest.mark.parametrize(
    "data",
    [b"", b"not an image", b"<svg/>", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff"],
)
def test_invalid_or_header_only_content_is_rejected(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "invalid.png"
    path.write_bytes(data)
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("image_format", ["GIF", "BMP", "TIFF"])
def test_other_decodable_formats_are_rejected(tmp_path: Path, image_format: str) -> None:
    path = tmp_path / "other.png"
    _write_image(path, image_format)
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("frames,default_image", [(1, False), (2, False), (2, True)])
def test_apng_including_single_frame_is_rejected(
    tmp_path: Path, frames: int, default_image: bool
) -> None:
    path = tmp_path / "animation.png"
    with Image.new("RGB", (3, 2), "red") as first, Image.new("RGB", (3, 2), "blue") as second:
        if frames == 1:
            first.save(path, format="PNG")
        else:
            first.save(
                path,
                format="PNG",
                save_all=True,
                append_images=[second],
                default_image=default_image,
                duration=100,
                loop=0,
            )
    if frames == 1:
        # Pillow may optimize a one-frame save into an ordinary static PNG.
        # Insert animation control and frame control after the 13-byte IHDR.
        # Frame zero uses the existing IDAT pixels, with no disposal or blend.
        data = path.read_bytes()
        ihdr_end = 8 + 12 + 13
        controls = _png_chunk(b"acTL", struct.pack(">II", 1, 0)) + _png_chunk(
            b"fcTL", struct.pack(">IIIIIHHBB", 0, 3, 2, 0, 0, 1, 10, 0, 0)
        )
        path.write_bytes(data[:ihdr_end] + controls + data[ihdr_end:])
    with Image.open(path) as image:
        assert image.get_format_mimetype() == "image/apng"
        assert image.n_frames == frames
        for frame in range(image.n_frames):
            image.seek(frame)
            image.load()
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


def test_multipicture_jpeg_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "multipicture.jpg"
    with Image.new("RGB", (3, 2), "red") as first, Image.new("RGB", (3, 2), "blue") as second:
        first.save(path, format="MPO", save_all=True, append_images=[second])
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("chunk_type", [b"acTL", b"fcTL", b"fdAT"])
def test_late_animation_chunks_cannot_hide_after_pixel_data(
    tmp_path: Path, chunk_type: bytes
) -> None:
    path = tmp_path / "late-animation.png"
    data = _write_image(path)
    path.write_bytes(data[:-12] + _png_chunk(chunk_type, b"\x00" * 8) + data[-12:])
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("removed", [1, 4, 8, 12, 20])
def test_truncated_png_including_iend_checksum_is_rejected(tmp_path: Path, removed: int) -> None:
    path = tmp_path / "truncated.png"
    data = _write_image(path)
    path.write_bytes(data[:-removed])
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("part", ["IDAT", "IEND"])
def test_corrupt_png_checksums_are_rejected(tmp_path: Path, part: str) -> None:
    path = tmp_path / "checksum.png"
    data = bytearray(_write_image(path))
    offset = data.index(part.encode())
    length = int.from_bytes(data[offset - 4 : offset], "big")
    data[offset + 4 + length] ^= 0xFF
    path.write_bytes(data)
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("compressed", [b"invalid deflate", zlib.compress(b"\x00\x00")])
def test_valid_png_checksums_do_not_replace_full_decode(tmp_path: Path, compressed: bytes) -> None:
    path = tmp_path / "broken-pixels.png"
    path.write_bytes(_png(7, 5, compressed))
    with Image.open(path) as image:
        image.verify()
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


def test_truncated_jpeg_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "truncated.jpg"
    data = _write_image(path, "JPEG")
    path.write_bytes(data[:-2])
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)


@pytest.mark.parametrize("pixel_threshold", [2, 1])
def test_pillow_bomb_warning_and_error_become_validation_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pixel_threshold: int
) -> None:
    path = tmp_path / "bomb.png"
    _write_image(path, size=(3, 1))
    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", pixel_threshold)
    with path.open("rb") as source, pytest.raises(InputValidationError):
        validate_image(source)
    assert Image.MAX_IMAGE_PIXELS == pixel_threshold


def test_permissive_pillow_mode_fails_closed_without_changing_globals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "source.png"
    _write_image(path)
    monkeypatch.setattr(ImageFile, "LOAD_TRUNCATED_IMAGES", True)
    with path.open("rb") as source, pytest.raises(InputValidationError, match="Strict"):
        validate_image(source)
    assert ImageFile.LOAD_TRUNCATED_IMAGES is True


def test_short_reads_are_supported_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    with path.open("rb") as source:
        read_sizes = _probe_reads(monkeypatch, source.fileno(), read_limit=3)
        info = validate_image(source)
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert all(0 < size <= 64 * 1024 for size in read_sizes)


@pytest.mark.parametrize("operation", ["validate", "copy"])
def test_cached_read_buffer_cannot_replace_current_descriptor_bytes(
    tmp_path: Path, operation: str
) -> None:
    path = tmp_path / "source.png"
    _write_image(path)
    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        source.read(1)  # Prefetch the original file into BufferedReader's cache.
        current = _write_image(path, size=(9, 6))
        if operation == "validate":
            info = validate_image(source)
            assert (info.width, info.height) == (9, 6)
            assert info.sha256 == hashlib.sha256(current).hexdigest()
        else:
            copy_source(source, target)
            target.seek(0)
            assert target.read() == current
        assert source.tell() == 1


@pytest.mark.parametrize("operation", ["validate", "copy"])
@pytest.mark.parametrize("change", ["grow", "shrink", "rewrite"])
def test_source_changes_during_read_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, change: str
) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    before = path.stat()

    def mutate() -> None:
        if change == "grow":
            path.write_bytes(data + b"more")
        elif change == "shrink":
            path.write_bytes(data[:1])
        else:
            path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))

    with path.open("rb", buffering=0) as source, (tmp_path / "copy").open("w+b") as target:
        _probe_reads(monkeypatch, source.fileno(), after_read=mutate, read_limit=3)
        with pytest.raises(InputValidationError):
            if operation == "validate":
                validate_image(source)
            else:
                copy_source(source, target)


@pytest.mark.parametrize(
    "field", ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"]
)
@pytest.mark.parametrize("operation", ["validate", "copy"])
def test_every_required_stat_field_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, operation: str
) -> None:
    path = tmp_path / "source.png"
    _write_image(path)
    real_fstat = os.fstat
    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        source_fd = source.fileno()
        source_stats = 0

        def changed_stat(descriptor: int):
            nonlocal source_stats
            result = real_fstat(descriptor)
            if descriptor != source_fd:
                return result
            source_stats += 1
            if source_stats == 1:
                return result
            values = {
                name: getattr(result, name)
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"
                )
            }
            values[field] ^= stat.S_IXUSR if field == "st_mode" else 1
            return SimpleNamespace(**values)

        monkeypatch.setattr(images.os, "fstat", changed_stat)
        with pytest.raises(InputValidationError, match="changed"):
            if operation == "validate":
                validate_image(source)
            else:
                copy_source(source, target)


def test_source_changes_during_decode_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    before = path.stat()
    original_load = ImageFile.ImageFile.load

    def changing_load(self, *args, **kwargs):
        result = original_load(self, *args, **kwargs)
        path.write_bytes(data)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
        return result

    monkeypatch.setattr(ImageFile.ImageFile, "load", changing_load)
    with path.open("rb") as source, pytest.raises(InputValidationError, match="changed"):
        validate_image(source)


@pytest.mark.parametrize("operation", ["validate", "copy"])
def test_descriptor_replacement_during_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    replacement = tmp_path / "replacement.png"
    replacement.write_bytes(data)
    with path.open("rb", buffering=0) as source, (tmp_path / "copy").open("w+b") as target:
        def replace_descriptor() -> None:
            with replacement.open("rb") as other:
                os.dup2(other.fileno(), source.fileno())

        _probe_reads(monkeypatch, source.fileno(), after_read=replace_descriptor)
        with pytest.raises(InputValidationError, match="changed"):
            if operation == "validate":
                validate_image(source)
            else:
                copy_source(source, target)


def test_in_memory_and_closed_handles_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    with pytest.raises(InputValidationError):
        validate_image(io.BytesIO(data))
    with path.open("rb") as source:
        pass
    with pytest.raises(InputValidationError):
        validate_image(source)


def test_pipe_is_rejected_before_any_blocking_read() -> None:
    reader, writer = os.pipe()
    try:
        with os.fdopen(reader, "rb") as source, pytest.raises(InputValidationError):
            validate_image(source)
    finally:
        os.close(writer)


@pytest.mark.parametrize("operation", ["validate", "copy"])
def test_read_failure_is_a_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    path = tmp_path / "source.png"
    _write_image(path)

    def failed_read(*args):
        raise OSError("injected read failure")

    monkeypatch.setattr(images.os, "pread", failed_read)
    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        with pytest.raises(InputValidationError, match="read safely"):
            if operation == "validate":
                validate_image(source)
            else:
                copy_source(source, target)


@pytest.mark.parametrize(
    "relative",
    [
        "", "/absolute", "//host/share", "a//b", "a/", ".", "./a", "..", "../a",
        "a/../b", "a/./b", "https://host/a", "file:a", "data:image/png,a", "C:/a",
        "a\\b", "a\x00b",
    ],
)
def test_unapproved_relative_names_fail_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    def forbidden_open(*args, **kwargs):
        pytest.fail("Rejected path reached a filesystem open")

    monkeypatch.setattr(images.os, "open", forbidden_open)
    with pytest.raises(InputValidationError):
        with open_approved_source(tmp_path, relative):
            pytest.fail("Invalid relative name was accepted")


@pytest.mark.parametrize("opener", ["approved", "regular"])
def test_nested_file_opens_and_closes(tmp_path: Path, opener: str) -> None:
    # macOS pytest directories may be spelled through /var's symlink. Resolve
    # only the trusted temporary fixture, never the path under test.
    root = tmp_path.resolve()
    path = root / "nested" / "image.png"
    path.parent.mkdir()
    data = _write_image(path)
    context = (
        open_approved_source(root, "nested/image.png")
        if opener == "approved"
        else open_regular(path)
    )
    with context as source:
        assert source.tell() == 0
        assert source.read() == data
        descriptor = source.fileno()
    assert source.closed
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_relative_root_and_authoritative_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve()
    (root / "approved").mkdir()
    _write_image(root / "approved" / "source.png")
    monkeypatch.chdir(root)
    with open_approved_source(Path("approved"), "source.png") as source:
        assert validate_image(source).image_format == "PNG"
    with open_regular(Path("approved/source.png")) as source:
        assert validate_image(source).image_format == "PNG"
    with open_approved_source(Path("."), "approved/source.png") as source:
        assert validate_image(source).image_format == "PNG"


@pytest.mark.parametrize("opener", ["approved", "regular"])
@pytest.mark.parametrize("link_position", ["ancestor", "root", "directory", "leaf"])
def test_symlinks_at_every_path_position_are_rejected(
    tmp_path: Path, opener: str, link_position: str
) -> None:
    base = tmp_path.resolve()
    root = base / "real" / "approved"
    path = root / "nested" / "source.png"
    path.parent.mkdir(parents=True)
    _write_image(path)
    relative = "nested/source.png"
    if link_position == "ancestor":
        (base / "alias").symlink_to(base / "real", target_is_directory=True)
        root = base / "alias" / "approved"
    elif link_position == "root":
        (base / "alias").symlink_to(root, target_is_directory=True)
        root = base / "alias"
    elif link_position == "directory":
        (root / "alias").symlink_to(root / "nested", target_is_directory=True)
        relative = "alias/source.png"
    else:
        (root / "alias.png").symlink_to(path)
        relative = "alias.png"
    context = (
        open_approved_source(root, relative)
        if opener == "approved"
        else open_regular(root / relative)
    )
    with pytest.raises(InputValidationError):
        with context:
            pytest.fail("Symlink was followed")


@pytest.mark.parametrize("opener", ["approved", "regular"])
@pytest.mark.parametrize("kind", ["missing", "directory", "fifo", "dangling"])
def test_nonregular_or_missing_leaf_is_rejected(tmp_path: Path, opener: str, kind: str) -> None:
    root = tmp_path.resolve()
    path = root / "source"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "dangling":
        path.symlink_to(root / "absent")
    context = open_approved_source(root, "source") if opener == "approved" else open_regular(path)
    expected = (
        FileNotFoundError
        if opener == "regular" and kind == "missing"
        else InputValidationError
    )
    with pytest.raises(expected):
        with context:
            pytest.fail("Nonregular source was accepted")


def test_authoritative_missing_ancestor_preserves_file_not_found(tmp_path: Path) -> None:
    path = tmp_path.resolve() / "missing" / "source.png"
    with pytest.raises(FileNotFoundError):
        with open_regular(path):
            pytest.fail("Missing ancestor was accepted")
    with pytest.raises(InputValidationError):
        with open_approved_source(path.parent, path.name):
            pytest.fail("Missing approved root was accepted")


def test_authoritative_open_does_not_reclassify_consumer_errors(tmp_path: Path) -> None:
    path = tmp_path.resolve() / "source.png"
    _write_image(path)
    error = InputValidationError("consumer failure")
    with pytest.raises(InputValidationError) as caught:
        with open_regular(path):
            raise error from FileNotFoundError("consumer's unrelated file")
    assert caught.value is error


def test_root_parent_traversal_and_non_directory_roots_are_rejected(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "directory").mkdir()
    path = root / "source.png"
    _write_image(path)
    for invalid_root in (root / "directory" / "..", path, root / "missing"):
        with pytest.raises(InputValidationError):
            with open_approved_source(invalid_root, "source.png"):
                pytest.fail("Invalid root was accepted")
    for invalid_path in (
        root / "directory" / ".." / "source.png", Path("/"), Path("."), root / ".."
    ):
        with pytest.raises(InputValidationError):
            with open_regular(invalid_path):
                pytest.fail("Invalid authoritative path was accepted")


@pytest.mark.parametrize("swap_component", ["approved", "nested"])
def test_directory_swap_keeps_the_opened_directory_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_component: str
) -> None:
    root = tmp_path.resolve() / "approved"
    nested = root / "nested"
    nested.mkdir(parents=True)
    original = _write_image(nested / "source.png")
    outside = tmp_path.resolve() / "outside"
    (outside / "nested").mkdir(parents=True)
    (outside / "source.png").write_bytes(b"outside")
    (outside / "nested" / "source.png").write_bytes(b"outside")
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, *, dir_fd=None):
        nonlocal swapped
        descriptor = real_open(path, flags, dir_fd=dir_fd)
        if not swapped and path == swap_component and flags & os.O_DIRECTORY:
            swapped = True
            current = root if swap_component == "approved" else nested
            current.rename(current.with_name(current.name + "-original"))
            current.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(images.os, "open", swapping_open)
    with open_approved_source(root, "nested/source.png") as source:
        assert source.read() == original
    assert swapped


@pytest.mark.parametrize("failure", ["leaf", "consumer"])
def test_all_open_descriptors_close_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root = tmp_path.resolve()
    (root / "nested").mkdir()
    path = root / "nested" / "source.png"
    _write_image(path)
    if failure == "leaf":
        path.unlink()
        path.symlink_to(root / "missing")
    opened: list[int] = []
    real_open = os.open

    def tracking_open(path, flags, *, dir_fd=None):
        descriptor = real_open(path, flags, dir_fd=dir_fd)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(images.os, "open", tracking_open)
    expected = InputValidationError if failure == "leaf" else RuntimeError
    with pytest.raises(expected):
        with open_approved_source(root, "nested/source.png"):
            raise RuntimeError("consumer failed")
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_copy_reads_from_zero_and_removes_preallocated_suffix(tmp_path: Path) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    destination = tmp_path / "destination"
    destination.write_bytes(b"stale" * 100)
    with path.open("rb") as source, destination.open("r+b") as target:
        source.seek(13)
        target.seek(27)
        assert copy_source(source, target) is None
        assert not source.closed and not target.closed
        assert source.tell() == 13
        assert target.tell() == len(data)
    assert destination.read_bytes() == data


def test_copy_of_empty_file_removes_preallocated_bytes(tmp_path: Path) -> None:
    """Copying bytes is independent from image validation, which rejects empty files."""
    path = tmp_path / "empty"
    path.touch()
    destination = tmp_path / "destination"
    destination.write_bytes(b"preallocated bytes")
    with path.open("rb") as source, destination.open("r+b") as target:
        copy_source(source, target)
    assert destination.read_bytes() == b""


def test_copy_handles_short_reads_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "source"
    data = bytes(range(256)) * 600
    path.write_bytes(data)
    destination = tmp_path / "destination"

    class ShortWriter(_FileProbe):
        def write(self, content) -> int:
            return self.file.write(content[:7])

    with path.open("rb") as source, destination.open("w+b") as target:
        read_sizes = _probe_reads(monkeypatch, source.fileno(), read_limit=113)
        copy_source(source, ShortWriter(target))
        assert all(0 < size <= 64 * 1024 for size in read_sizes)
    assert destination.read_bytes() == data


@pytest.mark.parametrize("hardlink", [False, True])
def test_copy_onto_same_inode_is_rejected_before_writing(tmp_path: Path, hardlink: bool) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    destination = tmp_path / "hardlink" if hardlink else path
    if hardlink:
        os.link(path, destination)
    with path.open("rb") as source, destination.open("r+b") as target:
        with pytest.raises(InputValidationError, match="different files"):
            copy_source(source, target)
    assert path.read_bytes() == data


def test_copy_append_destination_is_rejected_before_writing(tmp_path: Path) -> None:
    path = tmp_path / "source.png"
    _write_image(path)
    destination = tmp_path / "destination"
    destination.write_bytes(b"original")
    with path.open("rb") as source, destination.open("ab") as target:
        with pytest.raises(InputValidationError, match="append"):
            copy_source(source, target)
    assert destination.read_bytes() == b"original"


@pytest.mark.parametrize("written", [None, 0, -1, 100_000])
def test_copy_rejects_writes_that_make_no_valid_progress(
    tmp_path: Path, written: int | None
) -> None:
    path = tmp_path / "source.png"
    _write_image(path)

    class BadWriter(_FileProbe):
        def write(self, content):
            return written

    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        with pytest.raises(OSError, match="progress"):
            copy_source(source, BadWriter(target))


def test_copy_preserves_destination_io_errors(tmp_path: Path) -> None:
    path = tmp_path / "source.png"
    _write_image(path)

    class FailedWriter(_FileProbe):
        def write(self, content):
            raise OSError("injected destination failure")

    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        with pytest.raises(OSError, match="injected destination failure"):
            copy_source(source, FailedWriter(target))


def test_copy_checks_source_again_after_destination_flush(tmp_path: Path) -> None:
    path = tmp_path / "source.png"
    data = _write_image(path)
    before = path.stat()

    class ChangingFlush(_FileProbe):
        def flush(self) -> None:
            self.file.flush()
            path.write_bytes(data)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))

    with path.open("rb") as source, (tmp_path / "copy").open("w+b") as target:
        with pytest.raises(InputValidationError, match="changed"):
            copy_source(source, ChangingFlush(target))
