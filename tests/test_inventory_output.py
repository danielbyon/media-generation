"""Safe atomic inventory output tests."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from inventory_support import linux_host_observations, write_replay
from media_generation.inventory import report
from media_generation.inventory.report import (
    InventoryOptions,
    InventoryOutputError,
    _cap_transcript,
    collect_inventory,
    write_inventory,
)


def _result(tmp_path: Path):
    replay = write_replay(tmp_path / "replay.json", linux_host_observations())
    return collect_inventory(
        InventoryOptions(output_directory=tmp_path / "out", replay_path=replay)
    )


def test_output_replaces_preexisting_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    """A stale output link cannot redirect the write outside the directory."""
    outside = tmp_path / "outside.txt"
    outside.write_text("outside remains", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    (output / "inventory.json").symlink_to(outside)
    (output / "transcript.txt").symlink_to(outside)

    write_inventory(_result(tmp_path), output)

    assert outside.read_text(encoding="utf-8") == "outside remains"
    assert not (output / "inventory.json").is_symlink()
    assert not (output / "transcript.txt").is_symlink()
    payload = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "media-generation.inventory"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_symlink_substitution_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A regular output swapped for a link between checks is not followed."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    inventory.write_bytes(b"previous inventory")
    transcript.write_bytes(b"previous transcript")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside remains", encoding="utf-8")
    real_open = report.os.open
    swapped = False

    def swap_destination(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal swapped
        if (
            not swapped
            and isinstance(path, (str, bytes, os.PathLike))
            and os.fspath(path) == os.fspath(inventory)
            and flags & getattr(report.os, "O_NOFOLLOW", 0)
        ):
            swapped = True
            inventory.unlink()
            inventory.symlink_to(outside)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(report.os, "open", swap_destination)
    with pytest.raises(InventoryOutputError, match="snapshot existing output"):
        write_inventory(_result(tmp_path), output)

    assert swapped is True
    assert inventory.is_symlink()
    assert Path(os.readlink(inventory)) == outside
    assert transcript.read_bytes() == b"previous transcript"
    assert outside.read_text(encoding="utf-8") == "outside remains"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_file_growth_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination that grows past the snapshot cap is not published."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    inventory.write_bytes(b"12345678")
    transcript.write_bytes(b"previous transcript")
    monkeypatch.setattr(report, "MAX_PUBLICATION_SNAPSHOT_BYTES", 8)
    real_fstat = report.os.fstat
    grown = False

    def grow_after_open(descriptor: int) -> os.stat_result:
        nonlocal grown
        facts = real_fstat(descriptor)
        if not grown and stat.S_ISREG(facts.st_mode) and facts.st_size == 8:
            grown = True
            with inventory.open("ab") as handle:
                handle.write(b"9")
        return facts

    monkeypatch.setattr(report.os, "fstat", grow_after_open)
    with pytest.raises(InventoryOutputError, match="grew beyond snapshot limit"):
        write_inventory(_result(tmp_path), output)

    assert grown is True
    assert transcript.read_bytes() == b"previous transcript"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_path_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination replaced while its opened snapshot is read is rejected."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    previous = b"previous inventory"
    inventory.write_bytes(previous)
    transcript.write_bytes(b"previous transcript")
    real_fstat = report.os.fstat
    calls = {"count": 0}

    def replace_after_read(descriptor: int) -> os.stat_result:
        facts = real_fstat(descriptor)
        if stat.S_ISREG(facts.st_mode) and facts.st_size == len(previous):
            calls["count"] += 1
            if calls["count"] == 2:
                replacement = output / "replacement.json"
                replacement.write_bytes(previous)
                os.replace(replacement, inventory)
        return facts

    monkeypatch.setattr(report.os, "fstat", replace_after_read)
    with pytest.raises(InventoryOutputError, match="changed while snapshotting"):
        write_inventory(_result(tmp_path), output)

    assert calls["count"] == 2
    assert transcript.read_bytes() == b"previous transcript"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_nonregular_existing_destination(
    tmp_path: Path,
) -> None:
    """An existing FIFO is rejected without opening or replacing the pair."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    os.mkfifo(inventory)
    transcript.write_bytes(b"previous transcript")

    with pytest.raises(InventoryOutputError, match="not a regular file"):
        write_inventory(_result(tmp_path), output)

    assert stat.S_ISFIFO(inventory.lstat().st_mode)
    assert transcript.read_bytes() == b"previous transcript"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_oversized_existing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An oversized destination aborts before either output is replaced."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    inventory.write_bytes(b"12345")
    transcript.write_bytes(b"previous transcript")
    monkeypatch.setattr(report, "MAX_PUBLICATION_SNAPSHOT_BYTES", 4)

    with pytest.raises(InventoryOutputError, match="exceeds snapshot limit"):
        write_inventory(_result(tmp_path), output)

    assert inventory.read_bytes() == b"12345"
    assert transcript.read_bytes() == b"previous transcript"
    assert not list(output.glob(".*.tmp"))


def test_output_snapshot_rejects_unreadable_existing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable destination aborts before either output is replaced."""
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    inventory.write_bytes(b"previous inventory")
    transcript.write_bytes(b"previous transcript")
    real_open = report.os.open

    def deny_snapshot(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if (
            isinstance(path, (str, bytes, os.PathLike))
            and os.fspath(path) == os.fspath(inventory)
            and flags & getattr(report.os, "O_NOFOLLOW", 0)
        ):
            raise PermissionError("synthetic snapshot denial")
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type,return-value]

    monkeypatch.setattr(report.os, "open", deny_snapshot)
    with pytest.raises(InventoryOutputError, match="synthetic snapshot denial"):
        write_inventory(_result(tmp_path), output)

    assert inventory.read_bytes() == b"previous inventory"
    assert transcript.read_bytes() == b"previous transcript"
    assert not list(output.glob(".*.tmp"))


def test_output_cleans_temporary_file_when_replacement_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed atomic replace removes the exclusive temporary file."""
    output = tmp_path / "out"
    output.mkdir()
    result = _result(tmp_path)

    def fail_replace(source: object, destination: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr("media_generation.inventory.report.os.replace", fail_replace)
    with pytest.raises(InventoryOutputError, match="synthetic replace failure"):
        write_inventory(result, output)

    assert not list(output.glob(".*.tmp"))
    assert not (output / "inventory.json").exists()


def test_publication_marks_the_report_only_after_both_files_exist(
    tmp_path: Path,
) -> None:
    """Collection reports an unpublished result; publication updates it."""
    result = _result(tmp_path)

    assert result.summary["evidence_gate"]["report_written"] is False
    assert "report_written: false" in result.transcript

    output = tmp_path / "out"
    published = write_inventory(result, output)

    assert published.summary["evidence_gate"]["report_written"] is True
    assert "report_written: true" in published.transcript
    assert "report_written: false" not in published.transcript
    published_transcript = (output / "transcript.txt").read_text(encoding="utf-8")
    assert "report_written: true" in published_transcript
    assert "report_written: false" not in published_transcript
    payload = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert payload["evidence_gate"]["report_written"] is True


def test_failed_second_replacement_restores_the_previous_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed inventory replacement rolls the transcript back with it."""
    output = tmp_path / "out"
    write_inventory(_result(tmp_path), output)
    names = ("inventory.json", "transcript.txt")
    before = {name: (output / name).read_bytes() for name in names}

    real_replace = report.os.replace
    calls = {"count": 0}

    def fail_second(source: object, destination: object) -> None:
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("synthetic second replacement failure")
        real_replace(source, destination)

    monkeypatch.setattr(report.os, "replace", fail_second)
    with pytest.raises(InventoryOutputError, match="synthetic second replacement failure"):
        write_inventory(_result(tmp_path), output)

    assert {name: (output / name).read_bytes() for name in names} == before
    assert not list(output.glob(".*.tmp"))


def test_failed_second_replacement_restores_previous_symlink_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rollback restores symlink entries without touching their targets."""
    outside = tmp_path / "outside.txt"
    outside.write_text("outside remains", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    inventory = output / "inventory.json"
    transcript = output / "transcript.txt"
    inventory.symlink_to(outside)
    transcript.symlink_to(outside)
    real_replace = report.os.replace
    calls = {"count": 0}

    def fail_second(source: object, destination: object) -> None:
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("synthetic second replacement failure")
        real_replace(source, destination)

    monkeypatch.setattr(report.os, "replace", fail_second)
    with pytest.raises(InventoryOutputError, match="synthetic second replacement failure"):
        write_inventory(_result(tmp_path), output)

    assert inventory.is_symlink()
    assert transcript.is_symlink()
    assert Path(os.readlink(inventory)) == outside
    assert Path(os.readlink(transcript)) == outside
    assert outside.read_text(encoding="utf-8") == "outside remains"
    assert not list(output.glob(".*.tmp"))


def test_staging_failure_preserves_previous_pair_and_cleans_temporaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An interrupted staged write leaves the published pair untouched."""
    output = tmp_path / "out"
    write_inventory(_result(tmp_path), output)
    names = ("inventory.json", "transcript.txt")
    before = {name: (output / name).read_bytes() for name in names}

    def fail_fsync(descriptor: int) -> None:
        raise OSError("synthetic interrupted write")

    monkeypatch.setattr(report.os, "fsync", fail_fsync)
    with pytest.raises(InventoryOutputError, match="synthetic interrupted write"):
        write_inventory(_result(tmp_path), output)

    assert {name: (output / name).read_bytes() for name in names} == before
    assert not list(output.glob(".*.tmp"))


def test_transcript_cap_counts_utf8_bytes_and_includes_marker() -> None:
    """The truncation marker cannot push the transcript past its byte cap."""
    capped = _cap_transcript("é" * 200, limit=40)

    assert len(capped.encode("utf-8")) <= 40
    assert capped.endswith("[transcript truncated]\n")
