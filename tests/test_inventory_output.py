"""Safe atomic inventory output tests."""

from __future__ import annotations

import json
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
