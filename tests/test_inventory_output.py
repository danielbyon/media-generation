"""Safe atomic inventory output tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from inventory_support import linux_host_observations, write_replay
from media_generation.inventory.report import (
    InventoryOptions,
    InventoryOutputError,
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
