"""Bounded observation, replay validation, and provenance tests."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from media_generation.inventory.probes import (
    MAX_REPLAY_BYTES,
    LocalObservationSource,
    ProbeLedger,
    ProbeSpec,
    ReplayObservationSource,
    sanitize_text,
)
from media_generation.inventory.schema import (
    InventoryValidationError,
    Observation,
    ProbeStatus,
)


def test_text_read_is_bounded_and_reports_truncation(tmp_path: Path) -> None:
    """File reads never return more than the requested prefix."""
    path = tmp_path / "data.txt"
    path.write_text("abcdefghij", encoding="utf-8")
    source = LocalObservationSource()
    observation = source.read_text(path, limit=4)

    assert observation.status == "ok"
    assert observation.text == "abcd"
    assert observation.truncated is True


def test_missing_file_and_permission_failures_are_explicit(tmp_path: Path) -> None:
    """Absence and access failure map to distinct reason codes."""
    source = LocalObservationSource()
    missing = source.read_text(tmp_path / "missing.txt")
    assert missing.status == "unavailable"
    assert missing.reason == "file_not_found"

    directory = tmp_path / "directory"
    directory.mkdir()
    assert source.read_text(directory).reason == "os_error"


def test_stat_does_not_follow_symlinks(tmp_path: Path) -> None:
    """lstat metadata names the link rather than resolving its target."""
    target = tmp_path / "target.txt"
    target.write_text("data", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    observation = LocalObservationSource().stat(link)
    payload = json.loads(observation.text)

    assert payload["kind"] == "symlink"
    assert payload["symlink"] is True
    assert payload["link_target"] == str(target)
    assert payload["executable"] is False


def test_directory_listing_is_sorted_within_a_bounded_scan_window(
    tmp_path: Path,
) -> None:
    """Only the retained scan window is sorted; truncation is explicit."""
    for name in ("d.txt", "b.txt", "a.txt", "c.txt"):
        (tmp_path / name).write_text("x", encoding="utf-8")

    observation = LocalObservationSource().list_dir(tmp_path, limit=2)
    entries = json.loads(observation.text)

    names = [entry["name"] for entry in entries]
    assert len(names) == 2
    assert names == sorted(names)
    assert set(names) <= {"a.txt", "b.txt", "c.txt", "d.txt"}
    assert observation.truncated is True


def test_directory_listing_stops_enumerating_after_the_scan_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enumeration advances at most limit + 1 entries, never the whole directory."""
    import types

    from media_generation.inventory import probes

    class FakeEntry:
        def __init__(self, name: str) -> None:
            self.name = name

        def stat(self, *, follow_symlinks: bool) -> object:
            return types.SimpleNamespace(st_size=1)

        def is_symlink(self) -> bool:
            return False

        def is_dir(self, *, follow_symlinks: bool) -> bool:
            return False

        def is_file(self, *, follow_symlinks: bool) -> bool:
            return True

    class FakeDirectory:
        advances = 0

        def __enter__(self) -> "FakeDirectory":
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def __iter__(self) -> object:
            for index in range(1000):
                FakeDirectory.advances += 1
                if FakeDirectory.advances > 3:
                    raise AssertionError("enumeration continued past the limit")
                yield FakeEntry(f"{index}.txt")

    directory = tmp_path / "directory"
    directory.mkdir()
    monkeypatch.setattr(probes.os, "scandir", lambda path: FakeDirectory())

    observation = LocalObservationSource().list_dir(directory, limit=2)

    assert observation.truncated is True
    assert FakeDirectory.advances == 3
    assert [entry["name"] for entry in json.loads(observation.text)] == [
        "0.txt",
        "1.txt",
    ]


def test_run_uses_argv_without_a_shell() -> None:
    """A shell-looking single argument is treated as an executable name."""
    source = LocalObservationSource()
    observation = source.run(
        [sys.executable, "-c", "print('hello')"],
        timeout_seconds=5,
        output_limit=1024,
    )
    assert observation.status == "ok"
    assert observation.text.strip() == "hello"

    missing = source.run(
        ["echo hello"], timeout_seconds=5, output_limit=1024
    )
    assert missing.status == "unavailable"
    assert missing.reason == "binary_not_found"


def test_nonzero_exit_timeout_and_output_cap_are_distinct() -> None:
    """Process failures carry separate statuses and bounded output."""
    source = LocalObservationSource()
    nonzero = source.run(
        [sys.executable, "-c", "import sys; print('bad'); sys.exit(3)"],
        timeout_seconds=5,
        output_limit=1024,
    )
    assert nonzero.status == "error"
    assert nonzero.reason == "nonzero_exit"
    assert nonzero.exit_code == 3

    timeout = source.run(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_seconds=0.2,
        output_limit=1024,
    )
    assert timeout.status == "timeout"
    assert timeout.reason == "timeout"

    capped = source.run(
        [sys.executable, "-c", "print('x' * 10000)"],
        timeout_seconds=5,
        output_limit=64,
    )
    assert capped.truncated is True
    assert len(capped.text) <= 64


def test_sha256_streams_and_respects_the_limit(tmp_path: Path) -> None:
    """Digest computation reports an explicit skip rather than reading too much."""
    path = tmp_path / "model.bin"
    data = b"abc" * 100
    path.write_bytes(data)
    source = LocalObservationSource()
    observation, digest = source.sha256(path, limit=1024)

    assert observation.status == "ok"
    assert digest == "sha256:" + hashlib.sha256(data).hexdigest()

    skipped, no_digest = source.sha256(path, limit=10)
    assert skipped.status == "skipped"
    assert skipped.reason == "hash_limit_exceeded"
    assert no_digest is None


def test_replay_requires_synthetic_declaration_and_reports_missing_keys(
    tmp_path: Path,
) -> None:
    """Replay fixtures cannot masquerade as live evidence."""
    valid = tmp_path / "replay.json"
    valid.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-replay",
                "schema_version": 1,
                "synthetic": True,
                "observations": {"read:/synthetic": {"status": "ok", "text": "value"}},
            }
        ),
        encoding="utf-8",
    )
    source = ReplayObservationSource.from_path(valid)
    assert source.read_text(Path("/synthetic"), limit=10).text == "value"
    missing = source.read_text(Path("/missing"), limit=10)
    assert missing.status == "unavailable"
    assert missing.reason == "not_recorded"

    invalid = tmp_path / "invalid.json"
    invalid.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-replay",
                "schema_version": 1,
                "synthetic": False,
                "observations": {},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(InventoryValidationError, match="synthetic: true"):
        ReplayObservationSource.from_path(invalid)


def test_ledger_records_one_entry_per_attempt_and_omits_excerpt_from_json(
    tmp_path: Path,
) -> None:
    """Provenance is retained for every read while transcript text stays human-only."""
    path = tmp_path / "value.txt"
    path.write_text("value", encoding="utf-8")
    ledger = ProbeLedger(LocalObservationSource())
    ledger.read(ProbeSpec("test:read", "test"), path)
    ledger.record_observation(
        ProbeSpec("test:static", "test", "required"),
        source="synthetic",
        observation=(observation := LocalObservationSource().read_text(path)),
    )

    assert [record.probe_id for record in ledger.records] == ["test:read", "test:static"]
    payload = ledger.records[0].to_dict()
    assert "excerpt" not in payload
    assert ledger.records[0].excerpt == "value"
    assert ledger.records[1].status == ProbeStatus.OK.value
    assert observation.text == "value"


def test_sanitize_text_removes_home_and_caps_excerpt() -> None:
    """Transcript excerpts avoid the operator's home prefix and grow no further."""
    home = Path("/synthetic/home")
    text = sanitize_text(f"{home}/models/x.gguf and more", home=home, limit=10)
    assert text.startswith("~/models/x")
    assert text.endswith("[truncated]")


def test_probe_detail_is_sanitized_and_bounded_in_json() -> None:
    """Structured probe detail omits the home prefix and stays transcript-sized."""
    ledger = ProbeLedger(LocalObservationSource())
    ledger.record_observation(
        ProbeSpec("test:detail", "test"),
        source="synthetic",
        observation=Observation(
            status=ProbeStatus.ERROR.value,
            detail=f"{Path.home()}/private/model.gguf\n" + ("x" * 1200),
        ),
    )
    detail = ledger.records[0].to_dict()["detail"]

    assert isinstance(detail, str)
    assert str(Path.home()) not in detail
    assert detail.startswith("~/private/model.gguf")
    assert len(detail) <= 1020


def test_replay_rejects_oversized_document_before_full_read(tmp_path: Path) -> None:
    """A replay larger than the documented cap fails with a structured error."""
    path = tmp_path / "replay.json"
    path.write_bytes(b"{" + b" " * (MAX_REPLAY_BYTES + 16))

    with pytest.raises(InventoryValidationError, match="too large"):
        ReplayObservationSource.from_path(path)


def test_replay_rejects_invalid_utf8(tmp_path: Path) -> None:
    """Malformed encoding is reported as a validation error, not a crash."""
    path = tmp_path / "replay.json"
    path.write_bytes(
        b'{"schema":"media-generation.inventory-replay","schema_version":1,'
        b'"synthetic":true,"observations":{},"bad":"'
        + bytes([0xFF])
        + b'"}'
    )

    with pytest.raises(InventoryValidationError, match="not valid UTF-8"):
        ReplayObservationSource.from_path(path)


def test_replay_missing_file_is_a_validation_error(tmp_path: Path) -> None:
    """An inaccessible replay path preserves the structured error contract."""
    with pytest.raises(InventoryValidationError, match="not readable"):
        ReplayObservationSource.from_path(tmp_path / "missing.json")

def test_sha256_detects_growth_beyond_the_limit_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that grows after opening produces no partial digest."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"a" * 8)
    original = LocalObservationSource._open_read.__func__

    class GrowingHandle:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def fileno(self) -> int:
            return self._handle.fileno()

        def read(self, size: int = -1) -> bytes:
            return self._handle.read(size) + b"grown" * 64

        def __enter__(self) -> "GrowingHandle":
            return self

        def __exit__(self, *exc: object) -> None:
            self._handle.close()

    def growing_open(
        cls: type[LocalObservationSource],
        target: Path,
        *,
        follow_final_symlink: bool,
        root: Path | None = None,
    ) -> GrowingHandle:
        handle = original(
            cls,
            target,
            follow_final_symlink=follow_final_symlink,
            root=root,
        )
        return GrowingHandle(handle)

    monkeypatch.setattr(
        LocalObservationSource, "_open_read", classmethod(growing_open)
    )

    observation, digest = LocalObservationSource().sha256(path, limit=16)

    assert observation.status == "skipped"
    assert observation.reason == "hash_limit_exceeded"
    assert "grew beyond limit" in (observation.detail or "")
    assert digest is None


def test_sha256_detects_replacement_before_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path swapped before opening produces no digest for either file."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"original")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"replacement")
    original = LocalObservationSource._open_read.__func__

    def replacing_open(
        cls: type[LocalObservationSource],
        target: Path,
        *,
        follow_final_symlink: bool,
        root: Path | None = None,
    ) -> object:
        replacement.replace(target)
        return original(
            cls,
            target,
            follow_final_symlink=follow_final_symlink,
            root=root,
        )

    monkeypatch.setattr(
        LocalObservationSource, "_open_read", classmethod(replacing_open)
    )

    observation, digest = LocalObservationSource().sha256(path, limit=1024)

    assert observation.status == "skipped"
    assert observation.reason == "file_replaced_during_hash"
    assert observation.detail == "file identity changed before hashing"
    assert digest is None


def test_sha256_detects_replacement_during_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A swap after the first chunk discards the streamed digest."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"original")
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"original")
    original = LocalObservationSource._open_read.__func__

    class ReplacingHandle:
        def __init__(self, handle: Any, target: Path, swap: Path) -> None:
            self._handle = handle
            self._target = target
            self._swap = swap
            self._replaced = False

        def fileno(self) -> int:
            return self._handle.fileno()

        def read(self, size: int = -1) -> bytes:
            data = self._handle.read(size)
            if data and not self._replaced:
                self._swap.replace(self._target)
                self._replaced = True
            return data

        def __enter__(self) -> "ReplacingHandle":
            return self

        def __exit__(self, *exc: object) -> None:
            self._handle.close()

    def replacing_open(
        cls: type[LocalObservationSource],
        target: Path,
        *,
        follow_final_symlink: bool,
        root: Path | None = None,
    ) -> ReplacingHandle:
        handle = original(
            cls,
            target,
            follow_final_symlink=follow_final_symlink,
            root=root,
        )
        return ReplacingHandle(handle, target, replacement)

    monkeypatch.setattr(
        LocalObservationSource, "_open_read", classmethod(replacing_open)
    )

    observation, digest = LocalObservationSource().sha256(path, limit=1024)

    assert observation.status == "skipped"
    assert observation.reason == "file_replaced_during_hash"
    assert observation.detail == "file identity changed during hashing"
    assert digest is None


def test_intermediate_directory_replacement_is_not_followed(
    tmp_path: Path,
) -> None:
    """A directory swapped for a link after validation cannot redirect reads."""
    root = tmp_path / "models"
    nested = root / "nested"
    nested.mkdir(parents=True)
    target = nested / "blob.bin"
    target.write_bytes(b"inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "blob.bin").write_bytes(b"outside-secret")

    nested.rename(root / "validated")
    nested.symlink_to(outside, target_is_directory=True)

    ledger = ProbeLedger(LocalObservationSource())
    observation = ledger.read(
        ProbeSpec(probe_id="model:test", category="models"),
        target,
        root=root,
    )

    assert observation.status == "skipped"
    assert observation.reason in {
        "symlink_not_followed",
        "containment_path_changed",
    }
    assert not observation.text


def test_containment_fallback_rejects_nested_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without descriptor-relative opens, nested paths fail closed."""
    root = tmp_path / "models"
    nested = root / "nested"
    nested.mkdir(parents=True)
    target = nested / "blob.bin"
    target.write_bytes(b"inside")
    monkeypatch.setattr(os, "supports_dir_fd", set())

    ledger = ProbeLedger(LocalObservationSource())
    observation = ledger.read(
        ProbeSpec(probe_id="model:test", category="models"),
        target,
        root=root,
    )

    assert observation.status == "skipped"
    assert observation.reason == "descriptor_containment_unavailable"
    assert not observation.text


@pytest.mark.skipif(
    not getattr(os, "O_NOFOLLOW", 0), reason="O_NOFOLLOW is unavailable"
)
def test_containment_fallback_allows_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A direct child of a trusted root remains readable in the fallback."""
    root = tmp_path / "models"
    root.mkdir()
    target = root / "blob.bin"
    target.write_bytes(b"inside")
    monkeypatch.setattr(os, "supports_dir_fd", set())

    ledger = ProbeLedger(LocalObservationSource())
    observation = ledger.read(
        ProbeSpec(probe_id="model:test", category="models"),
        target,
        root=root,
    )

    assert observation.status == "ok"
    assert observation.text == "inside"


def test_directory_listing_uses_root_containment(tmp_path: Path) -> None:
    """A declared root allows bounded listing of a nested directory."""
    root = tmp_path / "models"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "b.bin").write_bytes(b"bb")
    (nested / "a.bin").write_bytes(b"a")

    observation = LocalObservationSource().list_dir(nested, limit=8, root=root)

    assert observation.status == "ok"
    assert observation.truncated is False
    payload = json.loads(observation.text or "[]")
    assert [item["name"] for item in payload] == ["a.bin", "b.bin"]

    root_listing = LocalObservationSource().list_dir(root, limit=8, root=root)
    assert root_listing.status == "ok"
    root_payload = json.loads(root_listing.text or "[]")
    assert [item["name"] for item in root_payload] == ["nested"]


def test_directory_listing_refuses_intermediate_replacement(
    tmp_path: Path,
) -> None:
    """A directory swapped for a link before listing cannot be enumerated."""
    root = tmp_path / "models"
    nested = root / "outer" / "nested"
    nested.mkdir(parents=True)
    (nested / "inside.bin").write_bytes(b"inside")
    outside = tmp_path / "outside"
    (outside / "nested").mkdir(parents=True)
    (outside / "nested" / "secret.bin").write_bytes(b"secret")
    source = LocalObservationSource()

    assert source.list_dir(nested, limit=8, root=root).status == "ok"
    (root / "outer").rename(root / "validated")
    (root / "outer").symlink_to(outside, target_is_directory=True)

    observation = source.list_dir(nested, limit=8, root=root)

    assert observation.status == "skipped"
    assert observation.reason in {
        "symlink_not_followed",
        "containment_path_changed",
    }
    assert not observation.text


def test_directory_listing_refuses_final_symlink(tmp_path: Path) -> None:
    """A linked directory cannot be listed through a declared root."""
    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"secret")
    linked = root / "linked"
    linked.symlink_to(outside, target_is_directory=True)

    observation = LocalObservationSource().list_dir(linked, limit=8, root=root)

    assert observation.status == "skipped"
    assert observation.reason in {
        "symlink_not_followed",
        "containment_path_changed",
    }
    assert not observation.text
