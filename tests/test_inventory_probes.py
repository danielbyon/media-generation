"""Bounded observation, replay validation, and provenance tests."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from media_generation.inventory.catalog import RUNTIME_CATALOG
from media_generation.inventory.discovery import _candidate, _python_distribution
from media_generation.inventory.probes import (
    DEFAULT_OUTPUT_LIMIT,
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

    def deny_open(*args: object, **kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    source._open_read = deny_open  # type: ignore[method-assign]
    denied = source.read_text(tmp_path / "denied.txt")
    assert denied.status == "unavailable"
    assert denied.reason == "permission_denied"


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


def test_run_rejects_negative_output_limit_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A negative byte cap is invalid and cannot start a child process."""

    def unexpected_popen(*args: object, **kwargs: object) -> object:
        raise AssertionError("Popen must not be called for an invalid limit")

    monkeypatch.setattr(
        "media_generation.inventory.probes.subprocess.Popen",
        unexpected_popen,
    )

    observation = LocalObservationSource().run(
        ["unused"], timeout_seconds=5, output_limit=-1
    )

    assert observation.status == "error"
    assert observation.reason == "invalid_output_limit"


def test_run_accepts_zero_output_limit() -> None:
    """A zero byte cap remains valid and retains no child output."""
    observation = LocalObservationSource().run(
        [sys.executable, "-c", "pass"],
        timeout_seconds=5,
        output_limit=0,
    )

    assert observation.status == "ok"
    assert observation.text == ""


@pytest.mark.parametrize("stream_order", [("stdout", "stderr"), ("stderr", "stdout")])
def test_run_shares_output_limit_across_stdout_and_stderr(
    stream_order: tuple[str, str],
) -> None:
    """Either output ordering draws from one aggregate retained-byte budget."""
    source = LocalObservationSource()
    first, second = stream_order
    observation = source.run(
        [
            sys.executable,
            "-c",
            (
                "import sys, time; "
                f"sys.{first}.write('o' * 64); sys.{first}.flush(); "
                "time.sleep(0.05); "
                f"sys.{second}.write('e' * 64); sys.{second}.flush()"
            ),
        ],
        timeout_seconds=5,
        output_limit=96,
    )

    retained = len(observation.text.encode("utf-8"))
    retained += len((observation.detail or "").encode("utf-8"))
    assert observation.truncated is True
    assert retained == 96


def test_run_finalizes_pipe_readers_when_descendant_retains_them(
    tmp_path: Path,
) -> None:
    """A descendant holding inherited pipes cannot hide the child's final output."""
    source = LocalObservationSource()
    descendant_pid_path = tmp_path / "descendant.pid"
    script = (
        "import subprocess, sys; "
        "descendant = subprocess.Popen("
        "[sys.executable, '-c', 'import time; time.sleep(10)'], "
        "stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stderr); "
        f"open({str(descendant_pid_path)!r}, 'w').write(str(descendant.pid)); "
        "sys.stdout.write('parent-out\\n'); sys.stdout.flush(); "
        "sys.stderr.write('parent-err\\n'); sys.stderr.flush()"
    )

    try:
        observation = source.run(
            [sys.executable, "-c", script],
            timeout_seconds=5,
            output_limit=1024,
        )
    finally:
        if descendant_pid_path.exists():
            try:
                os.kill(int(descendant_pid_path.read_text(encoding="utf-8")), 9)
            except ProcessLookupError:
                pass

    assert observation.status == "ok"
    assert observation.text == "parent-out\n"
    assert observation.detail == "parent-err"
    assert observation.truncated is False


def test_run_does_not_truncate_stdout_when_it_exactly_fills_limit() -> None:
    """A single stream at the byte limit is complete rather than truncated."""
    source = LocalObservationSource()
    observation = source.run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 64)"],
        timeout_seconds=5,
        output_limit=64,
    )

    assert observation.status == "ok"
    assert observation.truncated is False
    assert observation.text == "x" * 64
    assert observation.detail is None


def test_default_inventory_output_limit_is_32_kib() -> None:
    """Host inventory probes use the documented 32 KiB default output budget."""
    assert DEFAULT_OUTPUT_LIMIT == 32 * 1024


def test_run_reports_pipe_waiter_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed pipe waiter becomes an explicit collection error."""
    from media_generation.inventory import probes

    class BrokenSelector:
        def register(self, descriptor: int, events: int) -> None:
            pass

        def select(self, timeout: float | None = None) -> list[tuple[object, int]]:
            raise OSError(24, "Too many open files")

        def close(self) -> None:
            pass

    monkeypatch.setattr(probes, "_IS_WINDOWS", False)
    monkeypatch.setattr(probes.selectors, "DefaultSelector", BrokenSelector)

    observation = LocalObservationSource().run(
        [sys.executable, "-c", "print('unobservable')"],
        timeout_seconds=5,
        output_limit=1024,
    )

    assert observation.status == "error"
    assert observation.reason == "output_capture_failed"
    assert "Too many open files" in (observation.detail or "")


def test_run_uses_windows_pipe_availability_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows reads occur only after PeekNamedPipe reports buffered bytes."""
    from media_generation.inventory import probes

    real_read = probes.os.read
    reads: list[int] = []

    def available(descriptor: int) -> int:
        return 1

    def read(descriptor: int, count: int) -> bytes:
        reads.append(descriptor)
        return real_read(descriptor, count)

    monkeypatch.setattr(probes, "_IS_WINDOWS", True)
    monkeypatch.setattr(probes, "_windows_pipe_available_bytes", available)
    monkeypatch.setattr(probes.os, "read", read)

    observation = LocalObservationSource().run(
        [sys.executable, "-c", "print('windows-output')"],
        timeout_seconds=5,
        output_limit=1024,
    )

    assert observation.status == "ok"
    assert observation.text == "windows-output\n"
    assert reads


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


@pytest.mark.parametrize(
    ("case", "allowed_reasons"),
    [
        ("lexical", {"containment_path_changed"}),
        ("parent", {"containment_path_changed"}),
        (
            "ancestor_link",
            {"symlink_not_followed", "containment_path_changed"},
        ),
        ("final_link", {"symlink_not_followed"}),
    ],
)
def test_sha256_with_root_rejects_outside_paths_before_metadata(
    tmp_path: Path,
    case: str,
    allowed_reasons: set[str],
) -> None:
    """Containment failures cannot expose outside size or file bytes."""
    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.bin"
    secret.write_bytes(b"x" * 128)

    if case == "lexical":
        path = secret
    elif case == "parent":
        path = root / ".." / outside.name / secret.name
    elif case == "ancestor_link":
        (root / "linked").symlink_to(outside, target_is_directory=True)
        path = root / "linked" / secret.name
    else:
        (root / "linked.bin").symlink_to(secret)
        path = root / "linked.bin"

    observation, digest = LocalObservationSource().sha256(
        path,
        limit=8,
        follow_final_symlink=True,
        root=root,
    )

    assert observation.status == "skipped"
    assert observation.reason in allowed_reasons
    assert observation.reason != "hash_limit_exceeded"
    assert digest is None


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


def test_replay_rejects_non_utf8_encodable_strings(tmp_path: Path) -> None:
    """Escaped lone surrogates become structured replay validation errors."""
    path = tmp_path / "replay.json"
    payload = {
        "schema": "media-generation.inventory-replay",
        "schema_version": 1,
        "synthetic": True,
        "observations": {
            "run:which:test": {"status": "ok", "text": "\ud800"},
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(InventoryValidationError, match="cannot be encoded as UTF-8"):
        ReplayObservationSource.from_path(path)


def test_replay_missing_file_is_a_validation_error(tmp_path: Path) -> None:
    """An inaccessible replay path preserves the structured error contract."""
    with pytest.raises(InventoryValidationError, match="not readable"):
        ReplayObservationSource.from_path(tmp_path / "missing.json")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "schema": "media-generation.inventory-replay",
                "schema_version": 1,
                "synthetic": True,
                "observations": {"read:/synthetic": {"status": "ok", "text": 1}},
            },
            "text must be a string",
        ),
        (
            {
                "schema": "media-generation.inventory-replay",
                "schema_version": 1,
                "synthetic": True,
                "observations": {"read:/synthetic": {"status": "unknown"}},
            },
            "invalid status",
        ),
    ],
)
def test_replay_rejects_malformed_observation_payloads(
    tmp_path: Path, payload: dict[str, object], message: str
) -> None:
    """Recorded observations are validated before they reach a collector."""
    path = tmp_path / "replay.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(InventoryValidationError, match=message):
        ReplayObservationSource.from_path(path)


def test_malformed_candidate_stat_is_explicit_evidence(tmp_path: Path) -> None:
    """A successful probe with an undecodable payload is not reported as absence."""
    runtime_path = tmp_path / "runtime"
    source = ReplayObservationSource(
        {
            f"stat:{runtime_path}": Observation(status="ok", text="[]"),
        }
    )
    searched: list[str] = []

    path, payload = _candidate(
        ProbeLedger(source),
        runtime_id="synthetic",
        path=runtime_path,
        kind="binary",
        searched=searched,
    )

    assert path is None
    assert payload == {
        "path": str(runtime_path),
        "status": "malformed",
        "reason": "stat_payload_malformed",
    }
    assert searched == [str(runtime_path)]


def test_python_distribution_access_failure_is_not_reported_as_absence() -> None:
    """Permission failures retain metadata-unavailable evidence."""
    source = ReplayObservationSource(
        {
            "distribution:diffusers": Observation(
                status="error", reason="permission_denied"
            )
        }
    )
    spec = RUNTIME_CATALOG["diffusers"]

    record, degraded, finding = _python_distribution(
        ProbeLedger(source), spec, None
    )

    assert record["presence"] == "metadata_unavailable"
    assert record["identity"] == {
        "status": "error",
        "reason": "permission_denied",
    }
    assert degraded is True
    assert finding is not None
    assert finding.code == "runtime_distribution_metadata_unavailable"


def test_stable_diffusion_catalog_does_not_accept_generic_sd_alias() -> None:
    """A PATH binary named ``sd`` is too generic to identify the runtime."""
    assert "sd" not in RUNTIME_CATALOG["stable-diffusion.cpp"].names

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


def test_sha256_detects_in_place_metadata_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file modified in place during hashing never publishes a digest."""
    path = tmp_path / "model.bin"
    path.write_bytes(b"stable content")
    real_fstat = os.fstat
    calls = {"count": 0}

    def mutating_fstat(descriptor: int) -> SimpleNamespace:
        calls["count"] += 1
        facts = real_fstat(descriptor)
        if calls["count"] == 2:
            return SimpleNamespace(
                st_dev=facts.st_dev,
                st_ino=facts.st_ino,
                st_mode=facts.st_mode,
                st_size=facts.st_size,
                st_mtime_ns=facts.st_mtime_ns + 1,
                st_ctime_ns=facts.st_ctime_ns + 1,
            )
        return SimpleNamespace(
            st_dev=facts.st_dev,
            st_ino=facts.st_ino,
            st_mode=facts.st_mode,
            st_size=facts.st_size,
            st_mtime_ns=facts.st_mtime_ns,
            st_ctime_ns=facts.st_ctime_ns,
        )

    monkeypatch.setattr("media_generation.inventory.probes.os.fstat", mutating_fstat)

    observation, digest = LocalObservationSource().sha256(path, limit=1024)

    assert observation.status == "skipped"
    assert observation.reason == "file_changed_during_hash"
    assert digest is None


def test_replay_read_text_honors_requested_byte_limit() -> None:
    """Replay reads apply the same bound as recorded local reads."""
    source = ReplayObservationSource(
        {"read:/model": Observation(status="ok", text="é" * 50)}
    )

    observation = source.read_text(Path("/model"), limit=10)

    assert observation.truncated is True
    assert observation.text == "é" * 5


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
