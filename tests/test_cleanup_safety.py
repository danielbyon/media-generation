"""Race, lock, interruption, and failure tests for cleanup mechanics."""

from __future__ import annotations

import fcntl
import hashlib
import importlib
import importlib.util
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from cleanup_fixtures import (
    create_checkout,
    git,
    report_from_stdout,
    run_clean,
    snapshot_tree,
    write_bytecode_cache,
    write_pytest_cache,
    write_safe_build,
)


def load_cleanup_module(script: Path) -> ModuleType:
    """Import a copied cleanup script without installing the application."""

    specification = importlib.util.spec_from_file_location("fixture_cleanup", script)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    previous_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        specification.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_dont_write_bytecode
    package_name = module.run_cleanup.__module__.rsplit(".", 1)[0]
    module._PACKAGE_NAME = package_name
    module._engine = importlib.import_module(f"{package_name}.cleanup_engine")
    return module


def hold_worktree_lock(repo: Path) -> int:
    """Acquire the same directory lock used by cooperative producers."""

    descriptor = os.open(repo, os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


def test_cleaner_refuses_an_already_held_worktree_lock(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    descriptor = hold_worktree_lock(repo)
    try:
        result = run_clean(repo, "--json")
    finally:
        os.close(descriptor)

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["status"] == "busy"
    assert cache.is_dir()


def test_dry_run_does_not_acquire_or_create_a_lock_file(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    write_bytecode_cache(repo / "package")
    before = set(repo.iterdir())

    result = run_clean(repo, "--dry-run", "--json")

    assert result.returncode == 0, result.stderr
    assert set(repo.iterdir()) == before






def test_unlink_failure_reports_error_and_preserves_unrelated_bytes(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    first_cache = write_bytecode_cache(repo / "first", module="a")
    write_bytecode_cache(repo / "second", module="b")
    protected = repo / "evidence.txt"
    protected.write_text("durable", encoding="utf-8")
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    original_unlink = module.os.unlink
    calls = 0

    def failing_unlink(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PermissionError(13, "injected unlink failure")
        return original_unlink(*args, **kwargs)

    module.os.unlink = failing_unlink
    try:
        report = module.run_cleanup(module.resolve_worktree(repo / "scripts" / "clean.py"), dry_run=False)
    finally:
        module.os.unlink = original_unlink

    assert report["status"] == "partial"
    assert report["summary"]["error_count"] >= 1
    assert protected.read_text(encoding="utf-8") == "durable"
    assert first_cache.is_dir()
    assert any(path.read_bytes() == b"bytecode" for path in first_cache.iterdir())



def test_sigterm_leaves_protected_data_intact(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    protected = repo / "studio.sqlite3"
    protected.write_bytes(b"sqlite")
    process = subprocess.Popen(
        [sys.executable, str(repo / "scripts" / "clean.py"), "--json"],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    process.send_signal(signal.SIGTERM)
    process.communicate(timeout=20)

    assert protected.read_bytes() == b"sqlite"
    assert cache.exists() or not any(cache.glob("*.pyc"))


def test_tracked_membership_uses_nul_safe_index_even_for_newlines(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = repo / "package" / "__pycache__"
    cache.mkdir(parents=True)
    unusual = cache / "line\nbreak.cpython-311.pyc"
    unusual.write_bytes(b"tracked")
    git(repo, "add", "-f", str(cache.relative_to(repo)))
    before = snapshot_tree(repo, ["package/__pycache__"])

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, ["package/__pycache__"]) == before


def test_ignored_protected_directories_are_never_scanned_or_removed(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    protected_caches = []
    for directory in [
        ".venv",
        ".artifact-cleanup",
        ".chatgpt",
        ".serena",
        ".codegraph",
        ".playwright-cli",
        "artifacts",
        "coverage",
        "dist",
        "evidence",
        "fixtures",
        "node_modules",
        "snapshots",
        "test-results",
    ]:
        cache = write_bytecode_cache(repo / directory / "nested")
        protected_caches.append(cache)
    before = snapshot_tree(repo, [str(cache.relative_to(repo)) for cache in protected_caches])

    result = run_clean(repo, "--json")

    assert result.returncode == 0, result.stderr
    assert all(cache.is_dir() for cache in protected_caches)
    assert snapshot_tree(repo, [str(cache.relative_to(repo)) for cache in protected_caches]) == before


def test_bytecode_symlink_as_candidate_is_rejected(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    outside = tmp_path / "outside.pyc"
    outside.write_bytes(b"outside")
    package = repo / "package"
    package.mkdir()
    (package / "linked.pyc").symlink_to(outside)

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert outside.read_bytes() == b"outside"


def test_reclaimed_bytes_remain_worktree_wide_for_multiple_categories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_checkout(tmp_path)
    write_bytecode_cache(repo / "package")
    write_pytest_cache(repo)
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    engine = module._engine
    free_values = iter((1_000, 1_800))
    monkeypatch.setattr(
        engine,
        "_available_bytes",
        lambda _root_fd: next(free_values),
    )

    report = module.run_cleanup(
        module.resolve_worktree(repo / "scripts" / "clean.py"),
        dry_run=False,
    )

    assert report["summary"]["reclaimed_bytes"] == 800
    assert report["categories"]["bytecode"]["reclaimed_bytes"] == 0
    assert report["categories"]["pytest-cache"]["reclaimed_bytes"] == 0




def test_cleanup_facade_does_not_modify_the_import_path(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    import_path = tuple(sys.path)

    load_cleanup_module(repo / "scripts" / "clean.py")

    assert tuple(sys.path) == import_path


def test_artifact_cleanup_publication_state_is_never_scanned(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    publication = repo / ".artifact-cleanup" / "publication-1"
    bytecode = publication / "__pycache__" / "publication.cpython-311.pyc"
    bytecode.parent.mkdir(parents=True)
    bytecode.write_bytes(b"durable publication bytecode")
    marker = publication / "recovery-note.txt"
    marker.write_bytes(b"durable recovery state")
    marker_hash = hashlib.sha256(marker.read_bytes()).hexdigest()
    before = snapshot_tree(repo, [".artifact-cleanup"])

    result = run_clean(repo, "--json")

    assert result.returncode == 0, result.stderr
    assert snapshot_tree(repo, [".artifact-cleanup"]) == before
    assert hashlib.sha256(marker.read_bytes()).hexdigest() == marker_hash






def test_inaccessible_directory_produces_partial_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = create_checkout(tmp_path)
    blocked = repo / "unreadable-directory"
    blocked.mkdir()
    protected = blocked / "operator.bin"
    protected.write_bytes(b"protected bytes")
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    cleanup_fs = importlib.import_module(f"{module._PACKAGE_NAME}.cleanup_fs")
    original_open = cleanup_fs._open_directory_at

    def failing_open(directory_fd: int, name: str):
        if name == blocked.name:
            raise PermissionError(13, "injected scandir failure")
        return original_open(directory_fd, name)

    monkeypatch.setattr(cleanup_fs, "_open_directory_at", failing_open)

    report = module.run_cleanup(
        module.resolve_worktree(repo / "scripts" / "clean.py"),
        dry_run=False,
    )

    errors = [
        entry
        for entry in report["entries"]
        if isinstance(entry, dict) and entry.get("path") == blocked.name
    ]
    assert report["status"] == "partial"
    assert module._report_exit_code(report) != 0
    assert len(errors) == 1
    assert errors[0]["status"] == "error"
    assert protected.read_bytes() == b"protected bytes"
































def test_scan_depth_limit_is_reported_without_deleting_nested_content(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    deepest = repo
    for _ in range(130):
        deepest /= "d"
    deepest.mkdir(parents=True)
    sentinel = deepest / "operator-note.txt"
    sentinel.write_text("durable\n", encoding="utf-8")
    before = snapshot_tree(repo, ["d"])

    result = run_clean(repo, "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["status"] == "partial"
    assert any(
        entry["status"] == "error"
        and "depth" in entry["reason"].lower()
        for entry in report["entries"]
    )
    assert "RecursionError" not in result.stderr
    assert snapshot_tree(repo, ["d"]) == before


def test_build_validation_bounds_deep_source_walk_after_earlier_cleanup(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    build = write_safe_build(repo)
    pytest_cache = write_pytest_cache(repo)
    source_root = repo / "src" / "media_generation"
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    deepest_fd = os.open(source_root, flags)
    try:
        for _ in range(1_100):
            os.mkdir("d", dir_fd=deepest_fd)
            child_fd = os.open("d", flags, dir_fd=deepest_fd)
            os.close(deepest_fd)
            deepest_fd = child_fd
        marker_fd = os.open(
            "operator-note.txt",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=deepest_fd,
        )
        try:
            os.write(marker_fd, b"durable\n")
        finally:
            os.close(marker_fd)
        deepest_before = os.fstat(deepest_fd)

        result = run_clean(repo, "--json")

        assert not pytest_cache.exists()
        assert build.is_dir()
        deepest_after = os.fstat(deepest_fd)
        assert (deepest_after.st_dev, deepest_after.st_ino) == (
            deepest_before.st_dev,
            deepest_before.st_ino,
        )
        marker_fd = os.open("operator-note.txt", os.O_RDONLY, dir_fd=deepest_fd)
        try:
            assert os.read(marker_fd, 64) == b"durable\n"
        finally:
            os.close(marker_fd)
        report = report_from_stdout(result)
        assert result.returncode != 0
        assert report["status"] == "partial"
        assert report["summary"]["removed_count"] == 1
        build_entry = next(
            entry for entry in report["entries"] if entry["path"] == "build"
        )
        assert build_entry["status"] == "error"
        assert "depth" in build_entry["reason"].lower()
        assert "RecursionError" not in result.stderr
    finally:
        os.close(deepest_fd)


def test_worktree_lock_preserves_borrowed_authority_descriptor(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    authority = module.resolve_worktree_pinned(repo / "scripts" / "clean.py")
    try:
        before = os.fstat(authority.root_fd)
        with module.worktree_lock(authority, blocking=False):
            pass
        assert os.fstat(authority.root_fd).st_ino == before.st_ino
        with module.worktree_lock(authority, blocking=False):
            assert os.fstat(authority.root_fd).st_ino == before.st_ino
    finally:
        try:
            os.close(authority.root_fd)
        except OSError:
            pass


def test_second_unlink_failure_reports_removed_children(tmp_path: Path, monkeypatch) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package", module="a")
    (cache / "z.pyc").write_bytes(b"second")
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    original = os.unlink
    calls = 0
    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError(13, "second unlink failure")
        return original(*args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", fail_second)
        report = module.run_cleanup(module.resolve_worktree(repo / "scripts" / "clean.py"))
    assert report["status"] == "partial"
    assert module._report_exit_code(report) != 0
    assert report["summary"]["removed_count"] == 0
    assert (cache / "z.pyc").exists()
    error = next(e for e in report["entries"] if e["status"] == "error")
    assert "1 child" in error["reason"] and "partially removed" in error["reason"]
    assert error["estimated_bytes"] > 0
    assert "1 child" in module.format_human_report(report)


def test_final_root_rmdir_failure_reports_removed_children(tmp_path: Path, monkeypatch) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package", module="a")
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    original = os.rmdir
    def deny_root(name, *args, **kwargs):
        if name == "__pycache__":
            raise PermissionError(13, "root rmdir denied")
        return original(name, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os, "rmdir", deny_root)
        report = module.run_cleanup(module.resolve_worktree(repo / "scripts" / "clean.py"))
    assert report["status"] == "partial"
    assert module._report_exit_code(report) != 0
    assert cache.is_dir() and not list(cache.iterdir())
    assert report["summary"]["removed_count"] == 0
    error = next(e for e in report["entries"] if e["status"] == "error")
    assert "1 child" in error["reason"] and "partially removed" in error["reason"]
    assert "root rmdir denied" in error["reason"]
    assert error["estimated_bytes"] > 0


def test_child_rmdir_failure_reports_removed_children(tmp_path: Path, monkeypatch) -> None:
    repo = create_checkout(tmp_path)
    cache = write_pytest_cache(repo)
    module = load_cleanup_module(repo / "scripts" / "clean.py")
    original = os.rmdir
    def deny_child(name, *args, **kwargs):
        if name == "cache":
            raise PermissionError(13, "child rmdir denied")
        return original(name, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os, "rmdir", deny_child)
        report = module.run_cleanup(module.resolve_worktree(repo / "scripts" / "clean.py"))
    assert report["status"] == "partial"
    assert module._report_exit_code(report) != 0
    assert cache.is_dir()
    error = next(e for e in report["entries"] if e["status"] == "error")
    assert "partially removed" in error["reason"] and "child entries removed" in error["reason"]
    assert "child rmdir denied" in error["reason"]
    assert error["estimated_bytes"] > 0
    assert report["summary"]["removed_count"] == 0
