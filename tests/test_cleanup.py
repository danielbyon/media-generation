"""Behavioral coverage for safe worktree-scoped artifact cleanup."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cleanup_fixtures import (
    CLEAN_SCRIPT,
    clean_environment,
    create_checkout,
    git,
    report_from_stdout,
    run_clean,
    snapshot_tree,
    write_bytecode_cache,
    write_egg_info,
    write_pytest_cache,
    write_safe_build,
)


def test_help_is_standalone_and_non_destructive(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "pkg")
    before = snapshot_tree(repo, [str(cache.relative_to(repo))])

    result = run_clean(repo, "--help")

    assert result.returncode == 0, result.stderr
    assert "--dry-run" in result.stdout
    assert "--json" in result.stdout
    assert snapshot_tree(repo, [str(cache.relative_to(repo))]) == before


def test_dry_run_plans_allowlisted_candidates_without_mutation(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    bytecode = write_bytecode_cache(repo / "pkg")
    pytest_cache = write_pytest_cache(repo)
    metadata = write_egg_info(repo)
    build = write_safe_build(repo)
    before = snapshot_tree(repo)

    result = run_clean(repo, "--dry-run", "--json")

    report = report_from_stdout(result)
    assert result.returncode == 0, result.stderr
    assert report["dry_run"] is True
    assert report["status"] == "ok"
    assert report["summary"]["planned_count"] == 4
    assert report["summary"]["removed_count"] == 0
    assert report["summary"]["estimated_removable_bytes"] > 0
    assert {
        entry["status"] for entry in report["entries"]
    } == {"planned"}
    assert {entry["path"] for entry in report["entries"]} == {
        "build",
        ".pytest_cache",
        "pkg/__pycache__",
        "src/media_generation.egg-info",
    }
    assert snapshot_tree(repo) == before
    assert bytecode.is_dir()
    assert pytest_cache.is_dir()
    assert metadata.is_dir()
    assert build.is_dir()


@pytest.mark.parametrize(
    "invocation",
    [
        ("direct", "--dry-run"),
        ("direct", "--json"),
        ("direct", "--help"),
        ("make", "clean-dry-run"),
    ],
)
def test_non_destructive_entry_points_never_write_bytecode(
    tmp_path: Path,
    invocation: tuple[str, str],
) -> None:
    repo = create_checkout(tmp_path)
    before = snapshot_tree(repo)
    environment = clean_environment(repo.parent)
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    kind, argument = invocation
    if kind == "make":
        command = ["make", argument]
    else:
        command = [sys.executable, str(repo / "scripts" / "clean.py"), argument]

    result = subprocess.run(
        command,
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20.0,
    )

    assert result.returncode == 0, result.stderr
    assert snapshot_tree(repo) == before


def test_ordinary_clean_is_idempotent_without_creating_candidates(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    before = snapshot_tree(repo)
    environment = clean_environment(repo.parent)
    environment.pop("PYTHONDONTWRITEBYTECODE", None)
    command = [sys.executable, str(repo / "scripts" / "clean.py"), "--json"]

    first = subprocess.run(
        command,
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20.0,
    )
    second = subprocess.run(
        command,
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20.0,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert report_from_stdout(first)["summary"]["candidate_count"] == 0
    assert report_from_stdout(second)["summary"]["candidate_count"] == 0
    assert snapshot_tree(repo) == before


def test_default_clean_removes_verified_candidates_and_is_idempotent(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    bytecode = write_bytecode_cache(repo / "pkg")
    pytest_cache = write_pytest_cache(repo)
    metadata = write_egg_info(repo)
    build = write_safe_build(repo)
    protected = {
        ".venv/pyvenv.cfg": b"home = /usr/bin\n",
        ".chatgpt/run.json": b"{}",
        ".serena/project.yml": b"project: local\n",
        ".codegraph/graph.db": b"index",
        "artifacts/result.png": b"media",
        "studio.sqlite3-wal": b"wal",
        ".artifact-publication.lock": b"",
        ".artifact-cleanup/stage.tmp": b"stage",
    }
    for relative, content in protected.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    protected_before = snapshot_tree(repo, protected)

    first = run_clean(repo, "--json")
    second = run_clean(repo, "--json")

    first_report = report_from_stdout(first)
    second_report = report_from_stdout(second)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first_report["summary"]["removed_count"] == 4
    assert first_report["summary"]["reclaimed_bytes"] >= 0
    assert second_report["summary"]["candidate_count"] == 0
    assert second_report["summary"]["removed_count"] == 0
    assert not bytecode.exists()
    assert not pytest_cache.exists()
    assert not metadata.exists()
    assert not build.exists()
    assert snapshot_tree(repo, protected) == protected_before


def test_clean_runs_from_repository_subdirectory(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    subdirectory = repo / "tests" / "nested"
    subdirectory.mkdir(parents=True)

    result = run_clean(repo, "--json", cwd=subdirectory)

    assert result.returncode == 0, result.stderr
    assert not cache.exists()


def test_git_environment_overrides_cannot_redirect_authority(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    decoy = tmp_path / "decoy"
    decoy.mkdir()

    result = run_clean(
        repo,
        "--dry-run",
        "--json",
        extra_env={
            "GIT_DIR": str(decoy / ".git"),
            "GIT_WORK_TREE": str(decoy),
            "GIT_INDEX_FILE": str(decoy / "index"),
        },
    )

    assert result.returncode == 0, result.stderr
    report = report_from_stdout(result)
    assert any(entry["path"] == "package/__pycache__" for entry in report["entries"])
    assert cache.exists()


def test_tracked_bytecode_blocks_removal_and_fails_cleanup(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    git(repo, "add", "-f", str(cache.relative_to(repo)))
    before = snapshot_tree(repo, [str(cache.relative_to(repo))])

    result = run_clean(repo, "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["status"] == "partial"
    assert report["summary"]["removed_count"] == 0
    assert any(entry["status"] == "error" and "racked" in entry["reason"] for entry in report["entries"])
    assert snapshot_tree(repo, [str(cache.relative_to(repo))]) == before


@pytest.mark.parametrize(
    "unknown_name",
    ["notes.txt", "nested", "module.cpython-311.pyc.replacement"],
)
def test_mixed_bytecode_cache_is_preserved_wholesale(
    tmp_path: Path, unknown_name: str
) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")
    unknown = cache / unknown_name
    if unknown_name == "nested":
        unknown.mkdir()
        (unknown / "data").write_text("keep", encoding="utf-8")
    else:
        unknown.write_text("keep", encoding="utf-8")
    before = snapshot_tree(repo, [str(cache.relative_to(repo))])

    result = run_clean(repo, "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["summary"]["removed_count"] == 0
    assert snapshot_tree(repo, [str(cache.relative_to(repo))]) == before


def test_unrecognized_pytest_cache_is_preserved(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = repo / ".pytest_cache"
    cache.mkdir()
    (cache / "value").write_text("not pytest", encoding="utf-8")
    before = snapshot_tree(repo, [".pytest_cache"])

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, [".pytest_cache"]) == before


def test_unknown_pytest_cache_value_file_preserves_entire_cache(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    cache = write_pytest_cache(repo)
    (cache / "v" / "cache" / "operator-note.txt").write_text(
        "operator data",
        encoding="utf-8",
    )
    before = snapshot_tree(repo, [".pytest_cache"])

    result = run_clean(repo, "--json")
    report = report_from_stdout(result)

    assert result.returncode != 0
    assert report["status"] == "partial"
    assert report["summary"]["removed_count"] == 0
    assert snapshot_tree(repo, [".pytest_cache"]) == before


@pytest.mark.parametrize("relative_path", ["v", "v/cache"])
def test_pytest_cache_value_paths_must_be_directories(
    tmp_path: Path,
    relative_path: str,
) -> None:
    repo = create_checkout(tmp_path)
    cache = write_pytest_cache(repo)
    malformed = cache / relative_path
    shutil.rmtree(malformed)
    malformed.write_text("not a directory", encoding="utf-8")
    before = snapshot_tree(repo, [".pytest_cache"])

    result = run_clean(repo, "--json")
    report = report_from_stdout(result)

    assert result.returncode != 0
    assert report["status"] == "partial"
    assert report["summary"]["removed_count"] == 0
    assert snapshot_tree(repo, [".pytest_cache"]) == before


def test_wrong_project_egg_info_is_preserved(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    metadata = write_egg_info(repo)
    (metadata / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: another-project\nVersion: 1\n",
        encoding="utf-8",
    )
    before = snapshot_tree(repo, ["src/media_generation.egg-info"])

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, ["src/media_generation.egg-info"]) == before


def test_mixed_build_tree_and_distribution_are_preserved(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    build = write_safe_build(repo)
    (build / "lib" / "media_generation" / "unknown.txt").write_text(
        "operator data", encoding="utf-8"
    )
    distribution = repo / "dist"
    distribution.mkdir()
    (distribution / "media_generation-0.1.0.tar.gz").write_bytes(b"release")
    before = snapshot_tree(repo, ["build", "dist"])

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, ["build", "dist"]) == before


def test_symlinked_candidate_is_not_followed(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    outside = tmp_path / "outside"
    outside_cache = write_bytecode_cache(outside)
    target = outside_cache / "sample.cpython-311.pyc"
    package = repo / "package"
    package.mkdir()
    (package / "__pycache__").symlink_to(outside_cache, target_is_directory=True)
    before = snapshot_tree(outside, ["__pycache__"])

    result = run_clean(repo, "--json")

    assert result.returncode != 0
    assert target.read_bytes() == b"bytecode"
    assert snapshot_tree(outside, ["__pycache__"]) == before


def test_symlinked_script_invocation_is_rejected(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    outside = write_bytecode_cache(tmp_path / "outside")
    alias_root = tmp_path / "alias"
    alias_root.mkdir()
    (alias_root / "scripts").symlink_to(repo / "scripts", target_is_directory=True)

    result = subprocess.run(
        [sys.executable, str(alias_root / "scripts" / "clean.py"), "--json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode != 0
    assert outside.is_dir()


def test_hardlinked_bytecode_blocks_removal(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    outside = tmp_path / "outside.pyc"
    outside.write_bytes(b"protected")
    cache = repo / "package" / "__pycache__"
    cache.mkdir(parents=True)
    os.link(outside, cache / "linked.cpython-311.pyc")

    result = run_clean(repo, "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["summary"]["removed_count"] == 0
    assert cache.is_dir()
    assert outside.read_bytes() == b"protected"


def test_nested_repository_is_not_traversed(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    nested = repo / "vendor" / "nested"
    nested.mkdir(parents=True)
    git(nested, "init", "-b", "main")
    cache = write_bytecode_cache(nested / "package")

    result = run_clean(repo, "--json")

    assert result.returncode == 0, result.stderr
    assert cache.is_dir()


def test_unusual_bytecode_filename_is_removed_without_shell_interpolation(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    cache = repo / "package" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "space and $(touch escaped).cpython-311.pyc").write_bytes(b"bytecode")
    escaped = repo / "escaped"

    result = run_clean(repo, "--json")

    assert result.returncode == 0, result.stderr
    assert not cache.exists()
    assert not escaped.exists()


def test_linked_worktree_cleanup_is_independent(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-b", "fixture-linked", str(linked), "HEAD")
    repo_cache = write_bytecode_cache(repo / "main_package")
    linked_cache = write_bytecode_cache(linked / "linked_package")
    common_before = snapshot_tree(repo / ".git" / "worktrees") if (repo / ".git" / "worktrees").exists() else {}

    result = run_clean(linked, "--json")

    assert result.returncode == 0, result.stderr
    assert not linked_cache.exists()
    assert repo_cache.is_dir()
    common_after = snapshot_tree(repo / ".git" / "worktrees") if (repo / ".git" / "worktrees").exists() else {}
    assert common_after == common_before


def test_human_report_names_categories_and_byte_totals(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    write_bytecode_cache(repo / "package")

    result = run_clean(repo, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "bytecode" in result.stdout.lower()
    assert "estimated" in result.stdout.lower()
    assert "reclaimed" in result.stdout.lower()


def test_json_report_has_stable_top_level_and_category_shape(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    write_bytecode_cache(repo / "package")

    result = run_clean(repo, "--dry-run", "--json")
    report = report_from_stdout(result)

    assert set(report) == {
        "schema_version",
        "mode",
        "dry_run",
        "worktree",
        "status",
        "summary",
        "categories",
        "entries",
    }
    assert set(report["summary"]) == {
        "candidate_count",
        "planned_count",
        "removed_count",
        "skipped_count",
        "error_count",
        "estimated_removable_bytes",
        "reclaimed_bytes",
    }
    assert report["categories"]["bytecode"]["candidate_count"] == 1


def test_clean_script_does_not_import_application_or_third_party_modules(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    blocker = repo / "media_generation.py"
    blocker.write_text("raise RuntimeError('application import attempted')\n", encoding="utf-8")
    blocker_site = repo / "sitecustomize.py"
    blocker_site.write_text(
        "import sys\nsys.modules['PIL'] = None\n",
        encoding="utf-8",
    )

    result = run_clean(
        repo,
        "--dry-run",
        "--json",
        extra_env={"PYTHONPATH": str(repo)},
    )

    assert result.returncode == 0, result.stderr
    assert report_from_stdout(result)["summary"]["candidate_count"] == 0
    assert CLEAN_SCRIPT.exists()
