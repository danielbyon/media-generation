"""Contract checks for the developer Make workflow and CI wiring."""

from __future__ import annotations

import sys
from pathlib import Path

from cleanup_fixtures import MAKEFILE, SOURCE_ROOT, create_checkout, run_make, write_bytecode_cache


def test_help_is_the_first_and_default_target(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)

    result = run_make(repo)

    assert result.returncode == 0, result.stderr
    assert "Usage:" in result.stdout
    assert "make clean" in result.stdout


def test_make_clean_delegates_to_the_cleanup_engine(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    cache = write_bytecode_cache(repo / "package")

    result = run_make(repo, "clean", "PYTHON=" + sys.executable)
    source = MAKEFILE.read_text(encoding="utf-8")

    recipe = source.split("clean:", 1)[1].split("\n\n", 1)[0]
    assert "scripts/clean.py" in recipe
    assert "\trm " not in recipe
    assert result.returncode == 0, result.stderr
    assert not cache.exists()


def test_make_dry_run_passes_only_script_dry_run_flag(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    result = run_make(repo, "clean-dry-run", dry_run=True)

    assert result.returncode == 0, result.stderr
    assert "scripts/clean.py --dry-run" in result.stdout
    assert "\trm " not in result.stdout


def test_deep_target_requires_runtime_confirmation(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    result = run_make(repo, "clean-deep", dry_run=True)

    assert result.returncode == 0, result.stderr
    assert "scripts/clean.py deep --include-venv" in result.stdout
    assert "--confirm" not in result.stdout
    assert "--dry-run" not in result.stdout


def test_makefile_is_phony_and_avoids_gnu_only_constructs() -> None:
    source = MAKEFILE.read_text(encoding="utf-8")
    first_rule = next(
        line
        for line in source.splitlines()
        if line
        and not line.startswith(("#", "\t"))
        and line.endswith(":")
        and "=" not in line
    )

    assert first_rule == "help:"
    for target in [
        "help",
        "setup",
        "install",
        "test",
        "smoke",
        "check",
        "clean",
        "clean-dry-run",
        "clean-deep",
    ]:
        assert f".PHONY:" in source
        assert target in source.split(".PHONY:", 1)[1].splitlines()[0]
    for unsupported in ["$(shell", "$(wildcard", "$(eval", "$(foreach", "ifeq", "ifneq", "|"]:
        assert unsupported not in source


def test_make_producers_use_the_shared_lock_runner() -> None:
    source = MAKEFILE.read_text(encoding="utf-8")
    assert 'LOCK_RUNNER = "$$PYTHON" scripts/with_worktree_lock.py --' in source
    assert "export PYTHON" in source
    assert "export CLI" in source
    for target in ["setup", "install", "test", "smoke"]:
        block = source.split(f"{target}:", 1)[1].split("\n\n", 1)[0]
        assert "$(LOCK_RUNNER)" in block


def test_python_override_controls_every_python_command() -> None:
    source = MAKEFILE.read_text(encoding="utf-8")
    assert "PYTHON ?= python3" in source
    assert "python3 -m pytest" not in source
    assert "python3 -m pip" not in source


def test_smoke_uses_selected_python_console_script(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    selected_bin = tmp_path / "selected-python" / "bin"
    selected_bin.mkdir(parents=True)
    selected_python = selected_bin / "python3"
    selected_python.symlink_to(sys.executable)
    selected_cli = selected_bin / "media-generation"
    selected_cli.write_text("#!/bin/sh\nprintf 'selected console script\\n'\n", encoding="ascii")
    selected_cli.chmod(0o755)

    result = run_make(
        repo,
        "smoke",
        "PYTHON=" + str(selected_python),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "selected console script\n"


def test_smoke_does_not_execute_shell_metacharacters_from_python_override(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    marker = tmp_path / "python-injected"

    result = run_make(repo, "smoke", f"PYTHON={sys.executable}; touch {marker}; #")

    assert result.returncode != 0
    assert not marker.exists()


def test_smoke_does_not_execute_shell_metacharacters_from_cli_override(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    marker = tmp_path / "cli-injected"

    result = run_make(repo, "smoke", f'CLI="; touch {marker}; #')

    assert result.returncode != 0
    assert not marker.exists()


def test_ci_matrix_runs_each_make_gate_and_preserves_entrypoint_smoke() -> None:
    workflow = (SOURCE_ROOT / ".github" / "workflows" / "python-tests.yml").read_text(
        encoding="utf-8"
    )

    for os, version in (
        ("ubuntu-24.04", "3.14.4"),
        ("ubuntu-latest", "3.14"),
        ("macos-latest", "3.14.4"),
        ("macos-latest", "3.14"),
    ):
        assert f'- os: {os}\n            python-version: "{version}"' in workflow
    for command in ["make install", "make test", "make smoke", "make check", "make clean-dry-run"]:
        assert f"run: {command}" in workflow
    assert "media-generation --help" in workflow


def test_cleanup_documentation_covers_operations_and_limits() -> None:
    readme = (SOURCE_ROOT / "README.md").read_text(encoding="utf-8")
    cleanup_doc = SOURCE_ROOT / "docs" / "architecture" / "development-cleanup.md"
    assert cleanup_doc.exists()
    documentation = readme + cleanup_doc.read_text(encoding="utf-8")
    for phrase in [
        "make help",
        "make setup",
        "make clean-dry-run",
        "make clean-deep",
        "idle checkout",
        "estimated",
        "reclaimed",
        ".artifact-publication.lock",
        "partial",
    ]:
        assert phrase in documentation
