"""Safety checks for separately confirmed local virtual-environment cleanup."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cleanup_fixtures import (
    clean_environment,
    create_checkout,
    git,
    report_from_stdout,
    run_clean,
    snapshot_tree,
)


def make_virtual_environment(repo: Path, *, include_system: bool = False) -> Path:
    """Create a minimal inactive, pyvenv-recognizable environment."""

    environment = repo / ".venv"
    (environment / "bin").mkdir(parents=True)
    (environment / "lib" / "python3.14" / "site-packages").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "home = /usr/bin\n"
        f"include-system-site-packages = {str(include_system).lower()}\n"
        "version = 3.14.0\n",
        encoding="utf-8",
    )
    (environment / "bin" / "python").write_text("#!/bin/false\n", encoding="ascii")
    return environment


def make_real_virtual_environment(
    repo: Path,
    *,
    with_pip: bool = True,
    omit_optional_python_alias: bool = False,
    python_executable: str | None = None,
) -> Path:
    """Create a real disposable environment using the interpreter under test."""

    environment = repo / ".venv"
    command = [python_executable or sys.executable, "-m", "venv"]
    if not with_pip:
        command.append("--without-pip")
    command.append(str(environment))
    result = subprocess.run(
        command,
        cwd=repo,
        env=clean_environment(repo.parent),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    if omit_optional_python_alias:
        optional_alias = environment / "bin" / "𝜋thon"
        if optional_alias.exists():
            optional_alias.unlink()
    return environment


def assert_deep_clean_rejects_virtualenv(
    repo: Path, environment: Path, *, reason_fragment: str = "record"
) -> None:
    """Assert that a deep-clean refusal preserves the complete environment."""

    before = snapshot_tree(repo, [".venv"])
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["status"] == "partial"
    entry = next(
        item
        for item in report["entries"]
        if item["category"] == "virtual-environment"
    )
    assert entry["status"] == "error"
    assert reason_fragment in entry["reason"].lower()
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.is_dir()


def entry_reason(report: dict[str, object]) -> str:
    """Return the virtual-environment diagnostic from a cleanup report."""

    entries = report["entries"]
    assert isinstance(entries, list)
    return next(
        str(item["reason"])
        for item in entries
        if item["category"] == "virtual-environment"
    )


def test_unconfirmed_noninteractive_deep_clean_makes_no_changes(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "deep", "--include-venv", "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["status"] == "partial"
    assert report["mode"] == "deep"
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.is_dir()


def test_confirmed_deep_clean_removes_only_validated_local_environment(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(repo, with_pip=False)
    cache = repo / "package" / "__pycache__"
    cache.mkdir(parents=True)
    cache.joinpath("module.pyc").write_bytes(b"bytecode")

    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")

    report = report_from_stdout(result)
    assert result.returncode == 0, result.stderr
    assert report["summary"]["removed_count"] == 2
    assert not environment.exists()
    assert not cache.exists()




def test_deep_dry_run_needs_no_confirmation_and_changes_nothing(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(repo, with_pip=False)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "deep", "--include-venv", "--dry-run", "--json")

    report = report_from_stdout(result)
    assert result.returncode == 0, result.stderr
    assert report["summary"]["planned_count"] == 1
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.is_dir()


def test_deep_clean_rejects_symlinked_environment(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    outside = make_virtual_environment(tmp_path / "outside")
    outside_root = outside.parent
    (repo / ".venv").symlink_to(outside_root, target_is_directory=True)
    before = snapshot_tree(outside_root, [".venv"])

    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")

    assert result.returncode != 0
    assert snapshot_tree(outside_root, [".venv"]) == before


def test_deep_clean_rejects_shared_system_site_environment(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo, include_system=True)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")

    report = report_from_stdout(result)
    assert result.returncode != 0
    assert report["summary"]["error_count"] == 1
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.exists()


def test_deep_clean_rejects_active_environment(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(
        repo,
        "deep",
        "--include-venv",
        "--confirm",
        "--json",
        extra_env={"VIRTUAL_ENV": str(environment)},
    )

    assert result.returncode != 0
    assert snapshot_tree(repo, [".venv"]) == before


def test_deep_clean_rejects_environment_containing_tracked_content(
    tmp_path: Path,
) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    tracked = environment / "tracked-marker"
    tracked.write_text("indexed", encoding="utf-8")
    git(repo, "add", "-f", str(tracked.relative_to(repo)))
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, [".venv"]) == before


def test_ordinary_clean_never_touches_virtual_environment(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "--json")

    assert result.returncode == 0, result.stderr
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.is_dir()


def test_deep_requires_include_venv_selector(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    before = snapshot_tree(repo, [".venv"])

    result = run_clean(repo, "deep", "--confirm", "--json")

    assert result.returncode != 0
    assert snapshot_tree(repo, [".venv"]) == before
    assert environment.is_dir()


@pytest.mark.parametrize(
    "with_pip",
    [pytest.param(False, id="without-pip"), pytest.param(True, id="with-pip")],
)
def test_confirmed_deep_clean_removes_fresh_verifiable_real_virtualenv(
    tmp_path: Path, with_pip: bool
) -> None:
    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(repo, with_pip=with_pip)
    if with_pip:
        site_packages = next(environment.glob("lib/python*/site-packages"))
        assert (site_packages / "pip/_vendor/certifi/cacert.pem").is_file()

    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")

    report = report_from_stdout(result)
    assert result.returncode == 0, entry_reason(report)
    assert report["summary"]["removed_count"] == 1
    assert not environment.exists()


@pytest.mark.parametrize("python_version", ["3.11", "3.13", "3.14"])
@pytest.mark.parametrize(
    "with_pip",
    [pytest.param(False, id="without-pip"), pytest.param(True, id="with-pip")],
)
def test_confirmed_deep_clean_removes_supported_real_virtualenv_matrix(
    tmp_path: Path, python_version: str, with_pip: bool
) -> None:
    executable = shutil.which(f"python{python_version}")
    if executable is None:
        pytest.skip(f"python{python_version} is unavailable")

    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(
        repo, with_pip=with_pip, python_executable=executable
    )

    result = run_clean(
        repo,
        "deep",
        "--include-venv",
        "--confirm",
        "--json",
        python_executable=executable,
    )
    report = report_from_stdout(result)

    assert result.returncode == 0, entry_reason(report)
    assert report["summary"]["removed_count"] == 1
    assert not environment.exists()














@pytest.mark.parametrize("alternate_link", [False, True], ids=["stdlib-generated", "relative-alternate"])
def test_nested_venv_stdlib_alternate_interpreter_links_are_verified(
    tmp_path: Path, alternate_link: bool
) -> None:
    """A nested stdlib venv may link python3 to python rather than the versioned alias."""
    repo = create_checkout(tmp_path)
    outer = tmp_path / "outer"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(outer)], check=True)
    nested_python = str(outer / "bin" / "python")
    environment = make_real_virtual_environment(repo, with_pip=False, python_executable=nested_python)
    # Linux stdlib emits this relative alias when invoked through an existing venv.
    alias = environment / "bin" / "python3"
    if alternate_link:
        alias.unlink()
        alias.symlink_to("python")
    assert (environment / "bin" / "python").resolve() == Path(sys._base_executable).resolve()
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json", python_executable=nested_python)
    report = report_from_stdout(result)
    assert result.returncode == 0, entry_reason(report)
    assert not environment.exists()




def test_confirmed_local_venv_includes_operator_custom_contents(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(repo, with_pip=False)
    (environment / "personal_records.py").write_bytes(b"operator approved disposable contents")
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    report = report_from_stdout(result)
    assert result.returncode == 0, entry_reason(report)
    assert not environment.exists()
    assert "custom" in str(report).lower()


def test_deep_help_warns_all_custom_contents_are_deleted(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    result = run_clean(repo, "deep", "--help")
    assert result.returncode == 0
    assert "all" in result.stdout.lower() and "custom" in result.stdout.lower()


def test_deep_unlinks_internal_symlink_without_touching_external_target(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_real_virtual_environment(repo, with_pip=False)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"external protected bytes")
    (environment / "custom-link").symlink_to(outside)
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    assert result.returncode == 0, result.stderr
    assert outside.read_bytes() == b"external protected bytes"
    assert not environment.exists()


@pytest.mark.parametrize("configuration", ["", "home = /usr/bin\n", "include-system-site-packages = false\n", "home = \ninclude-system-site-packages = false\n"])
def test_deep_rejects_implausible_configuration(tmp_path: Path, configuration: str) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    (environment / "pyvenv.cfg").write_text(configuration)
    before = snapshot_tree(repo, [".venv"])
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    assert result.returncode != 0
    assert snapshot_tree(repo, [".venv"]) == before


def test_confirmed_deep_refuses_nested_repository(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    nested = environment / "operator-repository"
    nested.mkdir()
    git(nested, "init")
    (nested / "durable.txt").write_bytes(b"nested repository data")
    before = snapshot_tree(repo, [".venv"])
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    assert result.returncode != 0
    assert "nested Git" in str(report_from_stdout(result))
    assert snapshot_tree(repo, [".venv"]) == before


def test_confirmed_deep_preserves_nested_bare_repository(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    environment = make_virtual_environment(repo)
    git(repo, "init", "--bare", str(environment / "archive.git"))
    before = snapshot_tree(repo, [".venv"])
    result = run_clean(repo, "deep", "--include-venv", "--confirm", "--json")
    assert result.returncode != 0
    assert "nested Git" in str(report_from_stdout(result))
    assert snapshot_tree(repo, [".venv"]) == before


def test_global_dry_run_before_deep_preserves_environment(tmp_path: Path) -> None:
    repo = create_checkout(tmp_path)
    make_virtual_environment(repo)
    before = snapshot_tree(repo, [".venv"])
    result = run_clean(repo, "--dry-run", "deep", "--include-venv", "--confirm", "--json")
    report = report_from_stdout(result)
    assert result.returncode == 0
    assert report["dry_run"] is True
    assert snapshot_tree(repo, [".venv"]) == before
