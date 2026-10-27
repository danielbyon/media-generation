"""Helpers for exercising cleanup against disposable Git repositories.

The cleanup tests must never target the developer checkout.  These helpers make
small, fully owned Git repositories below pytest's temporary directory and copy
only the repository-side command files into them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SOURCE_ROOT = Path(__file__).resolve().parents[1]
CLEAN_SCRIPT = SOURCE_ROOT / "scripts" / "clean.py"
LOCK_SCRIPT = SOURCE_ROOT / "scripts" / "with_worktree_lock.py"
MAKEFILE = SOURCE_ROOT / "Makefile"

_GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_LITERAL_PATHSPECS": "1",
    "LC_ALL": "C",
}


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run Git in a fixture with deterministic, non-mutating optional locks."""

    environment = os.environ.copy()
    environment.update(_GIT_ENV)
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=check,
        capture_output=True,
        env=environment,
        text=True,
    )


def create_checkout(tmp_path: Path) -> Path:
    """Create a clean fixture checkout containing the command under test."""

    repo = tmp_path / "checkout"
    repo.mkdir()
    if MAKEFILE.exists():
        shutil.copy2(MAKEFILE, repo / MAKEFILE.name)
    if (SOURCE_ROOT / ".gitignore").exists():
        shutil.copy2(SOURCE_ROOT / ".gitignore", repo / ".gitignore")
    if CLEAN_SCRIPT.parent.exists():
        shutil.copytree(
            CLEAN_SCRIPT.parent,
            repo / "scripts",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )

    package = repo / "src" / "media_generation"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        '"""Fixture package used to prove build output matches source."""\n',
        encoding="utf-8",
    )
    (package / "cli.py").write_text(
        "def main() -> int:\n    return 0\n",
        encoding="utf-8",
    )
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Cleanup Test")
    git(repo, "config", "user.email", "cleanup@example.invalid")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "fixture baseline")
    return repo


def clean_environment(tmp_path: Path) -> dict[str, str]:
    """Return an environment isolated from operator and parent-Make state."""

    environment = os.environ.copy()
    environment.update(_GIT_ENV)
    environment["HOME"] = str(tmp_path / "home")
    environment["XDG_CONFIG_HOME"] = str(tmp_path / "xdg-config")
    environment.pop("VIRTUAL_ENV", None)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHON", None)
    environment.pop("MAKEFLAGS", None)
    environment.pop("MFLAGS", None)
    environment.pop("MAKELEVEL", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def run_clean(
    repo: Path,
    *arguments: str,
    cwd: Path | None = None,
    input_text: str | None = None,
    extra_env: dict[str, str] | None = None,
    python_executable: str | Path | None = None,
    timeout: float = 20.0,
) -> subprocess.CompletedProcess[str]:
    """Run the copied cleanup CLI without importing project dependencies."""

    environment = clean_environment(repo.parent)
    if extra_env:
        environment.update(extra_env)
    executable = str(python_executable) if python_executable else sys.executable
    return subprocess.run(
        [executable, str(repo / "scripts" / "clean.py"), *arguments],
        cwd=cwd or repo,
        env=environment,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_make(
    repo: Path,
    *arguments: str,
    dry_run: bool = False,
    extra_env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    """Run the fixture Makefile while preserving useful failure output."""

    environment = clean_environment(repo.parent)
    if extra_env:
        environment.update(extra_env)
    command = ["make", *arguments]
    if dry_run:
        command.insert(1, "-n")
    return subprocess.run(
        command,
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def report_from_stdout(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse the single JSON document required from ``--json``."""

    return json.loads(result.stdout)


def write_bytecode_cache(package: Path, *, module: str = "sample") -> Path:
    """Create a cache shaped like the one produced by CPython."""

    cache = package / "__pycache__"
    cache.mkdir(parents=True)
    (cache / f"{module}.cpython-311.pyc").write_bytes(b"bytecode")
    return cache


def write_pytest_cache(repo: Path) -> Path:
    """Create a pytest cache carrying pytest's cache-directory signature."""

    cache = repo / ".pytest_cache"
    (cache / "v" / "cache").mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text(
        "Signature: 8a477f597d28d172789f06886806bc55\n"
        "# This file is a cache directory tag created by pytest.\n",
        encoding="ascii",
    )
    (cache / "README.md").write_text("generated pytest cache\n", encoding="utf-8")
    (cache / "v" / "cache" / "nodeids").write_text("[]\n", encoding="utf-8")
    return cache


def write_egg_info(repo: Path) -> Path:
    """Create the exact setuptools metadata directory owned by this project."""

    metadata = repo / "src" / "media_generation.egg-info"
    metadata.mkdir(parents=True)
    (metadata / "PKG-INFO").write_text(
        "Metadata-Version: 2.4\nName: media-generation\nVersion: 0.1.0\n",
        encoding="utf-8",
    )
    (metadata / "top_level.txt").write_text("media_generation\n", encoding="utf-8")
    (metadata / "SOURCES.txt").write_text(
        "src/media_generation/__init__.py\n",
        encoding="utf-8",
    )
    return metadata


def write_safe_build(repo: Path) -> Path:
    """Create setuptools build output whose package files match ``src``."""

    source = repo / "src" / "media_generation"
    output = repo / "build" / "lib" / "media_generation"
    output.mkdir(parents=True)
    for source_file in sorted(source.glob("*.py")):
        shutil.copy2(source_file, output / source_file.name)
    return repo / "build"


def snapshot_tree(root: Path, paths: Iterable[str] | None = None) -> dict[str, tuple[Any, ...]]:
    """Capture content and important metadata while excluding caches under test."""

    selected = None if paths is None else set(paths)
    result: dict[str, tuple[Any, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if selected is not None and relative not in selected and not any(
            relative.startswith(f"{prefix}/") for prefix in selected
        ):
            continue
        stat_result = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        result[relative] = (
            stat_result.st_mode,
            stat_result.st_size,
            stat_result.st_mtime_ns,
            content,
            os.readlink(path) if path.is_symlink() else None,
        )
    return result
