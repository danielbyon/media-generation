"""Relocate the T01 evidence database and regenerate portable snapshots.

The SQLite service stores resolved runtime artifact paths. This utility repairs
those paths for the current checkout, verifies every artifact against its saved
SHA-256 digest, and rewrites the committed JSON snapshots with repository-relative
paths so the evidence remains inspectable after a checkout moves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

from media_generation.store import SQLiteStore


_SNAPSHOTS = (
    ("request.json", "request", "request_id"),
    ("job.json", "job", "job_id"),
    ("artifact.json", "artifact", "artifact_id"),
    ("provenance.json", "provenance", "job_id"),
    ("reference_request.json", "request", "request_id"),
    ("reference_job.json", "job", "job_id"),
    ("reference_artifact.json", "artifact", "artifact_id"),
    ("reference_provenance.json", "provenance", "job_id"),
)


def _console_script() -> Path:
    """Locate the installed CLI beside the Python interpreter running this tool."""
    suffix = ".exe" if os.name == "nt" else ""
    return Path(sysconfig.get_path("scripts")) / f"media-generation{suffix}"


def _read_snapshot_id(evidence_dir: Path, filename: str, key: str) -> str:
    """Read a stable record identity from the existing portable snapshot."""
    payload = json.loads((evidence_dir / filename).read_text(encoding="utf-8"))
    identity = payload.get(key)
    if not isinstance(identity, str) or not identity:
        raise ValueError(f"{filename} does not contain a non-empty {key}")
    return identity


def _run_cli(
    entry_point: Path,
    repository_root: Path,
    database_path: Path,
    command: str,
    identity: str,
) -> dict[str, Any]:
    """Retrieve one record through the installed black-box CLI."""
    if command == "provenance":
        arguments = ["provenance", "--db", str(database_path), "--job-id", identity]
    else:
        arguments = [command, "--db", str(database_path), "--id", identity]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    process = subprocess.run(
        [str(entry_point), *arguments],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"installed CLI failed for {command} {identity}: {process.stderr.strip()}"
        )
    response = json.loads(process.stdout)
    if not isinstance(response, dict):
        raise ValueError(f"installed CLI returned a non-object for {command} {identity}")
    return response


def _portable_paths(value: Any, repository_root: Path) -> Any:
    """Replace absolute artifact paths in snapshots with repository-relative paths."""
    if isinstance(value, dict):
        return {
            key: _portable_paths(item, repository_root)
            if key != "path"
            else _portable_path(item, repository_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_portable_paths(item, repository_root) for item in value]
    return value


def _portable_path(value: Any, repository_root: Path) -> Any:
    if not isinstance(value, str):
        return value
    path = Path(value)
    if not path.is_absolute():
        return value
    try:
        return path.resolve().relative_to(repository_root).as_posix()
    except ValueError as error:
        raise ValueError(f"artifact path is outside the checkout: {value}") from error


def _relocate_database(
    database_path: Path,
    artifact_source_dir: Path,
    runtime_artifact_dir: Path,
) -> int:
    """Build a staged database with verified files and final runtime paths."""
    temporary_path = database_path.with_name(f".{database_path.name}.relocating")
    temporary_path.unlink(missing_ok=True)
    SQLiteStore(temporary_path)
    tables = (
        "generation_requests",
        "generation_jobs",
        "generation_attempts",
        "generation_artifacts",
    )
    try:
        with sqlite3.connect(database_path) as source, sqlite3.connect(
            temporary_path
        ) as destination:
            destination.execute("PRAGMA foreign_keys = ON")
            destination.execute("BEGIN IMMEDIATE")
            artifact_count = 0
            for table in tables:
                columns = [
                    str(row[1])
                    for row in source.execute(f"PRAGMA table_info({table})").fetchall()
                ]
                if not columns:
                    raise ValueError(f"evidence database is missing table {table}")
                column_list = ", ".join(columns)
                placeholders = ", ".join("?" for _ in columns)
                rows = source.execute(f"SELECT {column_list} FROM {table}").fetchall()
                if table == "generation_artifacts":
                    artifact_id_index = columns.index("artifact_id")
                    path_index = columns.index("path")
                    hash_index = columns.index("sha256")
                    for index, original in enumerate(rows):
                        row = list(original)
                        artifact_id = str(row[artifact_id_index])
                        artifact_path = artifact_source_dir / f"{artifact_id}.png"
                        if not artifact_path.is_file():
                            raise FileNotFoundError(
                                f"evidence artifact is missing: {artifact_path}"
                            )
                        actual_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                        if actual_sha256 != row[hash_index]:
                            raise ValueError(
                                f"evidence artifact has an unexpected hash: {artifact_path}"
                            )
                        runtime_path = runtime_artifact_dir / artifact_path.name
                        row[path_index] = str(runtime_path.resolve())
                        rows[index] = tuple(row)
                    artifact_count = len(rows)
                destination.executemany(
                    f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})",
                    rows,
                )
            violations = destination.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise ValueError(f"relocated evidence violates foreign keys: {violations}")
        os.replace(temporary_path, database_path)
        return artifact_count
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def relocate(evidence_dir: Path) -> int:
    """Stage, validate, and atomically replace the relocated evidence tree."""
    evidence_dir = evidence_dir.expanduser().resolve()
    if len(evidence_dir.parents) < 2:
        raise ValueError("evidence directory must be nested as <checkout>/evidence/t01")
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"evidence directory does not exist: {evidence_dir}")
    repository_root = evidence_dir.parents[1]
    entry_point = _console_script()
    if not entry_point.is_file():
        raise FileNotFoundError(
            f"installed media-generation command not found at {entry_point}; "
            "install with python -m pip install -e '.[test]'"
        )

    identities = [
        (filename, command, identity_key, _read_snapshot_id(evidence_dir, filename, identity_key))
        for filename, command, identity_key in _SNAPSHOTS
    ]
    staging_dir = Path(
        tempfile.mkdtemp(prefix=f".{evidence_dir.name}.relocating-", dir=evidence_dir.parent)
    )
    backup_dir: Path | None = None
    try:
        shutil.copytree(evidence_dir, staging_dir, dirs_exist_ok=True)
        staged_database = staging_dir / "t01.sqlite3"
        artifact_count = _relocate_database(
            staged_database,
            staging_dir / "artifacts",
            evidence_dir / "artifacts",
        )

        for filename, command, identity_key, identity in identities:
            response = _run_cli(
                entry_point,
                repository_root,
                staged_database,
                command,
                identity,
            )
            if response.get(identity_key) != identity:
                raise ValueError(
                    f"installed CLI returned an unexpected identity for {command} {identity}"
                )
            portable_response = _portable_paths(response, repository_root)
            rendered = (
                json.dumps(
                    portable_response,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            (staging_dir / filename).write_text(rendered, encoding="utf-8")

        backup_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{evidence_dir.name}.previous-",
                dir=evidence_dir.parent,
            )
        )
        backup_dir.rmdir()
        try:
            os.replace(evidence_dir, backup_dir)
        except BaseException:
            backup_dir.rmdir()
            backup_dir = None
            raise
        try:
            os.replace(staging_dir, evidence_dir)
        except BaseException:
            try:
                os.replace(backup_dir, evidence_dir)
                backup_dir = None
            except OSError as rollback_error:
                raise RuntimeError(
                    "could not install relocated evidence; the original tree is "
                    f"preserved at {backup_dir}: {rollback_error}"
                ) from rollback_error
            raise
        shutil.rmtree(backup_dir, ignore_errors=True)
        backup_dir = None
    finally:
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)

    print(
        f"Relocated {artifact_count} artifact paths and refreshed "
        f"{len(_SNAPSHOTS)} snapshots."
    )
    return 0


def main() -> int:
    """Run the T01 evidence relocation command."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="T01 evidence directory (defaults to this script's directory)",
    )
    options = parser.parse_args()
    return relocate(options.evidence_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"T01 evidence relocation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
