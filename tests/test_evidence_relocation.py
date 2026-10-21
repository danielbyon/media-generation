"""Tests that committed T01 evidence can be relocated between checkout paths."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_relocation_repairs_runtime_paths_and_portable_snapshots(
    tmp_path: Path,
) -> None:
    """A copied evidence tree remains inspectable after its checkout path changes."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    relocated = tmp_path / "another-checkout" / "evidence" / "t01"
    relocated.parent.mkdir(parents=True)
    shutil.copytree(source, relocated)

    process = subprocess.run(
        [
            sys.executable,
            str(relocated / "relocate.py"),
            "--evidence-dir",
            str(relocated),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr

    artifact = json.loads((relocated / "artifact.json").read_text(encoding="utf-8"))
    artifact_path = relocated / "artifacts" / f"{artifact['artifact_id']}.png"
    assert artifact["path"] == f"evidence/t01/artifacts/{artifact_path.name}"
    assert artifact_path.is_file()

    database = relocated / "t01.sqlite3"
    with sqlite3.connect(database) as connection:
        stored_path, stored_hash = connection.execute(
            "SELECT path, sha256 FROM generation_artifacts WHERE artifact_id = ?",
            (artifact["artifact_id"],),
        ).fetchone()
    assert stored_path == str(artifact_path.resolve())
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == stored_hash

    provenance = json.loads((relocated / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["artifact"]["path"] == artifact["path"]
    reference = json.loads(
        (relocated / "reference_artifact.json").read_text(encoding="utf-8")
    )
    reference_path = relocated / "artifacts" / f"{reference['artifact_id']}.png"
    assert reference["path"] == f"evidence/t01/artifacts/{reference_path.name}"
    reference_provenance = json.loads(
        (relocated / "reference_provenance.json").read_text(encoding="utf-8")
    )
    assert reference_provenance["artifact"]["path"] == reference["path"]

    entry_point = Path(sys.prefix) / "bin" / "media-generation"
    inspected = subprocess.run(
        [
            str(entry_point),
            "artifact",
            "--db",
            str(database),
            "--id",
            str(artifact["artifact_id"]),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert inspected.returncode == 0, inspected.stderr
    runtime_artifact = json.loads(inspected.stdout)
    assert runtime_artifact["path"] == str(artifact_path.resolve())


def test_failed_relocation_preserves_original_database_and_snapshots(
    tmp_path: Path,
) -> None:
    """A late CLI failure must not leave a partly relocated evidence tree."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    relocated = tmp_path / "failed-checkout" / "evidence" / "t01"
    relocated.parent.mkdir(parents=True)
    shutil.copytree(source, relocated)

    reference_provenance_path = relocated / "reference_provenance.json"
    invalid_snapshot = json.loads(reference_provenance_path.read_text(encoding="utf-8"))
    invalid_snapshot["job_id"] = "job_00000000000000000000000000000000"
    reference_provenance_path.write_text(
        json.dumps(invalid_snapshot, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    database_path = relocated / "t01.sqlite3"
    original_database = database_path.read_bytes()
    original_snapshots = {
        path.name: path.read_bytes()
        for path in relocated.glob("*.json")
        if path.name != "validator-result.json"
    }

    process = subprocess.run(
        [
            sys.executable,
            str(relocated / "relocate.py"),
            "--evidence-dir",
            str(relocated),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert process.returncode != 0
    assert "installed CLI failed" in process.stderr
    assert database_path.read_bytes() == original_database
    assert {
        path.name: path.read_bytes()
        for path in relocated.glob("*.json")
        if path.name != "validator-result.json"
    } == original_snapshots
