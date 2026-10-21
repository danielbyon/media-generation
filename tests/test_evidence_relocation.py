"""Tests that committed T01 evidence can be relocated between checkout paths."""

from __future__ import annotations

import hashlib
import errno
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

import pytest

from evidence.t01 import relocate as relocation
from media_generation.domain import GenerationRequest
from media_generation.errors import IdempotencyConflictError
from media_generation.service import GenerationService


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
        idempotency_key = connection.execute(
            "SELECT idempotency_key FROM generation_jobs WHERE job_id = ?",
            (artifact["job_id"],),
        ).fetchone()[0]
        attempts_before = connection.execute(
            "SELECT COUNT(*) FROM generation_attempts WHERE job_id = ?",
            (artifact["job_id"],),
        ).fetchone()[0]
        effective_parameters = json.loads(
            connection.execute(
                "SELECT effective_parameters_json FROM generation_jobs WHERE job_id = ?",
                (artifact["job_id"],),
            ).fetchone()[0]
        )
    assert stored_path == str(artifact_path.resolve())
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == stored_hash
    assert effective_parameters["_resolved_output_directory"] == str(
        artifact_path.parent.resolve()
    )

    request_snapshot = json.loads(
        (relocated / "request.json").read_text(encoding="utf-8")
    )
    request = GenerationRequest(
        prompt=request_snapshot["prompt"],
        seed=request_snapshot["seed"],
        width=request_snapshot["width"],
        height=request_snapshot["height"],
        reference_ids=tuple(request_snapshot["reference_ids"]),
        output_slot=request_snapshot["output_slot"],
    )
    replay = GenerationService(database, relocated / "artifacts").submit(
        idempotency_key, request
    )
    assert replay.job_id == artifact["job_id"]
    assert replay.artifact_id == artifact["artifact_id"]
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM generation_attempts WHERE job_id = ?",
            (artifact["job_id"],),
        ).fetchone()[0] == attempts_before
    with pytest.raises(IdempotencyConflictError, match="output directory"):
        GenerationService(database, relocated / "other-artifacts").submit(
            idempotency_key, request
        )

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

    executable_suffix = ".exe" if os.name == "nt" else ""
    entry_point = Path(sysconfig.get_path("scripts")) / f"media-generation{executable_suffix}"
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


@pytest.mark.parametrize(
    "payload",
    [None, [], "snapshot", 17, {}, {"request_id": None}, {"request_id": ""}, {"request_id": "   "}],
)
def test_invalid_snapshot_identity_leaves_evidence_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    """Malformed snapshot shapes and identities fail before evidence is staged."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    request_path = evidence_dir / "request.json"
    request_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    sentinel = evidence_dir / "preserve.txt"
    sentinel.write_text("original evidence\n", encoding="utf-8")
    original_files = {
        path.relative_to(evidence_dir): path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(relocation, "_console_script", lambda: Path(sys.executable))

    with pytest.raises(ValueError, match="request.json"):
        relocation.relocate(evidence_dir)

    assert {
        path.relative_to(evidence_dir): path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    } == original_files


def test_invalid_snapshot_json_has_a_controlled_error_and_preserves_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid JSON reports the snapshot path without changing its evidence tree."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    request_path = evidence_dir / "request.json"
    request_path.write_text("{not-json\n", encoding="utf-8")
    original = request_path.read_bytes()
    monkeypatch.setattr(relocation, "_console_script", lambda: Path(sys.executable))

    with pytest.raises(ValueError, match="request.json"):
        relocation.relocate(evidence_dir)

    assert request_path.read_bytes() == original
    assert sorted(path.name for path in evidence_dir.iterdir()) == ["request.json"]


def _run_with_relocation_interruption(
    evidence_dir: Path,
    working_directory: Path,
    interruption: str,
) -> subprocess.CompletedProcess[str]:
    """Exit the relocation process at one directory-replacement boundary."""
    injector_dir = working_directory / f"fault-injector-{interruption}"
    injector_dir.mkdir()
    (injector_dir / "sitecustomize.py").write_text(
        """import os
import shutil
from pathlib import Path

target = Path(os.environ['T01_EVIDENCE_TARGET']).resolve()
mode = os.environ['T01_INTERRUPTION']
real_replace = os.replace
real_rmtree = shutil.rmtree
state_path = target.parent / f'.{target.name}.relocation-state.json'

def interrupted_replace(source, destination):
    source_path = Path(source)
    destination_path = Path(destination)
    is_stage_install = (
        source_path.parent == target.parent
        and source_path.name.startswith(f'.{target.name}.relocating-')
        and destination_path == target
    )
    is_cleanup_checkpoint = (
        source_path.parent == target.parent
        and source_path.name.startswith(f'.{target.name}.relocation-state-')
        and source_path.suffix == '.tmp'
        and destination_path == state_path
    )
    if mode == 'before' and source_path == target and destination_path.name.startswith(
        f'.{target.name}.previous-'
    ):
        os._exit(71)
    if mode == 'between' and is_stage_install:
        os._exit(72)
    result = real_replace(source, destination)
    if mode == 'after' and is_stage_install:
        os._exit(73)
    if mode == 'checkpoint' and is_cleanup_checkpoint:
        os._exit(75)
    return result

os.replace = interrupted_replace

def interrupted_rmtree(path, *args, **kwargs):
    source_path = Path(path)
    is_previous_tree = (
        source_path.parent == target.parent
        and source_path.name.startswith(f'.{target.name}.previous-')
    )
    is_staging_tree = (
        source_path.parent == target.parent
        and source_path.name.startswith(f'.{target.name}.relocating-')
    )
    if mode == 'partial_cleanup' and is_previous_tree:
        (source_path / 'request.json').unlink()
        os._exit(76)
    if mode == 'partial_staging_cleanup' and is_staging_tree:
        (source_path / 'request.json').unlink()
        os._exit(77)
    result = real_rmtree(path, *args, **kwargs)
    if mode == 'cleanup' and is_previous_tree:
        os._exit(74)
    return result

shutil.rmtree = interrupted_rmtree
""",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(injector_dir)
    environment["T01_EVIDENCE_TARGET"] = str(evidence_dir.resolve())
    environment["T01_INTERRUPTION"] = interruption
    return subprocess.run(
        [
            sys.executable,
            str(evidence_dir / "relocate.py"),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=working_directory,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _assert_relocated_tree_is_consistent(evidence_dir: Path) -> None:
    """Check that relocated snapshots, SQLite rows, and artifact bytes agree."""
    artifact = json.loads((evidence_dir / "artifact.json").read_text(encoding="utf-8"))
    artifact_path = evidence_dir / "artifacts" / f"{artifact['artifact_id']}.png"
    assert artifact_path.is_file()
    with sqlite3.connect(evidence_dir / "t01.sqlite3") as connection:
        stored_path, stored_hash = connection.execute(
            "SELECT path, sha256 FROM generation_artifacts WHERE artifact_id = ?",
            (artifact["artifact_id"],),
        ).fetchone()
    assert stored_path == str(artifact_path.resolve())
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == stored_hash


@pytest.mark.parametrize(
    ("interruption", "exit_code"),
    [
        ("before", 71),
        ("between", 72),
        ("after", 73),
        ("checkpoint", 75),
        ("cleanup", 74),
        ("partial_cleanup", 76),
    ],
)
def test_relocation_recovers_after_process_interruption(
    tmp_path: Path,
    interruption: str,
    exit_code: int,
) -> None:
    """A later invocation recovers each interrupted directory replacement safely."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    previous = next(evidence_dir.glob("artifacts/*.png"))
    original_hash = hashlib.sha256(previous.read_bytes()).hexdigest()

    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, interruption)

    assert interrupted.returncode == exit_code
    state_path = evidence_dir.parent / ".t01.relocation-state.json"
    assert state_path.is_file()
    if interruption in {"checkpoint", "cleanup", "partial_cleanup"}:
        recovery_state = json.loads(state_path.read_text(encoding="utf-8"))
        assert recovery_state["phase"] == "cleanup_pending"
    if interruption == "before":
        assert hashlib.sha256(next(evidence_dir.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
        assert list(evidence_dir.parent.glob(".t01.previous-*")) == []
    elif interruption == "between":
        assert not evidence_dir.exists()
        backup = next(evidence_dir.parent.glob(".t01.previous-*"))
        assert hashlib.sha256(next(backup.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
    elif interruption == "after":
        backup = next(evidence_dir.parent.glob(".t01.previous-*"))
        assert hashlib.sha256(next(backup.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
    elif interruption == "checkpoint":
        assert evidence_dir.is_dir()
        assert len(list(evidence_dir.parent.glob(".t01.previous-*"))) == 1
    elif interruption == "partial_cleanup":
        backup = next(evidence_dir.parent.glob(".t01.previous-*"))
        assert evidence_dir.is_dir()
        assert not (backup / "request.json").exists()
        assert next(backup.glob("artifacts/*.png")).is_file()
    else:  # backup cleanup completed before the process exited
        assert evidence_dir.is_dir()
        assert list(evidence_dir.parent.glob(".t01.previous-*")) == []

    recovered = subprocess.run(
        [
            sys.executable,
            str(evidence_dir / "relocate.py")
            if evidence_dir.exists()
            else str(next(evidence_dir.parent.glob(".t01.previous-*/relocate.py"))),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert recovered.returncode == 0, recovered.stderr
    assert not state_path.exists()
    assert list(evidence_dir.parent.glob(".t01.previous-*")) == []
    assert list(evidence_dir.parent.glob(".t01.relocating-*")) == []
    _assert_relocated_tree_is_consistent(evidence_dir)


def test_partial_backup_is_preserved_when_installed_target_is_untrusted(
    tmp_path: Path,
) -> None:
    """Recovery never removes remaining backup evidence if target integrity fails."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)

    interrupted = _run_with_relocation_interruption(
        evidence_dir, tmp_path, "partial_cleanup"
    )
    assert interrupted.returncode == 76
    backup = next(evidence_dir.parent.glob(".t01.previous-*"))
    remaining_artifact = next(backup.glob("artifacts/*.png"))
    remaining_hash = hashlib.sha256(remaining_artifact.read_bytes()).hexdigest()
    assert not (backup / "request.json").exists()

    (evidence_dir / "untrusted-target-change.txt").write_text(
        "do not clean the backup\n", encoding="utf-8"
    )
    retry = subprocess.run(
        [
            sys.executable,
            str(evidence_dir / "relocate.py"),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert retry.returncode != 0
    assert "ambiguous" in retry.stderr.lower()
    assert remaining_artifact.is_file()
    assert hashlib.sha256(remaining_artifact.read_bytes()).hexdigest() == remaining_hash
    assert (evidence_dir / "untrusted-target-change.txt").is_file()
    assert (evidence_dir.parent / ".t01.relocation-state.json").is_file()


def test_modified_partial_backup_is_preserved_with_a_complete_target(
    tmp_path: Path,
) -> None:
    """A complete target does not authorize deleting an unexpected backup change."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)

    interrupted = _run_with_relocation_interruption(
        evidence_dir, tmp_path, "partial_cleanup"
    )
    assert interrupted.returncode == 76
    backup = next(evidence_dir.parent.glob(".t01.previous-*"))
    remaining_artifact = next(backup.glob("artifacts/*.png"))
    remaining_hash = hashlib.sha256(remaining_artifact.read_bytes()).hexdigest()
    unexpected = backup / "manual-change.txt"
    unexpected.write_text("preserve ambiguous backup data\n", encoding="utf-8")

    retry = subprocess.run(
        [
            sys.executable,
            str(evidence_dir / "relocate.py"),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert retry.returncode != 0
    assert "ambiguous" in retry.stderr.lower()
    assert unexpected.read_text(encoding="utf-8") == "preserve ambiguous backup data\n"
    assert remaining_artifact.is_file()
    assert hashlib.sha256(remaining_artifact.read_bytes()).hexdigest() == remaining_hash
    _assert_relocated_tree_is_consistent(evidence_dir)
    assert (evidence_dir.parent / ".t01.relocation-state.json").is_file()


@pytest.mark.parametrize("interruption", ["between", "after"])
def test_recovery_preserves_ambiguous_stale_evidence(
    tmp_path: Path,
    interruption: str,
) -> None:
    """Changed journal-owned trees stop recovery without deleting the valid copy."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_artifact = next(evidence_dir.glob("artifacts/*.png"))
    original_hash = hashlib.sha256(original_artifact.read_bytes()).hexdigest()

    exit_code = 72 if interruption == "between" else 73
    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, interruption)
    assert interrupted.returncode == exit_code

    if interruption == "between":
        original_tree = next(evidence_dir.parent.glob(".t01.previous-*"))
        retry_script = original_tree / "relocate.py"
    else:
        original_tree = next(evidence_dir.parent.glob(".t01.previous-*"))
        retry_script = evidence_dir / "relocate.py"
    manual_evidence = original_tree / "manual-change.txt"
    manual_evidence.write_text("preserve this unreviewed change\n", encoding="utf-8")

    retry = subprocess.run(
        [sys.executable, str(retry_script), "--evidence-dir", str(evidence_dir)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert retry.returncode != 0
    assert "ambiguous" in retry.stderr.lower()
    assert manual_evidence.read_text(encoding="utf-8") == "preserve this unreviewed change\n"
    assert hashlib.sha256(next(original_tree.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
    assert (evidence_dir.parent / ".t01.relocation-state.json").is_file()
    if interruption == "between":
        assert not evidence_dir.exists()
        assert list(evidence_dir.parent.glob(".t01.relocating-*"))
    else:
        assert evidence_dir.is_dir()
        assert not (evidence_dir / "manual-change.txt").exists()


def test_ambiguous_recovery_preserves_original_backup(
    tmp_path: Path,
) -> None:
    """Unexpected evidence at the target blocks recovery without deleting backup."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    artifact_file = next(evidence_dir.glob("artifacts/*.png"))
    original_hash = hashlib.sha256(artifact_file.read_bytes()).hexdigest()

    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, "between")
    assert interrupted.returncode == 72
    backup = next(evidence_dir.parent.glob(".t01.previous-*"))
    evidence_dir.mkdir()
    (evidence_dir / "unexpected.txt").write_text("preserve\n", encoding="utf-8")

    retry = subprocess.run(
        [
            sys.executable,
            str(backup / "relocate.py"),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert retry.returncode != 0
    assert "ambiguous" in retry.stderr.lower()
    assert (evidence_dir / "unexpected.txt").read_text(encoding="utf-8") == "preserve\n"
    assert hashlib.sha256(next(backup.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
    assert (evidence_dir.parent / ".t01.relocation-state.json").is_file()


@pytest.mark.parametrize("interruption", ["between", "after"])
def test_tampered_staging_tree_never_replaces_or_deletes_original(
    tmp_path: Path,
    interruption: str,
) -> None:
    """Recovery rejects changed staged bytes while preserving the original backup."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_artifact = next(evidence_dir.glob("artifacts/*.png"))
    original_hash = hashlib.sha256(original_artifact.read_bytes()).hexdigest()

    exit_code = 72 if interruption == "between" else 73
    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, interruption)
    assert interrupted.returncode == exit_code
    backup = next(evidence_dir.parent.glob(".t01.previous-*"))
    if interruption == "between":
        staged_tree = next(evidence_dir.parent.glob(".t01.relocating-*"))
        retry_script = backup / "relocate.py"
        assert not evidence_dir.exists()
    else:
        staged_tree = evidence_dir
        retry_script = evidence_dir / "relocate.py"
    tampered_file = staged_tree / "tampered-during-recovery.txt"
    tampered_file.write_text("untrusted staged bytes\n", encoding="utf-8")

    retry = subprocess.run(
        [sys.executable, str(retry_script), "--evidence-dir", str(evidence_dir)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert retry.returncode != 0
    assert "ambiguous" in retry.stderr.lower()
    assert tampered_file.read_text(encoding="utf-8") == "untrusted staged bytes\n"
    assert hashlib.sha256(next(backup.glob("artifacts/*.png")).read_bytes()).hexdigest() == original_hash
    assert (evidence_dir.parent / ".t01.relocation-state.json").is_file()
    if interruption == "between":
        assert not evidence_dir.exists()
        assert staged_tree.is_dir()
    else:
        assert evidence_dir.is_dir()
        assert staged_tree is evidence_dir


def test_interrupted_staging_cleanup_resumes_only_with_intact_original(
    tmp_path: Path,
) -> None:
    """Recovery resumes partial staging deletion only while the original is intact."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = {
        path.relative_to(evidence_dir): path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    }

    interrupted_before_rename = _run_with_relocation_interruption(
        evidence_dir, tmp_path, "before"
    )
    assert interrupted_before_rename.returncode == 71

    interrupted_cleanup = _run_with_relocation_interruption(
        evidence_dir, tmp_path, "partial_staging_cleanup"
    )
    assert interrupted_cleanup.returncode == 77
    assert {
        path.relative_to(evidence_dir): path.read_bytes()
        for path in evidence_dir.rglob("*")
        if path.is_file()
    } == original_files
    journal_path = evidence_dir.parent / ".t01.relocation-state.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["phase"] == "staging_cleanup_pending"
    staging_dirs = list(evidence_dir.parent.glob(".t01.relocating-*"))
    assert len(staging_dirs) == 1
    assert not (staging_dirs[0] / "request.json").exists()

    recovered = subprocess.run(
        [
            sys.executable,
            str(evidence_dir / "relocate.py"),
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )

    assert recovered.returncode == 0, recovered.stderr
    assert not journal_path.exists()
    assert list(evidence_dir.parent.glob(".t01.relocation-state-*.tmp")) == []
    assert list(evidence_dir.parent.glob(".t01.relocating-*")) == []
    assert list(evidence_dir.parent.glob(".t01.previous-*")) == []
    _assert_relocated_tree_is_consistent(evidence_dir)


def test_concurrent_relocation_is_rejected_without_touching_live_staging(
    tmp_path: Path,
) -> None:
    """A second process cannot recover or replace a tree staged by the first."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    snapshot_ids = {
        filename: json.loads((evidence_dir / filename).read_text(encoding="utf-8"))[
            identity_key
        ]
        for filename, _, identity_key in relocation._SNAPSHOTS
    }

    injector_dir = tmp_path / "lock-injector"
    injector_dir.mkdir()
    (injector_dir / "sitecustomize.py").write_text(
        """import os
import shutil
import time
from pathlib import Path

target = Path(os.environ['T01_EVIDENCE_TARGET']).resolve()
stage_ready = Path(os.environ['T01_STAGE_READY'])
stage_release = Path(os.environ['T01_STAGE_RELEASE'])
real_copytree = shutil.copytree

def pause_after_staging(source, destination, *args, **kwargs):
    result = real_copytree(source, destination, *args, **kwargs)
    destination_path = Path(destination).resolve()
    if (
        destination_path.parent == target.parent
        and destination_path.name.startswith(f'.{target.name}.relocating-')
    ):
        stage_ready.write_text('ready', encoding='utf-8')
        deadline = time.monotonic() + 30
        while not stage_release.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not stage_release.exists():
            raise TimeoutError('test did not release staged relocation')
    return result

shutil.copytree = pause_after_staging
""",
        encoding="utf-8",
    )
    stage_ready = tmp_path / "stage-ready"
    stage_release = tmp_path / "stage-release"
    first_environment = os.environ.copy()
    first_environment["PYTHONPATH"] = os.pathsep.join(
        value
        for value in (str(injector_dir), first_environment.get("PYTHONPATH", ""))
        if value
    )
    first_environment["T01_EVIDENCE_TARGET"] = str(evidence_dir.resolve())
    first_environment["T01_STAGE_READY"] = str(stage_ready)
    first_environment["T01_STAGE_RELEASE"] = str(stage_release)
    first_environment["T01_PAUSE_AFTER_STAGE"] = "1"
    command = [
        sys.executable,
        str(evidence_dir / "relocate.py"),
        "--evidence-dir",
        str(evidence_dir),
    ]
    first = subprocess.Popen(
        command,
        cwd=tmp_path,
        env=first_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_stdout = ""
    first_stderr = ""
    try:
        deadline = time.monotonic() + 20
        while not stage_ready.exists():
            if first.poll() is not None:
                first_stdout, first_stderr = first.communicate()
                pytest.fail(
                    "first relocation exited before staging pause: "
                    f"{first_stdout}\n{first_stderr}"
                )
            if time.monotonic() >= deadline:
                pytest.fail("first relocation did not reach the pre-journal staging pause")
            time.sleep(0.01)

        journal_path = evidence_dir.parent / ".t01.relocation-state.json"
        assert not journal_path.exists()
        assert list(evidence_dir.parent.glob(".t01.relocation-state-*.tmp")) == []
        assert len(list(evidence_dir.parent.glob(".t01.relocating-*"))) == 1

        second = subprocess.run(
            command,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert second.returncode == 1
        assert "another relocation is already running" in second.stderr.lower()
        assert len(list(evidence_dir.parent.glob(".t01.relocating-*"))) == 1
        assert not journal_path.exists()
    finally:
        stage_release.write_text("continue", encoding="utf-8")
        first_stdout, first_stderr = first.communicate(timeout=60)

    assert first.returncode == 0, f"{first_stdout}\n{first_stderr}"
    _assert_relocated_tree_is_consistent(evidence_dir)
    for filename, _, identity_key in relocation._SNAPSHOTS:
        snapshot = json.loads((evidence_dir / filename).read_text(encoding="utf-8"))
        assert snapshot[identity_key] == snapshot_ids[filename]

    assert not (evidence_dir.parent / ".t01.relocation-state.json").exists()
    assert list(evidence_dir.parent.glob(".t01.relocation-state-*.tmp")) == []
    assert list(evidence_dir.parent.glob(".t01.relocating-*")) == []
    assert list(evidence_dir.parent.glob(".t01.previous-*")) == []

    subsequent = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )
    assert subsequent.returncode == 0, subsequent.stderr
    _assert_relocated_tree_is_consistent(evidence_dir)
    assert list(evidence_dir.parent.glob(".t01.relocating-*")) == []
    assert list(evidence_dir.parent.glob(".t01.previous-*")) == []


def test_relocation_lock_releases_after_an_exception(tmp_path: Path) -> None:
    """A failed relocation releases its OS lock for the next invocation."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)

    with pytest.raises(ValueError, match="injected failure"):
        with relocation._relocation_lock(evidence_dir):
            raise ValueError("injected failure")

    with relocation._relocation_lock(evidence_dir):
        pass


def test_directory_fsync_reports_success_and_unsupported_platforms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Directory sync reports whether the platform accepted the durability request."""
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(
        relocation.os,
        "open",
        lambda path, flags: events.append(("open", Path(path))) or 41,
    )
    monkeypatch.setattr(
        relocation.os,
        "fsync",
        lambda descriptor: events.append(("fsync", descriptor)),
    )
    monkeypatch.setattr(
        relocation.os,
        "close",
        lambda descriptor: events.append(("close", descriptor)),
    )

    assert relocation._fsync_directory(tmp_path) is True
    assert events == [
        ("open", tmp_path),
        ("fsync", 41),
        ("close", 41),
    ]

    def unsupported_fsync(_: int) -> None:
        raise OSError(errno.EINVAL, "directory fsync is unsupported")

    monkeypatch.setattr(relocation.os, "fsync", unsupported_fsync)
    assert relocation._fsync_directory(tmp_path) is False


def test_tree_replacement_syncs_parent_after_namespace_mutations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Journal and tree namespace changes are followed by parent-directory sync."""
    evidence_dir = tmp_path / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "original.txt").write_text("original\n", encoding="utf-8")
    staging_dir = tmp_path / ".t01.relocating-test"
    staging_dir.mkdir()
    (staging_dir / "staged.txt").write_text("staged\n", encoding="utf-8")
    events: list[tuple[str, Path]] = []
    real_link = relocation.os.link
    real_replace = relocation.os.replace
    real_rmtree = relocation.shutil.rmtree
    real_unlink = Path.unlink
    real_rmdir = Path.rmdir

    def record_link(source: object, destination: object, *args: object, **kwargs: object) -> None:
        real_link(source, destination, *args, **kwargs)
        events.append(("link", Path(destination)))

    def record_replace(source: object, destination: object, *args: object, **kwargs: object) -> None:
        real_replace(source, destination, *args, **kwargs)
        events.append(("replace", Path(destination)))

    def record_rmtree(path: object, *args: object, **kwargs: object) -> None:
        real_rmtree(path, *args, **kwargs)
        events.append(("rmtree", Path(path)))

    def record_unlink(path: Path, *args: object, **kwargs: object) -> None:
        existed = path.exists()
        real_unlink(path, *args, **kwargs)
        if existed:
            events.append(("unlink", path))

    def record_rmdir(path: Path, *args: object, **kwargs: object) -> None:
        real_rmdir(path, *args, **kwargs)
        events.append(("rmdir", path))

    monkeypatch.setattr(relocation.os, "link", record_link)
    monkeypatch.setattr(relocation.os, "replace", record_replace)
    monkeypatch.setattr(relocation.shutil, "rmtree", record_rmtree)
    monkeypatch.setattr(Path, "unlink", record_unlink)
    monkeypatch.setattr(Path, "rmdir", record_rmdir)
    monkeypatch.setattr(
        relocation,
        "_fsync_directory",
        lambda path: events.append(("fsync", Path(path))) or True,
    )

    relocation._replace_evidence_tree(evidence_dir, staging_dir)

    mutations = {"link", "replace", "rmtree", "unlink", "rmdir"}
    for index, (operation, _) in enumerate(events):
        if operation in mutations:
            assert events[index + 1] == ("fsync", evidence_dir.parent)
    assert any(operation == "link" for operation, _ in events)
    assert sum(operation == "replace" for operation, _ in events) >= 3
    assert any(operation == "rmtree" for operation, _ in events)
    assert any(operation == "unlink" for operation, _ in events)
