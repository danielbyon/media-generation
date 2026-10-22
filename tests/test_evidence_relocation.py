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
    injector_dir.mkdir(exist_ok=True)
    (injector_dir / "sitecustomize.py").write_text(
        """import os
import json
import shutil
from pathlib import Path

target = Path(os.environ['T01_EVIDENCE_TARGET']).resolve()
mode = os.environ['T01_INTERRUPTION']
real_replace = os.replace
real_link = os.link
real_unlink = os.unlink
real_rmtree = shutil.rmtree
real_copy2 = shutil.copy2
real_copytree = shutil.copytree
real_mkdir = Path.mkdir
copied_files = 0
state_path = target.parent / f'.{target.name}.relocation-state.json'
owner_path = target.parent / f'.{target.name}.relocation-owner.json'

def staging_root(path):
    candidate = Path(path)
    for parent in (candidate, *candidate.parents):
        if (
            parent.parent == target.parent
            and parent.name.startswith(f'.{target.name}.relocating-')
        ):
            return parent
    return None

def interrupted_mkdir(path, mode=0o777, parents=False, exist_ok=False):
    is_staging_path = (
        path.parent == target.parent
        and path.name.startswith(f'.{target.name}.relocating-')
    )
    if globals()['mode'] == 'reserved' and is_staging_path:
        os._exit(80)
    result = real_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)
    return result

Path.mkdir = interrupted_mkdir

def interrupted_link(source, destination, *args, **kwargs):
    if mode == 'owner_temp' and Path(destination) == owner_path:
        os._exit(85)
    if (
        mode == 'journal_temp'
        and Path(destination) == state_path
        and Path(source).parent == target.parent
        and Path(source).name.startswith(f'.{target.name}.relocation-state-')
        and Path(source).suffix == '.tmp'
    ):
        os._exit(86)
    if mode == 'prepared' and Path(destination) == state_path:
        os._exit(83)
    return real_link(source, destination, *args, **kwargs)

os.link = interrupted_link

def interrupted_unlink(path, *args, **kwargs):
    if mode == 'owner_partial_cleanup' and kwargs.get('dir_fd') is not None:
        try:
            owner = json.loads(owner_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            owner = {}
        if owner.get('phase') == 'cleanup_pending':
            result = real_unlink(path, *args, **kwargs)
            os._exit(84)
    return real_unlink(path, *args, **kwargs)

if mode == 'owner_partial_cleanup':
    os.unlink = interrupted_unlink
    os.supports_dir_fd.add(os.unlink)

def interrupted_copy2(source, destination, *args, **kwargs):
    global copied_files
    result = real_copy2(source, destination, *args, **kwargs)
    if mode == 'copying' and staging_root(destination) is not None:
        copied_files += 1
    if mode == 'copying' and copied_files == 4:
        os._exit(82)
    return result

def interrupted_copytree(source, destination, *args, **kwargs):
    destination_path = Path(destination)
    is_stage = (
        destination_path.parent == target.parent
        and destination_path.name.startswith(f'.{target.name}.relocating-')
    )
    # copytree runs after the staging directory identity is durably recorded.
    if mode == 'allocated' and is_stage:
        os._exit(81)
    if mode == 'copying' and is_stage:
        kwargs['copy_function'] = interrupted_copy2
    return real_copytree(source, destination, *args, **kwargs)

shutil.copytree = interrupted_copytree

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


def _file_digest_manifest(directory: Path) -> dict[str, str]:
    """Capture exact file contents without depending on filesystem timestamps."""
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in directory.rglob("*")
        if path.is_file()
    }


def _stable_evidence_identities(evidence_dir: Path) -> tuple[object, ...]:
    """Capture snapshot, database-row, and artifact identities across relocation."""
    snapshot_ids = tuple(
        (
            filename,
            json.loads((evidence_dir / filename).read_text(encoding="utf-8"))[identity_key],
        )
        for filename, _, identity_key in relocation._SNAPSHOTS
    )
    primary_keys = {
        "generation_requests": "request_id",
        "generation_jobs": "job_id",
        "generation_attempts": "attempt_id",
        "generation_artifacts": "artifact_id",
    }
    with sqlite3.connect(evidence_dir / "t01.sqlite3") as connection:
        database_ids = tuple(
            (
                table,
                tuple(
                    row[0]
                    for row in connection.execute(
                        f"SELECT {column} FROM {table} ORDER BY {column}"
                    )
                ),
            )
            for table, column in primary_keys.items()
        )
        artifact_hashes = tuple(
            connection.execute(
                "SELECT artifact_id, sha256 FROM generation_artifacts ORDER BY artifact_id"
            )
        )
    image_hashes = tuple(
        (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted((evidence_dir / "artifacts").glob("*.png"))
    )
    return snapshot_ids, database_ids, artifact_hashes, image_hashes


def test_orphaned_staging_owner_temporary_file_is_removed_on_recovery(
    tmp_path: Path,
) -> None:
    """A crash before owner publication leaves evidence intact and is recoverable."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identities = _stable_evidence_identities(evidence_dir)

    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, "owner_temp")

    owner_path = evidence_dir.parent / ".t01.relocation-owner.json"
    temporary_files = list(evidence_dir.parent.glob(".t01.relocation-owner-*.tmp"))
    assert interrupted.returncode == 85
    assert not owner_path.exists()
    assert len(temporary_files) == 1
    assert temporary_files[0].is_file()
    assert _file_digest_manifest(evidence_dir) == original_files

    recovered = _run_with_relocation_interruption(evidence_dir, tmp_path, "none")

    assert recovered.returncode == 0, recovered.stderr
    assert list(evidence_dir.parent.glob(".t01.relocation-owner-*.tmp")) == []
    assert _stable_evidence_identities(evidence_dir) == original_identities
    _assert_relocated_tree_is_consistent(evidence_dir)


def test_orphaned_recovery_journal_temporary_file_is_removed_without_changing_evidence(
    tmp_path: Path,
) -> None:
    """Recovery removes an unpublished journal temp after a process crash."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    unrelated_file = evidence_dir.parent / "unrelated.keep"
    unrelated_file.write_text("unrelated data\n", encoding="utf-8")

    interrupted = _run_with_relocation_interruption(
        evidence_dir, tmp_path, "journal_temp"
    )

    state_path = relocation._recovery_state_path(evidence_dir)
    temporary_files = list(
        evidence_dir.parent.glob(".t01.relocation-state-*.tmp")
    )
    assert interrupted.returncode == 86
    assert not state_path.exists()
    assert len(temporary_files) == 1
    assert temporary_files[0].is_file()
    assert _file_digest_manifest(evidence_dir) == original_files
    assert unrelated_file.read_text(encoding="utf-8") == "unrelated data\n"

    relocation._recover_evidence_replacement(evidence_dir)

    assert list(evidence_dir.parent.glob(".t01.relocation-state-*.tmp")) == []
    assert _file_digest_manifest(evidence_dir) == original_files
    assert unrelated_file.read_text(encoding="utf-8") == "unrelated data\n"


def test_recovery_journal_temporary_symlink_fails_closed(tmp_path: Path) -> None:
    """Recovery preserves a matching temporary symlink and its unrelated target."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "preserve.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    unrelated_file = tmp_path / "unrelated-target.txt"
    unrelated_file.write_text("unrelated data\n", encoding="utf-8")
    temporary_path = evidence_dir.parent / ".t01.relocation-state-untrusted.tmp"
    temporary_path.symlink_to(unrelated_file)
    original_evidence = _file_digest_manifest(evidence_dir)

    with pytest.raises(ValueError, match="ambiguous relocation recovery state"):
        relocation._recover_evidence_replacement(evidence_dir)

    assert _file_digest_manifest(evidence_dir) == original_evidence
    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert unrelated_file.read_text(encoding="utf-8") == "unrelated data\n"
    assert temporary_path.is_symlink()


def test_staging_owner_temporary_symlink_fails_closed(tmp_path: Path) -> None:
    """Recovery rejects owner temporary symlinks without changing their targets."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "preserve.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    target = tmp_path / "outside-owner-target.txt"
    target.write_text("unrelated data\n", encoding="utf-8")
    temporary_path = evidence_dir.parent / ".t01.relocation-owner-untrusted.tmp"
    temporary_path.symlink_to(target)

    with pytest.raises(ValueError, match="ambiguous pre-journal staging ownership"):
        relocation.relocate(evidence_dir)

    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert target.read_text(encoding="utf-8") == "unrelated data\n"
    assert temporary_path.is_symlink()


@pytest.mark.parametrize(
    ("field", "malformed_value"),
    [
        ("version", []),
        ("phase", []),
        ("evidence_name", []),
        ("staging_name", {}),
        ("backup_name", []),
        ("original_identity", []),
        ("staging_tree_manifest", []),
    ],
)
def test_recovery_rejects_malformed_journal_field_types_without_mutation(
    tmp_path: Path,
    field: str,
    malformed_value: object,
) -> None:
    """Malformed journal field types fail closed before changing recovery data."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "preserve.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    staging_dir = evidence_dir.parent / ".t01.relocating-safe"
    staging_dir.mkdir()
    staging_file = staging_dir / "staged.txt"
    staging_file.write_text("staged data\n", encoding="utf-8")
    original_identity = relocation._directory_identity(evidence_dir)
    staging_identity = relocation._directory_identity(staging_dir)
    assert original_identity is not None
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        evidence_dir.parent / ".t01.previous-safe",
        original_identity,
        staging_identity,
    )
    state_path = relocation._recovery_state_path(evidence_dir)
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload[field] = malformed_value
    state_path.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    original_state = state_path.read_bytes()

    with pytest.raises(ValueError, match="ambiguous relocation recovery state"):
        relocation._recover_evidence_replacement(evidence_dir)

    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert staging_file.read_text(encoding="utf-8") == "staged data\n"
    assert state_path.read_bytes() == original_state


@pytest.mark.parametrize(
    ("interruption", "exit_code"),
    [("allocated", 81), ("copying", 82), ("prepared", 83)],
)
def test_prejournal_staging_is_recovered_without_changing_original_evidence(
    tmp_path: Path,
    interruption: str,
    exit_code: int,
) -> None:
    """An owned stage interrupted before the journal is removed on the next run."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identities = _stable_evidence_identities(evidence_dir)

    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, interruption)

    assert interrupted.returncode == exit_code
    owner_path = evidence_dir.parent / ".t01.relocation-owner.json"
    assert owner_path.is_file()
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    staging_dir = evidence_dir.parent / owner["staging_name"]
    assert staging_dir.is_dir()
    staging_metadata = staging_dir.lstat()
    assert owner["staging_identity"] == {
        "device": staging_metadata.st_dev,
        "inode": staging_metadata.st_ino,
    }
    assert not (evidence_dir.parent / ".t01.relocation-state.json").exists()
    # The interruption itself must preserve the original evidence byte-for-byte.
    assert _file_digest_manifest(evidence_dir) == original_files
    if interruption == "allocated":
        assert list(staging_dir.iterdir()) == []

    recovered = _run_with_relocation_interruption(evidence_dir, tmp_path, "reserved")

    assert recovered.returncode == 80, recovered.stderr
    recovered_owner = json.loads(owner_path.read_text(encoding="utf-8"))
    recovered_staging_dir = evidence_dir.parent / recovered_owner["staging_name"]
    assert recovered_owner["transaction_id"] != owner["transaction_id"]
    assert recovered_owner["staging_identity"] is None
    assert not staging_dir.exists()
    assert not recovered_staging_dir.exists()
    assert _file_digest_manifest(evidence_dir) == original_files
    assert not (evidence_dir.parent / ".t01.relocation-state.json").exists()

    completed = _run_with_relocation_interruption(evidence_dir, tmp_path, "none")

    assert completed.returncode == 0, completed.stderr
    # A successful retry rewrites SQLite paths, so verify relocated content instead.
    _assert_relocated_tree_is_consistent(evidence_dir)
    assert _stable_evidence_identities(evidence_dir) == original_identities
    assert not owner_path.exists()
    assert list(evidence_dir.parent.glob(".t01.relocating-*")) == []
    assert list(evidence_dir.parent.glob(".t01.previous-*")) == []
    _assert_relocated_tree_is_consistent(evidence_dir)


def test_allocating_owner_recovers_when_reserved_staging_path_is_absent(
    tmp_path: Path,
) -> None:
    """An interrupted reservation without a staging path can be cleared safely."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identities = _stable_evidence_identities(evidence_dir)

    interrupted = _run_with_relocation_interruption(evidence_dir, tmp_path, "reserved")

    assert interrupted.returncode == 80
    owner_path = evidence_dir.parent / ".t01.relocation-owner.json"
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    staging_dir = evidence_dir.parent / owner["staging_name"]
    assert owner["phase"] == "allocating"
    assert owner["staging_identity"] is None
    assert not staging_dir.exists()
    assert _file_digest_manifest(evidence_dir) == original_files

    recovered = _run_with_relocation_interruption(evidence_dir, tmp_path, "none")

    assert recovered.returncode == 0, recovered.stderr
    assert _stable_evidence_identities(evidence_dir) == original_identities
    assert not owner_path.exists()
    assert not staging_dir.exists()
    _assert_relocated_tree_is_consistent(evidence_dir)


def test_unidentified_empty_staging_path_fails_closed_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty reserved path cannot be claimed without a recorded directory identity."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "original.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    original_identity = relocation._directory_identity(evidence_dir)
    assert original_identity is not None

    owner = relocation._create_staging_owner(evidence_dir)
    owner_path = relocation._staging_owner_path(evidence_dir)
    original_owner = owner_path.read_bytes()
    staging_dir = evidence_dir.parent / owner["staging_name"]
    staging_dir.mkdir()
    staging_identity = relocation._directory_identity(staging_dir)
    assert staging_identity is not None
    assert owner["_staging_identity"] is None

    real_scandir = relocation.os.scandir
    scanned_staging_paths: list[Path] = []

    def record_staging_scan(path: object) -> object:
        if path == staging_dir:
            scanned_staging_paths.append(staging_dir)
        return real_scandir(path)

    monkeypatch.setattr(relocation.os, "scandir", record_staging_scan)

    with pytest.raises(ValueError, match="ambiguous pre-journal staging ownership"):
        relocation._cleanup_owned_staging(evidence_dir)

    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert relocation._directory_identity(evidence_dir) == original_identity
    assert relocation._directory_identity(staging_dir) == staging_identity
    assert owner_path.read_bytes() == original_owner
    assert scanned_staging_paths == []


def test_orphan_cleanup_resumes_after_repeated_interruption_and_preserves_lookalikes(
    tmp_path: Path,
) -> None:
    """Repeated cleanup attempts resume one owned stage and leave lookalikes alone."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identities = _stable_evidence_identities(evidence_dir)

    interrupted_copy = _run_with_relocation_interruption(evidence_dir, tmp_path, "copying")
    assert interrupted_copy.returncode == 82
    owner_path = evidence_dir.parent / ".t01.relocation-owner.json"
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    staging_dir = evidence_dir.parent / owner["staging_name"]
    lookalike = evidence_dir.parent / ".t01.relocating-unrelated"
    lookalike.mkdir()
    lookalike_file = lookalike / "preserve.txt"
    lookalike_file.write_text("not owned by this transaction\n", encoding="utf-8")

    previous_file_count = sum(path.is_file() for path in staging_dir.rglob("*"))
    for _ in range(2):
        interrupted_cleanup = _run_with_relocation_interruption(
            evidence_dir,
            tmp_path,
            "owner_partial_cleanup",
        )
        assert interrupted_cleanup.returncode == 84, interrupted_cleanup.stderr
        owner = json.loads(owner_path.read_text(encoding="utf-8"))
        assert owner["phase"] == "cleanup_pending"
        current_file_count = sum(path.is_file() for path in staging_dir.rglob("*"))
        assert 0 < current_file_count < previous_file_count
        assert len(list(evidence_dir.parent.glob(".t01.relocating-*"))) == 2
        assert _file_digest_manifest(evidence_dir) == original_files
        assert lookalike_file.read_text(encoding="utf-8") == "not owned by this transaction\n"
        previous_file_count = current_file_count

    recovered = _run_with_relocation_interruption(evidence_dir, tmp_path, "none")

    assert recovered.returncode == 0, recovered.stderr
    assert _stable_evidence_identities(evidence_dir) == original_identities
    assert not owner_path.exists()
    assert not staging_dir.exists()
    assert lookalike_file.read_text(encoding="utf-8") == "not owned by this transaction\n"
    assert [path.name for path in evidence_dir.parent.glob(".t01.relocating-*")] == [
        lookalike.name
    ]
    _assert_relocated_tree_is_consistent(evidence_dir)


@pytest.mark.parametrize("owner_state", ["duplicate-fields", "symlink"])
def test_ambiguous_staging_owner_fails_closed_without_touching_evidence(
    tmp_path: Path,
    owner_state: str,
) -> None:
    """Malformed or linked owner records cannot authorize staging cleanup."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    sentinel = evidence_dir / "preserve.txt"
    sentinel.write_text("original evidence\n", encoding="utf-8")
    owner_path = evidence_dir.parent / ".t01.relocation-owner.json"
    if owner_state == "duplicate-fields":
        owner_path.write_text('{"version":1,"version":1}\n', encoding="utf-8")
    else:
        target = tmp_path / "owner-target.json"
        target.write_text("{}\n", encoding="utf-8")
        owner_path.symlink_to(target)

    with pytest.raises(ValueError, match="ambiguous pre-journal staging ownership"):
        relocation.relocate(evidence_dir)

    assert sentinel.read_text(encoding="utf-8") == "original evidence\n"
    assert owner_path.is_symlink() if owner_state == "symlink" else owner_path.exists()


@pytest.mark.parametrize(
    ("record_type", "field", "path_kind"),
    [
        ("owner", "staging_name", "parent"),
        ("owner", "staging_name", "absolute"),
        ("journal", "staging_name", "parent"),
        ("journal", "staging_name", "absolute"),
        ("journal", "staging_name", "traversal"),
        ("journal", "backup_name", "parent"),
        ("journal", "backup_name", "absolute"),
        ("journal", "backup_name", "traversal"),
    ],
)
def test_owner_and_journal_reject_escaped_transaction_paths(
    tmp_path: Path,
    record_type: str,
    field: str,
    path_kind: str,
) -> None:
    """Owner and journal names cannot redirect recovery outside the sibling paths."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "preserve.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    if path_kind == "parent":
        unsafe_name = "../outside.txt"
    elif path_kind == "traversal":
        transaction_prefix = (
            ".t01.relocating-safe"
            if field == "staging_name"
            else ".t01.previous-safe"
        )
        unsafe_name = f"{transaction_prefix}/../outside.txt"
    else:
        unsafe_name = str((tmp_path / "absolute-outside.txt").resolve())
    outside_file = (evidence_dir.parent / unsafe_name).resolve()
    outside_file.parent.mkdir(parents=True, exist_ok=True)
    outside_file.write_text("unrelated data\n", encoding="utf-8")

    if record_type == "owner":
        relocation._create_staging_owner(evidence_dir)
        record_path = evidence_dir.parent / ".t01.relocation-owner.json"
        expected_error = "ambiguous pre-journal staging ownership"
    else:
        staging_dir = evidence_dir.parent / ".t01.relocating-safe"
        staging_dir.mkdir()
        (staging_dir / "staged.txt").write_text("staged data\n", encoding="utf-8")
        original_identity = relocation._directory_identity(evidence_dir)
        staging_identity = relocation._directory_identity(staging_dir)
        assert original_identity is not None
        assert staging_identity is not None
        relocation._write_recovery_state(
            evidence_dir,
            staging_dir,
            evidence_dir.parent / ".t01.previous-safe",
            original_identity,
            staging_identity,
        )
        record_path = evidence_dir.parent / ".t01.relocation-state.json"
        expected_error = "ambiguous relocation recovery state"

    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload[field] = unsafe_name
    record_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    original_record = record_path.read_bytes()

    with pytest.raises(ValueError, match=expected_error):
        relocation.relocate(evidence_dir)

    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert outside_file.read_text(encoding="utf-8") == "unrelated data\n"
    assert record_path.read_bytes() == original_record


@pytest.mark.parametrize("path_kind", ["parent", "absolute", "missing-parent"])
def test_recovery_rejects_escaped_or_malformed_manifest_paths(
    tmp_path: Path,
    path_kind: str,
) -> None:
    """Recovery rejects escaping manifest paths and entries with missing parents."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "preserve.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    staging_dir = evidence_dir.parent / ".t01.relocating-safe"
    staging_dir.mkdir()
    staging_file = staging_dir / "staged.txt"
    staging_file.write_text("staged data\n", encoding="utf-8")
    outside_file: Path | None = None
    if path_kind == "parent":
        manifest_path = "../outside.txt"
        outside_file = (evidence_dir / manifest_path).resolve()
    elif path_kind == "absolute":
        outside_file = (tmp_path / "absolute-manifest-target.txt").resolve()
        manifest_path = str(outside_file)
    else:
        manifest_path = "missing-parent/child.txt"
    if outside_file is not None:
        outside_file.parent.mkdir(parents=True, exist_ok=True)
        outside_file.write_text("unrelated data\n", encoding="utf-8")

    original_identity = relocation._directory_identity(evidence_dir)
    staging_identity = relocation._directory_identity(staging_dir)
    assert original_identity is not None
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        evidence_dir.parent / ".t01.previous-safe",
        original_identity,
        staging_identity,
    )
    state_path = evidence_dir.parent / ".t01.relocation-state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["original_tree_manifest"] = {
        "root_mode": payload["original_tree_manifest"]["root_mode"],
        "entries": [
            {
                "path": manifest_path,
                "kind": "file",
                "mode": 0o644,
                "size": 0,
                "sha256": "0" * 64,
            }
        ],
    }
    state_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    original_state = state_path.read_bytes()

    with pytest.raises(ValueError, match="ambiguous relocation recovery state"):
        relocation.relocate(evidence_dir)

    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert staging_file.read_text(encoding="utf-8") == "staged data\n"
    assert state_path.read_bytes() == original_state
    if outside_file is not None:
        assert outside_file.read_text(encoding="utf-8") == "unrelated data\n"


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


def test_recovery_rejects_symlinked_transaction_staging_path(
    tmp_path: Path,
) -> None:
    """A linked staging path cannot authorize recovery to touch its target."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identity = relocation._directory_identity(evidence_dir)
    assert original_identity is not None

    staging_dir = evidence_dir.parent / ".t01.relocating-symlink"
    backup_dir = evidence_dir.parent / ".t01.previous-symlink"
    staging_dir.mkdir()
    staging_identity = relocation._directory_identity(staging_dir)
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        backup_dir,
        original_identity,
        staging_identity,
    )

    replacement_target = tmp_path / "unrelated-replacement-target"
    replacement_target.mkdir()
    replacement_file = replacement_target / "preserve.txt"
    replacement_file.write_text("unrelated replacement data\n", encoding="utf-8")
    staging_dir.rmdir()
    staging_dir.symlink_to(replacement_target, target_is_directory=True)

    with pytest.raises(ValueError, match="relocation recovery path is not a directory"):
        relocation._recover_evidence_replacement(evidence_dir)

    assert _file_digest_manifest(evidence_dir) == original_files
    assert relocation._directory_identity(evidence_dir) == original_identity
    assert replacement_file.read_text(encoding="utf-8") == "unrelated replacement data\n"
    assert staging_dir.is_symlink()
    assert relocation._recovery_state_path(evidence_dir).is_file()


def test_recovery_rejects_replaced_staging_directory_with_mismatched_identity(
    tmp_path: Path,
) -> None:
    """A replacement directory cannot inherit the journal's staging identity."""
    source = REPOSITORY_ROOT / "evidence" / "t01"
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.parent.mkdir(parents=True)
    shutil.copytree(source, evidence_dir)
    original_files = _file_digest_manifest(evidence_dir)
    original_identity = relocation._directory_identity(evidence_dir)
    assert original_identity is not None

    staging_dir = evidence_dir.parent / ".t01.relocating-mismatched-identity"
    backup_dir = evidence_dir.parent / ".t01.previous-mismatched-identity"
    staging_dir.mkdir()
    (staging_dir / "owned-stage.txt").write_text(
        "recorded staging tree\n", encoding="utf-8"
    )
    recorded_staging_identity = relocation._directory_identity(staging_dir)
    assert recorded_staging_identity is not None
    state = relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        backup_dir,
        original_identity,
        recorded_staging_identity,
    )
    assert relocation._read_identity_record(state["staging_identity"], "staging") == (
        recorded_staging_identity
    )

    displaced_staging = tmp_path / "displaced-original-staging"
    staging_dir.rename(displaced_staging)
    staging_dir.mkdir()
    replacement_file = staging_dir / "replacement.txt"
    replacement_file.write_text("unrelated replacement data\n", encoding="utf-8")
    assert relocation._directory_identity(staging_dir) != recorded_staging_identity

    with pytest.raises(ValueError, match="staging identity changed"):
        relocation._recover_evidence_replacement(evidence_dir)

    assert _file_digest_manifest(evidence_dir) == original_files
    assert relocation._directory_identity(evidence_dir) == original_identity
    assert replacement_file.read_text(encoding="utf-8") == "unrelated replacement data\n"
    assert (displaced_staging / "owned-stage.txt").read_text(encoding="utf-8") == (
        "recorded staging tree\n"
    )
    assert relocation._recovery_state_path(evidence_dir).is_file()


def test_legacy_v3_recovery_uses_staging_manifest_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A v3 journal derives the staging manifest before cleaning an abandoned stage."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "original.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    staging_dir = evidence_dir.parent / ".t01.relocating-legacy-v3"
    shutil.copytree(evidence_dir, staging_dir)
    original_identity = relocation._directory_identity(evidence_dir)
    staging_identity = relocation._directory_identity(staging_dir)
    assert original_identity is not None
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        evidence_dir.parent / ".t01.previous-legacy-v3",
        original_identity,
        staging_identity,
    )

    state_path = relocation._recovery_state_path(evidence_dir)
    legacy_state = json.loads(state_path.read_text(encoding="utf-8"))
    legacy_state["version"] = 3
    legacy_state.pop("staging_tree_manifest")
    state_path.write_text(
        json.dumps(legacy_state, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expected_staging_manifest = relocation._tree_manifest(staging_dir)
    real_rmtree = relocation.shutil.rmtree
    observed_checkpoint: dict[str, object] = {}

    def observe_staging_cleanup(path: str | Path, *args: object, **kwargs: object) -> None:
        if Path(path) == staging_dir:
            checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
            observed_checkpoint.update(checkpoint)
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(relocation.shutil, "rmtree", observe_staging_cleanup)

    relocation._recover_evidence_replacement(evidence_dir)

    assert observed_checkpoint["version"] == relocation._RECOVERY_STATE_VERSION
    assert observed_checkpoint["phase"] == "staging_cleanup_pending"
    assert observed_checkpoint["staging_tree_manifest"] == expected_staging_manifest
    assert evidence_file.read_text(encoding="utf-8") == "original evidence\n"
    assert not staging_dir.exists()
    assert not state_path.exists()


def test_legacy_v3_cleanup_pending_recovers_without_staging_manifest(
    tmp_path: Path,
) -> None:
    """A v3 cleanup checkpoint removes its verified backup without a stage manifest."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "original.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    staging_dir = evidence_dir.parent / ".t01.relocating-legacy-v3"
    staging_dir.mkdir()
    staged_file = staging_dir / "installed.txt"
    staged_file.write_text("installed replacement\n", encoding="utf-8")
    backup_dir = evidence_dir.parent / ".t01.previous-legacy-v3"
    original_identity = relocation._directory_identity(evidence_dir)
    staging_identity = relocation._directory_identity(staging_dir)
    assert original_identity is not None
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        backup_dir,
        original_identity,
        staging_identity,
    )

    state_path = relocation._recovery_state_path(evidence_dir)
    legacy_state = json.loads(state_path.read_text(encoding="utf-8"))
    legacy_state["version"] = 3
    legacy_state["phase"] = "cleanup_pending"
    legacy_state.pop("staging_tree_manifest")
    state_path.write_text(
        json.dumps(legacy_state, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(evidence_dir, backup_dir)
    os.replace(staging_dir, evidence_dir)

    relocation._recover_evidence_replacement(evidence_dir)

    assert (evidence_dir / "installed.txt").read_text(encoding="utf-8") == (
        "installed replacement\n"
    )
    assert not backup_dir.exists()
    assert not staging_dir.exists()
    assert not state_path.exists()


@pytest.mark.parametrize("phase", ["prepared", "cleanup_pending"])
def test_ambiguous_legacy_v3_recovery_preserves_trees_and_journal(
    tmp_path: Path,
    phase: str,
) -> None:
    """Ambiguous v3 recovery leaves its trees and journal available for review."""
    evidence_dir = tmp_path / "checkout" / "evidence" / "t01"
    evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / "original.txt"
    evidence_file.write_text("original evidence\n", encoding="utf-8")
    staging_dir = evidence_dir.parent / ".t01.relocating-legacy-v3"
    staging_dir.mkdir()
    staged_file = staging_dir / "installed.txt"
    staged_file.write_text("installed replacement\n", encoding="utf-8")
    backup_dir = evidence_dir.parent / ".t01.previous-legacy-v3"
    original_identity = relocation._directory_identity(evidence_dir)
    staging_identity = relocation._directory_identity(staging_dir)
    assert original_identity is not None
    assert staging_identity is not None
    relocation._write_recovery_state(
        evidence_dir,
        staging_dir,
        backup_dir,
        original_identity,
        staging_identity,
    )

    state_path = relocation._recovery_state_path(evidence_dir)
    legacy_state = json.loads(state_path.read_text(encoding="utf-8"))
    legacy_state["version"] = 3
    legacy_state["phase"] = phase
    legacy_state.pop("staging_tree_manifest")
    state_path.write_text(
        json.dumps(legacy_state, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if phase == "prepared":
        staged_file.write_text("unexpected stage change\n", encoding="utf-8")
        original_tree = evidence_dir
        staging_tree = staging_dir
    else:
        os.replace(evidence_dir, backup_dir)
        os.replace(staging_dir, evidence_dir)
        (backup_dir / "unreviewed.txt").write_text(
            "preserve unreviewed data\n", encoding="utf-8"
        )
        original_tree = backup_dir
        staging_tree = evidence_dir
    original_tree_files = _file_digest_manifest(original_tree)
    staging_tree_files = _file_digest_manifest(staging_tree)
    original_state = state_path.read_bytes()

    with pytest.raises(ValueError, match="ambiguous relocation recovery state"):
        relocation._recover_evidence_replacement(evidence_dir)

    assert _file_digest_manifest(original_tree) == original_tree_files
    assert _file_digest_manifest(staging_tree) == staging_tree_files
    assert state_path.read_bytes() == original_state


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
