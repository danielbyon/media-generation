"""T03 publication contracts, exercised through real files and SQLite restarts.

Traceability labels in test names and docstrings identify the publication,
recovery, ownership, atomicity, I/O, concurrency, and integrity requirements.
Faults target the public checkpoint hook or an actual storage operation; the
oracles inspect decoded files, durable records, and public service results.
Images are created in temporary directories. Abrupt workers use ``os._exit``
so neither exception handling nor context-manager cleanup can repair a crash.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import multiprocessing
import os
import sqlite3
import stat
import subprocess
import sys
import textwrap
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier, Event
from typing import BinaryIO, Callable

import pytest
from PIL import Image
from PIL.PngImagePlugin import PngInfo

from media_generation import publication as publication_module
from media_generation import store as store_module
from media_generation.adapters import DeterministicCpuAdapter, ImageMetadata
from media_generation.domain import ArtifactSource, GenerationPlan, GenerationRequest
from media_generation.errors import (
    GenerationExecutionError,
    InputValidationError,
    PublicationError,
    PublicationIncompleteError,
    RecordNotFoundError,
)
from media_generation.service import GenerationService


PRE_READY_CHECKPOINTS = (
    "intent_committed",
    "stage_created",
    "before_stage_write",
    "stage_written",
    "before_validation",
    "validated",
    "before_file_sync",
    "file_synced",
)
READY_CHECKPOINTS = (
    "ready_committed",
    "before_publish",
    "file_published",
    "before_directory_sync",
    "directory_synced",
    "before_commit",
)
COMMITTED_CHECKPOINTS = (
    "after_commit", "cleanup_captured", "before_cleanup_unlink", "cleanup_unlinked",
    "cleanup_complete", "before_reply",
)
CHECKPOINTS = PRE_READY_CHECKPOINTS + READY_CHECKPOINTS + COMMITTED_CHECKPOINTS
CRASH_EXIT = 73
WORKER_TIMEOUT = 30
ROOT_TOKEN = "user.media_generation.root"
STAGE_TOKEN = "user.media_generation.publication"
CLEANUP_TOKEN = "user.media_generation.cleanup"
CLEANUP_DIRECTORY = ".artifact-cleanup"


@dataclass(frozen=True)
class _Workspace:
    """Independent source, database, and destination paths for one test."""

    database: Path
    output: Path
    source_root: Path

    def service(self, **kwargs) -> GenerationService:
        """Open a fresh service without implicitly reconciling pending work."""
        return GenerationService(self.database, self.output, **kwargs)


def _write_png(path: Path, color: tuple[int, int, int] = (37, 109, 211)) -> bytes:
    """Create an ordinary image independently of the production adapter."""
    with Image.new("RGB", (17, 13), color) as image:
        image.save(path, format="PNG")
    return path.read_bytes()


@pytest.fixture
def workspace(tmp_path: Path) -> _Workspace:
    """Resolve the temporary root before exercising no-follow path traversal."""
    root = tmp_path.resolve()
    paths = _Workspace(root / "studio.sqlite3", root / "artifacts", root / "sources")
    paths.source_root.mkdir()
    _write_png(paths.source_root / "input.png")
    return paths


def _request(reference_ids: tuple[str, ...] = ()) -> GenerationRequest:
    """Use a small reproducible request whose output slot is intentionally shared."""
    return GenerationRequest(
        prompt="A copper lighthouse", seed=23, width=17, height=13,
        reference_ids=reference_ids, output_slot="cover",
    )


def _rows(database: Path, sql: str, parameters: tuple = ()) -> list[dict]:
    """Read committed state through an independent, read-only SQLite connection."""
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(sql, parameters)]


def _only_publication(workspace: _Workspace) -> dict:
    """Obtain the sole journal entry in tests that start without parent artifacts."""
    records = _rows(workspace.database, "SELECT * FROM artifact_publications")
    assert len(records) == 1, records
    return records[0]


def _publication_for(workspace: _Workspace, artifact_id: str) -> dict:
    """Find the journal entry for one logical identity, regardless of content hash."""
    records = _rows(
        workspace.database, "SELECT * FROM artifact_publications WHERE artifact_id = ?",
        (artifact_id,),
    )
    assert len(records) == 1, records
    return records[0]


def _identity(path: Path) -> tuple[int, int]:
    """Identify a directory entry itself without following a replacement symlink."""
    observed = path.lstat()
    return observed.st_dev, observed.st_ino


def _token(
    path: Path, name: str, reader: Callable[[int, str], bytes] | None = None,
) -> bytes | None:
    """Read an ownership token through the portable production descriptor API."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return (reader or publication_module.read_token)(descriptor, name)
    except OSError as error:
        if error.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
            return None
        raise
    finally:
        os.close(descriptor)


def _simulate_token_damage(
    monkeypatch: pytest.MonkeyPatch, target: Path, name: str, damage: str,
) -> dict:
    """Override one inode's token reads without requiring platform-specific xattr tools.

    The original fstat identifies descriptors even when another fault simulates
    inode reuse. Creation attempts on that same token are recorded and rejected;
    recovery must never manufacture evidence for an uncertain existing inode.
    """
    expected_identity = _identity(target)
    native_fstat = os.fstat
    original_read = publication_module.read_token
    original_create = publication_module.create_token
    observations = {"reads": 0, "creates": []}

    def matches(descriptor: int, token_name: str) -> bool:
        observed = native_fstat(descriptor)
        return (
            (observed.st_dev, observed.st_ino) == expected_identity
            and os.fsdecode(token_name) == name
        )

    def read(descriptor: int, token_name: str) -> bytes:
        if matches(descriptor, token_name):
            observations["reads"] += 1
            if damage == "missing":
                raise OSError(getattr(errno, "ENOATTR", errno.ENODATA), "injected missing token")
            original = original_read(descriptor, token_name)
            assert original
            # Preserve token length and ASCII hex validity when testing a root.
            return (b"0" if original[:1] != b"0" else b"1") + original[1:]
        return original_read(descriptor, token_name)

    def create(descriptor: int, token_name: str, value: bytes) -> None:
        if matches(descriptor, token_name):
            observations["creates"].append(value)
            raise AssertionError("recovery attempted to manufacture an ownership token")
        original_create(descriptor, token_name, value)

    monkeypatch.setattr(publication_module, "read_token", read)
    monkeypatch.setattr(publication_module, "create_token", create)
    return observations


def _reconcile_without_authority(workspace: _Workspace, *, root_failure: bool = False) -> None:
    """Require attention, permitting a fatal root ownership error at the API boundary."""
    try:
        report = workspace.service().reconcile()
    except PublicationError:
        if not root_failure:
            raise
    else:
        assert report["status"] == "attention_required", report


def _invoke(service: GenerationService, workspace: _Workspace, operation: str):
    """Exercise generation and administrative import through their public APIs."""
    if operation == "generated":
        return service.submit("checkpoint-test", _request())
    return service.import_image(workspace.source_root, "input.png")


def _assert_unpublished(workspace: _Workspace, record: dict, job_status: str) -> None:
    """No artifact or lineage may become visible while publication is incomplete."""
    service = workspace.service()
    with pytest.raises(RecordNotFoundError):
        service.get_artifact(record["artifact_id"])
    assert _rows(
        workspace.database, "SELECT * FROM artifact_edges WHERE target_id = ?",
        (record["artifact_id"],),
    ) == []
    if record["job_id"] is not None:
        job = service.get_job(record["job_id"])
        assert job.status == job_status
        assert job.artifact_id is None
        provenance = service.get_provenance(job.job_id)
        assert provenance["attempt"]["status"] == job_status
        assert provenance["artifact"] is None


def _assert_committed(workspace: _Workspace, record: dict) -> dict:
    """Verify public success against independently decoded, hashed, owned bytes."""
    service = workspace.service()
    artifact = service.get_artifact(record["artifact_id"])
    path = Path(artifact.path)
    assert path.parent == workspace.output
    assert stat.S_ISREG(path.lstat().st_mode)
    assert _identity(path) == (record["stage_dev"], record["stage_ino"])
    encoded = path.read_bytes()
    assert len(encoded) == artifact.file_size
    assert hashlib.sha256(encoded).hexdigest() == artifact.sha256
    with Image.open(path) as image:
        image.load()
        assert image.size == (artifact.width, artifact.height)
        assert image.format == artifact.image_format
    assert service.get_integrity(artifact.artifact_id)["status"] == "ok"
    assert _publication_for(workspace, artifact.artifact_id)["state"] == "committed"
    if record["job_id"] is not None:
        job = service.get_job(record["job_id"])
        assert job.status == "succeeded"
        assert job.artifact_id == artifact.artifact_id
        provenance = service.get_provenance(job.job_id)
        assert provenance["attempt"]["status"] == "succeeded"
        assert provenance["attempt"]["error_message"] is None
        assert provenance["artifact"] == artifact.to_dict()
    return artifact.to_dict()


@pytest.mark.parametrize("link_position", ("ancestor", "root", "directory", "leaf"))
def test_t03_import_rejects_symlink_components_in_approved_source_path(
    workspace: _Workspace, link_position: str,
) -> None:
    """TAC-3: import rechecks the operator path instead of resolving links away."""
    base = workspace.source_root.parent
    approved = base / "approved-source"
    nested = approved / "nested"
    nested.mkdir(parents=True)
    source = nested / "input.png"
    _write_png(source)
    relative = "nested/input.png"
    if link_position == "ancestor":
        real_parent = base / "real-parent"
        real_parent.mkdir()
        approved.rename(real_parent / approved.name)
        (base / "ancestor-link").symlink_to(real_parent, target_is_directory=True)
        approved_root = base / "ancestor-link" / approved.name
    elif link_position == "root":
        approved_root = base / "approved-link"
        approved_root.symlink_to(approved, target_is_directory=True)
    elif link_position == "directory":
        approved_root = approved
        (approved / "nested-link").symlink_to(nested, target_is_directory=True)
        relative = "nested-link/input.png"
    else:
        approved_root = approved
        (approved / "input-link.png").symlink_to(source)
        relative = "input-link.png"

    service = workspace.service()
    tables = ("generation_artifacts", "artifact_edges", "artifact_publications")
    before = {table: _rows(workspace.database, f"SELECT * FROM {table}") for table in tables}
    with pytest.raises(InputValidationError, match="without following links"):
        service.import_image(approved_root, relative)
    after = {table: _rows(workspace.database, f"SELECT * FROM {table}") for table in tables}
    assert after == before


def _reconcile_repeatedly(workspace: _Workspace, *, status: str = "complete") -> list[dict]:
    """Reopen storage for every pass so process-local state cannot mask recovery."""
    reports = []
    for _ in range(3):
        report = workspace.service().reconcile()
        assert report["status"] == status, report
        reports.append(report)
    return reports


CRASH_PROGRAM = textwrap.dedent(
    """
    import json
    import os
    import sys
    from pathlib import Path
    from media_generation.domain import GenerationRequest
    from media_generation.service import GenerationService

    database, output, source, operation, target, payload = sys.argv[1:]

    def checkpoint(name):
        if name == target:
            print(name, flush=True)
            os._exit(73)

    service = GenerationService(
        Path(database), Path(output), publication_checkpoint=checkpoint
    )
    if operation == "generated":
        service.submit("checkpoint-test", GenerationRequest(**json.loads(payload)))
    else:
        service.import_image(Path(source), "input.png")
    """
)


def _crash_at(workspace: _Workspace, checkpoint: str, operation: str = "generated") -> dict:
    """Require proof that a fresh interpreter died at the requested boundary."""
    environment = os.environ.copy()
    source = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source, environment.get("PYTHONPATH", "")) if item
    )
    result = subprocess.run(
        [
            sys.executable, "-c", CRASH_PROGRAM, str(workspace.database),
            str(workspace.output), str(workspace.source_root), operation,
            checkpoint, json.dumps(_request().to_dict()),
        ],
        env=environment, capture_output=True, text=True, timeout=WORKER_TIMEOUT,
        check=False,
    )
    assert result.returncode == CRASH_EXIT, (result.stdout, result.stderr)
    assert result.stdout.strip() == checkpoint
    return _only_publication(workspace)


@pytest.mark.parametrize("operation", ("generated", "imported"))
@pytest.mark.parametrize("checkpoint", CHECKPOINTS)
def test_t03_recovery_checkpoint_exception_has_one_durable_outcome(
    workspace: _Workspace, operation: str, checkpoint: str,
) -> None:
    """T03 recovery: handled faults abandon unready data and preserve committed success."""
    reached = []

    def interrupt(name: str) -> None:
        if name == checkpoint:
            reached.append(name)
            raise RuntimeError("injected checkpoint failure: " + name)

    service = workspace.service(publication_checkpoint=interrupt)
    if checkpoint in COMMITTED_CHECKPOINTS:
        result = _invoke(service, workspace, operation)
    else:
        error = PublicationError
        if operation == "generated":
            error = (PublicationIncompleteError if checkpoint in READY_CHECKPOINTS
                     else GenerationExecutionError)
        with pytest.raises(error, match="injected checkpoint failure") as failure:
            _invoke(service, workspace, operation)
    assert reached == [checkpoint]
    record = _only_publication(workspace)
    if checkpoint in PRE_READY_CHECKPOINTS:
        _assert_unpublished(workspace, record, "failed")
        assert record["state"] == "abandoned"
    elif checkpoint in READY_CHECKPOINTS:
        _assert_unpublished(workspace, record, "running")
        assert record["state"] == "ready"
        if operation == "generated":
            assert failure.value.job_id == record["job_id"]
            assert not isinstance(failure.value, GenerationExecutionError)
    else:
        assert result.artifact_id == record["artifact_id"]
        _assert_committed(workspace, record)

    _reconcile_repeatedly(workspace)
    if checkpoint in PRE_READY_CHECKPOINTS:
        _assert_unpublished(workspace, record, "failed")
        assert _only_publication(workspace)["state"] == "abandoned"
    else:
        before = _assert_committed(workspace, record)
        _reconcile_repeatedly(workspace)
        assert _assert_committed(workspace, record) == before
    assert not (workspace.output / record["stage_name"]).exists()
    assert not (workspace.output / CLEANUP_DIRECTORY / record["publication_id"]).exists()


@pytest.mark.parametrize("operation", ("generated", "imported"))
@pytest.mark.parametrize("checkpoint", CHECKPOINTS)
def test_t03_recovery_abrupt_exit_reopens_and_converges_without_reexecution(
    workspace: _Workspace, operation: str, checkpoint: str,
) -> None:
    """T03 recovery: every crash boundary converges using only durable journal and files."""
    record = _crash_at(workspace, checkpoint, operation)
    before_artifacts = _rows(workspace.database, "SELECT * FROM generation_artifacts")
    assert len(before_artifacts) == int(checkpoint in COMMITTED_CHECKPOINTS)
    if checkpoint in PRE_READY_CHECKPOINTS:
        assert record["state"] == "allocated"
        _assert_unpublished(workspace, record, "running")
    elif checkpoint in READY_CHECKPOINTS:
        assert record["state"] == "ready"
        _assert_unpublished(workspace, record, "running")
    else:
        assert record["state"] == "committed"

    _reconcile_repeatedly(workspace)
    if checkpoint in PRE_READY_CHECKPOINTS:
        assert _only_publication(workspace)["state"] == "abandoned"
        _assert_unpublished(workspace, record, "failed")
    else:
        snapshot = _assert_committed(workspace, record)
        _reconcile_repeatedly(workspace)
        assert _assert_committed(workspace, record) == snapshot
        if operation == "generated":
            replay = workspace.service().submit("checkpoint-test", _request())
            assert replay.job_id == record["job_id"]
            assert replay.artifact_id == record["artifact_id"]
            assert replay.status == "succeeded"
    assert not (workspace.output / record["stage_name"]).exists()
    assert not (workspace.output / CLEANUP_DIRECTORY / record["publication_id"]).exists()
    assert len(_rows(workspace.database, "SELECT * FROM artifact_publications")) == 1
    assert len(_rows(workspace.database, "SELECT * FROM generation_attempts")) == (
        1 if operation == "generated" else 0
    )


def test_t03_publication_file_and_directory_are_synced_before_metadata_is_visible(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 durability: final bytes and their directory precede atomic artifact/job visibility."""
    events = []
    real_fsync = os.fsync
    inspected = []

    def track_sync(descriptor: int) -> None:
        identity = os.fstat(descriptor)
        real_fsync(descriptor)
        events.append(("sync", stat.S_ISDIR(identity.st_mode), identity.st_dev, identity.st_ino))

    def checkpoint(name: str) -> None:
        events.append((name,))
        if name != "before_commit":
            return
        records = _rows(
            workspace.database, "SELECT * FROM artifact_publications WHERE job_id IS NOT NULL"
        )
        assert len(records) == 1
        record = records[0]
        path = workspace.output / record["final_name"]
        payload = json.loads(record["artifact_json"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == payload["sha256"]
        with Image.open(path) as image:
            image.load()
            assert image.size == (_request().width, _request().height)
        _assert_unpublished(workspace, record, "running")
        published = events.index(("file_published",))
        final_identity = _identity(path)
        root_identity = _identity(workspace.output)
        file_synced = max(
            index for index, event in enumerate(events)
            if event == ("sync", False, *final_identity)
        )
        directory_synced = max(
            index for index, event in enumerate(events)
            if event == ("sync", True, *root_identity)
        )
        assert published < file_synced < directory_synced < len(events) - 1
        inspected.append(record)

    def complete(*args, **kwargs) -> None:
        assert len(inspected) == 1
        events.append(("metadata_commit",))
        real_complete(*args, **kwargs)

    parent = workspace.service().import_image(workspace.source_root, "input.png")
    service = workspace.service(publication_checkpoint=checkpoint)
    real_complete = service._store.complete_execution
    monkeypatch.setattr(publication_module.os, "fsync", track_sync)
    monkeypatch.setattr(service._store, "complete_execution", complete)
    result = service.submit("durability", _request((parent.artifact_id,)))
    assert len(inspected) == 1
    _assert_committed(workspace, inspected[0])
    assert events.index(("before_commit",)) < events.index(("metadata_commit",))
    assert service.get_lineage(result.artifact_id)["parents"] == [{
        "source_id": parent.artifact_id, "target_id": result.artifact_id,
        "role": "reference", "position": 0,
    }]


def test_t03_atomicity_complete_execution_commit_then_raise_keeps_success(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 acknowledgement loss: an exception after commit cannot delete or fail success."""
    service = workspace.service()
    parent = service.import_image(workspace.source_root, "input.png")
    original = service._store.complete_execution
    committed = []

    def commit_then_raise(artifact, *args, **kwargs) -> None:
        original(artifact, *args, **kwargs)
        committed.append((artifact.to_dict(), Path(artifact.path).read_bytes(), _identity(Path(artifact.path))))
        raise sqlite3.OperationalError("commit acknowledgement lost")

    monkeypatch.setattr(service._store, "complete_execution", commit_then_raise)
    result = service.submit("commit-then-raise", _request((parent.artifact_id,)))
    assert len(committed) == 1
    assert result.status == "succeeded"
    snapshot, encoded, identity = committed[0]
    record = _publication_for(workspace, result.artifact_id)
    job_snapshot = service.get_job(result.job_id).to_dict()
    lineage = service.get_lineage(result.artifact_id)
    assert len(lineage["parents"]) == 1
    for report in _reconcile_repeatedly(workspace):
        assert any(item["publication_id"] == record["publication_id"]
                   and item["state"] == "committed" for item in report["publications"])
        assert service.get_artifact(result.artifact_id).to_dict() == snapshot
        assert service.get_job(result.job_id).to_dict() == job_snapshot
        assert service.get_lineage(result.artifact_id) == lineage
        assert Path(snapshot["path"]).read_bytes() == encoded
        assert _identity(Path(snapshot["path"])) == identity


@pytest.mark.parametrize("commit_outcome", ("rollback", "committed"))
def test_t03_atomicity_sqlite_commit_exception_is_resolved_from_durable_state(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch, commit_outcome: str,
) -> None:
    """T03 SQLite failure: both failed COMMIT and lost COMMIT acknowledgement recover atomically."""
    service = workspace.service()
    parents = [service.import_image(workspace.source_root, "input.png") for _ in range(2)]
    references = tuple(parent.artifact_id for parent in parents)
    armed = Event()
    injected = []
    real_connect = sqlite3.connect

    class FaultyCommit(sqlite3.Connection):
        """Fail exactly the metadata transaction, before or after its real commit."""

        def commit(self) -> None:
            if armed.is_set() and not injected:
                injected.append(commit_outcome)
                if commit_outcome == "committed":
                    super().commit()
                raise sqlite3.OperationalError("injected SQLite commit failure")
            super().commit()

    def connect(*args, **kwargs):
        kwargs["factory"] = FaultyCommit
        return real_connect(*args, **kwargs)

    def arm(name: str) -> None:
        if name == "before_commit":
            armed.set()

    service = workspace.service(publication_checkpoint=arm)
    with monkeypatch.context() as fault:
        fault.setattr(store_module.sqlite3, "connect", connect)
        if commit_outcome == "rollback":
            with pytest.raises(PublicationIncompleteError, match="injected SQLite commit failure"):
                service.submit("sqlite-commit", _request(references))
        else:
            result = service.submit("sqlite-commit", _request(references))
            assert result.status == "succeeded"
    assert injected == [commit_outcome]
    records = _rows(workspace.database, "SELECT * FROM artifact_publications WHERE job_id IS NOT NULL")
    assert len(records) == 1
    record = records[0]
    path = workspace.output / record["final_name"]
    encoded, identity = path.read_bytes(), _identity(path)
    if commit_outcome == "rollback":
        assert record["state"] == "ready"
        _assert_unpublished(workspace, record, "running")
    _reconcile_repeatedly(workspace)
    _assert_committed(workspace, record)
    assert path.read_bytes() == encoded
    assert _identity(path) == identity
    lineage = workspace.service().get_lineage(record["artifact_id"])
    assert [(edge["source_id"], edge["position"]) for edge in lineage["parents"]] == [
        (references[0], 0), (references[1], 1),
    ]
    assert len(_rows(workspace.database, "SELECT * FROM generation_attempts")) == 1


def test_t03_atomicity_partial_lineage_insert_rolls_back_artifact_and_job(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 atomic visibility: a later edge failure exposes neither earlier edges nor success."""
    service = workspace.service()
    parents = [service.import_image(workspace.source_root, "input.png") for _ in range(2)]
    references = tuple(parent.artifact_id for parent in parents)
    insert_sources = service._store._insert_sources
    inserted = []

    def fail_second_edge(connection, artifact_id, sources) -> None:
        insert_sources(connection, artifact_id, sources[:1])
        inserted.append(artifact_id)
        raise sqlite3.IntegrityError("injected second lineage edge failure")

    with monkeypatch.context() as fault:
        fault.setattr(service._store, "_insert_sources", fail_second_edge)
        with pytest.raises(PublicationIncompleteError, match="second lineage edge failure"):
            service.submit("lineage-rollback", _request(references))
    assert len(inserted) == 1
    record = _publication_for(workspace, inserted[0])
    _assert_unpublished(workspace, record, "running")
    assert (workspace.output / record["final_name"]).is_file()
    _reconcile_repeatedly(workspace)
    _assert_committed(workspace, record)
    assert [edge["source_id"] for edge in workspace.service().get_lineage(inserted[0])["parents"]] == list(references)


def test_t03_ownership_unknown_files_and_stage_lookalikes_are_reported_and_preserved(
    workspace: _Workspace,
) -> None:
    """T03 cleanup: a filename or absent metadata never grants deletion authority."""
    service = workspace.service()
    workspace.output.mkdir()
    unknown = workspace.output / "unregistered.png"
    stage = workspace.output / (".pub_" + "a" * 32 + ".stage")
    _write_png(unknown)
    stage.write_bytes(b"unowned partial file")
    directory = workspace.output / "unregistered-directory"
    directory.mkdir()
    (directory / "keep.txt").write_text("keep this descendant", encoding="utf-8")
    link = workspace.output / "unregistered-link"
    source = workspace.source_root / "input.png"
    link.symlink_to(source)
    before = {path.name: _identity(path) for path in (unknown, stage, directory, link)}
    source_bytes = source.read_bytes()
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert set(report["orphan_files"]) == set(before)
        assert {name: _identity(workspace.output / name) for name in before} == before
        assert unknown.read_bytes() == source_bytes
        assert stage.read_bytes() == b"unowned partial file"
        assert (directory / "keep.txt").read_text(encoding="utf-8") == "keep this descendant"
        assert link.is_symlink()
        assert source.read_bytes() == source_bytes
    report = service.reconcile()
    assert report["status"] == "attention_required"
    assert report["publications"] == []


@pytest.mark.parametrize("checkpoint", ("intent_committed", "stage_created", "ready_committed"))
@pytest.mark.parametrize("replacement", ("regular", "symlink"))
def test_t03_ownership_unowned_or_replaced_stage_survives_repeated_recovery(
    workspace: _Workspace, checkpoint: str, replacement: str,
) -> None:
    """T03 ownership: even identical bytes cannot substitute for a journal-owned inode."""
    record = _crash_at(workspace, checkpoint)
    stage = workspace.output / record["stage_name"]
    source = workspace.source_root / "input.png"
    encoded = stage.read_bytes() if checkpoint == "ready_committed" else source.read_bytes()
    competitor = workspace.source_root / "replacement"
    if replacement == "regular":
        competitor.write_bytes(encoded)
    else:
        competitor.symlink_to(source)
    identity = _identity(competitor)
    assert identity != (record["stage_dev"], record["stage_ino"])
    competitor.replace(stage)
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert _identity(stage) == identity
        assert stage.is_symlink() == (replacement == "symlink")
        assert stage.read_bytes() == (source.read_bytes() if replacement == "symlink" else encoded)
        entry = report["publications"][0]
        if checkpoint == "ready_committed":
            assert entry["state"] == "ready"
            assert entry.get("error")
            _assert_unpublished(workspace, record, "running")
        else:
            assert entry["state"] == "abandoned"
            assert entry["cleanup"].startswith("ownership_uncertain")
            _assert_unpublished(workspace, record, "failed")


@pytest.mark.parametrize("replacement", ("identical-image", "different-image", "symlink"))
def test_t03_ownership_final_collision_never_overwrites_or_adopts_competitor(
    workspace: _Workspace, replacement: str,
) -> None:
    """T03 collision: an existing final path remains untouched even when its hash matches."""
    injected = []

    def collide(name: str) -> None:
        if name != "before_publish":
            return
        record = _only_publication(workspace)
        final = workspace.output / record["final_name"]
        if replacement == "identical-image":
            final.write_bytes((workspace.output / record["stage_name"]).read_bytes())
        elif replacement == "different-image":
            _write_png(final, (211, 29, 41))
        else:
            final.symlink_to(workspace.source_root / "input.png")
        injected.append((_identity(final), final.read_bytes()))

    service = workspace.service(publication_checkpoint=collide)
    with pytest.raises(PublicationIncompleteError, match="collision"):
        service.submit("collision", _request())
    assert len(injected) == 1
    record = _only_publication(workspace)
    final = workspace.output / record["final_name"]
    stage = workspace.output / record["stage_name"]
    staged_bytes = stage.read_bytes()
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["publications"][0]["state"] == "ready"
        assert report["publications"][0].get("error")
        assert (_identity(final), final.read_bytes()) == injected[0]
        assert final.is_symlink() == (replacement == "symlink")
        assert stage.read_bytes() == staged_bytes
        _assert_unpublished(workspace, record, "running")


@pytest.mark.parametrize("checkpoint", ("ready_committed", "file_published"))
@pytest.mark.parametrize("damage", ("valid-wrong-image", "truncated-image"))
def test_t03_recovery_revalidates_owned_bytes_before_exposing_success(
    workspace: _Workspace, checkpoint: str, damage: str,
) -> None:
    """T03 validation: durable inode ownership alone cannot authorize changed content."""
    record = _crash_at(workspace, checkpoint)
    stage = workspace.output / record["stage_name"]
    original_identity = _identity(stage)
    if damage == "valid-wrong-image":
        changed = _write_png(stage, (222, 10, 33))
    else:
        changed = stage.read_bytes()[:20]
        stage.write_bytes(changed)
    assert _identity(stage) == original_identity
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["publications"][0]["state"] == "ready"
        assert report["publications"][0].get("error")
        _assert_unpublished(workspace, record, "running")
        assert stage.read_bytes() == changed
        assert _identity(stage) == original_identity


def test_t03_recovery_missing_ready_stage_does_not_regenerate_or_claim_success(
    workspace: _Workspace,
) -> None:
    """T03 missing ownership evidence: a lost unlinked stage remains unresolved."""
    record = _crash_at(workspace, "ready_committed")
    (workspace.output / record["stage_name"]).unlink()
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["publications"][0]["state"] == "ready"
        assert report["publications"][0].get("error")
        _assert_unpublished(workspace, record, "running")
        assert not (workspace.output / record["final_name"]).exists()


def test_t03_recovery_owned_final_is_sufficient_when_stage_name_is_missing(
    workspace: _Workspace,
) -> None:
    """T03 replay: a validated owned final survives a lost staging link before metadata commit."""
    record = _crash_at(workspace, "before_commit")
    final = workspace.output / record["final_name"]
    encoded, identity = final.read_bytes(), _identity(final)
    (workspace.output / record["stage_name"]).unlink()
    _reconcile_repeatedly(workspace)
    _assert_committed(workspace, record)
    assert final.read_bytes() == encoded
    assert _identity(final) == identity


class _FailingWriteAdapter(DeterministicCpuAdapter):
    """Write a real partial file before surfacing a device or capacity failure."""

    def __init__(self, error_number: int) -> None:
        self.error_number = error_number
        self.calls = 0

    def generate(self, plan: GenerationPlan, destination: BinaryIO) -> ImageMetadata:
        self.calls += 1
        destination.write(b"partial image payload")
        destination.flush()
        raise OSError(self.error_number, "injected staging write failure")


@pytest.mark.parametrize("error_number", (errno.ENOSPC, errno.EIO), ids=("disk-full", "write-error"))
def test_t03_io_partial_write_failure_abandons_only_owned_stage(
    workspace: _Workspace, error_number: int,
) -> None:
    """T03 I/O: partial writes cannot expose an artifact or remove unrelated destination files."""
    adapter = _FailingWriteAdapter(error_number)
    service = workspace.service(adapter=adapter)
    workspace.output.mkdir()
    unknown = workspace.output / "keep.png"
    original = _write_png(unknown)
    with pytest.raises(GenerationExecutionError, match="injected staging write failure"):
        service.submit("write-error", _request())
    assert adapter.calls == 1
    record = _only_publication(workspace)
    assert record["state"] == "abandoned"
    _reconcile_repeatedly(workspace, status="attention_required")
    _assert_unpublished(workspace, record, "failed")
    assert not (workspace.output / record["stage_name"]).exists()
    assert unknown.read_bytes() == original


@pytest.mark.parametrize("error_number", (errno.ENOSPC, errno.EIO), ids=("disk-full", "sync-error"))
@pytest.mark.parametrize("checkpoint", ("before_file_sync", "before_directory_sync", "after_commit"))
def test_t03_io_fsync_failure_never_exposes_premature_or_downgraded_success(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch, error_number: int, checkpoint: str,
) -> None:
    """T03 durability faults: failed syncs fail closed; cleanup syncs cannot undo a commit."""
    armed = Event()
    injected = []
    real_fsync = os.fsync

    def arm(name: str) -> None:
        if name == checkpoint:
            armed.set()

    def fail_sync(descriptor: int) -> None:
        if armed.is_set() and not injected:
            observed = os.fstat(descriptor)
            assert stat.S_ISDIR(observed.st_mode) == (checkpoint != "before_file_sync")
            injected.append((observed.st_dev, observed.st_ino))
            raise OSError(error_number, "injected fsync failure")
        real_fsync(descriptor)

    service = workspace.service(publication_checkpoint=arm)
    with monkeypatch.context() as fault:
        fault.setattr(publication_module.os, "fsync", fail_sync)
        if checkpoint == "after_commit":
            result = service.submit("sync-error", _request())
            assert result.status == "succeeded"
        else:
            error = (PublicationIncompleteError if checkpoint == "before_directory_sync"
                     else GenerationExecutionError)
            with pytest.raises(error, match="injected fsync failure"):
                service.submit("sync-error", _request())
    assert len(injected) == 1
    record = _only_publication(workspace)
    if checkpoint == "before_file_sync":
        assert record["state"] == "abandoned"
        _assert_unpublished(workspace, record, "failed")
    elif checkpoint == "before_directory_sync":
        assert record["state"] == "ready"
        assert (workspace.output / record["final_name"]).is_file()
        _assert_unpublished(workspace, record, "running")
    else:
        _assert_committed(workspace, record)
    _reconcile_repeatedly(workspace)
    if checkpoint == "before_file_sync":
        _assert_unpublished(workspace, record, "failed")
    else:
        _assert_committed(workspace, record)


def test_t03_io_failed_postcommit_stage_cleanup_is_retryable_without_deleting_final(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 cleanup failure: committed content and provenance survive a denied stage unlink."""
    real_unlink = os.unlink
    denied = []

    def deny_stage(path, *args, **kwargs) -> None:
        if Path(os.fsdecode(path)).name.startswith("pub_"):
            assert Path(os.fsdecode(path)).name == _only_publication(workspace)["publication_id"]
            denied.append(str(path))
            raise OSError(errno.EACCES, "injected cleanup denial")
        real_unlink(path, *args, **kwargs)

    service = workspace.service()
    with monkeypatch.context() as fault:
        fault.setattr(publication_module.os, "unlink", deny_stage)
        result = service.submit("cleanup-denied", _request())
        assert result.status == "succeeded"
        record = _only_publication(workspace)
        snapshot = _assert_committed(workspace, record)
        report = service.reconcile()
        assert report["status"] == "attention_required"
        assert report["publications"][0]["state"] == "committed"
        assert "cleanup_pending" in report["publications"][0]["cleanup"]
        captured = workspace.output / CLEANUP_DIRECTORY / record["publication_id"]
        assert captured.is_file()
    assert denied
    _reconcile_repeatedly(workspace)
    assert _assert_committed(workspace, record) == snapshot
    assert not (workspace.output / record["stage_name"]).exists()
    assert not captured.exists()


def _paused_publisher(database, output, checkpoint, reached, release, results, abrupt) -> None:
    """Hold a real publication lock until the parent permits progress or abrupt exit."""
    try:
        def pause(name: str) -> None:
            if name == checkpoint:
                reached.set()
                if not release.wait(WORKER_TIMEOUT):
                    raise TimeoutError("publisher was not released")
                if abrupt:
                    os._exit(CRASH_EXIT)

        service = GenerationService(Path(database), Path(output), publication_checkpoint=pause)
        results.put(("ok", service.submit("process-race", _request()).to_dict()))
    except BaseException:
        results.put(("error", traceback.format_exc()))


def _contending_reconciler(database, output, blocked, finished, results) -> None:
    """Prove kernel lock contention before performing a normal blocking reconciliation."""
    original = publication_module.fcntl.flock

    def observe_contention(descriptor: int, operation: int) -> None:
        if operation == publication_module.fcntl.LOCK_EX:
            try:
                original(descriptor, operation | publication_module.fcntl.LOCK_NB)
                return
            except BlockingIOError:
                blocked.set()
        original(descriptor, operation)

    try:
        service = GenerationService(Path(database), Path(output))
        publication_module.fcntl.flock = observe_contention
        results.put(("ok", service.reconcile()))
    except BaseException:
        results.put(("error", traceback.format_exc()))
    finally:
        publication_module.fcntl.flock = original
        finished.set()


def _stop_process(process) -> None:
    """Bound worker cleanup even when an assertion exposes a locking regression."""
    if process.pid is None:
        return
    process.join(timeout=WORKER_TIMEOUT)
    if process.is_alive():
        process.terminate()
        process.join(timeout=WORKER_TIMEOUT)
    if process.is_alive():
        process.kill()
        process.join(timeout=WORKER_TIMEOUT)


@pytest.mark.parametrize("checkpoint", ("stage_written", "ready_committed", "before_commit", "after_commit"))
@pytest.mark.parametrize("abrupt", (False, True), ids=("publisher-finishes", "publisher-dies"))
def test_t03_concurrency_reconciliation_waits_for_live_publisher_and_recovers_after_exit(
    workspace: _Workspace, checkpoint: str, abrupt: bool,
) -> None:
    """T03 exclusion: reconciliation cannot abandon a live writer, and death releases its lock."""
    workspace.service()
    context = multiprocessing.get_context("spawn")
    reached, release, blocked, finished = (context.Event() for _ in range(4))
    published, reconciled = context.Queue(), context.Queue()
    publisher = context.Process(
        target=_paused_publisher,
        args=(str(workspace.database), str(workspace.output), checkpoint,
              reached, release, published, abrupt),
    )
    reconciler = context.Process(
        target=_contending_reconciler,
        args=(str(workspace.database), str(workspace.output), blocked, finished, reconciled),
    )
    try:
        publisher.start()
        assert reached.wait(WORKER_TIMEOUT), "publisher did not reach its checkpoint"
        held = _only_publication(workspace)
        held_stage = workspace.output / held["stage_name"]
        assert held_stage.is_file()
        reconciler.start()
        assert blocked.wait(WORKER_TIMEOUT), "reconciler did not contend on the publisher's lock"
        assert not finished.is_set()
        assert _only_publication(workspace)["state"] == held["state"]
        assert held_stage.is_file()
        release.set()
        publisher.join(timeout=WORKER_TIMEOUT)
        assert not publisher.is_alive()
        assert publisher.exitcode == (CRASH_EXIT if abrupt else 0)
        if not abrupt:
            status, result = published.get(timeout=WORKER_TIMEOUT)
            assert status == "ok", result
            assert result["status"] == "succeeded"
        status, report = reconciled.get(timeout=WORKER_TIMEOUT)
        assert status == "ok", report
        assert report["status"] == "complete"
        reconciler.join(timeout=WORKER_TIMEOUT)
        assert not reconciler.is_alive()
        assert reconciler.exitcode == 0
        if abrupt and checkpoint in PRE_READY_CHECKPOINTS:
            assert report["publications"][0]["state"] == "abandoned"
            _assert_unpublished(workspace, held, "failed")
        else:
            assert report["publications"][0]["state"] == "committed"
            _assert_committed(workspace, held)
        _reconcile_repeatedly(workspace)
        assert not held_stage.exists()
    finally:
        release.set()
        _stop_process(publisher)
        _stop_process(reconciler)
        published.close()
        reconciled.close()
        published.join_thread()
        reconciled.join_thread()


def test_t03_concurrency_same_key_and_output_reuses_one_live_execution(
    workspace: _Workspace,
) -> None:
    """T03 idempotency: a concurrent retry neither publishes nor creates a second attempt."""
    reached, release = Event(), Event()
    writes = []

    def hold_before_commit(name: str) -> None:
        if name == "before_stage_write":
            writes.append(name)
        if name == "before_commit":
            reached.set()
            if not release.wait(WORKER_TIMEOUT):
                raise TimeoutError("publisher was not released")

    writer = workspace.service(publication_checkpoint=hold_before_commit)
    retry = workspace.service()
    with ThreadPoolExecutor(max_workers=2) as workers:
        publishing = workers.submit(writer.submit, "same-key", _request())
        try:
            assert reached.wait(WORKER_TIMEOUT)
            duplicate = workers.submit(retry.submit, "same-key", _request()).result(timeout=WORKER_TIMEOUT)
            record = _only_publication(workspace)
            assert duplicate.job_id == record["job_id"]
            assert duplicate.status == "running"
            assert duplicate.artifact_id is None
            _assert_unpublished(workspace, record, "running")
        finally:
            release.set()
        completed = publishing.result(timeout=WORKER_TIMEOUT)
    assert retry.submit("same-key", _request()) == completed
    assert duplicate.output_slot_id == completed.output_slot_id
    assert writes == ["before_stage_write"]
    assert len(_rows(workspace.database, "SELECT * FROM generation_jobs")) == 1
    assert len(_rows(workspace.database, "SELECT * FROM generation_attempts")) == 1
    assert len(_rows(workspace.database, "SELECT * FROM generation_artifacts")) == 1
    _assert_committed(workspace, record)


def test_t03_concurrency_same_output_label_and_bytes_keep_distinct_logical_identities(
    workspace: _Workspace,
) -> None:
    """T03 identity: separate keys sharing output intent and content cannot overwrite one another."""
    services = (workspace.service(), workspace.service())
    start = Barrier(2)

    def submit(index: int):
        start.wait(timeout=WORKER_TIMEOUT)
        return services[index].submit(f"parallel-{index}", _request())

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(submit, index) for index in range(2)]
        results = [future.result(timeout=WORKER_TIMEOUT) for future in futures]
    assert all(result.status == "succeeded" for result in results)
    assert len({result.job_id for result in results}) == 2
    assert len({result.output_slot_id for result in results}) == 2
    assert len({result.artifact_id for result in results}) == 2
    artifacts = [services[0].get_artifact(result.artifact_id) for result in results]
    assert len({artifact.path for artifact in artifacts}) == 2
    assert len({artifact.sha256 for artifact in artifacts}) == 1
    _reconcile_repeatedly(workspace)
    for artifact in artifacts:
        _assert_committed(workspace, _publication_for(workspace, artifact.artifact_id))
    assert len(_rows(workspace.database, "SELECT * FROM generation_attempts")) == 2


def test_t03_identity_duplicate_import_bytes_keep_independent_provenance_and_lineage(
    workspace: _Workspace,
) -> None:
    """T03 identity: equal content hashes do not merge imports or their ordered source edges."""
    service = workspace.service()
    original = service.import_image(workspace.source_root, "input.png")
    duplicate = service.import_image(
        workspace.source_root, "input.png", sources=(ArtifactSource(original.artifact_id, "derivation"),)
    )
    independent = service.import_image(workspace.source_root, "input.png")
    assert len({original.artifact_id, duplicate.artifact_id, independent.artifact_id}) == 3
    assert original.sha256 == duplicate.sha256 == independent.sha256
    assert len({original.path, duplicate.path, independent.path}) == 3
    assert service.get_lineage(original.artifact_id)["parents"] == []
    assert service.get_lineage(independent.artifact_id)["parents"] == []
    assert service.get_lineage(duplicate.artifact_id)["parents"] == [{
        "source_id": original.artifact_id, "target_id": duplicate.artifact_id,
        "role": "derivation", "position": 0,
    }]
    snapshots = {artifact.artifact_id: artifact.to_dict() for artifact in (original, duplicate, independent)}
    _reconcile_repeatedly(workspace)
    for artifact_id, snapshot in snapshots.items():
        assert service.get_artifact(artifact_id).to_dict() == snapshot
        _assert_committed(workspace, _publication_for(workspace, artifact_id))


@pytest.mark.parametrize("operation", ("generated", "imported"))
@pytest.mark.parametrize("damage", ("missing", "truncated", "different-valid-image", "symlink"))
def test_t03_integrity_damage_is_reported_without_rewriting_provenance_or_success(
    workspace: _Workspace, operation: str, damage: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 integrity: observations of lost or corrupt files never rewrite immutable publication facts."""
    service = workspace.service()
    result = _invoke(service, workspace, operation)
    artifact = service.get_artifact(result.artifact_id)
    snapshot = artifact.to_dict()
    record = _only_publication(workspace)
    job = None if record["job_id"] is None else service.get_job(record["job_id"]).to_dict()
    lineage = service.get_lineage(artifact.artifact_id)
    path = Path(artifact.path)
    if damage == "missing":
        path.unlink()
    elif damage == "truncated":
        path.write_bytes(path.read_bytes()[:20])
    elif damage == "different-valid-image":
        replacement = path.with_name(".concurrent-valid-image")
        _write_png(replacement, (222, 3, 19))
        original_validate = publication_module.validate_image
        replaced = False

        def replace_path_after_open(content: BinaryIO):
            nonlocal replaced
            if not replaced:
                replacement.replace(path)
                replaced = True
            return original_validate(content)

        monkeypatch.setattr(publication_module, "validate_image", replace_path_after_open)
    else:
        path.unlink()
        path.symlink_to(workspace.source_root / "input.png")
    damaged_identity = None if damage == "missing" else _identity(path)
    damaged_bytes = None if damage == "missing" else path.read_bytes()
    expected = "missing" if damage == "missing" else "corrupt"
    assert service.get_integrity(artifact.artifact_id)["status"] == expected
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["integrity"][0]["status"] == expected
        assert report["publications"][0]["state"] == "committed"
        assert service.get_artifact(artifact.artifact_id).to_dict() == snapshot
        assert service.get_lineage(artifact.artifact_id) == lineage
        if job is not None:
            assert service.get_job(record["job_id"]).to_dict() == job
        if damage == "missing":
            assert not path.exists()
        elif damage == "different-valid-image":
            assert path.is_symlink() is False
            assert path.read_bytes() != damaged_bytes
        else:
            assert _identity(path) == damaged_identity
            assert path.read_bytes() == damaged_bytes
            assert path.is_symlink() == (damage == "symlink")


def test_t03_ownership_publication_tokens_are_unique_and_destination_token_is_stable(
    workspace: _Workspace,
) -> None:
    """T03 ownership: equal bytes have separate ownership tokens under one durable root token."""
    first = workspace.service().submit("first-owner", _request())
    first_record = _publication_for(workspace, first.artifact_id)
    first_artifact = workspace.service().get_artifact(first.artifact_id)
    root_token = _token(workspace.output, ROOT_TOKEN)
    first_token = _token(Path(first_artifact.path), STAGE_TOKEN)
    assert root_token and first_token
    second = workspace.service().submit("second-owner", _request())
    second_record = _publication_for(workspace, second.artifact_id)
    second_artifact = workspace.service().get_artifact(second.artifact_id)
    second_token = _token(Path(second_artifact.path), STAGE_TOKEN)
    assert second_token and second_token != first_token
    assert first_artifact.sha256 == second_artifact.sha256
    assert first_record["root_token"] == second_record["root_token"] == root_token.decode("ascii")
    cleanup = workspace.output / CLEANUP_DIRECTORY
    assert stat.S_IMODE(cleanup.stat().st_mode) == 0o700
    assert _token(cleanup, CLEANUP_TOKEN) == root_token
    _reconcile_repeatedly(workspace)
    assert _token(workspace.output, ROOT_TOKEN) == root_token
    assert _token(Path(first_artifact.path), STAGE_TOKEN) == first_token
    assert _token(Path(second_artifact.path), STAGE_TOKEN) == second_token

    service_a = workspace.service()
    service_b = GenerationService(workspace.database, workspace.output.with_name("artifacts-b"))
    artifact_b = service_b.import_image(workspace.source_root, "input.png")
    assert service_b.get_integrity(artifact_b.artifact_id)["status"] == "ok"
    foreign = service_a.get_integrity(artifact_b.artifact_id)
    assert foreign["status"] == "ok"
    assert foreign["detail"] is None
    foreign_path = Path(artifact_b.path)
    foreign_path.write_bytes(foreign_path.read_bytes() + b"\0")
    assert service_a.get_integrity(artifact_b.artifact_id)["status"] == "corrupt"
    foreign_path.unlink()
    assert service_a.get_integrity(artifact_b.artifact_id)["status"] == "missing"
    assert service_a.get_integrity(first_artifact.artifact_id)["status"] == "ok"


@pytest.mark.parametrize("owner", ("root", "stage"))
@pytest.mark.parametrize("damage", ("missing", "mismatch"))
@pytest.mark.parametrize("checkpoint", ("stage_written", "ready_committed", "after_commit"))
def test_t03_ownership_recovery_never_manufactures_missing_or_mismatched_tokens(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
    owner: str, damage: str, checkpoint: str,
) -> None:
    """T03 ownership: uncertain tokens prevent deletion or new success through repeated restarts."""
    record = _crash_at(workspace, checkpoint)
    stage = workspace.output / record["stage_name"]
    captured = workspace.output / CLEANUP_DIRECTORY / record["publication_id"]
    original_bytes, original_identity = stage.read_bytes(), _identity(stage)
    target = workspace.output if owner == "root" else stage
    token_name = ROOT_TOKEN if owner == "root" else STAGE_TOKEN
    original_token = _token(target, token_name)
    assert original_token
    artifacts_before = _rows(workspace.database, "SELECT * FROM generation_artifacts")
    job_before = workspace.service().get_job(record["job_id"]).to_dict()
    final = None if record["final_name"] is None else workspace.output / record["final_name"]
    final_existed = final is not None and final.exists()
    with monkeypatch.context() as fault:
        observed = _simulate_token_damage(fault, target, token_name, damage)
        for _ in range(3):
            _reconcile_without_authority(workspace, root_failure=owner == "root")
            retained = [path for path in (stage, captured) if path.exists()]
            assert len(retained) == 1
            assert retained[0].read_bytes() == original_bytes
            assert _identity(retained[0]) == original_identity
            assert _rows(workspace.database, "SELECT * FROM generation_artifacts") == artifacts_before
            assert _only_publication(workspace)["root_token"] == record["root_token"]
            if final_existed:
                assert final.read_bytes() == original_bytes
                assert _identity(final) == original_identity
            elif final is not None:
                assert not final.exists()
            if checkpoint == "after_commit":
                assert workspace.service().get_job(record["job_id"]).to_dict() == job_before
                assert _only_publication(workspace)["state"] == "committed"
            else:
                job = workspace.service().get_job(record["job_id"])
                assert job.status in {"running", "failed"}
                assert job.artifact_id is None
        assert observed["reads"] > 0
        assert observed["creates"] == []
    physical_target = workspace.output if owner == "root" else retained[0]
    assert _token(physical_target, token_name) == original_token


@pytest.mark.parametrize("owner", ("stage", "root"))
def test_t03_ownership_simulated_inode_reuse_cannot_replace_absent_token_evidence(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch, owner: str,
) -> None:
    """T03 inode ABA: matching device/inode numbers never authorize an unmarked replacement."""
    record = _crash_at(workspace, "ready_committed")
    stage = workspace.output / record["stage_name"]
    encoded = stage.read_bytes()
    retired_stage = None
    if owner == "stage":
        replacement = workspace.source_root / "foreign-stage.png"
        replacement.write_bytes(encoded)
        replacement.replace(stage)
        target, token_name = stage, STAGE_TOKEN
        identities = {_identity(stage): (record["stage_dev"], record["stage_ino"])}
    else:
        retired_root = workspace.source_root / "retired-output"
        workspace.output.rename(retired_root)
        retired_stage = retired_root / record["stage_name"]
        workspace.output.mkdir(mode=0o700)
        stage.write_bytes(encoded)
        target, token_name = workspace.output, ROOT_TOKEN
        identities = {
            _identity(workspace.output): (record["root_dev"], record["root_ino"]),
            _identity(stage): (record["stage_dev"], record["stage_ino"]),
        }
    assert _token(target, token_name) is None
    assert all(actual != saved for actual, saved in identities.items())
    actual_stage_identity = _identity(stage)
    original_fstat = os.fstat
    spoofed = []

    class ReusedInodeStat:
        """Preserve real file properties while modelling a recycled inode number."""

        def __init__(self, actual: os.stat_result, saved: tuple[int, int]) -> None:
            self.actual = actual
            self.st_dev, self.st_ino = saved

        def __getattr__(self, name):
            return getattr(self.actual, name)

    def reused_inode(descriptor: int):
        actual = original_fstat(descriptor)
        identity = (actual.st_dev, actual.st_ino)
        if identity in identities:
            spoofed.append(identity)
            return ReusedInodeStat(actual, identities[identity])
        return actual

    with monkeypatch.context() as fault:
        observed = _simulate_token_damage(fault, target, token_name, "missing")
        fault.setattr(publication_module.os, "fstat", reused_inode)
        for _ in range(3):
            _reconcile_without_authority(workspace, root_failure=owner == "root")
            assert stage.read_bytes() == encoded
            assert _identity(stage) == actual_stage_identity
            assert not (workspace.output / record["final_name"]).exists()
            _assert_unpublished(workspace, record, "running")
            assert _only_publication(workspace)["state"] == "ready"
        assert observed["reads"] > 0
        assert observed["creates"] == []
        # A missing root token may be rejected before the first root inode check.
        assert spoofed or owner == "root"
    assert _token(target, token_name) is None
    if retired_stage is not None:
        assert retired_stage.read_bytes() == encoded
        assert _identity(retired_stage) == (record["stage_dev"], record["stage_ino"])


@pytest.mark.parametrize("damage", ("missing", "mismatch"))
def test_t03_ownership_cleanup_directory_token_is_required_before_capture(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch, damage: str,
) -> None:
    """T03 cleanup authority: an existing private directory is not adopted without its root token."""
    service = workspace.service()
    result = service.submit("cleanup-owner", _request())
    artifact = service.get_artifact(result.artifact_id)
    record = _only_publication(workspace)
    final = Path(artifact.path)
    snapshot, encoded = artifact.to_dict(), final.read_bytes()
    cleanup = workspace.output / CLEANUP_DIRECTORY
    original_token = _token(cleanup, CLEANUP_TOKEN)
    assert original_token == _token(workspace.output, ROOT_TOKEN)
    stage = workspace.output / record["stage_name"]
    # A surviving owned staging link is the only additional state needed to
    # reproduce interrupted post-commit cleanup, without mutating database rows.
    os.link(final, stage)
    marker = cleanup / "unowned.txt"
    marker.write_bytes(b"preserve unknown private-directory content")
    with monkeypatch.context() as fault:
        observed = _simulate_token_damage(fault, cleanup, CLEANUP_TOKEN, damage)
        for _ in range(3):
            _reconcile_without_authority(workspace)
            assert stage.read_bytes() == encoded
            assert _identity(stage) == (record["stage_dev"], record["stage_ino"])
            assert final.read_bytes() == encoded
            assert marker.read_bytes() == b"preserve unknown private-directory content"
            assert service.get_artifact(result.artifact_id).to_dict() == snapshot
            assert service.get_job(result.job_id).status == "succeeded"
            assert not (cleanup / record["publication_id"]).exists()
        assert observed["reads"] > 0
        assert observed["creates"] == []
    assert _token(cleanup, CLEANUP_TOKEN) == original_token


def test_t03_ownership_stage_swapped_at_cleanup_rename_is_retained_without_deleting_media(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 capture race: rename may capture a competitor, but validation must preserve its bytes."""
    competitor = workspace.source_root / "competitor.png"
    foreign_bytes = _write_png(competitor, (251, 7, 80))
    foreign_identity = _identity(competitor)
    original_rename, original_fsync = os.rename, os.fsync
    swaps, events = [], []

    def track_sync(descriptor: int) -> None:
        observed = os.fstat(descriptor)
        original_fsync(descriptor)
        events.append(("sync", observed.st_dev, observed.st_ino))

    def swap_before_rename(source, destination, *args, **kwargs) -> None:
        if Path(os.fsdecode(source)).name.endswith(".stage"):
            record = _only_publication(workspace)
            assert Path(os.fsdecode(source)).name == record["stage_name"]
            assert Path(os.fsdecode(destination)).name == record["publication_id"]
            assert swaps == []
            assert record["state"] == "committed"
            final = workspace.output / record["final_name"]
            swaps.append((final.read_bytes(), _identity(final)))
            competitor.replace(workspace.output / record["stage_name"])
            original_rename(source, destination, *args, **kwargs)
            events.append(("capture",))
            return
        original_rename(source, destination, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(publication_module.os, "rename", swap_before_rename)
        fault.setattr(publication_module.os, "fsync", track_sync)
        result = workspace.service().submit("capture-race", _request())
    assert result.status == "succeeded"
    assert len(swaps) == 1
    record = _only_publication(workspace)
    cleanup = workspace.output / CLEANUP_DIRECTORY
    captured = cleanup / record["publication_id"]
    final = workspace.output / record["final_name"]
    assert stat.S_IMODE(cleanup.stat().st_mode) == 0o700
    assert _token(cleanup, CLEANUP_TOKEN) == _token(workspace.output, ROOT_TOKEN)
    assert captured.read_bytes() == foreign_bytes
    assert _identity(captured) == foreign_identity
    assert _token(captured, STAGE_TOKEN) is None
    assert not (workspace.output / record["stage_name"]).exists()
    capture_index = events.index(("capture",))
    assert ("sync", *_identity(workspace.output)) in events[capture_index + 1:]
    assert ("sync", *_identity(cleanup)) in events[capture_index + 1:]
    snapshot = _assert_committed(workspace, record)
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["publications"][0]["state"] == "committed"
        assert captured.read_bytes() == foreign_bytes
        assert _identity(captured) == foreign_identity
        assert (final.read_bytes(), _identity(final)) == swaps[0]
        assert workspace.service().get_artifact(result.artifact_id).to_dict() == snapshot
        assert workspace.service().get_job(result.job_id).status == "succeeded"
    assert {path.name for path in workspace.output.iterdir() if not path.name.startswith(".")} == {final.name}


@pytest.mark.parametrize("substitution", ("symlink-to-foreign-file", "hardlink-to-committed-artifact"))
def test_t03_generated_writer_uses_pinned_stream_after_stage_name_substitution(
    workspace: _Workspace, substitution: str,
) -> None:
    """T03 generated writer: an attacker-controlled stage name cannot redirect the pinned stream."""
    service = workspace.service()
    protected = service.submit("protected-media", _request())
    protected_artifact = service.get_artifact(protected.artifact_id)
    protected_path = Path(protected_artifact.path)
    protected_snapshot = service.get_provenance(protected.job_id)
    target = (workspace.source_root / "input.png"
              if substitution == "symlink-to-foreign-file" else protected_path)
    target_bytes, target_identity = target.read_bytes(), _identity(target)
    pinned = workspace.source_root / "pinned-original.stage"
    replacements = []

    def substitute(name: str) -> None:
        if name != "before_stage_write":
            return
        records = _rows(workspace.database, "SELECT * FROM artifact_publications WHERE state = 'allocated'")
        assert len(records) == 1
        record = records[0]
        stage = workspace.output / record["stage_name"]
        stage.rename(pinned)
        if substitution == "symlink-to-foreign-file":
            stage.symlink_to(target)
        else:
            os.link(target, stage)
        replacements.append((record, _identity(stage)))

    malicious = workspace.service(publication_checkpoint=substitute)
    request = GenerationRequest(prompt="A red saltwater buoy", seed=99, width=11, height=9)
    with pytest.raises(GenerationExecutionError, match="staging|writer|owned") as failed:
        malicious.submit("substituted-stage", request)
    assert len(replacements) == 1
    record, alias_identity = replacements[0]
    assert failed.value.job_id == record["job_id"]
    assert _identity(pinned) == (record["stage_dev"], record["stage_ino"])
    with Image.open(pinned) as image:
        image.load()
        assert image.size == (request.width, request.height)
        assert image.format == "PNG"
    assert pinned.read_bytes() != target_bytes
    assert target.read_bytes() == target_bytes
    assert _identity(target) == target_identity
    _assert_unpublished(workspace, record, "failed")
    _reconcile_repeatedly(workspace, status="attention_required")
    candidates = (
        workspace.output / record["stage_name"],
        workspace.output / CLEANUP_DIRECTORY / record["publication_id"],
    )
    retained = [path for path in candidates if path.exists() or path.is_symlink()]
    assert len(retained) == 1
    assert _identity(retained[0]) == alias_identity
    assert retained[0].read_bytes() == target_bytes
    assert target.read_bytes() == target_bytes
    assert _identity(target) == target_identity
    assert service.get_provenance(protected.job_id) == protected_snapshot
    assert service.get_integrity(protected.artifact_id)["status"] == "ok"


def test_t03_publication_final_mutated_after_validation_returns_cannot_commit_metadata(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 validation race: the final inode snapshot must precede validation and its return."""
    final_phase = Event()
    real_validate = publication_module.validate_image
    mutations, commits = [], []

    def checkpoint(name: str) -> None:
        if name == "file_published":
            final_phase.set()

    def mutate_after_validation(content: BinaryIO):
        info = real_validate(content)
        if final_phase.is_set() and not mutations:
            record = _only_publication(workspace)
            final = workspace.output / record["final_name"]
            observed = os.fstat(content.fileno())
            assert _identity(final) == (observed.st_dev, observed.st_ino)
            before = final.read_bytes()
            # A size change makes this deterministic even on filesystems with
            # coarse timestamps. The returned metadata still describes before.
            with final.open("ab") as changed:
                changed.write(b"appended after final validation returned")
                changed.flush()
            mutations.append((before, final.read_bytes(), _identity(final)))
        return info

    service = workspace.service(publication_checkpoint=checkpoint)
    real_complete = service._store.complete_execution

    def observe_commit(*args, **kwargs) -> None:
        commits.append(args[0].artifact_id)
        real_complete(*args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(publication_module, "validate_image", mutate_after_validation)
        fault.setattr(service._store, "complete_execution", observe_commit)
        with pytest.raises(PublicationIncompleteError):
            service.submit("validate-return-race", _request())
    assert len(mutations) == 1
    assert commits == []
    before, changed, identity = mutations[0]
    assert len(changed) > len(before)
    record = _only_publication(workspace)
    final = workspace.output / record["final_name"]
    stage = workspace.output / record["stage_name"]
    assert record["state"] == "ready"
    _assert_unpublished(workspace, record, "running")
    for report in _reconcile_repeatedly(workspace, status="attention_required"):
        assert report["publications"][0]["state"] == "ready"
        assert final.read_bytes() == stage.read_bytes() == changed
        assert _identity(final) == _identity(stage) == identity
        _assert_unpublished(workspace, record, "running")


def test_t03_publication_fifo_replacing_final_is_opened_nonblocking_and_preserved(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 final-file acquisition: a FIFO substitution cannot block while holding the root lock."""
    original_open = os.open
    substituted, final_open_flags = [], []

    def replace_final(name: str) -> None:
        if name != "file_published":
            return
        record = _only_publication(workspace)
        final = workspace.output / record["final_name"]
        staged_bytes = (workspace.output / record["stage_name"]).read_bytes()
        final.unlink()
        os.mkfifo(final, 0o600)
        substituted.append((record, _identity(final), staged_bytes))

    def guarded_open(path, flags: int, *args, **kwargs) -> int:
        if substituted and Path(os.fsdecode(path)).name == substituted[0][0]["final_name"]:
            final_open_flags.append(flags)
            # Assert before the syscall, so even an implementation regression
            # produces a bounded failure instead of hanging the test runner.
            assert flags & os.O_NONBLOCK, "the final descriptor must be opened nonblocking"
        return original_open(path, flags, *args, **kwargs)

    service = workspace.service(publication_checkpoint=replace_final)
    with monkeypatch.context() as fault:
        fault.setattr(publication_module.os, "open", guarded_open)
        with pytest.raises(PublicationIncompleteError):
            service.submit("fifo-final", _request())
        assert len(substituted) == 1
        assert final_open_flags
        assert all(flags & os.O_NONBLOCK for flags in final_open_flags)
        record, fifo_identity, staged_bytes = substituted[0]
        final = workspace.output / record["final_name"]
        stage = workspace.output / record["stage_name"]
        assert record["state"] == "ready"
        _assert_unpublished(workspace, record, "running")
        for report in _reconcile_repeatedly(workspace, status="attention_required"):
            assert report["publications"][0]["state"] == "ready"
            assert stat.S_ISFIFO(final.lstat().st_mode)
            assert _identity(final) == fifo_identity
            assert stage.read_bytes() == staged_bytes
            _assert_unpublished(workspace, record, "running")


def _store_snapshot(workspace: _Workspace) -> dict[str, list[dict]]:
    """Read every durable table a rejected publication transition could touch."""
    tables = (
        "artifact_publications",
        "generation_artifacts",
        "artifact_edges",
        "generation_jobs",
        "generation_attempts",
    )
    return {
        table: _rows(workspace.database, f"SELECT * FROM {table} ORDER BY rowid")
        for table in tables
    }


def test_t03_lifecycle_general_update_cannot_set_committed_or_publish(
    workspace: _Workspace,
) -> None:
    """T03 journal API: metadata updates cannot bypass the commit transaction."""
    record = _crash_at(workspace, "before_stage_write")
    publication_id = str(record["publication_id"])
    before = _store_snapshot(workspace)
    store = workspace.service()._store

    with pytest.raises(ValueError, match="unsupported publication update"):
        store.update_publication(publication_id, state="committed")

    assert _store_snapshot(workspace) == before
    assert store.publication(publication_id)["state"] == "allocated"
    assert _rows(workspace.database, "SELECT * FROM generation_artifacts") == []
    assert _rows(workspace.database, "SELECT * FROM artifact_edges") == []
    job = workspace.service().get_job(str(record["job_id"]))
    assert job.status == "running"
    assert job.artifact_id is None


def test_t03_lifecycle_allocated_to_ready_transition_records_metadata(
    workspace: _Workspace,
) -> None:
    """T03 journal API: ready is an explicit allocated-to-ready transition."""
    record = _crash_at(workspace, "before_stage_write")
    publication_id = str(record["publication_id"])
    store = workspace.service()._store

    store.mark_publication_ready(publication_id, "final.png", '{"artifact_id": "test"}')

    durable = store.publication(publication_id)
    assert durable["state"] == "ready"
    assert durable["final_name"] == "final.png"
    assert durable["artifact_json"] == '{"artifact_id": "test"}'
    with pytest.raises(RuntimeError, match="not allocated"):
        store.abandon_publication(publication_id, "too late")
    assert store.publication(publication_id)["state"] == "ready"


def test_t03_lifecycle_allocated_to_abandoned_transition_records_error(
    workspace: _Workspace,
) -> None:
    """T03 journal API: abandonment is an explicit allocated-to-abandoned transition."""
    record = _crash_at(workspace, "before_stage_write")
    publication_id = str(record["publication_id"])
    store = workspace.service()._store

    store.abandon_publication(publication_id, "injected abandonment")

    durable = store.publication(publication_id)
    assert durable["state"] == "abandoned"
    assert durable["error"] == "injected abandonment"
    with pytest.raises(RuntimeError, match="not allocated"):
        store.mark_publication_ready(publication_id, "final.png", "{}")
    assert store.publication(publication_id)["state"] == "abandoned"


def test_t03_lifecycle_committed_publication_rejects_transition_methods(
    workspace: _Workspace,
) -> None:
    """T03 journal API: committed publications accept no further lifecycle transition."""
    service = workspace.service()
    artifact = service.import_image(workspace.source_root, "input.png")
    record = _publication_for(workspace, artifact.artifact_id)
    assert record["state"] == "committed"

    with pytest.raises(RuntimeError, match="not allocated"):
        service._store.mark_publication_ready(
            str(record["publication_id"]), Path(artifact.path).name, "{}"
        )
    with pytest.raises(RuntimeError, match="not allocated"):
        service._store.abandon_publication(str(record["publication_id"]), "too late")

    assert service._store.publication(str(record["publication_id"]))["state"] == "committed"


def _png_bytes(size: tuple[int, int], color: tuple[int, int, int]) -> bytes:
    """Encode one ordinary image independently of the publication adapter."""
    stream = io.BytesIO()
    Image.new("RGB", size, color).save(stream, format="PNG")
    return stream.getvalue()


def _png_bytes_of_size(encoded_size: int, color: tuple[int, int, int]) -> bytes:
    """Encode a valid image padded to an exact length with a text chunk."""
    base = _png_bytes((17, 13), color)
    if len(base) == encoded_size:
        return base
    # A tEXt chunk occupies 12 bytes of envelope plus its key, separator, and value.
    padding = encoded_size - len(base) - 20
    assert padding >= 0, (len(base), encoded_size)
    metadata = PngInfo()
    metadata.add_text("Comment", "x" * padding)
    stream = io.BytesIO()
    Image.new("RGB", (17, 13), color).save(stream, format="PNG", pnginfo=metadata)
    replacement = stream.getvalue()
    assert len(replacement) == encoded_size, (len(replacement), encoded_size)
    return replacement


def _rewrite_in_place_during_validation(
    monkeypatch: pytest.MonkeyPatch, replacement: bytes, path: Path,
) -> list[tuple[os.stat_result, os.stat_result]]:
    """Rewrite validated bytes in the same inode before verification returns."""
    real_validate = publication_module.validate_image
    observations: list[tuple[os.stat_result, os.stat_result]] = []
    expected_identity = _identity(path)

    def validate_then_rewrite(content: BinaryIO):
        info = real_validate(content)
        descriptor = os.open(path, os.O_RDWR)
        before = os.fstat(descriptor)
        assert len(replacement) == before.st_size
        os.pwrite(descriptor, replacement, 0)
        os.ftruncate(descriptor, len(replacement))
        os.fsync(descriptor)
        changed = os.fstat(descriptor)
        # Force a distinct timestamp so detection never depends on clock resolution.
        os.utime(descriptor, ns=(changed.st_atime_ns, changed.st_mtime_ns + 1_000_000_000))
        after = os.fstat(descriptor)
        os.close(descriptor)
        assert _identity_from_stat(before) == _identity_from_stat(after)
        assert _identity_from_stat(after) == expected_identity
        assert before.st_size == after.st_size
        assert (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)
        observations.append((before, after))
        return info

    monkeypatch.setattr(publication_module, "validate_image", validate_then_rewrite)
    return observations


def _identity_from_stat(value: os.stat_result) -> tuple[int, int]:
    """Expose the device and inode pair of an already-open descriptor snapshot."""
    return value.st_dev, value.st_ino


@pytest.mark.parametrize("operation", ("generated", "imported"))
def test_t03_integrity_same_inode_rewrite_during_validation_is_corrupt(
    workspace: _Workspace, operation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 integrity: an equal-length in-place rewrite cannot be reported as trusted."""
    service = workspace.service()
    invoked = _invoke(service, workspace, operation)
    artifact = service.get_artifact(invoked.artifact_id)
    assert service.get_integrity(artifact.artifact_id)["status"] == "ok"
    replacement = _png_bytes_of_size(artifact.file_size, (200, 30, 70))
    assert len(replacement) == Path(artifact.path).stat().st_size

    observations = _rewrite_in_place_during_validation(
        monkeypatch, replacement, Path(artifact.path)
    )
    report = service.get_integrity(artifact.artifact_id)

    assert report["status"] == "corrupt"
    assert "changed during validation" in str(report["detail"])
    assert len(observations) == 1


def test_t03_generation_reference_rejects_same_inode_rewrite_before_adapter(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 reference admission: changed content fails before adapter execution."""
    service = workspace.service()
    parent = service.import_image(workspace.source_root, "input.png")
    calls: list[tuple[object, ...]] = []

    def record_adapter_call(*args: object, **kwargs: object) -> None:
        calls.append(args)

    monkeypatch.setattr(service.adapter, "generate", record_adapter_call)
    _rewrite_in_place_during_validation(
        monkeypatch,
        _png_bytes_of_size(parent.file_size, (200, 30, 70)),
        Path(parent.path),
    )

    with pytest.raises(GenerationExecutionError, match="reference artifact"):
        service.submit("rewrite-reference", _request((parent.artifact_id,)))

    assert calls == []
    jobs = _rows(workspace.database, "SELECT * FROM generation_jobs")
    assert len(jobs) == 1
    assert jobs[0]["status"] == "failed"
    assert service.get_job(str(jobs[0]["job_id"])).artifact_id is None


def test_t03_reconciliation_reports_same_inode_rewrite_without_rewriting_success(
    workspace: _Workspace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T03 reconciliation: integrity observations cannot rewrite committed history."""
    service = workspace.service()
    result = service.submit("reconcile-rewrite", _request())
    artifact = service.get_artifact(result.artifact_id)
    record = _only_publication(workspace)
    frozen_artifact = artifact.to_dict()
    frozen_lineage = service.get_lineage(artifact.artifact_id)
    frozen_job = service.get_job(str(record["job_id"])).to_dict()
    _rewrite_in_place_during_validation(
        monkeypatch,
        _png_bytes_of_size(artifact.file_size, (200, 30, 70)),
        Path(artifact.path),
    )

    report = service.reconcile()

    assert report["status"] == "attention_required"
    assert [entry["status"] for entry in report["integrity"]] == ["corrupt"]
    assert service.get_artifact(artifact.artifact_id).to_dict() == frozen_artifact
    assert service.get_lineage(artifact.artifact_id) == frozen_lineage
    assert service.get_job(str(record["job_id"])).to_dict() == frozen_job
    assert _only_publication(workspace)["state"] == "committed"
