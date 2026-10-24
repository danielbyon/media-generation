"""Independent process coverage of explicit import, generation, and inspection."""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

from media_generation import cli as cli_module
from media_generation.adapters import DeterministicCpuAdapter
from media_generation.service import GenerationService
from media_generation.store import SQLiteStore


def cli(tmp_path, *arguments, success=True, inspection_failure=False):
    env = os.environ.copy()
    env.pop('PYTHONPATH',None)
    process = subprocess.run([sys.executable,'-m','media_generation',*map(str,arguments)],
                             cwd=tmp_path,env=env,capture_output=True,text=True,timeout=30)
    if success:
        assert process.returncode == 0, process.stderr
        return json.loads(process.stdout)
    assert process.returncode != 0
    if inspection_failure:
        return json.loads(process.stdout)
    assert not process.stdout
    return json.loads(process.stderr)


def test_import_reference_generation_and_inspection_across_processes(tmp_path):
    """TAC-11: imported bytes become references using only stable artifact IDs."""
    source = tmp_path/'approved';source.mkdir()
    image = source/'image.untrusted-extension'
    Image.new('RGB',(13,17),'green').save(image,format='JPEG')
    real_root = tmp_path/'artifact-store'
    real_root.mkdir()
    root = tmp_path/'artifacts'
    root.symlink_to(real_root, target_is_directory=True)
    database = tmp_path/'studio.sqlite'
    malformed_lineage = cli(tmp_path,'import','--db',database,'--output-dir',root,
                            '--approved-root',source,'--source',image.name,
                            '--sources-json','{',success=False)
    assert malformed_lineage['error']['code'] == 'validation_error'
    assert malformed_lineage['error']['message'].startswith('invalid sources JSON:')
    imported = cli(tmp_path,'import','--db',database,'--output-dir',root,
                   '--approved-root',source,'--source',image.name)
    assert imported['format'] == 'JPEG' and imported['origin'] == 'imported'
    assert Path(imported['path']).read_bytes() == image.read_bytes()
    assert Path(imported['path']).parent == real_root.resolve()
    assert 'job_id' not in imported
    generated = cli(tmp_path,'submit','--db',database,'--output-dir',root,
                    '--idempotency-key','from-import','--request-json',json.dumps({
                        'prompt':'From imported reference','reference_ids':[imported['artifact_id']]}))
    artifact = cli(tmp_path,'artifact','--db',database,'--id',generated['artifact_id'])
    assert set(artifact) == {'artifact_id','job_id','attempt_id','output_slot_id','path',
        'media_type','format','width','height','file_size','sha256','created_at'}
    parents = cli(tmp_path,'lineage','--db',database,'--id',generated['artifact_id'])['parents']
    assert parents[0]['source_id'] == imported['artifact_id'] and parents[0]['role'] == 'reference'
    assert cli(tmp_path,'integrity','--db',database,'--output-dir',root,'--id',imported['artifact_id'])['status']=='ok'
    Path(imported['path']).write_bytes(b'externally changed')
    assert cli(tmp_path,'integrity','--db',database,'--output-dir',root,'--id',imported['artifact_id'])['status']=='corrupt'
    assert cli(tmp_path,'artifact','--db',database,'--id',imported['artifact_id']) == imported
    report=cli(tmp_path,'reconcile','--db',database,'--output-dir',root,
               success=False,inspection_failure=True)
    assert report['status']=='attention_required'
    assert len(report['integrity'])==2
    assert not report['orphan_files']


@pytest.mark.parametrize('source_name',['../outside.png','/tmp/outside.png','https://example.com/image.png','bad.png'])
def test_cli_rejects_unapproved_or_malformed_source_without_artifact(tmp_path,source_name):
    source=tmp_path/'approved';source.mkdir();(source/'bad.png').write_bytes(b'not a PNG')
    database=tmp_path/'studio.sqlite'
    error=cli(tmp_path,'import','--db',database,'--output-dir',tmp_path/'images',
              '--approved-root',source,'--source',source_name,success=False)
    assert error['error']['code'] == 'validation_error'
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM generation_artifacts').fetchone()[0] == 0
        assert connection.execute('SELECT count(*) FROM generation_jobs').fetchone()[0] == 0


@pytest.mark.parametrize("link_position", ("ancestor", "root", "directory", "leaf"))
def test_cli_import_rejects_symlink_components_in_approved_source_path(
    tmp_path, link_position,
):
    """TAC-3: the CLI reports a validation error and leaves durable state unchanged."""
    base = tmp_path.resolve()
    approved = base / "approved-source"
    nested = approved / "nested"
    nested.mkdir(parents=True)
    source = nested / "input.png"
    Image.new("RGB", (13, 17), "green").save(source, format="PNG")
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

    database = base / "studio.sqlite"
    output = base / "artifacts"
    error = cli(
        tmp_path,
        "import",
        "--db",
        database,
        "--output-dir",
        output,
        "--approved-root",
        approved_root,
        "--source",
        relative,
        success=False,
    )
    assert error["error"]["code"] == "validation_error"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM artifact_edges").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM artifact_publications").fetchone()[0] == 0


def test_integrity_help_distinguishes_owner_from_legacy_directory(capsys):
    """The help names the publication owner used by journal-backed artifacts."""
    with pytest.raises(SystemExit) as stopped:
        cli_module.main(["integrity", "--help"])
    assert stopped.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "journal-backed artifacts use their recorded publication owner" in help_text
    assert "legacy artifacts without publication records" in help_text


def _submit_arguments(database, output):
    """Use the same request and idempotency key throughout a recovery scenario."""
    return [
        "submit", "--db", str(database), "--output-dir", str(output),
        "--idempotency-key", "publication-error-contract", "--request-json",
        json.dumps({"prompt": "Recover publication", "width": 16, "height": 16}),
    ]


@pytest.mark.parametrize("checkpoint", (
    "ready_committed", "before_publish", "file_published",
    "before_directory_sync", "directory_synced", "before_commit",
))
def test_cli_recoverable_publication_reports_job_and_recovers(
    tmp_path, monkeypatch, capsys, checkpoint,
):
    """A ready publication reports recovery guidance without failing its execution."""
    database, output = tmp_path / "studio.sqlite", tmp_path / "artifacts"

    def interrupt(name):
        if name == checkpoint:
            raise OSError("injected recoverable publication failure")

    def service_with_fault(*args, **kwargs):
        return GenerationService(*args, publication_checkpoint=interrupt, **kwargs)

    monkeypatch.setattr(cli_module, "GenerationService", service_with_fault)
    arguments = _submit_arguments(database, output)
    assert cli_module.main(arguments) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["code"] == "publication_incomplete"
    assert "injected recoverable publication failure" in error["message"]
    assert "reconcile" in error["recovery"]
    assert "same database and output directory" in error["recovery"]
    assert "same request and idempotency key" in error["recovery"]
    job_id = error["job_id"]
    job = cli(tmp_path, "job", "--db", database, "--id", job_id)
    assert job["status"] == "running"
    assert job["artifact_id"] is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT status, finished_at, error_message FROM generation_attempts"
        ).fetchall() == [("running", None, None)]
        assert connection.execute(
            "SELECT state FROM artifact_publications"
        ).fetchall() == [("ready",)]
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone() == (0,)

    pending = cli(tmp_path, *arguments)
    assert pending["job_id"] == job_id
    assert pending["status"] == "running" and pending["artifact_id"] is None
    report = cli(tmp_path, "reconcile", "--db", database, "--output-dir", output)
    assert report["status"] == "complete"
    recovered = cli(tmp_path, *arguments)
    assert recovered["job_id"] == job_id and recovered["status"] == "succeeded"
    assert recovered["artifact_id"] is not None
    assert cli(tmp_path, *arguments) == recovered
    artifact = cli(tmp_path, "artifact", "--db", database, "--id", recovered["artifact_id"])
    assert Path(artifact["path"]).is_file()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM generation_jobs").fetchall() == [("succeeded",)]
        assert connection.execute("SELECT status FROM generation_attempts").fetchall() == [("succeeded",)]
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone() == (1,)


def test_cli_adapter_failure_remains_terminal_generation_failed(tmp_path, monkeypatch, capsys):
    """An adapter failure before publication readiness retains the T01 error contract."""
    database, output = tmp_path / "studio.sqlite", tmp_path / "artifacts"

    def fail_generation(self, plan, staged):
        raise RuntimeError("injected adapter failure")

    monkeypatch.setattr(DeterministicCpuAdapter, "generate", fail_generation)
    arguments = _submit_arguments(database, output)
    assert cli_module.main(arguments) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["code"] == "generation_failed"
    assert "injected adapter failure" in error["message"]
    assert "recovery" not in error
    replay = cli(tmp_path, *arguments)
    assert replay["job_id"] == error["job_id"]
    assert replay["status"] == "failed" and replay["artifact_id"] is None
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM generation_jobs").fetchall() == [("failed",)]
        assert connection.execute("SELECT status FROM generation_attempts").fetchall() == [("failed",)]
        assert connection.execute("SELECT count(*) FROM generation_artifacts").fetchone() == (0,)


def test_cli_reconciliation_before_error_classification_returns_committed_success(
    tmp_path, monkeypatch, capsys,
):
    """A reconciler completing after publisher unlock must win over an earlier error."""
    database, output = tmp_path / "studio.sqlite", tmp_path / "artifacts"

    def interrupt(name):
        if name == "ready_committed":
            raise OSError("injected recoverable publication failure")

    def service_with_fault(*args, **kwargs):
        service = GenerationService(*args, publication_checkpoint=interrupt, **kwargs)
        fail_execution = service._store.fail_execution

        def reconcile_then_record(*args, **kwargs):
            GenerationService(database, output).reconcile()
            return fail_execution(*args, **kwargs)

        monkeypatch.setattr(service._store, "fail_execution", reconcile_then_record)
        return service

    monkeypatch.setattr(cli_module, "GenerationService", service_with_fault)
    arguments = _submit_arguments(database, output)
    assert cli_module.main(arguments) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["status"] == "succeeded" and result["artifact_id"] is not None
    assert cli(tmp_path, *arguments) == result


@pytest.mark.parametrize("failure", ("after_commit", "before_reply", "commit_acknowledgement"))
def test_cli_committed_publication_returns_success_despite_failure(
    tmp_path, monkeypatch, capsys, failure,
):
    """A durable commit stays successful when a later operation or reply fails."""
    database, output = tmp_path / "studio.sqlite", tmp_path / "artifacts"
    if failure == "commit_acknowledgement":
        complete_execution = SQLiteStore.complete_execution

        def commit_then_raise(self, *args, **kwargs):
            complete_execution(self, *args, **kwargs)
            raise sqlite3.OperationalError("commit acknowledgement lost")

        monkeypatch.setattr(SQLiteStore, "complete_execution", commit_then_raise)
    else:
        def interrupt(name):
            if name == failure:
                raise OSError("injected postcommit failure")

        def service_with_fault(*args, **kwargs):
            return GenerationService(*args, publication_checkpoint=interrupt, **kwargs)

        monkeypatch.setattr(cli_module, "GenerationService", service_with_fault)

    arguments = _submit_arguments(database, output)
    assert cli_module.main(arguments) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["status"] == "succeeded" and result["artifact_id"] is not None
    assert cli(tmp_path, *arguments) == result
    artifact = cli(tmp_path, "artifact", "--db", database, "--id", result["artifact_id"])
    assert Path(artifact["path"]).is_file()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status FROM generation_jobs").fetchall() == [("succeeded",)]
        assert connection.execute("SELECT status FROM generation_attempts").fetchall() == [("succeeded",)]
