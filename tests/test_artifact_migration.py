"""Compatibility against the actual pre-T03 schema, without a binary DB fixture."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest

from media_generation.adapters import DeterministicCpuAdapter
from media_generation.domain import (
    ArtifactSource, GenerationPlan, GenerationRequest, ResolvedReference,
)
from media_generation.publication import PublicationManager
from media_generation.service import GenerationService


def legacy_database(tmp_path, *, cross_root=False):
    """Construct a T01 database directly, without invoking the new store at all."""
    database = tmp_path / 'legacy.sqlite3'
    root = tmp_path / 'images'
    root.mkdir()
    root_alias = tmp_path / 'images-alias'
    root_alias.symlink_to(root, target_is_directory=True)
    foreign_root = tmp_path / 'foreign-images'
    if cross_root:
        foreign_root.mkdir()
    artifact_count = 4 if cross_root else 2
    timestamp = '2026-10-21T00:00:00+00:00'
    adapter = DeterministicCpuAdapter()
    artifacts = []
    with sqlite3.connect(database) as connection:
        connection.executescript((Path(__file__).parent / 'fixtures/t01-schema.sql').read_text())
        for index in range(artifact_count):
            suffix = f'{index+1:032x}'
            request_id, job_id, attempt_id, slot_id, artifact_id = (
                prefix + suffix for prefix in ('req_', 'job_', 'att_', 'slot_', 'art_'))
            source_index = {1:0, 2:1}.get(index)
            references = (() if source_index is None else
                          (artifacts[source_index]['artifact_id'],))
            resolved_references = (() if source_index is None else (
                ResolvedReference(artifacts[source_index]['artifact_id'],
                                  artifacts[source_index]['sha256'],
                                  Path(artifacts[source_index]['path'])),
                ))
            request = GenerationRequest('Legacy image', seed=index, width=8, height=9,
                                        reference_ids=references)
            if cross_root and index in (1, 3):
                artifact_root = foreign_root
            elif cross_root and index == 2:
                artifact_root = root
            else:
                artifact_root = root_alias
            destination = artifact_root / f'{artifact_id}.png'
            with destination.open('w+b') as output:
                adapter.generate(GenerationPlan(job_id, attempt_id, request.prompt, index,
                                 8, 9, resolved_references, 'primary', slot_id), output)
            connection.execute('INSERT INTO generation_requests VALUES (?,?,?,?)',
                (request_id, request.canonical_json(), request.digest(), timestamp))
            connection.execute('INSERT INTO generation_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (job_id, request_id, f'legacy-{index}', request.digest(), 'succeeded',
                 adapter.adapter_id, json.dumps(adapter.configuration), request.prompt, index,
                 json.dumps(references), 'primary', slot_id, json.dumps({'width':8, 'height':9}),
                 timestamp, timestamp))
            connection.execute('INSERT INTO generation_attempts VALUES (?,?,?,?,?,?,?,?)',
                (attempt_id,job_id,1,'succeeded',adapter.adapter_id,timestamp,timestamp,None))
            artifact = dict(artifact_id=artifact_id,job_id=job_id,attempt_id=attempt_id,
                output_slot_id=slot_id,path=str(destination),media_type='image/png',format='PNG',
                width=8,height=9,file_size=destination.stat().st_size,
                sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),created_at=timestamp)
            connection.execute('INSERT INTO generation_artifacts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                               tuple(artifact.values()))
            artifacts.append(artifact)
    if cross_root:
        return database,root,artifacts[:3],artifacts[3]
    return database,root,artifacts


def _legacy_alias_only_case(tmp_path):
    """Remove the real-root child edge so artifact 2 trusts only the alias parent."""
    database, root, artifacts, unlinked = legacy_database(tmp_path, cross_root=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE generation_jobs SET validated_reference_ids_json = '[]' WHERE job_id = ?",
            (artifacts[2]["job_id"],),
        )
    return database, root, artifacts, unlinked


def test_t01_cross_root_lineage_accepts_only_a_verified_legacy_alias_after_restart(
    tmp_path,
):
    """TAC-3: a direct T01 edge through an alias preserves historical reads."""
    database, root, artifacts, unlinked = _legacy_alias_only_case(tmp_path)
    service = GenerationService(database, root)
    assert Path(artifacts[0]["path"]).parent.is_symlink()
    assert service.get_integrity(artifacts[0]["artifact_id"])["status"] == "ok"
    assert service.get_integrity(artifacts[1]["artifact_id"])["status"] == "ok"

    restarted = GenerationService(database, root)
    assert restarted.get_integrity(artifacts[1]["artifact_id"])["status"] == "ok"
    assert Path(restarted.get_artifact(artifacts[1]["artifact_id"]).path) == Path(
        artifacts[1]["path"]
    )
    assert restarted.get_integrity(unlinked["artifact_id"])["status"] != "ok"


@pytest.mark.parametrize("damage", ("missing", "corrupt", "redirected"))
def test_t01_cross_root_alias_does_not_authorize_missing_corrupt_or_redirected_neighbor(
    tmp_path, damage,
):
    """TAC-3: alias compatibility cannot outlive its verified legacy evidence."""
    database, root, artifacts, _ = _legacy_alias_only_case(tmp_path)
    neighbor = Path(artifacts[0]["path"])
    alias = neighbor.parent
    if damage == "missing":
        neighbor.unlink()
    elif damage == "corrupt":
        neighbor.write_bytes(b"not an image")
    else:
        replacement = tmp_path / "replacement-images"
        replacement.mkdir()
        (replacement / neighbor.name).write_bytes(neighbor.read_bytes())
        alias.unlink()
        alias.symlink_to(replacement, target_is_directory=True)

    service = GenerationService(database, root)
    assert service.get_integrity(artifacts[0]["artifact_id"])["status"] != "ok"
    assert service.get_integrity(artifacts[1]["artifact_id"])["status"] != "ok"
    assert Path(service.get_artifact(artifacts[1]["artifact_id"]).path) == Path(
        artifacts[1]["path"]
    )


def test_t01_alias_redirect_during_neighbor_verification_remains_untrusted(
    tmp_path, monkeypatch,
):
    """TAC-3: an alias must remain bound to the root throughout verification."""
    database, root, artifacts, _ = _legacy_alias_only_case(tmp_path)
    neighbor = Path(artifacts[0]["path"])
    alias = neighbor.parent
    replacement = tmp_path / "replacement-images"
    replacement.mkdir()
    (replacement / neighbor.name).write_bytes(neighbor.read_bytes())
    original = PublicationManager._verified_image
    redirected = False

    @contextmanager
    def redirect_after_verify(self, directory, name, artifact, **options):
        nonlocal redirected
        with original(self, directory, name, artifact, **options) as verified:
            yield verified
        if artifact.artifact_id == artifacts[0]["artifact_id"] and not redirected:
            redirected = True
            alias.unlink()
            alias.symlink_to(replacement, target_is_directory=True)

    monkeypatch.setattr(
        PublicationManager, "_verified_image", redirect_after_verify,
    )
    service = GenerationService(database, root)
    report = service.get_integrity(artifacts[1]["artifact_id"])
    assert redirected
    assert report["status"] != "ok"


@pytest.mark.parametrize("damage", ("missing", "corrupt"))
def test_t01_broken_alias_neighbor_does_not_mask_a_verified_authorized_neighbor(
    tmp_path, damage,
):
    """TAC-3: candidate failures remain local to the neighbor under inspection."""
    database, root, artifacts, _ = legacy_database(tmp_path, cross_root=True)
    alias_neighbor = Path(artifacts[0]["path"])
    if damage == "missing":
        alias_neighbor.unlink()
    else:
        alias_neighbor.write_bytes(b"not an image")

    service = GenerationService(database, root)
    assert service.get_integrity(artifacts[0]["artifact_id"])["status"] != "ok"
    assert service.get_integrity(artifacts[1]["artifact_id"])["status"] == "ok"


def test_real_t01_database_migrates_without_changing_generated_json_or_records(tmp_path):
    """TAC-3: legacy retrieval, references, idempotency, and bytes survive migration."""
    database,root,artifacts,unlinked = legacy_database(tmp_path,cross_root=True)
    with sqlite3.connect(database) as connection:
        original = {table:connection.execute(f'SELECT * FROM {table}').fetchall()
                    for table in ('generation_requests','generation_jobs','generation_attempts')}
        assert connection.execute('PRAGMA user_version').fetchone()[0] == 0
    service = GenerationService(database,root)
    for artifact in artifacts:
        assert service.get_artifact(artifact['artifact_id']).to_dict() == artifact
        assert service.get_integrity(artifact['artifact_id'])['status'] == 'ok'
    assert Path(artifacts[0]['path']).parent.is_symlink()
    assert Path(artifacts[1]['path']).parent == tmp_path/'foreign-images'
    assert service.get_lineage(artifacts[1]['artifact_id'])['parents'] == [{
        'source_id':artifacts[0]['artifact_id'],'target_id':artifacts[1]['artifact_id'],
        'role':'reference','position':0}]
    replay = service.submit('legacy-0',GenerationRequest('Legacy image',seed=0,width=8,height=9))
    assert replay.artifact_id == artifacts[0]['artifact_id']
    with sqlite3.connect(database) as connection:
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        for table,rows in original.items():
            assert connection.execute(f'SELECT * FROM {table}').fetchall() == rows
    generated = service.submit('legacy-reference',GenerationRequest('Use legacy',seed=8,
        reference_ids=tuple(artifact['artifact_id'] for artifact in artifacts[:2])))
    assert generated.status == 'succeeded'
    restarted = GenerationService(database,root)
    parents = restarted.get_lineage(generated.artifact_id)['parents']
    assert [parent['source_id'] for parent in parents] == [
        artifacts[0]['artifact_id'], artifacts[1]['artifact_id']]
    assert restarted.get_artifact(artifacts[0]['artifact_id']).to_dict() == artifacts[0]
    legacy = artifacts[0]
    legacy_path = Path(legacy['path'])
    alias = legacy_path.parent
    replacement = tmp_path/'replacement-images'
    replacement.mkdir()
    (replacement/legacy_path.name).write_bytes(legacy_path.read_bytes())
    alias.unlink()
    alias.symlink_to(replacement, target_is_directory=True)
    assert service.get_integrity(legacy['artifact_id'])['status'] == 'missing'
    foreign_path = Path(artifacts[1]['path'])
    foreign_path.write_bytes(foreign_path.read_bytes() + b'\0')
    assert service.get_integrity(artifacts[1]['artifact_id'])['status'] == 'corrupt'
    unlinked_report = service.get_integrity(unlinked['artifact_id'])
    assert unlinked_report['status'] == 'missing'
    assert unlinked_report['detail'] == 'artifact belongs to a different output root'


def test_import_identity_roles_and_transactional_graph_constraints(tmp_path):
    """TAC-2/7/8: duplicate bytes keep identities; edges retain role and order."""
    database,root,legacy = legacy_database(tmp_path)
    service = GenerationService(database,root)
    source_root = Path(legacy[0]['path']).parent.resolve()
    assert not source_root.is_symlink()
    first = service.import_image(source_root,Path(legacy[0]['path']).name)
    second = service.import_image(source_root,Path(legacy[0]['path']).name,sources=(
        ArtifactSource(first.artifact_id,'inspiration'),
        ArtifactSource(legacy[0]['artifact_id'],'source'),
        ArtifactSource(legacy[1]['artifact_id'],'derivation')))
    assert first.sha256 == second.sha256 == legacy[0]['sha256']
    assert len({first.artifact_id,second.artifact_id,legacy[0]['artifact_id']}) == 3
    assert 'job_id' not in first.to_dict() and 'attempt_id' not in first.to_dict()
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM generation_jobs').fetchone()[0] == 2
    parents = GenerationService(database,root).get_lineage(second.artifact_id)['parents']
    assert [item['role'] for item in parents] == ['inspiration','source','derivation']
    assert [item['position'] for item in parents] == [0,1,2]
    result = service.submit('import-reference',GenerationRequest('Use import',reference_ids=(first.artifact_id,)))
    assert result.status == 'succeeded'
    assert service.get_lineage(result.artifact_id)['parents'][0]['role'] == 'reference'
    for values,reason in (
        ((first.artifact_id,first.artifact_id,'reference',0), 'CHECK constraint'),
        (('art_'+'f'*32,first.artifact_id,'reference',0), 'FOREIGN KEY'),
        ((second.artifact_id,first.artifact_id,'derivation',0), 'cycle'),
    ):
        with sqlite3.connect(database) as connection:
            connection.execute('PRAGMA foreign_keys=ON')
            # Exercise graph constraints inside a publication transaction. The
            # transaction is rolled back so historical lineage remains sealed.
            connection.execute("UPDATE artifact_publications SET state='ready' WHERE artifact_id=?",
                               (first.artifact_id,))
            with pytest.raises(sqlite3.IntegrityError,match=reason):
                connection.execute('INSERT INTO artifact_edges VALUES (?,?,?,?)',values)
            connection.rollback()
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError,match='sealed'):
            connection.execute('INSERT INTO artifact_edges VALUES (?,?,?,?)',
                               (first.artifact_id,second.artifact_id,'reference',3))
    with sqlite3.connect(database) as connection:
        for statement in ("UPDATE artifact_edges SET role='inspiration'",'DELETE FROM artifact_edges',
                          "UPDATE generation_artifacts SET sha256='changed'",'DELETE FROM generation_artifacts'):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
    assert service.get_lineage(second.artifact_id)['parents'] == parents


def test_lineage_commit_failure_exposes_neither_artifact_nor_partial_edges(tmp_path, monkeypatch):
    """TAC-4/7: an edge error rolls back artifact, job success, and all edges."""
    from media_generation.errors import PublicationIncompleteError

    database,root,legacy = legacy_database(tmp_path)
    service = GenerationService(database,root)
    insert_sources = service._store._insert_sources

    def partial_edge_failure(connection,artifact_id,sources):
        insert_sources(connection,artifact_id,sources[:1])
        raise sqlite3.OperationalError('injected failure between edge inserts')

    monkeypatch.setattr(service._store,'_insert_sources',partial_edge_failure)
    with pytest.raises(PublicationIncompleteError) as error:
        service.submit('edge-rollback',GenerationRequest('Ordered references',
            reference_ids=tuple(a['artifact_id'] for a in legacy)))
    job = service.get_job(error.value.job_id)
    assert job.status == 'running' and job.artifact_id is None
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM generation_artifacts').fetchone()[0] == 2
        assert connection.execute('SELECT count(*) FROM artifact_edges').fetchone()[0] == 1
        assert connection.execute('SELECT state FROM artifact_publications').fetchone()[0] == 'ready'
    restarted = GenerationService(database,root)
    assert restarted.reconcile()['status'] == 'complete'
    result = restarted.get_job(job.job_id)
    assert result.status == 'succeeded'
    assert [edge['source_id'] for edge in restarted.get_lineage(result.artifact_id)['parents']] == [
        artifact['artifact_id'] for artifact in legacy]


def test_duplicate_lineage_is_rejected_before_allocating_publication(tmp_path):
    """Invalid parent lists cannot strand durable content awaiting an impossible commit."""
    from media_generation.errors import InputValidationError

    database,root,legacy=legacy_database(tmp_path)
    service=GenerationService(database,root)
    duplicate=ArtifactSource(legacy[0]['artifact_id'],'inspiration')
    with pytest.raises(InputValidationError,match='repeat'):
        service.import_image(root,Path(legacy[0]['path']).name,sources=(duplicate,duplicate))
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM artifact_publications').fetchone()[0] == 0
        assert connection.execute('SELECT count(*) FROM generation_artifacts').fetchone()[0] == 2
    assert set(path.name for path in root.iterdir()) == {Path(item['path']).name for item in legacy}


@pytest.mark.parametrize('role',['unknown',[],None])
def test_invalid_lineage_roles_are_explicit_validation_errors(role):
    from media_generation.errors import InputValidationError

    with pytest.raises(InputValidationError,match='role'):
        ArtifactSource('art_'+'1'*32,role)
