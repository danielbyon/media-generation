"""Upgrade actual historical DDL without inventing already-upgraded fixtures."""

import json
from pathlib import Path
import sqlite3

import pytest

from media_generation.adapters import (
    PROCESS_CONTAINED_CONTRACT,
    DeterministicCpuAdapter,
)
from media_generation.errors import GenerationError
from media_generation.service import GenerationService
from media_generation.store import (
    SQLiteStore,
    _ARTIFACT_PUBLICATION_AUTHORITY_DDL,
    _EXECUTION_ATTEMPTS_DDL,
    _EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL,
    _EXECUTION_JOBS_QUEUED_INDEX_DDL,
    _EXECUTION_JOBS_V3_DDL,
    _EXECUTION_RESOURCE_DDL,
    _WRITER_EPOCH,
    _WRITER_EPOCH_FUNCTION,
)
from test_artifact_migration import legacy_database
from test_durable_execution import request


def historical_running(root: Path, version: str) -> tuple[Path, Path, str]:
    """Seed unfinished work using frozen T01 or final T03 SQL, not current APIs."""
    database, images = root / "historical.sqlite3", root / "images"
    schema = (Path(__file__).parent / "fixtures" / f"{version}-schema.sql").read_text()
    adapter, payload = DeterministicCpuAdapter(), request()
    ids = [prefix + "1" * 32 for prefix in ("req_", "job_", "att_", "slot_")]
    timestamp = "2026-10-21T00:00:00+00:00"
    parameters = {"width": 12, "height": 9}
    if version == "t03":
        parameters["_resolved_output_directory"] = str(images)
    with sqlite3.connect(database) as connection:
        connection.executescript(schema)
        connection.execute(
            "INSERT INTO generation_requests VALUES (?,?,?,?)",
            (ids[0], payload.canonical_json(), payload.digest(), timestamp),
        )
        connection.execute(
            "INSERT INTO generation_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                ids[1],
                ids[0],
                "unfinished",
                payload.digest(),
                "running",
                adapter.adapter_id,
                json.dumps(adapter.configuration),
                payload.prompt,
                payload.seed,
                "[]",
                "primary",
                ids[3],
                json.dumps(parameters),
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO generation_attempts VALUES (?,?,?,?,?,?,?,?)",
            (ids[2], ids[1], 1, "running", adapter.adapter_id, timestamp, None, None),
        )
        if version == "t03":
            connection.execute(
                """INSERT INTO artifact_publications (
                    publication_id, artifact_id, root, root_dev, root_ino,
                    root_token, stage_name, state, job_id, attempt_id,
                    sources_json, created_at
                ) VALUES (?,?,?,?,?,?,?,'allocated',?,?,?,?)""",
                (
                    "pub_" + "2" * 32,
                    "art_" + "3" * 32,
                    str(images),
                    123,
                    456,
                    "4" * 32,
                    ".historical.stage",
                    ids[1],
                    ids[2],
                    "[]",
                    timestamp,
                ),
            )
    return database, images, ids[1]


def historical_failed(root: Path, version: str) -> tuple[Path, Path, str]:
    """Convert a frozen historical job and attempt into a terminal failure."""
    database, images, job_id = historical_running(root, version)
    timestamp = "2026-10-21T00:01:00+00:00"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE generation_jobs SET status = 'failed', updated_at = ? "
            "WHERE job_id = ?",
            (timestamp, job_id),
        )
        connection.execute(
            "UPDATE generation_attempts SET status = 'failed', finished_at = ?, "
            "error_message = 'historical adapter failure' WHERE job_id = ?",
            (timestamp, job_id),
        )
        if version == "t03":
            connection.execute(
                "DELETE FROM artifact_publications WHERE job_id = ?", (job_id,)
            )
    return database, images, job_id


@pytest.mark.parametrize("version", ("t01", "t03"))
def test_unfinished_historical_work_is_quarantined_without_row_mutation(
    tmp_path: Path,
    version: str,
) -> None:
    database, images, job_id = historical_running(tmp_path, version)
    with sqlite3.connect(database) as connection:
        before = connection.execute("SELECT * FROM generation_attempts").fetchall()
    service = GenerationService(database, images)

    snapshot = service.get_provenance(job_id)
    assert snapshot["execution"]["resource_state"] == "quarantined"
    assert snapshot["attempts"][0]["termination_proven"] is False
    assert snapshot["privacy_compliance"]["status"] == "unverified"
    assert "historical_record_unverified" in {
        reason["code"] for reason in snapshot["privacy_compliance"]["reasons"]
    }
    assert service.work()["status"] == "resource_busy"

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT * FROM generation_attempts").fetchall() == before
        if version == "t03":
            assert connection.execute(
                "SELECT state FROM artifact_publications"
            ).fetchone()[0] == "allocated"


@pytest.mark.parametrize("version", ("t01", "t03"))
def test_failed_execution_migration_rolls_back_entire_historical_upgrade(
    tmp_path: Path,
    version: str,
    monkeypatch,
) -> None:
    database, images, _ = historical_running(tmp_path, version)
    with sqlite3.connect(database) as connection:
        before = list(connection.iterdump())
        version_before = connection.execute("PRAGMA user_version").fetchone()[0]
    migrate = SQLiteStore._migrate_execution

    def fail_after_schema_changes(self, connection):
        migrate(self, connection)
        raise sqlite3.OperationalError("injected migration failure")

    monkeypatch.setattr(SQLiteStore, "_migrate_execution", fail_after_schema_changes)
    with pytest.raises(sqlite3.OperationalError, match="injected migration failure"):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == version_before


def test_t01_successful_rows_bytes_and_lineage_survive_execution_upgrade(
    tmp_path: Path,
) -> None:
    database, images, artifacts = legacy_database(tmp_path)
    with sqlite3.connect(database) as connection:
        legacy_references = {
            artifact["artifact_id"]: json.loads(
                connection.execute(
                    "SELECT validated_reference_ids_json FROM generation_jobs WHERE job_id = ?",
                    (artifact["job_id"],),
                ).fetchone()[0]
            )
            for artifact in artifacts
        }
        before_rows = {
            name: connection.execute(f"SELECT * FROM {name}").fetchall()
            for name in ("generation_requests", "generation_jobs", "generation_attempts")
        }
        before_lineage = {
            artifact["artifact_id"]: {
                "artifact_id": artifact["artifact_id"],
                "parents": [
                    {
                        "source_id": source_id,
                        "target_id": artifact["artifact_id"],
                        "role": "reference",
                        "position": position,
                    }
                    for position, source_id in enumerate(
                        legacy_references[artifact["artifact_id"]]
                    )
                ],
                "children": [
                    {
                        "source_id": artifact["artifact_id"],
                        "target_id": child_id,
                        "role": "reference",
                        "position": position,
                    }
                    for child_id, references in legacy_references.items()
                    for position, source_id in enumerate(references)
                    if source_id == artifact["artifact_id"]
                ],
            }
            for artifact in artifacts
        }
        before_bytes = {
            artifact["artifact_id"]: Path(artifact["path"]).read_bytes()
            for artifact in artifacts
        }

    service = GenerationService(database, images)
    for artifact in artifacts:
        assert service.get_artifact(artifact["artifact_id"]).to_dict() == artifact
        assert service.get_integrity(artifact["artifact_id"])["status"] == "ok"
        snapshot = service.get_provenance(artifact["job_id"])
        assert snapshot["status"] == "succeeded"
        assert snapshot["attempt"]["attempt_id"] == artifact["attempt_id"]
        assert Path(artifact["path"]).read_bytes() == before_bytes[artifact["artifact_id"]]
        assert service.get_lineage(artifact["artifact_id"]) == before_lineage[artifact["artifact_id"]]

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        for name, rows in before_rows.items():
            assert connection.execute(f"SELECT * FROM {name}").fetchall() == rows


def test_t03_allocated_journal_and_attempt_rows_survive_upgrade(tmp_path: Path) -> None:
    database, images, _ = historical_running(tmp_path, "t03")
    with sqlite3.connect(database) as connection:
        publications_before = connection.execute(
            "SELECT * FROM artifact_publications"
        ).fetchall()
        attempts_before = connection.execute("SELECT * FROM generation_attempts").fetchall()

    GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT * FROM artifact_publications").fetchall() == publications_before
        assert connection.execute("SELECT * FROM generation_attempts").fetchall() == attempts_before


def test_execution_migration_is_idempotent_after_success(tmp_path: Path) -> None:
    database, images, job_id = historical_running(tmp_path, "t03")
    service = GenerationService(database, images)
    first = service.get_provenance(job_id)
    with sqlite3.connect(database) as connection:
        after_first = list(connection.iterdump())

    second = GenerationService(database, images).get_provenance(job_id)
    assert second == first
    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == after_first


def test_version_four_migrates_to_admission_schema_without_rewriting_history(
    tmp_path: Path,
) -> None:
    """Admission migration is additive and leaves every historical execution row intact."""
    database, images, job_id = historical_running(tmp_path, "t03")
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        before = {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in (
                "generation_requests",
                "generation_jobs",
                "generation_attempts",
                "execution_jobs",
                "execution_attempts",
                "execution_resource",
            )
        }
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_update")
        connection.execute("DROP TABLE execution_admissions")
        connection.execute("PRAGMA user_version = 4")

    GenerationService(database, images).get_provenance(job_id)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        for table, rows in before.items():
            assert connection.execute(f"SELECT * FROM {table}").fetchall() == rows
        assert connection.execute("SELECT count(*) FROM execution_admissions").fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'execution_admissions'"
        ).fetchone()[0] == 1


def test_version_four_queued_execution_requires_readmission_before_dispatch(
    tmp_path: Path,
) -> None:
    """A pre-admission queue reuses its identity only after typed re-admission."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from test_resource_admission import GIB, inventory_report, workload_demand

    database, images = tmp_path / "studio.sqlite3", tmp_path / "images"
    queued = GenerationService(database, images).enqueue(
        "migrated-t04-queued", request(), max_attempts=2
    )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_update")
        connection.execute("DROP TABLE execution_admissions")
        connection.execute("PRAGMA user_version = 4")

    migrated = GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT count(*) FROM execution_admissions").fetchone()[0] == 0

    assert migrated.work()["processed"] == 0
    snapshot = migrated.get_provenance(queued.job_id)
    assert snapshot["status"] == "queued"
    assert snapshot["attempts"] == []
    assert snapshot["admission"]["decision"] == "unrecorded"
    assert snapshot["admission"]["profile"] is None
    assert snapshot["admission"]["demand"] is None
    assert snapshot["admission"]["required_bytes"] == {}

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(workload_demand())
    readmitted = GenerationService(database, images, admission_profile=profile)
    reused = readmitted.enqueue(
        "migrated-t04-queued", request(), workload_demand=demand
    )

    assert reused.job_id == queued.job_id
    assert reused.status == "queued"
    inspection = readmitted.inspect_admission(queued.job_id)
    assert inspection is not None
    assert inspection.admission.decision == "queued"
    assert inspection.admission.profile_fingerprint == profile.fingerprint
    assert inspection.admission.demand == demand.to_dict()
    assert inspection.admission.required_bytes == {"system_ram": 48 * GIB}
    assert readmitted.work()["processed"] == 1
    completed = readmitted.get_provenance(queued.job_id)
    assert completed["status"] == "succeeded"
    assert completed["admission"]["decision"] == "released"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM execution_admissions").fetchone()[0] == 1


def test_version_four_queued_readmission_rejects_missing_or_conflicting_evidence(
    tmp_path: Path,
) -> None:
    """Historical reuse cannot attach partial or different admission evidence."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.errors import IdempotencyConflictError
    from test_resource_admission import GIB, inventory_report, workload_demand

    database, images = tmp_path / "studio.sqlite3", tmp_path / "images"
    service = GenerationService(database, images)
    queued = service.enqueue("migrated-t04-conflict", request(), max_attempts=2)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_update")
        connection.execute("DROP TABLE execution_admissions")
        connection.execute("PRAGMA user_version = 4")

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(workload_demand())
    profile_only = GenerationService(database, images, admission_profile=profile)
    with pytest.raises(IdempotencyConflictError, match="profile and demand"):
        profile_only.enqueue("migrated-t04-conflict", request())

    readmitted = GenerationService(database, images, admission_profile=profile)
    readmitted.enqueue("migrated-t04-conflict", request(), workload_demand=demand)
    conflicting_demand = parse_workload_demand(
        workload_demand(system_ram_bytes=21 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    with pytest.raises(IdempotencyConflictError, match="different admission evidence"):
        readmitted.enqueue(
            "migrated-t04-conflict", request(), workload_demand=conflicting_demand
        )

    inspection = readmitted.inspect_admission(queued.job_id)
    assert inspection is not None
    assert inspection.admission.demand == demand.to_dict()
    assert readmitted.work()["processed"] == 1


def test_version_four_running_retry_failure_requires_readmission_before_retry(
    tmp_path: Path,
) -> None:
    """A migrated owner may finalize a failure, but queued retry needs admission."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from test_resource_admission import GIB, inventory_report, workload_demand

    class ContainedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

    database, images = tmp_path / "studio.sqlite3", tmp_path / "images"
    service = GenerationService(database, images, adapter=ContainedAdapter())
    queued = service.enqueue("migrated-running-failure", request(), max_attempts=2)
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    claim = service._store.claim_next_execution(
        attempt_id="att_0123456789abcdef0123456789abcdef",
        owner_id="worker_migrated_failure",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(images),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )
    assert claim is not None
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_update")
        connection.execute("DROP TABLE execution_admissions")
        connection.execute("PRAGMA user_version = 4")

    migrated = GenerationService(database, images, adapter=ContainedAdapter())
    assert migrated._store.fail_execution(
        queued.job_id,
        claim.attempt_id,
        "transient migrated failure",
        "2026-10-27T00:00:02Z",
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="retryable",
        termination_proven=True,
    )
    snapshot = migrated.get_provenance(queued.job_id)
    assert snapshot["status"] == "queued"
    assert snapshot["attempts"][0]["status"] == "failed"
    assert snapshot["execution"]["retry_eligible"] is True
    assert snapshot["execution"]["resource_state"] == "available"
    assert snapshot["admission"]["decision"] == "unrecorded"
    assert migrated._store.retry_execution(
        queued.job_id, "2026-10-27T00:00:03Z"
    ) is False
    assert migrated.work()["processed"] == 0

    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )
    demand = parse_workload_demand(workload_demand())
    readmitted = GenerationService(
        database,
        images,
        adapter=ContainedAdapter(),
        admission_profile=profile,
    )
    readmitted.enqueue(
        "migrated-running-failure", request(), workload_demand=demand
    )
    inspection = readmitted.inspect_admission(queued.job_id)
    assert inspection is not None
    assert inspection.admission.decision == "queued"
    assert readmitted.work()["processed"] == 1
    assert readmitted.get_provenance(queued.job_id)["status"] == "succeeded"


def test_version_four_running_owner_can_complete_without_admission_row(
    tmp_path: Path,
) -> None:
    """Migration does not block an already-claimed historical owner from finishing."""
    from media_generation.domain import GenerationArtifact, GenerationPlan

    class ContainedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

    database, images = tmp_path / "studio.sqlite3", tmp_path / "images"
    service = GenerationService(database, images, adapter=ContainedAdapter())
    queued = service.enqueue("migrated-running-success", request())
    _, adapter_configuration_json, _, privacy_compliance_json = (
        service._current_privacy_snapshot()
    )
    claim = service._store.claim_next_execution(
        attempt_id="att_fedcba9876543210fedcba9876543210",
        owner_id="worker_migrated_success",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=adapter_configuration_json,
        privacy_compliance_json=privacy_compliance_json,
        resolved_output_directory=str(images),
        process_contained=True,
        containment_contract=PROCESS_CONTAINED_CONTRACT,
        timestamp="2026-10-27T00:00:00Z",
        lease_expires_at="2026-10-27T00:01:00Z",
        job_id=queued.job_id,
    )
    assert claim is not None
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_execution_admissions_update")
        connection.execute("DROP TABLE execution_admissions")
        connection.execute("PRAGMA user_version = 4")

    migrated = GenerationService(database, images, adapter=ContainedAdapter())
    plan = GenerationPlan(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        resolved_prompt=claim.resolved_prompt,
        seed=claim.resolved_seed,
        width=claim.width,
        height=claim.height,
        references=claim.references,
        output_slot=claim.output_slot,
        output_slot_id=claim.output_slot_id,
    )

    def write_image(destination, staged) -> None:
        migrated.adapter.generate(plan, staged)

    def make_artifact(info, destination) -> GenerationArtifact:
        return GenerationArtifact(
            artifact_id="art_0123456789abcdef0123456789abcdef",
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            output_slot_id=claim.output_slot_id,
            path=str(destination),
            media_type=info.media_type,
            image_format=info.image_format,
            width=info.width,
            height=info.height,
            file_size=info.file_size,
            sha256=info.sha256,
            created_at="2026-10-27T00:00:01Z",
        )

    artifact = migrated._publication.publish(
        write_image,
        make_artifact,
        artifact_id="art_0123456789abcdef0123456789abcdef",
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
    )

    assert artifact.artifact_id == "art_0123456789abcdef0123456789abcdef"
    snapshot = migrated.get_provenance(queued.job_id)
    assert snapshot["status"] == "succeeded"
    assert snapshot["admission"]["decision"] == "unrecorded"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT count(*) FROM execution_admissions").fetchone()[0] == 0


def test_version_five_missing_admission_table_fails_closed(tmp_path: Path) -> None:
    """A version marker cannot hide an incomplete admission schema."""
    database, images, _ = historical_running(tmp_path, "t03")
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE execution_admissions")
        before = list(connection.iterdump())

    with pytest.raises(RuntimeError, match="execution_admissions"):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5


def test_valid_version_three_schema_advances_to_version_five(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A complete v3 schema remains upgradeable even when the column exists."""
    database, images, _ = historical_running(tmp_path, "t03")
    with monkeypatch.context() as patch:
        patch.setattr(
            SQLiteStore,
            "_migrate_privacy",
            staticmethod(lambda connection: None),
        )
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert "privacy_compliance_json" in {
            row[1]
            for row in connection.execute("PRAGMA table_info(execution_jobs)")
        }
        attempts_before = connection.execute(
            "SELECT * FROM generation_attempts"
        ).fetchall()
        publications_before = connection.execute(
            "SELECT * FROM artifact_publications"
        ).fetchall()

    GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute(
            "SELECT * FROM generation_attempts"
        ).fetchall() == attempts_before
        assert connection.execute(
            "SELECT * FROM artifact_publications"
        ).fetchall() == publications_before


def test_privacy_migration_accepts_alter_table_definition(tmp_path: Path) -> None:
    """The additive ALTER TABLE path remains a valid historical v4 variant."""
    database = tmp_path / "version-three.sqlite3"
    with sqlite3.connect(database) as connection:
        for statement in (
            _EXECUTION_JOBS_V3_DDL,
            _EXECUTION_JOBS_QUEUED_INDEX_DDL,
            _EXECUTION_ATTEMPTS_DDL,
            _EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL,
            _EXECUTION_RESOURCE_DDL,
            _ARTIFACT_PUBLICATION_AUTHORITY_DDL,
        ):
            connection.execute(statement)
        connection.execute("PRAGMA user_version = 3")

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        SQLiteStore._migrate_privacy(connection)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
        assert "privacy_compliance_json" in {
            row[1]
            for row in connection.execute("PRAGMA table_info(execution_jobs)")
        }


def test_version_three_weakened_check_retains_fragment_but_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A weakened CHECK cannot pass by retaining the expected SQL text."""
    database, images, _ = historical_running(tmp_path, "t03")
    with monkeypatch.context() as patch:
        patch.setattr(
            SQLiteStore,
            "_migrate_privacy",
            staticmethod(lambda connection: None),
        )
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        original_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("execution_jobs",),
        ).fetchone()[0]
        weakened_sql = original_sql.replace(
            "CHECK (max_attempts >= 1)",
            "CHECK (max_attempts >= 1 OR 1)",
        )
        assert weakened_sql != original_sql
        assert "max_attempts>=1" in "".join(weakened_sql.split())
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = ?",
            (weakened_sql, "execution_jobs"),
        )
        connection.execute("PRAGMA writable_schema = OFF")
        connection.commit()

    with sqlite3.connect(database) as connection:
        before = list(connection.iterdump())

    with pytest.raises(
        RuntimeError,
        match="execution_jobs has a divergent table definition",
    ):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


@pytest.mark.parametrize(
    ("definition_change", "table_name", "expected_message"),
    (
        (
            "foreign-key-action",
            "execution_jobs",
            "execution_jobs has a divergent table definition",
        ),
        (
            "table-option",
            "execution_resource",
            "execution_resource has a divergent table definition",
        ),
    ),
)
def test_version_three_table_definition_is_compared_in_full(
    tmp_path: Path,
    monkeypatch,
    definition_change: str,
    table_name: str,
    expected_message: str,
) -> None:
    """Foreign-key actions and table options are part of the DDL contract."""
    database, images, _ = historical_running(tmp_path, "t03")
    with monkeypatch.context() as patch:
        patch.setattr(
            SQLiteStore,
            "_migrate_privacy",
            staticmethod(lambda connection: None),
        )
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        original_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()[0]
        if definition_change == "foreign-key-action":
            changed_sql = original_sql.replace(
                "REFERENCES generation_jobs(job_id)",
                "REFERENCES generation_jobs(job_id) ON DELETE CASCADE",
                1,
            )
        else:
            changed_sql = original_sql + " STRICT"
        assert changed_sql != original_sql
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = ?",
            (changed_sql, table_name),
        )
        connection.execute("PRAGMA writable_schema = OFF")
        connection.commit()

    with sqlite3.connect(database) as connection:
        before = list(connection.iterdump())

    with pytest.raises(
        RuntimeError,
        match=expected_message,
    ):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_version_three_missing_execution_index_fails_without_privacy_advance(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The version marker cannot hide a removed execution ordering constraint."""
    database, images, _ = historical_running(tmp_path, "t03")
    with monkeypatch.context() as patch:
        patch.setattr(
            SQLiteStore,
            "_migrate_privacy",
            staticmethod(lambda connection: None),
        )
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        connection.execute("DROP INDEX execution_attempts_running_idx")
        before = list(connection.iterdump())

    with pytest.raises(RuntimeError, match="missing index execution_attempts_running_idx"):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


@pytest.mark.parametrize(
    ("version", "has_privacy_column"),
    ((3, False), (4, True)),
)
def test_partial_execution_schema_preserves_existing_schema_version(
    tmp_path: Path,
    version: int,
    has_privacy_column: bool,
) -> None:
    """Table names and the privacy marker do not substitute for schema structure."""
    database = tmp_path / "partial.sqlite3"
    privacy_column = ",\n    privacy_compliance_json TEXT" if has_privacy_column else ""
    with sqlite3.connect(database) as connection:
        connection.executescript(
            f"""
            CREATE TABLE execution_jobs (
                job_id TEXT PRIMARY KEY{privacy_column}
            );
            CREATE TABLE execution_attempts (
                attempt_id TEXT PRIMARY KEY
            );
            CREATE TABLE execution_resource (
                id INTEGER PRIMARY KEY,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE artifact_publication_authority (
                publication_id TEXT PRIMARY KEY
            );
            INSERT INTO execution_resource VALUES (
                1, 'available', '2026-10-26T00:00:00+00:00'
            );
            PRAGMA user_version = {version};
            """
        )

    with sqlite3.connect(database) as connection:
        before = list(connection.iterdump())

    with pytest.raises(RuntimeError, match=rf"schema version {version} incomplete"):
        GenerationService(database, tmp_path / "images")

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == version
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(execution_jobs)")
        }
        assert ("privacy_compliance_json" in columns) is has_privacy_column


def test_t03_ready_journal_without_attempt_authority_stays_quarantined(
    tmp_path: Path,
) -> None:
    database, images, _ = historical_running(tmp_path, "t03")
    publication_id = "pub_" + "2" * 32
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE artifact_publications "
            "SET state = 'ready', final_name = 'historical.png', artifact_json = '{}' "
            "WHERE publication_id = ?",
            (publication_id,),
        )

    service = GenerationService(database, images)

    assert service._store.publication_authority_current(publication_id) is False
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM artifact_publication_authority "
            "WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone()[0] == "quarantined"
        assert connection.execute(
            "SELECT state FROM artifact_publications WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()[0] == "ready"


def test_version_three_marker_without_execution_sidecars_fails_closed(
    tmp_path: Path,
) -> None:
    database, images, _ = legacy_database(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA user_version = 3")
        before = list(connection.iterdump())

    with pytest.raises(
        RuntimeError,
        match=(
            r"^database schema version 3 incomplete; missing tables: "
            r"artifact_publication_authority, execution_attempts, "
            r"execution_jobs, execution_resource$"
        ),
    ):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_version_three_marker_without_singleton_resource_fails_closed(
    tmp_path: Path,
) -> None:
    """Complete sidecar tables are insufficient without the DB-wide reservation."""
    database, images, _ = legacy_database(tmp_path)
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM execution_resource")
        before = list(connection.iterdump())
        jobs_before = connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0]

    with pytest.raises(RuntimeError, match="execution_resource.*singleton row"):
        GenerationService(database, images)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == jobs_before


EXPECTED_WRITER_GUARDS = {
    "t04_writer_guard_generation_requests_insert",
    "t04_writer_guard_generation_jobs_insert",
    "t04_writer_guard_generation_jobs_update",
    "t04_writer_guard_generation_attempts_insert",
    "t04_writer_guard_generation_attempts_update",
    "t04_writer_guard_generation_artifacts_insert",
    "t04_writer_guard_artifact_edges_insert",
    "t04_writer_guard_artifact_publications_insert",
    "t04_writer_guard_artifact_publications_update",
    "t04_writer_guard_artifact_integrity_insert",
    "t04_writer_guard_artifact_integrity_update",
    "t04_writer_guard_execution_admissions_insert",
    "t04_writer_guard_execution_admissions_update",
}


@pytest.mark.parametrize("version", ("t01", "t03"))
def test_historical_writer_dml_is_rejected_after_migration(
    tmp_path: Path,
    version: str,
) -> None:
    """A stale executable must fail at its first legacy-table mutation."""
    database, images, _ = historical_running(tmp_path, version)
    GenerationService(database, images)

    with sqlite3.connect(database) as historical_writer:
        before = list(historical_writer.iterdump())
        with pytest.raises(sqlite3.OperationalError, match="no such function: media_generation_writer_epoch"):
            historical_writer.execute(
                "INSERT INTO generation_requests "
                "(request_id, canonical_json, request_digest, created_at) VALUES (?, ?, ?, ?)",
                (
                    "req_stalewriter0000000000000000001",
                    request().canonical_json(),
                    request().digest(),
                    "2026-10-24T00:00:00+00:00",
                ),
            )
        assert list(historical_writer.iterdump()) == before
        assert historical_writer.execute("PRAGMA user_version").fetchone()[0] == 5


def test_current_writer_passes_guards_and_missing_guard_is_recreated(
    tmp_path: Path,
) -> None:
    database, images, _ = historical_running(tmp_path, "t03")
    service = GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        guards = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'trigger' AND name LIKE 't04_writer_guard_%'"
            )
        }
        assert guards == EXPECTED_WRITER_GUARDS
        connection.execute("DROP TRIGGER t04_writer_guard_generation_jobs_insert")

    restarted = GenerationService(database, images)
    admitted = restarted.enqueue("after-migration", request())
    assert admitted.status == "queued"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 't04_writer_guard_generation_jobs_insert'"
        ).fetchone() == (1,)


def test_pre_v4_writer_epoch_is_rejected_after_upgrade(tmp_path: Path) -> None:
    database, images, _ = historical_running(tmp_path, "t03")
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        for name in EXPECTED_WRITER_GUARDS:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (name,),
            ).fetchone()
            assert row is not None
            legacy_sql = str(row[0]).replace(f"!= {_WRITER_EPOCH}", "!= 3")
            connection.execute(f"DROP TRIGGER {name}")
            connection.execute(legacy_sql)
        connection.execute("PRAGMA user_version = 3")

    GenerationService(database, images)

    with sqlite3.connect(database) as stale_writer:
        stale_writer.create_function(_WRITER_EPOCH_FUNCTION, 0, lambda: 3)
        job_row = stale_writer.execute(
            "SELECT job_id FROM generation_jobs LIMIT 1"
        ).fetchone()
        assert job_row is not None
        before = list(stale_writer.iterdump())
        with pytest.raises(sqlite3.IntegrityError, match="stale media-generation writer"):
            stale_writer.execute(
                """UPDATE generation_jobs
                   SET updated_at = updated_at
                   WHERE job_id = ?""",
                (job_row[0],),
            )
        assert list(stale_writer.iterdump()) == before
        assert stale_writer.execute("PRAGMA user_version").fetchone()[0] == 5
        trigger_sql = stale_writer.execute(
            """SELECT sql FROM sqlite_master
               WHERE type = 'trigger'
                 AND name = 't04_writer_guard_generation_requests_insert'"""
        ).fetchone()[0]
        assert f"!= {_WRITER_EPOCH}" in trigger_sql


def test_divergent_writer_guard_fails_closed(tmp_path: Path) -> None:
    database, images, _ = historical_running(tmp_path, "t03")
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER t04_writer_guard_generation_requests_insert")
        connection.execute(
            "CREATE TRIGGER t04_writer_guard_generation_requests_insert "
            "BEFORE INSERT ON generation_requests BEGIN SELECT 1; END"
        )

    with pytest.raises(RuntimeError, match="writer guard.*divergent"):
        GenerationService(database, images)


def test_version_three_job_without_execution_state_fails_closed(tmp_path: Path) -> None:
    """Rows admitted by an older writer cannot be silently left joinable."""
    database, images, _ = historical_running(tmp_path, "t03")
    GenerationService(database, images)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DROP TRIGGER t04_writer_guard_generation_jobs_insert")
        connection.execute("DROP TRIGGER t04_writer_guard_generation_requests_insert")
        request_id = "req_stalewriter00000000000000000"
        digest = request().digest()
        connection.execute(
            "INSERT INTO generation_requests VALUES (?, ?, ?, ?)",
            (
                request_id,
                request().canonical_json(),
                digest,
                "2026-10-24T00:00:00+00:00",
            ),
        )
        connection.execute(
            "INSERT INTO generation_jobs ("
            "job_id, request_id, idempotency_key, request_digest, status, "
            "adapter_id, adapter_configuration_json, resolved_prompt, resolved_seed, "
            "validated_reference_ids_json, output_slot, output_slot_id, "
            "effective_parameters_json, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, 'succeeded', ?, ?, ?, 0, '[]', 'stale', ?, ?, ?, ?)",
            (
                "job_stalewriter000000000000000000",
                request_id,
                "stale-writer-job",
                digest,
                DeterministicCpuAdapter().adapter_id,
                json.dumps(DeterministicCpuAdapter().configuration),
                request().prompt,
                "slot_stalewriter0000000000000000",
                json.dumps({"width": 12, "height": 9}),
                "2026-10-24T00:00:00+00:00",
                "2026-10-24T00:00:00+00:00",
            ),
        )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5

    with pytest.raises(RuntimeError, match="without execution state"):
        GenerationService(database, images)


def test_failed_historical_job_replays_without_accepting_missing_contract(
    tmp_path: Path,
) -> None:
    """Legacy NULL containment remains reusable without replaying failed work."""
    database, images, job_id = historical_failed(tmp_path, "t03")
    service = GenerationService(database, images, DeterministicCpuAdapter())

    migrated = service.get_provenance(job_id)
    assert migrated["execution"]["status"] == "failed"
    assert migrated["execution"]["containment_contract"] is None
    assert migrated["execution"]["retry_eligible"] is False
    assert len(migrated["attempts"]) == 1

    replayed = service.submit("unfinished", request())
    after = service.get_provenance(job_id)

    assert replayed.job_id == job_id
    assert replayed.status == "failed"
    assert after["execution"]["status"] == "failed"
    assert after["execution"]["max_attempts"] == 1
    assert after["execution"]["retry_eligible"] is False
    assert after["execution"]["containment_contract"] is None
    assert len(after["attempts"]) == 1
    assert after["attempts"][0]["status"] == "failed"
    assert after["attempts"][0]["failure_class"] == "terminal"
    assert service.work() == {"status": "idle", "processed": 0}
    assert service.get_provenance(job_id)["attempts"] == after["attempts"]
    with pytest.raises(GenerationError, match="not eligible for retry"):
        service.retry(job_id)


@pytest.mark.parametrize("version", ("t01", "t03"))
@pytest.mark.parametrize("status", ("failed", "succeeded"))
def test_terminal_historical_status_is_not_termination_proof(
    tmp_path: Path, version: str, status: str
) -> None:
    """A completed legacy row cannot invent external-process containment."""
    database, images, job_id = historical_failed(tmp_path, version)
    with sqlite3.connect(database) as connection:
        if status == "succeeded":
            connection.execute("UPDATE generation_jobs SET status = 'succeeded'")
            connection.execute("UPDATE generation_attempts SET status = 'succeeded', error_message = NULL")
        before = connection.execute("SELECT * FROM generation_attempts").fetchall()
    service = GenerationService(database, images)
    snapshot = service.get_provenance(job_id)
    assert snapshot["status"] == status
    assert snapshot["attempt"]["containment_contract"] is None
    assert snapshot["attempt"]["termination_proven"] is False
    assert snapshot["execution"]["retry_eligible"] is False
    assert service.work() == {"status": "idle", "processed": 0}
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT * FROM generation_attempts").fetchall() == before


@pytest.mark.parametrize("version", ("t01", "t03"))
def test_ownerless_historical_attempt_cannot_authorize_finalization(
    tmp_path: Path, version: str
) -> None:
    """Unknown historical ownership must not become a current execution claim."""
    database, images, job_id = historical_running(tmp_path, version)
    service = GenerationService(database, images)
    attempt_id = service.get_provenance(job_id)["attempt"]["attempt_id"]
    with sqlite3.connect(database) as connection:
        before = list(connection.iterdump())

    assert service._store.assert_attempt_authority(job_id, attempt_id, None, None) is False
    assert service._store.fail_execution(
        job_id, attempt_id, "ownerless mutation", "2026-10-25T00:00:00+00:00"
    ) is False

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
    assert service.get_provenance(job_id)["execution"]["resource_state"] == "quarantined"


def test_historical_null_privacy_evidence_remains_unverified_and_reusable(
    tmp_path: Path,
) -> None:
    """NULL evidence identifies a version-3 row without inventing qualification."""
    database, images, job_id = historical_failed(tmp_path, "t03")
    service = GenerationService(database, images, DeterministicCpuAdapter())

    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT privacy_compliance_json FROM execution_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()[0]
    assert stored is None

    provenance = service.get_provenance(job_id)
    assert provenance["privacy_compliance"]["status"] == "unverified"
    assert "historical_record_unverified" in {
        reason["code"] for reason in provenance["privacy_compliance"]["reasons"]
    }

    replayed = service.submit("unfinished", request())
    assert replayed.job_id == job_id
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT privacy_compliance_json FROM execution_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()[0] is None


def test_direct_claim_cannot_omit_protected_privacy_evidence(
    tmp_path: Path,
) -> None:
    """A direct caller cannot claim protected work without matching evidence."""
    database = tmp_path / "studio.sqlite3"
    images = tmp_path / "artifacts"
    service = GenerationService(database, images)
    queued = service.enqueue(
        "protected-direct-claim",
        request(),
    )

    with sqlite3.connect(database) as connection:
        protected_evidence = connection.execute(
            "SELECT privacy_compliance_json FROM execution_jobs WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone()[0]
    assert isinstance(protected_evidence, str)
    assert json.loads(protected_evidence)["status"] == "unverified"

    with pytest.raises(
        GenerationError,
        match="protected execution claim requires exact privacy-compliance evidence",
    ):
        service._store.claim_next_execution(
            attempt_id="att_22222222222222222222222222222222",
            owner_id="worker_protected_direct",
            adapter_id=service.adapter.adapter_id,
            adapter_configuration_json=json.dumps(
                service.adapter.configuration,
                sort_keys=True,
                separators=(",", ":"),
            ),
            resolved_output_directory=str(images),
            process_contained=True,
            containment_contract=PROCESS_CONTAINED_CONTRACT,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            job_id=queued.job_id,
        )

    with pytest.raises(
        GenerationError,
        match="protected execution claim requires exact adapter-configuration evidence",
    ):
        service._store.claim_next_execution(
            attempt_id="att_22222222222222222222222222222222",
            owner_id="worker_protected_direct",
            adapter_id=service.adapter.adapter_id,
            privacy_compliance_json=protected_evidence,
            resolved_output_directory=str(images),
            process_contained=True,
            containment_contract=PROCESS_CONTAINED_CONTRACT,
            timestamp="2026-10-26T00:00:00+00:00",
            lease_expires_at="2026-10-26T00:01:00+00:00",
            job_id=queued.job_id,
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM generation_attempts"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT current_attempt_id, status FROM execution_jobs WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (None, "queued")
        assert connection.execute(
            "SELECT state, job_id, attempt_id FROM execution_resource WHERE id = 1"
        ).fetchone() == ("available", None, None)


@pytest.mark.parametrize(
    "stored_evidence",
    ("not-json", '{"adapter_id":"incomplete-record"}'),
)
def test_malformed_non_null_privacy_evidence_fails_closed(
    tmp_path: Path,
    stored_evidence: str,
) -> None:
    """Malformed v4 evidence must not be presented or reused as historical."""
    database, images, job_id = historical_failed(tmp_path, "t03")
    service = GenerationService(database, images, DeterministicCpuAdapter())
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE execution_jobs SET privacy_compliance_json = ? WHERE job_id = ?",
            (stored_evidence, job_id),
        )
        before = list(connection.iterdump())

    expected = "stored privacy-compliance evidence is malformed"
    with pytest.raises(GenerationError, match=expected):
        service.submit("unfinished", request())
    with pytest.raises(GenerationError, match=expected):
        service.get_provenance(job_id)

    with sqlite3.connect(database) as connection:
        assert list(connection.iterdump()) == before
        assert connection.execute(
            "SELECT privacy_compliance_json FROM execution_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()[0] == stored_evidence
