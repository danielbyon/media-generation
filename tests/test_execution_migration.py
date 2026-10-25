"""Upgrade actual historical DDL without inventing already-upgraded fixtures."""

import json
from pathlib import Path
import sqlite3

import pytest

from media_generation.adapters import DeterministicCpuAdapter
from media_generation.service import GenerationService
from media_generation.store import SQLiteStore
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
        has_edges = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'artifact_edges'"
        ).fetchone() is not None
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
        if has_edges:
            before_lineage = {
                artifact["artifact_id"]: {
                    "artifact_id": artifact["artifact_id"],
                    "parents": [
                        dict(zip(("source_id", "target_id", "role", "position"), row))
                        for row in connection.execute(
                            "SELECT * FROM artifact_edges WHERE target_id = ? ORDER BY position",
                            (artifact["artifact_id"],),
                        ).fetchall()
                    ],
                    "children": [
                        dict(zip(("source_id", "target_id", "role", "position"), row))
                        for row in connection.execute(
                            """SELECT * FROM artifact_edges WHERE source_id = ?
                               ORDER BY target_id, position""",
                            (artifact["artifact_id"],),
                        ).fetchall()
                    ],
                }
                for artifact in artifacts
            }
        else:
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
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

    with pytest.raises(RuntimeError, match="schema version 3 is incomplete"):
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
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == jobs_before
