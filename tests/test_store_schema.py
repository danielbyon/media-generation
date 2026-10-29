"""Contracts for one current SQLite schema and non-destructive reopening."""

from __future__ import annotations

import json
from pathlib import Path
import hashlib
import sqlite3

import pytest

from media_generation.domain import GenerationRequest
from media_generation.service import GenerationService
from media_generation.store import (
    _CURRENT_INDEX_DDL,
    _CURRENT_SCHEMA_VERSION,
    _CURRENT_TABLE_DDL,
    _CURRENT_TABLES,
    _EXECUTION_RESOURCE_DDL,
    _STATIC_TRIGGER_DDL,
    _WRITER_EPOCH,
    _WRITER_EPOCH_FUNCTION,
    _WRITER_GUARDS,
    SQLiteStore,
)


def _digest(path: Path) -> str:
    """Return exact bytes so a rejected open can be proven non-mutating."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _objects(path: Path) -> dict[str, set[str]]:
    """Read schema object names without opening the application store."""
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT type, name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
    result = {"table": set(), "index": set(), "trigger": set(), "view": set()}
    for object_type, name in rows:
        result.setdefault(str(object_type), set()).add(str(name))
    return result


def _current_trigger_names() -> set[str]:
    """Return the exact immutable and incompatible-writer trigger set."""
    guards = {
        SQLiteStore._writer_guard_sql(table, operation)[0]
        for table, operation in _WRITER_GUARDS
    }
    return set(_STATIC_TRIGGER_DDL) | guards


def _assert_rejected_without_mutation(path: Path, match: str) -> None:
    """Require a read-only validation failure that leaves database bytes intact."""
    before = _digest(path)
    with pytest.raises(RuntimeError, match=match):
        SQLiteStore(path)
    assert _digest(path) == before


def _set_queued_admission_to_empty_evidence(path: Path, job_id: str) -> None:
    """Simulate a current row whose queued decision has no pinned documents."""
    _set_queued_admission_to_documents(path, job_id, {}, {})


def _set_queued_admission_to_documents(
    path: Path,
    job_id: str,
    profile: object,
    demand: object,
) -> None:
    """Replace queued admission documents without changing their identity column."""
    with sqlite3.connect(path) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            """UPDATE execution_admissions
               SET decision = 'queued', decision_reason = 'capacity_fit',
                   admission_profile_json = ?, workload_demand_json = ?
               WHERE job_id = ?""",
            (json.dumps(profile), json.dumps(demand), job_id),
        )


def _set_queued_admission_required_bytes(
    path: Path,
    job_id: str,
    required_bytes: dict[str, int],
) -> None:
    """Replace the resource amount pinned to one queued admission."""
    with sqlite3.connect(path) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        connection.execute(
            "UPDATE execution_admissions SET required_bytes_json = ? WHERE job_id = ?",
            (json.dumps(required_bytes), job_id),
        )


def _heavyweight_admission():
    """Return a valid profile and demand pair for persisted-evidence tests."""
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from test_resource_admission import GIB, inventory_report, workload_demand

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
    demand = parse_workload_demand(
        workload_demand(system_ram_bytes=20 * GIB, accelerator_memory_bytes=20 * GIB)
    )
    return profile, demand


@pytest.mark.parametrize("disable_dqs", (False, True))
def test_execution_resource_schema_uses_portable_string_literals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, disable_dqs: bool,
) -> None:
    """Basic constraints always run; disabling DQS needs Python SQLite support."""
    monkeypatch.setenv("PATH", str(tmp_path / "no-executables"))
    if disable_dqs and not (
        hasattr(sqlite3.Connection, "setconfig")
        and hasattr(sqlite3, "SQLITE_DBCONFIG_DQS_DDL")
        and hasattr(sqlite3, "SQLITE_DBCONFIG_DQS_DML")
    ):
        pytest.skip("this Python SQLite API cannot configure DQS; basic constraints still run")
    with sqlite3.connect(tmp_path / "schema.sqlite3") as connection:
        if disable_dqs:
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_DQS_DDL, False)
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_DQS_DML, False)
        connection.execute(_EXECUTION_RESOURCE_DDL)
        connection.execute(
            "INSERT INTO execution_resource(id, state, updated_at) VALUES (1, 'available', 'now')"
        )
        for state in ("claimed", "quarantined"):
            connection.execute("UPDATE execution_resource SET state = ?", (state,))
            assert connection.execute("SELECT state FROM execution_resource").fetchone() == (
                state,
            )
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute("UPDATE execution_resource SET state = 'unknown'")


def test_fresh_database_initializes_complete_current_schema(tmp_path: Path) -> None:
    """Fresh initialization creates every current object and its resource row."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)

    objects = _objects(database)
    assert objects["table"] == set(_CURRENT_TABLES)
    assert objects["index"] == set(_CURRENT_INDEX_DDL)
    assert objects["trigger"] == _current_trigger_names()
    assert objects["view"] == set()
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (
            _CURRENT_SCHEMA_VERSION,
        )
        assert connection.execute(
            "SELECT id, state, job_id, attempt_id, owner_id, reason "
            "FROM execution_resource"
        ).fetchall() == [(1, "available", None, None, None, None)]

    SQLiteStore(database)


def test_failed_initialization_rolls_back_the_complete_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure before commit leaves no partial schema or version marker."""
    database = tmp_path / "studio.sqlite3"

    def fail_after_tables(cls, connection):
        raise RuntimeError("injected initialization failure")

    monkeypatch.setattr(
        SQLiteStore,
        "_install_writer_guards",
        classmethod(fail_after_tables),
    )
    with pytest.raises(RuntimeError, match="injected initialization failure"):
        SQLiteStore(database)

    assert database.exists()
    assert database.stat().st_size == 0
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchone() == (0,)
        assert connection.execute("PRAGMA user_version").fetchone() == (0,)


def test_current_schema_reopens_and_preserves_queued_data(tmp_path: Path) -> None:
    """Exact current-schema validation permits same-schema durable reuse."""
    database = tmp_path / "studio.sqlite3"
    first = GenerationService(database, tmp_path / "images")
    request = GenerationRequest("reopen", seed=7, width=8, height=9)
    queued = first.enqueue("reopen-current", request)

    reopened = GenerationService(database, tmp_path / "images")

    persisted_request = reopened.get_request(queued.request_id)
    assert persisted_request["prompt"] == request.prompt
    assert persisted_request["request_digest"] == request.digest()
    provenance = reopened.get_provenance(queued.job_id)
    assert provenance["status"] == "queued"
    assert provenance["attempt"] is None
    assert reopened.inspect_admission(queued.job_id).admission.decision == "not_required"


@pytest.mark.parametrize("version", (_CURRENT_SCHEMA_VERSION - 1, _CURRENT_SCHEMA_VERSION + 1))
def test_unsupported_schema_version_is_rejected_without_mutation(
    tmp_path: Path, version: int,
) -> None:
    """Older and newer versions are never upgraded, downgraded, or normalized."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {version}")

    _assert_rejected_without_mutation(
        database,
        "unsupported database schema version",
    )


def test_nonempty_unversioned_database_is_rejected_without_mutation(
    tmp_path: Path,
) -> None:
    """An unversioned development table is not eligible for normalization."""
    database = tmp_path / "studio.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE historical_jobs (id TEXT PRIMARY KEY)")

    _assert_rejected_without_mutation(
        database,
        "unsupported database schema version 0",
    )


def test_malformed_current_schema_rejects_extra_objects_without_mutation(
    tmp_path: Path,
) -> None:
    """Current version alone never authorizes extra tables, indexes, or views."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unexpected_table (id TEXT)")

    _assert_rejected_without_mutation(database, "unexpected tables")


def test_current_schema_requires_exact_index_definitions(
    tmp_path: Path,
) -> None:
    """A same-named index with changed columns is structurally incompatible."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    index_name = next(iter(_CURRENT_INDEX_DDL))
    with sqlite3.connect(database) as connection:
        connection.execute(f'DROP INDEX "{index_name}"')
        connection.execute(
            f'CREATE INDEX "{index_name}" ON generation_requests(request_digest)'
        )

    _assert_rejected_without_mutation(database, "divergent definition")


def test_current_schema_requires_exact_table_definitions(
    tmp_path: Path,
) -> None:
    """A same-named table with changed DDL is structurally incompatible."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    table_name = next(iter(_CURRENT_TABLE_DDL))
    with sqlite3.connect(database) as connection:
        table_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()[0]
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_master SET sql = ? WHERE type = 'table' AND name = ?",
            (f"{table_sql} STRICT", table_name),
        )
        connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
        connection.execute("PRAGMA writable_schema = OFF")

    _assert_rejected_without_mutation(
        database,
        f"{table_name} divergent table definition",
    )


def test_current_schema_requires_complete_trigger_set(tmp_path: Path) -> None:
    """A missing current trigger rejects reopening without mutation."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    trigger_name = next(iter(_STATIC_TRIGGER_DDL))
    with sqlite3.connect(database) as connection:
        connection.execute(f'DROP TRIGGER "{trigger_name}"')

    _assert_rejected_without_mutation(database, "missing triggers")


def test_current_schema_requires_exact_trigger_definitions(
    tmp_path: Path,
) -> None:
    """A same-named trigger with changed behavior is structurally incompatible."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    trigger_name = next(iter(_STATIC_TRIGGER_DDL))
    with sqlite3.connect(database) as connection:
        connection.execute(f'DROP TRIGGER "{trigger_name}"')
        connection.execute(
            f'CREATE TRIGGER "{trigger_name}" AFTER INSERT ON generation_requests '
            "BEGIN SELECT 1; END"
        )

    _assert_rejected_without_mutation(
        database,
        f"trigger {trigger_name} divergent definition",
    )


@pytest.mark.parametrize("corruption", ("missing", "invalid"))
def test_current_schema_requires_valid_resource_singleton(
    tmp_path: Path, corruption: str,
) -> None:
    """The heavyweight resource must remain exactly one valid row."""
    database = tmp_path / "studio.sqlite3"
    SQLiteStore(database)
    with sqlite3.connect(database) as connection:
        if corruption == "missing":
            connection.execute("DELETE FROM execution_resource")
        else:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE execution_resource SET state = 'invalid' WHERE id = 1"
            )
            connection.execute("PRAGMA ignore_check_constraints = OFF")

    _assert_rejected_without_mutation(
        database,
        "execution_resource singleton row missing or invalid",
    )


def test_current_schema_requires_admission_for_every_job(tmp_path: Path) -> None:
    """A current execution sidecar cannot exist without admission evidence."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "missing-admission",
        GenerationRequest("missing", seed=1, width=8, height=8),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM execution_admissions WHERE job_id = ?", (queued.job_id,)
        )

    _assert_rejected_without_mutation(database, "execution job lacks admission evidence")


def test_current_schema_rejects_queued_admission_without_capacity_evidence(
    tmp_path: Path,
) -> None:
    """A queued decision cannot reopen without both pinned documents."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "queued-without-evidence",
        GenerationRequest("missing capacity", seed=1, width=8, height=8),
    )
    _set_queued_admission_to_empty_evidence(database, queued.job_id)

    _assert_rejected_without_mutation(
        database,
        "queued admission lacks pinned profile and workload demand",
    )


def test_current_schema_rejects_malformed_nonempty_queued_admission(
    tmp_path: Path,
) -> None:
    """Non-empty JSON objects must still satisfy the typed profile schema."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "queued-malformed-nonempty",
        GenerationRequest("malformed", seed=1, width=8, height=8),
    )
    _set_queued_admission_to_documents(
        database,
        queued.job_id,
        {"x": 1},
        {"x": 1},
    )

    _assert_rejected_without_mutation(
        database,
        "admission profile contains unsupported fields: x",
    )


def test_current_schema_rejects_profile_identity_mismatch(tmp_path: Path) -> None:
    """A pinned profile must match its independent fingerprint column."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "profile-identity-mismatch",
        GenerationRequest("identity", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    _set_queued_admission_to_documents(
        database,
        queued.job_id,
        profile.to_dict(),
        demand.to_dict(),
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            "UPDATE execution_admissions SET profile_fingerprint = ? WHERE job_id = ?",
            ("sha256:" + "0" * 64, queued.job_id),
        )

    _assert_rejected_without_mutation(database, "profile fingerprint")


def test_current_schema_rejects_required_bytes_contradiction(tmp_path: Path) -> None:
    """The pinned reservation amount must match profile and demand capacity."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "required-bytes-mismatch",
        GenerationRequest("required bytes", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    _set_queued_admission_required_bytes(database, queued.job_id, {"system_ram": 0})

    _assert_rejected_without_mutation(database, "required bytes")


def test_claim_rejects_live_queued_admission_without_capacity_evidence(
    tmp_path: Path,
) -> None:
    """An invalid live row cannot create an attempt before reopening."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "live-queued-without-evidence",
        GenerationRequest("missing live capacity", seed=1, width=8, height=8),
    )
    _set_queued_admission_to_empty_evidence(database, queued.job_id)

    with pytest.raises(
        RuntimeError,
        match="queued admission lacks pinned profile and workload demand",
    ):
        service.work()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)


def test_claim_rejects_malformed_nonempty_workload_demand(tmp_path: Path) -> None:
    """Claim validation must parse workload demand before creating an attempt."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "claim-malformed-demand",
        GenerationRequest("malformed demand", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    _set_queued_admission_to_documents(
        database,
        queued.job_id,
        profile.to_dict(),
        {"x": 1},
    )

    with pytest.raises(
        RuntimeError,
        match="workload demand contains unsupported fields: x",
    ):
        service.work()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)


def test_claim_rejects_profile_identity_mismatch(tmp_path: Path) -> None:
    """Claim validation rejects contradictory identity before resource mutation."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "claim-profile-identity-mismatch",
        GenerationRequest("claim identity", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    _set_queued_admission_to_documents(
        database,
        queued.job_id,
        profile.to_dict(),
        demand.to_dict(),
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            "UPDATE execution_admissions SET profile_fingerprint = ? WHERE job_id = ?",
            ("sha256:" + "0" * 64, queued.job_id),
        )

    with pytest.raises(RuntimeError, match="profile fingerprint"):
        service.work()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone() == ("available",)


def test_claim_rejects_required_bytes_contradiction_before_mutation(
    tmp_path: Path,
) -> None:
    """Claim validation rejects a forged reservation before creating an attempt."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "claim-required-bytes-mismatch",
        GenerationRequest("claim required bytes", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    _set_queued_admission_required_bytes(database, queued.job_id, {"system_ram": 0})

    with pytest.raises(RuntimeError, match="required bytes"):
        service.work()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT state FROM execution_resource WHERE id = 1"
        ).fetchone() == ("available",)


def test_not_required_is_limited_to_the_exact_cpu_adapter(tmp_path: Path) -> None:
    """A database cannot relabel a heavyweight adapter as CPU-exempt."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "cpu-exempt",
        GenerationRequest("cpu", seed=1, width=8, height=8),
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            "UPDATE generation_jobs SET adapter_id = 'heavyweight-adapter' "
            "WHERE job_id = ?",
            (queued.job_id,),
        )

    _assert_rejected_without_mutation(database, "not_required admission")


@pytest.mark.parametrize("decision", ("reserved", "released", "quarantined"))
def test_current_schema_rejects_evidence_free_cpu_exemption_after_transition(
    tmp_path: Path, decision: str,
) -> None:
    """A CPU exemption remains CPU-bound through its post-queue states."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        f"{decision}-cpu-exempt",
        GenerationRequest(f"{decision} cpu", seed=1, width=8, height=8),
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            """UPDATE execution_admissions
            SET decision = ?,
                   decision_reason = 'lightweight_admission_not_required',
                   reserved_bytes_json = '{}'
               WHERE job_id = ?""",
            (decision, queued.job_id),
        )
        connection.execute(
            "UPDATE generation_jobs SET adapter_id = 'heavyweight-adapter' "
            "WHERE job_id = ?",
            (queued.job_id,),
        )

    _assert_rejected_without_mutation(database, "not_required admission")


def test_current_schema_accepts_capacity_backed_heavyweight_reservation(
    tmp_path: Path,
) -> None:
    """A heavyweight reservation remains valid with pinned capacity evidence."""
    database = tmp_path / "studio.sqlite3"
    profile, demand = _heavyweight_admission()
    service = GenerationService(
        database,
        tmp_path / "images",
        admission_profile=profile,
    )
    queued = service.enqueue(
        "reserved-heavyweight",
        GenerationRequest("reserved heavyweight", seed=1, width=8, height=8),
        workload_demand=demand,
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            """UPDATE execution_admissions
            SET decision = 'reserved',
                decision_reason = 'resource_reserved',
                reserved_bytes_json = required_bytes_json
            WHERE job_id = ?""",
            (queued.job_id,),
        )

    reopened = SQLiteStore(database)
    inspection = reopened.inspect_admission(queued.job_id)

    assert inspection is not None
    admission = inspection.admission
    assert admission.decision == "reserved"
    assert admission.profile_fingerprint == profile.fingerprint
    assert admission.profile == profile.to_dict()
    assert admission.demand == demand.to_dict()
    assert admission.reserved_bytes == admission.required_bytes


def test_incompatible_writer_epoch_guard_blocks_mutation(tmp_path: Path) -> None:
    """A stale writer cannot mutate a current-schema database."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue(
        "writer-guard",
        GenerationRequest("guard", seed=1, width=8, height=8),
    )
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH - 1,
            deterministic=True,
        )
        with pytest.raises(sqlite3.IntegrityError, match="stale media-generation writer"):
            connection.execute(
                "UPDATE generation_jobs SET updated_at = 'stale' WHERE job_id = ?",
                (queued.job_id,),
            )
