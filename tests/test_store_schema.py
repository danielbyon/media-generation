"""Portable SQL contracts for the durable execution schema."""

from __future__ import annotations

import inspect
from pathlib import Path
import sqlite3
import textwrap

import pytest

from media_generation.store import SQLiteStore


def _execution_resource_ddl() -> str:
    """Read the actual resource schema statement for independent SQL execution."""
    source = inspect.getsource(SQLiteStore._migrate_execution)
    start = source.index("CREATE TABLE execution_resource (")
    end = source.index(')"""', start) + 1
    return textwrap.dedent(source[start:end])


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
        connection.execute(_execution_resource_ddl())
        connection.execute(
            "INSERT INTO execution_resource(id, state, updated_at) VALUES (1, 'available', 'now')"
        )
        for state in ("claimed", "quarantined"):
            connection.execute("UPDATE execution_resource SET state = ?", (state,))
            assert connection.execute("SELECT state FROM execution_resource").fetchone() == (state,)
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            connection.execute("UPDATE execution_resource SET state = 'unknown'")
