"""Portable SQL contracts for the durable execution schema."""

from __future__ import annotations

import inspect
from pathlib import Path
import subprocess
import textwrap

from media_generation.store import SQLiteStore


def _execution_resource_ddl() -> str:
    """Extract the schema statement exercised by a double-quote-disabled CLI."""
    source = inspect.getsource(SQLiteStore._migrate_execution)
    start = source.index("CREATE TABLE execution_resource (")
    end = source.index(')"""', start) + 1
    return textwrap.dedent(source[start:end])


def test_execution_resource_schema_uses_portable_string_literals(
    tmp_path: Path,
) -> None:
    """The resource state contract works when SQLite disables DQS fallback."""
    database = tmp_path / "schema.sqlite3"
    setup = (
        ".dbconfig dqs_ddl off\n"
        ".dbconfig dqs_dml off\n"
        f"{_execution_resource_ddl()};\n"
        "INSERT INTO execution_resource(id, state, updated_at) "
        "VALUES (1, 'available', '2026-10-24T00:00:00+00:00');\n"
        "UPDATE execution_resource SET state = 'claimed' WHERE id = 1;\n"
        "UPDATE execution_resource SET state = 'quarantined' WHERE id = 1;\n"
    )

    created = subprocess.run(
        ["sqlite3", str(database)],
        input=setup,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert created.returncode == 0, created.stderr

    rejected = subprocess.run(
        ["sqlite3", str(database)],
        input=(
            ".dbconfig dqs_dml off\n"
            "UPDATE execution_resource SET state = 'unknown' WHERE id = 1;\n"
        ),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert rejected.returncode != 0
    assert "CHECK constraint failed" in rejected.stderr
