"""Current-schema execution persistence contracts replacing migration tests."""

from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from media_generation.adapters import DeterministicCpuAdapter
from media_generation.errors import GenerationError
from media_generation.service import GenerationService
from media_generation.store import (
    _WRITER_EPOCH,
    _WRITER_EPOCH_FUNCTION,
)
from test_durable_execution import request


def _assert_no_artifact(service: GenerationService, job_id: str) -> None:
    """Require that failed admission or privacy never creates image output."""
    assert service.get_provenance(job_id)["attempt"] is None
    assert service.get_job(job_id).artifact_id is None
    assert list((service.output_directory).glob("*.png")) == []


def test_deterministic_cpu_runs_without_heavyweight_admission(tmp_path: Path) -> None:
    """The exact bundled adapter receives not_required and executes normally."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")

    first = service.submit("deterministic", request())
    replay = GenerationService(database, tmp_path / "images").submit(
        "deterministic", request()
    )

    assert first.status == "succeeded"
    assert first.artifact_id is not None
    assert replay.job_id == first.job_id
    assert replay.artifact_id == first.artifact_id
    inspection = service.inspect_admission(first.job_id)
    assert inspection is not None
    assert inspection.admission.decision == "released"
    assert inspection.admission.profile_fingerprint is None
    assert inspection.admission.required_bytes == {}


def test_deterministic_cpu_subclass_cannot_inherit_the_exemption(
    tmp_path: Path,
) -> None:
    """A CPU subclass without explicit admission cannot create orphaned work."""

    from media_generation.errors import InputValidationError
    from media_generation.service import GenerationService

    class SubclassedCpu(DeterministicCpuAdapter):
        pass

    service = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
        adapter=SubclassedCpu(),
    )

    with pytest.raises(
        InputValidationError,
        match="heavyweight execution requires explicit profile and demand evidence",
    ):
        service.enqueue("subclass", request())

    with service._store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM generation_jobs").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM execution_jobs").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM execution_admissions").fetchone()[0] == 0


def test_current_privacy_evidence_is_required_before_claim(tmp_path: Path) -> None:
    """A same-schema job with malformed privacy evidence never executes."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue("privacy", request())
    with sqlite3.connect(database) as connection:
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute(
            "UPDATE execution_jobs SET privacy_compliance_json = '{}' WHERE job_id = ?",
            (queued.job_id,),
        )

    with pytest.raises(GenerationError, match="privacy-compliance evidence"):
        service.work()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT count(*) FROM execution_attempts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM generation_artifacts WHERE job_id = ?",
            (queued.job_id,),
        ).fetchone() == (0,)
    assert list((tmp_path / "images").glob("*.png")) == []


def test_same_schema_reopen_rejects_missing_execution_sidecar(
    tmp_path: Path,
) -> None:
    """A current-version job cannot be reopened without its execution state."""
    database = tmp_path / "studio.sqlite3"
    service = GenerationService(database, tmp_path / "images")
    queued = service.enqueue("missing-sidecar", request())
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "DELETE FROM execution_admissions WHERE job_id = ?", (queued.job_id,)
        )
        connection.execute(
            "DELETE FROM execution_jobs WHERE job_id = ?", (queued.job_id,)
        )

    with pytest.raises(RuntimeError, match="generation job lacks execution state"):
        GenerationService(database, tmp_path / "images")
