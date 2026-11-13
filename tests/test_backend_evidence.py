"""Durable backend execution evidence and supervision contracts."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import signal
import sqlite3
import stat
import sys
import time
from pathlib import Path

import pytest

from media_generation import backend_provenance, cli, engine
from media_generation.backend_provenance import (
    LAUNCH_SCHEMA,
    RECORD_SCHEMA_VERSION,
    OutputClassification,
    backend_digest,
    classify_output,
    digest,
)
from media_generation.domain import GenerationPlan, GenerationRequest
from media_generation.errors import (
    BackendEvidenceError,
    BackendPreparationError,
    GenerationExecutionError,
    InputValidationError,
    RecordNotFoundError,
)
from media_generation.service import GenerationService, _lease_deadline, _now
from media_generation.store import _WRITER_EPOCH, _WRITER_EPOCH_FUNCTION
from media_generation.supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)
from test_t08_support import build_bundle, heavy_admission_profile, heavy_workload_demand
from test_engine_adapter import RUNTIME, _adapter


@pytest.fixture(autouse=True)
def synthetic_rocm_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply deterministic read-only runtime evidence on any test host."""
    monkeypatch.setattr(
        engine, "capture_runtime_fingerprint", lambda: dict(RUNTIME)
    )


def _service(
    tmp_path: Path, bundle, *, adapter=None, attempt_runner=None
) -> GenerationService:
    output = tmp_path / "images"
    return GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=adapter or _adapter(bundle, output),
        admission_profile=heavy_admission_profile(),
        attempt_runner=attempt_runner,
    )


def _request() -> GenerationRequest:
    return GenerationRequest("a red cube", seed=7, width=64, height=64)


def _claim(service: GenerationService, job_id: str):
    (_, configuration_json, _, privacy_json) = service._current_privacy_snapshot()
    claim = service._store.claim_next_execution(
        attempt_id="att_manual",
        owner_id="owner_manual",
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=configuration_json,
        privacy_compliance_json=privacy_json,
        resolved_output_directory=str(service.output_directory),
        process_contained=False,
        containment_contract=None,
        timestamp=_now(),
        lease_expires_at=_lease_deadline(service._lease),
        job_id=job_id,
    )
    assert claim is not None
    return claim


def _raw_connection(path: Path) -> sqlite3.Connection:
    """Open SQLite with the application's writer guard registered.

    The guards use a SQL function so ordinary external connections cannot
    mutate the current schema. Corruption tests opt in explicitly and can then
    distinguish guard behavior from the table's own state-machine triggers.
    """

    connection = sqlite3.connect(path)
    connection.create_function(
        _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
    )
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _plan(claim) -> GenerationPlan:
    return GenerationPlan(
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


def _launch(prepared) -> dict[str, object]:
    return {
        "schema": LAUNCH_SCHEMA,
        "schema_version": RECORD_SCHEMA_VERSION,
        "attempt_id": prepared.attempt_id,
        "listener_pid": 4242,
        "monotonic_start_ns": 1,
        "launched": True,
        "argv": list(prepared.argv),
        "environment": dict(prepared.environment),
    }


def _observed(attempt_id: str) -> dict[str, object]:
    return {
        "schema": "media-generation.backend-execution-observed",
        "schema_version": RECORD_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "exit_code": 0,
        "signal": None,
        "direct_child_reaped": True,
        "duration_seconds": 0.5,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "stdout_classification": "empty",
        "stderr_classification": "empty",
        "stdout_codes": ["blank"],
        "stderr_codes": ["blank"],
        "process_tree_containment": False,
        "inherited_streams_retained_after_reap": False,
        "stream_state_unknown": False,
    }


class _TestAuthority(ExecutionEvidenceAuthority):
    """Minimal app-owned authority for supervisor-only tests."""

    def __init__(
        self,
        attempt_id: str,
        *,
        current: bool = True,
        launch_error: Exception | None = None,
        launch_wait_for: Path | None = None,
    ) -> None:
        self._attempt_id = attempt_id
        self._current = current
        self._launch_error = launch_error
        self._launch_wait_for = launch_wait_for
        self.launches: list[LaunchFact] = []
        self.observations: list[ProcessObservation] = []

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    def verify_current(self) -> bool:
        return self._current

    def record_launch(self, fact: LaunchFact) -> None:
        assert isinstance(fact, LaunchFact)
        self.launches.append(fact)
        if self._launch_wait_for is not None:
            deadline = time.monotonic() + 2.0
            while (
                not self._launch_wait_for.exists()
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
        if self._launch_error is not None:
            raise self._launch_error

    def record_observation(self, fact: ProcessObservation) -> None:
        assert isinstance(fact, ProcessObservation)
        self.observations.append(fact)


def _insert_resolved(service, claim, prepared) -> str:
    return service._store.insert_resolved_execution(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=dict(prepared.resolved_record),
        timestamp=_now(),
    )


def test_successful_execution_persists_complete_observed_evidence(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    result = service.submit(
        "success", _request(), workload_demand=heavy_workload_demand()
    )
    provenance = service.get_provenance(result.job_id)
    assert provenance["status"] == "succeeded"
    assert provenance["backend_execution"] == {
        "attempt_id": provenance["attempt"]["attempt_id"],
        "state": "observed",
        "resolved_digest": provenance["backend_execution"]["resolved_digest"],
        "observed_at": provenance["backend_execution"]["observed_at"],
    }
    assert set(provenance["backend_execution"]) == {
        "attempt_id",
        "state",
        "resolved_digest",
        "observed_at",
    }
    assert provenance["attempt"]["termination_proven"] is True
    assert service._store.resource_snapshot()["state"] == "available"

    record = service.get_execution(result.job_id)
    assert record["state"] == "observed"
    assert record["launch"]["launched"] is True
    assert record["observed"]["direct_child_reaped"] is True
    assert record["observed"]["process_tree_containment"] is False
    assert record["resolved_digest"] == backend_digest(record["resolved"])
    assert backend_digest(record["resolved"]) == digest(record["resolved"])
    resolved = record["resolved"]
    assert resolved["verification_id"].startswith("sha256:")
    assert resolved["candidate_id"].startswith("sha256:")
    assert resolved["backend_kind"] == "local-inference"
    assert resolved["engine"]["id"] == "stable-diffusion.cpp"
    assert resolved["recipe"]["id"] == "qwen-image-edit-2511-recipe"
    assert [component["role"] for component in resolved["components"]] == [
        "diffusion_model",
        "vae",
        "text_encoder",
    ]
    assert resolved["adapters"] == []
    assert resolved["prompt"] == "a red cube"
    assert (resolved["seed"], resolved["width"], resolved["height"]) == (7, 64, 64)
    assert resolved["sampling"] == {
        "sampling_method": "euler",
        "steps": 8,
        "cfg_scale": 2.5,
        "flow_shift": 3.0,
        "strength": None,
    }
    assert resolved["conditioning"] == []
    assert isinstance(resolved["argv"], list)
    assert resolved["invocation_contract"] == "sd-cpp-exec-v1"
    assert resolved["cli_contract"] == "model-args/v1"
    assert resolved["environment"]["names"] == sorted(resolved["environment"]["names"])
    assert "HTTP_PROXY" not in resolved["environment"]["names"]
    assert set(resolved["environment"]["values"]) <= {
        "HIP_VISIBLE_DEVICES",
        "HSA_OVERRIDE_GFX_VERSION",
    }
    assert resolved["runtime"]["rocm_version"] == RUNTIME["rocm_version"]
    assert resolved["output_basename"] == "output.png"
    legacy_record = dict(resolved)
    legacy_record["environment"] = dict(resolved["environment"])
    legacy_record["environment"].pop("sha256")
    backend_provenance.validate_resolved_record(legacy_record)


@pytest.mark.parametrize(
    "changed_name",
    [
        "LD_LIBRARY_PATH",
        "PATH",
        "ROCM_PATH",
        "HIP_VISIBLE_DEVICES",
        "HSA_OVERRIDE_GFX_VERSION",
    ],
)
def test_environment_record_binds_every_effective_value_without_storing_paths(
    changed_name: str,
) -> None:
    environment = {
        "LD_LIBRARY_PATH": "/srv/runtime/lib",
        "PATH": "/usr/bin",
        "ROCM_PATH": "/srv/runtime/rocm",
        "HIP_VISIBLE_DEVICES": "0",
        "HSA_OVERRIDE_GFX_VERSION": "11.0.0",
    }
    changed = dict(environment)
    changed[changed_name] += ".changed"

    record = backend_provenance.environment_record(environment)
    changed_record = backend_provenance.environment_record(changed)

    assert record != changed_record
    assert set(record["values"]) == {
        "HIP_VISIBLE_DEVICES",
        "HSA_OVERRIDE_GFX_VERSION",
    }
    serialized = json.dumps(record)
    assert "/srv/runtime/lib" not in serialized
    assert "/usr/bin" not in serialized
    assert "/srv/runtime/rocm" not in serialized


def test_failed_reaped_execution_is_terminal_and_releases_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_bundle(tmp_path)
    bundle.set_mode(behavior="exit_nonzero", exit_code=4)
    service = _service(tmp_path, bundle)
    cleaned: list[Path] = []
    cleanup = service.adapter.cleanup_execution

    def capture_cleanup(prepared: object) -> None:
        cleaned.append(Path(prepared.scratch_directory))
        cleanup(prepared)

    monkeypatch.setattr(service.adapter, "cleanup_execution", capture_cleanup)
    with pytest.raises(GenerationExecutionError) as raised:
        service.submit("failure", _request(), workload_demand=heavy_workload_demand())
    job_id = raised.value.job_id
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "failed"
    assert provenance["attempt"]["failure_class"] == "terminal"
    assert provenance["attempt"]["termination_proven"] is True
    assert provenance["backend_execution"]["state"] == "observed"
    assert service.get_execution(job_id)["observed"]["exit_code"] == 4
    assert service._store.resource_snapshot()["state"] == "available"
    assert provenance["artifact"] is None
    assert cleaned and all(not scratch.exists() for scratch in cleaned)


@pytest.mark.parametrize("behavior", ("invalid_bytes", "partial_bytes"))
def test_invalid_or_partial_output_after_reap_is_terminal_and_releases_resource(
    tmp_path: Path, behavior: str
) -> None:
    bundle = build_bundle(tmp_path)
    bundle.set_mode(behavior=behavior)
    service = _service(tmp_path, bundle)
    with pytest.raises(GenerationExecutionError) as raised:
        service.submit(behavior, _request(), workload_demand=heavy_workload_demand())
    provenance = service.get_provenance(raised.value.job_id)
    assert provenance["status"] == "failed"
    assert provenance["attempt"]["failure_class"] == "terminal"
    assert provenance["attempt"]["termination_proven"] is True
    assert service._store.resource_snapshot()["state"] == "available"


def test_observation_persistence_failure_fails_closed_into_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)

    def refuse(**_: object) -> None:
        raise RuntimeError("simulated evidence write failure")

    monkeypatch.setattr(service._store, "mark_execution_observed", refuse)
    with pytest.raises(GenerationExecutionError) as raised:
        service.submit(
            "observation-failure", _request(), workload_demand=heavy_workload_demand()
        )
    job_id = raised.value.job_id
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert provenance["attempt"]["termination_proven"] is False
    assert provenance["backend_execution"]["state"] == "launched"
    assert service._store.resource_snapshot()["state"] == "quarantined"
    restarted = _service(tmp_path, bundle)
    assert restarted.recover()["status"] == "attention_required"


def test_unreaped_attempt_is_ambiguous_and_recover_reports_attention(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "unreaped", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    service._store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    service.adapter.cleanup_execution(prepared)
    restarted = _service(tmp_path, bundle)
    assert restarted.recover()["status"] == "attention_required"
    provenance = restarted.get_provenance(queued.job_id)
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    assert provenance["attempt"]["termination_proven"] is False
    assert provenance["backend_execution"]["state"] == "launched"
    assert restarted._store.resource_snapshot()["state"] == "quarantined"
    assert restarted.recover()["status"] == "attention_required"


def test_pre_dispatch_refusal_is_terminal_without_ambiguous_quarantine(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "refusal", _request(), workload_demand=heavy_workload_demand()
    )
    bundle.recipe_path.write_bytes(bundle.recipe_path.read_bytes() + b" ")
    report = service.work()
    assert report["processed"] == 1
    provenance = service.get_provenance(queued.job_id)
    assert provenance["status"] == "failed"
    assert provenance["attempt"]["failure_class"] == "terminal"
    assert provenance["attempt"]["termination_proven"] is True
    assert provenance["backend_execution"] is None
    assert provenance["execution"]["failure_message"] == (
        "execution_preparation_failed: bundle_corrupt"
    )
    assert service._store.resource_snapshot()["state"] == "available"
    with pytest.raises(RecordNotFoundError):
        service.get_execution(queued.job_id)


def test_residual_descendant_quarantines_a_successful_execution(
    tmp_path: Path,
) -> None:
    """A grandchild that keeps the pipes open prevents termination proof."""
    bundle = build_bundle(tmp_path)
    bundle.set_mode(behavior="grandchild")
    service = _service(tmp_path, bundle)

    result = service.submit(
        "grandchild", _request(), workload_demand=heavy_workload_demand()
    )

    provenance = service.get_provenance(result.job_id)
    assert provenance["status"] == "succeeded"
    assert provenance["artifact"] is not None
    assert provenance["attempt"]["termination_proven"] is False
    record = service.get_execution(result.job_id)
    assert record["observed"]["direct_child_reaped"] is True
    assert record["observed"]["inherited_streams_retained_after_reap"] is True
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_nul_prompt_is_refused_before_any_backend_attempt(
    tmp_path: Path,
) -> None:
    """A NUL byte is a terminal input error before admission or dispatch."""

    with pytest.raises(InputValidationError, match="NUL"):
        GenerationRequest("a red\x00cube")
    assert GenerationRequest("  café 场景  ").prompt == "café 场景"

    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM execution_jobs"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM backend_executions"
        ).fetchone()[0] == 0
    assert service._store.resource_snapshot()["state"] == "available"


def test_missing_executable_after_resolution_is_terminal_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spawn that cannot start the verified engine is a terminal refusal."""
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "missing-engine", _request(), workload_demand=heavy_workload_demand()
    )
    original_run = ProcessSupervisor.run

    def run_after_removal(self, argv, *, env, cwd):
        bundle.engine_path.unlink()
        return original_run(self, argv, env=env, cwd=cwd)

    monkeypatch.setattr(ProcessSupervisor, "run", run_after_removal)

    report = service.work()

    assert report["processed"] == 1
    provenance = service.get_provenance(queued.job_id)
    assert provenance["status"] == "failed"
    assert provenance["attempt"]["failure_class"] == "terminal"
    assert provenance["attempt"]["termination_proven"] is True
    assert provenance["execution"]["failure_message"] == (
        "execution_preparation_failed: engine_launch_failed"
    )
    record = service.get_execution(queued.job_id)
    assert record["state"] == "resolved"
    assert record.get("launch") is None
    assert service._store.resource_snapshot()["state"] == "available"


def test_stale_owner_or_epoch_cannot_write_evidence(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "stale", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    store = service._store
    with pytest.raises(BackendEvidenceError):
        store.insert_resolved_execution(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="someone_else",
            claim_epoch=claim.claim_epoch,
            record=dict(prepared.resolved_record),
            timestamp=_now(),
        )
    with pytest.raises(BackendEvidenceError):
        store.insert_resolved_execution(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch + 1,
            record=dict(prepared.resolved_record),
            timestamp=_now(),
        )
    _insert_resolved(service, claim, prepared)
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_launched(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="someone_else",
            claim_epoch=claim.claim_epoch,
            record=_launch(prepared),
            timestamp=_now(),
        )
    assert store.get_backend_execution(claim.job_id)["state"] == "resolved"
    store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_observed(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch + 1,
            record=_observed(claim.attempt_id),
            timestamp=_now(),
        )
    assert store.get_backend_execution(claim.job_id)["state"] == "launched"
    service.adapter.cleanup_execution(prepared)


def test_launch_requires_resolved_and_each_transition_occurs_once(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "transitions", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    store = service._store
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_launched(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch,
            record=_launch(prepared),
            timestamp=_now(),
        )
    _insert_resolved(service, claim, prepared)
    with pytest.raises(BackendEvidenceError):
        _insert_resolved(service, claim, prepared)
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_observed(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch,
            record=_observed(claim.attempt_id),
            timestamp=_now(),
        )
    store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_launched(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch,
            record=_launch(prepared),
            timestamp=_now(),
        )
    store.mark_execution_observed(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_observed(claim.attempt_id),
        timestamp=_now(),
    )
    with pytest.raises(BackendEvidenceError):
        store.mark_execution_observed(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch,
            record=_observed(claim.attempt_id),
            timestamp=_now(),
        )
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE backend_executions SET resolved_json = '{}' WHERE attempt_id = ?",
                (claim.attempt_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE backend_executions SET state = 'launched' WHERE attempt_id = ?",
                (claim.attempt_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "DELETE FROM backend_executions WHERE attempt_id = ?",
                (claim.attempt_id,),
            )
    service.adapter.cleanup_execution(prepared)


def test_sql_rejects_initial_rows_in_later_stages(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "direct-insert", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        for state in ("launched", "observed"):
            launch_json = "{}" if state in {"launched", "observed"} else None
            observed_json = "{}" if state == "observed" else None
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(
                    """INSERT INTO backend_executions
                    (attempt_id, job_id, backend_kind, candidate_id,
                     resolved_json, resolved_digest, resolved_at,
                     launch_json, launch_at, observed_json, observed_at, state)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        claim.attempt_id,
                        claim.job_id,
                        "stable-diffusion-cpp",
                        "sha256:" + "0" * 64,
                        "{}",
                        "0" * 64,
                        _now(),
                        launch_json,
                        _now() if launch_json is not None else None,
                        observed_json,
                        _now() if observed_json is not None else None,
                        state,
                    ),
                )


def test_recovery_with_malformed_observation_cannot_release_resource(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "recovery-malformed", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    service._store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    service._store.mark_execution_observed(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_observed(claim.attempt_id),
        timestamp=_now(),
    )
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        connection.execute(
            "UPDATE backend_executions SET observed_json = '{}' WHERE attempt_id = ?",
            (claim.attempt_id,),
        )
    before = service._store.resource_snapshot()
    assert before["state"] == "claimed"
    with pytest.raises(BackendEvidenceError):
        service.recover()
    after = service._store.resource_snapshot()
    assert after["state"] == "claimed"
    assert after["job_id"] == before["job_id"]
    with pytest.raises(BackendEvidenceError):
        service.get_provenance(queued.job_id)
    service.adapter.cleanup_execution(prepared)


def test_resolved_record_is_never_launch_or_termination_proof(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "resolved-only", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    record = service.get_execution(queued.job_id)
    assert record["state"] == "resolved"
    assert record["launch"] is None
    assert record["observed"] is None
    assert service._store.termination_evidence_proven(
        queued.job_id, claim.attempt_id
    ) is False
    provenance = service.get_provenance(queued.job_id)
    assert provenance["backend_execution"]["state"] == "resolved"
    assert provenance["backend_execution"]["observed_at"] is None
    service.adapter.cleanup_execution(prepared)


def test_malformed_persisted_evidence_raises_fail_closed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "corrupt-row", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        connection.execute(
            "UPDATE backend_executions SET resolved_json = '{}' WHERE attempt_id = ?",
            (claim.attempt_id,),
        )
    with pytest.raises(BackendEvidenceError):
        service.get_execution(queued.job_id)
    with pytest.raises(BackendEvidenceError):
        service._store.termination_evidence_proven(queued.job_id, claim.attempt_id)
    service.adapter.cleanup_execution(prepared)


def test_malformed_launch_evidence_raises_fail_closed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "corrupt-launch", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    service._store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        updated = connection.execute(
            "UPDATE backend_executions SET launch_json = '{}' WHERE attempt_id = ?",
            (claim.attempt_id,),
        )
        assert updated.rowcount == 1
    with pytest.raises(BackendEvidenceError):
        service.get_execution(queued.job_id)
    with pytest.raises(BackendEvidenceError):
        service._store.termination_evidence_proven(queued.job_id, claim.attempt_id)
    service.adapter.cleanup_execution(prepared)


def test_malformed_observed_evidence_raises_fail_closed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "corrupt-observation", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    service._store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    )
    service._store.mark_execution_observed(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=_observed(claim.attempt_id),
        timestamp=_now(),
    )
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        updated = connection.execute(
            "UPDATE backend_executions SET observed_json = '{}' WHERE attempt_id = ?",
            (claim.attempt_id,),
        )
        assert updated.rowcount == 1
    with pytest.raises(BackendEvidenceError):
        service.get_execution(queued.job_id)
    with pytest.raises(BackendEvidenceError):
        service._store.termination_evidence_proven(queued.job_id, claim.attempt_id)
    service.adapter.cleanup_execution(prepared)


def test_resolved_digest_mismatch_raises_fail_closed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "corrupt-digest", _request(), workload_demand=heavy_workload_demand()
    )
    claim = _claim(service, queued.job_id)
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        updated = connection.execute(
            "UPDATE backend_executions SET resolved_digest = ? WHERE attempt_id = ?",
            ("0" * 64, claim.attempt_id),
        )
        assert updated.rowcount == 1
    with pytest.raises(BackendEvidenceError):
        service.get_execution(queued.job_id)
    with pytest.raises(BackendEvidenceError):
        service._store.termination_evidence_proven(queued.job_id, claim.attempt_id)
    service.adapter.cleanup_execution(prepared)


def test_backend_evidence_is_restart_stable(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    result = service.submit(
        "restart", _request(), workload_demand=heavy_workload_demand()
    )
    first = service.get_execution(result.job_id)
    restarted = GenerationService(
        tmp_path / "studio.sqlite3",
        tmp_path / "images",
    )
    second = restarted.get_execution(result.job_id)
    assert first == second
    assert first["resolved_digest"] == backend_digest(first["resolved"])
    assert restarted.get_provenance(result.job_id)["backend_execution"] == service.get_provenance(
        result.job_id
    )["backend_execution"]


def test_adapter_that_never_spawns_cannot_produce_termination_proof(
    tmp_path: Path,
) -> None:
    """Leaving execute without a supervised child cannot yield launch or reaping."""
    bundle = build_bundle(tmp_path)
    output = tmp_path / "images"
    adapter = _adapter(bundle, output)

    def execute_without_spawn(plan, destination, *, supervisor):
        return None

    adapter.execute = execute_without_spawn  # type: ignore[method-assign]
    service = _service(tmp_path, bundle, adapter=adapter)
    queued = service.enqueue(
        "never-spawned", _request(), workload_demand=heavy_workload_demand()
    )
    report = service.work()
    assert report["processed"] == 1
    provenance = service.get_provenance(queued.job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["artifact"] is None
    assert provenance["attempt"]["termination_proven"] is False
    assert provenance["attempt"]["failure_class"] == "ambiguous"
    record = service.get_execution(queued.job_id)
    assert record["state"] == "resolved"
    assert record.get("launch") is None
    assert record.get("observed") is None
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_supervisor_records_signal_termination() -> None:
    argv = [
        sys.executable,
        "-c",
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    ]
    authority = _TestAuthority("att_signal")
    observation = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    ).run(argv, env={}, cwd=Path.cwd())
    assert observation.exit_code is None
    assert observation.signal is not None
    assert observation.to_mapping()["direct_child_reaped"] is True
    assert authority.observations == [observation]
    assert authority.launches[0].argv == tuple(argv)


def test_supervisor_classifies_output_and_hashes_every_byte() -> None:
    """Captured text is described, never stored, while digests stay complete."""

    payload = b"x" * 300_000 + bytes(range(1, 32))
    argv = [
        sys.executable,
        "-c",
        (
            "import sys; "
            "sys.stdout.buffer.write(b'x'*300000 + bytes(range(1,32)))"
        ),
    ]
    authority = _TestAuthority("att_classification")
    observation = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    ).run(argv, env={}, cwd=Path.cwd())
    assert observation.stdout_bytes == len(payload)
    assert observation.stdout_sha256 == hashlib.sha256(payload).hexdigest()
    assert observation.stderr_sha256 == hashlib.sha256(b"").hexdigest()
    assert observation.stdout_classification == "truncated"
    assert observation.stderr_classification == "empty"
    assert "truncated" in observation.stdout_codes
    assert "lines_bounded" in observation.stdout_codes
    assert observation.stderr_codes == ("blank",)
    stored = observation.to_mapping()
    assert not {"stdout_excerpt", "stderr_excerpt"} & set(stored)


def test_supervisor_returns_despite_surviving_grandchild(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path)
    adapter = _adapter(bundle, tmp_path / "images")
    bundle.set_mode(behavior="grandchild")
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_grandchild",
            attempt_id="att_grandchild",
            resolved_prompt="a red cube",
            seed=1,
        width=64,
        height=64,
            references=(),
            output_slot="primary",
            output_slot_id="slot",
        )
    )
    started = time.monotonic()
    authority = _TestAuthority("att_grandchild")
    observation = ProcessSupervisor(
        authority,
        expected_argv=prepared.argv,
        expected_environment=prepared.environment,
        drain_timeout_seconds=0.2,
    ).run(
        prepared.argv,
        env=prepared.environment,
        cwd=prepared.scratch_directory,
    )
    elapsed = time.monotonic() - started
    assert observation.exit_code == 0
    assert elapsed < 2.0
    assert observation.to_mapping()["process_tree_containment"] is False
    adapter.cleanup_execution(prepared)


def test_launch_recorder_failure_kills_and_reaps_child(tmp_path: Path) -> None:
    pid_path = tmp_path / "child.pid"
    argv = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, time; "
            f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
            "time.sleep(5)"
        ),
    ]
    authority = _TestAuthority(
        "att_launch_failure",
        launch_error=RuntimeError("launch evidence could not be written"),
        launch_wait_for=pid_path,
    )
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    )
    started = time.monotonic()
    with pytest.raises(RuntimeError):
        supervisor.run(argv, env={}, cwd=Path.cwd())
    assert time.monotonic() - started < 3.0
    assert supervisor.process_started is True
    assert authority.launches
    child_pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_managed_listener_identity_uses_injected_backend_neutral_pid_check() -> None:
    authority = _TestAuthority("att_listener_owner")
    argv = (sys.executable, "-c", "import time; time.sleep(30)")
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.05,
    )
    observed_child_pid: list[int] = []
    resolver_calls: list[tuple[str, int]] = []

    def session(control) -> str:
        observed_child_pid.append(control.pid)
        control.require_listener_owner("127.0.0.1", 8188)
        return "owned"

    def listener_owner_pid(host: str, port: int) -> int:
        resolver_calls.append((host, port))
        return observed_child_pid[-1]

    result, observation = supervisor.run_managed(
        argv,
        env={},
        cwd=Path.cwd(),
        session=session,
        listener_owner_pid=listener_owner_pid,
        shutdown_timeout_seconds=0.2,
    )

    assert result == "owned"
    assert resolver_calls == [("127.0.0.1", 8188)]
    assert len(authority.launches) == len(authority.observations) == 1
    assert observation is authority.observations[0]
    assert observation.exit_code is None


@pytest.mark.parametrize(
    ("listener_owner_pid", "error"),
    [
        (None, "listener ownership proof is unavailable"),
        (lambda _host, _port: 123, "not owned by the managed direct child"),
        (lambda _host, _port: True, "not owned by the managed direct child"),
    ],
)
def test_managed_listener_identity_fails_closed_without_child_pid_proof(
    listener_owner_pid, error: str
) -> None:
    authority = _TestAuthority("att_listener_owner_refused")
    argv = (sys.executable, "-c", "import time; time.sleep(30)")
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.05,
    )

    with pytest.raises(BackendEvidenceError, match=error):
        supervisor.run_managed(
            argv,
            env={},
            cwd=Path.cwd(),
            session=lambda control: control.require_listener_owner(
                "127.0.0.1", 8188
            ),
            listener_owner_pid=listener_owner_pid,
            shutdown_timeout_seconds=0.2,
        )

    assert supervisor.process_started is True
    assert len(authority.launches) == len(authority.observations) == 1


def _write_runtime_marker(path: Path, value: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    return str(path)


def _isolate_runtime_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    default_rocm_version: str | None = None,
    amdgpu_version: str | None = None,
    amdgpu_srcversion: str | None = None,
) -> Path:
    """Point runtime marker lookups at synthetic files instead of the host."""

    default_root = tmp_path / "default-rocm"
    if default_rocm_version is not None:
        _write_runtime_marker(default_root / ".info" / "version", default_rocm_version)
    monkeypatch.setattr(backend_provenance, "_DEFAULT_ROCM_ROOT", str(default_root))

    version_path = tmp_path / "amdgpu-version"
    srcversion_path = tmp_path / "amdgpu-srcversion"
    if amdgpu_version is not None:
        _write_runtime_marker(version_path, amdgpu_version)
    if amdgpu_srcversion is not None:
        _write_runtime_marker(srcversion_path, amdgpu_srcversion)
    monkeypatch.setattr(
        backend_provenance, "_AMDGPU_VERSION_MARKER", str(version_path)
    )
    monkeypatch.setattr(
        backend_provenance, "_AMDGPU_SRCVERSION_MARKER", str(srcversion_path)
    )
    return default_root


def test_runtime_fingerprint_reads_rocm_version_from_explicit_rocm_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A configured ROCM_PATH selects the installation release marker."""

    active_root = tmp_path / "active-rocm"
    _write_runtime_marker(active_root / ".info" / "version", "6.4.1")
    _isolate_runtime_markers(tmp_path, monkeypatch, default_rocm_version="9.9.9")
    monkeypatch.setenv("ROCM_PATH", str(active_root))

    runtime = backend_provenance.capture_runtime_fingerprint()

    assert runtime["rocm_path"] == str(active_root)
    assert runtime["rocm_version"] == "6.4.1"


def test_runtime_fingerprint_falls_back_to_default_rocm_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable ROCM_PATH marker still falls back to /opt/rocm."""

    _isolate_runtime_markers(tmp_path, monkeypatch, default_rocm_version="6.4.0")
    monkeypatch.setenv("ROCM_PATH", str(tmp_path / "rocm-without-marker"))

    runtime = backend_provenance.capture_runtime_fingerprint()

    assert runtime["rocm_version"] == "6.4.0"


def test_runtime_fingerprint_prefers_amdgpu_version_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The semantic module version wins when the kernel exposes it."""

    _isolate_runtime_markers(
        tmp_path,
        monkeypatch,
        amdgpu_version="6.12.0",
        amdgpu_srcversion="ABCD1234",
    )

    runtime = backend_provenance.capture_runtime_fingerprint()

    assert runtime["amdgpu_version"] == "6.12.0"


def test_runtime_fingerprint_falls_back_to_amdgpu_srcversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The opaque module build identifier fills the same field when needed."""

    _isolate_runtime_markers(
        tmp_path,
        monkeypatch,
        amdgpu_srcversion="ABCD1234",
    )

    runtime = backend_provenance.capture_runtime_fingerprint()

    assert runtime["amdgpu_version"] == "ABCD1234"


def test_runtime_fingerprint_returns_none_when_markers_are_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing markers stay null and still fail closed at dispatch validation."""

    _isolate_runtime_markers(tmp_path, monkeypatch)
    monkeypatch.delenv("ROCM_PATH", raising=False)

    runtime = backend_provenance.capture_runtime_fingerprint()

    assert runtime["rocm_version"] is None
    assert runtime["amdgpu_version"] is None
    with pytest.raises(BackendPreparationError) as raised:
        engine._validate_runtime({**runtime, "platform": "linux"})
    assert raised.value.code == "runtime_evidence_incomplete"


def test_drain_failure_kills_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure while draining still terminates and reaps the direct child."""
    pid_path = tmp_path / "drain-child.pid"
    argv = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, time; "
            f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
            "time.sleep(5)"
        ),
    ]
    authority = _TestAuthority("att_drain_failure")

    def fail_drain(self, process, *, stdout_capture, stderr_capture):
        deadline = time.monotonic() + 5.0
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise RuntimeError("drain registration failed")

    monkeypatch.setattr(ProcessSupervisor, "_drain_until_reaped", fail_drain)
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    )

    with pytest.raises(RuntimeError):
        supervisor.run(argv, env={}, cwd=Path.cwd())

    child_pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_open_stream_probe_captures_every_byte_it_reads() -> None:
    """A residual-descendant probe must not drop bytes from counts or digests."""
    from media_generation.supervisor import _PipeCapture

    read_fd, write_fd = os.pipe()
    payload = b"late descendant bytes that must stay in the digest\n"
    try:
        os.write(write_fd, payload)
        os.set_blocking(read_fd, False)
        capture = _PipeCapture()
        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            decision, stream_state_unknown = (
                ProcessSupervisor._streams_still_open(((stream, capture),))
            )
        read_fd = -1
        assert decision is True
        assert stream_state_unknown is False
        assert capture.byte_count == len(payload)
        assert capture.sha256 == hashlib.sha256(payload).hexdigest()
        assert capture.prefix.startswith(b"late descendant bytes")
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        os.close(write_fd)


def test_supervisor_refuses_mismatched_invocation_before_spawn() -> None:
    authority = _TestAuthority("att_mismatch")
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=[sys.executable, "-c", "print('expected')"],
        expected_environment={},
    )
    with pytest.raises(BackendEvidenceError):
        supervisor.run(
            [sys.executable, "-c", "print('different')"],
            env={},
            cwd=Path.cwd(),
        )
    assert supervisor.process_started is False
    assert authority.launches == []


def test_supervisor_refuses_stale_authority_without_spawning() -> None:
    argv = [sys.executable, "-c", "print('unused')"]
    authority = _TestAuthority("att_stale", current=False)
    supervisor = ProcessSupervisor(
        authority, expected_argv=argv, expected_environment={}
    )
    with pytest.raises(BackendEvidenceError):
        supervisor.run(argv, env={}, cwd=Path.cwd())
    assert supervisor.process_started is False
    assert authority.launches == []


def test_supervisor_run_is_single_use() -> None:
    argv = [sys.executable, "-c", "print('once')"]
    authority = _TestAuthority("att_once")
    supervisor = ProcessSupervisor(
        authority, expected_argv=argv, expected_environment={}
    )
    supervisor.run(argv, env={}, cwd=Path.cwd())
    with pytest.raises(RuntimeError, match="only once"):
        supervisor.run(argv, env={}, cwd=Path.cwd())


def _is_pipe_descriptor(descriptor: int) -> bool:
    """Return whether a descriptor is a pipe, so injected faults stay scoped."""

    try:
        return stat.S_ISFIFO(os.fstat(descriptor).st_mode)
    except OSError:
        return False


def _install_read_failure(
    monkeypatch: pytest.MonkeyPatch, phase: str, failure: Exception
) -> dict[str, object]:
    """Fail the first supervisor pipe read during one drain phase."""

    real_read = os.read
    state: dict[str, object] = {"phase": "idle", "failed": False}

    def failing_read(descriptor: int, length: int) -> bytes:
        if (
            state["phase"] == phase
            and state["failed"] is False
            and _is_pipe_descriptor(descriptor)
        ):
            state["failed"] = True
            raise failure
        return real_read(descriptor, length)

    monkeypatch.setattr(os, "read", failing_read)
    return state


def _observed_record(service: GenerationService, job_id: str) -> dict[str, object]:
    """Return the persisted observation for one job and assert it exists."""

    record = service.get_execution(job_id)
    assert record["state"] == "observed"
    observed = record["observed"]
    assert isinstance(observed, dict)
    return observed


@pytest.mark.parametrize(
    "failure",
    (
        OSError(errno.EIO, "simulated unexpected read failure"),
        OSError(errno.EBADF, "simulated closed descriptor"),
        ValueError("simulated closed stream"),
    ),
    ids=("unexpected-os-error", "closed-descriptor", "closed-stream"),
)
def test_read_error_while_draining_keeps_the_attempt_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """An unreadable pipe is uncertainty, not EOF, so its resource is held."""

    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    state = _install_read_failure(monkeypatch, "drain", failure)
    real_drain = ProcessSupervisor._drain_until_reaped

    def draining_with_phase(self, process, *, stdout_capture, stderr_capture):
        state["phase"] = "drain"
        try:
            return real_drain(
                self,
                process,
                stdout_capture=stdout_capture,
                stderr_capture=stderr_capture,
            )
        finally:
            state["phase"] = "done"

    monkeypatch.setattr(ProcessSupervisor, "_drain_until_reaped", draining_with_phase)

    result = service.submit(
        "drain-read-error", _request(), workload_demand=heavy_workload_demand()
    )

    assert state["failed"] is True
    observed = _observed_record(service, result.job_id)
    assert observed["direct_child_reaped"] is True
    assert observed["stream_state_unknown"] is True
    assert observed["inherited_streams_retained_after_reap"] is False
    provenance = service.get_provenance(result.job_id)
    assert provenance["attempt"]["termination_proven"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


@pytest.mark.parametrize(
    "failure",
    (
        OSError(errno.EIO, "simulated unexpected read failure"),
        OSError(errno.EBADF, "simulated closed descriptor"),
        ValueError("simulated closed stream"),
    ),
    ids=("unexpected-os-error", "closed-descriptor", "closed-stream"),
)
def test_read_error_during_the_post_reap_probe_keeps_the_attempt_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    """A failed probe read cannot be rounded down to a closed stream."""

    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    state = _install_read_failure(monkeypatch, "probe", failure)
    real_probe = ProcessSupervisor._streams_still_open

    def probing_with_phase(streams):
        state["phase"] = "probe"
        try:
            return real_probe(streams)
        finally:
            state["phase"] = "done"

    monkeypatch.setattr(
        ProcessSupervisor, "_streams_still_open", staticmethod(probing_with_phase)
    )

    result = service.submit(
        "probe-read-error", _request(), workload_demand=heavy_workload_demand()
    )

    assert state["failed"] is True
    observed = _observed_record(service, result.job_id)
    assert observed["direct_child_reaped"] is True
    assert observed["stream_state_unknown"] is True
    assert observed["inherited_streams_retained_after_reap"] is False
    provenance = service.get_provenance(result.job_id)
    assert provenance["attempt"]["termination_proven"] is False
    assert service._store.resource_snapshot()["state"] == "quarantined"


def test_detached_descendant_does_not_block_termination_proof(tmp_path: Path) -> None:
    """Reaping and stream observation do not detect a detached descendant.

    The direct child starts a descendant in its own session with stdout and
    stderr redirected away from the inherited pipes, then exits. Supervision
    observes no retained pipe writer, so the attempt reports a reaped child and
    releases the resource while the descendant is still running. The evidence
    is therefore a statement about one direct child and its inherited streams
    only: it never proves that no descendant process exists, and this T08 slice
    does not track, terminate, or recover descendant processes.
    """

    bundle = build_bundle(tmp_path)
    pid_path = tmp_path / "descendant.pid"
    bundle.set_mode(
        behavior="detached_grandchild",
        descendant_pid_path=str(pid_path),
        descendant_sleep_seconds=5,
    )
    service = _service(tmp_path, bundle)

    result = service.submit(
        "detached-descendant", _request(), workload_demand=heavy_workload_demand()
    )

    observed = _observed_record(service, result.job_id)
    assert observed["direct_child_reaped"] is True
    assert observed["inherited_streams_retained_after_reap"] is False
    assert observed["stream_state_unknown"] is False
    assert observed["process_tree_containment"] is False
    provenance = service.get_provenance(result.job_id)
    assert provenance["status"] == "succeeded"
    assert provenance["attempt"]["termination_proven"] is True
    assert service._store.resource_snapshot()["state"] == "available"

    descendant_pid = int(pid_path.read_text(encoding="utf-8"))
    try:
        os.kill(descendant_pid, 0)
    finally:
        try:
            os.kill(descendant_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _without_declared_request(payload: object) -> str:
    """Return evidence JSON without the declared request text.

    The application records the request prompt as submitted job input and
    passes it to the engine in the argument vector on purpose. Those declared
    fields, whose names end in "prompt" or are "argv", are the only places the
    request text belongs; every other part of the evidence must be free of it.
    """

    return json.dumps(_drop_declared_request_keys(json.loads(json.dumps(payload))))


def _drop_declared_request_keys(node: object) -> object:
    """Return a copy of one evidence tree without declared request text."""

    if isinstance(node, dict):
        return {
            key: _drop_declared_request_keys(value)
            for key, value in node.items()
            if key != "argv" and not key.endswith("prompt")
        }
    if isinstance(node, list):
        return [_drop_declared_request_keys(item) for item in node]
    return node


def test_execution_evidence_never_persists_prompt_or_credential(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Subprocess output is described, not stored, so an echo cannot persist secrets.

    The conformance engine echoes the request prompt on stdout and prints a fake
    credential on stderr. The observation keeps byte counts, complete digests,
    and taxonomy codes, so the credential reaches no persisted record, no
    provenance snapshot, no file in the workspace, and no execution command
    output, while the prompt is confined to the declared request fields.
    """

    prompt = "a quiet violet lighthouse"
    credential = "sk-live-CONFORMANCE-0123456789"
    bundle = build_bundle(tmp_path)
    bundle.set_mode(behavior="echo_secrets")
    service = _service(tmp_path, bundle)

    result = service.submit(
        "echo-secrets",
        GenerationRequest(prompt, seed=7, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    )

    record = service.get_execution(result.job_id)
    observed = _observed_record(service, result.job_id)
    assert observed["stdout_bytes"] > 0
    assert observed["stderr_bytes"] > 0
    assert observed["stdout_sha256"] != observed["stderr_sha256"]
    assert "prompt_echo_detected" in observed["stdout_codes"]
    assert "secret_like_material_detected" in observed["stderr_codes"]
    assert not {"stdout_excerpt", "stderr_excerpt"} & set(observed)

    assert prompt not in json.dumps(observed)
    assert credential not in json.dumps(observed)
    assert credential not in json.dumps(record)
    assert prompt not in _without_declared_request(record)

    provenance_record = service.get_provenance(result.job_id)
    provenance = json.dumps(provenance_record)
    assert credential not in provenance
    assert prompt not in _without_declared_request(provenance_record)

    capsys.readouterr()
    assert (
        cli.main(
            [
                "execution",
                "--db",
                str(tmp_path / "studio.sqlite3"),
                "--job-id",
                result.job_id,
            ]
        )
        == 0
    )
    printed = capsys.readouterr().out
    assert credential not in printed
    assert prompt not in _without_declared_request(json.loads(printed))
    assert "stdout_excerpt" not in printed

    evidence_root = tmp_path / "studio.sqlite3"
    persisted = evidence_root.read_bytes() + b"".join(
        item.read_bytes()
        for item in sorted((tmp_path / "images").rglob("*"))
        if item.is_file()
    )
    assert credential.encode("utf-8") not in persisted


def test_output_classification_codes_never_carry_captured_text() -> None:
    """Taxonomy codes describe risk classes without reproducing matched text."""

    prompt = "a quiet violet lighthouse"
    credential = "sk-live-CONFORMANCE-0123456789"
    payload = (
        f"{prompt}\n"
        f"{credential}\n"
        "/home/operator/models/qwen.gguf\n"
        "https://example.invalid/upload\n"
    ).encode("utf-8")

    result = classify_output(
        payload, total_bytes=len(payload), prompt_markers=(prompt,)
    )

    assert result.classification == "utf8"
    assert result.codes == (
        "contains_absolute_path",
        "contains_url",
        "lines_bounded",
        "prompt_echo_detected",
        "secret_like_material_detected",
    )
    rendered = repr(result)
    assert prompt not in rendered
    assert credential not in rendered


def test_output_classification_marks_empty_non_utf8_and_truncated() -> None:
    """Every bounded encoding classification is reachable and validated."""

    assert classify_output(b"", total_bytes=0) == OutputClassification(
        "empty", ("blank",)
    )
    non_utf8 = classify_output(b"\xff\xfe binary", total_bytes=9)
    assert non_utf8.classification == "non_utf8"
    assert "non_utf8" in non_utf8.codes
    truncated = classify_output(b"kept prefix", total_bytes=40)
    assert truncated.classification == "truncated"
    assert "truncated" in truncated.codes
    with pytest.raises(ValueError):
        classify_output(b"text", total_bytes=-1)
    with pytest.raises(ValueError):
        classify_output(b"text", total_bytes=True)
    with pytest.raises(ValueError):
        OutputClassification("unsupported", ("blank",))
    with pytest.raises(ValueError):
        OutputClassification("utf8", ("unknown_code",))


def test_closed_reader_with_live_writer_makes_stream_state_unknown() -> None:
    """A closed reader cannot certify EOF while its write end remains open."""

    from media_generation.supervisor import _PipeCapture

    read_fd, write_fd = os.pipe()
    try:
        stream = os.fdopen(read_fd, "rb", buffering=0)
        read_fd = -1
        stream.close()
        capture = _PipeCapture()
        assert ProcessSupervisor._streams_still_open(((stream, capture),)) == (
            False,
            True,
        )
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        os.close(write_fd)

    read_fd, write_fd = os.pipe()
    try:
        os.close(read_fd)

        class _ClosedDescriptor:
            def fileno(self) -> int:
                return read_fd

        capture = _PipeCapture()
        assert ProcessSupervisor._streams_still_open(
            ((_ClosedDescriptor(), capture),)
        ) == (False, True)
    finally:
        os.close(write_fd)


def test_output_classification_requires_codes_and_marks_long_output() -> None:
    """Classification invariants reject empty code sets and flag many lines."""

    with pytest.raises(ValueError):
        OutputClassification("empty", ())
    payload = chr(10).join(f"line {index}" for index in range(80)).encode("utf-8")
    many_lines = classify_output(payload, total_bytes=len(payload))
    assert many_lines.classification == "utf8"
    assert "many_lines" in many_lines.codes


def test_empty_read_is_genuine_eof_control() -> None:
    """Only an empty read establishes EOF without stream uncertainty."""

    from media_generation.supervisor import _PipeCapture

    read_fd, write_fd = os.pipe()
    try:
        os.close(write_fd)
        write_fd = -1
        os.set_blocking(read_fd, False)
        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            read_fd = -1
            capture = _PipeCapture()
            assert ProcessSupervisor._streams_still_open(((stream, capture),)) == (
                False,
                False,
            )
            assert capture.byte_count == 0
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_selector_registration_failure_closes_selector_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Partial selector registration still uses the outer cleanup path."""

    from media_generation import supervisor as supervisor_module

    pid_path = tmp_path / "selector-child.pid"
    argv = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, time; "
            f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
            "time.sleep(5)"
        ),
    ]
    authority = _TestAuthority("att_selector_registration_failure")

    class _FailingSelector:
        def __init__(self) -> None:
            self.register_calls = 0
            self.closed = 0
            self.active: set[object] = set()
            self.seen_streams: list[object] = []

        def register(self, fileobj, events, data=None) -> None:
            del events, data
            self.register_calls += 1
            self.seen_streams.append(fileobj)
            if self.register_calls == 2:
                deadline = time.monotonic() + 2.0
                while not pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise RuntimeError("second selector registration failed")
            self.active.add(fileobj)

        def close(self) -> None:
            self.closed += 1
            self.active.clear()

        def select(self, timeout=None):
            raise AssertionError(f"select must not be reached ({timeout})")

    selectors_created: list[_FailingSelector] = []

    def make_selector() -> _FailingSelector:
        selector = _FailingSelector()
        selectors_created.append(selector)
        return selector

    monkeypatch.setattr(
        supervisor_module.selectors, "DefaultSelector", make_selector
    )
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    )

    with pytest.raises(RuntimeError, match="second selector registration failed"):
        supervisor.run(argv, env={}, cwd=Path.cwd())

    assert supervisor.process_started is True
    assert authority.observations == []
    assert len(selectors_created) == 1
    selector = selectors_created[0]
    assert selector.register_calls == 2
    assert selector.closed == 1
    assert selector.active == set()
    assert len(selector.seen_streams) == 2
    assert all(stream.closed for stream in selector.seen_streams)

    child_pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_selector_construction_failure_reaps_child_and_closes_pipes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A selector construction failure still uses the outer cleanup path."""

    from media_generation import supervisor as supervisor_module

    pid_path = tmp_path / "selector-construction-child.pid"
    argv = [
        sys.executable,
        "-c",
        (
            "import os, pathlib, time; "
            f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); "
            "time.sleep(5)"
        ),
    ]
    authority = _TestAuthority("att_selector_construction_failure")
    constructor_calls = 0

    def fail_selector_construction():
        nonlocal constructor_calls
        constructor_calls += 1
        deadline = time.monotonic() + 2.0
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        raise RuntimeError("selector construction failed")

    terminated: list[object] = []
    pipes_closed_before_outer_cleanup: list[tuple[bool, bool]] = []
    real_terminate = ProcessSupervisor._terminate_after_drain_failure

    def recording_terminate(process) -> None:
        terminated.append(process)
        assert process.stdout is not None
        assert process.stderr is not None
        pipes_closed_before_outer_cleanup.append(
            (process.stdout.closed, process.stderr.closed)
        )
        real_terminate(process)

    monkeypatch.setattr(
        supervisor_module.selectors,
        "DefaultSelector",
        fail_selector_construction,
    )
    monkeypatch.setattr(
        ProcessSupervisor,
        "_terminate_after_drain_failure",
        staticmethod(recording_terminate),
    )
    supervisor = ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    )

    with pytest.raises(RuntimeError, match="selector construction failed"):
        supervisor.run(argv, env={}, cwd=Path.cwd())

    assert constructor_calls == 1
    assert supervisor.process_started is True
    assert authority.observations == []
    assert len(terminated) == 1
    assert pipes_closed_before_outer_cleanup == [(True, True)]
    process = terminated[0]
    assert process.returncode is not None
    assert process.stdout is not None
    assert process.stderr is not None
    assert process.stdout.closed is True
    assert process.stderr.closed is True

    child_pid = int(pid_path.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
