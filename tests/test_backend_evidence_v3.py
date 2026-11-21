"""Versioned resolved evidence while preserving schema-6 launch semantics."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import backend_provenance, comfyui, comfyui_runtime_pins, engine
from media_generation.backend_provenance import (
    RECORD_SCHEMA_VERSION,
    RESOLVED_RECORD_SCHEMA_VERSION,
    backend_digest,
    canonical_json,
    digest,
)
from media_generation.domain import GenerationRequest
from media_generation.errors import BackendEvidenceError, PrivacyComplianceError
from media_generation.privacy import (
    COMFYUI_ADAPTER_ID,
    COMFYUI_CONFIGURATION_VERSION,
    COMFYUI_SAFE_ENVIRONMENT_NAMES,
    PrivacyControl,
    PrivacyComplianceStatus,
    comfyui_invocation_privacy_settings,
)
from media_generation.service import GenerationService, _now
from media_generation.comfyui import ComfyUIAdapter
from media_generation.store import _STATIC_TRIGGER_DDL
from media_generation.supervisor import ProcessSupervisor

from test_backend_evidence import (
    _insert_resolved,
    _launch,
    _observed,
    _plan,
    _raw_connection,
    _request,
    _service,
    _TestAuthority,
)
from test_engine_adapter import RUNTIME
from test_comfyui_adapter import _rgb_png
from media_generation.service import _lease_deadline
from test_t08_support import build_bundle, heavy_admission_profile, heavy_workload_demand
from test_t09_support import (
    SYNTHETIC_COMFYUI_TOOL_VERSION,
    allow_synthetic_runtime_for_tests,
    build_comfyui_bundle,
    synthetic_runtime_approval_for_tests,
    synthetic_child_environment_for_tests,
)


@pytest.fixture(autouse=True)
def _synthetic_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "capture_runtime_fingerprint", lambda: dict(RUNTIME))
    approval = synthetic_runtime_approval_for_tests()

    def load_synthetic_approval(*, verify_paths: bool = True) -> SimpleNamespace:
        assert verify_paths in {True, False}
        return approval

    monkeypatch.setattr(
        comfyui,
        "_require_independent_runtime_pin_binding",
        allow_synthetic_runtime_for_tests,
    )
    monkeypatch.setattr(
        comfyui,
        "_require_runtime_launch_binding",
        allow_synthetic_runtime_for_tests,
    )
    monkeypatch.setattr(
        comfyui,
        "_bind_child_node_implementations",
        lambda *_launch_inputs: None,
    )
    monkeypatch.setattr(
        comfyui,
        "_child_environment",
        synthetic_child_environment_for_tests,
    )
    monkeypatch.setattr(comfyui, "_load_runtime_pin_approval", load_synthetic_approval)
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "load_runtime_pin_approval",
        load_synthetic_approval,
    )


def test_v3_valid_matching_record_reaches_predispatch_privacy_recomputation(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-valid-predispatch",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_valid_predispatch")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _legacy_v3_record(dict(prepared.resolved_record), claim.attempt_id)

    try:
        assert "privacy_evidence" not in record
        service._require_execution_privacy(
            replace(prepared, resolved_record=record)
        )
    finally:
        service.adapter.cleanup_execution(prepared)


def test_v3_stale_matching_record_is_refused_before_dispatch(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-stale-predispatch",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_stale_predispatch")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _legacy_v3_record(dict(prepared.resolved_record), claim.attempt_id)
    privacy = record["privacy"]
    assert isinstance(privacy, dict)
    privacy[PrivacyControl.TELEMETRY.value] = True

    try:
        with pytest.raises(PrivacyComplianceError) as refused:
            service._require_execution_privacy(
                replace(prepared, resolved_record=record)
            )
        assert "resolved_privacy_mismatch" in refused.value.result.reason_codes
    finally:
        service.adapter.cleanup_execution(prepared)


def test_v3_unsafe_synchronized_record_is_refused_before_dispatch(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-unsafe-predispatch",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_unsafe_predispatch")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _legacy_v3_record(dict(prepared.resolved_record), claim.attempt_id)
    effective = record["effective_execution"]
    assert isinstance(effective, dict)
    node_class, pin = next(iter(effective["configuration"]["nodes"].items()))
    pin["inputs"].append("telemetry")
    node = next(
        node
        for node in effective["graph"].values()
        if node["class_type"] == node_class
    )
    node["inputs"]["telemetry"] = True
    effective["request_body"]["prompt"] = effective["graph"]
    record["privacy"] = comfyui_invocation_privacy_settings(
        prepared.argv, prepared.environment, effective
    )

    try:
        with pytest.raises(PrivacyComplianceError) as refused:
            service._require_execution_privacy(
                replace(prepared, resolved_record=record)
            )
        assert refused.value.result.status is not PrivacyComplianceStatus.PASS
        assert "setting_value_unrecognized" in refused.value.result.reason_codes
    finally:
        service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("adapter_id", "declaration", "expected"),
    [
        (engine.ADAPTER_ID, None, False),
        (
            engine.ADAPTER_ID,
            {
                "schema": backend_provenance.RESOURCE_RELEASE_DECLARATION_SCHEMA,
                "schema_version": (
                    backend_provenance.RESOURCE_RELEASE_DECLARATION_VERSION
                ),
                "required_scope": (
                    backend_provenance.DIRECT_CHILD_RESOURCE_RELEASE_SCOPE
                ),
            },
            False,
        ),
        (
            engine.ADAPTER_ID,
            {
                "schema": backend_provenance.RESOURCE_RELEASE_DECLARATION_SCHEMA,
                "schema_version": (
                    backend_provenance.RESOURCE_RELEASE_DECLARATION_VERSION
                ),
                "required_scope": (
                    backend_provenance.PROCESS_TREE_RESOURCE_RELEASE_SCOPE
                ),
            },
            True,
        ),
        (COMFYUI_ADAPTER_ID, None, True),
        (
            COMFYUI_ADAPTER_ID,
            {
                "schema": backend_provenance.RESOURCE_RELEASE_DECLARATION_SCHEMA,
                "schema_version": (
                    backend_provenance.RESOURCE_RELEASE_DECLARATION_VERSION
                ),
                "required_scope": (
                    backend_provenance.DIRECT_CHILD_RESOURCE_RELEASE_SCOPE
                ),
            },
            True,
        ),
        (COMFYUI_ADAPTER_ID, "not-an-object", True),
        (engine.ADAPTER_ID, {"schema": "unsupported"}, True),
        (engine.ADAPTER_ID, "not-an-object", True),
        ("", None, True),
    ],
)
def test_resource_release_declaration_fails_closed(
    adapter_id: str,
    declaration: object,
    expected: bool,
) -> None:
    configuration: dict[str, object] = {}
    if declaration is not None:
        configuration[backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY] = declaration

    assert (
        backend_provenance.configuration_requires_process_tree_resource_release(
            configuration,
            adapter_id=adapter_id,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("declaration", "case"),
    (
        (None, "missing"),
        ("not-an-object", "malformed"),
        (
            {
                backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY: {
                    "schema": "unsupported"
                }
            },
            "unsupported",
        ),
        (
            {
                "schema": backend_provenance.RESOURCE_RELEASE_DECLARATION_SCHEMA,
                "schema_version": (
                    backend_provenance.RESOURCE_RELEASE_DECLARATION_VERSION
                ),
                "required_scope": (
                    backend_provenance.DIRECT_CHILD_RESOURCE_RELEASE_SCOPE
                ),
            },
            "direct-child",
        ),
    ),
    ids=("missing", "malformed", "unsupported", "direct-child"),
)
def test_comfyui_release_policy_fails_closed_for_untrusted_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declaration: object,
    case: str,
) -> None:
    """ComfyUI quarantine follows durable adapter identity, not its config."""
    original_configuration = ComfyUIAdapter.configuration.fget
    assert original_configuration is not None

    def altered_configuration(adapter: ComfyUIAdapter) -> dict[str, object]:
        configuration = dict(original_configuration(adapter))
        if declaration is None:
            configuration.pop(
                backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY,
                None,
            )
        elif case == "unsupported":
            configuration[backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY] = (
                declaration[backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY]
            )
        else:
            configuration[backend_provenance.RESOURCE_RELEASE_DECLARATION_KEY] = (
                declaration
            )
        return configuration

    monkeypatch.setattr(
        ComfyUIAdapter,
        "configuration",
        property(altered_configuration),
    )
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        f"comfyui-release-{case}",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    assert service.work()["processed"] == 1

    provenance = service.get_provenance(job_id)
    execution = service.get_execution(job_id)
    resource = service._store.resource_snapshot()
    listener_marker = bundle.files / "listener-bound.json"
    listener_bind_error = bundle.files / "listener-bind-error.json"
    listener_pre_bind = bundle.files / "listener-pre-bind.json"
    observed = execution["observed"]
    listener_bound = (
        listener_marker.read_text(encoding="utf-8") if listener_marker.exists() else None
    )
    bind_error = (
        listener_bind_error.read_text(encoding="utf-8")
        if listener_bind_error.exists()
        else None
    )
    child_exit_code = observed.get("exit_code") if observed else None
    child_signal = observed.get("signal") if observed else None
    child_stderr_bytes = observed.get("stderr_bytes") if observed else None
    child_duration_seconds = observed.get("duration_seconds") if observed else None
    diagnostics = (
        f"failure={provenance['execution']['failure_message']}; "
        f"state={execution['state']}; launch_recorded={execution['launch'] is not None}; "
        f"exit_code={child_exit_code}; signal={child_signal}; "
        f"duration={child_duration_seconds}; stderr_bytes={child_stderr_bytes}; "
        f"pre_bind={'present' if listener_pre_bind.exists() else 'absent'}; "
        f"listener_bound={listener_bound}; listener_bind_error={bind_error}"
    )
    assert provenance["status"] == "succeeded", diagnostics
    assert listener_marker.is_file()
    assert provenance["attempt"]["termination_proven"] is False
    assert execution["observed"]["direct_child_reaped"] is True
    assert execution["observed"]["process_tree_containment"] is False
    assert resource["state"] == "quarantined"
    assert "process-tree" in resource["reason"]


def test_release_policy_requires_admitted_and_attempt_adapter_identity_to_agree(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    queued = service.enqueue(
        "comfyui-release-identity",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    claim = _claim(service, queued.job_id, "att_comfyui_release_identity")
    connection = _raw_connection(tmp_path / "studio.sqlite3")
    try:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE generation_attempts SET adapter_id = ? "
            "WHERE attempt_id = ?",
            (engine.ADAPTER_ID, claim.attempt_id),
        )
        connection.commit()
        assert service._store._attempt_requires_process_tree_resource_release(
            connection,
            claim.job_id,
            claim.attempt_id,
        )
    finally:
        connection.close()


def test_legacy_containment_contract_cannot_bypass_comfyui_release_policy(
    tmp_path: Path,
) -> None:
    """A stale direct-child contract cannot release ComfyUI capacity."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    queued = service.enqueue(
        "comfyui-legacy-containment",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    claim = _claim(service, queued.job_id, "att_comfyui_legacy_containment")
    connection = _raw_connection(tmp_path / "studio.sqlite3")
    try:
        connection.row_factory = sqlite3.Row
        assert not service._store._resource_release_proven(
            connection,
            claim.job_id,
            claim.attempt_id,
            containment_contract="legacy-direct-child",
            effective_termination_proven=True,
            direct_child_termination_proven=False,
        )
    finally:
        connection.close()


@pytest.mark.parametrize("canceled", (False, True))
def test_comfyui_recovery_reports_attention_after_direct_child_observation(
    tmp_path: Path,
    canceled: bool,
) -> None:
    """Recovering ComfyUI work cannot report a reusable T06 resource."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        f"comfyui-recovery-{canceled}",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, f"att_comfyui_recovery_{canceled}")
    prepared = service.adapter.resolve_execution(_plan(claim))
    _insert_resolved(service, claim, prepared)
    assert service._store.mark_execution_launched(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        record=_launch(prepared),
        timestamp=_now(),
    ) is None
    assert service._store.mark_execution_observed(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        record=_observed(claim.attempt_id),
        timestamp=_now(),
    ) is None
    if canceled:
        assert service.cancel(job_id)["outcome"] == "requested"

    report = service.recover()

    assert report["status"] == "attention_required"
    assert report["resource_state"] == "quarantined"
    assert "process-tree" in report["resource_reason"]
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == ("canceled" if canceled else "failed")
    assert provenance["attempt"]["termination_proven"] is False
    execution = service.get_execution(job_id)
    assert execution["observed"]["direct_child_reaped"] is True
    assert execution["observed"]["process_tree_containment"] is False
    assert provenance["execution"]["resource_state"] == "quarantined"
    if not canceled:
        assert provenance["execution"]["failure_message"] == (
            "worker process ended after adapter termination evidence was validated"
        )
    resource = service._store.resource_snapshot()
    assert resource["state"] == "quarantined"
    assert "process-tree" in resource["reason"]
    assert provenance["execution"]["resource_reason"] == resource["reason"]


def test_stale_contract_cannot_create_comfyui_termination_in_failure_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persisted adapter policy outranks a stale failure-time contract."""
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "comfyui-stale-contract-failure",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    execute_calls: list[str] = []

    def fail_after_stale_contract(plan, _stream, *, supervisor):
        del supervisor
        execute_calls.append(plan.attempt_id)
        connection = _raw_connection(tmp_path / "studio.sqlite3")
        try:
            connection.execute(
                """UPDATE execution_attempts
                   SET process_contained = 1, containment_contract = ?
                   WHERE attempt_id = ?""",
                ("legacy-direct-child", plan.attempt_id),
            )
            connection.commit()
        finally:
            connection.close()
        raise RuntimeError("injected execution failure")

    monkeypatch.setattr(service.adapter, "execute", fail_after_stale_contract)
    monkeypatch.setattr(
        ProcessSupervisor,
        "process_started",
        property(lambda _supervisor: True),
    )
    report = service.work()

    assert execute_calls == [service.get_provenance(job_id)["attempt"]["attempt_id"]]
    assert report["status"] == "attention_required"
    provenance = service.get_provenance(job_id)
    assert provenance["status"] == "ambiguous"
    assert provenance["attempt"]["termination_proven"] is False
    assert provenance["execution"]["resource_state"] == "quarantined"
    resource = service._store.resource_snapshot()
    assert resource["state"] == "quarantined"
    assert "process-tree" in resource["reason"]
    assert not (bundle.files / "prompt-count.txt").exists()


def _comfy_service(tmp_path: Path, bundle) -> GenerationService:
    output = tmp_path / "images"
    return GenerationService(
        tmp_path / "studio.sqlite3",
        output,
        adapter=ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=output,
        ),
        admission_profile=heavy_admission_profile(),
    )


def _v3_record(
    resolved_record: dict[str, object], attempt_id: str
) -> dict[str, object]:
    """Copy one adapter-resolved v3 record for a persistence test.

    The caller must provide the exact record returned by
    ``ComfyUIAdapter.resolve_execution``. This helper intentionally does not
    convert v2 records because an effective ComfyUI graph cannot be inferred
    from launch-only evidence.
    """
    record = json.loads(canonical_json(resolved_record))
    version = record.get("schema_version")
    assert type(version) is int and version == RESOLVED_RECORD_SCHEMA_VERSION
    assert record.get("attempt_id") == attempt_id
    _bind_explicit_node_classes(record)
    return record


def _legacy_v3_record(
    resolved_record: dict[str, object], attempt_id: str
) -> dict[str, object]:
    """Return a historical ComfyUI resolved v3 record without v4 evidence."""
    record = _v3_record(resolved_record, attempt_id)
    if record.get("schema_version") != RESOLVED_RECORD_SCHEMA_VERSION:
        raise AssertionError("adapter did not return the current resolved record")
    record["schema_version"] = 3
    record.pop("privacy_evidence", None)
    return record


def _rehash_privacy_evidence(record: dict[str, object]) -> None:
    evidence = record["privacy_evidence"]
    assert isinstance(evidence, dict)
    payload = {key: value for key, value in evidence.items() if key != "fingerprint"}
    evidence["fingerprint"] = digest(payload)


def _rehash_effective(record: dict[str, object]) -> None:
    effective = record["effective_execution"]
    graph = effective["graph"]
    configuration = effective["configuration"]
    body = effective["request_body"]
    body["prompt"] = graph
    effective["graph_sha256"] = digest(graph)
    effective["configuration_sha256"] = digest(configuration)
    effective["request_body_sha256"] = digest(body)


def _mutate_reference_latents_method(record: dict[str, object]) -> None:
    effective = record["effective_execution"]
    workflow = effective["configuration"]["workflow"]  # type: ignore[index]
    for graph in (effective["graph"], workflow["template"]):  # type: ignore[index]
        for node in graph.values():  # type: ignore[union-attr]
            if node.get("class_type") == "FluxKontextMultiReferenceLatentMethod":
                node["inputs"]["reference_latents_method"] = "index_timestep_one"
    template_sha256 = digest(workflow["template"])
    workflow["template_sha256"] = template_sha256
    approval = workflow["approval"]
    operation = workflow["operation"]
    document = approval["document"]
    document["operations"][operation]["graph_sha256"] = template_sha256
    encoded = (canonical_json(document) + "\n").encode("utf-8")
    approval["document_size_bytes"] = len(encoded)
    approval["document_sha256"] = hashlib.sha256(encoded).hexdigest()


def _set_resolved_environment(
    record: dict[str, object], name: str, value: str
) -> None:
    environment = record["environment"]
    effective_environment = record["effective_execution"]["configuration"]["server"][
        "environment"
    ]
    values = {name: value}
    environment["names"] = sorted(values)
    environment["values"] = values
    effective_environment.clear()
    effective_environment.update(values)
    _rehash_effective(record)


def _bind_explicit_node_classes(record: dict[str, object]) -> None:
    effective = record["effective_execution"]
    for class_name, pin in effective["configuration"]["nodes"].items():
        pin["class"] = class_name
    _rehash_effective(record)


def _mutate_remote_launch_executable(record: dict[str, object]) -> None:
    effective = record["effective_execution"]
    configuration = effective["configuration"]
    remote = "https://unapproved.invalid/comfyui"
    record["argv"][0] = remote
    configuration["engine"]["executable_path"] = remote
    configuration["server"]["argv"][0] = remote


def _mutate_secret_environment(record: dict[str, object]) -> None:
    effective = record["effective_execution"]
    environment = record["environment"]
    config_environment = effective["configuration"]["server"]["environment"]
    name = "AWS_SECRET_ACCESS_KEY"
    environment["names"].append(name)
    environment["values"][name] = "synthetic-secret-value"
    config_environment[name] = "synthetic-secret-value"


def _finalize(service: GenerationService, claim, prepared) -> None:
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
    assert service._store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "test settlement",
        _now(),
        attempt_owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        failure_class="terminal",
        termination_proven=True,
    )


def _claim(service: GenerationService, job_id: str, attempt_id: str):
    _, configuration_json, _, privacy_json = service._current_privacy_snapshot()
    claim = service._store.claim_next_execution(
        attempt_id=attempt_id,
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


def test_v2_and_v3_records_share_schema_nine_and_survive_restart(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "v2")
    service = _service(tmp_path, bundle)

    v2_job = service.enqueue(
        "v2-record", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    v2_claim = _claim(service, v2_job, "att_v2_record")
    v2_prepared = service.adapter.resolve_execution(_plan(v2_claim))
    _insert_resolved(service, v2_claim, v2_prepared)
    _finalize(service, v2_claim, v2_prepared)

    comfy_bundle = build_comfyui_bundle(tmp_path / "v3")
    comfy_service = _comfy_service(tmp_path, comfy_bundle)
    v3_job = comfy_service.enqueue(
        "v3-record",
        GenerationRequest("a blue cube", seed=9, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    ).job_id
    v3_claim = _claim(comfy_service, v3_job, "att_v3_record")
    v3_prepared = comfy_service.adapter.resolve_execution(_plan(v3_claim))
    v3_record = _v3_record(dict(v3_prepared.resolved_record), v3_claim.attempt_id)
    v3_record["prompt"] = v3_claim.resolved_prompt
    v3_record["seed"] = v3_claim.resolved_seed
    v3_record["conditioning"] = []
    comfy_service._store.insert_resolved_execution(
        job_id=v3_claim.job_id,
        attempt_id=v3_claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=v3_claim.claim_epoch,
        record=v3_record,
        timestamp=_now(),
    )
    _finalize(comfy_service, v3_claim, v3_prepared)

    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        v2_bytes = connection.execute(
            "SELECT resolved_json FROM backend_executions WHERE attempt_id = ?",
            (v2_claim.attempt_id,),
        ).fetchone()[0]
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 9

    restarted = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images")
    v2 = restarted.get_execution(v2_job)
    v3 = restarted.get_execution(v3_job)
    assert v2["resolved"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["resolved"]["schema_version"] == RESOLVED_RECORD_SCHEMA_VERSION
    assert v2["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v2["observed"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["observed"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["resolved"]["effective_execution"]["request_body"] == v3[
        "resolved"
    ]["effective_execution"]["request_body"]
    with sqlite3.connect(tmp_path / "studio.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT resolved_json FROM backend_executions WHERE attempt_id = ?",
                (v2_claim.attempt_id,),
            ).fetchone()[0]
            == v2_bytes
        )

    service.adapter.cleanup_execution(v2_prepared)
    comfy_service.adapter.cleanup_execution(v3_prepared)


def test_v2_v3_v4_records_share_schema_nine_and_survive_restart(
    tmp_path: Path,
) -> None:
    v2_root = tmp_path / "v2"
    v2_bundle = build_bundle(v2_root / "bundle")
    service = _service(v2_root, v2_bundle)
    v2_job = service.enqueue(
        "v2-record", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    v2_claim = _claim(service, v2_job, "att_v2_record")
    v2_prepared = service.adapter.resolve_execution(_plan(v2_claim))
    _insert_resolved(service, v2_claim, v2_prepared)
    _finalize(service, v2_claim, v2_prepared)

    legacy_root = tmp_path / "v3"
    comfy_bundle = build_comfyui_bundle(legacy_root / "bundle")
    comfy_service = _comfy_service(legacy_root, comfy_bundle)
    legacy_job = comfy_service.enqueue(
        "v3-record",
        GenerationRequest("a blue cube", seed=9, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    ).job_id
    legacy_claim = _claim(comfy_service, legacy_job, "att_v3_record")
    legacy_prepared = comfy_service.adapter.resolve_execution(_plan(legacy_claim))
    legacy_record = _legacy_v3_record(
        dict(legacy_prepared.resolved_record), legacy_claim.attempt_id
    )
    legacy_record["prompt"] = legacy_claim.resolved_prompt
    legacy_record["seed"] = legacy_claim.resolved_seed
    legacy_record["conditioning"] = []
    comfy_service._store.insert_resolved_execution(
        job_id=legacy_claim.job_id,
        attempt_id=legacy_claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=legacy_claim.claim_epoch,
        record=legacy_record,
        timestamp=_now(),
    )
    _finalize(comfy_service, legacy_claim, legacy_prepared)

    current_root = tmp_path / "v4"
    current_bundle = build_comfyui_bundle(current_root / "bundle")
    current_service = _comfy_service(current_root, current_bundle)
    current_job = current_service.enqueue(
        "v4-record",
        GenerationRequest("a green cube", seed=10, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    ).job_id
    current_claim = _claim(current_service, current_job, "att_v4_record")
    current_prepared = current_service.adapter.resolve_execution(_plan(current_claim))
    current_record = _v3_record(
        dict(current_prepared.resolved_record), current_claim.attempt_id
    )
    current_record["prompt"] = current_claim.resolved_prompt
    current_record["seed"] = current_claim.resolved_seed
    current_record["conditioning"] = []
    current_service._store.insert_resolved_execution(
        job_id=current_claim.job_id,
        attempt_id=current_claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=current_claim.claim_epoch,
        record=current_record,
        timestamp=_now(),
    )
    _finalize(current_service, current_claim, current_prepared)

    assert RESOLVED_RECORD_SCHEMA_VERSION == 4
    guard = current_prepared.resolved_record["privacy_evidence"]
    assert isinstance(guard, dict)
    assert guard["status"] == "pass"
    assert guard["evidence_source"] == "application-owned-profile+effective-configuration"
    assert guard["effective_configuration_sha256"] == digest(
        current_prepared.resolved_record["effective_execution"]["configuration"]
    )
    assert "do-not-emit-this-secret" not in canonical_json(guard)

    for root in (v2_root, legacy_root, current_root):
        with sqlite3.connect(root / "studio.sqlite3") as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 9

    restarted = GenerationService(
        v2_root / "studio.sqlite3", v2_root / "images"
    )
    legacy_restarted = GenerationService(
        legacy_root / "studio.sqlite3", legacy_root / "images"
    )
    current_restarted = GenerationService(
        current_root / "studio.sqlite3", current_root / "images"
    )
    v2 = restarted.get_execution(v2_job)
    v3 = legacy_restarted.get_execution(legacy_job)
    v4 = current_restarted.get_execution(current_job)
    assert v2["resolved"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["resolved"]["schema_version"] == 3
    assert v4["resolved"]["schema_version"] == 4
    assert "privacy_evidence" not in v3["resolved"]
    assert v4["resolved"]["privacy_evidence"]["schema_version"] == 1
    assert v2["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v4["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v2["observed"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v3["observed"]["schema_version"] == RECORD_SCHEMA_VERSION
    assert v4["observed"]["schema_version"] == RECORD_SCHEMA_VERSION

    service.adapter.cleanup_execution(v2_prepared)
    comfy_service.adapter.cleanup_execution(legacy_prepared)
    current_service.adapter.cleanup_execution(current_prepared)


@pytest.mark.parametrize(
    "mutation",
    (
        "configuration_digest",
        "profile_id",
        "profile_version",
        "profile_fingerprint",
        "adapter_id",
        "engine_id",
        "engine_version",
        "configuration_version",
        "evidence_source",
        "reason_code",
    ),
)
def test_v4_privacy_evidence_tampering_fails_closed(
    tmp_path: Path, mutation: str
) -> None:
    comfy_bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, comfy_bundle)
    job = service.enqueue(
        "v4-tamper",
        GenerationRequest("a blue cube", seed=9, width=64, height=64),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job, "att_v4_tamper")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    evidence = record["privacy_evidence"]
    assert isinstance(evidence, dict)
    replacement = {
        "profile_id": "caller-selected-profile",
        "profile_version": 999,
        "profile_fingerprint": "0" * 64,
        "adapter_id": "caller-selected-adapter",
        "engine_id": "caller-selected-engine",
        "engine_version": "caller-selected-version",
        "configuration_version": "caller-selected-configuration",
        "evidence_source": "caller-claimed-policy",
    }
    if mutation == "configuration_digest":
        evidence["effective_configuration_sha256"] = "0" * 64
    elif mutation == "reason_code":
        evidence["reasons"].append("caller_selected_reason")
    else:
        evidence[mutation] = replacement[mutation]
    _rehash_privacy_evidence(record)

    with pytest.raises(BackendEvidenceError):
        service._store.insert_resolved_execution(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id="owner_manual",
            claim_epoch=claim.claim_epoch,
            record=record,
            timestamp=_now(),
        )
    service.adapter.cleanup_execution(prepared)


def test_managed_supervisor_reaps_direct_child_and_keeps_record_v2() -> None:
    argv = [sys.executable, "-c", "import time; time.sleep(30)"]
    authority = _TestAuthority("managed-attempt")
    supervisor = __import__(
        "media_generation.supervisor", fromlist=["ProcessSupervisor"]
    ).ProcessSupervisor(
        authority,
        expected_argv=argv,
        expected_environment={},
        drain_timeout_seconds=0.2,
    )

    def session(control) -> str:
        assert control.is_running()
        assert control.pid > 0
        control.require_current()
        return "completed"

    result, observation = supervisor.run_managed(
        argv,
        env={},
        cwd=Path.cwd(),
        session=session,
        shutdown_timeout_seconds=1.0,
    )
    assert result == "completed"
    assert observation.signal is not None
    assert observation.to_mapping()["schema_version"] == RECORD_SCHEMA_VERSION
    assert authority.launches[0].to_mapping()["schema_version"] == RECORD_SCHEMA_VERSION
    assert authority.observations == [observation]


def test_drain_thread_start_failure_reaps_child_and_keeps_schema6_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "drain-thread-start-failure",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    children = []
    original_spawn = comfyui.ProcessSupervisor._spawn_and_record_launch
    original_start = threading.Thread.start

    def capture_child(supervisor, argv, environment, cwd):
        process = original_spawn(supervisor, argv, environment, cwd)
        children.append(process)
        return process

    def fail_drain_thread(thread: threading.Thread) -> None:
        if thread.name.startswith("managed-process-drain-"):
            raise RuntimeError("injected drain thread startup failure")
        original_start(thread)

    monkeypatch.setattr(
        comfyui.ProcessSupervisor, "_spawn_and_record_launch", capture_child
    )
    monkeypatch.setattr(threading.Thread, "start", fail_drain_thread)

    try:
        report = service.work()

        assert report["processed"] == 1
        execution = service.get_execution(job_id)
        assert execution["state"] == "launched"
        assert execution["launch"] is not None
        assert execution["launch"]["schema_version"] == RECORD_SCHEMA_VERSION
        assert execution["observed"] is None
        assert service._store.resource_snapshot()["state"] == "quarantined"
        assert len(children) == 1
        assert children[0].poll() is not None
        assert children[0].wait(timeout=0) == children[0].returncode
    finally:
        for process in children:
            if process.poll() is None:
                process.kill()
                process.wait()


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda record: record["effective_execution"]["graph"]["1"]["inputs"].__setitem__(
                "steps", 9
            ),
            "unsupported shape",
        ),
        (lambda record: record.__setitem__("schema_version", 99), "unsupported schema"),
        (
            lambda record: record["effective_execution"]["request_body"].__setitem__(
                "prompt_id", str(uuid.uuid4())
            ),
            "request identity",
        ),
    ],
)
def test_v3_tampering_and_unsupported_versions_fail_closed(
    tmp_path: Path, mutator, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-tamper", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    claim = _claim(service, job_id, "att_v3_tamper")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    service._store.insert_resolved_execution(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=record,
        timestamp=_now(),
    )
    mutated = json.loads(canonical_json(record))
    mutator(mutated)
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        connection.execute(
            "UPDATE backend_executions SET resolved_json = ?, resolved_digest = ? "
            "WHERE attempt_id = ?",
            (canonical_json(mutated), backend_digest(mutated), claim.attempt_id),
        )
        connection.execute(
            _STATIC_TRIGGER_DDL["backend_executions_stage_transition"]
        )
    with pytest.raises(BackendEvidenceError, match=reason):
        service.get_execution(job_id)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda record: record["effective_execution"]["graph"]["1"].__setitem__(
                "class_type", "UntrustedNode"
            ),
            "not permitted",
        ),
        (
            lambda record: record["effective_execution"]["graph"]["4"]["inputs"].__setitem__(
                "text", "https://example.invalid/prompt"
            ),
            "remote or data URI",
        ),
        (
            lambda record: record["effective_execution"]["graph"]["4"]["inputs"].__setitem__(
                "text", "api_key=synthetic-secret-value"
            ),
            "credential-like",
        ),
        (
            lambda record: record["effective_execution"]["graph"]["4"]["inputs"].__setitem__(
                "text", "data:image/png;base64,AAAA"
            ),
            "remote or data URI",
        ),
    ],
)
def test_v3_rejects_self_consistent_unsafe_graphs_after_digest_recomputation(
    tmp_path: Path, mutator, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-self-consistent-tamper", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    claim = _claim(service, job_id, "att_v3_self_consistent")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    mutator(record)
    _rehash_effective(record)
    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_rejects_self_consistent_nonzero_reference_latent_policy(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, profile_version=2)
    service = _comfy_service(tmp_path, bundle)
    (tmp_path / "reference.png").write_bytes(_rgb_png(64, 64))
    reference = service.import_image(tmp_path, "reference.png")
    job_id = service.enqueue(
        "v3-reference-policy-tamper",
        GenerationRequest(
            "a red cube",
            seed=7,
            width=64,
            height=64,
            reference_ids=(reference.artifact_id,),
            reference_roles=("reference",),
        ),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_reference_policy")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    _mutate_reference_latents_method(record)
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="reference-latent method"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            _mutate_remote_launch_executable,
            "executable",
        ),
        (
            _mutate_secret_environment,
            "environment",
        ),
    ],
)
def test_v3_launch_is_cross_bound_to_effective_configuration_after_rehash(
    tmp_path: Path, mutator, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-hostile-launch", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    claim = _claim(service, job_id, "att_v3_hostile_launch")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    mutator(record)
    record["environment"]["names"].sort()
    _rehash_effective(record)
    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda record: record["components"].append(
                dict(record["components"][0])
            ),
            "duplicate",
        ),
        (
            lambda record: (
                record["components"][1].__setitem__(
                    "id", record["components"][0]["id"]
                ),
                next(
                    item
                    for item in record["effective_execution"]["configuration"][
                        "model_files"
                    ]
                    if item["role"] == record["components"][1]["role"]
                ).__setitem__("component_id", record["components"][0]["id"]),
            ),
            "duplicate",
        ),
        (
            lambda record: record["components"].append(
                {
                    **next(
                        item for item in record["components"] if item["role"] == "other"
                    ),
                    "id": "unexpected-extra-node-bundle",
                }
            ),
            "component",
        ),
        (
            lambda record: record["components"].append(
                {
                    "id": "unexpected-vision-encoder",
                    "role": "vision_encoder",
                    "sha256": "9" * 64,
                    "precision": "unknown",
                    "quantization": "unknown",
                }
            ),
            "role",
        ),
        (
            lambda record: record["effective_execution"]["configuration"][
                "model_files"
            ][0].__setitem__("sha256", "9" * 64),
            "model file",
        ),
    ],
)
def test_v3_rejects_duplicate_or_unexpected_component_pins_after_rehash(
    tmp_path: Path, mutator, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-hostile-components", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    claim = _claim(service, job_id, "att_v3_hostile_components")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    mutator(record)
    record["effective_execution"]["configuration"]["components"] = json.loads(
        canonical_json(record["components"])
    )
    _rehash_effective(record)
    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_rejects_self_consistent_prompt_mismatch(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-prompt-mismatch", _request(), workload_demand=heavy_workload_demand()
    ).job_id
    claim = _claim(service, job_id, "att_v3_prompt_mismatch")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    record["effective_execution"]["graph"]["4"]["inputs"]["text"] = "changed prompt"
    _rehash_effective(record)
    with pytest.raises(BackendEvidenceError, match="resolved prompt"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("location", "width", "height", "reason"),
    [
        ("resolved", 100, 64, "dimension multiple"),
        ("resolved", 65, 64, "dimension multiple"),
        ("resolved", 100_000, 100_000, "maximum dimension"),
        ("resolved", 56, 64, "at least 64"),
        ("resolved", 2056, 64, "maximum dimension"),
        ("graph", 100, 64, "dimension multiple"),
        ("graph", 65, 64, "dimension multiple"),
        ("graph", 100_000, 100_000, "maximum dimension"),
        ("graph", 56, 64, "at least 64"),
        ("graph", 2056, 64, "maximum dimension"),
    ],
)
def test_v3_rejects_self_consistent_dimensions_outside_adapter_contract(
    tmp_path: Path,
    location: str,
    width: int,
    height: int,
    reason: str,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-hostile-dimensions",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_hostile_dimensions")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    configuration = record["effective_execution"]["configuration"]
    if location == "resolved":
        record["width"] = width
        record["height"] = height
        configuration["model_facing"]["width"] = width
        configuration["model_facing"]["height"] = height
    for node in record["effective_execution"]["graph"].values():
        inputs = node["inputs"]
        if "width" in inputs and "height" in inputs:
            inputs["width"] = width
            inputs["height"] = height
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (
            lambda record: record["effective_execution"]["configuration"]["nodes"][
                "KSampler"
            ].pop("class"),
            "missing class",
        ),
        (
            lambda record: record["effective_execution"]["configuration"]["nodes"][
                "KSampler"
            ].__setitem__("class", "VAEDecode"),
            "class does not match",
        ),
        (
            lambda record: record["effective_execution"]["configuration"]["nodes"][
                "KSampler"
            ].__setitem__("unexpected", True),
            "unexpected unexpected",
        ),
        (
            lambda record: record["effective_execution"]["graph"]["7"][
                "inputs"
            ].__setitem__("unpinned_input", 1),
            "unsupported shape",
        ),
    ],
)
def test_v3_rejects_malformed_or_unapproved_node_pins(
    tmp_path: Path, mutator, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-hostile-node-pin",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_hostile_node_pin")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    mutator(record)
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_allows_repeated_node_classes_keyed_by_node_id(tmp_path: Path) -> None:
    base_bundle = build_comfyui_bundle(tmp_path / "base")
    recipe = json.loads(canonical_json(base_bundle.recipe_document))
    recipe["operations"]["generate"]["graph"]["12"] = {
        "class_type": "EmptyLatentImage",
        "inputs": {"width": "$width", "height": "$height", "batch_size": 1},
    }
    bundle = build_comfyui_bundle(
        tmp_path / "repeated",
        alter_recipe={"operations": recipe["operations"]},
    )
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-repeated-node-class",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_repeated_node_class")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    graph = record["effective_execution"]["graph"]
    assert graph["6"]["class_type"] == "EmptyLatentImage"
    assert graph["12"]["class_type"] == "EmptyLatentImage"
    backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_persists_canonical_approved_graph_link_topology(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-link-topology",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_link_topology")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)

    workflow = record["effective_execution"]["configuration"]["workflow"]
    expected_template = bundle.recipe_document["operations"]["generate"]["graph"]
    approved_pin = service.adapter.configuration["workflow_approval"]

    assert workflow["template_sha256"] == digest(expected_template)
    assert workflow["template"] == expected_template
    assert digest(workflow["template"]) == workflow["template_sha256"]
    assert workflow["approval"] == approved_pin
    assert workflow["approval"]["component_id"] == workflow["id"]
    assert workflow["approval"]["component_sha256"] == workflow["document_sha256"]
    assert (
        workflow["approval"]["document"]["operations"]["generate"]["graph_sha256"]
        == workflow["template_sha256"]
    )
    assert {
        "consumer": "4",
        "consumer_class": "CLIPTextEncode",
        "input": "clip",
        "source": "2",
        "source_class": "CLIPLoader",
        "output": 0,
    } in workflow["links"]
    assert workflow["links"] == sorted(
        workflow["links"], key=lambda link: (link["consumer"], link["input"])
    )
    backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("consumer", "input_name", "link"),
    [
        ("4", "clip", ["3", 0]),
        ("4", "clip", ["2", 1]),
        ("7", "positive", ["5", 0]),
    ],
)
def test_v3_rejects_self_consistent_graph_link_reroute(
    tmp_path: Path,
    consumer: str,
    input_name: str,
    link: list[object],
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-link-tamper",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_link_tamper")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    record["effective_execution"]["graph"][consumer]["inputs"][input_name] = link
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="link topology"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_rejects_graph_and_link_list_tamper_against_template_pin(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-link-list-tamper",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_link_list_tamper")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    effective = record["effective_execution"]
    effective["graph"]["4"]["inputs"]["clip"] = ["3", 0]
    workflow = effective["configuration"]["workflow"]
    clip_link = next(
        link
        for link in workflow["links"]
        if link["consumer"] == "4" and link["input"] == "clip"
    )
    clip_link["source"] = "3"
    clip_link["source_class"] = "VAELoader"
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="link topology"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize("name", sorted(COMFYUI_SAFE_ENVIRONMENT_NAMES))
def test_v3_accepts_each_comfyui_environment_name(
    tmp_path: Path, name: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-environment-name",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_environment_name")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _legacy_v3_record(
        dict(prepared.resolved_record), claim.attempt_id
    )
    value = "random" if name == "PYTHONHASHSEED" else "synthetic-runtime-value"
    _set_resolved_environment(record, name, value)

    backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("name", "value", "reason"),
    [
        ("HTTPS_PROXY", "http://127.0.0.1:9", "prohibited"),
        ("AWS_SECRET_ACCESS_KEY", "synthetic-secret-value", "prohibited"),
        ("LD_LIBRARY_PATH", "api_key=synthetic-secret-value", "credential-like"),
        ("PYTHONHASHSEED", "4294967296", "resolved environment"),
    ],
)
def test_v3_rejects_unknown_or_secret_bearing_environment_entries(
    tmp_path: Path, name: str, value: str, reason: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-environment-refusal",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_environment_refusal")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    _set_resolved_environment(record, name, value)

    with pytest.raises(BackendEvidenceError, match=reason):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize("version", [3.0, "3", True])
def test_v3_schema_version_dispatch_requires_exact_integer(
    tmp_path: Path, version: object
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-schema-type",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_schema_type")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    mutated = json.loads(canonical_json(record))
    mutated["schema_version"] = version

    with pytest.raises(BackendEvidenceError, match="unsupported schema"):
        backend_provenance.validate_resolved_record(mutated)
    service._store.insert_resolved_execution(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=record,
        timestamp=_now(),
    )
    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        connection.execute(
            "UPDATE backend_executions SET resolved_json = ?, resolved_digest = ? "
            "WHERE attempt_id = ?",
            (canonical_json(mutated), backend_digest(mutated), claim.attempt_id),
        )
        connection.execute(
            _STATIC_TRIGGER_DDL["backend_executions_stage_transition"]
        )
    with pytest.raises(BackendEvidenceError, match="unsupported schema"):
        service.get_execution(job_id)
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize("mutation", ["missing", "malformed", "extra"])
def test_v3_rejects_missing_malformed_or_extra_workflow_approval(
    tmp_path: Path, mutation: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        f"v3-workflow-approval-{mutation}",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, f"att_v3_workflow_approval_{mutation}")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    workflow = record["effective_execution"]["configuration"]["workflow"]
    if mutation == "missing":
        workflow.pop("approval", None)
    elif mutation == "malformed":
        workflow["approval"]["document_sha256"] = "0" * 64
    else:
        workflow["approval"]["unexpected"] = True
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="approval"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_v3_store_restart_rejects_rehashed_template_and_link_reroute(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-workflow-approval-restart-tamper",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_workflow_approval_restart_tamper")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    service._store.insert_resolved_execution(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id="owner_manual",
        claim_epoch=claim.claim_epoch,
        record=record,
        timestamp=_now(),
    )
    mutated = json.loads(canonical_json(record))
    effective = mutated["effective_execution"]
    effective["graph"]["4"]["inputs"]["clip"] = ["3", 0]
    workflow = effective["configuration"]["workflow"]
    workflow["template"]["4"]["inputs"]["clip"] = ["3", 0]
    workflow["template_sha256"] = digest(workflow["template"])
    link = next(
        link
        for link in workflow["links"]
        if link["consumer"] == "4" and link["input"] == "clip"
    )
    link["source"] = "3"
    link["source_class"] = "VAELoader"
    _rehash_effective(mutated)

    with _raw_connection(tmp_path / "studio.sqlite3") as connection:
        connection.execute("DROP TRIGGER backend_executions_stage_transition")
        connection.execute(
            "UPDATE backend_executions SET resolved_json = ?, resolved_digest = ? "
            "WHERE attempt_id = ?",
            (canonical_json(mutated), backend_digest(mutated), claim.attempt_id),
        )
        connection.execute(
            _STATIC_TRIGGER_DDL["backend_executions_stage_transition"]
        )

    restarted = GenerationService(tmp_path / "studio.sqlite3", tmp_path / "images")
    with pytest.raises(BackendEvidenceError, match="approval"):
        restarted.get_execution(job_id)
    service.adapter.cleanup_execution(prepared)


def test_v3_model_selector_role_is_bound_to_node_class(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-selector-role-class",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_selector_role_class")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    effective = record["effective_execution"]
    graph = effective["graph"]
    configuration = effective["configuration"]
    workflow = configuration["workflow"]
    graph["2"]["class_type"] = "CLIPVisionLoader"
    workflow["template"]["2"]["class_type"] = "CLIPVisionLoader"
    workflow["template_sha256"] = digest(workflow["template"])
    pin = configuration["nodes"].pop("CLIPLoader")
    pin["class"] = "CLIPVisionLoader"
    configuration["nodes"]["CLIPVisionLoader"] = pin
    approval = workflow["approval"]
    approval_document = approval["document"]
    approved_operation = approval_document["operations"]["generate"]
    approved_nodes = approved_operation["nodes"]
    approved_nodes["CLIPVisionLoader"] = approved_nodes.pop("CLIPLoader")
    approved_operation["graph_sha256"] = workflow["template_sha256"]
    canonical_approval = canonical_json(approval_document) + "\n"
    approval["document_sha256"] = hashlib.sha256(
        canonical_approval.encode("utf-8")
    ).hexdigest()
    approval["document_size_bytes"] = len(canonical_approval.encode("utf-8"))
    for link in workflow["links"]:
        if link["source"] == "2":
            link["source_class"] = "CLIPVisionLoader"
    _rehash_effective(record)

    try:
        with pytest.raises(BackendEvidenceError, match="model selector"):
            backend_provenance._validate_effective_graph(
                graph,
                pins=configuration["nodes"],
                record=record,
                configuration=configuration,
            )
    finally:
        service.adapter.cleanup_execution(prepared)


def test_v3_lora_loader_cannot_select_adapter_folder_role(tmp_path: Path) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "v3-lora-loader-adapter-role",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_v3_lora_loader_adapter_role")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    effective = record["effective_execution"]
    graph = effective["graph"]
    configuration = effective["configuration"]
    workflow = configuration["workflow"]

    model_file = next(
        item for item in configuration["model_files"] if item["role"] == "text_encoder"
    )
    model_file["role"] = "adapter"
    search_path = Path(model_file["search_path"])
    model_file["search_path"] = str(
        search_path.parent.parent / "adapters" / search_path.name
    )
    component_id = model_file["component_id"]
    for component in record["components"] + configuration["components"]:
        if component["id"] == component_id:
            component["role"] = "adapter"

    graph["2"] = {
        "class_type": "LoraLoader",
        "inputs": {"lora_name": search_path.name},
    }
    workflow["template"]["2"] = {
        "class_type": "LoraLoader",
        "inputs": {"lora_name": "$adapter_lora"},
    }
    pin = configuration["nodes"].pop("CLIPLoader")
    pin["class"] = "LoraLoader"
    pin["inputs"] = ["lora_name"]
    configuration["nodes"]["LoraLoader"] = pin

    approval = workflow["approval"]
    approval_document = approval["document"]
    approved_operation = approval_document["operations"]["generate"]
    approved_nodes = approved_operation["nodes"]
    approved_nodes["LoraLoader"] = approved_nodes.pop("CLIPLoader")
    workflow["template_sha256"] = digest(workflow["template"])
    approved_operation["graph_sha256"] = workflow["template_sha256"]
    workflow["links"] = backend_provenance._comfyui_graph_links(
        workflow["template"],
        pins=configuration["nodes"],
        label="tampered LoRA workflow template",
    )
    canonical_approval = canonical_json(approval_document) + "\n"
    approval["document_sha256"] = hashlib.sha256(
        canonical_approval.encode("utf-8")
    ).hexdigest()
    approval["document_size_bytes"] = len(canonical_approval.encode("utf-8"))
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="model selector"):
        backend_provenance._validate_effective_graph(
            graph,
            pins=configuration["nodes"],
            record=record,
            configuration=configuration,
        )
    service.adapter.cleanup_execution(prepared)


@pytest.mark.parametrize(
    ("node_id", "input_name", "tampered_value"),
    [
        ("7", "seed", True),
        ("7", "steps", 8.0),
        ("7", "denoise", True),
    ],
)
def test_v3_rejects_graph_scalars_with_inexact_json_types(
    tmp_path: Path,
    node_id: str,
    input_name: str,
    tampered_value: object,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        f"v3-scalar-type-{input_name}",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, f"att_v3_scalar_type_{input_name}")
    prepared = service.adapter.resolve_execution(_plan(claim))
    record = _v3_record(dict(prepared.resolved_record), claim.attempt_id)
    effective = record["effective_execution"]
    effective["graph"][node_id]["inputs"][input_name] = tampered_value
    if input_name == "seed":
        record["seed"] = 1
        effective["configuration"]["model_facing"]["seed"] = 1
    _rehash_effective(record)

    with pytest.raises(BackendEvidenceError, match="exact JSON type"):
        backend_provenance.validate_resolved_record(record)
    service.adapter.cleanup_execution(prepared)


def test_comfyui_privacy_checks_each_graph_node_against_its_own_pin(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    service = _comfy_service(tmp_path, bundle)
    job_id = service.enqueue(
        "comfy-privacy-each-node-pin",
        _request(),
        workload_demand=heavy_workload_demand(),
    ).job_id
    claim = _claim(service, job_id, "att_comfy_privacy_each_node_pin")
    prepared = service.adapter.resolve_execution(_plan(claim))
    effective = json.loads(
        canonical_json(prepared.resolved_record["effective_execution"])
    )
    valid = comfyui.comfyui_invocation_privacy_settings(
        prepared.argv, prepared.environment, effective
    )
    effective["graph"]["1"]["inputs"]["unapproved_private_toggle"] = True
    effective["request_body"]["prompt"] = effective["graph"]
    tampered = comfyui.comfyui_invocation_privacy_settings(
        prepared.argv, prepared.environment, effective
    )

    assert all(value is False for value in valid.values())
    assert all(value is None for value in tampered.values())
    service.adapter.cleanup_execution(prepared)
