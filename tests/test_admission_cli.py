"""Operator CLI contracts for versioned capacity admission evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from media_generation.cli import main
from test_durable_execution import request
from test_resource_admission import GIB, inventory_report


def _write_json(path: Path, value: object) -> Path:
    """Write one deterministic operator document for a CLI invocation."""
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def _operator_documents(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Return report, policy, and known-demand paths for an image workload."""
    inventory = _write_json(tmp_path / "inventory.json", inventory_report())
    policy = _write_json(
        tmp_path / "policy.json",
        {
            "schema": "media-generation.admission-policy",
            "schema_version": 1,
            "pool_headroom_bytes": {"system_ram": 8 * GIB},
        },
    )
    demand = _write_json(
        tmp_path / "demand.json",
        {
            "schema": "media-generation.workload-demand",
            "schema_version": 1,
            "kind": "image",
            "memory": {
                "status": "known",
                "system_ram_bytes": 20 * GIB,
                "accelerator_memory_bytes": 20 * GIB,
            },
            "context": {"status": "not_applicable"},
            "offload": {"status": "known", "mode": "none"},
            "residency": {"status": "known", "mode": "transient"},
        },
    )
    return inventory, policy, demand


def test_cli_admits_and_inspects_one_pinned_capacity_decision(
    tmp_path: Path, capsys
) -> None:
    """The public CLI binds T02 evidence, policy, and demand to one job."""
    inventory, policy, demand = _operator_documents(tmp_path)
    database = tmp_path / "studio.sqlite3"
    arguments = [
        "enqueue",
        "--db",
        str(database),
        "--output-dir",
        str(tmp_path / "images"),
        "--idempotency-key",
        "cli-admission",
        "--request-json",
        request().canonical_json(),
        "--inventory-report",
        str(inventory),
        "--admission-policy",
        str(policy),
        "--workload-demand",
        str(demand),
    ]

    assert main(arguments) == 0
    enqueued = json.loads(capsys.readouterr().out)
    assert enqueued["status"] == "queued"

    assert main(
        ["admission", "--db", str(database), "--job-id", enqueued["job_id"]]
    ) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["admission"]["decision"] == "queued"
    assert inspected["admission"]["reason"] == "capacity_fit"
    assert inspected["admission"]["reserved_bytes"] is None
    assert inspected["resource"] is None


def test_cli_claimed_admission_reports_fence_and_lease(
    tmp_path: Path, capsys
) -> None:
    """An owning job can audit the active claim's fence and lease through the CLI."""
    from concurrent.futures import ThreadPoolExecutor
    import threading

    from media_generation.adapters import (
        PROCESS_CONTAINED_CONTRACT,
        DeterministicCpuAdapter,
    )
    from media_generation.admission import load_admission_profile, load_workload_demand
    from media_generation.service import GenerationService

    entered = threading.Event()
    resume = threading.Event()

    class PausedAdapter(DeterministicCpuAdapter):
        containment_contract = PROCESS_CONTAINED_CONTRACT

        def generate(self, plan, destination):
            entered.set()
            assert resume.wait(5)
            return super().generate(plan, destination)

    inventory, policy, demand = _operator_documents(tmp_path)
    database = tmp_path / "studio.sqlite3"
    profile = load_admission_profile(inventory, policy)
    workload = load_workload_demand(demand)
    service = GenerationService(
        database,
        tmp_path / "images",
        adapter=PausedAdapter(),
        admission_profile=profile,
    )
    job = service.enqueue("claimed-inspection", request(), workload_demand=workload)

    with ThreadPoolExecutor(max_workers=1) as pool:
        running = pool.submit(service.work)
        try:
            assert entered.wait(5)
            assert main(["admission", "--db", str(database), "--job-id", job.job_id]) == 0
            inspected = json.loads(capsys.readouterr().out)
            resource = inspected["resource"]
            assert inspected["admission"]["decision"] == "reserved"
            assert resource["state"] == "claimed"
            assert resource["job_id"] == job.job_id
            assert resource["attempt_id"]
            assert resource["owner_id"]
            assert isinstance(resource["claim_epoch"], int)
            assert isinstance(resource["lease_expires_at"], str)
        finally:
            resume.set()
        assert running.result(timeout=10)["status"] == "complete"


def test_cli_malformed_admission_document_returns_structured_error(
    tmp_path: Path, capsys
) -> None:
    """Malformed operator input never reaches a legacy unaccounted admission."""
    inventory, policy, demand = _operator_documents(tmp_path)
    demand.write_text("{not valid json", encoding="utf-8")

    exit_code = main(
        [
            "enqueue",
            "--db",
            str(tmp_path / "studio.sqlite3"),
            "--output-dir",
            str(tmp_path / "images"),
            "--idempotency-key",
            "malformed-admission",
            "--request-json",
            request().canonical_json(),
            "--inventory-report",
            str(inventory),
            "--admission-policy",
            str(policy),
            "--workload-demand",
            str(demand),
        ]
    )

    error = json.loads(capsys.readouterr().err)
    assert exit_code == 2
    assert error["error"]["code"] == "admission_validation_error"


def test_cli_out_of_range_demand_returns_structured_admission_error(
    tmp_path: Path, capsys
) -> None:
    """A byte count beyond SQLite's signed range never creates execution work."""
    inventory, policy, demand = _operator_documents(tmp_path)
    payload = json.loads(demand.read_text(encoding="utf-8"))
    payload["memory"]["system_ram_bytes"] = 1 << 63
    _write_json(demand, payload)
    database = tmp_path / "studio.sqlite3"

    exit_code = main(
        [
            "enqueue",
            "--db",
            str(database),
            "--output-dir",
            str(tmp_path / "images"),
            "--idempotency-key",
            "out-of-range-demand",
            "--request-json",
            request().canonical_json(),
            "--inventory-report",
            str(inventory),
            "--admission-policy",
            str(policy),
            "--workload-demand",
            str(demand),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2, (captured.out, captured.err)
    error = json.loads(captured.err)
    assert error["error"]["code"] == "admission_validation_error"
    assert "system_ram_bytes" in error["error"]["message"]
    assert "SQLite signed 64-bit" in error["error"]["message"]
    assert not database.exists()


@pytest.mark.parametrize(
    "admission_enabled",
    [False, True],
    ids=["admission-disabled", "admission-enabled"],
)
def test_adapter_failure_details_are_redacted_from_admission_and_cli(
    tmp_path: Path, capsys, monkeypatch, admission_enabled: bool
) -> None:
    """Adapter exception text cannot reach admission evidence or CLI output."""
    from media_generation.adapters import DeterministicCpuAdapter
    from media_generation import cli as cli_module
    from media_generation.admission import (
        build_admission_profile,
        parse_admission_policy,
        parse_workload_demand,
    )
    from media_generation.service import GenerationService

    prompt_sentinel = "PROMPT_SENTINEL_platypus"
    credential_sentinel = "API_TOKEN_SENTINEL_7f3c"
    exception_text = f"provider rejected {prompt_sentinel} with {credential_sentinel}"

    class SecretFailure(DeterministicCpuAdapter):
        containment_contract = None

        def generate(self, plan, stream):
            raise RuntimeError(exception_text)

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
    services: list[GenerationService] = []

    def service_factory(database, output_dir, *, admission_profile=None):
        service = GenerationService(
            database,
            output_dir,
            adapter=SecretFailure(),
            admission_profile=admission_profile,
        )
        services.append(service)
        return service

    monkeypatch.setattr(cli_module, "GenerationService", service_factory)
    demand = _write_json(
        tmp_path / "demand.json",
        {
            "schema": "media-generation.workload-demand",
            "schema_version": 1,
            "kind": "image",
            "memory": {"status": "known", "system_ram_bytes": 1, "accelerator_memory_bytes": 0},
            "context": {"status": "not_applicable"},
            "offload": {"status": "known", "mode": "none"},
            "residency": {"status": "known", "mode": "transient"},
        },
    )
    inventory = _write_json(tmp_path / "inventory.json", inventory_report())
    policy = _write_json(
        tmp_path / "policy.json",
        {
            "schema": "media-generation.admission-policy",
            "schema_version": 1,
            "pool_headroom_bytes": {"system_ram": 8 * GIB},
        },
    )
    request_with_prompt = request()
    request_payload = request_with_prompt.to_dict()
    request_payload["prompt"] = prompt_sentinel
    arguments = [
        "submit",
        "--db",
        str(tmp_path / "studio.sqlite3"),
        "--output-dir",
        str(tmp_path / "images"),
        "--idempotency-key",
        "redacted-failure",
        "--request-json",
        json.dumps(request_payload),
    ]
    if admission_enabled:
        arguments.extend(
            [
                "--inventory-report",
                str(inventory),
                "--admission-policy",
                str(policy),
                "--workload-demand",
                str(demand),
            ]
        )

    assert main(arguments) == 1

    captured = capsys.readouterr()
    assert prompt_sentinel not in captured.out + captured.err
    assert credential_sentinel not in captured.out + captured.err
    error = json.loads(captured.err)
    job_id = error["error"]["job_id"]
    assert error["error"]["message"] == "execution_ambiguous"
    if admission_enabled:
        inspection = services[0].inspect_admission(job_id)
        assert inspection is not None
        admission = inspection.admission
        assert admission.reason == "execution_ambiguous"
        assert prompt_sentinel not in json.dumps(admission.to_dict())
        assert credential_sentinel not in json.dumps(admission.to_dict())


def test_cli_distinguishes_unrecorded_historical_job_from_missing(
    tmp_path: Path, capsys
) -> None:
    """Historical jobs without admission evidence remain inspectable by identity."""
    from test_execution_migration import historical_running

    database, _images, job_id = historical_running(tmp_path, "t03")

    assert main(["admission", "--db", str(database), "--job-id", job_id]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["admission"]["job_id"] == job_id
    assert inspected["admission"]["decision"] == "unrecorded"
    assert inspected["admission"]["reason"] == "legacy_admission_not_recorded"

    missing = "job_" + "f" * 32
    assert main(["admission", "--db", str(database), "--job-id", missing]) == 4
    captured = capsys.readouterr()
    error = json.loads(captured.err)
    assert error["error"]["code"] == "not_found"

