"""Command-line interface for submitting and inspecting local generations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .admission import (
    AdmissionProfile,
    WorkloadDemand,
    load_admission_profile,
    load_workload_demand,
)
from .domain import GenerationRequest, ArtifactSource
from .errors import (
    GenerationExecutionError,
    GenerationError,
    IdempotencyConflictError,
    InputValidationError,
    RecordNotFoundError,
    UnknownReferenceError,
    UnsupportedCapabilityError,
    PublicationError,
    PublicationIncompleteError,
    ArtifactIntegrityError,
    ResourceBusyError,
)
from .candidate import (
    CandidateAcquisitionError,
    CandidateOutputError,
    CandidateValidationError,
    candidate_exit_code,
    inspect_candidate,
    parse_trusted_evidence,
    prepare_candidate,
    verify_candidate,
)
from .service import GenerationService
from .inventory import (
    InventoryOptions,
    InventoryOutputError,
    InventoryValidationError,
    collect_inventory,
    write_inventory,
)


class _JsonArgumentParser(argparse.ArgumentParser):
    """Write parser syntax failures using the CLI's structured error format."""

    def error(self, message: str) -> None:
        _write_json(
            {"error": {"code": "argument_error", "message": message}},
            sys.stderr,
        )
        raise SystemExit(2)


def _add_admission_arguments(command: argparse.ArgumentParser) -> None:
    """Add one optional, all-or-none capacity evidence input group."""
    command.add_argument(
        "--inventory-report",
        type=Path,
        help="strict T02 inventory report used to derive the capacity profile",
    )
    command.add_argument(
        "--admission-policy",
        type=Path,
        help="strict operator policy with explicit headroom for every pool",
    )
    command.add_argument(
        "--workload-demand",
        type=Path,
        help="strict versioned memory, context, offload, and residency demand",
    )


def _admission_inputs(
    options: argparse.Namespace,
) -> tuple[AdmissionProfile | None, WorkloadDemand | None]:
    """Load admission inputs only when the operator supplied capacity evidence."""
    values = (
        options.inventory_report,
        options.admission_policy,
        options.workload_demand,
    )
    if not any(values):
        return None, None
    if not all(values):
        raise InputValidationError(
            "--inventory-report, --admission-policy, and --workload-demand "
            "must be provided together"
        )
    return (
        load_admission_profile(options.inventory_report, options.admission_policy),
        load_workload_demand(options.workload_demand),
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the documented local-only command surface."""
    parser = _JsonArgumentParser(
        prog="media-generation",
        description="Submit and inspect synchronous local image generations.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    submit = commands.add_parser("submit", help="persist and execute one generation request")
    submit.add_argument("--db", required=True, type=Path, help="SQLite database path")
    submit.add_argument("--output-dir", required=True, type=Path, help="image artifact directory")
    submit.add_argument("--idempotency-key", required=True, help="stable key for this request")
    submit.add_argument(
        "--request-json",
        required=True,
        help="engine-neutral JSON request; use - to read JSON from standard input",
    )
    _add_admission_arguments(submit)

    enqueue = commands.add_parser("enqueue", help="durably admit a generation request")
    enqueue.add_argument("--db", required=True, type=Path)
    enqueue.add_argument("--output-dir", required=True, type=Path)
    enqueue.add_argument("--idempotency-key", required=True)
    enqueue.add_argument("--request-json", required=True)
    enqueue.add_argument(
        "--max-attempts",
        type=int,
        default=None,
        help="total attempts for a new admission; omit to use or preserve policy",
    )
    _add_admission_arguments(enqueue)

    worker = commands.add_parser("worker", help="execute compatible queued jobs")
    worker.add_argument("--db", required=True, type=Path)
    worker.add_argument("--output-dir", required=True, type=Path)
    worker.add_argument("--limit", type=int, default=1)

    cancel = commands.add_parser("cancel", help="fence a queued or active job")
    cancel.add_argument("--db", required=True, type=Path)
    cancel.add_argument("--output-dir", type=Path, default=Path.cwd())
    cancel.add_argument("--job-id", required=True)

    retry = commands.add_parser("retry", help="requeue eligible failed work")
    retry.add_argument("--db", required=True, type=Path)
    retry.add_argument("--output-dir", type=Path, default=Path.cwd())
    retry.add_argument("--job-id", required=True)

    recover = commands.add_parser("recover", help="reconcile interrupted execution")
    recover.add_argument("--db", required=True, type=Path)
    recover.add_argument("--output-dir", required=True, type=Path)

    for name, help_text in (
        ("request", "retrieve an immutable request snapshot"),
        ("job", "retrieve durable job state"),
        ("artifact", "retrieve a logical image artifact"),
        ("integrity", "verify authoritative artifact bytes"),
        ("lineage", "inspect ordered artifact parents and children"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--db", required=True, type=Path, help="SQLite database path")
        command.add_argument("--id", required=True, help=f"{name} ID")
        if name == "integrity":
            command.add_argument(
                "--output-dir", required=True, type=Path,
                help=("directory for legacy artifacts without publication records; "
                      "journal-backed artifacts use their recorded publication owner"),
            )

    provenance = commands.add_parser("provenance", help="retrieve request, job, attempt, and artifact")
    provenance.add_argument("--db", required=True, type=Path, help="SQLite database path")
    provenance.add_argument("--job-id", required=True, help="generation job ID")
    admission = commands.add_parser(
        "admission", help="inspect a pinned capacity decision and reservation"
    )
    admission.add_argument("--db", required=True, type=Path, help="SQLite database path")
    admission.add_argument("--job-id", required=True, help="generation job ID")
    inventory = commands.add_parser(
        "inventory",
        help="collect read-only host, runtime, and model inventory",
    )
    inventory.add_argument(
        "--output",
        required=True,
        type=Path,
        help="directory for inventory.json and transcript.txt",
    )
    inventory.add_argument(
        "--manifest",
        type=Path,
        help="strict manifest declaring model roots, bundles, and runtime probes",
    )
    inventory.add_argument(
        "--hash-components",
        action="store_true",
        help="compute bounded SHA-256 digests for declared model components",
    )
    inventory.add_argument(
        "--hash-limit-bytes",
        type=int,
        default=16 * 1024 * 1024 * 1024,
        help="maximum bytes hashed per component (default: 16 GiB)",
    )
    inventory.add_argument(
        "--replay",
        type=Path,
        help="synthetic observation replay file for deterministic testing",
    )

    ingest = commands.add_parser("import", help="operator-approved local image ingestion")
    ingest.add_argument("--db", required=True, type=Path)
    ingest.add_argument("--output-dir", required=True, type=Path)
    ingest.add_argument("--approved-root", required=True, type=Path,
                        help="explicitly authorize reads beneath this source directory")
    ingest.add_argument("--source", required=True, help="relative path beneath the approved root")
    ingest.add_argument("--sources-json", default="[]",
                        help="ordered lineage parents: [{artifact_id, role}]")
    reconcile = commands.add_parser("reconcile", help="recover owned publications and inspect integrity")
    reconcile.add_argument("--db", required=True, type=Path)
    reconcile.add_argument("--output-dir", required=True, type=Path)
    candidate = commands.add_parser(
        "candidate", help="inspect, verify, or prepare an exact declared model candidate"
    )
    candidate_commands = candidate.add_subparsers(dest="candidate_command", required=True)
    for name, help_text in (
        ("inspect", "inspect one strict candidate declaration"),
        ("verify", "repeat offline static verification without writing"),
        ("prepare", "write an offline-ready manifest and acquisition journal"),
    ):
        command = candidate_commands.add_parser(name, help=help_text)
        command.add_argument(
            "--declaration",
            required=True,
            type=Path,
            help="strict T07 candidate declaration JSON",
        )
        command.add_argument(
            "--trusted-evidence",
            type=Path,
            help="separate host-owned pins for candidate evidence documents",
        )
        if name == "prepare":
            command.add_argument(
                "--manifest-output",
                required=True,
                type=Path,
                help="prepared manifest destination outside declared artifact paths",
            )
            command.add_argument(
                "--journal-output",
                type=Path,
                help="durable redacted journal; defaults beside the manifest",
            )
            command.add_argument(
                "--acquire",
                action="store_true",
                help="explicitly permit bounded transfer of missing declared artifacts",
            )
            command.add_argument(
                "--acquisition-config",
                type=Path,
                help="separate transport authorization and credentials file",
            )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one CLI operation and emit a single JSON response."""
    parser = build_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == "candidate":
            return _run_candidate(options)
        if options.command == "inventory":
            return _run_inventory(options)
        if options.command == "submit":
            request = _parse_request(options.request_json)
            profile, demand = _admission_inputs(options)
            service = GenerationService(
                options.db, options.output_dir, admission_profile=profile
            )
            result = service.submit(
                options.idempotency_key, request, workload_demand=demand
            )
            _write_json(result.to_dict(), sys.stdout)
            return 0

        if options.command == "enqueue":
            request = _parse_request(options.request_json)
            profile, demand = _admission_inputs(options)
            service = GenerationService(
                options.db, options.output_dir, admission_profile=profile
            )
            result = service.enqueue(
                options.idempotency_key,
                request,
                max_attempts=options.max_attempts,
                workload_demand=demand,
            )
            _write_json(result.to_dict(), sys.stdout)
            return 0

        if options.command == "admission":
            service = GenerationService(options.db, Path.cwd())
            inspection = service.inspect_admission(options.job_id)
            if inspection is None:
                raise RecordNotFoundError(f"job not found: {options.job_id}")
            _write_json(inspection.to_dict(), sys.stdout)
            return 0

        if options.command == "worker":
            service = GenerationService(options.db, options.output_dir)
            report = service.work(limit=options.limit)
            if report["status"] == "resource_busy":
                return _write_error(
                    "resource_busy", "local generation resource is busy", 1,
                    outcomes=report.get("outcomes", []),
                )
            _write_json(report, sys.stdout)
            return int(any(
                item["status"] != "succeeded" or not item["termination_proven"]
                for item in report.get("outcomes", [])
            ))

        if options.command == "recover":
            service = GenerationService(options.db, options.output_dir)
            report = service.recover()
            if report["status"] == "resource_busy":
                return _write_error("resource_busy", "local generation resource is busy", 1)
            _write_json(report, sys.stdout)
            return 1 if report["status"] == "attention_required" else 0

        if options.command == "cancel":
            service = GenerationService(options.db, options.output_dir)
            _write_json(service.cancel(options.job_id), sys.stdout)
            return 0

        if options.command == "retry":
            service = GenerationService(options.db, options.output_dir)
            _write_json(service.retry(options.job_id).to_dict(), sys.stdout)
            return 0

        if options.command in {"import", "reconcile"}:
            service = GenerationService(options.db, options.output_dir)
            if options.command == "reconcile":
                response = service.reconcile()
            else:
                try:
                    parents = json.loads(options.sources_json, object_pairs_hook=_unique_object_pairs)
                except (json.JSONDecodeError, UnicodeError) as error:
                    raise InputValidationError(f"invalid sources JSON: {error}") from error
                if not isinstance(parents, list) or not all(isinstance(item, dict) for item in parents):
                    raise InputValidationError("sources JSON must be an array of artifact_id/role objects")
                try:
                    sources = tuple(ArtifactSource(**item) for item in parents)
                except TypeError as error:
                    raise InputValidationError(f"invalid lineage source: {error}") from error
                response = service.import_image(options.approved_root, options.source, sources=sources).to_dict()
            _write_json(response, sys.stdout)
            if options.command == "reconcile" and response["status"] == "attention_required":
                return 1
            return 0

        inspection_root = options.output_dir if options.command == "integrity" else Path(".")
        service = GenerationService(options.db, inspection_root)
        if options.command == "request":
            response = service.get_request(options.id)
        elif options.command == "job":
            response = service.get_job(options.id).to_dict()
        elif options.command == "artifact":
            response = service.get_artifact(options.id).to_dict()
        elif options.command == "integrity":
            response = service.get_integrity(options.id)
        elif options.command == "lineage":
            response = service.get_lineage(options.id)
        else:
            response = service.get_provenance(options.job_id)
        _write_json(response, sys.stdout)
        return 0
    except InputValidationError as error:
        return _write_error("validation_error", str(error), 2)
    except UnsupportedCapabilityError as error:
        return _write_error("unsupported_capability", str(error), 2)
    except UnknownReferenceError as error:
        return _write_error("unknown_reference", str(error), 2)
    except IdempotencyConflictError as error:
        return _write_error("idempotency_conflict", str(error), 3)
    except RecordNotFoundError as error:
        return _write_error("not_found", str(error), 4)
    except ResourceBusyError as error:
        return _write_error("resource_busy", str(error), 1, job_id=error.job_id)
    except GenerationExecutionError as error:
        return _write_error(
            "generation_failed", error.safe_message, 1, job_id=error.job_id
        )
    except PublicationIncompleteError as error:
        return _write_error("publication_incomplete", error.safe_message, 1,
                            job_id=error.job_id, recovery=error.recovery)
    except PublicationError as error:
        return _write_error("publication_incomplete", str(error), 1)
    except ArtifactIntegrityError as error:
        return _write_error("artifact_integrity", str(error), 1)
    except GenerationError as error:
        return _write_error("generation_error", str(error), 1)
    except OSError as error:
        return _write_error("storage_error", str(error), 1)
    except CandidateValidationError as error:
        return _write_error("candidate_validation_error", str(error), 2)
    except CandidateOutputError as error:
        return _write_error("candidate_output_error", str(error), 7)
    except CandidateAcquisitionError as error:
        return _write_error("candidate_acquisition_error", str(error), 8)
    except InventoryValidationError as error:
        return _write_error("admission_validation_error", str(error), 2)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        return _write_error("validation_error", f"invalid request JSON: {error}", 2)


def _run_inventory(options: argparse.Namespace) -> int:
    """Collect and write one inventory report, preserving status exit codes."""
    try:
        result = collect_inventory(
            InventoryOptions(
                output_directory=options.output,
                manifest_path=options.manifest,
                hash_components=options.hash_components,
                hash_limit_bytes=options.hash_limit_bytes,
                replay_path=options.replay,
            )
        )
        published = write_inventory(result, options.output)
    except InventoryValidationError as error:
        return _write_error("inventory_validation_error", str(error), 2)
    except InventoryOutputError as error:
        return _write_error("inventory_output_error", str(error), 3)
    _write_json({**published.summary, **(published.publication or {})}, sys.stdout)
    return published.exit_code


def _run_candidate(options: argparse.Namespace) -> int:
    """Run one bounded candidate operation and preserve its static status."""
    trusted_evidence = (
        ()
        if options.trusted_evidence is None
        else parse_trusted_evidence(options.trusted_evidence)
    )
    if options.candidate_command == "inspect":
        report = inspect_candidate(
            options.declaration, trusted_evidence=trusted_evidence
        )
    elif options.candidate_command == "verify":
        report = verify_candidate(
            options.declaration, trusted_evidence=trusted_evidence
        )
    else:
        report = prepare_candidate(
            options.declaration,
            manifest_output=options.manifest_output,
            journal_output=options.journal_output,
            acquire=options.acquire,
            acquisition_config=options.acquisition_config,
            trusted_evidence_path=options.trusted_evidence,
            trusted_evidence=trusted_evidence,
        )
    _write_json(report, sys.stdout)
    return candidate_exit_code(str(report["status"]))


def _parse_request(source: str) -> GenerationRequest:
    """Parse strict engine-neutral JSON into a validated immutable request."""
    raw = sys.stdin.read() if source == "-" else source
    payload = json.loads(raw, object_pairs_hook=_unique_object_pairs)
    if not isinstance(payload, dict):
        raise InputValidationError("request JSON must contain an object")
    allowed_fields = {"prompt", "seed", "width", "height", "reference_ids", "output_slot"}
    unknown_fields = sorted(set(payload) - allowed_fields)
    if unknown_fields:
        raise InputValidationError(f"unsupported request fields: {', '.join(unknown_fields)}")
    try:
        return GenerationRequest(**payload)
    except TypeError as error:
        raise InputValidationError(f"invalid request fields: {error}") from error


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject repeated JSON keys so request intent cannot be ambiguous."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InputValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _write_json(value: object, output: object) -> None:
    """Write one deterministic JSON object followed by a newline."""
    output.write(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n")


def _write_error(code: str, message: str, exit_code: int, **details: object) -> int:
    """Write a machine-readable failure to stderr without a success-shaped response."""
    _write_json({"error": {"code": code, "message": message, **details}}, sys.stderr)
    return exit_code
