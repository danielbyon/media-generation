"""Command-line interface for local media generation and inference."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from .admission import (
    AdmissionProfile,
    WorkloadDemand,
    load_admission_profile,
    load_workload_demand,
    parse_workload_demand,
)
from .domain import GenerationRequest, ArtifactSource
from .errors import (
    BackendEvidenceError,
    BackendPreparationError,
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
from .engine import StableDiffusionCppAdapter
from .comfyui import COMFYUI_BACKEND_KIND, ComfyUIAdapter
from .candidate import (
    CandidateAcquisitionError,
    CandidateOutputError,
    CandidateValidationError,
    LLAMA_CPP_BACKEND_KIND,
    candidate_exit_code,
    inspect_candidate,
    parse_trusted_evidence,
    prepare_candidate,
    verify_candidate,
)
from .service import GenerationService
from .batch_execution import GenerationBatchService
from .screening import (
    ScreeningConfigurationError,
    ScreeningError,
    ScreeningManifest,
    ScreeningManifestError,
    ScreeningRunner,
    render_summary,
)
from .screening_store import ScreeningLedger, ScreeningStoreError
from .inventory import (
    InventoryOptions,
    InventoryOutputError,
    InventoryValidationError,
    collect_inventory,
    write_inventory,
)
from .inference import InferenceKind
from .llama_cpp import (
    HardwareCompatibilityEvidence,
    LlamaCppComponent,
    LlamaCppConfiguration,
    LlamaCppRequest,
    ResourceDemandEvidence,
    ResponseStreamVerification,
    RuntimeBuildEvidence,
    RuntimeQualification,
)


MAX_INFERENCE_REQUEST_FILE_BYTES = 128 * 1024
_MAX_INFERENCE_JSON_BYTES = 256 * 1024


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


def _add_batch_admission_arguments(command: argparse.ArgumentParser) -> None:
    """Add the profile and per-slot demand inputs used by batch admission."""
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
        "--workload-demands",
        type=Path,
        help=(
            "versioned JSON mapping each output slot to a strict T04 workload demand"
        ),
    )


def _batch_admission_inputs(
    options: argparse.Namespace,
) -> tuple[AdmissionProfile | None, dict[str, WorkloadDemand] | None]:
    """Load one profile and an exact output-slot demand map, if supplied."""
    values = (
        options.inventory_report,
        options.admission_policy,
        options.workload_demands,
    )
    if not any(values):
        return None, None
    if not all(values):
        raise InputValidationError(
            "--inventory-report, --admission-policy, and --workload-demands "
            "must be provided together"
        )
    profile = load_admission_profile(
        options.inventory_report, options.admission_policy
    )
    demands = _load_batch_workload_demands(options.workload_demands)
    return profile, demands


def _load_batch_workload_demands(path: Path) -> dict[str, WorkloadDemand]:
    """Load a versioned map whose keys are immutable GenerationRequest slots."""
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object_pairs
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputValidationError(f"cannot read batch workload demands: {error}") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "schema_version",
        "demands",
    }:
        raise InputValidationError("batch workload demands have an invalid shape")
    if payload.get("schema") != "media-generation.batch-workload-demands":
        raise InputValidationError("unsupported batch workload demand schema")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise InputValidationError("unsupported batch workload demand schema_version")
    raw_demands = payload.get("demands")
    if not isinstance(raw_demands, dict) or not raw_demands:
        raise InputValidationError("batch workload demands must be a non-empty object")
    parsed: dict[str, WorkloadDemand] = {}
    for output_slot, demand in raw_demands.items():
        if not isinstance(output_slot, str) or not output_slot:
            raise InputValidationError("batch demand keys must be output-slot strings")
        parsed[output_slot] = parse_workload_demand(demand)
    return parsed


def _add_engine_arguments(
    command: argparse.ArgumentParser, *, required_candidate: bool = False
) -> None:
    """Add the optional declared local engine selection to one command."""
    command.add_argument(
        "--engine-candidate",
        type=Path,
        required=required_candidate,
        help="strict T07 candidate declaration for pinned local inference",
    )
    command.add_argument(
        "--engine-trusted-evidence",
        type=Path,
        help="host-owned evidence pins; requires --engine-candidate",
    )
    command.add_argument(
        "--engine-backend",
        choices=("stable-diffusion-cpp", "comfyui"),
        default="stable-diffusion-cpp",
        help="explicit backend invoked by --engine-candidate",
    )


def _engine_adapter(
    options: argparse.Namespace, output_directory: Path
) -> StableDiffusionCppAdapter | ComfyUIAdapter | None:
    """Build the optional engine adapter without falling back on refusal."""
    if options.engine_trusted_evidence is not None and options.engine_candidate is None:
        raise InputValidationError(
            "--engine-trusted-evidence requires --engine-candidate"
        )
    if options.engine_candidate is None:
        if options.engine_backend == "comfyui":
            raise InputValidationError("--engine-backend comfyui requires --engine-candidate")
        return None
    if options.engine_backend == "comfyui":
        return ComfyUIAdapter(
            candidate_path=options.engine_candidate,
            output_directory=output_directory,
            trusted_evidence_path=options.engine_trusted_evidence,
        )
    return StableDiffusionCppAdapter(
        candidate_path=options.engine_candidate,
        output_directory=output_directory,
        trusted_evidence_path=options.engine_trusted_evidence,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the documented local-only command surface."""
    parser = _JsonArgumentParser(
        prog="media-generation",
        description="Submit and inspect local image, text, and vision work.",
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
    _add_engine_arguments(submit)

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
    _add_engine_arguments(enqueue)

    worker = commands.add_parser("worker", help="execute compatible queued jobs")
    worker.add_argument("--db", required=True, type=Path)
    worker.add_argument("--output-dir", required=True, type=Path)
    worker.add_argument("--limit", type=int, default=1)
    _add_engine_arguments(worker)

    inference = commands.add_parser(
        "inference", help="queue and supervise local text or vision inference"
    )
    inference_commands = inference.add_subparsers(
        dest="inference_command", required=True
    )

    inference_enqueue = inference_commands.add_parser(
        "enqueue", help="persist one text or vision inference request"
    )
    inference_enqueue.add_argument("--db", required=True, type=Path)
    inference_enqueue.add_argument("--idempotency-key", required=True)
    inference_enqueue.add_argument("--request-file", required=True, type=Path)
    inference_enqueue.add_argument("--deadline-seconds", type=float, default=300.0)
    inference_enqueue.add_argument("--runtime-config", required=True, type=Path)
    inference_enqueue.add_argument("--inventory-report", required=True, type=Path)
    inference_enqueue.add_argument("--admission-policy", required=True, type=Path)
    inference_enqueue.add_argument("--workload-demands", required=True, type=Path)

    inference_worker = inference_commands.add_parser(
        "worker", help="run qualified requests using the local llama.cpp CLI"
    )
    inference_worker.add_argument("--db", required=True, type=Path)
    inference_worker.add_argument("--output-dir", required=True, type=Path)
    inference_worker.add_argument("--limit", type=int, default=1)
    inference_worker.add_argument("--runtime-config", required=True, type=Path)
    inference_worker.add_argument("--runtime-qualification", required=True, type=Path)
    inference_worker.add_argument("--candidate", required=True, type=Path)
    inference_worker.add_argument("--trusted-evidence", required=True, type=Path)
    inference_worker.add_argument("--inventory-report", required=True, type=Path)
    inference_worker.add_argument("--admission-policy", required=True, type=Path)
    inference_worker.add_argument("--workload-demands", required=True, type=Path)

    inference_cancel = inference_commands.add_parser(
        "cancel", help="fence a queued or active inference request"
    )
    inference_cancel.add_argument("--db", required=True, type=Path)
    inference_cancel.add_argument("--job-id", required=True)

    inference_recover = inference_commands.add_parser(
        "recover", help="reconcile interrupted inference execution"
    )
    inference_recover.add_argument("--db", required=True, type=Path)
    inference_recover.add_argument("--output-dir", required=True, type=Path)

    inference_provenance = inference_commands.add_parser(
        "provenance", help="inspect one inference request and its attempts"
    )
    inference_provenance.add_argument("--db", required=True, type=Path)
    inference_provenance.add_argument("--job-id", required=True)

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
    execution = commands.add_parser(
        "execution", help="retrieve full validated backend execution records"
    )
    execution.add_argument("--db", required=True, type=Path, help="SQLite database path")
    execution.add_argument("--job-id", required=True, help="generation job ID")
    execution.add_argument(
        "--attempt-id",
        help="attempt ID; defaults to the job's current attempt",
    )
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

    batch = commands.add_parser(
        "batch", help="run, resume, or report a durable sequential generation batch"
    )
    batch_commands = batch.add_subparsers(dest="batch_command", required=True)
    batch_run = batch_commands.add_parser("run", help="persist and execute a new batch")
    batch_run.add_argument("--db", required=True, type=Path)
    batch_run.add_argument("--output-dir", required=True, type=Path)
    batch_run.add_argument("--batch-key", required=True)
    batch_run.add_argument(
        "--requests-json",
        required=True,
        help="JSON array of engine-neutral requests; use - to read from standard input",
    )
    batch_run.add_argument("--max-attempts", type=int, default=1)
    _add_batch_admission_arguments(batch_run)
    _add_engine_arguments(batch_run)

    batch_resume = batch_commands.add_parser(
        "resume", help="resume an existing batch with its pinned execution evidence"
    )
    batch_resume.add_argument("--db", required=True, type=Path)
    batch_resume.add_argument("--output-dir", required=True, type=Path)
    batch_resume.add_argument("--batch-id", required=True)
    _add_batch_admission_arguments(batch_resume)
    _add_engine_arguments(batch_resume)

    batch_report = batch_commands.add_parser(
        "report", help="read-only execution, publication, and artifact-integrity report"
    )
    batch_report.add_argument("--db", required=True, type=Path)
    batch_report.add_argument("--batch-id", required=True)

    screen = commands.add_parser(
        "screen", help="run, resume, or report a versioned character-screening benchmark"
    )
    screen_commands = screen.add_subparsers(dest="screen_command", required=True)
    screen_run = screen_commands.add_parser("run", help="freeze and execute a new screening run")
    screen_run.add_argument("--manifest", required=True, type=Path)
    screen_run.add_argument("--data-dir", required=True, type=Path)
    screen_run.add_argument("--service-db", type=Path)
    screen_run.add_argument("--output-dir", type=Path)
    _add_admission_arguments(screen_run)
    _add_engine_arguments(screen_run, required_candidate=True)
    screen_run.add_argument("--max-cases", type=int)

    screen_resume = screen_commands.add_parser(
        "resume", help="reconcile and continue incomplete cases in an existing run"
    )
    screen_resume.add_argument("--run-id", required=True)
    screen_resume.add_argument("--data-dir", required=True, type=Path)
    screen_resume.add_argument("--service-db", type=Path)
    screen_resume.add_argument("--output-dir", type=Path)
    _add_admission_arguments(screen_resume)
    _add_engine_arguments(screen_resume)
    screen_resume.add_argument("--max-cases", type=int)

    screen_report = screen_commands.add_parser(
        "report", help="print a machine-readable report or readable case summary"
    )
    screen_report.add_argument("--run-id", required=True)
    screen_report.add_argument("--data-dir", required=True, type=Path)
    screen_report.add_argument("--service-db", type=Path)
    screen_report.add_argument("--output-dir", type=Path)
    screen_report.add_argument("--format", choices=("json", "summary"), default="json")

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
        command.add_argument(
            "--engine-backend",
            choices=("stable-diffusion-cpp", "comfyui", "llama-cpp"),
            default="stable-diffusion-cpp",
            help="engine-specific candidate compatibility rules",
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
        if options.command == "inference":
            return _run_inference(options)
        if options.command == "candidate":
            return _run_candidate(options)
        if options.command == "inventory":
            return _run_inventory(options)
        if options.command == "screen":
            return _run_screen(options)
        if options.command == "batch":
            if options.batch_command == "report":
                report = GenerationBatchService.report_database(
                    options.db, options.batch_id
                )
            else:
                if options.batch_command == "run":
                    requests = _parse_batch_requests(options.requests_json)
                else:
                    requests = None
                profile, demands = _batch_admission_inputs(options)
                adapter = _engine_adapter(options, options.output_dir)
                service = GenerationService(
                    options.db,
                    options.output_dir,
                    adapter=adapter,
                    admission_profile=profile,
                )
                batches = GenerationBatchService(service)
                if options.batch_command == "run":
                    assert requests is not None
                    report = batches.submit(
                        options.batch_key,
                        requests,
                        workload_demands=demands,
                        max_attempts=options.max_attempts,
                    )
                else:
                    report = batches.resume(
                        options.batch_id,
                        workload_demands=demands,
                    )
            _write_json(report, sys.stdout)
            return int(report.get("report_state") != "complete")
        if options.command == "submit":
            request = _parse_request(options.request_json)
            profile, demand = _admission_inputs(options)
            adapter = _engine_adapter(options, options.output_dir)
            if adapter is None:
                service = GenerationService(
                    options.db, options.output_dir, admission_profile=profile
                )
            else:
                service = GenerationService(
                    options.db,
                    options.output_dir,
                    adapter=adapter,
                    admission_profile=profile,
                )
            result = service.submit(
                options.idempotency_key, request, workload_demand=demand
            )
            _write_json(result.to_dict(), sys.stdout)
            return 1 if result.attention_required else 0

        if options.command == "enqueue":
            request = _parse_request(options.request_json)
            profile, demand = _admission_inputs(options)
            adapter = _engine_adapter(options, options.output_dir)
            if adapter is None:
                service = GenerationService(
                    options.db, options.output_dir, admission_profile=profile
                )
            else:
                service = GenerationService(
                    options.db,
                    options.output_dir,
                    adapter=adapter,
                    admission_profile=profile,
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
            adapter = _engine_adapter(options, options.output_dir)
            if adapter is None:
                service = GenerationService(options.db, options.output_dir)
            else:
                service = GenerationService(
                    options.db, options.output_dir, adapter=adapter
                )
            report = service.work(limit=options.limit)
            if report["status"] == "resource_busy":
                return _write_error(
                    "resource_busy", "local generation resource is busy", 1,
                    outcomes=report.get("outcomes", []),
                    resource_state=report.get("resource_state"),
                    resource_reason=report.get("resource_reason"),
                )
            _write_json(report, sys.stdout)
            return 1 if report["status"] == "attention_required" else int(any(
                item["status"] != "succeeded"
                or not item["termination_proven"]
                or item.get("resource_state") == "quarantined"
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

        if options.command == "execution":
            service = GenerationService(options.db, Path.cwd())
            _write_json(
                service.get_execution(options.job_id, options.attempt_id),
                sys.stdout,
            )
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
    except BackendPreparationError as error:
        return _write_error(
            "backend_preparation_failed", str(error), 1, code=error.code
        )
    except BackendEvidenceError as error:
        return _write_error("backend_evidence_error", str(error), 1)
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


def _run_inference(options: argparse.Namespace) -> int:
    """Run one local inference queue operation and write its safe report."""
    from .inference_service import InferenceService

    command = options.inference_command
    output_directory = getattr(options, "output_dir", Path.cwd())
    service_arguments: dict[str, object] = {}
    if command in {"enqueue", "worker"}:
        profile = load_admission_profile(
            options.inventory_report, options.admission_policy
        )
        service_arguments = {
            "configuration": _load_llama_cpp_configuration(options.runtime_config),
            "admission_profile": profile,
            "workload_demand": _load_inference_workload_demands(
                options.workload_demands
            ),
        }
        if command == "worker":
            service_arguments.update(
                runtime_qualification=_load_runtime_qualifications(
                    options.runtime_qualification
                ),
                candidate_declaration_path=options.candidate,
                candidate_trusted_evidence=parse_trusted_evidence(
                    options.trusted_evidence
                ),
            )
    service = InferenceService(
        database_path=options.db,
        output_directory=output_directory,
        **service_arguments,
    )

    if command == "enqueue":
        request = _parse_inference_request_file(options.request_file)
        response = service.enqueue(
            options.idempotency_key,
            request,
            deadline_seconds=options.deadline_seconds,
        )
    elif command == "worker":
        response = service.work(limit=options.limit)
    elif command == "cancel":
        response = service.cancel(options.job_id)
    elif command == "recover":
        response = service.recover()
    else:
        response = service.provenance(options.job_id)

    _write_json(response, sys.stdout)
    status = response.get("status") if isinstance(response, dict) else None
    if command == "worker":
        blocked = response.get("preflight_blocked", [])
        return 0 if status in {"complete", "idle"} and not blocked else 1
    if command == "recover":
        return 0 if status == "complete" else 1
    if command == "enqueue":
        return 0 if status == "queued" else 1
    if command in {"cancel", "provenance"} and status == "not_found":
        return 4
    return 0


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




def _run_screen(options: argparse.Namespace) -> int:
    """Run one headless screening operation against external durable storage."""
    try:
        data_directory = _require_external_path(options.data_dir, "screening data directory")
        ledger = ScreeningLedger(data_directory / "screening.sqlite3")

        if options.screen_command == "run":
            manifest_path = _require_external_path(options.manifest, "screening manifest")
            manifest = ScreeningManifest.from_json(manifest_path)
            service_database = options.service_db or data_directory / "generation.sqlite3"
            output_directory = options.output_dir or data_directory / "artifacts"
            profile, demand = _admission_inputs(options)
            adapter = _engine_adapter(options, output_directory)
            if adapter is None:
                raise ScreeningConfigurationError(
                    "screening runs require an explicitly selected pinned engine candidate"
                )
            identity = _screen_execution_identity(adapter, profile, demand)
            runner = ScreeningRunner(
                data_directory=data_directory,
                service_database=service_database,
                output_directory=output_directory,
                execution_identity=identity,
                service_factory=lambda: GenerationService(
                    service_database,
                    output_directory,
                    adapter=adapter,
                    admission_profile=profile,
                ),
                workload_demand=demand,
            )
            run_id = runner.create_run(manifest)
            sys.stderr.write(f"screening_run_id={run_id}\n")
            sys.stderr.flush()
            report = runner.resume(run_id, max_cases=options.max_cases)
        elif options.screen_command == "resume":
            frozen_run = ledger.get_run(options.run_id)
            frozen_identity = frozen_run["execution_identity"]
            assert isinstance(frozen_identity, dict)
            service_database = options.service_db or Path(
                str(frozen_identity.get("service_database", data_directory / "generation.sqlite3"))
            )
            output_directory = options.output_dir or Path(
                str(frozen_identity.get("output_directory", data_directory / "artifacts"))
            )
            if options.engine_candidate is None:
                if options.engine_trusted_evidence is not None:
                    raise ScreeningConfigurationError(
                        "--engine-trusted-evidence requires --engine-candidate"
                    )
                identity = None
                factory = None
                demand = None
            else:
                profile, demand = _admission_inputs(options)
                adapter = _engine_adapter(options, output_directory)
                assert adapter is not None
                identity = _screen_execution_identity(adapter, profile, demand)
                factory = lambda: GenerationService(
                    service_database,
                    output_directory,
                    adapter=adapter,
                    admission_profile=profile,
                )
            runner = ScreeningRunner(
                data_directory=data_directory,
                service_database=service_database,
                output_directory=output_directory,
                execution_identity=identity,
                service_factory=factory,
                workload_demand=demand,
            )
            report = runner.resume(options.run_id, max_cases=options.max_cases)
        else:
            frozen_run = ledger.get_run(options.run_id)
            frozen_identity = frozen_run["execution_identity"]
            assert isinstance(frozen_identity, dict)
            service_database = options.service_db or Path(
                str(frozen_identity.get("service_database", data_directory / "generation.sqlite3"))
            )
            output_directory = options.output_dir or Path(
                str(frozen_identity.get("output_directory", data_directory / "artifacts"))
            )
            runner = ScreeningRunner(
                data_directory=data_directory,
                service_database=service_database,
                output_directory=output_directory,
                execution_identity=None,
                service_factory=None,
            )
            report = runner.report(options.run_id)

        if options.screen_command == "report" and options.format == "summary":
            sys.stdout.write(render_summary(report))
        else:
            _write_json(report, sys.stdout)
        if options.screen_command == "report":
            return 0
        matrix_execution = report.get("matrix_execution")
        return (
            0
            if isinstance(matrix_execution, dict)
            and matrix_execution.get("execution_success") is True
            else 1
        )
    except ScreeningManifestError as error:
        return _write_error("screening_manifest_error", str(error), 2)
    except (ScreeningError, ScreeningStoreError, ValueError, OSError, sqlite3.Error) as error:
        return _write_error("screening_error", str(error), 2)
    except GenerationError as error:
        return _write_error("screening_execution_error", str(error), 3)


def _screen_execution_identity(
    adapter: object,
    profile: AdmissionProfile | None,
    demand: WorkloadDemand | None,
) -> dict[str, object]:
    """Freeze engine, admission evidence, and candidate identity for one run."""
    return {
        "adapter_id": adapter.adapter_id,
        "adapter_configuration": adapter.configuration,
        "admission_profile": None if profile is None else profile.to_dict(),
        "workload_demand": None if demand is None else demand.to_dict(),
    }


def _require_external_path(path: Path, label: str) -> Path:
    """Reject input paths that would bind private screening state into Git."""
    resolved = path.expanduser().resolve()
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            raise ScreeningConfigurationError(f"{label} must be outside Git worktrees")
    return resolved


def _run_candidate(options: argparse.Namespace) -> int:
    """Run one bounded candidate operation and preserve its static status."""
    trusted_evidence = (
        ()
        if options.trusted_evidence is None
        else parse_trusted_evidence(options.trusted_evidence)
    )
    selected_backend_kind = (
        COMFYUI_BACKEND_KIND
        if options.engine_backend == "comfyui"
        else LLAMA_CPP_BACKEND_KIND
        if options.engine_backend == "llama-cpp"
        else None
    )
    if options.candidate_command == "inspect":
        report = inspect_candidate(
            options.declaration,
            trusted_evidence=trusted_evidence,
            selected_backend_kind=selected_backend_kind,
        )
    elif options.candidate_command == "verify":
        report = verify_candidate(
            options.declaration,
            trusted_evidence=trusted_evidence,
            selected_backend_kind=selected_backend_kind,
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
            selected_backend_kind=selected_backend_kind,
        )
    _write_json(report, sys.stdout)
    return candidate_exit_code(str(report["status"]))


def _parse_request(source: str) -> GenerationRequest:
    """Parse strict engine-neutral JSON into a validated immutable request."""
    raw = sys.stdin.read() if source == "-" else source
    payload = json.loads(raw, object_pairs_hook=_unique_object_pairs)
    if not isinstance(payload, dict):
        raise InputValidationError("request JSON must contain an object")
    allowed_fields = {
        "prompt",
        "seed",
        "width",
        "height",
        "reference_ids",
        "reference_roles",
        "output_slot",
        "operation",
    }
    unknown_fields = sorted(set(payload) - allowed_fields)
    if unknown_fields:
        raise InputValidationError(f"unsupported request fields: {', '.join(unknown_fields)}")
    try:
        return GenerationRequest(**payload)
    except TypeError as error:
        raise InputValidationError(f"invalid request fields: {error}") from error


def _parse_inference_request_file(source: Path) -> LlamaCppRequest:
    """Read a bounded inference request file without placing its prompt in argv."""
    try:
        raw = source.read_bytes()
    except OSError as error:
        raise InputValidationError("cannot read inference request file") from error
    if len(raw) > MAX_INFERENCE_REQUEST_FILE_BYTES:
        raise InputValidationError("inference request file exceeds the size limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object_pairs
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise InputValidationError("invalid inference request JSON") from error
    if not isinstance(payload, dict) or set(payload) - {
        "kind", "prompt", "image_path"
    }:
        raise InputValidationError("inference request must contain only kind, prompt, and image_path")
    try:
        kind = InferenceKind(payload.get("kind"))
    except (TypeError, ValueError) as error:
        raise InputValidationError("inference request kind must be text or vision") from error
    prompt = payload.get("prompt")
    image_value = payload.get("image_path")
    if not isinstance(prompt, str):
        raise InputValidationError("inference request prompt must be text")
    if image_value is not None and not isinstance(image_value, str):
        raise InputValidationError("inference request image_path must be a string")
    image_path = None if image_value is None else Path(image_value).expanduser()
    if image_path is not None and not image_path.is_absolute():
        image_path = source.expanduser().resolve().parent / image_path
    try:
        return LlamaCppRequest(kind=kind, prompt=prompt, image_path=image_path)
    except (TypeError, ValueError) as error:
        raise InputValidationError(f"invalid inference request: {error}") from error


def _load_llama_cpp_configuration(source: Path) -> LlamaCppConfiguration:
    """Load the exact local runtime and component paths from one JSON file."""
    payload = _load_inference_json_object(source, "runtime configuration")
    required = {"executable_path", "model_component", "projector_component"}
    optional = {"max_tokens", "hardware_fingerprint_sha256"}
    if not required <= set(payload) or set(payload) - required - optional:
        raise InputValidationError("runtime configuration has an invalid shape")
    base = source.expanduser().resolve().parent
    try:
        return LlamaCppConfiguration(
            executable_path=_relative_path(payload["executable_path"], base),
            model_component=_parse_llama_cpp_component(
                payload["model_component"], base, "model_component"
            ),
            projector_component=_parse_llama_cpp_component(
                payload["projector_component"], base, "projector_component"
            ),
            **{
                name: payload[name]
                for name in optional
                if name in payload
            },
        )
    except (TypeError, ValueError) as error:
        raise InputValidationError(f"invalid runtime configuration: {error}") from error


def _load_runtime_qualifications(
    source: Path,
) -> dict[InferenceKind, RuntimeQualification]:
    """Load kind-specific build, stream, hardware, and resource evidence."""
    payload = _load_inference_json_object(source, "runtime qualification")
    if not payload or set(payload) - {kind.value for kind in InferenceKind}:
        raise InputValidationError("runtime qualification keys must be text or vision")
    base = source.expanduser().resolve().parent
    qualifications: dict[InferenceKind, RuntimeQualification] = {}
    for name, raw in payload.items():
        kind = InferenceKind(name)
        record = _require_inference_object(
            raw,
            {"build", "response_stream", "hardware", "resources"},
            label=f"{name} qualification",
        )
        build_raw = _require_inference_object(
            record["build"],
            {
                "executable_path", "source_version", "binary_sha256", "build_id",
                "evidence_sha256",
            },
            label=f"{name} build evidence",
        )
        stream_raw = _require_inference_object(
            record["response_stream"],
            {
                "executable_sha256", "source_version", "model_sha256",
                "projector_sha256", "inference_kind", "schema_sha256",
                "stdout_contract", "stderr_contract", "evidence_sha256",
            },
            label=f"{name} response-stream evidence",
        )
        hardware_raw = _require_inference_object(
            record["hardware"],
            {
                "executable_sha256", "model_sha256", "projector_sha256",
                "hardware_fingerprint_sha256", "assessment", "evidence_sha256",
            },
            label=f"{name} hardware evidence",
        )
        resources_raw = _require_inference_object(
            record["resources"],
            {
                "executable_sha256", "model_sha256", "projector_sha256",
                "hardware_fingerprint_sha256", "max_tokens", "measured_peak_bytes",
            "available_memory_bytes", "context_tokens", "max_image_pixels",
            "evidence_sha256",
            },
            label=f"{name} resource evidence",
        )
        try:
            stream_raw["inference_kind"] = InferenceKind(
                stream_raw["inference_kind"]
            )
            if stream_raw["inference_kind"] is not kind:
                raise ValueError("response stream kind does not match its key")
            qualifications[kind] = RuntimeQualification(
                build=RuntimeBuildEvidence(
                    executable_path=_relative_path(
                        build_raw["executable_path"], base
                    ),
                    **{
                        key: value
                        for key, value in build_raw.items()
                        if key != "executable_path"
                    },
                ),
                response_stream=ResponseStreamVerification(**stream_raw),
                hardware=HardwareCompatibilityEvidence(**hardware_raw),
                resources=ResourceDemandEvidence(**resources_raw),
            )
        except (TypeError, ValueError) as error:
            raise InputValidationError(
                f"invalid {name} runtime qualification: {error}"
            ) from error
    return qualifications


def _load_inference_json_object(source: Path, label: str) -> dict[str, object]:
    try:
        with source.open("rb") as stream:
            raw = stream.read(_MAX_INFERENCE_JSON_BYTES + 1)
    except OSError as error:
        raise InputValidationError(f"cannot read {label}") from error
    if len(raw) > _MAX_INFERENCE_JSON_BYTES:
        raise InputValidationError(f"{label} exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object_pairs)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise InputValidationError(f"invalid {label} JSON") from error
    if not isinstance(payload, dict):
        raise InputValidationError(f"{label} must be a JSON object")
    return payload


def _load_inference_workload_demands(
    source: Path,
) -> dict[InferenceKind, WorkloadDemand]:
    """Load a strict map of independent text and vision resource demands."""
    payload = _load_inference_json_object(source, "workload demands")
    if not payload or set(payload) - {kind.value for kind in InferenceKind}:
        raise InputValidationError("workload demand keys must be text or vision")
    demands: dict[InferenceKind, WorkloadDemand] = {}
    for name, value in payload.items():
        try:
            demand = parse_workload_demand(value)
        except (TypeError, ValueError, InventoryValidationError) as error:
            raise InputValidationError(f"invalid {name} workload demand") from error
        if demand.kind != name:
            raise InputValidationError(f"{name} workload demand has a mismatched kind")
        demands[InferenceKind(name)] = demand
    return demands


def _require_inference_object(
    value: object, keys: set[str], *, label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InputValidationError(f"{label} has an invalid shape")
    return value


def _relative_path(value: object, base: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("file path must be a non-empty string")
    path = Path(value).expanduser()
    return path if path.is_absolute() else base / path


def _parse_llama_cpp_component(
    value: object, base: Path, label: str
) -> LlamaCppComponent:
    component = _require_inference_object(
        value, {"role", "path", "sha256"}, label=label
    )
    return LlamaCppComponent(
        role=component["role"],
        path=_relative_path(component["path"], base),
        sha256=component["sha256"],
    )


def _parse_batch_requests(source: str) -> tuple[GenerationRequest, ...]:
    """Parse a strict JSON array and validate each engine-neutral request."""
    raw = sys.stdin.read() if source == "-" else source
    try:
        payload = json.loads(raw, object_pairs_hook=_unique_object_pairs)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise InputValidationError(f"invalid batch requests JSON: {error}") from error
    if not isinstance(payload, list) or not payload:
        raise InputValidationError("batch requests JSON must be a non-empty array")
    requests: list[GenerationRequest] = []
    for item in payload:
        if not isinstance(item, dict):
            raise InputValidationError("each batch request must be a JSON object")
        requests.append(_parse_request(json.dumps(item, ensure_ascii=False)))
    return tuple(requests)


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
