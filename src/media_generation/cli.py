"""Command-line interface for submitting and inspecting local generations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .domain import GenerationRequest, ArtifactSource
from .errors import (
    GenerationExecutionError,
    IdempotencyConflictError,
    InputValidationError,
    RecordNotFoundError,
    UnknownReferenceError,
    UnsupportedCapabilityError,
    PublicationError,
    PublicationIncompleteError,
    ArtifactIntegrityError,
)
from .service import GenerationService


class _JsonArgumentParser(argparse.ArgumentParser):
    """Write parser syntax failures using the CLI's structured error format."""

    def error(self, message: str) -> None:
        _write_json(
            {"error": {"code": "argument_error", "message": message}},
            sys.stderr,
        )
        raise SystemExit(2)


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

    provenance = commands.add_parser("provenance", help="retrieve request, job, attempt, and artifact")
    provenance.add_argument("--db", required=True, type=Path, help="SQLite database path")
    provenance.add_argument("--job-id", required=True, help="generation job ID")
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
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one CLI operation and emit a single JSON response."""
    parser = build_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == "submit":
            request = _parse_request(options.request_json)
            service = GenerationService(options.db, options.output_dir)
            result = service.submit(options.idempotency_key, request)
            _write_json(result.to_dict(), sys.stdout)
            return 0

        if options.command in {"import", "reconcile"}:
            service = GenerationService(options.db, options.output_dir)
            if options.command == "reconcile":
                response = service.reconcile()
            else:
                parents = json.loads(options.sources_json, object_pairs_hook=_unique_object_pairs)
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

        service = GenerationService(options.db, Path("."))
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
    except GenerationExecutionError as error:
        return _write_error("generation_failed", str(error), 1, job_id=error.job_id)
    except PublicationIncompleteError as error:
        return _write_error("publication_incomplete", str(error), 1,
                            job_id=error.job_id, recovery=error.recovery)
    except PublicationError as error:
        return _write_error("publication_incomplete", str(error), 1)
    except ArtifactIntegrityError as error:
        return _write_error("artifact_integrity", str(error), 1)
    except OSError as error:
        return _write_error("storage_error", str(error), 1)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        return _write_error("validation_error", f"invalid request JSON: {error}", 2)


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


def _write_error(code: str, message: str, exit_code: int, **details: str) -> int:
    """Write a machine-readable failure to stderr without a success-shaped response."""
    _write_json({"error": {"code": code, "message": message, **details}}, sys.stderr)
    return exit_code
