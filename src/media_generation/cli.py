"""Command-line interface for submitting and inspecting local generations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .domain import GenerationRequest
from .errors import (
    GenerationExecutionError,
    IdempotencyConflictError,
    InputValidationError,
    RecordNotFoundError,
    UnknownReferenceError,
    UnsupportedCapabilityError,
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
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--db", required=True, type=Path, help="SQLite database path")
        command.add_argument("--id", required=True, help=f"{name} ID")

    provenance = commands.add_parser("provenance", help="retrieve request, job, attempt, and artifact")
    provenance.add_argument("--db", required=True, type=Path, help="SQLite database path")
    provenance.add_argument("--job-id", required=True, help="generation job ID")

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
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    """Run one CLI operation and emit a single JSON response."""
    parser = build_parser()
    options = parser.parse_args(arguments)
    try:
        if options.command == "inventory":
            return _run_inventory(options)
        if options.command == "submit":
            request = _parse_request(options.request_json)
            service = GenerationService(options.db, options.output_dir)
            result = service.submit(options.idempotency_key, request)
            _write_json(result.to_dict(), sys.stdout)
            return 0

        service = GenerationService(options.db, Path("."))
        if options.command == "request":
            response = service.get_request(options.id)
        elif options.command == "job":
            response = service.get_job(options.id).to_dict()
        elif options.command == "artifact":
            response = service.get_artifact(options.id).to_dict()
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
