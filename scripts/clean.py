#!/usr/bin/env python3
"""Command-line interface for verified worktree-scoped artifact cleanup."""

from __future__ import annotations

import sys

# Help and read-only cleanup modes must not create import bytecode candidates.
sys.dont_write_bytecode = True

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if __package__:
    from .cleanup_engine import (
        _add_report_entry,
        _new_report,
        format_human_report,
        run_cleanup,
    )
    from .cleanup_model import CleanupError, CleanupReport
    from .cleanup_scope import (
        resolve_worktree,
        resolve_worktree_pinned,
        worktree_lock,
    )
else:
    _original_sys_path = tuple(sys.path)
    sys.path.insert(0, os.fspath(_SCRIPT_DIRECTORY.parent))
    try:
        from scripts.cleanup_engine import (
            _add_report_entry,
            _new_report,
            format_human_report,
            run_cleanup,
        )
        from scripts.cleanup_model import CleanupError, CleanupReport
        from scripts.cleanup_scope import (
            resolve_worktree,
            resolve_worktree_pinned,
            worktree_lock,
        )
    finally:
        sys.path[:] = _original_sys_path

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Remove only verified regenerable outputs from this Git worktree. "
            "Use --dry-run to inspect the plan without changing files."
        )
    )
    parser.add_argument("--dry-run", action="store_true", help="report without changing files")
    parser.add_argument("--json", action="store_true", help="write one machine-readable JSON report")
    subcommands = parser.add_subparsers(dest="command")
    deep = subcommands.add_parser("deep", help="remove all local .venv contents, including custom files", description="Warning: confirmed deep cleanup removes all .venv contents, including custom files. Stop all writers before cleanup.")
    deep.add_argument(
        "--include-venv",
        action="store_true",
        help="remove all contents of a verified local .venv, including custom files",
    )
    deep.add_argument(
        "--confirm",
        action="store_true",
        help="affirm deep removal without an interactive prompt",
    )
    deep.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    deep.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    return parser


def _emit(report: CleanupReport, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    else:
        print(format_human_report(report))


def _report_exit_code(report: CleanupReport) -> int:
    return 0 if report["status"] == "ok" else 1


def _busy_report(root: Path, *, mode: str, dry_run: bool) -> CleanupReport:
    report = _new_report(root, mode=mode, dry_run=dry_run)
    report["status"] = "busy"
    _add_report_entry(
        report,
        path=".",
        category="coordination",
        kind="directory",
        status="error",
        reason="another cooperative worktree producer holds the cleanup lock",
    )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Run the cleanup command and return a process exit status."""

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    deep = arguments.command == "deep"
    dry_run = bool(arguments.dry_run)
    json_output = bool(arguments.json)
    include_venv = bool(getattr(arguments, "include_venv", False))
    confirmed = bool(getattr(arguments, "confirm", False))
    mode = "deep" if deep else "default"
    try:
        authority = resolve_worktree_pinned(Path(sys.argv[0]))
        root = authority.path
    except (CleanupError, OSError) as error:
        print(f"cleanup: {error}", file=sys.stderr)
        return 2

    try:
        with worktree_lock(authority, blocking=False) as root_fd:
            confirmation: str | None = None
            if deep and include_venv and not dry_run and not confirmed:
                if sys.stdin.isatty():
                    print("Warning: all .venv contents, including custom files, will be removed. Type 'remove .venv' to confirm: ", end="", file=sys.stderr, flush=True)
                    confirmation = sys.stdin.readline().rstrip("\r\n")
                else:
                    confirmation = ""
            report = run_cleanup(
                root,
                dry_run=dry_run,
                deep=deep,
                include_venv=include_venv,
                confirmed=confirmed,
                confirmation=confirmation,
                locked_root_fd=root_fd,
                active_environment_pins=authority.active_environment_pins,
            )
    except BlockingIOError:
        report = _busy_report(root, mode=mode, dry_run=dry_run)
    except KeyboardInterrupt:
        report = _new_report(root, mode=mode, dry_run=dry_run)
        report["status"] = "partial"
        _add_report_entry(
            report,
            path=".",
            category="coordination",
            kind="directory",
            status="error",
            reason="cleanup was interrupted; rerun to continue safely",
        )
        _emit(report, json_output=json_output)
        return 130
    except CleanupError as error:
        print(f"cleanup: {error}", file=sys.stderr)
        return 2

    finally:
        os.close(authority.root_fd)

    _emit(report, json_output=json_output)
    return _report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
