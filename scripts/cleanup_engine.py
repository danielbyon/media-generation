"""Coordinate validated cleanup and construct stable operator reports."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from .cleanup_fs import (
    Candidate,
    _capture_active_environment_directories,
    _flags_for_directory,
    _lstat_at,
    _remove_directory_at,
    _remove_file_at,
    _scan_candidates,
    _validate_candidate,
)
from .cleanup_model import (
    CandidateError,
    CategorySummary,
    CleanupReport,
    CleanupError,
    _CATEGORIES,
    SCHEMA_VERSION,
)
from .cleanup_scope import _assert_path_matches_descriptor, tracked_paths


def _empty_category() -> CategorySummary:
    return {
        "candidate_count": 0,
        "planned_count": 0,
        "removed_count": 0,
        "skipped_count": 0,
        "error_count": 0,
        "estimated_removable_bytes": 0,
        "reclaimed_bytes": 0,
    }


def _new_report(root: Path, *, mode: str, dry_run: bool) -> CleanupReport:
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "dry_run": dry_run,
        "worktree": os.fspath(root),
        "status": "ok",
        "summary": _empty_category(),
        "categories": {category: _empty_category() for category in _CATEGORIES},
        "entries": [],
    }


def _add_report_entry(
    report: CleanupReport,
    *,
    path: str,
    category: str,
    kind: str,
    status: str,
    reason: str,
    estimated_bytes: int = 0,
    reclaimed_bytes: int = 0,
) -> None:
    category_counts = report["categories"][category]
    counts = report["summary"]
    for target in (counts, category_counts):
        target["candidate_count"] += 1
        target[f"{status}_count"] += 1
        target["estimated_removable_bytes"] += estimated_bytes
        target["reclaimed_bytes"] += reclaimed_bytes
    report["entries"].append(
        {
            "path": path,
            "category": category,
            "kind": kind,
            "status": status,
            "reason": reason,
            "estimated_bytes": estimated_bytes,
            "reclaimed_bytes": reclaimed_bytes,
        }
    )


def _finalize_report(report: CleanupReport) -> CleanupReport:
    summary = report["summary"]
    if summary["error_count"] or summary["skipped_count"]:
        report["status"] = "partial"
    return report


def _reclaimed_delta(before: int, after: int) -> int:
    return max(0, after - before)


def _available_bytes(root_fd: int) -> int:
    """Return free bytes for the filesystem containing the pinned root."""

    filesystem = os.fstatvfs(root_fd)
    return filesystem.f_bavail * filesystem.f_frsize


def run_cleanup(
    root: Path | str,
    *,
    dry_run: bool = False,
    deep: bool = False,
    include_venv: bool = False,
    confirmed: bool = False,
    confirmation: str | None = None,
    locked_root_fd: int | None = None,
    active_environment_pins: frozenset[tuple[int, int]] | None = None,
) -> CleanupReport:
    """Validate and remove eligible candidates below a proven worktree root.

    ``confirmation`` is intended for command-line interaction.  Noninteractive
    callers must pass ``confirmed=True`` explicitly to authorize deep cleanup.
    """

    root_path = Path(root)
    if locked_root_fd is None:
        root_path = root_path.resolve(strict=True)
    report = _new_report(root_path, mode="deep" if deep else "default", dry_run=dry_run)
    if deep and not include_venv:
        _add_report_entry(
            report,
            path=".venv",
            category="virtual-environment",
            kind="directory",
            status="error",
            reason="deep cleanup requires the explicit --include-venv selector",
        )
        return _finalize_report(report)

    if deep and not dry_run and not confirmed:
        if confirmation is None:
            _add_report_entry(
                report,
                path=".venv",
                category="virtual-environment",
                kind="directory",
                status="error",
                reason="deep cleanup requires explicit interactive confirmation",
            )
            return _finalize_report(report)
        if confirmation != "remove .venv":
            _add_report_entry(
                report,
                path=".venv",
                category="virtual-environment",
                kind="directory",
                status="error",
                reason="interactive confirmation did not authorize removal",
            )
            return _finalize_report(report)

    owns_root_fd = locked_root_fd is None
    if active_environment_pins is None:
        active_environment_pins = _capture_active_environment_directories()
    root_fd = -1
    try:
        if locked_root_fd is None:
            root_fd = os.open(root_path, _flags_for_directory())
            _assert_path_matches_descriptor(root_path, root_fd)
        else:
            root_fd = locked_root_fd
        _assert_path_matches_descriptor(root_path, root_fd)
        tracked = tracked_paths(root_fd)
        candidates = _scan_candidates(root_fd)
        if deep:
            venv_status: os.stat_result | None
            try:
                venv_status = _lstat_at(root_fd, ".venv")
            except FileNotFoundError:
                venv_status = None
            if venv_status is None:
                candidates = [
                    candidate for candidate in candidates if candidate.category != "virtual-environment"
                ]
            elif stat.S_ISLNK(venv_status.st_mode):
                candidates.append(
                    Candidate(
                        ".venv",
                        "virtual-environment",
                        "directory",
                        None,
                        "candidate is a symbolic link",
                    )
                )
            elif stat.S_ISDIR(venv_status.st_mode):
                candidates.append(
                    Candidate(
                        ".venv",
                        "virtual-environment",
                        "directory",
                        venv_status,
                    )
                )
            else:
                candidates.append(
                    Candidate(
                        ".venv",
                        "virtual-environment",
                        "directory",
                        venv_status,
                        ".venv is not a directory",
                    )
                )
        candidates = sorted(candidates, key=lambda candidate: candidate.path)
        free_before = _available_bytes(root_fd)

        for candidate in candidates:
            parent_fd = -1
            estimate = 0
            try:
                parent_fd, initial, facts, estimate = _validate_candidate(
                    root_fd,
                    root_path,
                    candidate,
                    tracked,
                    active_environment_pins,
                )
                if dry_run:
                    _add_report_entry(
                        report,
                        path=candidate.path,
                        category=candidate.category,
                        kind=candidate.kind,
                        status="planned",
                        reason="validated against the cleanup allowlist",
                        estimated_bytes=estimate,
                    )
                elif candidate.kind == "file":
                    _remove_file_at(parent_fd, Path(candidate.path).name, initial)
                    _add_report_entry(
                        report,
                        path=candidate.path,
                        category=candidate.category,
                        kind=candidate.kind,
                        status="removed",
                        reason="validated single-link bytecode file",
                        estimated_bytes=estimate,
                    )
                else:
                    assert facts is not None
                    _remove_directory_at(
                        parent_fd,
                        Path(candidate.path).name,
                        initial,
                        facts,
                        allow_symlinks=candidate.category == "virtual-environment",
                    )
                    _add_report_entry(
                        report,
                        path=candidate.path,
                        category=candidate.category,
                        kind=candidate.kind,
                        status="removed",
                        reason=("confirmed removal of all local .venv contents, including custom files" if candidate.category == "virtual-environment" else "validated project-owned regenerable directory"),
                        estimated_bytes=estimate,
                    )
            except (CandidateError, OSError, UnicodeError) as error:
                _add_report_entry(
                    report,
                    path=candidate.path,
                    category=candidate.category,
                    kind=candidate.kind,
                    status="error",
                    reason=str(error) or error.__class__.__name__,
                    estimated_bytes=estimate,
                )
            finally:
                if parent_fd >= 0:
                    os.close(parent_fd)

        if not dry_run:
            summary = report["summary"]
            assert isinstance(summary, dict)
            summary["reclaimed_bytes"] = _reclaimed_delta(
            free_before, _available_bytes(root_fd)
            )
            return _finalize_report(report)
        return _finalize_report(report)
    finally:
        if owns_root_fd and root_fd >= 0:
            os.close(root_fd)


def format_human_report(report: CleanupReport) -> str:
    """Render a concise report suitable for a terminal operator."""

    summary = report["summary"]
    lines = [
        f"Cleanup worktree: {report['worktree']}",
        f"Mode: {report['mode']}{' (dry run)' if report['dry_run'] else ''}",
        f"Status: {report['status']}",
    ]
    for name in _CATEGORIES:
        counts = report["categories"][name]
        lines.append(
            f"{name}: candidates={counts['candidate_count']} "
            f"planned={counts['planned_count']} removed={counts['removed_count']} "
            f"skipped={counts['skipped_count']} errors={counts['error_count']} "
            f"estimated={counts['estimated_removable_bytes']} bytes "
            f"reclaimed={counts['reclaimed_bytes']} bytes"
        )
    lines.append(
        "Total: "
        f"candidates={summary['candidate_count']} planned={summary['planned_count']} "
        f"removed={summary['removed_count']} skipped={summary['skipped_count']} "
        f"errors={summary['error_count']} "
        f"estimated_removable={summary['estimated_removable_bytes']} bytes "
        f"actual_reclaimed={summary['reclaimed_bytes']} bytes"
    )
    for entry in report["entries"]:
        lines.append(
            f"- {entry['status']}: {entry['path']} [{entry['category']}]: {entry['reason']}"
        )
    return "\n".join(lines)
