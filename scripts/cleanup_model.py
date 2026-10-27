"""Shared constants and failures for the standalone cleanup command."""

from __future__ import annotations

from typing import TypedDict

SCHEMA_VERSION = 1
_PYTEST_CACHE_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
_PROTECTED_DIRECTORY_NAMES = {
    ".git",
    ".artifact-cleanup",
    ".venv",
    ".chatgpt",
    ".serena",
    ".codegraph",
    ".playwright-cli",
    "artifacts",
    "coverage",
    "dist",
    "evidence",
    "fixtures",
    "node_modules",
    "snapshots",
    "test-results",
}
_MAX_SCAN_ENTRIES = 200_000
_MAX_TREE_ENTRIES = 200_000
_MAX_TREE_DEPTH = 128
_MAX_METADATA_FILE_SIZE = 4 * 1024 * 1024
_CATEGORIES = (
    "bytecode",
    "pytest-cache",
    "setuptools-metadata",
    "setuptools-build",
    "virtual-environment",
    "coordination",
)


class CategorySummary(TypedDict):
    """Counters reported for one cleanup category."""

    candidate_count: int
    planned_count: int
    removed_count: int
    skipped_count: int
    error_count: int
    estimated_removable_bytes: int
    reclaimed_bytes: int


class ReportEntry(TypedDict):
    """One candidate outcome in a cleanup report."""

    path: str
    category: str
    kind: str
    status: str
    reason: str
    estimated_bytes: int
    reclaimed_bytes: int


class CleanupReport(TypedDict):
    """Stable machine-readable cleanup report consumed by the CLI."""

    schema_version: int
    mode: str
    dry_run: bool
    worktree: str
    status: str
    summary: CategorySummary
    categories: dict[str, CategorySummary]
    entries: list[ReportEntry]
_EGG_INFO_NAMES = {
    "PKG-INFO",
    "SOURCES.txt",
    "dependency_links.txt",
    "entry_points.txt",
    "requires.txt",
    "top_level.txt",
}


class CleanupError(RuntimeError):
    """Indicate that cleanup could not establish a safe operating boundary."""


class CandidateError(RuntimeError):
    """Indicate that one candidate changed or failed ownership validation."""
