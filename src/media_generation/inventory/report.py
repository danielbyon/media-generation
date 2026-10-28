"""Inventory orchestration, status semantics, transcripts, and atomic output.

Report writing and evidence completeness are separate outcomes.  A successful
write can still carry a ``partial`` or ``blocked`` host-inventory status, and the
process exit code distinguishes those cases for automation.  Capability support
is never promoted beyond advertised or declared evidence.
"""

from __future__ import annotations

import errno
import importlib.metadata
import json
import os
import secrets
import stat
import tempfile
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from .components import inspect_bundles
from .contract import validate_inventory_report
from .discovery import discover_runtimes
from .fingerprint import build_environment_fingerprint
from .host import collect_host
from .manifest import InventoryManifest, empty_manifest, parse_manifest
from .probes import (
    LocalObservationSource,
    ObservationSource,
    ProbeLedger,
    ReplayObservationSource,
    sanitize_text,
)
from .schema import (
    SCHEMA_NAME,
    SCHEMA_VERSION,
    Finding,
    InventoryOutputError,
    InventoryStatus,
    InventoryValidationError,
    Severity,
    utc_now,
)


TRANSCRIPT_LIMIT = 1024 * 1024
TRANSCRIPT_MARKER = b"\n[transcript truncated]\n"
MAX_PUBLICATION_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_PUBLICATION_SYMLINK_TARGET_BYTES = 4096
SEVERITY_ORDER = {"blocked": 0, "warning": 1, "info": 2}


@dataclass(frozen=True, slots=True)
class InventoryOptions:
    """One collection request; the output directory is written separately."""

    output_directory: Path
    manifest_path: Path | None = None
    hash_components: bool = False
    hash_limit_bytes: int = 16 * 1024 * 1024 * 1024
    replay_path: Path | None = None

    def __post_init__(self) -> None:
        """Reject options that would produce ambiguous collection behavior."""
        if self.hash_limit_bytes < 1:
            raise InventoryValidationError("hash limit must be a positive byte count")


@dataclass(frozen=True, slots=True)
class InventoryResult:
    """Complete in-memory report plus the status used for process exit."""

    host_inventory_status: str
    exit_code: int
    inventory: dict[str, object]
    transcript: str
    summary: dict[str, object]
    publication: dict[str, str] | None = None


def _collector_version() -> str:
    """Return the installed package version without a network lookup."""
    try:
        return importlib.metadata.version("media-generation")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - source checkout
        return "unknown"


def _run_id() -> str:
    """Return a sortable, non-secret run identifier."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"inv_{stamp}_{secrets.token_hex(4)}"


def _status_from_probes(
    ledger: ProbeLedger,
    *,
    host_degraded: bool,
    runtime_degraded: bool,
    bundle_degraded: bool,
) -> tuple[str, list[str]]:
    """Separate host completeness from successful report writing."""
    reasons: list[str] = []
    required_failures = [
        record
        for record in ledger.records
        if record.criticality == "required" and record.status != "ok"
    ]
    blocked_probes = {"host:os-identity", "host:memory"}
    blocked = any(record.probe_id in blocked_probes for record in required_failures)
    for record in required_failures:
        reasons.append(f"required_probe_{record.status}:{record.probe_id}")
    if host_degraded:
        reasons.append("host_observation_incomplete")
    if runtime_degraded:
        reasons.append("configured_runtime_incomplete")
    if bundle_degraded:
        reasons.append("configured_bundle_incomplete")
    if blocked:
        return InventoryStatus.BLOCKED.value, reasons
    if reasons:
        return InventoryStatus.PARTIAL.value, reasons
    return InventoryStatus.OK.value, reasons


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Return findings in a deterministic, status-first order."""
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 99),
            item.code,
            item.subject,
            item.message,
        ),
    )


def _sorted_probe_dicts(ledger: ProbeLedger) -> list[dict[str, object]]:
    """Return probe records in deterministic category/id order."""
    records = sorted(
        ledger.records,
        key=lambda item: (item.category, item.probe_id, item.started_at),
    )
    return [record.to_dict() for record in records]


def _model_inventory(
    manifest: InventoryManifest, *, configuration: str
) -> dict[str, object]:
    """Describe declared model coverage without implying filesystem absence."""
    bundles_configured = bool(manifest.bundles)
    if configuration == "not_configured":
        reason = "manifest_not_supplied"
    elif not bundles_configured:
        reason = "no_bundles_declared"
    else:
        reason = None
    return {
        "inspection": "configured" if bundles_configured else "not_configured",
        "reason": reason,
        "model_roots": {
            "status": "configured" if manifest.model_roots else "not_configured",
            "items": [
                {
                    "id": root.id,
                    "path": str(root.path),
                    "inspection": "boundary_only_not_scanned",
                }
                for root in manifest.model_roots
            ],
        },
        "bundles": {
            "status": "configured" if bundles_configured else "not_configured",
            "declared_count": len(manifest.bundles),
        },
    }


def _build_transcript(
    *,
    ledger: ProbeLedger,
    inventory: dict[str, object],
    status: str,
    configuration: str,
    mode: str,
    findings: list[Finding],
) -> str:
    """Render a deterministic, human-inspectable discovery transcript."""
    run = inventory["run"]
    assert isinstance(run, dict)
    fingerprint = inventory["environment_fingerprint"]
    assert isinstance(fingerprint, dict)
    evidence = inventory["evidence_gate"]
    assert isinstance(evidence, dict)
    lines: list[str] = [
        "media-generation inventory transcript",
        f"schema: {SCHEMA_NAME} v{SCHEMA_VERSION}",
        f"run_id: {run['run_id']}",
        f"collection_mode: {mode}",
    ]
    if mode == "replay":
        lines.append("SYNTHETIC REPLAY: recorded fixture observations; not live host evidence.")
    lines.extend(
        [
            f"configuration_inspection: {configuration}",
            f"host_inventory_status: {status}",
            f"report_written: {str(bool(evidence['report_written'])).lower()}",
        f"evidence_origin: {evidence['evidence_origin']}",
            f"apex_verification: {evidence['apex_verification']}",
            f"capability_qualification: {evidence['capability_qualification']}",
            f"environment_fingerprint: {fingerprint['digest']}",
            f"manifest_digest: {run.get('manifest_digest') or 'not_configured'}",
            "",
            "probes:",
        ]
    )
    records = sorted(
        ledger.records,
        key=lambda item: (item.category, item.probe_id, item.started_at),
    )
    for record in records:
        command = " ".join(record.command) if record.command else record.source
        lines.append(
            f"[{record.category}] {record.probe_id} [{record.status}] "
            f"{record.duration_ms}ms {sanitize_text(command, home=Path.home())}"
        )
        if record.reason is not None:
            lines.append(f"  reason: {record.reason}")
        if record.detail:
            lines.append(
                "  detail: "
                + sanitize_text(record.detail, home=Path.home(), limit=1000).replace("\n", " ")
            )
        if record.excerpt:
            for excerpt_line in record.excerpt.splitlines():
                lines.append(f"  | {excerpt_line}")
    lines.extend(["", "findings:"])
    for finding in findings:
        lines.append(f"[{finding.severity}] {finding.code} {finding.subject}: {finding.message}")
    lines.extend(
        [
            "",
            "evidence gate:",
            f"  report_written: {evidence['report_written']}",
            f"  host_inventory_status: {evidence['host_inventory_status']}",
            f"  configuration_inspection: {evidence['configuration_inspection']}",
            f"  evidence_origin: {evidence['evidence_origin']}",
            f"  apex_verification: {evidence['apex_verification']}",
            f"  capability_qualification: {evidence['capability_qualification']}",
        ]
    )
    return _cap_transcript("\n".join(lines) + "\n")


def _cap_transcript(text: str, limit: int = TRANSCRIPT_LIMIT) -> str:
    """Return UTF-8 text no larger than the limit in bytes, marker included."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = TRANSCRIPT_MARKER
    if limit <= len(marker):
        return marker[:limit].decode("utf-8", errors="ignore")
    truncated = encoded[: limit - len(marker)].decode("utf-8", errors="ignore").rstrip()
    return truncated + marker.decode("utf-8")


def _set_report_written(text: str, written: bool) -> str:
    """Rewrite metadata publication lines in an already rendered transcript."""
    value = str(bool(written)).lower()
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip(" ")
        if stripped.startswith("report_written: false"):
            indentation = line[: len(line) - len(stripped)]
            line = indentation + stripped.replace(
                "report_written: false", f"report_written: {value}", 1
            )
        lines.append(line)
    return "".join(lines)


def _resolve_operator_path(value: Path | None, *, label: str) -> Path | None:
    """Resolve an operator-supplied path or raise a structured validation error."""
    if value is None:
        return None
    try:
        return Path(value).expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise InventoryValidationError(f"{label} path cannot be resolved: {value}") from error


def collect_inventory(options: InventoryOptions) -> InventoryResult:
    """Collect one inventory report without writing files."""
    started_at = utc_now()
    started = time.monotonic()
    manifest_path = _resolve_operator_path(options.manifest_path, label="manifest")
    replay_path = _resolve_operator_path(options.replay_path, label="replay document")
    manifest: InventoryManifest = (
        parse_manifest(manifest_path) if manifest_path is not None else empty_manifest()
    )
    configuration = "configured" if manifest_path is not None else "not_configured"
    if replay_path is not None:
        source: ObservationSource = ReplayObservationSource.from_path(replay_path)
        mode = "replay"
    else:
        source = LocalObservationSource()
        mode = "local"
    ledger = ProbeLedger(source)
    host_facts = collect_host(ledger, manifest.policy)
    runtimes, runtime_findings, runtime_degraded = discover_runtimes(ledger, manifest)
    bundles, bundle_findings, bundle_degraded = inspect_bundles(
        ledger,
        manifest,
        hash_components=options.hash_components,
        hash_limit_bytes=options.hash_limit_bytes,
    )
    fingerprint = build_environment_fingerprint(host_facts.data, runtimes)
    status, status_reasons = _status_from_probes(
        ledger,
        host_degraded=host_facts.degraded,
        runtime_degraded=runtime_degraded,
        bundle_degraded=bundle_degraded,
    )
    findings = list(host_facts.findings) + list(runtime_findings) + list(bundle_findings)
    if manifest_path is None:
        findings.append(
            Finding(
                code="configuration_not_configured",
                severity=Severity.INFO.value,
                subject="configuration",
                message=(
                    "No manifest was supplied; model roots, component bundles, recipes, "
                    "and declared capabilities were not inspected (not_configured)."
                ),
            )
        )
    findings.append(
        Finding(
            code="capability_claims_unverified",
            severity=Severity.INFO.value,
            subject="capabilities",
            message=(
                "All capability entries are advertised or operator-declared only; "
                "no local execution, APEX verification, or qualification was performed."
            ),
        )
    )
    failed_probes = [
        record
        for record in ledger.records
        if record.status not in {"ok", "skipped"}
    ]
    if failed_probes:
        findings.append(
            Finding(
                code="probe_failures_present",
                severity=Severity.INFO.value,
                subject="probes",
                message=(
                    f"{len(failed_probes)} probe(s) did not complete successfully, including "
                    "optional absence; see probes[] for reasons."
                ),
            )
        )
    findings = _sorted_findings(findings)
    finished_at = utc_now()
    duration_ms = int((time.monotonic() - started) * 1000)
    run_id = _run_id()
    evidence_gate = {
        "report_written": False,
        "host_inventory_status": status,
        "configuration_inspection": configuration,
        "evidence_origin": "synthetic_replay" if mode == "replay" else "local_host",
        "apex_verification": "unverified",
        "apex_verification_reason": "live_apex_inventory_not_performed",
        "capability_qualification": "unverified",
        "capability_qualification_reason": "no_execution_or_qualification",
    }
    run = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": duration_ms,
        "mode": mode,
        "configuration": configuration,
        "collector": {
            "name": "media-generation",
            "version": _collector_version(),
            "fingerprint_algorithm": fingerprint["algorithm"],
        },
        "manifest_path": str(manifest_path) if manifest_path is not None else None,
        "manifest_digest": manifest.digest or None,
        "manifest_description": manifest.description,
        "output_directory": str(Path(options.output_directory).expanduser().resolve()),
        "hash_components": options.hash_components,
        "hash_limit_bytes": options.hash_limit_bytes,
        "status_reasons": sorted(status_reasons),
    }
    inventory: dict[str, object] = {
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "run": run,
    "model_inventory": _model_inventory(manifest, configuration=configuration),
        "host": host_facts.data,
        "environment_fingerprint": fingerprint,
        "runtimes": runtimes,
        "bundles": bundles,
        "probes": _sorted_probe_dicts(ledger),
        "findings": [finding.to_dict() for finding in findings],
        "evidence_gate": evidence_gate,
    }
    validate_inventory_report(inventory)
    transcript = _build_transcript(
        ledger=ledger,
        inventory=inventory,
        status=status,
        configuration=configuration,
        mode=mode,
        findings=findings,
    )
    exit_code = {
        InventoryStatus.OK.value: 0,
        InventoryStatus.PARTIAL.value: 4,
        InventoryStatus.BLOCKED.value: 5,
    }[status]
    summary = {
    "host_inventory_status": status,
        "exit_code": exit_code,
        "run_id": run_id,
        "environment_fingerprint": fingerprint["digest"],
        "finding_count": len(findings),
        "configuration_inspection": configuration,
        "evidence_gate": evidence_gate,
    }
    return InventoryResult(
    host_inventory_status=status,
        exit_code=exit_code,
        inventory=inventory,
        transcript=transcript,
        summary=summary,
    )


@dataclass(frozen=True, slots=True)
class _MissingSnapshot:
    """Destination did not exist before publication."""


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    """Bounded bytes captured from one regular destination file."""

    data: bytes


@dataclass(frozen=True, slots=True)
class _SymlinkSnapshot:
    """Destination symlink target captured without following the link."""

    target: str


_MISSING_SNAPSHOT = _MissingSnapshot()
_DestinationSnapshot = _MissingSnapshot | _FileSnapshot | _SymlinkSnapshot


def _stage_file(path: Path, data: bytes) -> str:
    """Write bytes to an exclusive temporary file beside the destination."""
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return temporary


def _write_atomic_bytes(path: Path, data: bytes) -> None:
    """Write bytes atomically for best-effort publication rollback."""
    temporary: str | None = None
    try:
        temporary = _stage_file(path, data)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _snapshot_identity(facts: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return filesystem identity and version fields used for race checks."""
    return (
        facts.st_dev,
        facts.st_ino,
        facts.st_mode,
        facts.st_size,
        facts.st_mtime_ns,
        facts.st_ctime_ns,
    )


def _snapshot_error(path: Path, reason: str) -> InventoryOutputError:
    """Return one structured pre-publication snapshot failure."""
    return InventoryOutputError(
        f"could not safely snapshot existing output {path}: {reason}"
    )


def _snapshot_symlink(path: Path, before: os.stat_result) -> _SymlinkSnapshot:
    """Capture one symlink target without reading through it."""
    if before.st_size > MAX_PUBLICATION_SYMLINK_TARGET_BYTES:
        raise _snapshot_error(path, "symlink target exceeds snapshot limit")
    try:
        target = os.readlink(path)
        after = path.lstat()
    except OSError as error:
        raise _snapshot_error(path, str(error)) from error
    if not stat.S_ISLNK(after.st_mode) or _snapshot_identity(
        after
    ) != _snapshot_identity(before):
        raise _snapshot_error(path, "destination changed while snapshotting")
    try:
        target_size = len(os.fsencode(target))
    except (UnicodeError, ValueError) as error:
        raise _snapshot_error(path, "symlink target is not encodable") from error
    if target_size > MAX_PUBLICATION_SYMLINK_TARGET_BYTES:
        raise _snapshot_error(path, "symlink target exceeds snapshot limit")
    return _SymlinkSnapshot(target)


def _snapshot(path: Path) -> _DestinationSnapshot:
    """Capture one existing destination with no-follow, bounded reads.

    The destination is opened with ``O_NOFOLLOW`` and checked through the
    opened descriptor and the final path. Any unreadable, unsupported,
    oversized, or changed destination aborts publication before either output
    file is staged or replaced.
    """
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return _MISSING_SNAPSHOT
    except OSError as error:
        raise _snapshot_error(path, str(error)) from error
    if stat.S_ISLNK(facts.st_mode):
        return _snapshot_symlink(path, facts)
    if not stat.S_ISREG(facts.st_mode):
        raise _snapshot_error(path, "existing destination is not a regular file")
    if facts.st_size > MAX_PUBLICATION_SNAPSHOT_BYTES:
        raise _snapshot_error(path, "existing destination exceeds snapshot limit")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow:
        raise _snapshot_error(path, "platform cannot open without following links")
    descriptor = -1
    opened: os.stat_result
    after: os.stat_result
    data: bytes
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | nofollow
            | nonblock
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise _snapshot_error(path, "opened destination is not a regular file")
        if _snapshot_identity(opened) != _snapshot_identity(facts):
            raise _snapshot_error(path, "destination was replaced before opening")
        if opened.st_size > MAX_PUBLICATION_SNAPSHOT_BYTES:
            raise _snapshot_error(path, "existing destination exceeds snapshot limit")
        chunks: list[bytes] = []
        remaining = MAX_PUBLICATION_SNAPSHOT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as error:
        raise _snapshot_error(path, str(error)) from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(data) > MAX_PUBLICATION_SNAPSHOT_BYTES:
        raise _snapshot_error(path, "existing destination grew beyond snapshot limit")
    if len(data) != opened.st_size:
        raise _snapshot_error(path, "destination changed while snapshotting")
    if _snapshot_identity(after) != _snapshot_identity(opened):
        raise _snapshot_error(path, "destination changed while snapshotting")
    try:
        final = path.lstat()
    except OSError as error:
        raise _snapshot_error(path, str(error)) from error
    if (
        not stat.S_ISREG(final.st_mode)
        or _snapshot_identity(final) != _snapshot_identity(opened)
    ):
        raise _snapshot_error(path, "destination changed while snapshotting")
    return _FileSnapshot(data)


def _stage_symlink(path: Path, target: str) -> str:
    """Create one exclusive temporary symlink beside its destination."""
    for _ in range(16):
        temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
        try:
            os.symlink(target, temporary)
        except FileExistsError:
            continue
        return str(temporary)
    raise OSError(
        errno.EEXIST,
        "could not allocate an exclusive temporary symlink",
        str(path),
    )


def _restore(path: Path, snapshot: _DestinationSnapshot) -> None:
    """Restore one destination after a failed second-file publication."""
    if isinstance(snapshot, _FileSnapshot):
        _write_atomic_bytes(path, snapshot.data)
    elif isinstance(snapshot, _SymlinkSnapshot):
        temporary: str | None = None
        try:
            temporary = _stage_symlink(path, snapshot.target)
            os.replace(temporary, path)
            temporary = None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
    elif isinstance(snapshot, _MissingSnapshot):
        path.unlink(missing_ok=True)
    else:
        raise AssertionError(f"unsupported destination snapshot: {snapshot!r}")


def write_inventory(
    result: InventoryResult, output_directory: Path
) -> InventoryResult:
    """Publish the report pair and record publication in the returned result."""
    directory = Path(output_directory).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise InventoryOutputError(f"could not create output directory {directory}: {error}") from error
    if not directory.is_dir():
        raise InventoryOutputError(f"output path is not a directory: {directory}")
    inventory_path = directory / "inventory.json"
    transcript_path = directory / "transcript.txt"

    evidence = result.inventory.get("evidence_gate")
    final_evidence = dict(evidence) if isinstance(evidence, dict) else {}
    final_evidence["report_written"] = True
    final_inventory = {**result.inventory, "evidence_gate": final_evidence}
    final_transcript = _set_report_written(result.transcript, True)
    inventory_text = json.dumps(
        final_inventory, ensure_ascii=True, indent=2, sort_keys=True
    ) + "\n"

    previous = {
        inventory_path: _snapshot(inventory_path),
        transcript_path: _snapshot(transcript_path),
    }
    staged: dict[Path, str] = {}
    published: list[Path] = []
    try:
        staged[inventory_path] = _stage_file(
            inventory_path, inventory_text.encode("utf-8")
        )
        staged[transcript_path] = _stage_file(
            transcript_path, final_transcript.encode("utf-8")
        )
        os.replace(staged[transcript_path], transcript_path)
        published.append(transcript_path)
        del staged[transcript_path]
        os.replace(staged[inventory_path], inventory_path)
        published.append(inventory_path)
        del staged[inventory_path]
    except BaseException as error:
        rollback_error: OSError | None = None
        for path in reversed(published):
            try:
                _restore(path, previous[path])
            except OSError as failure:
                rollback_error = failure
        if rollback_error is not None:
            raise InventoryOutputError(
                f"could not publish {directory} and rollback failed: {rollback_error}"
            ) from error
        if isinstance(error, OSError):
            raise InventoryOutputError(f"could not publish {directory}: {error}") from error
        raise
    finally:
        for temporary in staged.values():
            try:
                os.unlink(temporary)
            except OSError:
                pass

    return replace(
        result,
        inventory=final_inventory,
        transcript=final_transcript,
        summary={**result.summary, "evidence_gate": final_evidence},
        publication={
            "inventory_path": str(inventory_path.resolve()),
            "transcript_path": str(transcript_path.resolve()),
        },
    )
