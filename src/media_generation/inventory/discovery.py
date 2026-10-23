"""Passive runtime identity discovery and declared capability attribution.

Search scope is deliberately small: an explicit manifest path, executable
names on ``PATH``, a short catalog of conventional install locations, the
active Python environment's installed distributions, and declared ComfyUI
directory markers.  Nothing is searched recursively and no version command runs
unless the manifest opts in.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Iterable

from .catalog import RuntimeSpec, runtime_specs
from .manifest import InventoryManifest, RuntimeDeclaration
from .probes import DEFAULT_OUTPUT_LIMIT, ProbeLedger, ProbeSpec
from .schema import Finding, Observation, ProbeStatus, Severity


RUNTIME_DIGEST_LIMIT = 512 * 1024 * 1024
MAX_CANDIDATES = 16
_SEMVER = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.]+)?)\b")
_COMFY_VERSION = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")


def _declared_for(manifest: InventoryManifest, runtime_id: str) -> RuntimeDeclaration | None:
    """Return the manifest declaration for one catalog runtime, if present."""
    for declaration in manifest.runtimes:
        if declaration.id == runtime_id:
            return declaration
    return None


def _stat_payload(observation: Observation) -> dict[str, object] | None:
    """Decode a recorded lstat payload or return ``None``."""
    if not observation.ok:
        return None
    try:
        payload = json.loads(observation.text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _candidate(
    ledger: ProbeLedger,
    *,
    runtime_id: str,
    path: Path,
    kind: str,
    markers: tuple[str, ...] = (),
    searched: list[str],
) -> tuple[Path | None, dict[str, object] | None]:
    """Validate one candidate path without following symlinks."""
    searched.append(str(path))
    observation = ledger.stat(ProbeSpec(f"runtime:{runtime_id}:candidate", "runtime"), path)
    payload = _stat_payload(observation)
    if payload is None:
        if observation.ok:
            return None, {
                "path": str(path),
                "status": "malformed",
                "reason": "stat_payload_malformed",
            }
        return None, {"path": str(path), "status": observation.status, "reason": observation.reason}
    if payload.get("symlink"):
        return None, {"path": str(path), "status": "skipped", "reason": "symlink_not_followed"}
    if kind == "directory":
        if payload.get("kind") != "directory":
            return None, {"path": str(path), "status": "unavailable", "reason": "not_a_directory"}
        for marker in markers:
            marker_observation = ledger.stat(
                ProbeSpec(f"runtime:{runtime_id}:marker", "runtime"), path / marker
            )
            marker_payload = _stat_payload(marker_observation)
            if marker_payload is None:
                return None, {
                    "path": str(path),
                    "status": "malformed" if marker_observation.ok else marker_observation.status,
                    "reason": (
                        "marker_stat_malformed"
                        if marker_observation.ok
                        else marker_observation.reason or marker_observation.status
                    ),
                }
            if marker_payload.get("kind") != "file":
                return None, {
                    "path": str(path),
                    "status": "unavailable",
                    "reason": f"marker_not_found:{marker}",
                }
        return path, payload
    if kind == "binary":
        if payload.get("kind") != "file":
            return None, {"path": str(path), "status": "unavailable", "reason": "not_a_file"}
        if payload.get("executable") is not True:
            return None, {"path": str(path), "status": "unavailable", "reason": "not_executable"}
        return path, payload
    return path, payload


def _find_candidate(
    ledger: ProbeLedger,
    spec: RuntimeSpec,
    declaration: RuntimeDeclaration | None,
) -> tuple[Path | None, dict[str, object] | None, list[str], list[dict[str, object]]]:
    """Check a declared path, PATH names, then conventional locations in order."""
    searched: list[str] = []
    rejected: list[dict[str, object]] = []
    if declaration is not None and declaration.path is not None:
        path, payload = _candidate(
            ledger,
            runtime_id=spec.id,
            path=declaration.path,
            kind=spec.kind,
            markers=spec.markers,
            searched=searched,
        )
        if path is not None:
            return path, payload, searched, rejected
        if payload is not None:
            rejected.append(payload)
        return None, None, searched, rejected
    for name in spec.names:
        observation = ledger.which(ProbeSpec(f"runtime:{spec.id}:which", "runtime"), name)
        searched.append(f"PATH:{name}")
        if not observation.ok:
            continue
        path, payload = _candidate(
            ledger,
            runtime_id=spec.id,
            path=Path(observation.text),
            kind=spec.kind,
            markers=spec.markers,
            searched=searched,
        )
        if path is not None:
            return path, payload, searched, rejected
        if payload is not None:
            rejected.append(payload)
    for raw in spec.known_paths:
        if len(searched) >= MAX_CANDIDATES:
            break
        path, payload = _candidate(
            ledger,
            runtime_id=spec.id,
            path=Path(raw).expanduser(),
            kind=spec.kind,
            markers=spec.markers,
            searched=searched,
        )
        if path is not None:
            return path, payload, searched, rejected
        if payload is not None:
            rejected.append(payload)
    return None, None, searched, rejected


def _runtime_digest(
    ledger: ProbeLedger, runtime_id: str, path: Path
) -> dict[str, object]:
    """Return a bounded binary digest with an explicit unavailable state."""
    observation, digest = ledger.sha256(
        ProbeSpec(f"runtime:{runtime_id}:digest", "runtime"),
        path,
        limit=RUNTIME_DIGEST_LIMIT,
    )
    if digest is not None:
        return {"status": "computed", "algorithm": "sha256", "value": digest}
    return {
        "status": "skipped" if observation.status == ProbeStatus.SKIPPED.value else "unavailable",
        "algorithm": "sha256",
        "value": None,
        "reason": observation.reason,
    }


def _read_version_file(
    ledger: ProbeLedger, runtime_id: str, path: Path
) -> dict[str, object]:
    """Read a small engine version file and extract a declared version."""
    observation = ledger.read(
        ProbeSpec(f"runtime:{runtime_id}:version-file", "runtime"),
        path,
        limit=64 * 1024,
    )
    if not observation.ok:
        return {"status": observation.status, "value": None, "reason": observation.reason}
    match = _COMFY_VERSION.search(observation.text)
    if match is None:
        return {"status": "unknown", "value": None, "reason": "version_not_reported"}
    return {"status": "observed", "value": match.group(1), "source": str(path)}


def _safe_git_ref(root: Path, ref: str) -> Path | None:
    """Return a ref path only when it stays inside ``.git`` and is a ref."""
    if not ref.startswith("refs/") or ".." in ref.split("/"):
        return None
    candidate = root / ".git" / ref
    try:
        if os.path.commonpath((str(candidate), str(root / ".git"))) != str(root / ".git"):
            return None
    except ValueError:  # pragma: no cover - different drives on Windows
        return None
    return candidate


def _git_revision(
    ledger: ProbeLedger, runtime_id: str, root: Path
) -> dict[str, object]:
    """Resolve a bounded, non-recursive source revision from ``.git`` metadata."""
    head = ledger.read(
        ProbeSpec(f"runtime:{runtime_id}:git-head", "runtime"),
        root / ".git" / "HEAD",
        limit=4096,
    )
    if not head.ok:
        return {"status": head.status, "value": None, "reason": head.reason}
    text = head.text.strip()
    if re.fullmatch(r"[0-9a-f]{40}", text):
        return {"status": "observed", "value": text, "source": str(root / ".git" / "HEAD")}
    match = re.match(r"ref:\s*(\S+)", text)
    if match is not None:
        ref_path = _safe_git_ref(root, match.group(1))
        if ref_path is not None:
            ref = ledger.read(
                ProbeSpec(f"runtime:{runtime_id}:git-ref", "runtime"),
                ref_path,
                limit=4096,
            )
            if ref.ok and re.fullmatch(r"[0-9a-f]{40}", ref.text.strip()):
                return {"status": "observed", "value": ref.text.strip(), "source": str(ref_path)}
        packed = ledger.read(
            ProbeSpec(f"runtime:{runtime_id}:git-packed-refs", "runtime"),
            root / ".git" / "packed-refs",
            limit=256 * 1024,
        )
        if packed.ok:
            for line in packed.text.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == match.group(1):
                    if re.fullmatch(r"[0-9a-f]{40}", parts[0]):
                        return {
                            "status": "observed",
                            "value": parts[0],
                            "source": str(root / ".git" / "packed-refs"),
                        }
    return {"status": "unknown", "value": None, "reason": "revision_not_resolved"}


def _version_from_output(text: str) -> str | None:
    """Extract the first dotted version-like token from command output."""
    match = _SEMVER.search(text)
    return match.group(1) if match is not None else None


def _probe_version(
    ledger: ProbeLedger,
    *,
    spec: RuntimeSpec,
    executable: Path,
    policy_timeout: float,
) -> tuple[dict[str, object], bool]:
    """Run one fixed version/help command and return its parsed identity."""
    assert spec.version_argv is not None
    observation = ledger.run(
        ProbeSpec(f"runtime:{spec.id}:version", "runtime"),
        [str(executable), *spec.version_argv],
        timeout_seconds=policy_timeout,
        output_limit=32 * 1024,
    )
    if not observation.ok:
        return (
            {
                "status": observation.status,
                "value": None,
                "source": "command",
                "reason": observation.reason,
            },
            True,
        )
    version = _version_from_output(observation.text)
    if version is None:
        return (
            {
                "status": "unknown",
                "value": None,
                "source": "command",
                "reason": "version_not_reported",
            },
            False,
        )
    return ({"status": "observed", "value": version, "source": "command"}, False)


def _python_distribution(
    ledger: ProbeLedger, spec: RuntimeSpec, declaration: RuntimeDeclaration | None
) -> tuple[dict[str, object], bool, Finding | None]:
    """Read recorded distribution metadata without importing the package."""
    name = spec.names[0]
    observation = ledger.python_distribution(
        ProbeSpec(f"runtime:{spec.id}:distribution", "runtime"), name
    )
    capabilities = (
        {
            "status": "configured",
            "items": [item.to_dict() for item in declaration.capabilities],
        }
        if declaration is not None and declaration.capabilities
        else {"status": "not_configured", "items": []}
    )
    if not observation.ok:
        reason = observation.reason or observation.status
        unrecorded = reason == "not_recorded"
        missing = (
            observation.status == ProbeStatus.UNAVAILABLE.value
            and reason == "distribution_not_found"
        )
        status = "not_inspected" if unrecorded else observation.status
        record = {
            "id": spec.id,
            "kind": spec.kind,
            "presence": (
                "not_inspected"
                if unrecorded
                else "not_found_in_search_scope"
                if missing
                else "metadata_unavailable"
            ),
            "path": None,
            "searched": [f"python_distribution:{name}"],
            "identity": {"status": status, "reason": reason},
            "version": {"status": status, "value": None, "reason": reason},
            "capabilities": capabilities,
        }
        if unrecorded or missing:
            return record, False, None
        return (
            record,
            True,
            Finding(
                code="runtime_distribution_metadata_unavailable",
                severity=Severity.WARNING.value,
                subject=f"runtime:{spec.id}",
                message="Installed distribution metadata could not be read reliably.",
            ),
        )
    try:
        metadata = json.loads(observation.text)
    except json.JSONDecodeError:
        metadata = None
    version = metadata.get("version") if isinstance(metadata, dict) else None
    location = metadata.get("location") if isinstance(metadata, dict) else None
    if not isinstance(version, str) or not version:
        record = {
            "id": spec.id,
            "kind": spec.kind,
            "presence": "metadata_malformed",
            "path": None,
            "searched": [f"python_distribution:{name}"],
            "identity": {
                "status": "malformed",
                "reason": "distribution_metadata_malformed",
            },
            "version": {
                "status": "malformed",
                "value": None,
                "reason": "distribution_metadata_malformed",
            },
            "capabilities": capabilities,
        }
        return (
            record,
            True,
            Finding(
                code="runtime_distribution_metadata_malformed",
                severity=Severity.WARNING.value,
                subject=f"runtime:{spec.id}",
                message="Installed distribution metadata was not a valid version record.",
            ),
        )
    record = {
        "id": spec.id,
        "kind": spec.kind,
        "presence": "observed",
        "path": location if isinstance(location, str) else None,
        "searched": [f"python_distribution:{name}"],
        "identity": {
            "status": "observed",
            "package": name,
            "version": version,
            "location": location if isinstance(location, str) else None,
        },
        "version": {
            "status": "observed",
            "value": version,
            "source": "python_distribution_metadata",
        },
        "capabilities": capabilities,
    }
    return record, False, None


def discover_runtimes(
    ledger: ProbeLedger, manifest: InventoryManifest
) -> tuple[list[dict[str, object]], list[Finding], bool]:
    """Identify supported runtimes and attach declared capability attribution."""
    records: list[dict[str, object]] = []
    findings: list[Finding] = []
    degraded = False
    for spec in runtime_specs():
        declaration = _declared_for(manifest, spec.id)
        if spec.kind == "python_distribution":
            record, probe_failed, finding = _python_distribution(ledger, spec, declaration)
            records.append(record)
            degraded = degraded or probe_failed
            if finding is not None:
                findings.append(finding)
            continue
        path, payload, searched, rejected = _find_candidate(ledger, spec, declaration)
        capabilities = (
            {
                "status": "configured",
                "items": [item.to_dict() for item in declaration.capabilities],
            }
            if declaration is not None and declaration.capabilities
            else {"status": "not_configured", "items": []}
        )
        if path is None:
            declared_missing = declaration is not None and declaration.path is not None
            presence = "declared_path_unavailable" if declared_missing else "not_found_in_search_scope"
            records.append(
                {
                    "id": spec.id,
                    "kind": spec.kind,
                    "presence": presence,
                    "path": None,
                    "searched": searched,
                    "rejected_candidates": rejected,
                    "identity": {"status": "unavailable", "reason": "not_found_in_search_scope"},
                    "version": {
                        "status": "not_inspected",
                        "value": None,
                        "reason": "not_found_in_search_scope",
                    },
                    "capabilities": capabilities,
                }
            )
            if declared_missing:
                degraded = True
                findings.append(
                    Finding(
                        code="runtime_declared_path_unavailable",
                        severity=Severity.WARNING.value,
                        subject=f"runtime:{spec.id}",
                        message="A configured runtime path was not usable; no discovered identity is reported.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        code="runtime_not_found",
                        severity=Severity.INFO.value,
                        subject=f"runtime:{spec.id}",
                        message="No executable or conventional directory was found in the bounded search scope.",
                    )
                )
            continue
        identity: dict[str, object] = {
            "status": "observed",
            "path": str(path),
            "size_bytes": payload.get("size_bytes") if payload else None,
            "mtime": payload.get("mtime") if payload else None,
        "executable": payload.get("executable") if payload else None,
        }
        build: dict[str, object] = {}
        if spec.kind == "binary":
            identity["digest"] = _runtime_digest(ledger, spec.id, path)
        elif spec.kind == "directory":
            identity["markers"] = list(spec.markers)
            if spec.version_file is not None:
                build["version_file"] = _read_version_file(
                    ledger, spec.id, path / spec.version_file
                )
            if spec.git_head:
                build["source_revision"] = _git_revision(ledger, spec.id, path)
        version: dict[str, object] = {
            "status": "not_inspected",
            "value": None,
            "reason": "version_probe_not_enabled",
        }
        if (
            declaration is not None
            and declaration.probe_version
            and spec.version_argv is not None
            and spec.kind == "binary"
        ):
            version, failed = _probe_version(
                ledger,
                spec=spec,
                executable=path,
                policy_timeout=manifest.policy.timeout_seconds,
            )
            if failed:
                degraded = True
                findings.append(
                    Finding(
                        code="runtime_version_probe_failed",
                        severity=Severity.WARNING.value,
                        subject=f"runtime:{spec.id}",
                        message="The configured version probe did not complete successfully.",
                    )
                )
        record = {
            "id": spec.id,
            "kind": spec.kind,
            "presence": "observed",
            "path": str(path),
            "searched": searched,
            "identity": identity,
            "version": version,
            "build": build,
            "capabilities": capabilities,
        }
        records.append(record)
    if not any(record.get("presence") == "observed" for record in records):
        findings.append(
            Finding(
                code="runtime_discovery_empty",
                severity=Severity.INFO.value,
                subject="runtimes",
                message=(
                    "No supported runtime was observed in PATH, conventional locations, "
                    "or the active Python environment."
                ),
            )
        )
    return records, findings, degraded
