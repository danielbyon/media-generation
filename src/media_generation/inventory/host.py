"""Read-only host, accelerator, and memory-topology observation.

Passive probes use standard-library platform facts, ``/etc/os-release``,
``/proc``, and Linux DRM sysfs.  External device commands (``lspci``,
``nvidia-smi``, ``rocm-smi``, ``hipconfig``) run only when a manifest enables
``probe_policy.device_queries``; every invocation is fixed in code, bounded, and
recorded in the probe ledger.  No probe loads a model or changes device state.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .manifest import ProbePolicy
from .probes import DEFAULT_OUTPUT_LIMIT, ProbeLedger, ProbeSpec
from .schema import Finding, Observation, ProbeStatus, Severity, utc_now


MAX_ACCELERATORS = 8
MAX_DRM_FILES = 32
DRM_ROOT = Path("/sys/class/drm")
SYS_DEVICES_ROOT = Path("/sys/devices")
SYS_MODULE_ROOT = Path("/sys/module")
_DRIVER_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True, slots=True)
class HostFacts:
    """Structured host facts plus findings that affect report status."""

    data: dict[str, object]
    findings: tuple[Finding, ...]
    degraded: bool


def _unquote(value: str) -> str:
    """Remove one pair of matching shell-style quotes from a value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return value


def parse_os_release(text: str) -> dict[str, str]:
    """Parse the documented key/value form of ``/etc/os-release``."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, raw = stripped.split("=", 1)
        values[key.strip()] = _unquote(raw.strip())
    return values


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse selected ``/proc/meminfo`` byte counts."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if not parts or not parts[0].isdigit():
            continue
        multiplier = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
        values[key.strip()] = int(parts[0]) * multiplier
    return values


def parse_cpuinfo_model(text: str) -> str | None:
    """Return the first CPU model string found in ``/proc/cpuinfo``."""
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in {"model name", "hardware", "processor"}:
            candidate = value.strip()
            if candidate and not candidate.isdigit():
                return candidate
    return None


def parse_uevent(text: str) -> dict[str, str]:
    """Parse one sysfs ``uevent`` file into key/value pairs."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def _int_text(value: str) -> int | None:
    """Parse a sysfs integer, returning ``None`` when absent or malformed."""
    stripped = value.strip()
    if not stripped:
        return None
    try:
        return int(stripped, 0)
    except ValueError:
        return None


def _read_int(
    ledger: ProbeLedger,
    *,
    probe_id: str,
    path: Path,
    category: str = "gpu",
    criticality: str = "optional",
    root: Path | None = None,
) -> int | None:
    """Read one integer sysfs file and return None on any failure."""
    observation = ledger.read(
        ProbeSpec(probe_id, category, criticality),
        path,
        limit=4096,
        follow_final_symlink=False,
        root=root,
    )
    if not observation.ok:
        return None
    return _int_text(observation.text)


def _read_text(
    ledger: ProbeLedger,
    *,
    probe_id: str,
    path: Path,
    category: str = "gpu",
    criticality: str = "optional",
    root: Path | None = None,
) -> str | None:
    """Read one small text file and return None on any failure."""
    observation = ledger.read(
        ProbeSpec(probe_id, category, criticality),
        path,
        limit=8192,
        follow_final_symlink=False,
        root=root,
    )
    if not observation.ok:
        return None
    return observation.text


def _platform_os(system: str, *, mac_version: str, release: str) -> dict[str, object]:
    """Return an honest platform fallback when os-release is unavailable."""
    if system == "Darwin":
        return {
            "id": "macos",
            "name": "macOS",
            "version_id": mac_version or None,
            "source": "platform",
            "fallback": True,
        }
    return {
        "id": system.lower() if system else "unknown",
        "name": system or "unknown",
        "version_id": release or None,
        "source": "platform",
        "fallback": True,
    }


def _classify_vram(accelerator: dict[str, object]) -> str:
    """Classify ``vram`` only when the observation source proves the pool kind."""
    source = str(accelerator.get("source") or "")
    if source == "nvidia-smi":
        return "dedicated_vram"
    return "unknown_vram"


def _pool_additive(kind: str) -> bool:
    """Return whether a pool may be added to the independent memory total."""
    return kind == "dedicated_vram"


def _make_pool(
    *,
    name: str,
    kind: str,
    total_bytes: int | None,
    source: str,
    free_bytes: int | None = None,
) -> dict[str, object]:
    """Build one normalized memory-pool observation."""
    return {
        "name": name,
        "kind": kind,
        "total_bytes": total_bytes,
        "free_bytes": free_bytes,
        "additive": _pool_additive(kind),
        "source": source,
    }


def resolve_memory_topology(
    *,
    system_total_bytes: int | None,
    accelerators: list[dict[str, object]],
) -> tuple[dict[str, object], list[Finding]]:
    """Describe reported pools and sharing without summing shared memory twice.

    System RAM and each dedicated VRAM pool are independent and may be added for
    a reported total.  GTT apertures, visible VRAM aliases, and APU carve-outs
    are views into memory that has already been counted; they are recorded but
    never added.  A dedicated VRAM pool larger than system RAM is valid.  Only a
    *shared* pool larger than system RAM is treated as a conflict.
    """
    findings: list[Finding] = []
    evidence: list[dict[str, object]] = []
    allocatable: list[dict[str, object]] = []
    sharing: list[dict[str, object]] = []
    warnings: list[str] = []
    dedicated = False
    shared = False
    unknown = False
    conflict = False
    tool_evidence = False

    if system_total_bytes is not None:
        allocatable.append(
            {
                "id": "system_ram",
                "kind": "system_ram",
                "total_bytes": system_total_bytes,
                "source": "system",
            }
        )

    for accelerator in accelerators:
        accelerator_id = str(accelerator.get("id") or "accelerator")
        pools = accelerator.get("pools")
        if not isinstance(pools, list):
            continue
        if accelerator.get("source") in {"nvidia-smi", "rocm-smi"}:
            tool_evidence = True
        for pool in pools:
            if not isinstance(pool, dict):
                continue
            kind = str(pool.get("kind") or "unknown")
            total = pool.get("total_bytes")
            if not isinstance(total, int):
                total = None
            evidence.append(
                {
                    "accelerator_id": accelerator_id,
                    "pool": pool.get("name"),
                    "kind": kind,
                    "total_bytes": total,
                    "free_bytes": pool.get("free_bytes"),
                    "source": pool.get("source"),
                }
            )
            if kind == "dedicated_vram":
                dedicated = True
                if total is not None:
                    allocatable.append(
                        {
                            "id": f"{accelerator_id}:{pool.get('name')}",
                            "kind": kind,
                            "total_bytes": total,
                            "source": pool.get("source"),
                        }
                    )
                sharing.append(
                    {
                        "accelerator_id": accelerator_id,
                        "pool": pool.get("name"),
                        "relationship": "dedicated_device_memory",
                    }
                )
            elif kind == "shared_carveout":
                shared = True
                sharing.append(
                    {
                        "accelerator_id": accelerator_id,
                        "pool": pool.get("name"),
                        "relationship": "carveout_within_system_ram",
                    }
                )
                if system_total_bytes is not None and total is not None and total > system_total_bytes:
                    conflict = True
                    warnings.append("shared_pool_exceeds_system_memory")
            elif kind == "shared_gtt":
                sharing.append(
                    {
                        "accelerator_id": accelerator_id,
                        "pool": pool.get("name"),
                        "relationship": "shared_system_aperture",
                    }
                )
                if system_total_bytes is not None and total is not None and total > system_total_bytes:
                    conflict = True
                    warnings.append("shared_pool_exceeds_system_memory")
            elif kind == "visible_vram_alias":
                sharing.append(
                    {
                        "accelerator_id": accelerator_id,
                        "pool": pool.get("name"),
                        "relationship": "duplicate_alias_not_additive",
                    }
                )
            else:
                unknown = True
                sharing.append(
                    {
                        "accelerator_id": accelerator_id,
                        "pool": pool.get("name"),
                        "relationship": "unknown_sharing",
                    }
                )

    if conflict:
        topology_class = "ambiguous"
        reported_total: int | None = None
        confidence = "low"
    elif dedicated and shared:
        topology_class = "ambiguous"
        reported_total = None
        confidence = "low"
    elif dedicated and unknown:
        topology_class = "ambiguous"
        reported_total = None
        confidence = "low"
    elif dedicated:
        topology_class = "discrete"
        reported_total = sum(
            int(item["total_bytes"]) for item in allocatable if isinstance(item.get("total_bytes"), int)
        )
        confidence = "high" if tool_evidence else "medium"
    elif shared and not unknown:
        topology_class = "unified_shared"
        reported_total = system_total_bytes
        confidence = "high" if tool_evidence else "medium"
    elif unknown:
        topology_class = "unknown"
        reported_total = system_total_bytes
        confidence = "low"
    else:
        topology_class = "unknown"
        reported_total = system_total_bytes
        confidence = "low"
        if accelerators:
            warnings.append("no_gpu_memory_pools_observed")

    if topology_class == "unified_shared" and system_total_bytes is None:
        topology_class = "unknown"
        reported_total = None
        confidence = "low"

    for code in sorted(set(warnings)):
        findings.append(
            Finding(
                code=code,
                severity=Severity.WARNING.value,
                subject="memory.topology",
                message=(
                    "Reported shared GPU memory exceeds system memory; totals were not combined."
                    if code == "shared_pool_exceeds_system_memory"
                    else "Accelerators were observed without a reported VRAM or shared pool."
                ),
            )
        )
    return (
        {
            "class": topology_class,
            "reported_total_bytes": reported_total,
            "reported_total_is_allocatable_pool": False,
            "system_total_bytes": system_total_bytes,
            "confidence": confidence,
            "allocatable_pools": allocatable,
            "sharing_relationships": sharing,
            "evidence": evidence,
            "warnings": sorted(set(warnings)),
        },
        findings,
    )


def _trusted_sysfs_device(device_facts: dict[str, object]) -> bool:
    """Accept a sysfs device directory or a symlink resolved under /sys/devices."""
    if device_facts.get("kind") == "directory":
        return True
    if device_facts.get("kind") != "symlink":
        return False
    real = device_facts.get("realpath")
    if not isinstance(real, str):
        return False
    try:
        resolved = Path(real).resolve(strict=False)
        root = SYS_DEVICES_ROOT.resolve(strict=False)
        return resolved.is_relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False


def _collect_accelerators(
    ledger: ProbeLedger,
    *,
    system: str,
) -> tuple[list[dict[str, object]], list[Finding], bool, dict[str, object]]:
    """Enumerate Linux DRM cards through sysfs without external tooling."""
    findings: list[Finding] = []
    degraded = False
    drm_root = DRM_ROOT
    if system != "Linux":
        ledger.record_observation(
            ProbeSpec("gpu:sysfs-enumeration", "gpu"),
            source="platform",
            observation=Observation(
                status=ProbeStatus.SKIPPED.value,
                reason="unsupported_platform",
                detail="Linux DRM sysfs enumeration is unavailable on this platform",
            ),
        )
        return (
            [],
            findings,
            False,
            {"status": "not_applicable", "reason": "unsupported_platform"},
        )
    listing = ledger.list_dir(
        ProbeSpec("gpu:drm-directory", "gpu", "optional"),
        drm_root,
        limit=MAX_DRM_FILES,
    )
    if not listing.ok:
        findings.append(
            Finding(
                code="accelerator_enumeration_unavailable",
                severity=Severity.WARNING.value,
                subject="gpu",
                message="Linux DRM sysfs was not readable; accelerator metadata is unavailable.",
            )
        )
        return (
            [],
            findings,
            True,
            {
                "status": "unavailable",
                "reason": listing.reason or "drm_directory_unreadable",
            },
        )
    if listing.truncated:
        degraded = True
        findings.append(
            Finding(
                code="accelerator_enumeration_truncated",
                severity=Severity.WARNING.value,
                subject="gpu",
                message="DRM directory listing reached its bounded entry limit.",
            )
        )
    try:
        entries = json.loads(listing.text)
    except (TypeError, json.JSONDecodeError):
        entries = None
    if not isinstance(entries, list):
        findings.append(
            Finding(
                code="accelerator_listing_malformed",
                severity=Severity.WARNING.value,
                subject="gpu",
                message="DRM directory listing could not be parsed.",
            )
        )
        return (
            [],
            findings,
            True,
            {"status": "malformed", "reason": "drm_listing_malformed"},
        )
    cards = sorted(
        entry["name"]
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("name"), str)
        and re.fullmatch(r"card\d+", str(entry["name"]))
    )
    discovered_cards = cards
    card_limit_reached = len(discovered_cards) > MAX_ACCELERATORS
    if card_limit_reached:
        cards = discovered_cards[:MAX_ACCELERATORS]
        degraded = True
        findings.append(
            Finding(
                code="accelerator_limit_reached",
                severity=Severity.WARNING.value,
                subject="gpu",
                message=f"Only the first {MAX_ACCELERATORS} DRM cards were inspected.",
            )
        )
    accelerators: list[dict[str, object]] = []
    inspection_failures = 0
    for card in cards:
        device = drm_root / card / "device"
        device_stat = ledger.stat(
            ProbeSpec(f"gpu:{card}:device-directory", "gpu"), device
        )
        try:
            device_facts = json.loads(device_stat.text) if device_stat.ok else {}
        except (TypeError, json.JSONDecodeError):
            device_facts = {}
        if not isinstance(device_facts, dict):
            device_facts = {}
        if not device_stat.ok or not _trusted_sysfs_device(device_facts):
            inspection_failures += 1
            degraded = True
            reason = (
                device_stat.reason
                if not device_stat.ok
                else "untrusted_device_link"
                if device_facts.get("kind") == "symlink"
                else "malformed_device_metadata"
                if not device_facts.get("kind")
                else "not_a_directory"
            )
            findings.append(
                Finding(
                    code="gpu_card_unavailable",
                    severity=Severity.WARNING.value,
                    subject=f"gpu:{card}",
                    message=(
                        f"DRM card device metadata was not usable; reason: {reason}."
                    ),
                )
            )
            continue
        device_root = drm_root
        device_base = device
        if device_facts.get("kind") != "directory":
            real = device_facts.get("realpath")
            if isinstance(real, str):
                try:
                    device_base = Path(real).resolve(strict=False)
                    device_root = SYS_DEVICES_ROOT
                    contained = device_base.is_relative_to(
                        device_root.resolve(strict=False)
                    )
                except (OSError, RuntimeError, ValueError):
                    contained = False
            else:
                contained = False
            if not contained:
                inspection_failures += 1
                degraded = True
                findings.append(
                    Finding(
                        code="gpu_card_unavailable",
                        severity=Severity.WARNING.value,
                        subject=f"gpu:{card}",
                        message=(
                            "DRM card device metadata was not usable; "
                            "reason: device path escaped the trusted sysfs root."
                        ),
                    )
                )
                continue
        vendor_text = _read_text(
            ledger,
            probe_id=f"gpu:{card}:vendor",
            path=device_base / "vendor",
            root=device_root,
        )
        device_text = _read_text(
            ledger,
            probe_id=f"gpu:{card}:device",
            path=device_base / "device",
            root=device_root,
        )
        class_text = _read_text(
            ledger,
            probe_id=f"gpu:{card}:class",
            path=device_base / "class",
            root=device_root,
        )
        uevent_text = _read_text(
            ledger,
            probe_id=f"gpu:{card}:uevent",
            path=device_base / "uevent",
            root=device_root,
        )
        driver_stat = ledger.stat(
            ProbeSpec(f"gpu:{card}:driver", "gpu"), device_base / "driver"
        )
        driver: str | None = None
        if driver_stat.ok:
            try:
                driver_payload = json.loads(driver_stat.text)
            except (TypeError, json.JSONDecodeError):
                driver_payload = None
            if isinstance(driver_payload, dict):
                link_target = driver_payload.get("link_target")
                if isinstance(link_target, str) and link_target:
                    driver = Path(link_target).name or None
            else:
                driver = None
        uevent = parse_uevent(uevent_text or "")
        pci_class = (class_text or uevent.get("PCI_CLASS") or "").strip().lower()
        if pci_class and not pci_class.startswith("0x"):
            pci_class = "0x" + pci_class
        if pci_class and not pci_class.startswith("0x03"):
            continue
        vram = _read_int(
            ledger,
            probe_id=f"gpu:{card}:vram-total",
            path=device_base / "mem_info_vram_total",
            root=device_root,
        )
        vis_vram = _read_int(
            ledger,
            probe_id=f"gpu:{card}:visible-vram-total",
            path=device_base / "mem_info_vis_vram_total",
            root=device_root,
        )
        gtt = _read_int(
            ledger,
            probe_id=f"gpu:{card}:gtt-total",
            path=device_base / "mem_info_gtt_total",
            root=device_root,
        )
        accelerator: dict[str, object] = {
            "id": f"drm:{card}",
            "vendor_id": (vendor_text or "").strip().lower() or None,
            "device_id": (device_text or "").strip().lower() or None,
            "pci_class": pci_class or None,
            "pci_address": uevent.get("PCI_SLOT_NAME"),
            "driver": driver or uevent.get("DRIVER"),
            "driver_version": None,
            "source": "sysfs",
            "pools": [],
        }
        vram_kind = _classify_vram(accelerator)
        pools: list[dict[str, object]] = []
        if vram is not None:
            pools.append(
                _make_pool(
                    name="vram",
                    kind=vram_kind,
                    total_bytes=vram,
                    source=f"/sys/class/drm/{card}/device/mem_info_vram_total",
                )
            )
        if vis_vram is not None:
            pools.append(
                _make_pool(
                    name="vis_vram",
                    kind="visible_vram_alias",
                    total_bytes=vis_vram,
                    source=f"/sys/class/drm/{card}/device/mem_info_vis_vram_total",
                )
            )
        if gtt is not None:
            pools.append(
                _make_pool(
                    name="gtt",
                    kind="shared_gtt",
                    total_bytes=gtt,
                    source=f"/sys/class/drm/{card}/device/mem_info_gtt_total",
                )
            )
        accelerator["pools"] = pools
        if driver and _DRIVER_NAME.match(driver):
            driver_version = _read_text(
                ledger,
                probe_id=f"gpu:{card}:{driver}-version",
                path=SYS_MODULE_ROOT / driver / "version",
                root=SYS_MODULE_ROOT,
            )
            if driver_version:
                accelerator["driver_version"] = driver_version.strip()
        accelerators.append(accelerator)
    if not accelerators:
        if inspection_failures or listing.truncated or card_limit_reached:
            observation = Observation(
                status=ProbeStatus.UNAVAILABLE.value,
                reason=(
                    "accelerator_metadata_unavailable"
                    if inspection_failures
                    else "accelerator_enumeration_incomplete"
                ),
                text=(
                    f"{inspection_failures} DRM card candidate(s) could not be "
                    "inspected and the directory scan was "
                    f"{'truncated' if listing.truncated else 'complete'}; "
                    "no absence claim is made."
                ),
            )
            degraded = True
        else:
            observation = Observation(
                status=ProbeStatus.OK.value,
                text=(
                    f"{len(cards)} DRM card candidate(s) inspected; "
                    "no display-class device metadata observed."
                ),
            )
        ledger.record_observation(
            ProbeSpec("gpu:enumeration-result", "gpu"),
            source="sysfs",
            observation=observation,
        )
    enumeration: dict[str, object] = {
        "status": (
            "partial"
            if inspection_failures or listing.truncated or card_limit_reached
            else "observed"
        ),
        "candidate_count": len(discovered_cards),
        "inspected_count": len(cards) - inspection_failures,
        "inspection_failures": inspection_failures,
        "listing_truncated": listing.truncated,
        "card_limit_reached": card_limit_reached,
    }
    if enumeration["status"] == "partial":
        enumeration["reason"] = (
            "accelerator_inspection_failed"
            if inspection_failures
            else "accelerator_enumeration_truncated"
        )
    return accelerators, findings, degraded, enumeration


def _merge_tool_accelerator(
    accelerators: list[dict[str, object]], candidate: dict[str, object]
) -> None:
    """Attach tool-observed metadata to a matching sysfs card when possible."""
    address = candidate.get("pci_address")
    if isinstance(address, str):
        for accelerator in accelerators:
            existing = accelerator.get("pci_address")
            if isinstance(existing, str) and (
                existing.endswith(address[-12:]) or address.endswith(existing[-12:])
            ):
                for key in ("name", "driver_version", "compute_capability"):
                    if candidate.get(key) is not None:
                        accelerator[key] = candidate[key]
                candidate_pools = candidate.get("pools")
                if isinstance(candidate_pools, list):
                    existing_pools = accelerator.setdefault("pools", [])
                    assert isinstance(existing_pools, list)
                    names = {
                        pool.get("name")
                        for pool in existing_pools
                        if isinstance(pool, dict)
                    }
                    for pool in candidate_pools:
                        if not isinstance(pool, dict):
                            continue
                        if pool.get("name") not in names:
                            existing_pools.append(pool)
                            continue
                        for index, existing_pool in enumerate(existing_pools):
                            if (
                                not isinstance(existing_pool, dict)
                                or existing_pool.get("name") != pool.get("name")
                            ):
                                continue
                            if (
                                existing_pool.get("kind") == "unknown_vram"
                                and pool.get("kind") != "unknown_vram"
                            ):
                                existing_pools[index] = pool
                            break
                accelerator["source"] = candidate.get("source")
                return
    accelerators.append(candidate)


def _collect_device_queries(
    ledger: ProbeLedger,
    policy: ProbePolicy,
    accelerators: list[dict[str, object]],
) -> dict[str, object]:
    """Run opt-in, fixed device-query commands and merge their observations."""
    toolchain: dict[str, object] = {}
    if not policy.device_queries:
        ledger.record_observation(
            ProbeSpec("gpu:device-queries", "gpu-tool"),
            source="policy",
            observation=Observation(
                status=ProbeStatus.SKIPPED.value,
                reason="disabled_by_policy",
                detail="probe_policy.device_queries is false",
            ),
        )
        return toolchain
    timeout = policy.timeout_seconds

    lspci = ledger.which(ProbeSpec("gpu-tool:lspci", "gpu-tool"), "lspci")
    if lspci.ok:
        result = ledger.run(
            ProbeSpec("gpu-tool:lspci", "gpu-tool"),
            [lspci.text, "-nn"],
            timeout_seconds=timeout,
            output_limit=DEFAULT_OUTPUT_LIMIT,
        )
        if result.ok:
            for line in result.text.splitlines():
                match = re.match(
                    r"^([0-9a-fA-F:.]+)\s+(?:VGA compatible controller|3D controller|Display controller):\s+(.*?)\s+\[([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\]",
                    line,
                )
                if not match:
                    continue
                address, description, _ids = match.groups()
                for accelerator in accelerators:
                    existing = accelerator.get("pci_address")
                    if isinstance(existing, str) and existing.endswith(address):
                        accelerator["name"] = description.strip()

    nvidia = ledger.which(ProbeSpec("gpu-tool:nvidia-smi", "gpu-tool"), "nvidia-smi")
    if nvidia.ok:
        result = ledger.run(
            ProbeSpec("gpu-tool:nvidia-smi", "gpu-tool"),
            [
                nvidia.text,
                "--query-gpu=name,memory.total,memory.free,driver_version,compute_cap,pci.bus_id",
                "--format=csv,noheader,nounits",
            ],
            timeout_seconds=timeout,
            output_limit=DEFAULT_OUTPUT_LIMIT,
        )
        if result.ok:
            for line in result.text.splitlines():
                fields = [field.strip() for field in line.split(",")]
                if len(fields) < 6:
                    continue
                name, total, free, driver_version, compute, address = fields[:6]
                try:
                    total_bytes = int(float(total)) * 1024 * 1024
                    free_bytes = int(float(free)) * 1024 * 1024
                except ValueError:
                    total_bytes = None
                    free_bytes = None
                _merge_tool_accelerator(
                    accelerators,
                    {
                        "id": "nvidia:" + address,
                        "name": name,
                        "vendor_id": "0x10de",
                        "device_id": None,
                        "pci_class": "0x030000",
                        "pci_address": address,
                        "driver": "nvidia",
                        "driver_version": driver_version,
                        "compute_capability": compute,
                        "source": "nvidia-smi",
                        "pools": [
                            _make_pool(
                                name="vram",
                                kind="dedicated_vram",
                                total_bytes=total_bytes,
                                free_bytes=free_bytes,
                                source="nvidia-smi",
                            )
                        ],
                    },
                )

    rocm = ledger.which(ProbeSpec("gpu-tool:rocm-smi", "gpu-tool"), "rocm-smi")
    if rocm.ok:
        result = ledger.run(
            ProbeSpec("gpu-tool:rocm-smi", "gpu-tool"),
            [rocm.text, "--showproductname", "--showmeminfo", "vram", "--json"],
            timeout_seconds=timeout,
            output_limit=DEFAULT_OUTPUT_LIMIT,
        )
        if result.ok:
            try:
                payload = json.loads(result.text)
            except json.JSONDecodeError:
                ledger.record_observation(
                    ProbeSpec("gpu-tool:rocm-smi:parse", "gpu-tool"),
                    source="rocm-smi",
                    observation=Observation(
                        status=ProbeStatus.MALFORMED.value,
                        reason="parse_error",
                        detail="rocm-smi output was not valid JSON",
                    ),
                )
            else:
                if isinstance(payload, dict):
                    for key, raw in payload.items():
                        if not isinstance(key, str) or not re.fullmatch(r"card\d+", key):
                            continue
                        if not isinstance(raw, dict):
                            continue
                        card_id = "drm:" + key
                        total = raw.get("VRAM Total Memory (B)")
                        if not isinstance(total, (int, str)):
                            continue
                        try:
                            total_bytes = int(str(total))
                        except ValueError:
                            continue
                        for accelerator in accelerators:
                            if accelerator.get("id") != card_id:
                                continue
                            accelerator["name"] = raw.get("Card series") or raw.get("Card model")
                            pools = accelerator.setdefault("pools", [])
                            assert isinstance(pools, list)
                            pools[:] = [
                                pool
                                for pool in pools
                                if not (isinstance(pool, dict) and pool.get("name") == "vram")
                            ]
                            pools.append(
                                _make_pool(
                                    name="vram",
                                    kind=_classify_vram(accelerator),
                                    total_bytes=total_bytes,
                                    source="rocm-smi",
                                )
                            )
                            accelerator["source"] = "rocm-smi"
                            break

    hip = ledger.which(ProbeSpec("gpu-tool:hipconfig", "gpu-tool"), "hipconfig")
    if hip.ok:
        result = ledger.run(
            ProbeSpec("gpu-tool:hipconfig", "gpu-tool"),
            [hip.text, "--version"],
            timeout_seconds=timeout,
            output_limit=DEFAULT_OUTPUT_LIMIT,
        )
        if result.ok:
            for line in result.text.splitlines():
                if "version" in line.lower():
                    toolchain["hip_version"] = line.strip()
                    break
    return toolchain


def collect_host(ledger: ProbeLedger, policy: ProbePolicy) -> HostFacts:
    """Collect platform, CPU, memory, and accelerator observations."""
    findings: list[Finding] = []
    degraded = False
    platform_facts = ledger.platform_facts()
    system = str(platform_facts.get("system") or "")
    machine = str(platform_facts.get("machine") or "")
    release = str(platform_facts.get("release") or "")
    hostname = str(platform_facts.get("hostname") or "")
    mac_version = str(platform_facts.get("mac_version") or "")
    processor = str(platform_facts.get("processor") or "")
    cpu_count = platform_facts.get("cpu_count")
    physical_memory = platform_facts.get("physical_memory_bytes")
    python_facts = platform_facts.get("python")
    if not isinstance(python_facts, dict):
        python_facts = {}
    ledger.record_observation(
        ProbeSpec("host:kernel", "host", "required"),
        source="platform",
        observation=Observation(
            status=ProbeStatus.OK.value if system and release else ProbeStatus.UNAVAILABLE.value,
            text=json.dumps({"system": system, "release": release, "machine": machine}),
            reason=None if system and release else "platform_identity_unavailable",
        ),
    )
    os_release = ledger.read(
        ProbeSpec("host:os-release", "host"), Path("/etc/os-release"), limit=16 * 1024
    )
    os_values = parse_os_release(os_release.text) if os_release.ok else {}
    if os_values.get("ID") or os_values.get("NAME"):
        os_data: dict[str, object] = {
            "id": os_values.get("ID") or system.lower(),
            "name": os_values.get("NAME") or system,
            "version_id": os_values.get("VERSION_ID"),
            "pretty_name": os_values.get("PRETTY_NAME"),
            "source": "/etc/os-release",
            "fallback": False,
        }
    else:
        os_data = _platform_os(system, mac_version=mac_version, release=release)
    if not os_data.get("id"):
        degraded = True
    ledger.record_observation(
        ProbeSpec("host:os-identity", "host", "required"),
        source=str(os_data.get("source")),
        observation=Observation(
            status=ProbeStatus.OK.value if os_data.get("id") else ProbeStatus.UNAVAILABLE.value,
            text=json.dumps(os_data, sort_keys=True),
            reason=None if os_data.get("id") else "os_identity_unavailable",
        ),
    )

    cpu_model: str | None = None
    if system == "Linux":
        cpuinfo = ledger.read(ProbeSpec("host:cpuinfo", "host"), Path("/proc/cpuinfo"), limit=128 * 1024)
        if cpuinfo.ok:
            cpu_model = parse_cpuinfo_model(cpuinfo.text)
    if cpu_model is None:
        cpu_model = processor if processor and processor.lower() not in {"arm", "arm64"} else None
    cpu_data = {
        "model": cpu_model,
        "architecture": machine or None,
        "logical_cores": cpu_count if isinstance(cpu_count, int) else None,
        "source": "/proc/cpuinfo" if system == "Linux" and cpu_model else "platform",
    }
    ledger.record_observation(
        ProbeSpec("host:cpu", "host"),
        source=str(cpu_data["source"]),
        observation=Observation(
            status=ProbeStatus.OK.value,
            text=json.dumps(cpu_data, sort_keys=True),
        ),
    )

    memory_total: int | None = None
    memory_available: int | None = None
    memory_source = "unavailable"
    meminfo = ledger.read(
        ProbeSpec("host:meminfo", "memory"), Path("/proc/meminfo"), limit=64 * 1024
    )
    if meminfo.ok:
        values = parse_meminfo(meminfo.text)
        memory_total = values.get("MemTotal")
        memory_available = values.get("MemAvailable")
        memory_source = "/proc/meminfo"
    if memory_total is None:
        memory_total = physical_memory if isinstance(physical_memory, int) else None
        if memory_total is not None:
            memory_source = "sysconf"
    memory_system = {
        "total_bytes": memory_total,
        "available_bytes": memory_available,
        "source": memory_source,
    }
    ledger.record_observation(
        ProbeSpec("host:memory", "memory", "required"),
        source=memory_source,
        observation=Observation(
            status=ProbeStatus.OK.value if memory_total is not None else ProbeStatus.UNAVAILABLE.value,
            text=json.dumps(memory_system, sort_keys=True),
            reason=None if memory_total is not None else "system_memory_unavailable",
        ),
    )
    if memory_total is None:
        degraded = True

    (
        accelerators,
        accelerator_findings,
        accelerator_degraded,
        accelerator_enumeration,
    ) = _collect_accelerators(ledger, system=system)
    findings.extend(accelerator_findings)
    degraded = degraded or accelerator_degraded
    toolchain = _collect_device_queries(ledger, policy, accelerators)
    rocm_version_file = ledger.read(
        ProbeSpec("gpu:rocm-version-file", "gpu-tool"),
        Path("/opt/rocm/.info/version"),
        limit=4096,
    )
    if rocm_version_file.ok:
        toolchain["rocm_version"] = rocm_version_file.text.strip()
        toolchain["rocm_version_source"] = "/opt/rocm/.info/version"
    topology, topology_findings = resolve_memory_topology(
        system_total_bytes=memory_total,
        accelerators=accelerators,
    )
    findings.extend(topology_findings)
    degraded = degraded or topology["class"] == "ambiguous"
    data: dict[str, object] = {
        "identity": {"hostname": hostname or None, "platform": system or None},
        "os": os_data,
        "kernel": {"release": release or None, "machine": machine or None},
        "cpu": cpu_data,
        "memory": {"system": memory_system, "topology": topology},
        "accelerators": accelerators,
        "accelerator_enumeration": accelerator_enumeration,
        "runtime_toolchain": toolchain,
        "python": {
            "implementation": python_facts.get("implementation"),
            "version": python_facts.get("version"),
            "prefix": python_facts.get("prefix"),
            "base_prefix": python_facts.get("base_prefix"),
        },
    }
    return HostFacts(data=data, findings=tuple(findings), degraded=degraded)
