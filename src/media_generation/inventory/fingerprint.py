"""Deterministic environment fingerprints over stable observed components.

The fingerprint intentionally ignores run metadata, transient memory use, probe
order, and hostnames.  Missing stable components remain in the input document as
explicit unknown entries so enabling a previously unavailable probe changes the
digest instead of silently disappearing from it.
"""

from __future__ import annotations

from typing import Any

from .schema import (
    FINGERPRINT_ALGORITHM,
    FINGERPRINT_INPUT_VERSION,
    digest_value,
)


EXCLUDED_INPUTS = (
    "run_id",
    "started_at",
    "finished_at",
    "duration_ms",
    "probe_order",
    "memory_available_bytes",
    "memory_free_bytes",
    "hostname",
    "output_directory",
    "manifest_path",
    "environment_variables",
    "locale",
)


def _unknown(reason: str) -> dict[str, object]:
    """Represent a missing stable attribute explicitly."""
    return {"status": "unknown", "reason": reason}


def _stable_os(os_data: dict[str, Any]) -> dict[str, object]:
    """Return the stable subset of OS identity."""
    identifier = os_data.get("id")
    if not identifier:
        return _unknown("os_identity_unavailable")
    return {
        "id": identifier,
        "version_id": os_data.get("version_id"),
    }


def _stable_kernel(kernel: dict[str, Any]) -> dict[str, object]:
    """Return the stable subset of kernel identity."""
    release = kernel.get("release")
    if not release:
        return _unknown("kernel_release_unavailable")
    return {"release": release, "machine": kernel.get("machine")}


def _stable_cpu(cpu: dict[str, Any]) -> dict[str, object]:
    """Return the stable subset of CPU identity."""
    model = cpu.get("model")
    architecture = cpu.get("architecture")
    if not model and not architecture:
        return _unknown("cpu_identity_unavailable")
    return {
        "model": model,
        "architecture": architecture,
        "logical_cores": cpu.get("logical_cores"),
    }


def _stable_accelerators(accelerators: list[dict[str, Any]]) -> list[dict[str, object]]:
    """Return sorted accelerator identity plus reported pool sizes."""
    stable: list[dict[str, object]] = []
    for accelerator in accelerators:
        pools = accelerator.get("pools")
        pool_values: list[dict[str, object]] = []
        if isinstance(pools, list):
            for pool in pools:
                if not isinstance(pool, dict):
                    continue
                pool_values.append(
                    {
                        "name": pool.get("name"),
                        "kind": pool.get("kind"),
                        "total_bytes": pool.get("total_bytes"),
                    }
                )
        pool_values.sort(key=lambda item: str(item.get("name")))
        stable.append(
            {
                "id": accelerator.get("id"),
                "vendor_id": accelerator.get("vendor_id"),
                "device_id": accelerator.get("device_id"),
                "pci_class": accelerator.get("pci_class"),
                "pci_address": accelerator.get("pci_address"),
                "driver": accelerator.get("driver"),
                "driver_version": accelerator.get("driver_version"),
                "name": accelerator.get("name"),
                "pools": pool_values,
            }
        )
    stable.sort(key=lambda item: str(item.get("id")))
    return stable


def _stable_runtimes(runtimes: list[dict[str, Any]]) -> list[dict[str, object]]:
    """Return runtimes sorted by catalog id, including observed executable identity."""
    stable: list[dict[str, object]] = []
    for runtime in runtimes:
        identity = runtime.get("identity")
        identity_dict = identity if isinstance(identity, dict) else {}
        digest = identity_dict.get("digest")
        digest_dict = digest if isinstance(digest, dict) else {"status": "unavailable"}
        version = runtime.get("version")
        version_dict = version if isinstance(version, dict) else {"status": "unavailable"}
        build = runtime.get("build")
        build_dict = build if isinstance(build, dict) else {}
        revision = build_dict.get("source_revision")
        revision_dict = revision if isinstance(revision, dict) else {"status": "unavailable"}
        version_file = build_dict.get("version_file")
        version_file_dict = (
            version_file if isinstance(version_file, dict) else {"status": "unavailable"}
        )
        stable.append(
            {
                "id": runtime.get("id"),
                "presence": runtime.get("presence"),
                "path": runtime.get("path"),
                "size_bytes": identity_dict.get("size_bytes"),
                "executable": identity_dict.get("executable"),
                "digest_status": digest_dict.get("status"),
                "digest": digest_dict.get("value"),
                "version_status": version_dict.get("status"),
                "version": version_dict.get("value"),
                "source_revision_status": revision_dict.get("status"),
                "source_revision": revision_dict.get("value"),
                "version_file_status": version_file_dict.get("status"),
                "version_file": version_file_dict.get("value"),
            }
        )
    stable.sort(key=lambda item: str(item.get("id")))
    return stable


def _stable_accelerator_enumeration(value: object) -> dict[str, object]:
    """Return accelerator coverage so incomplete scans change the digest."""
    if not isinstance(value, dict):
        return {"status": "unknown"}
    return {
        "status": value.get("status"),
        "reason": value.get("reason"),
        "candidate_count": value.get("candidate_count"),
        "inspected_count": value.get("inspected_count"),
        "inspection_failures": value.get("inspection_failures"),
        "listing_truncated": value.get("listing_truncated"),
        "card_limit_reached": value.get("card_limit_reached"),
    }


def build_environment_fingerprint(
    host: dict[str, Any], runtimes: list[dict[str, Any]]
) -> dict[str, object]:
    """Build and digest the canonical stable environment input document."""
    memory = host.get("memory")
    memory_dict = memory if isinstance(memory, dict) else {}
    topology = memory_dict.get("topology")
    topology_dict = topology if isinstance(topology, dict) else {}
    inputs: dict[str, object] = {
        "os": _stable_os(host.get("os") or {}),
        "kernel": _stable_kernel(host.get("kernel") or {}),
        "cpu": _stable_cpu(host.get("cpu") or {}),
        "accelerators": _stable_accelerators(host.get("accelerators") or []),
        "accelerator_enumeration": _stable_accelerator_enumeration(
            host.get("accelerator_enumeration")
        ),
        "memory": {
            "system_total_bytes": (memory_dict.get("system") or {}).get("total_bytes")
            if isinstance(memory_dict.get("system"), dict)
            else None,
            "topology": topology_dict.get("class"),
            "reported_total_bytes": topology_dict.get("reported_total_bytes"),
        },
        "runtimes": _stable_runtimes(runtimes),
        "python": {
            "implementation": (host.get("python") or {}).get("implementation")
            if isinstance(host.get("python"), dict)
            else None,
            "version": (host.get("python") or {}).get("version")
            if isinstance(host.get("python"), dict)
            else None,
        },
    }
    return {
        "algorithm": FINGERPRINT_ALGORITHM,
        "input_version": FINGERPRINT_INPUT_VERSION,
        "digest": digest_value(inputs),
        "inputs": inputs,
        "excluded_inputs": list(EXCLUDED_INPUTS),
    }
