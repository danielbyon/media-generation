"""Determinism and sensitivity tests for environment fingerprints."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from media_generation.inventory import probes
from media_generation.inventory.fingerprint import build_environment_fingerprint
from media_generation.inventory.report import InventoryOptions, collect_inventory
from inventory_support import linux_host_observations, observation, write_replay


GIB = 1024**3


def _host() -> dict[str, object]:
    return {
        "identity": {"hostname": "synthetic-host", "platform": "Linux"},
        "os": {"id": "ubuntu", "name": "Ubuntu", "version_id": "24.04"},
        "kernel": {"release": "synthetic-kernel-1", "machine": "x86_64"},
        "cpu": {
            "model": "Synthetic CPU",
            "architecture": "x86_64",
            "logical_cores": 16,
        },
        "memory": {
            "system": {"total_bytes": 64 * GIB, "available_bytes": 32 * GIB},
            "topology": {
                "class": "unified_shared",
                "reported_total_bytes": 64 * GIB,
            },
        },
        "accelerators": [
            {
                "id": "drm:card1",
                "vendor_id": "0x1234",
                "device_id": "0x5678",
                "pci_class": "0x038000",
                "pci_address": "0000:01:00.0",
                "driver": "example-gpu",
                "driver_version": "6.12.0-synthetic",
                "name": "Synthetic GPU",
                "pools": [
                    {
                        "name": "vram",
                        "kind": "shared_carveout",
                        "total_bytes": 512 * 1024**2,
                    }
                ],
            }
        ],
        "python": {"implementation": "CPython", "version": "3.14.0"},
    }


def _runtimes() -> list[dict[str, object]]:
    return [
        {
            "id": "ollama",
            "presence": "observed",
            "path": "/usr/bin/ollama",
            "identity": {
                "size_bytes": 1234,
                "digest": {"status": "computed", "value": "sha256:abc"},
            },
            "version": {"status": "not_inspected", "value": None},
        },
        {
            "id": "comfyui",
            "presence": "observed",
            "path": "/synthetic/ComfyUI",
            "identity": {"status": "observed", "size_bytes": None},
            "version": {"status": "not_inspected", "value": None},
            "build": {
                "source_revision": {"status": "observed", "value": "a" * 40},
                "version_file": {"status": "observed", "value": "1.2.3"},
            },
        },
    ]


def test_fingerprint_is_stable_across_order_and_transient_values() -> None:
    """Probe ordering and free/used memory must not affect the digest."""
    first = build_environment_fingerprint(_host(), _runtimes())
    host = _host()
    memory = host["memory"]
    assert isinstance(memory, dict)
    system = memory["system"]
    assert isinstance(system, dict)
    system["available_bytes"] = 1
    host["identity"]["hostname"] = "different-host"  # type: ignore[index]
    accelerators = host["accelerators"]
    assert isinstance(accelerators, list)
    host["accelerators"] = list(reversed(accelerators))
    runtimes = list(reversed(_runtimes()))
    second = build_environment_fingerprint(host, runtimes)

    assert first["digest"] == second["digest"]
    assert "hostname" in first["excluded_inputs"]
    assert "memory_available_bytes" in first["excluded_inputs"]


def test_fingerprint_changes_when_kernel_changes() -> None:
    """A tracked kernel change must change the fingerprint."""
    first = build_environment_fingerprint(_host(), _runtimes())
    host = copy.deepcopy(_host())
    host["kernel"]["release"] = "synthetic-kernel-2"  # type: ignore[index]
    second = build_environment_fingerprint(host, _runtimes())
    assert first["digest"] != second["digest"]


def test_fingerprint_changes_when_runtime_identity_changes() -> None:
    """Executable identity participates even when version probes are disabled."""
    first = build_environment_fingerprint(_host(), _runtimes())
    runtimes = _runtimes()
    runtimes[0]["identity"]["digest"]["value"] = "sha256:def"  # type: ignore[index]
    second = build_environment_fingerprint(_host(), runtimes)
    assert first["digest"] != second["digest"]


def test_fingerprint_tracks_engine_source_revision() -> None:
    """A directory runtime's git build identity participates in the fingerprint."""
    first = build_environment_fingerprint(_host(), _runtimes())
    runtimes = copy.deepcopy(_runtimes())
    runtimes[1]["build"]["source_revision"]["value"] = "b" * 40  # type: ignore[index]
    second = build_environment_fingerprint(_host(), runtimes)

    assert first["digest"] != second["digest"]


def test_fingerprint_records_missing_cpu_as_unknown() -> None:
    """An unavailable CPU model remains explicit rather than disappearing."""
    host = _host()
    host["cpu"] = {"model": None, "architecture": None, "logical_cores": None}
    fingerprint = build_environment_fingerprint(host, _runtimes())
    inputs = fingerprint["inputs"]
    assert isinstance(inputs, dict)
    assert inputs["cpu"] == {"status": "unknown", "reason": "cpu_identity_unavailable"}


def test_replay_distribution_metadata_is_independent_of_local_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Synthetic replay never consults the host's installed distributions."""
    observations = linux_host_observations()
    for name, version in (
        ("torch", "2.5.0-synthetic"),
        ("diffusers", "0.31.0-synthetic"),
        ("transformers", "4.46.0-synthetic"),
        ("rocm", "6.2.0-synthetic"),
    ):
        observations[f"distribution:{name}"] = observation(
            json.dumps({"version": version, "location": f"/synthetic/{name}"})
        )
    replay = write_replay(tmp_path / "replay.json", observations)
    options = InventoryOptions(output_directory=tmp_path / "out", replay_path=replay)

    first = collect_inventory(options).inventory
    calls: list[str] = []
    real_distribution = probes.importlib.metadata.distribution

    def fail_distribution(name: str) -> object:
        if name == "media-generation":
            return real_distribution(name)
        calls.append(name)
        raise AssertionError("replay must not read local distribution metadata")

    monkeypatch.setattr(probes.importlib.metadata, "distribution", fail_distribution)
    second = collect_inventory(options).inventory

    assert calls == []
    assert first["runtimes"] == second["runtimes"]
    assert first["environment_fingerprint"] == second["environment_fingerprint"]
    torch = next(runtime for runtime in first["runtimes"] if runtime["id"] == "torch")
    assert torch["version"]["value"] == "2.5.0-synthetic"


def test_replay_unrecorded_distribution_is_not_an_absence_claim(
    tmp_path: Path,
) -> None:
    """A missing replay record means not inspected, not an installed-package absence."""
    observations = linux_host_observations()
    for name in ("torch", "diffusers", "transformers", "rocm"):
        observations.pop(f"distribution:{name}", None)
    replay = write_replay(tmp_path / "replay.json", observations)

    inventory = collect_inventory(
        InventoryOptions(output_directory=tmp_path / "out", replay_path=replay)
    ).inventory

    torch = next(runtime for runtime in inventory["runtimes"] if runtime["id"] == "torch")
    assert torch["presence"] == "not_inspected"
    assert torch["version"]["status"] == "not_inspected"
    assert torch["version"]["reason"] == "not_recorded"
