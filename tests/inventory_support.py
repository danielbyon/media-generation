"""Shared helpers for synthetic inventory and black-box CLI tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLI_ENTRY_POINT = Path(sysconfig.get_path("scripts")) / "media-generation"


def run_cli(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run the installed console entry point outside the checkout."""
    assert CLI_ENTRY_POINT.is_file(), "install the project with: pip install -e '.[test]'"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [str(CLI_ENTRY_POINT), *arguments],
        cwd=cwd or Path(tempfile.gettempdir()),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def run_module_cli(
    *arguments: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the documented ``python3 -m media_generation`` entry point."""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "media_generation", *arguments],
        cwd=cwd or REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def json_stdout(process: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse a successful command's JSON response."""
    assert process.returncode in {0, 4, 5}, process.stderr
    payload = json.loads(process.stdout)
    assert isinstance(payload, dict)
    return payload


def json_stderr(process: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Parse a failed command's structured error response."""
    assert process.returncode != 0
    assert process.stdout == ""
    payload = json.loads(process.stderr)
    assert isinstance(payload, dict)
    return payload


def stat_payload(
    *,
    kind: str = "file",
    size_bytes: int = 0,
    symlink: bool = False,
    realpath: str = "/synthetic/path",
    link_target: str | None = None,
    executable: bool = False,
) -> dict[str, object]:
    """Build a synthetic lstat payload matching the local source shape."""
    payload: dict[str, object] = {
        "exists": True,
        "kind": kind,
        "size_bytes": size_bytes,
        "mtime": "2026-01-01T00:00:00Z",
        "symlink": symlink,
        "realpath": realpath,
        "executable": executable,
    }
    if link_target is not None:
        payload["link_target"] = link_target
    return payload


def observation(text: str = "", *, status: str = "ok", **fields: object) -> dict[str, object]:
    """Build one replay observation entry."""
    payload: dict[str, object] = {"status": status, "text": text}
    payload.update(fields)
    return payload


def write_replay(
    path: Path,
    observations: dict[str, dict[str, object]],
    platform: dict[str, object] | None = None,
) -> Path:
    """Write a clearly synthetic replay document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "media-generation.inventory-replay",
        "schema_version": 1,
        "synthetic": True,
        "description": "Synthetic observations for deterministic tests; not host evidence.",
        "platform": platform
        or {
            "system": "Linux",
            "release": "synthetic-kernel-1",
            "machine": "x86_64",
            "hostname": "synthetic-host",
            "processor": "synthetic-cpu",
            "cpu_count": 16,
            "physical_memory_bytes": 64 * 1024**3,
            "python": {
                "implementation": "CPython",
                "version": "3.14.0",
                "prefix": "/synthetic/python",
                "base_prefix": "/synthetic/python",
            },
        },
        "observations": observations,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def linux_host_observations(
    *,
    with_gpu: bool = True,
    with_drm_listing: bool = True,
    device_symlink: bool = False,
    meminfo: str | None = None,
) -> dict[str, dict[str, object]]:
    """Return synthetic Linux host observations with no real host values."""
    observations: dict[str, dict[str, object]] = {
        "read:/etc/os-release": observation(
            'ID=example-linux\nNAME="Example Linux"\nVERSION_ID="1.0"\n'
            'PRETTY_NAME="Example Linux (synthetic fixture)"\n'
        ),
        "read:/proc/meminfo": observation(
            meminfo
            or "MemTotal:       67108864 kB\n"
            "MemAvailable:   33554432 kB\n"
            "MemFree:        16777216 kB\n"
            "SwapTotal:       8388608 kB\n"
        ),
        "read:/proc/cpuinfo": observation(
            "processor\t: 0\nmodel name\t: Synthetic Example CPU (fixture)\n"
        ),
    }
    if with_drm_listing:
        entries = (
            [
                {
                    "name": "card1",
                    "kind": "directory",
                    "size_bytes": 0,
                    "symlink": False,
                }
            ]
            if with_gpu
            else []
        )
        observations["list:/sys/class/drm"] = observation(json.dumps(entries))
    if with_gpu:
        device = "/sys/class/drm/card1/device"
        if device_symlink:
            target = "/sys/devices/pci0000:00/0000:00:01.0/0000:01:00.0"
            observations[f"stat:{device}"] = observation(
                json.dumps(
                    stat_payload(
                        kind="symlink",
                        symlink=True,
                        realpath=target,
                        link_target="../../../devices/pci0000:00/0000:00:01.0/0000:01:00.0",
                    )
                )
            )
        else:
            observations[f"stat:{device}"] = observation(
                json.dumps(stat_payload(kind="directory", realpath=device))
            )
        read_base = target if device_symlink else device
        observations[f"read:{read_base}/vendor"] = observation("0x1234\n")
        observations[f"read:{read_base}/device"] = observation("0x5678\n")
        observations[f"read:{read_base}/class"] = observation("0x038000\n")
        observations[f"read:{read_base}/uevent"] = observation(
            "DRIVER=example-gpu\nPCI_CLASS=38000\nPCI_SLOT_NAME=0000:01:00.0\n"
        )
        observations[f"stat:{read_base}/driver"] = observation(
            json.dumps(
                stat_payload(
                    kind="symlink",
                    symlink=True,
                    link_target="../../../../bus/pci/drivers/example-gpu",
                    realpath=read_base + "/driver",
                )
            )
        )
        observations[f"read:{read_base}/mem_info_vram_total"] = observation("536870912\n")
        observations[f"read:{read_base}/mem_info_vis_vram_total"] = observation("536870912\n")
        observations[f"read:{read_base}/mem_info_gtt_total"] = observation("34359738368\n")
        observations["read:/sys/module/example-gpu/version"] = observation("1.0-synthetic\n")
    for name in ("sd", "stable-diffusion.cpp", "invokeai", "ollama", "llama-server", "llama-cli"):
        observations[f"which:{name}"] = observation(status="unavailable", reason="binary_not_found")
    observations["read:/opt/rocm/.info/version"] = observation(
        status="unavailable", reason="file_not_found"
    )
    for name, version in (
        ("torch", "2.5.0-synthetic"),
        ("diffusers", "0.31.0-synthetic"),
        ("transformers", "4.46.0-synthetic"),
        ("rocm", "6.2.0-synthetic"),
    ):
        observations[f"distribution:{name}"] = observation(
            json.dumps({"version": version, "location": f"/synthetic/{name}"})
        )
    return observations


def build_safetensors(header: dict[str, object]) -> bytes:
    """Build a minimal, valid safetensors-like byte string."""
    raw = json.dumps(header).encode("utf-8")
    return len(raw).to_bytes(8, "little") + raw + b"\x00" * 64


def _gguf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return len(raw).to_bytes(8, "little") + raw


def build_gguf(entries: list[tuple[str, int, object]], *, version: int = 3) -> bytes:
    """Build a minimal GGUF header with scalar or string metadata values."""
    payload = bytearray(b"GGUF")
    payload += version.to_bytes(4, "little")
    payload += (0).to_bytes(8, "little")
    payload += len(entries).to_bytes(8, "little")
    for key, value_type, value in entries:
        payload += _gguf_string(key)
        payload += value_type.to_bytes(4, "little")
        if value_type == 8:
            payload += _gguf_string(str(value))
        elif value_type == 7:
            payload += (1 if value else 0).to_bytes(1, "little")
        elif value_type == 4:
            payload += int(value).to_bytes(4, "little")
        elif value_type == 10:
            payload += int(value).to_bytes(8, "little")
        else:  # pragma: no cover - helper guard
            raise AssertionError(f"unsupported helper value type {value_type}")
    return bytes(payload) + b"\x00" * 64
