"""Black-box tests for the read-only inventory command."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from inventory_support import (
    build_gguf,
    json_stderr,
    json_stdout,
    linux_host_observations,
    observation,
    run_cli,
    run_module_cli,
    stat_payload,
    write_replay,
)


GIB = 1024**3


def _run_replay(tmp_path: Path, observations: dict[str, dict[str, object]], **kwargs: object):
    replay = write_replay(tmp_path / "replay.json", observations, **kwargs)  # type: ignore[arg-type]
    output = tmp_path / "output"
    process = run_cli("inventory", "--replay", str(replay), "--output", str(output))
    return process, output


def test_documented_module_entry_point_runs_inventory(tmp_path: Path) -> None:
    """The documented ``python3 -m media_generation inventory`` path works."""
    replay = write_replay(tmp_path / "replay.json", linux_host_observations())
    output = tmp_path / "out"

    process = run_module_cli(
        "inventory", "--replay", str(replay), "--output", str(output)
    )

    assert process.returncode == 0, process.stderr
    summary = json_stdout(process)
    assert summary["evidence_gate"]["evidence_origin"] == "synthetic_replay"  # type: ignore[index]
    assert (output / "inventory.json").is_file()
    assert (output / "transcript.txt").is_file()


def test_inventory_help_is_available() -> None:
    """The new command exposes conventional argparse help."""
    process = run_cli("inventory", "--help")
    assert process.returncode == 0
    assert process.stdout.startswith("usage: media-generation inventory")
    assert process.stderr == ""


def test_missing_output_argument_uses_structured_error() -> None:
    """Argument syntax failures retain the T01 structured error contract."""
    process = run_cli("inventory")
    error = json_stderr(process)
    assert error["error"]["code"] == "argument_error"  # type: ignore[index]


def test_replay_reports_unified_memory_without_double_counting(tmp_path: Path) -> None:
    """A synthetic APU-like fixture reports shared pools separately."""
    process, output = _run_replay(tmp_path, linux_host_observations())
    summary = json_stdout(process)

    assert process.returncode == 0
    assert summary["host_inventory_status"] == "ok"
    assert summary["configuration_inspection"] == "not_configured"
    assert summary["evidence_gate"]["report_written"] is True  # type: ignore[index]
    assert summary["evidence_gate"]["apex_verification"] == "unverified"  # type: ignore[index]
    assert summary["evidence_gate"]["evidence_origin"] == "synthetic_replay"  # type: ignore[index]

    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["schema"] == "media-generation.inventory"
    assert inventory["schema_version"] == 1
    assert inventory["run"]["mode"] == "replay"
    assert inventory["model_inventory"]["inspection"] == "not_configured"  # type: ignore[index]
    assert inventory["model_inventory"]["reason"] == "manifest_not_supplied"  # type: ignore[index]
    assert "absent" not in json.dumps(inventory["model_inventory"])
    topology = inventory["host"]["memory"]["topology"]
    assert topology["class"] == "unknown"
    assert topology["reported_total_bytes"] == 64 * GIB
    assert [pool["id"] for pool in topology["allocatable_pools"]] == ["system_ram"]
    assert "unknown_sharing" in {
        item["relationship"] for item in topology["sharing_relationships"]
    }
    assert inventory["runtimes"]
    assert all(runtime["presence"] != "absent" for runtime in inventory["runtimes"])
    transcript = (output / "transcript.txt").read_text(encoding="utf-8")
    assert "SYNTHETIC REPLAY" in transcript
    assert "host_inventory_status: ok" in transcript
    assert "evidence_origin: synthetic_replay" in transcript
    assert "apex_verification: unverified" in transcript
    assert "environment_fingerprint: sha256:" in transcript


def test_replay_partial_and_blocked_statuses_are_distinct_from_write_success(
    tmp_path: Path,
) -> None:
    """Report writing succeeds while exit codes expose incomplete or blocked runs."""
    partial_process, partial_output = _run_replay(
        tmp_path / "partial",
        linux_host_observations(with_drm_listing=False),
    )
    partial_summary = json_stdout(partial_process)
    assert partial_process.returncode == 4
    assert partial_summary["host_inventory_status"] == "partial"
    assert partial_summary["evidence_gate"]["report_written"] is True  # type: ignore[index]
    assert (partial_output / "inventory.json").is_file()

    blocked_process, blocked_output = _run_replay(
        tmp_path / "blocked",
        {},
        platform={
            "system": "Windows",
            "release": "synthetic-10",
            "machine": "AMD64",
            "hostname": "synthetic-host",
        },
    )
    blocked_summary = json_stdout(blocked_process)
    assert blocked_process.returncode == 5
    assert blocked_summary["host_inventory_status"] == "blocked"
    assert blocked_summary["evidence_gate"]["host_inventory_status"] == "blocked"  # type: ignore[index]
    assert blocked_summary["evidence_gate"]["report_written"] is True  # type: ignore[index]
    blocked = json.loads((blocked_output / "inventory.json").read_text(encoding="utf-8"))
    assert blocked["host"]["memory"]["system"]["total_bytes"] is None
    assert blocked["evidence_gate"]["capability_qualification"] == "unverified"


def test_repeated_replay_runs_are_safe_and_fingerprint_is_stable(tmp_path: Path) -> None:
    """Repeated output replaces files atomically and stable inputs keep the digest."""
    replay = write_replay(tmp_path / "replay.json", linux_host_observations())
    output = tmp_path / "output"
    first = run_cli("inventory", "--replay", str(replay), "--output", str(output))
    first_summary = json_stdout(first)
    second = run_cli("inventory", "--replay", str(replay), "--output", str(output))
    second_summary = json_stdout(second)

    assert first.returncode == 0 and second.returncode == 0
    assert first_summary["run_id"] != second_summary["run_id"]
    assert first_summary["environment_fingerprint"] == second_summary["environment_fingerprint"]
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["run"]["run_id"] == second_summary["run_id"]


def test_missing_or_malformed_manifest_fails_without_writing_output(
    tmp_path: Path,
) -> None:
    """Declaration failures are exit-2 errors, not partial reports."""
    output = tmp_path / "output"
    missing = run_cli(
        "inventory", "--manifest", str(tmp_path / "missing.json"), "--output", str(output)
    )
    error = json_stderr(missing)
    assert error["error"]["code"] == "inventory_validation_error"  # type: ignore[index]
    assert not (output / "inventory.json").exists()

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    process = run_cli(
        "inventory", "--manifest", str(malformed), "--output", str(output)
    )
    assert json_stderr(process)["error"]["code"] == "inventory_validation_error"  # type: ignore[index]


@pytest.mark.parametrize("option", ["--manifest", "--replay"])
def test_symlink_loop_path_is_a_structured_validation_error(
    tmp_path: Path, option: str
) -> None:
    """Path-resolution loops do not escape the CLI error contract."""
    loop = tmp_path / "loop"
    loop.symlink_to(loop)
    output = tmp_path / "output"

    process = run_cli("inventory", option, str(loop), "--output", str(output))

    error = json_stderr(process)
    assert process.returncode == 2
    assert error["error"]["code"] == "inventory_validation_error"  # type: ignore[index]
    assert error["error"]["message"]  # type: ignore[index]
    assert not (output / "inventory.json").exists()


def test_replay_document_must_be_synthetic(tmp_path: Path) -> None:
    """A replay file cannot be presented as real host evidence."""
    replay = tmp_path / "replay.json"
    replay.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-replay",
                "schema_version": 1,
                "synthetic": False,
                "observations": {},
            }
        ),
        encoding="utf-8",
    )
    process = run_cli(
        "inventory", "--replay", str(replay), "--output", str(tmp_path / "out")
    )
    assert json_stderr(process)["error"]["code"] == "inventory_validation_error"  # type: ignore[index]


def test_output_path_that_is_a_file_fails_with_output_error(tmp_path: Path) -> None:
    """Output failures have a distinct structured code and exit status."""
    output = tmp_path / "not-a-directory"
    output.write_text("occupied", encoding="utf-8")
    process = run_cli("inventory", "--output", str(output))
    error = json_stderr(process)
    assert process.returncode == 3
    assert error["error"]["code"] == "inventory_output_error"  # type: ignore[index]


def test_invalid_hash_limit_is_rejected(tmp_path: Path) -> None:
    """A non-positive hash bound cannot silently disable the limit."""
    process = run_cli(
        "inventory",
        "--output",
        str(tmp_path / "out"),
        "--hash-limit-bytes",
        "0",
    )
    assert json_stderr(process)["error"]["code"] == "inventory_validation_error"  # type: ignore[index]


def _write_bundle_manifest(tmp_path: Path) -> tuple[Path, Path]:
    """Create a real GGUF file and a manifest that references it."""
    models = tmp_path / "models"
    models.mkdir()
    model = models / "synthetic.gguf"
    model.write_bytes(
        build_gguf(
            [
                ("general.architecture", 8, "qwen_image"),
                ("general.file_type", 4, 14),
            ]
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-manifest",
                "schema_version": 1,
                "model_roots": [{"id": "models", "path": "models"}],
                "bundles": [
                    {
                        "id": "bundle-a",
                        "engine": "stable-diffusion.cpp",
                        "recipe": {
                            "id": "recipe-a",
                            "source": {"kind": "operator", "value": "synthetic fixture"},
                            "parameters": {"steps": 20},
                        },
                        "components": [
                            {
                                "id": "transformer",
                                "role": "diffusion_model",
                                "path": "models/synthetic.gguf",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest, model


def test_bundle_without_hashing_is_declared_not_complete(tmp_path: Path) -> None:
    """Filename and header inspection never imply a content-addressed bundle."""
    manifest, _ = _write_bundle_manifest(tmp_path)
    output = tmp_path / "out"
    process = run_cli("inventory", "--manifest", str(manifest), "--output", str(output))
    assert process.returncode in {0, 4}
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    bundle = inventory["bundles"][0]
    model_inventory = inventory["model_inventory"]

    assert model_inventory["inspection"] == "configured"  # type: ignore[index]
    assert model_inventory["model_roots"]["items"][0]["inspection"] == (  # type: ignore[index]
        "boundary_only_not_scanned"
    )
    assert bundle["identity"]["status"] == "declared"
    assert bundle["identity"]["digest"] is None
    component = bundle["components"][0]
    assert component["digest"]["status"] == "unchecked"
    assert component["metadata"]["format"] == "gguf"
    assert component["metadata"]["quantization"] == "Q4_K_S"
    assert bundle["capabilities"]["status"] == "not_configured"


def test_bundle_with_explicit_hashing_becomes_complete(tmp_path: Path) -> None:
    """Opt-in hashing produces authentic digests and a complete bundle identity."""
    manifest, model = _write_bundle_manifest(tmp_path)
    output = tmp_path / "out"
    process = run_cli(
        "inventory",
        "--manifest",
        str(manifest),
        "--output",
        str(output),
        "--hash-components",
    )
    assert process.returncode in {0, 4}
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    bundle = inventory["bundles"][0]
    component = bundle["components"][0]

    assert component["digest"]["status"] == "computed"
    assert component["digest"]["value"].startswith("sha256:")
    assert bundle["identity"]["status"] == "complete"
    assert bundle["identity"]["digest"].startswith("sha256:")
    assert inventory["run"]["hash_components"] is True
    assert model.stat().st_size > 0


def test_local_inventory_runs_without_apex_or_gpu(tmp_path: Path) -> None:
    """The command produces a schema-valid report on an ordinary development host."""
    output = tmp_path / "local"
    process = run_cli("inventory", "--output", str(output))
    assert process.returncode in {0, 4}
    summary = json_stdout(process)
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))

    assert summary["host_inventory_status"] in {"ok", "partial"}
    assert inventory["schema_version"] == 1
    assert inventory["run"]["mode"] == "local"
    assert inventory["environment_fingerprint"]["digest"].startswith("sha256:")
    assert inventory["host"]["memory"]["topology"]["class"] in {
        "unified_shared",
        "discrete",
        "ambiguous",
        "unknown",
    }
    transcript = (output / "transcript.txt").read_text(encoding="utf-8")
    for probe in inventory["probes"]:
        assert probe["probe_id"] in transcript


def test_configured_empty_manifest_does_not_claim_model_absence(tmp_path: Path) -> None:
    """Supplying an empty manifest configures inspection without finding anything."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-manifest",
                "schema_version": 1,
                "model_roots": [],
                "runtimes": [],
                "bundles": [],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"
    process = run_cli("inventory", "--manifest", str(manifest), "--output", str(output))
    summary = json_stdout(process)
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))

    assert summary["configuration_inspection"] == "configured"
    assert inventory["model_inventory"] == {
        "inspection": "not_configured",
        "reason": "no_bundles_declared",
        "model_roots": {"status": "not_configured", "items": []},
        "bundles": {"status": "not_configured", "declared_count": 0},
    }
    assert inventory["bundles"] == []


def _runtime_manifest(tmp_path: Path, *, probe_version: bool) -> tuple[Path, Path, Path]:
    """Create an explicit runtime path and a marker that proves execution."""
    executable = tmp_path / "bin" / "ollama"
    executable.parent.mkdir()
    marker = tmp_path / "executed"
    executable.write_text(
        "#!/bin/sh\n"
        f"touch {shlex.quote(str(marker))}\n"
        "echo 'fake ollama version 9.9.9'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-manifest",
                "schema_version": 1,
                "runtimes": [
                    {
                        "id": "ollama",
                        "path": "bin/ollama",
                        "probe_version": probe_version,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest, executable, marker


def test_explicit_runtime_path_is_identified_without_executing_it(tmp_path: Path) -> None:
    """Passive runtime identity includes path, metadata, and an authentic digest."""
    manifest, executable, marker = _runtime_manifest(tmp_path, probe_version=False)
    output = tmp_path / "out"
    process = run_cli("inventory", "--manifest", str(manifest), "--output", str(output))
    assert process.returncode in {0, 4}
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    runtime = next(item for item in inventory["runtimes"] if item["id"] == "ollama")

    assert runtime["presence"] == "observed"
    assert runtime["path"] == str(executable.resolve())
    assert runtime["identity"]["size_bytes"] == executable.stat().st_size
    assert runtime["identity"]["executable"] is True
    assert runtime["identity"]["digest"]["status"] == "computed"
    assert runtime["identity"]["digest"]["value"].startswith("sha256:")
    assert runtime["version"]["status"] == "not_inspected"
    assert runtime["version"]["reason"] == "version_probe_not_enabled"
    assert not marker.exists()


def test_version_probe_runs_only_after_explicit_opt_in(tmp_path: Path) -> None:
    """The fixed catalog argv runs only when the manifest declares it."""
    manifest, _, marker = _runtime_manifest(tmp_path, probe_version=True)
    output = tmp_path / "out"
    process = run_cli("inventory", "--manifest", str(manifest), "--output", str(output))
    assert process.returncode in {0, 4}
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    runtime = next(item for item in inventory["runtimes"] if item["id"] == "ollama")

    assert marker.is_file()
    assert runtime["version"] == {
        "status": "observed",
        "value": "9.9.9",
        "source": "command",
    }
    version_probe = next(
        probe for probe in inventory["probes"] if probe["probe_id"] == "runtime:ollama:version"
    )
    assert version_probe["command"] == [str(Path(runtime["path"])), "--version"]


def test_declared_capabilities_remain_unqualified(tmp_path: Path) -> None:
    """Manifest claims never become local execution or qualification evidence."""
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-manifest",
                "schema_version": 1,
                "runtimes": [
                    {
                        "id": "ollama",
                        "declared_capabilities": [
                            {
                                "task": "text_to_image",
                                "support": "declared",
                                "source": {"kind": "operator", "value": "synthetic fixture"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"
    process = run_cli("inventory", "--manifest", str(manifest), "--output", str(output))
    assert process.returncode in {0, 4}
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    runtime = next(item for item in inventory["runtimes"] if item["id"] == "ollama")
    capability = runtime["capabilities"]["items"][0]

    assert capability["support"] == "declared"
    assert capability["local_execution"] == "not_performed"
    assert capability["qualification"] == "unqualified"
    assert inventory["evidence_gate"]["capability_qualification"] == "unverified"


def test_device_queries_require_explicit_opt_in(tmp_path: Path) -> None:
    """Without policy opt-in, no GPU command is resolved or executed."""
    observations = linux_host_observations()
    observations["which:rocm-smi"] = {"status": "ok", "text": "/synthetic/rocm-smi"}
    process, output = _run_replay(tmp_path, observations)
    assert process.returncode == 0
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))

    assert not [
        probe for probe in inventory["probes"] if probe["probe_id"].startswith("gpu-tool:")
    ]
    policy_probe = next(
        probe for probe in inventory["probes"] if probe["probe_id"] == "gpu:device-queries"
    )
    assert policy_probe["status"] == "skipped"
    assert policy_probe["reason"] == "disabled_by_policy"


def test_replay_accepts_trusted_sysfs_device_symlink(tmp_path: Path) -> None:
    """A DRM card device link resolved under /sys/devices is inspected."""
    process, output = _run_replay(
        tmp_path, linux_host_observations(device_symlink=True)
    )

    summary = json_stdout(process)
    assert process.returncode == 0
    assert summary["host_inventory_status"] == "ok"
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    accelerators = inventory["host"]["accelerators"]
    assert len(accelerators) == 1
    assert accelerators[0]["id"] == "drm:card1"
    assert accelerators[0]["pools"]
    assert inventory["host"]["memory"]["topology"]["class"] == "unknown"


def test_replay_untrusted_sysfs_device_symlink_is_partial(tmp_path: Path) -> None:
    """A device link outside /sys/devices cannot become a successful absence claim."""
    observations = linux_host_observations()
    observations["stat:/sys/class/drm/card1/device"] = observation(
        json.dumps(
            stat_payload(
                kind="symlink",
                symlink=True,
                realpath="/tmp/untrusted-device",
                link_target="../../tmp/untrusted-device",
            )
        )
    )

    process, output = _run_replay(tmp_path, observations)

    assert process.returncode == 4
    summary = json_stdout(process)
    assert summary["host_inventory_status"] == "partial"
    assert summary["evidence_gate"]["report_written"] is True  # type: ignore[index]
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["host"]["accelerators"] == []
    transcript = (output / "transcript.txt").read_text(encoding="utf-8")
    assert "no absence claim is made" in transcript


def test_replay_inaccessible_drm_device_is_partial(tmp_path: Path) -> None:
    """A permission failure is unavailable, not evidence that no GPU exists."""
    observations = linux_host_observations()
    observations["stat:/sys/class/drm/card1/device"] = observation(
        status="unavailable", reason="permission_denied", text=""
    )

    process, output = _run_replay(tmp_path, observations)

    assert process.returncode == 4
    summary = json_stdout(process)
    assert summary["host_inventory_status"] == "partial"
    inventory = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
    assert inventory["host"]["accelerators"] == []
    transcript = (output / "transcript.txt").read_text(encoding="utf-8")
    assert "permission_denied" in transcript
