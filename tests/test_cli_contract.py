"""Black-box tests for the locally installed generation command."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one independent CLI process against the source checkout."""
    environment = os.environ.copy()
    source_root = str(REPOSITORY_ROOT / "src")
    current_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root
        if not current_pythonpath
        else os.pathsep.join((source_root, current_pythonpath))
    )
    return subprocess.run(
        [sys.executable, "-m", "media_generation", *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def _json_output(process: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert process.returncode == 0, (
        f"CLI exited with {process.returncode}: {process.stderr}"
    )
    return json.loads(process.stdout)


def _json_error(process: subprocess.CompletedProcess[str]) -> dict[str, object]:
    assert process.returncode != 0
    return json.loads(process.stderr)


def _submit(
    database: Path,
    output_directory: Path,
    idempotency_key: str,
    request: dict[str, object],
) -> subprocess.CompletedProcess[str]:
    """Submit through the same public process boundary used by local users."""
    return _run_cli(
        "submit",
        "--db",
        str(database),
        "--output-dir",
        str(output_directory),
        "--idempotency-key",
        idempotency_key,
        "--request-json",
        json.dumps(request),
    )


def _read_rgb_png(path: Path) -> tuple[int, int, bytes]:
    """Decode the PNG container and its unfiltered RGB scanlines."""
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    offset = 8
    image_size: tuple[int, int] | None = None
    compressed_pixels = bytearray()
    while offset < len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_data = data[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(
            ">I", data[offset + 8 + length : offset + 12 + length]
        )[0]
        assert stored_crc == zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if chunk_type == b"IHDR":
            width, height, bit_depth, color_type, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", chunk_data)
            )
            assert (bit_depth, color_type, compression, filtering, interlace) == (
                8,
                2,
                0,
                0,
                0,
            )
            image_size = (width, height)
        elif chunk_type == b"IDAT":
            compressed_pixels.extend(chunk_data)
        elif chunk_type == b"IEND":
            break
        offset += length + 12

    assert image_size is not None
    width, height = image_size
    pixels = zlib.decompress(compressed_pixels)
    assert len(pixels) == height * (1 + width * 3)
    assert all(pixels[row * (1 + width * 3)] == 0 for row in range(height))
    return width, height, pixels


def test_submit_and_retrieve_request_job_artifact_and_provenance_after_restart(
    tmp_path: Path,
) -> None:
    """A fresh CLI process can retrieve the exact persisted generation result."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    submitted = _json_output(
        _run_cli(
            "submit",
            "--db",
            str(database),
            "--output-dir",
            str(output_directory),
            "--idempotency-key",
            "restart-contract-1",
            "--request-json",
            json.dumps(
                {
                    "prompt": "An ochre fox beneath a violet moon",
                    "seed": 731,
                    "width": 32,
                    "height": 24,
                    "reference_ids": [],
                    "output_slot": "hero",
                }
            ),
        )
    )

    request = _json_output(
        _run_cli("request", "--db", str(database), "--id", str(submitted["request_id"]))
    )
    job = _json_output(
        _run_cli("job", "--db", str(database), "--id", str(submitted["job_id"]))
    )
    artifact = _json_output(
        _run_cli("artifact", "--db", str(database), "--id", str(submitted["artifact_id"]))
    )
    provenance = _json_output(
        _run_cli("provenance", "--db", str(database), "--job-id", str(submitted["job_id"]))
    )

    assert request["prompt"] == "An ochre fox beneath a violet moon"
    assert request["seed"] == 731
    assert job["status"] == "succeeded"
    assert job["output_slot"] == "hero"
    assert job["resolved_prompt"] == request["prompt"]
    assert job["resolved_seed"] == 731
    assert job["adapter_id"] == "deterministic-cpu-png-v1"
    assert job["adapter_configuration"] == {
        "configuration_version": 1,
        "image_format": "PNG",
        "pattern_version": 1,
    }
    assert job["validated_reference_ids"] == []
    assert job["effective_parameters"] == {"width": 32, "height": 24}
    assert artifact["artifact_id"] == submitted["artifact_id"]
    assert artifact["output_slot_id"] == job["output_slot_id"]
    assert artifact["media_type"] == "image/png"
    assert artifact["file_size"] > 0
    assert len(str(artifact["sha256"])) == 64
    assert provenance["job_id"] == submitted["job_id"]
    assert provenance["adapter_id"] == job["adapter_id"]
    assert provenance["effective_parameters"] == job["effective_parameters"]
    assert provenance["attempt"]["status"] == "succeeded"

    image_path = Path(str(artifact["path"]))
    width, height, pixels = _read_rgb_png(image_path)
    assert (width, height) == (32, 24)
    assert pixels


def test_idempotency_reuses_canonical_intent_and_conflicts_on_changed_intent(
    tmp_path: Path,
) -> None:
    """One key cannot create duplicate work or be rebound to another prompt."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    first = _json_output(
        _submit(database, output_directory, "same-intent", {"prompt": "A paper kite", "seed": 9})
    )
    same_intent = _json_output(
        _submit(
            database,
            output_directory,
            "same-intent",
            {
                "height": 64,
                "reference_ids": [],
                "output_slot": "primary",
                "seed": 9,
                "width": 64,
                "prompt": "A paper kite",
            },
        )
    )
    changed_intent = _json_error(
        _submit(
            database,
            output_directory,
            "same-intent",
            {"prompt": "A paper kite over water", "seed": 9},
        )
    )

    assert same_intent["job_id"] == first["job_id"]
    assert same_intent["request_id"] == first["request_id"]
    assert same_intent["artifact_id"] == first["artifact_id"]
    assert changed_intent["error"]["code"] == "idempotency_conflict"  # type: ignore[index]


def test_identical_image_content_keeps_distinct_logical_artifact_identities(
    tmp_path: Path,
) -> None:
    """Content hashes may match while each generation keeps its own artifact ID."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    first = _json_output(
        _submit(database, output_directory, "copy-a", {"prompt": "Quiet blue dunes", "seed": 4})
    )
    second = _json_output(
        _submit(database, output_directory, "copy-b", {"prompt": "Quiet blue dunes", "seed": 4})
    )
    first_artifact = _json_output(
        _run_cli("artifact", "--db", str(database), "--id", str(first["artifact_id"]))
    )
    second_artifact = _json_output(
        _run_cli("artifact", "--db", str(database), "--id", str(second["artifact_id"]))
    )

    assert first_artifact["artifact_id"] != second_artifact["artifact_id"]
    assert first_artifact["sha256"] == second_artifact["sha256"]


def test_reference_ids_are_resolved_and_unknown_or_path_values_are_rejected(
    tmp_path: Path,
) -> None:
    """Only existing logical artifacts can be supplied as reference inputs."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    source = _json_output(
        _submit(database, output_directory, "reference-source", {"prompt": "Source image", "seed": 1})
    )
    reference_job = _json_output(
        _submit(
            database,
            output_directory,
            "reference-consumer",
            {
                "prompt": "A study based on the reference",
                "seed": 2,
                "reference_ids": [source["artifact_id"]],
            },
        )
    )
    provenance = _json_output(
        _run_cli(
            "provenance",
            "--db",
            str(database),
            "--job-id",
            str(reference_job["job_id"]),
        )
    )
    unknown = _json_error(
        _submit(
            database,
            output_directory,
            "unknown-reference",
            {"prompt": "Unknown reference", "reference_ids": ["art_00000000000000000000000000000000"]},
        )
    )
    path_value = _json_error(
        _submit(
            database,
            output_directory,
            "path-reference",
            {"prompt": "Path is not an artifact ID", "reference_ids": ["/tmp/input.png"]},
        )
    )

    assert provenance["validated_reference_ids"] == [source["artifact_id"]]
    assert unknown["error"]["code"] == "unknown_reference"  # type: ignore[index]
    assert path_value["error"]["code"] == "validation_error"  # type: ignore[index]
    recovered = _json_output(
        _submit(
            database,
            output_directory,
            "unknown-reference",
            {"prompt": "Valid replacement intent"},
        )
    )
    assert recovered["status"] == "succeeded"


def test_unsupported_dimensions_and_invalid_requests_do_not_bind_idempotency_keys(
    tmp_path: Path,
) -> None:
    """Rejected inputs are explicit and leave the key available for valid intent."""
    database = tmp_path / "studio.sqlite3"
    output_directory = tmp_path / "artifacts"
    unsupported = _json_error(
        _submit(
            database,
            output_directory,
            "unsupported-size",
            {"prompt": "Too large", "width": 1024, "height": 64},
        )
    )
    invalid = _json_error(
        _submit(database, output_directory, "invalid-request", {"prompt": "   "})
    )
    valid_after_rejection = _json_output(
        _submit(database, output_directory, "invalid-request", {"prompt": "Valid now"})
    )
    valid_after_unsupported = _json_output(
        _submit(
            database,
            output_directory,
            "unsupported-size",
            {"prompt": "Within the supported size"},
        )
    )

    assert unsupported["error"]["code"] == "unsupported_capability"  # type: ignore[index]
    assert invalid["error"]["code"] == "validation_error"  # type: ignore[index]
    assert valid_after_rejection["status"] == "succeeded"
    assert valid_after_unsupported["status"] == "succeeded"
