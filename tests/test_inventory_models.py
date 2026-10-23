"""Bounded header parsing, component inspection, and bundle identity tests."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest

from media_generation.inventory.components import (
    MAX_DIRECTORY_ENTRIES,
    _bundle_identity,
    _inspect_component,
    _read_sidecar,
    _recipe_record,
    inspect_bundles,
    inspect_gguf,
    inspect_safetensors,
)
from media_generation.inventory.manifest import (
    ModelRoot,
    RecipeDeclaration,
    parse_manifest,
)
from media_generation.inventory.probes import (
    LocalObservationSource,
    ProbeLedger,
    ReplayObservationSource,
)
from media_generation.inventory.schema import Observation

from inventory_support import build_gguf, build_safetensors, observation, stat_payload, write_replay


def _ledger() -> ProbeLedger:
    return ProbeLedger(LocalObservationSource())


def test_safetensors_header_reports_dtype_and_safe_metadata() -> None:
    """Recognized headers yield dtype counts without reading tensor payloads."""
    data = build_safetensors(
        {
            "__metadata__": {"architecture": "flux", "quantization": "fp8", "ignored": "x"},
            "tensor.0": {"dtype": "F16", "shape": [2], "data_offsets": [0, 4]},
            "tensor.1": {"dtype": "F16", "shape": [2], "data_offsets": [4, 8]},
        }
    )
    result = inspect_safetensors(data, file_truncated=False)

    assert result["status"] == "observed"
    assert result["tensor_count"] == 2
    assert result["dtype_summary"] == {"F16": 2}
    assert result["architecture"] == "flux"
    assert result["quantization"] == "fp8"
    assert "ignored" in result["metadata_keys"]


def test_safetensors_rejects_short_or_oversized_headers() -> None:
    """Malformed length fields produce explicit outcomes."""
    assert inspect_safetensors(b"short", file_truncated=False)["status"] == "malformed"
    oversized = (2 * 1024 * 1024).to_bytes(8, "little") + b"x" * 64
    assert inspect_safetensors(oversized, file_truncated=False)["reason"] == (
        "header_length_out_of_bounds"
    )
    invalid = (4).to_bytes(8, "little") + b"nope"
    assert inspect_safetensors(invalid, file_truncated=False)["reason"] == "invalid_header_json"


def test_safetensors_truncated_prefix_is_distinguished_from_malformed() -> None:
    """A file larger than the inspected prefix is truncated, not necessarily corrupt."""
    data = (1000).to_bytes(8, "little") + b"{}"
    assert inspect_safetensors(data, file_truncated=True)["status"] == "truncated"
    assert inspect_safetensors(data, file_truncated=False)["status"] == "malformed"


def test_gguf_header_reports_architecture_and_quantization() -> None:
    """A bounded GGUF parse exposes selected metadata and file type."""
    data = build_gguf(
        [
            ("general.architecture", 8, "qwen_image"),
            ("general.file_type", 4, 14),
            ("general.name", 8, "Synthetic Qwen"),
            ("split.count", 4, 2),
        ]
    )
    result = inspect_gguf(data, file_truncated=False)

    assert result["status"] == "observed"
    assert result["format"] == "gguf"
    assert result["architecture"] == "qwen_image"
    assert result["quantization"] == "Q4_K_S"
    assert result["quantization_enum"] == 14
    assert result["tensor_count"] == 0
    assert result["split"] == {"split.count": 2}


@pytest.mark.parametrize(
    ("file_type", "label"),
    [
        (0, "ALL_F32"),
        (1, "MOSTLY_F16"),
        (2, "Q4_0"),
        (3, "Q4_1"),
        (7, "Q8_0"),
        (8, "Q5_0"),
        (9, "Q5_1"),
        (10, "Q2_K"),
        (11, "Q3_K_S"),
        (12, "Q3_K_M"),
        (13, "Q3_K_L"),
        (14, "Q4_K_S"),
        (15, "Q4_K_M"),
        (16, "Q5_K_S"),
        (17, "Q5_K_M"),
        (18, "Q6_K"),
        (19, "IQ2_XXS"),
        (20, "IQ2_XS"),
        (21, "Q2_K_S"),
        (22, "IQ3_XS"),
        (23, "IQ3_XXS"),
        (24, "IQ1_S"),
        (25, "IQ4_NL"),
        (26, "IQ3_S"),
        (27, "IQ3_M"),
        (28, "IQ2_S"),
        (29, "IQ2_M"),
        (30, "IQ4_XS"),
        (31, "IQ1_M"),
        (32, "BF16"),
        (36, "TQ1_0"),
        (37, "TQ2_0"),
        (38, "MXFP4_MOE"),
        (39, "NVFP4"),
        (40, "Q1_0"),
        (41, "Q2_0"),
    ],
)
def test_gguf_file_type_matches_upstream_enum(
    file_type: int, label: str
) -> None:
    """Every retained file type maps to its authoritative llama.cpp value."""
    data = build_gguf([("general.file_type", 4, file_type)])

    result = inspect_gguf(data, file_truncated=False)

    assert result["status"] == "observed"
    assert result["quantization"] == label
    assert result["quantization_enum"] == file_type


@pytest.mark.parametrize("file_type", [999, 1024])
def test_gguf_unknown_file_type_retains_raw_enum(file_type: int) -> None:
    """An unrecognized or sentinel file type is unclassified, not guessed."""
    data = build_gguf([("general.file_type", 4, file_type)])

    result = inspect_gguf(data, file_truncated=False)

    assert result["status"] == "observed"
    assert result["quantization"] is None
    assert result["quantization_enum"] == file_type


def test_component_quantization_comes_from_header_not_filename(
    tmp_path: Path,
) -> None:
    """A GGUF filename cannot override the parsed file-type enum."""
    root = tmp_path / "models"
    root.mkdir()
    path = root / "model-Q4_K_M.gguf"
    path.write_bytes(build_gguf([("general.file_type", 4, 10)]))

    record, _ = _inspect_component(
        _ledger(),
        component_id="bundle/filename",
        role="diffusion_model",
        path=path,
        roots=(ModelRoot(id="models", path=root),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    metadata = record["metadata"]
    assert metadata["quantization"] == "Q2_K"  # type: ignore[index]
    assert metadata["quantization_enum"] == 10  # type: ignore[index]


def test_gguf_truncation_and_unknown_value_types_are_explicit() -> None:
    """Incomplete data never becomes a fabricated architecture or quant value."""
    data = build_gguf([("general.architecture", 8, "qwen_image")])
    truncated = inspect_gguf(data[:30], file_truncated=True)
    assert truncated["status"] == "truncated"
    assert truncated["reason"] == "metadata_limit_reached"
    assert inspect_gguf(data[:30], file_truncated=False)["status"] == "malformed"

    payload = bytearray(b"GGUF")
    payload += (3).to_bytes(4, "little")
    payload += (0).to_bytes(8, "little")
    payload += (1).to_bytes(8, "little")
    key = b"general.architecture"
    payload += len(key).to_bytes(8, "little") + key
    payload += (99).to_bytes(4, "little")
    assert inspect_gguf(bytes(payload), file_truncated=False)["reason"] == "unknown_value_type"


def test_pickle_like_component_is_never_read(tmp_path: Path) -> None:
    """Serialized Python objects are reported as unsafe and not inspected."""
    path = tmp_path / "model.ckpt"
    path.write_bytes(b"not really a pickle")
    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/model",
        role="checkpoint",
        path=path,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is False
    assert record["metadata"]["status"] == "not_inspected"  # type: ignore[index]
    assert record["metadata"]["reason"] == "unsafe_serialization_not_read"  # type: ignore[index]
    assert record["digest"]["status"] == "unchecked"  # type: ignore[index]


def test_component_digest_is_streamed_and_limit_is_enforced(tmp_path: Path) -> None:
    """Full hashing is opt-in and a size bound yields an explicit skip."""
    path = tmp_path / "model.gguf"
    data = b"x" * 2048
    path.write_bytes(data)
    ledger = _ledger()
    computed, _ = _inspect_component(
        ledger,
        component_id="bundle/computed",
        role="diffusion_model",
        path=path,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=True,
        hash_limit_bytes=4096,
    )
    skipped, _ = _inspect_component(
        ledger,
        component_id="bundle/skipped",
        role="diffusion_model",
        path=path,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=True,
        hash_limit_bytes=100,
    )

    assert computed["digest"]["status"] == "computed"  # type: ignore[index]
    assert computed["digest"]["value"] == "sha256:" + hashlib.sha256(data).hexdigest()  # type: ignore[index]
    assert skipped["digest"]["status"] == "skipped"  # type: ignore[index]
    assert skipped["digest"]["reason"] == "hash_limit_exceeded"  # type: ignore[index]


def test_symlinked_component_is_skipped(tmp_path: Path) -> None:
    """Component symlinks are not followed, even when they point inside a root."""
    target = tmp_path / "target.gguf"
    target.write_bytes(b"data")
    link = tmp_path / "link.gguf"
    link.symlink_to(target)
    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/link",
        role="diffusion_model",
        path=link,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["status"] == "skipped"
    assert record["reason"] == "symlink_not_followed"


def test_directory_component_has_bounded_listing_and_sidecar(tmp_path: Path) -> None:
    """Diffusers-style directories are listed shallowly with approved config keys."""
    root = tmp_path / "pipeline"
    root.mkdir()
    (root / "model_index.json").write_text(
        json.dumps({"_class_name": "FluxPipeline", "model_type": "flux"}), encoding="utf-8"
    )
    (root / "weights.safetensors").write_bytes(b"x")
    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/pipeline",
        role="diffusion_model",
        path=root,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is False
    metadata = record["metadata"]
    assert metadata["format"] == "directory"  # type: ignore[index]
    assert metadata["entry_count"] == 2  # type: ignore[index]
    assert metadata["sidecar"]["selected_keys"]["_class_name"] == "FluxPipeline"  # type: ignore[index]


def test_bundle_identity_never_implies_completeness_without_digests() -> None:
    """Declared paths alone produce ``declared`` identity, not a bundle digest."""
    recipe = {"status": "declared", "digest": "sha256:recipe"}
    component = {
        "id": "transformer",
        "role": "diffusion_model",
        "kind": "file",
        "size_bytes": 10,
        "status": "observed",
        "digest": {"status": "unchecked", "value": None},
    }
    declared = _bundle_identity(engine="diffusers", recipe=recipe, components=[component])
    assert declared["status"] == "declared"
    assert declared["digest"] is None

    computed = dict(component)
    computed["digest"] = {"status": "computed", "value": "sha256:content"}
    complete = _bundle_identity(engine="diffusers", recipe=recipe, components=[computed])
    assert complete["status"] == "complete"
    assert isinstance(complete["digest"], str) and complete["digest"].startswith("sha256:")

    second = dict(component)
    partial = _bundle_identity(
        engine="diffusers", recipe=recipe, components=[computed, second]
    )
    assert partial["status"] == "partial"

    unavailable = dict(component)
    unavailable["status"] = "unavailable"
    missing = _bundle_identity(
        engine="diffusers", recipe=recipe, components=[unavailable]
    )
    assert missing["status"] == "unavailable"


def test_component_sidecar_is_read_for_recognized_file(tmp_path: Path) -> None:
    """A recognized sibling ``config.json`` contributes selected metadata only."""
    path = tmp_path / "weights.safetensors"
    path.write_bytes(
        build_safetensors({"__metadata__": {"architecture": "synthetic"}})
    )
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "_class_name": "SyntheticTransformer",
                "torch_dtype": "float16",
                "unrelated": "do not copy",
            }
        ),
        encoding="utf-8",
    )
    record, _ = _inspect_component(
        _ledger(),
        component_id="bundle/transformer",
        role="diffusion_model",
        path=path,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    metadata = record["metadata"]
    assert metadata["format"] == "safetensors"  # type: ignore[index]
    assert metadata["sidecar"]["selected_keys"] == {  # type: ignore[index]
        "_class_name": "SyntheticTransformer",
        "torch_dtype": "float16",
    }


def test_missing_component_degrades_and_stays_unavailable(tmp_path: Path) -> None:
    """Missing files are not replaced by filename-based assumptions."""
    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/missing",
        role="vae",
        path=tmp_path / "missing.safetensors",
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=True,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["status"] == "unavailable"
    assert record["digest"]["status"] == "unavailable"  # type: ignore[index]
    assert os.path.exists(tmp_path / "missing.safetensors") is False


def test_gguf_array_limit_is_enforced_before_iteration() -> None:
    """An oversized declared array is rejected without allocating its items."""
    payload = bytearray(b"GGUF")
    payload += (3).to_bytes(4, "little")
    payload += (0).to_bytes(8, "little")
    payload += (1).to_bytes(8, "little")
    key = b"general.tags"
    payload += len(key).to_bytes(8, "little") + key
    payload += (9).to_bytes(4, "little")
    payload += (8).to_bytes(4, "little")
    payload += (4097).to_bytes(8, "little")
    payload += b"\x00" * 64

    result = inspect_gguf(bytes(payload), file_truncated=False)

    assert result["status"] == "malformed"
    assert result["reason"] == "array_too_large"


def test_directory_component_listing_failure_is_explicit(tmp_path: Path) -> None:
    """An unreadable directory is unavailable, not an empty observed listing."""
    path = tmp_path / "model-directory"
    replay = write_replay(
        tmp_path / "replay.json",
        {
            f"stat:{path}": observation(
                json.dumps(stat_payload(kind="directory", realpath=str(path)))
            ),
            f"list:{path}": observation(
                status="unavailable", reason="permission_denied", text=""
            ),
        },
    )
    ledger = ProbeLedger(ReplayObservationSource.from_path(replay))

    record, degraded = _inspect_component(
        ledger,
        component_id="bundle/directory",
        role="diffusion_model",
        path=path,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["status"] == "unavailable"
    assert record["reason"] == "permission_denied"
    assert record["metadata"] == {
        "status": "unavailable",
        "format": "directory",
        "reason": "permission_denied",
    }


def test_intermediate_symlink_escaping_model_root_is_rejected(tmp_path: Path) -> None:
    """A linked ancestor cannot redirect a component read outside the root."""
    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "model.gguf").write_bytes(b"outside")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/escape",
        role="diffusion_model",
        path=root / "linked" / "model.gguf",
        roots=(ModelRoot(id="models", path=root),),
        hash_components=True,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["status"] == "skipped"
    assert record["reason"] == "symlink_ancestor_not_followed"
    assert record["digest"]["status"] == "skipped"  # type: ignore[index]
    assert record["metadata"]["status"] == "not_inspected"  # type: ignore[index]


def test_component_outside_model_root_is_unavailable(tmp_path: Path) -> None:
    """A path outside every declared root is never inspected."""
    root = tmp_path / "models"
    root.mkdir()
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"outside")

    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/outside",
        role="diffusion_model",
        path=outside,
        roots=(ModelRoot(id="models", path=root),),
        hash_components=True,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["status"] == "unavailable"
    assert record["reason"] == "outside_model_root"
    assert record["metadata"]["reason"] == "outside_model_root"  # type: ignore[index]


def test_sidecar_symlink_is_not_followed(tmp_path: Path) -> None:
    """An approved sidecar link cannot point at an unrelated file."""
    root = tmp_path / "pipeline"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"_class_name": "Outside"}', encoding="utf-8")
    (root / "config.json").symlink_to(outside)

    record, _ = _inspect_component(
        _ledger(),
        component_id="bundle/pipeline",
        role="diffusion_model",
        path=root,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    metadata = record["metadata"]
    assert metadata["status"] == "observed"  # type: ignore[index]
    assert "sidecar" not in metadata  # type: ignore[operator]


def test_recipe_final_symlink_is_not_hashed(tmp_path: Path) -> None:
    """Recipe hashing never follows a final link, even within the root."""
    root = tmp_path / "models"
    root.mkdir()
    target = root / "recipe.json"
    target.write_text('{"steps": 20}', encoding="utf-8")
    link = root / "recipe-link.json"
    link.symlink_to(target)

    record, degraded = _recipe_record(
        _ledger(),
        bundle_id="bundle-a",
        recipe=RecipeDeclaration(
            id="recipe-a", source=None, parameters=None, path=link
        ),
        roots=(ModelRoot(id="models", path=root),),
    )

    assert degraded is True
    assert record["status"] == "skipped"
    assert record["reason"] == "symlink_not_followed"
    assert record["digest"] is None


def test_component_replacement_after_parsing_is_rejected(tmp_path: Path) -> None:
    """A component swapped for a link after parsing is blocked at inspection."""
    models = tmp_path / "models"
    models.mkdir()
    component = models / "model.gguf"
    component.write_bytes(b"original")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "media-generation.inventory-manifest",
                "schema_version": 1,
                "description": "Synthetic race fixture",
                "model_roots": [{"id": "models", "path": "models"}],
                "runtimes": [],
                "bundles": [
                    {
                        "id": "bundle-a",
                        "engine": "stable-diffusion.cpp",
                        "recipe": {
                            "id": "recipe-a",
                            "parameters": {"steps": 20},
                        },
                        "components": [
                            {
                                "id": "transformer",
                                "role": "diffusion_model",
                                "path": "models/model.gguf",
                            }
                        ],
                    }
                ],
                "probe_policy": {"device_queries": False, "timeout_seconds": 5},
            }
        ),
        encoding="utf-8",
    )
    manifest = parse_manifest(manifest_path)
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"outside")
    component.unlink()
    component.symlink_to(outside)

    records, _, degraded = inspect_bundles(
        _ledger(), manifest, hash_components=False, hash_limit_bytes=1024
    )

    assert degraded is True
    record = records[0]["components"][0]  # type: ignore[index]
    assert record["status"] == "skipped"
    assert record["reason"] == "symlink_not_followed"

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo is unavailable")
def test_recipe_fifo_is_rejected_without_blocking(tmp_path: Path) -> None:
    """A writer-less FIFO cannot block file-backed recipe hashing."""
    root = tmp_path / "models"
    root.mkdir()
    fifo = root / "recipe.fifo"
    os.mkfifo(fifo)
    result: list[tuple[dict[str, object], bool]] = []

    def collect() -> None:
        result.append(
            _recipe_record(
                _ledger(),
                bundle_id="bundle-a",
                recipe=RecipeDeclaration(
                    id="recipe-a",
                    source=None,
                    parameters=None,
                    path=fifo,
                ),
                roots=(ModelRoot(id="models", path=root),),
            )
        )

    worker = threading.Thread(target=collect, daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(timeout=5)
    elapsed = time.monotonic() - started

    assert not worker.is_alive(), "recipe hashing blocked on a writer-less FIFO"
    assert elapsed < 5
    record, degraded = result[0]
    assert degraded is True
    assert record["status"] == "skipped"
    assert record["reason"] == "not_regular_file"
    assert record["digest"] is None


def test_gguf_boolean_file_type_is_not_an_enum() -> None:
    """A boolean GGUF file type is malformed evidence, not enum zero or one."""
    data = build_gguf([("general.file_type", 7, True)])

    result = inspect_gguf(data, file_truncated=False)

    assert result["status"] == "observed"
    assert result["quantization_enum"] is None
    assert result["quantization"] is None


def test_directory_component_truncation_degrades_the_run(tmp_path: Path) -> None:
    """A bounded directory listing reports that model evidence is incomplete."""
    component = tmp_path / "model-directory"
    component.mkdir()
    for index in range(MAX_DIRECTORY_ENTRIES + 1):
        (component / f"part-{index:03d}.bin").write_bytes(b"x")

    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/model",
        role="diffusion_model",
        path=component,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["metadata"]["truncated"] is True  # type: ignore[index]


def test_malformed_component_header_degrades_the_run(tmp_path: Path) -> None:
    """A truncated GGUF header is surfaced as incomplete configured evidence."""
    component = tmp_path / "model.gguf"
    component.write_bytes(b"GGUF" + b"\x00" * 8)

    record, degraded = _inspect_component(
        _ledger(),
        component_id="bundle/model",
        role="diffusion_model",
        path=component,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["metadata"]["status"] == "malformed"  # type: ignore[index]


def test_component_replacement_during_inspection_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file swapped after validation is detected before its header is trusted."""
    component = tmp_path / "model.gguf"
    component.write_bytes(build_gguf([("general.architecture", 8, "flux")]))
    source = LocalObservationSource()
    real_read_prefix = source.read_prefix
    swapped = {"done": False}

    def swapping_read_prefix(path: Path, **kwargs: object):
        if path == component and not swapped["done"]:
            swapped["done"] = True
            component.write_bytes(
                build_gguf([("general.architecture", 8, "replacement")])
                + b"\x00" * 128
            )
        return real_read_prefix(path, **kwargs)  # type: ignore[arg-type]

    source.read_prefix = swapping_read_prefix  # type: ignore[method-assign]

    record, degraded = _inspect_component(
        ProbeLedger(source),
        component_id="bundle/model",
        role="diffusion_model",
        path=component,
        roots=(ModelRoot(id="models", path=tmp_path),),
        hash_components=False,
        hash_limit_bytes=1024,
    )

    assert degraded is True
    assert record["metadata"]["status"] == "skipped"  # type: ignore[index]
    assert (
        record["metadata"]["reason"]  # type: ignore[index]
        == "component_replaced_during_inspection"
    )


def test_bundle_identity_rejects_skipped_recipe() -> None:
    """A skipped recipe cannot produce a complete bundle identity."""
    identity = _bundle_identity(
        engine="stable-diffusion.cpp",
        recipe={"status": "skipped", "digest": None},
        components=[
            {
                "id": "model",
                "role": "diffusion_model",
                "kind": "file",
                "size_bytes": 10,
                "status": "observed",
                "digest": {"status": "unchecked", "value": None},
            }
        ],
    )

    assert identity["status"] == "unavailable"


def test_malformed_sidecar_stat_is_explicitly_degraded() -> None:
    """A non-object stat payload cannot abort sidecar inspection."""
    path = Path("/models/model.json")
    source = ReplayObservationSource(
        {f"stat:{path}": Observation(status="ok", text="[]")}
    )

    record = _read_sidecar(
        ProbeLedger(source),
        component_id="bundle/model",
        path=path,
        roots=(ModelRoot(id="models", path=Path("/models")),),
    )

    assert record == {
        "path": str(path),
        "status": "malformed",
        "reason": "sidecar_stat_malformed",
    }
