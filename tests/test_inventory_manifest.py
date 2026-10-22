"""Strict manifest validation and path-scope tests."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from media_generation.inventory.manifest import MAX_MANIFEST_BYTES, parse_manifest
from media_generation.inventory.schema import InventoryValidationError


def _manifest() -> dict[str, object]:
    return {
        "schema": "media-generation.inventory-manifest",
        "schema_version": 1,
        "description": "Synthetic manifest",
        "model_roots": [{"id": "models", "path": "models"}],
        "runtimes": [
            {
                "id": "ollama",
                "path": "bin/ollama",
                "probe_version": True,
                "declared_capabilities": [
                    {
                        "task": "text_to_image",
                        "support": "advertised",
                        "source": {"kind": "url", "value": "https://example.invalid/doc"},
                    }
                ],
            }
        ],
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
                    {"id": "transformer", "role": "diffusion_model", "path": "models/model.gguf"}
                ],
            }
        ],
        "probe_policy": {"device_queries": False, "timeout_seconds": 5},
    }


def _write(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_valid_manifest_resolves_paths_relative_to_the_file(tmp_path: Path) -> None:
    """Declared paths are anchored to the manifest, not the process directory."""
    manifest = parse_manifest(_write(tmp_path, _manifest()))

    assert manifest.model_roots[0].path == (tmp_path / "models").resolve()
    assert manifest.bundles[0].components[0].path == (tmp_path / "models" / "model.gguf").resolve()
    assert manifest.runtimes[0].path == (tmp_path / "bin" / "ollama").resolve()
    assert manifest.runtimes[0].probe_version is True
    assert manifest.bundles[0].capabilities == ()
    assert manifest.runtimes[0].capabilities[0].support == "advertised"


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    """Duplicate keys cannot be resolved by last-one-wins parsing."""
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"schema":"media-generation.inventory-manifest",'
        '"schema_version":1,"schema_version":2}',
        encoding="utf-8",
    )
    with pytest.raises(InventoryValidationError, match="duplicate JSON key"):
        parse_manifest(path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.update({"unexpected": True}),
        lambda payload: payload.update({"schema": "wrong"}),
        lambda payload: payload.update({"schema_version": 99}),
        lambda payload: payload["runtimes"][0].update({"id": "unknown-engine"}),
        lambda payload: payload["probe_policy"].update({"timeout_seconds": 0}),
        lambda payload: payload["probe_policy"].update({"device_queries": "yes"}),
        lambda payload: payload["bundles"][0].update({"engine": "unknown-engine"}),
    ],
    ids=(
        "unknown-top-level-key",
        "wrong-schema",
        "wrong-version",
        "unknown-runtime",
        "timeout-out-of-range",
        "device-queries-not-boolean",
        "unknown-bundle-engine",
    ),
)
def test_invalid_manifest_shapes_are_rejected(tmp_path: Path, mutate: object) -> None:
    """Typos and unsupported values fail closed with a validation error."""
    payload = copy.deepcopy(_manifest())
    mutate(payload)  # type: ignore[operator]
    with pytest.raises(InventoryValidationError):
        parse_manifest(_write(tmp_path, payload))


def test_tested_capability_cannot_be_declared(tmp_path: Path) -> None:
    """Manifests cannot promote advertised support to tested support."""
    payload = copy.deepcopy(_manifest())
    payload["runtimes"][0]["declared_capabilities"][0]["support"] = "tested"  # type: ignore[index]
    with pytest.raises(InventoryValidationError, match="tested support cannot be declared"):
        parse_manifest(_write(tmp_path, payload))


def test_component_outside_model_roots_is_rejected(tmp_path: Path) -> None:
    """A declared component cannot escape its explicit model root."""
    payload = copy.deepcopy(_manifest())
    payload["bundles"][0]["components"][0]["path"] = "../outside.gguf"  # type: ignore[index]
    with pytest.raises(InventoryValidationError, match="outside declared model roots"):
        parse_manifest(_write(tmp_path, payload))


def test_python_distribution_path_is_rejected(tmp_path: Path) -> None:
    """Python distributions are identified by metadata, not an executable path."""
    payload = copy.deepcopy(_manifest())
    payload["runtimes"][0] = {"id": "torch", "path": "/usr/bin/python"}
    with pytest.raises(InventoryValidationError, match="not supported for Python distributions"):
        parse_manifest(_write(tmp_path, payload))


def test_comfyui_version_probe_is_rejected(tmp_path: Path) -> None:
    """Only catalog entries with a fixed version argv can opt in."""
    payload = copy.deepcopy(_manifest())
    payload["runtimes"][0] = {"id": "comfyui", "probe_version": True}
    with pytest.raises(InventoryValidationError, match="cannot enable a version probe"):
        parse_manifest(_write(tmp_path, payload))


def test_recipe_must_have_identity(tmp_path: Path) -> None:
    """A bundle cannot declare a recipe with no source, parameters, or file."""
    payload = copy.deepcopy(_manifest())
    payload["bundles"][0]["recipe"] = {"id": "empty"}  # type: ignore[index]
    with pytest.raises(InventoryValidationError, match="must declare a source"):
        parse_manifest(_write(tmp_path, payload))


def test_duplicate_bundle_and_component_ids_are_rejected(tmp_path: Path) -> None:
    """Identity collisions fail instead of silently overwriting records."""
    payload = copy.deepcopy(_manifest())
    bundles = payload["bundles"]
    bundles.append(copy.deepcopy(bundles[0]))  # type: ignore[union-attr]
    with pytest.raises(InventoryValidationError, match="bundle ids must be unique"):
        parse_manifest(_write(tmp_path, payload))

    payload = copy.deepcopy(_manifest())
    components = payload["bundles"][0]["components"]  # type: ignore[index]
    components.append(copy.deepcopy(components[0]))
    with pytest.raises(InventoryValidationError, match="components ids must be unique"):
        parse_manifest(_write(tmp_path, payload))


def test_bundle_requires_a_model_root(tmp_path: Path) -> None:
    """Model declarations cannot exist without an explicit root."""
    payload = copy.deepcopy(_manifest())
    payload["model_roots"] = []
    with pytest.raises(InventoryValidationError, match="requires at least one declared model root"):
        parse_manifest(_write(tmp_path, payload))


def test_manifest_size_is_bounded(tmp_path: Path) -> None:
    """Manifests are declarations, not an unbounded input channel."""
    path = tmp_path / "manifest.json"
    path.write_text("{" + " " * (1024 * 1024 + 1) + "}", encoding="utf-8")
    with pytest.raises(InventoryValidationError, match="too large"):
        parse_manifest(path)


def test_component_through_escaping_symlink_is_rejected(tmp_path: Path) -> None:
    """An intermediate link cannot redirect a component outside its root."""
    models = tmp_path / "models"
    models.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "model.gguf").write_bytes(b"outside")
    (models / "linked").symlink_to(outside, target_is_directory=True)
    payload = copy.deepcopy(_manifest())
    payload["bundles"][0]["components"][0]["path"] = "models/linked/model.gguf"  # type: ignore[index]

    with pytest.raises(InventoryValidationError, match="outside declared model roots"):
        parse_manifest(_write(tmp_path, payload))


def test_recipe_symlink_escaping_model_root_is_rejected(tmp_path: Path) -> None:
    """A recipe link that resolves outside the root is rejected at parse time."""
    models = tmp_path / "models"
    models.mkdir()
    outside = tmp_path / "outside-recipe.json"
    outside.write_text('{"steps": 20}', encoding="utf-8")
    (models / "recipe.json").symlink_to(outside)
    payload = copy.deepcopy(_manifest())
    payload["bundles"][0]["recipe"] = {  # type: ignore[index]
        "id": "recipe-a",
        "path": "models/recipe.json",
    }

    with pytest.raises(InventoryValidationError, match="outside declared model roots"):
        parse_manifest(_write(tmp_path, payload))

def test_manifest_growth_after_stat_is_rejected_without_overread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read-time bounds reject a manifest that grows after the size check."""
    path = tmp_path / "manifest.json"
    path.write_text("{" + " " * MAX_MANIFEST_BYTES + "}", encoding="utf-8")
    real_stat = Path.stat

    def understating_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        result = real_stat(self, *args, **kwargs)  # type: ignore[arg-type]
        if self != path:
            return result
        return os.stat_result(
            (
                result.st_mode,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                result.st_uid,
                result.st_gid,
                2,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )

    reads: list[int] = []
    real_open = Path.open

    class CountingHandle:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            return self._handle.read(size)

        def __enter__(self) -> "CountingHandle":
            return self

        def __exit__(self, *exc: object) -> None:
            self._handle.close()

    def counting_open(self: Path, *args: object, **kwargs: object) -> CountingHandle:
        return CountingHandle(real_open(self, *args, **kwargs))

    monkeypatch.setattr(Path, "stat", understating_stat)
    monkeypatch.setattr(Path, "open", counting_open)

    with pytest.raises(InventoryValidationError, match="too large"):
        parse_manifest(path)

    assert reads == [MAX_MANIFEST_BYTES + 1]


def test_manifest_replaced_by_directory_after_stat_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path swapped after validation yields a structured error, not a crash."""
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_manifest()), encoding="utf-8")
    real_open = Path.open

    def replacing_open(self: Path, *args: object, **kwargs: object) -> object:
        if self == path and path.is_file():
            path.unlink()
            path.mkdir()
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", replacing_open)

    with pytest.raises(InventoryValidationError, match="not readable"):
        parse_manifest(path)
