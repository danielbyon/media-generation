"""Safety tests for declarations that must not trigger external effects."""

from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

from inventory_support import write_replay
from media_generation.inventory import InventoryOptions, collect_inventory


def test_url_sources_are_attribution_only_and_never_fetched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A manifest URL is preserved as provenance without network retrieval."""
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
                            "source": {
                                "kind": "url",
                                "value": "https://example.invalid/recipe.json",
                            },
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
            }
        ),
        encoding="utf-8",
    )
    replay = write_replay(tmp_path / "replay.json", {})
    output = tmp_path / "unwritten"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("inventory attempted network access")

    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(urllib.request, "urlopen", fail)

    result = collect_inventory(
        InventoryOptions(
            output_directory=output,
            manifest_path=manifest,
            replay_path=replay,
        )
    )

    assert not output.exists()
    bundle = result.inventory["bundles"][0]
    assert bundle["recipe"]["source"] == {
        "kind": "url",
        "value": "https://example.invalid/recipe.json",
    }
    assert bundle["components"][0]["status"] == "unavailable"
    assert result.inventory["run"]["mode"] == "replay"
