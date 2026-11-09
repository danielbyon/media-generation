"""Focused adapter integration tests for ComfyUI node authority v3."""

from __future__ import annotations

from pathlib import Path

import pytest

from media_generation import comfyui
from media_generation._comfyui_node_authority import NodeInputs
from media_generation.errors import BackendPreparationError
from test_t09_support import COMFYUI_QWEN_NODE_CLASSES, build_comfyui_bundle


def test_node_authority_v3_loads_exact_qwen_graph_registration_contract(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(
        tmp_path,
        profile_version=2,
        node_authority_version=3,
    )

    candidate = comfyui.load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )

    assert candidate.node_authority is not None
    assert len(candidate.node_authority.nodes) == 15
    assert candidate.node_authority.nodes["CLIPLoader"].inputs.optional == (
        "device",
    )
    assert candidate.node_authority.nodes["SaveImage"].inputs.hidden == (
        "extra_pnginfo",
        "prompt",
    )


def test_node_authority_v2_remains_readable_without_changing_v2_pins(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(
        tmp_path,
        profile_version=2,
        node_authority_version=2,
    )

    candidate = comfyui.load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )

    assert candidate.node_authority is None
    assert candidate.recipe.nodes["CLIPLoader"]["inputs"] == (
        "clip_name",
        "type",
    )


def test_node_authority_v3_rejects_a_missing_graph_class(tmp_path: Path) -> None:
    classes = tuple(
        name for name in COMFYUI_QWEN_NODE_CLASSES if name != "SaveImage"
    )
    bundle = build_comfyui_bundle(
        tmp_path,
        profile_version=2,
        node_authority_version=3,
        node_authority_classes=classes,
    )

    with pytest.raises(BackendPreparationError, match="workflow node pin"):
        comfyui.load_comfyui_candidate(
            bundle.declaration_path, bundle.trusted_evidence_path
        )


def test_node_authority_v3_rejects_hidden_and_missing_required_graph_inputs() -> None:
    trusted_nodes = {
        "SaveImage": {
            "inputs": ("filename_prefix", "images"),
            "input_contract": NodeInputs(
                required=("filename_prefix", "images"),
                optional=(),
                hidden=("extra_pnginfo", "prompt"),
            ),
        }
    }
    hidden_graph = {
        "1": {
            "class_type": "SaveImage",
            "inputs": {
                "filename_prefix": "output",
                "images": [],
                "prompt": "hidden value",
            },
        }
    }
    with pytest.raises(BackendPreparationError, match="hidden parameter"):
        comfyui._parse_graph(
            hidden_graph,
            label="hidden input graph",
            trusted_nodes=trusted_nodes,
        )

    missing_required = {
        "1": {
            "class_type": "SaveImage",
            "inputs": {"filename_prefix": "output"},
        }
    }
    with pytest.raises(BackendPreparationError, match="required parameter"):
        comfyui._parse_graph(
            missing_required,
            label="missing required input graph",
            trusted_nodes=trusted_nodes,
        )
