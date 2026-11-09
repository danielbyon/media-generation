"""Focused production-runtime tests for ComfyUI node authority v3."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from media_generation import comfyui
from media_generation.comfyui_runtime_pins import RuntimePinApproval
from media_generation.errors import BackendPreparationError
from test_comfyui_runtime_pins import _external_test_interpreter, _signed_approval
from test_t09_support import build_comfyui_bundle


def _candidate(tmp_path: Path):
    bundle = build_comfyui_bundle(
        tmp_path,
        profile_version=2,
        node_authority_version=3,
        python_interpreter=_external_test_interpreter(),
    )
    return comfyui.load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )


def _signed_test_approval(
    tmp_path: Path, candidate
) -> RuntimePinApproval:
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    raw = approval_path.read_bytes()
    envelope = json.loads(raw)
    return RuntimePinApproval(
        payload=MappingProxyType(dict(envelope["payload"])),
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        public_key_sha256=hashlib.sha256(public_key_path.read_bytes()).hexdigest(),
    )


def test_v3_production_binding_matches_signed_source_and_archive(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    approval = _signed_test_approval(tmp_path, candidate)

    assert comfyui._require_independent_runtime_pin_binding(candidate, approval) is approval


def test_v3_production_binding_rejects_interpreter_mismatch_before_launch(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    approval = _signed_test_approval(tmp_path, candidate)
    payload = dict(approval.payload)
    interpreter = dict(payload["interpreter"])
    interpreter["sha256"] = "0" * 64
    payload["interpreter"] = interpreter
    mismatched = RuntimePinApproval(
        payload=MappingProxyType(payload),
        manifest_sha256=approval.manifest_sha256,
        public_key_sha256=approval.public_key_sha256,
    )

    with pytest.raises(BackendPreparationError) as error:
        comfyui._require_independent_runtime_pin_binding(candidate, mismatched)

    assert error.value.code == "bundle_unverified"
    assert error.value.__cause__ is not None
    assert "candidate interpreter" in str(error.value.__cause__)


def test_v3_production_binding_rejects_source_bytes_changed_after_signing(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    approval = _signed_test_approval(tmp_path, candidate)
    source_root = candidate.declaration.engine.executable.resolved_path(
        candidate.declaration.root_index
    ).parent
    source = source_root / "nodes.py"
    original = source.read_bytes()
    source.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))

    with pytest.raises(BackendPreparationError) as error:
        comfyui._require_independent_runtime_pin_binding(candidate, approval)

    assert error.value.code == "bundle_unverified"


def test_v3_production_binding_rejects_component_archive_tampering(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    approval = _signed_test_approval(tmp_path, candidate)
    component = next(
        item for item in candidate.declaration.components if item.role == "other"
    )
    archive = component.artifact.resolved_path(candidate.declaration.root_index)
    original = archive.read_bytes()
    archive.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))

    with pytest.raises(BackendPreparationError) as error:
        comfyui._require_independent_runtime_pin_binding(candidate, approval)

    assert error.value.code == "bundle_corrupt"
