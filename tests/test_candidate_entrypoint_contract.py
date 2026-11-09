"""T07 launch-contract regression tests for native and Python entrypoints."""

from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from media_generation import candidate
from media_generation._candidate_contract import (
    CandidateValidationError,
    parse_candidate,
)
from media_generation._candidate_evaluation import _observe_target, evaluate_candidate
from media_generation.comfyui import load_comfyui_candidate
from media_generation.engine import load_engine_candidate
from media_generation.errors import BackendPreparationError
from test_candidate_preparation import (
    _Response,
    _acquisition_config,
    _artifact_subject,
    _compatibility_document,
    _fixture,
    _payload,
    _pin,
    _rewrite,
    _trusted_evidence,
)
from candidate_linux_fakes import inject_linux_inode_operations
from test_t09_support import build_comfyui_bundle


_LEGACY_FIXTURE_ID = (
    "sha256:854b1ad6edcf5ddfe24a4b41a657ffa551b4bb418c0183a06d3f2f736e90c25b"
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _pin_written_file(files: Path, name: str) -> dict[str, object]:
    data = (files / name).read_bytes()
    return {
        "root": "files",
        "path": name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _python_script_fixture(
    tmp_path: Path, *, interpreter_mode: int = 0o755
) -> Path:
    candidate_path = _fixture(tmp_path)
    files = tmp_path / "files"
    declaration: dict[str, Any] = json.loads(candidate_path.read_text(encoding="utf-8"))
    engine = declaration["engine"]
    script_path = files / "engine.bin"
    script_path.chmod(0o444)

    interpreter_path = files / "python.bin"
    interpreter_path.write_bytes(b"synthetic-python-interpreter-v1\n")
    interpreter_path.chmod(interpreter_mode)
    interpreter_pin = _pin_written_file(files, interpreter_path.name)
    interpreter_subject = _artifact_subject(
        "engine", str(engine["id"]), "python-interpreter", interpreter_pin
    )

    provenance_document_path = files / "python-interpreter-provenance.json"
    _write_json(
        provenance_document_path,
        {
            "schema": "media-generation.candidate-provenance-evidence",
            "schema_version": 1,
            "publisher": "Synthetic Python publisher",
            "revision": "synthetic-python-revision",
            "canonical_url": "https://python.example/source",
            "subject": interpreter_subject,
        },
    )
    license_document_path = files / "python-interpreter-license.json"
    _write_json(
        license_document_path,
        {
            "schema": "media-generation.candidate-license-evidence",
            "schema_version": 1,
            "subject": interpreter_subject,
            "license": {
                "name": "Synthetic Python terms",
                "spdx": "LicenseRef-Test",
                "terms_url": "https://python.example/license",
            },
        },
    )
    launch = {
        "schema": "media-generation.engine-launch",
        "schema_version": 1,
        "kind": "python-script",
        "interpreter": interpreter_pin,
        "provenance": {
            "publisher": "Synthetic Python publisher",
            "revision": "synthetic-python-revision",
            "canonical_url": "https://python.example/source",
            "evidence": _pin_written_file(files, provenance_document_path.name),
        },
        "license": {
            "name": "Synthetic Python terms",
            "spdx": "LicenseRef-Test",
            "terms_url": "https://python.example/license",
            "evidence": _pin_written_file(files, license_document_path.name),
        },
    }
    engine["launch"] = launch

    recipe = declaration["recipe"]
    compatibility = _compatibility_document(
        engine,
        recipe,
        declaration["components"],
        declaration["adapters"],
        recipe["compatibility_evidence"][0]["claims"],
    )
    compatibility["engine"]["launch"] = launch
    compatibility_path = files / "compatibility.json"
    _write_json(compatibility_path, compatibility)
    recipe["compatibility_evidence"][0]["document"] = _pin_written_file(
        files, compatibility_path.name
    )
    _write_json(candidate_path, declaration)
    return candidate_path


def _items(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["artifact"]: item for item in report["items"]}


def test_legacy_native_entrypoint_keeps_identity_and_execute_requirement(
    tmp_path: Path,
) -> None:
    declaration_path = _fixture(tmp_path)
    declaration = parse_candidate(declaration_path)
    assert declaration.stable_candidate_id() == _LEGACY_FIXTURE_ID

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["engine.executable"]["status"] == "ready"

    executable = tmp_path / "files" / "engine.bin"
    executable.chmod(0o444)
    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["engine.executable"]["code"] == "executable_bit_missing"
    assert report["candidate_id"] == _LEGACY_FIXTURE_ID


@pytest.mark.parametrize("engine_id", ("synthetic-engine", "comfyui"))
def test_engine_id_alone_does_not_allow_a_non_executable_entrypoint(
    tmp_path: Path, engine_id: str
) -> None:
    declaration_path = _fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["id"] = engine_id
    (tmp_path / "files" / "engine.bin").chmod(0o444)
    _write_json(declaration_path, declaration)

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["engine.executable"]["code"] == "executable_bit_missing"


def test_python_script_contract_accepts_readable_0444_script_and_checks_interpreter(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = parse_candidate(declaration_path)
    assert declaration.engine.launch is not None
    assert declaration.engine.launch.kind == "python-script"
    assert stat.S_IMODE((tmp_path / "files" / "engine.bin").stat().st_mode) == 0o444

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    items = _items(report)
    assert items["engine.executable"]["status"] == "ready"
    assert items["engine.interpreter"]["status"] == "ready"
    assert items["engine.interpreter.provenance.evidence"]["status"] == "unverified"
    assert items["engine.interpreter.license.evidence"]["status"] == "unverified"

    parsed = parse_candidate(declaration_path)
    script = parsed.engine.executable
    interpreter = parsed.engine.launch.interpreter
    assert (script.root, script.path) != (interpreter.root, interpreter.path)
    assert _observe_target(parsed, "engine", script).status == "ready"
    assert _observe_target(parsed, "engine.interpreter", interpreter).status == "ready"
    assert "engine.interpreter" in parsed.artifact_targets()


def test_stable_diffusion_cpp_adapter_does_not_run_python_script_candidates(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["id"] = "stable-diffusion.cpp"
    declaration["recipe"]["engine_id"] = "stable-diffusion.cpp"
    _write_json(declaration_path, declaration)

    with pytest.raises(BackendPreparationError, match="native executable"):
        load_engine_candidate(declaration_path)


def test_comfyui_requires_explicit_python_script_contract_even_for_comfyui_id(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    declaration = json.loads(bundle.declaration_path.read_text(encoding="utf-8"))
    declaration["engine"].pop("launch", None)
    (tmp_path / "bundle" / "files" / "comfyui-source" / "comfyui-server.py").chmod(
        0o755
    )
    _write_json(bundle.declaration_path, declaration)

    with pytest.raises(BackendPreparationError, match="launch contract"):
        load_comfyui_candidate(bundle.declaration_path, bundle.trusted_evidence_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (("schema_version", 2), ("kind", "native-executable")),
)
def test_unsupported_python_script_launch_contract_fails_closed(
    tmp_path: Path, field: str, value: object
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"][field] = value
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError):
        parse_candidate(declaration_path)


@pytest.mark.parametrize("path", ("../python.bin", "/etc/passwd"))
def test_python_interpreter_pin_rejects_unsafe_paths(
    tmp_path: Path, path: str
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"]["interpreter"]["path"] = path
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError):
        parse_candidate(declaration_path)


def test_python_interpreter_root_cannot_overlap_candidate_files_root(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    files = tmp_path / "files"
    (files / "python-root").mkdir()
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["roots"].append(
        {"id": "python", "path": "files/python-root"}
    )
    declaration["engine"]["launch"]["interpreter"]["root"] = "python"
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError, match="nested roots"):
        parse_candidate(declaration_path)


def test_missing_launch_contract_keeps_legacy_execute_requirement(tmp_path: Path) -> None:
    declaration_path = _fixture(tmp_path)
    (tmp_path / "files" / "engine.bin").chmod(0o444)

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["engine.executable"]["code"] == "executable_bit_missing"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("missing", "file_missing"),
        ("bytes", "sha256_mismatch"),
        ("size", "size_mismatch"),
        ("mode", "executable_bit_missing"),
    ),
)
def test_python_script_launch_fails_closed_when_interpreter_is_unavailable_or_drifted(
    tmp_path: Path, mutation: str, expected_code: str
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    interpreter_path = tmp_path / "files" / "python.bin"
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    if mutation == "missing":
        interpreter_path.unlink()
    elif mutation == "bytes":
        interpreter_path.write_bytes(b"x" * interpreter_path.stat().st_size)
    elif mutation == "size":
        declaration["engine"]["launch"]["interpreter"]["size_bytes"] += 1
        _write_json(declaration_path, declaration)
    else:
        interpreter_path.chmod(0o644)

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["engine.interpreter"]["code"] == expected_code


@pytest.mark.parametrize("artifact_name", ("engine.bin", "python.bin"))
def test_python_script_and_interpreter_symlinks_are_rejected(
    tmp_path: Path, artifact_name: str
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    files = tmp_path / "files"
    target = files / artifact_name
    replacement = files / f"{artifact_name}.replacement"
    replacement.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(replacement.name)

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    artifact = "engine.executable" if artifact_name == "engine.bin" else "engine.interpreter"
    assert _items(report)[artifact]["status"] != "ready"


def test_python_interpreter_cannot_alias_script_path(tmp_path: Path) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"]["interpreter"] = declaration["engine"]["executable"]
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError, match="interpreter"):
        parse_candidate(declaration_path)


def test_python_interpreter_cannot_alias_recipe_path(tmp_path: Path) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"]["interpreter"] = declaration["recipe"]["document"]
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError, match="interpreter"):
        parse_candidate(declaration_path)


def test_python_interpreter_cannot_alias_component_hard_link(tmp_path: Path) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    files = tmp_path / "files"
    interpreter_path = files / "python.bin"
    component_path = files / "diffusion.safetensors"
    component_path.unlink()
    component_path.hardlink_to(interpreter_path)
    interpreter_stat = interpreter_path.stat()
    component_stat = component_path.stat()
    assert (interpreter_stat.st_dev, interpreter_stat.st_ino) == (
        component_stat.st_dev,
        component_stat.st_ino,
    )

    with pytest.raises(CandidateValidationError, match="interpreter"):
        parse_candidate(declaration_path)


def test_evaluate_candidate_rejects_post_parse_hard_link_alias(
    tmp_path: Path,
) -> None:
    declaration_path = _fixture(tmp_path)
    payload = _payload(declaration_path)
    files = tmp_path / "files"
    diffusion_path = files / "diffusion.safetensors"
    vae_path = files / "vae.safetensors"
    diffusion_bytes = diffusion_path.read_bytes()
    vae_path.write_bytes(diffusion_bytes)

    vae = next(
        component for component in payload["components"] if component["id"] == "vae"
    )
    vae["artifact"] = _pin_written_file(files, vae_path.name)
    _rewrite(declaration_path, payload)

    parsed = parse_candidate(declaration_path)
    before = evaluate_candidate(parsed).report("inspect")
    before_items = _items(before)
    assert before_items["component:diffusion"]["status"] == "ready"
    assert before_items["component:vae"]["status"] == "ready"
    assert "candidate.physical_identity" not in before_items

    vae_path.unlink()
    os.link(diffusion_path, vae_path)

    after = evaluate_candidate(parsed).report("inspect")
    after_items = _items(after)
    alias = after_items["candidate.physical_identity"]
    assert after["status"] == "corrupt"
    assert after_items["component:diffusion"]["status"] == "ready"
    assert after_items["component:vae"]["status"] == "ready"
    assert alias["status"] == "corrupt"
    assert alias["code"] == "physical_alias"


def test_verify_candidate_fails_closed_for_script_interpreter_alias(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"]["interpreter"] = declaration["engine"]["executable"]
    _write_json(declaration_path, declaration)

    with pytest.raises(CandidateValidationError, match="interpreter"):
        candidate.verify_candidate(
            declaration_path, trusted_evidence=_trusted_evidence()
        )


def test_interpreter_identity_changes_candidate_and_compatibility_binding(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    before = parse_candidate(declaration_path).stable_candidate_id()
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"]["launch"]["interpreter"]["sha256"] = "b" * 64
    _write_json(declaration_path, declaration)
    after = parse_candidate(declaration_path).stable_candidate_id()
    assert after != before

    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    compatibility = _items(report)["recipe.compatibility.evidence[0]"]
    assert compatibility["code"] == "evidence_contract_mismatch"


def test_changing_launch_mode_invalidates_prior_compatibility_evidence(
    tmp_path: Path,
) -> None:
    declaration_path = _python_script_fixture(tmp_path)
    before = parse_candidate(declaration_path).stable_candidate_id()
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["engine"].pop("launch")
    (tmp_path / "files" / "engine.bin").chmod(0o755)
    _write_json(declaration_path, declaration)

    parsed = parse_candidate(declaration_path)
    assert parsed.stable_candidate_id() != before
    report = candidate.verify_candidate(
        declaration_path, trusted_evidence=_trusted_evidence()
    )
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )


def test_python_launch_candidate_preparation_uses_the_same_interpreter_target(
    tmp_path: Path,
) -> None:
    from media_generation._candidate_acquisition import prepare_candidate

    declaration_path = _python_script_fixture(tmp_path)
    declaration = parse_candidate(declaration_path)
    assert declaration.artifact_targets()["engine.interpreter"] == (
        declaration.engine.launch.interpreter
    )

    manifest_path = tmp_path / "prepared.json"
    prepared = prepare_candidate(
        declaration_path,
        manifest_output=manifest_path,
        trusted_evidence=_trusted_evidence(),
    )
    prepared_items = _items(prepared)
    assert prepared_items["engine.executable"]["status"] == "ready"
    assert prepared_items["engine.interpreter"]["status"] == "ready"


def test_acquisition_reconciliation_keeps_script_readable_and_interpreter_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "darwin":
        inject_linux_inode_operations(monkeypatch, tmp_path / "injected-linux-inodes")
    declaration_path = _python_script_fixture(tmp_path)
    files = tmp_path / "files"
    interpreter_path = files / "python.bin"
    interpreter_bytes = interpreter_path.read_bytes()
    interpreter_path.unlink()
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    declaration["acquisition"] = {
        "sources": [
            {
                "artifact": "engine.interpreter",
                "url": "https://downloads.example/python.bin",
            }
        ]
    }
    _write_json(declaration_path, declaration)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(interpreter_bytes))},
            body=interpreter_bytes,
        ),
    )

    report = candidate.prepare_candidate(
        declaration_path,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=_acquisition_config(tmp_path),
        trusted_evidence=_trusted_evidence(),
    )

    items = _items(report)
    assert items["engine.executable"]["status"] == "ready"
    assert items["engine.interpreter"]["status"] == "ready"
    assert (files / "engine.bin").stat().st_mode & 0o111 == 0
    assert (files / "python.bin").stat().st_mode & 0o111
