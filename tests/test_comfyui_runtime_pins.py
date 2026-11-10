from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from media_generation.backend_provenance import canonical_json
from media_generation import comfyui
from media_generation.comfyui import ComfyUIAdapter, load_comfyui_candidate
from media_generation import comfyui_runtime_pins
from media_generation.domain import GenerationPlan, ResolvedReference
from media_generation.errors import BackendPreparationError
from media_generation.privacy import (
    PrivacyControl,
    application_privacy_profile,
    comfyui_invocation_privacy_settings,
)
from test_t09_support import build_comfyui_bundle as _build_comfyui_bundle


_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_APPROVAL_ENV = "MEDIA_GENERATION_COMFYUI_RUNTIME_APPROVAL_PATH"
_PUBLIC_KEY_ENV = "MEDIA_GENERATION_COMFYUI_RUNTIME_PUBLIC_KEY_PATH"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AssertionError(f"test runtime tree unexpectedly contains a symlink: {path}")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            entries.append({"path": relative, "kind": "directory"})
        else:
            data = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    return hashlib.sha256(canonical_json(entries).encode("utf-8")).hexdigest()


def _tree_pin(root: Path) -> dict[str, object]:
    digest, size_bytes, entry_count = comfyui_runtime_pins._tree_sha256(root)
    return {
        "path": str(root.resolve()),
        "sha256": digest,
        "size_bytes": size_bytes,
        "entry_count": entry_count,
    }


def _file_pin(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    assert stat.S_ISREG(info.st_mode)
    return {
        "path": str(resolved),
        "size_bytes": info.st_size,
        "sha256": _sha256_file(resolved),
    }


def _external_test_interpreter() -> Path:
    repository_root = Path(__file__).resolve().parents[1]
    for candidate in (
        Path(sys.executable),
        Path("/usr/local/bin/python3"),
        Path("/opt/homebrew/bin/python3"),
        Path("/usr/bin/python3"),
    ):
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if (
            resolved.is_file()
            and os.access(resolved, os.X_OK)
            and not resolved.is_relative_to(repository_root)
        ):
            return resolved
    raise AssertionError("test runtime needs an executable Python outside the repository")


def build_comfyui_bundle(tmp_path: Path, **kwargs):
    """Build signed-runtime fixtures with an interpreter outside the checkout."""
    return _build_comfyui_bundle(
        tmp_path,
        python_interpreter=_external_test_interpreter(),
        **kwargs,
    )


def _signed_approval(
    tmp_path: Path,
    candidate,
    *,
    interpreter_path: Path | None = None,
) -> tuple[Path, Path, str]:
    openssl = shutil.which("openssl")
    assert openssl is not None, "OpenSSL is required to create isolated test keys"

    runtime = tmp_path / "synthetic-runtime"
    python_base_prefix = runtime / "python-base-prefix"
    python_stdlib = python_base_prefix / "stdlib"
    python_stdlib_dynload = python_stdlib / "lib-dynload"
    python_stdlib_dynload.mkdir(parents=True)
    stdlib_file = python_stdlib / "stdlib-fixture.py"
    stdlib_file.write_text("PINNED_STDLIB_FIXTURE = True\n", encoding="utf-8")
    declaration = candidate.declaration
    executable = declaration.engine.executable.resolved_path(declaration.root_index)
    if interpreter_path is None:
        launch = declaration.engine.launch
        if launch is None or launch.kind != "python-script":
            raise AssertionError("ComfyUI candidate must declare Python-script launch")
        interpreter = launch.interpreter.resolved_path(declaration.root_index)
    else:
        interpreter_path.parent.mkdir(parents=True, exist_ok=True)
        interpreter_path.write_bytes(b"synthetic test interpreter\n")
        interpreter = interpreter_path
    roots: list[dict[str, object]] = []
    root_roles = (
        "comfyui_source",
        "python_home",
        "python_imports",
        "native_dependencies",
        "frontend",
        "node_implementations",
    )
    for role in root_roles:
        if role == "frontend":
            root = (
                candidate.declaration.recipe.document.resolved_path(
                    candidate.declaration.root_index
                ).parent
                / "frontend"
            )
        elif role == "comfyui_source":
            root = executable.parent
        else:
            root = runtime / role
        root.mkdir(parents=True, exist_ok=True)
        if not any(root.iterdir()):
            (root / "approved-runtime-file.txt").write_text(
                f"synthetic {role}\n", encoding="utf-8"
            )
        roots.append(
            {"role": role, "path": str(root.resolve()), "sha256": _tree_sha256(root)}
        )

    workflow = declaration.recipe.document.resolved_path(declaration.root_index)
    components = [
        {
            "component_id": component.id,
            "role": component.role,
            **_file_pin(component.artifact.resolved_path(declaration.root_index)),
        }
        for component in declaration.components
    ]
    payload = {
        "schema": "media-generation.comfyui-runtime-pin-set",
        "schema_version": comfyui_runtime_pins.RUNTIME_PIN_SCHEMA_VERSION,
        "tool_id": declaration.engine.id,
        "tool_version": declaration.engine.version,
        "configuration_version": "comfyui-local/v2",
        "candidate_id": candidate.candidate_id,
        "roots": roots,
        "python_base_prefix": str(python_base_prefix.resolve()),
        "python_stdlib_paths": [
            str(python_stdlib.resolve()),
            str(python_stdlib_dynload.resolve()),
        ],
        "python_stdlib_pins": [
            _tree_pin(python_stdlib),
            _tree_pin(python_stdlib_dynload),
        ],
        "interpreter": _file_pin(interpreter),
        "entrypoint": _file_pin(executable),
        "workflow": {
            "id": candidate.recipe.id,
            **_file_pin(workflow),
        },
        "components": components,
        "trusted_evidence": [
            {
                "authority_id": record.authority_id,
                "document_size_bytes": record.document_size_bytes,
                "document_sha256": record.document_sha256,
            }
            for record in sorted(candidate.trusted_evidence, key=lambda item: item.authority_id)
        ],
    }
    payload_bytes = canonical_json(payload).encode("utf-8")
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    private_key = operator_dir / "test-only-private.pem"
    public_key = operator_dir / "runtime-public-key"
    payload_path = operator_dir / "payload.json"
    signature_path = operator_dir / "signature.bin"
    subprocess.run(
        [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    public_der = subprocess.check_output(
        [openssl, "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"]
    )
    assert public_der.startswith(_ED25519_SPKI_PREFIX)
    public_key.write_bytes(base64.b64encode(public_der[len(_ED25519_SPKI_PREFIX) :]) + b"\n")
    payload_path.write_bytes(payload_bytes)
    subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        capture_output=True,
    )
    envelope = {
        "payload": payload,
        "signature": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
    }
    approval_path = operator_dir / "runtime-approval.json"
    approval_path.write_bytes((canonical_json(envelope) + "\n").encode("utf-8"))
    return approval_path, public_key, payload["tool_version"]


def _launch_argv(payload: dict[str, object], roots: dict[str, str], base: Path) -> list[str]:
    return [
        payload["interpreter"]["path"],
        "-P",
        "-s",
        "-S",
        str(comfyui_runtime_pins.COMFYUI_PYTHON_BOOTSTRAP_PATH),
        roots["python_home"],
        payload["python_base_prefix"],
        "--stdlib-paths",
        *payload["python_stdlib_paths"],
        "--import-roots",
        roots["python_imports"],
        roots["comfyui_source"],
        "--",
        payload["entrypoint"]["path"],
        "--front-end-root",
        roots["frontend"],
        "--base-directory",
        str(base),
    ]


def _launch_environment(roots: dict[str, str]) -> dict[str, str]:
    return {
        "PATH": comfyui_runtime_pins.COMFYUI_CLOSED_PATH,
        "LD_LIBRARY_PATH": roots["native_dependencies"],
    }


def test_test_approval_pins_python_and_server_entrypoint_separately(
    tmp_path: Path,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, _, _ = _signed_approval(tmp_path, candidate)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    entrypoint = candidate.declaration.engine.executable.resolved_path(
        candidate.declaration.root_index
    )

    declared_interpreter = candidate.declaration.engine.launch.interpreter.resolved_path(
        candidate.declaration.root_index
    )
    assert payload["interpreter"] == _file_pin(declared_interpreter)
    assert payload["entrypoint"]["path"] == str(entrypoint.resolve())


def test_child_environment_replaces_inherited_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    approval = comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)
    attacker_path = tmp_path / "attacker-bin"
    monkeypatch.setenv("PATH", str(attacker_path))

    environment = comfyui._child_environment(("PATH",), approval)

    assert environment["PATH"] == comfyui_runtime_pins.COMFYUI_CLOSED_PATH
    assert str(attacker_path) not in environment["PATH"]


def _install_signed_approval_for_test(
    monkeypatch: pytest.MonkeyPatch, approval_path: Path, public_key_path: Path
) -> None:
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: public_key_path.read_bytes(),
    )


def test_signed_runtime_approval_registers_the_exact_comfyui_version(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, approved_version = _signed_approval(
        tmp_path, candidate
    )
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    attacker_key_path = tmp_path / "attacker-public-key"
    attacker_key_path.write_bytes(b"attacker-selected-key")
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(attacker_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: public_key_path.read_bytes(),
        raising=False,
    )

    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )

    assert adapter.configuration["engine"]["version"] == approved_version
    profile = application_privacy_profile(adapter.adapter_id, adapter.configuration)
    assert profile.tool_version == approved_version


def test_environment_selected_public_key_cannot_verify_an_approval(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    trusted_approval, trusted_key_path, _ = _signed_approval(
        tmp_path / "trusted", candidate
    )
    attacker_approval, attacker_key_path, _ = _signed_approval(
        tmp_path / "attacker", candidate
    )
    monkeypatch.setenv(_APPROVAL_ENV, str(attacker_approval))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(attacker_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: trusted_key_path.read_bytes(),
        raising=False,
    )

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match="signature is invalid"):
        comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)


def test_unprotected_host_trust_root_is_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    public_key_path.parent.chmod(0o777)
    public_key_path.chmod(0o666)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_HOST_TRUST_KEY_PATH",
        public_key_path,
        raising=False,
    )

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)


def test_symlinked_host_trust_root_is_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    alias = tmp_path / "trust-root-alias"
    alias.symlink_to(public_key_path.parent, target_is_directory=True)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_HOST_TRUST_KEY_PATH",
        alias / public_key_path.name,
        raising=False,
    )

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)


def test_missing_host_trust_key_fails_closed(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path)
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_HOST_TRUST_KEY_PATH",
        tmp_path / "missing-host-trust-key",
        raising=False,
    )

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)


def test_runtime_roots_must_match_the_child_command(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: public_key_path.read_bytes(),
        raising=False,
    )
    approval = comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    roots = {item["role"]: item["path"] for item in payload["roots"]}
    base_directory = tmp_path / "child-base"
    models_directory = base_directory / "models"
    models_directory.mkdir(parents=True)
    environment = _launch_environment(roots)
    argv = _launch_argv(payload, roots, base_directory)
    argv[6] = roots["comfyui_source"]

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match="Python roots"):
        comfyui_runtime_pins.verify_runtime_launch_binding(
            approval,
            argv=argv,
            environment=environment,
            workflow_path=Path(payload["workflow"]["path"]),
            models_directory=models_directory,
            model_files=(),
        )


def test_signed_node_root_must_match_child_custom_nodes_path(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: public_key_path.read_bytes(),
        raising=False,
    )
    approval = comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    roots = {item["role"]: item["path"] for item in payload["roots"]}
    base_directory = tmp_path / "child-base"
    models_directory = base_directory / "models"
    models_directory.mkdir(parents=True)
    wrong_node_root = tmp_path / "wrong-node-root"
    wrong_node_root.mkdir()
    (base_directory / "custom_nodes").symlink_to(
        wrong_node_root, target_is_directory=True
    )
    environment = _launch_environment(roots)

    with pytest.raises(
        comfyui_runtime_pins.RuntimePinError, match="node implementation path"
    ):
        comfyui_runtime_pins.verify_runtime_launch_binding(
            approval,
            argv=_launch_argv(payload, roots, base_directory),
            environment=environment,
            workflow_path=Path(payload["workflow"]["path"]),
            models_directory=models_directory,
            model_files=(),
        )


def test_inherited_import_and_native_paths_are_replaced_with_signed_roots(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    monkeypatch.setenv(_APPROVAL_ENV, str(approval_path))
    monkeypatch.setenv(_PUBLIC_KEY_ENV, str(public_key_path))
    monkeypatch.setenv("PYTHONPATH", "/attacker/python-imports")
    monkeypatch.setenv("PYTHONHOME", "/attacker/python-home")
    monkeypatch.setenv("PYTHONHASHSEED", "random")
    monkeypatch.setenv("PYTHONUSERBASE", "/attacker/user-base")
    monkeypatch.setenv("PYTHONSTARTUP", "/attacker/startup.py")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/attacker/native-libraries")
    monkeypatch.setattr(
        comfyui_runtime_pins,
        "_read_host_trust_key",
        lambda: public_key_path.read_bytes(),
        raising=False,
    )
    envelope = json.loads(approval_path.read_text(encoding="utf-8"))
    roots = {item["role"]: item["path"] for item in envelope["payload"]["roots"]}
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    reference_path = tmp_path / "reference.bin"
    reference_path.write_bytes(b"synthetic upload")

    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_environment_binding",
            attempt_id="attempt_environment_binding",
            resolved_prompt="environment binding",
            seed=1,
            width=64,
            height=64,
            references=(
                ResolvedReference(
                    artifact_id="synthetic-reference",
                    content_sha256=hashlib.sha256(reference_path.read_bytes()).hexdigest(),
                    path=reference_path,
                    role="reference",
                ),
            ),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    try:
        assert prepared.argv[1:5] == (
            "-P",
            "-s",
            "-S",
            str(comfyui_runtime_pins.COMFYUI_PYTHON_BOOTSTRAP_PATH),
        )
        assert prepared.argv[5:8] == (
            roots["python_home"],
            envelope["payload"]["python_base_prefix"],
            "--stdlib-paths",
        )
        import_roots_index = prepared.argv.index("--import-roots")
        assert prepared.argv[8:import_roots_index] == tuple(
            envelope["payload"]["python_stdlib_paths"]
        )
        assert prepared.argv[import_roots_index + 1 : import_roots_index + 4] == (
            roots["python_imports"],
            roots["comfyui_source"],
            "--",
        )
        assert prepared.argv[import_roots_index + 4] == envelope["payload"]["entrypoint"]["path"]
        assert "PYTHONHOME" not in prepared.environment
        assert prepared.environment["PYTHONHASHSEED"] == "random"
        assert not any(
            name.upper().startswith("PYTHON")
            and name.upper() != "PYTHONHASHSEED"
            for name in prepared.environment
        )
        assert prepared.environment["LD_LIBRARY_PATH"] == roots["native_dependencies"]
        assert (prepared.scratch_directory / "custom_nodes").resolve(strict=True) == Path(
            roots["node_implementations"]
        )
        assert "PYTHONPATH" not in prepared.environment
        assert "/attacker/" not in prepared.environment["LD_LIBRARY_PATH"]
        assert comfyui_invocation_privacy_settings(
            prepared.argv,
            prepared.environment,
            prepared.resolved_record["effective_execution"],
        ) == {control.value: False for control in PrivacyControl}
    finally:
        adapter.cleanup_execution(prepared)


def test_isolated_bootstrap_ignores_user_site_hooks_and_python_path_injection(
    tmp_path: Path,
) -> None:
    interpreter = _external_test_interpreter()
    clean_environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("PYTHON")
    }
    path_result = subprocess.run(
        [
            str(interpreter),
            "-P",
            "-s",
            "-S",
            "-c",
            "import json,sys,sysconfig;print(json.dumps({'prefix':sys.prefix,'base_prefix':sys.base_prefix,'path':sys.path,'stdlib':sysconfig.get_path('stdlib'),'dynload':sysconfig.get_config_var('DESTSHARED')}))",
        ],
        env=clean_environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert path_result.returncode == 0, path_result.stderr
    startup = json.loads(path_result.stdout)
    python_home = startup["prefix"]
    python_base_prefix = startup["base_prefix"]
    initial_paths = startup["path"]
    python_stdlib_paths = list(
        dict.fromkeys((startup["stdlib"], startup["dynload"] or str(Path(startup["stdlib"]) / "lib-dynload")))
    )
    assert initial_paths and all(isinstance(path, str) and path for path in initial_paths)

    source_root = tmp_path / "approved-source"
    source_root.mkdir()
    python_imports = tmp_path / "approved-imports"
    python_imports.mkdir()
    probe = source_root / "probe.py"
    probe.write_text(
        "import json, sys\n"
        "print(json.dumps({'safe_path': sys.flags.safe_path, 'no_user_site': sys.flags.no_user_site, 'no_site': sys.flags.no_site, 'path': sys.path}))\n",
        encoding="utf-8",
    )
    attacker_root = tmp_path / "attacker-imports"
    attacker_root.mkdir()
    user_base = tmp_path / "user-base"
    user_site_result = subprocess.run(
        [
            str(interpreter),
            "-S",
            "-c",
            "import site;print(site.getusersitepackages())",
        ],
        env={**clean_environment, "PYTHONUSERBASE": str(user_base)},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert user_site_result.returncode == 0, user_site_result.stderr
    user_site = Path(user_site_result.stdout.strip())
    user_site.mkdir(parents=True, exist_ok=True)
    marker = tmp_path / "startup-hook-ran"
    marker_literal = repr(str(marker))
    hook = f"from pathlib import Path; Path({marker_literal}).write_text('ran')\n"
    (attacker_root / "sitecustomize.py").write_text(hook, encoding="utf-8")
    (user_site / "sitecustomize.py").write_text(hook, encoding="utf-8")
    (user_site / "usercustomize.py").write_text(hook, encoding="utf-8")
    (user_site / "untrusted.pth").write_text(
        f"import pathlib; pathlib.Path({marker_literal}).write_text('ran')\n",
        encoding="utf-8",
    )

    bootstrap = Path(comfyui.__file__).with_name("_comfyui_python_bootstrap.py")
    environment = {
        **clean_environment,
        "PYTHONUSERBASE": str(user_base),
        "PYTHONSTARTUP": str(attacker_root / "startup.py"),
    }
    process = subprocess.run(
        [
            str(interpreter),
            "-P",
            "-s",
            "-S",
            str(bootstrap),
            python_home,
            python_base_prefix,
            "--stdlib-paths",
            *python_stdlib_paths,
            "--import-roots",
            str(python_imports),
            str(source_root),
            "--",
            str(probe),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert process.returncode == 0, process.stderr
    effective = json.loads(process.stdout)
    assert effective["safe_path"] is True
    assert effective["no_user_site"] == 1
    assert effective["no_site"] == 1
    assert effective["path"] == python_stdlib_paths + [
        str(python_imports),
        str(source_root),
    ]
    assert effective["path"] != initial_paths
    assert str(attacker_root) not in effective["path"]
    assert str(user_site) not in effective["path"]
    assert not marker.exists()

    escaped_environment = {**environment, "PYTHONPATH": str(attacker_root)}
    escaped = subprocess.run(
        [
            str(interpreter),
            "-P",
            "-s",
            "-S",
            str(bootstrap),
            python_home,
            python_base_prefix,
            "--stdlib-paths",
            *python_stdlib_paths,
            "--import-roots",
            str(python_imports),
            str(source_root),
            "--",
            str(probe),
        ],
        env=escaped_environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert escaped.returncode != 0
    assert "outside signed runtime roots" in escaped.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("drift", "expected_error"),
    [
        ("python_home", "sys.prefix does not match the signed Python home"),
        (
            "python_base_prefix",
            "sys.base_prefix does not match the signed Python base prefix",
        ),
    ],
)
def test_isolated_bootstrap_rejects_incorrect_signed_prefixes(
    tmp_path: Path, drift: str, expected_error: str
) -> None:
    interpreter = Path(sys.executable).resolve(strict=True)
    environment = {"PATH": comfyui_runtime_pins.COMFYUI_CLOSED_PATH}
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
        if system_root:
            environment["SystemRoot"] = system_root
    startup_result = subprocess.run(
        [
            str(interpreter),
            "-P",
            "-s",
            "-S",
            "-c",
            "import json,sys,sysconfig;print(json.dumps({'prefix':sys.prefix,'base_prefix':sys.base_prefix,'stdlib':sysconfig.get_path('stdlib'),'dynload':sysconfig.get_config_var('DESTSHARED')}))",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert startup_result.returncode == 0, startup_result.stderr
    startup = json.loads(startup_result.stdout)
    python_home = startup["prefix"]
    python_base_prefix = startup["base_prefix"]
    stdlib = startup["stdlib"]
    stdlib_paths = [
        stdlib,
        startup["dynload"] or str(Path(stdlib) / "lib-dynload"),
    ]
    source_root = tmp_path / "approved-source"
    source_root.mkdir()
    import_root = tmp_path / "approved-imports"
    import_root.mkdir()
    entrypoint = source_root / "probe.py"
    entrypoint.write_text("print('started')\n", encoding="utf-8")
    if drift == "python_home":
        python_home = str((tmp_path / "incorrect-python-home").resolve())
    else:
        python_base_prefix = str((tmp_path / "incorrect-base-prefix").resolve())

    bootstrap = Path(comfyui.__file__).with_name("_comfyui_python_bootstrap.py")
    process = subprocess.run(
        [
            str(interpreter),
            "-P",
            "-s",
            "-S",
            str(bootstrap),
            python_home,
            python_base_prefix,
            "--stdlib-paths",
            *stdlib_paths,
            "--import-roots",
            str(import_root),
            str(source_root),
            "--",
            str(entrypoint),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert process.returncode != 0
    assert expected_error in process.stderr
    assert process.stdout == ""


def test_runtime_role_must_be_a_string_before_set_membership() -> None:
    malformed = [
        {"role": role, "path": f"/runtime/{role}", "sha256": "0" * 64}
        for role in comfyui_runtime_pins._ROOT_ROLES
    ]
    malformed[0]["role"] = []

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins._validate_roots(malformed)


def test_runtime_tree_rejects_symlink_added_after_directory_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.bin").write_bytes(b"outside")
    (root / "child").mkdir()

    original_open = comfyui_runtime_pins.os.open
    changed = False

    def replace_child_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal changed
        if path == "child" and dir_fd is not None and not changed:
            child = root / "child"
            child.rmdir()
            child.symlink_to(outside, target_is_directory=True)
            changed = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(comfyui_runtime_pins.os, "open", replace_child_before_open)
    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins._tree_sha256(root)
    assert changed


@pytest.mark.parametrize(
    ("limit_name", "limit", "contents"),
    [
        ("_MAX_ROOT_ENTRIES", 1, ("one", "two")),
        ("_MAX_TREE_DEPTH", 1, ("nested",)),
        ("_MAX_PINNED_FILE_BYTES", 3, ("oversized",)),
    ],
)
def test_runtime_tree_enforces_entry_depth_and_file_bounds_before_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    contents: tuple[str, ...],
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    if limit_name == "_MAX_TREE_DEPTH":
        (root / "nested").mkdir()
        ((root / "nested") / "deeper").mkdir()
    elif limit_name == "_MAX_PINNED_FILE_BYTES":
        (root / "oversized").write_bytes(b"four")
    else:
        for name in contents:
            (root / name).write_bytes(b"x")
    monkeypatch.setattr(comfyui_runtime_pins, limit_name, limit)
    opened_entries: list[str] = []
    original_open = comfyui_runtime_pins.os.open

    def record_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            opened_entries.append(path)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(comfyui_runtime_pins.os, "open", record_open)

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins._tree_sha256(root)

    if limit_name == "_MAX_ROOT_ENTRIES":
        assert len(opened_entries) == 1
    elif limit_name == "_MAX_TREE_DEPTH":
        assert "deeper" not in opened_entries
    else:
        assert "oversized" not in opened_entries


def test_runtime_tree_hashes_files_in_bounded_chunks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    file_bytes = b"x" * (2 * comfyui_runtime_pins._HASH_CHUNK_BYTES + 17)
    (root / "large.bin").write_bytes(file_bytes)
    read_sizes: list[int] = []
    original_read = comfyui_runtime_pins.os.read

    def record_read(descriptor: int, size: int) -> bytes:
        read_sizes.append(size)
        return original_read(descriptor, size)

    monkeypatch.setattr(comfyui_runtime_pins.os, "read", record_read)

    _, total_size, _ = comfyui_runtime_pins._tree_sha256(root)

    assert total_size == len(file_bytes)
    assert len(read_sizes) >= 3
    assert max(read_sizes) <= comfyui_runtime_pins._HASH_CHUNK_BYTES


def test_runtime_roots_share_the_aggregate_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    first_root = Path(payload["roots"][0]["path"])
    first_root_size = comfyui_runtime_pins._tree_sha256(first_root)[1]
    opened_entries: list[str] = []
    original_open = comfyui_runtime_pins.os.open

    def record_open(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            opened_entries.append(path)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(comfyui_runtime_pins, "_MAX_TOTAL_ROOT_BYTES", first_root_size)
    monkeypatch.setattr(comfyui_runtime_pins.os, "open", record_open)

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match="byte limit"):
        comfyui_runtime_pins.load_runtime_pin_approval()

    assert "approved-runtime-file.txt" not in opened_entries


def test_standard_library_roots_share_the_runtime_tree_byte_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    runtime_root_bytes = sum(
        comfyui_runtime_pins._tree_sha256(Path(root["path"]))[1]
        for root in payload["roots"]
    )
    assert payload["python_stdlib_pins"][0]["size_bytes"] > 0
    monkeypatch.setattr(
        comfyui_runtime_pins, "_MAX_TOTAL_ROOT_BYTES", runtime_root_bytes
    )

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match="byte limit"):
        comfyui_runtime_pins.load_runtime_pin_approval()


@pytest.mark.parametrize(
    "drift",
    [
        "comfyui_source",
        "python_imports",
        "native_dependencies",
        "node_implementations",
        "frontend",
        "python_stdlib",
        "interpreter",
        "workflow",
        "model",
    ],
)
def test_signed_runtime_closure_rejects_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(
        tmp_path,
        candidate,
        interpreter_path=(
            tmp_path / "synthetic-runtime" / "test-interpreter"
            if drift == "interpreter"
            else None
        ),
    )
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]

    if drift in {"comfyui_source", "python_imports", "native_dependencies", "node_implementations", "frontend"}:
        root = Path(next(item["path"] for item in payload["roots"] if item["role"] == drift))
        if drift == "comfyui_source":
            workflow = Path(payload["workflow"]["path"])
            assert not workflow.is_relative_to(root)
            workflow_bytes = workflow.read_bytes()
            target = root / "unlisted-source-module.py"
            target.write_text("unapproved source addition\n", encoding="utf-8")
        else:
            target = next(path for path in root.rglob("*") if path.is_file())
    elif drift == "python_stdlib":
        target = Path(payload["python_stdlib_paths"][0]) / "stdlib-fixture.py"
    elif drift == "interpreter":
        target = Path(payload["interpreter"]["path"])
    elif drift == "workflow":
        target = Path(payload["workflow"]["path"])
    else:
        target = Path(payload["components"][0]["path"])
    if drift == "python_stdlib":
        target.write_bytes(b"XINNED_STDLIB_FIXTURE = True\n")
    else:
        target.write_bytes(target.read_bytes() + b"drift")

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins.load_runtime_pin_approval()
    if drift == "comfyui_source":
        assert workflow.read_bytes() == workflow_bytes


@pytest.mark.parametrize("metadata_field", ["size_bytes", "entry_count"])
def test_signed_python_stdlib_tree_metadata_must_match(
    tmp_path: Path, metadata_field: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, _, _ = _signed_approval(tmp_path, candidate)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    pin = payload["python_stdlib_pins"][0]
    pin[metadata_field] += 1

    with pytest.raises(
        comfyui_runtime_pins.RuntimePinError,
        match="Python standard library tree changed after approval",
    ):
        comfyui_runtime_pins._verify_runtime_paths(payload)


@pytest.mark.parametrize(
    "corruption", ["bad_signature", "duplicate_key", "malformed_json", "noncanonical_json"]
)
def test_signed_runtime_manifest_rejects_signature_and_encoding_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)

    if corruption == "bad_signature":
        envelope = json.loads(approval_path.read_text(encoding="utf-8"))
        signature = bytearray(base64.b64decode(envelope["signature"]))
        signature[0] ^= 1
        envelope["signature"] = base64.b64encode(signature).decode("ascii")
        approval_path.write_bytes((canonical_json(envelope) + "\n").encode("utf-8"))
    elif corruption == "duplicate_key":
        approval_path.write_bytes(b'{"payload":{},"payload":{},"signature":"bad"}\n')
    elif corruption == "malformed_json":
        approval_path.write_bytes(b"{not json\n")
    else:
        approval_path.write_bytes(b" " + approval_path.read_bytes())

    with pytest.raises(comfyui_runtime_pins.RuntimePinError):
        comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)


def test_signed_runtime_root_path_rejects_symlink_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    pinned_root = Path(
        next(item["path"] for item in payload["roots"] if item["role"] == "python_imports")
    )
    original_root = pinned_root.with_name("python_imports-original")
    pinned_root.rename(original_root)
    pinned_root.symlink_to(original_root, target_is_directory=True)

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match="symlinks"):
        comfyui_runtime_pins.load_runtime_pin_approval()


def test_signed_python_stdlib_drift_is_rejected_during_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    stdlib_file = Path(payload["python_stdlib_paths"][0]) / "stdlib-fixture.py"
    stdlib_file.write_bytes(b"XINNED_STDLIB_FIXTURE = True\n")
    plan = GenerationPlan(
        job_id="job_stdlib_resolution_recheck",
        attempt_id="attempt_stdlib_resolution_recheck",
        resolved_prompt="stdlib resolution recheck",
        seed=1,
        width=64,
        height=64,
        references=(),
        output_slot="slot",
        output_slot_id="slot_id",
    )

    with pytest.raises(BackendPreparationError):
        adapter.resolve_execution(plan)


def test_signed_python_stdlib_path_rejects_symlink_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    stdlib_root = Path(payload["python_stdlib_paths"][0])
    original_root = stdlib_root.with_name("stdlib-original")
    stdlib_root.rename(original_root)
    stdlib_root.symlink_to(original_root, target_is_directory=True)

    with pytest.raises(BackendPreparationError):
        ComfyUIAdapter(
            candidate_path=bundle.declaration_path,
            trusted_evidence_path=bundle.trusted_evidence_path,
            output_directory=tmp_path / "images",
        )


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("interpreter", "interpreter"),
        ("entrypoint", "entrypoint"),
        ("python_import", "Python roots"),
        ("python_home", "Python setting"),
        ("pythonpath", "unapproved Python setting"),
        ("python_hashseed", "unapproved Python setting"),
        ("native", "native library path"),
        ("child_path", "PATH"),
        ("node", "node implementation path"),
        ("frontend", "frontend command path"),
        ("model", "model search path"),
        ("workflow", "workflow path"),
    ],
)
def test_signed_runtime_launch_binding_rejects_path_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
    message: str,
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    approval = comfyui_runtime_pins.load_runtime_pin_approval(verify_paths=False)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))["payload"]
    roots = {item["role"]: item["path"] for item in payload["roots"]}
    base_directory = tmp_path / "child-base"
    models_directory = base_directory / "models"
    models_directory.mkdir(parents=True)
    (base_directory / "custom_nodes").symlink_to(
        roots["node_implementations"], target_is_directory=True
    )
    component = payload["components"][0]
    model_link = models_directory / Path(component["path"]).name
    model_link.symlink_to(component["path"])
    model_files = (
        {
            "component_id": component["component_id"],
            "role": component["role"],
            "sha256": component["sha256"],
            "search_path": str(model_link),
        },
    )
    argv = _launch_argv(payload, roots, base_directory)
    environment = _launch_environment(roots)
    workflow_path = Path(payload["workflow"]["path"])

    if drift == "interpreter":
        argv[0] = str(workflow_path)
    elif drift == "entrypoint":
        argv[argv.index("--") + 1] = str(workflow_path)
    elif drift == "python_import":
        argv[argv.index("--import-roots") + 1] = roots["comfyui_source"]
    elif drift == "python_home":
        environment["PYTHONHOME"] = roots["python_imports"]
    elif drift == "pythonpath":
        environment["PYTHONPATH"] = roots["comfyui_source"]
    elif drift == "python_hashseed":
        environment["PYTHONHASHSEED"] = "4294967296"
    elif drift == "native":
        environment["LD_LIBRARY_PATH"] = roots["python_imports"]
    elif drift == "child_path":
        environment["PATH"] = str(tmp_path / "attacker-bin")
    elif drift == "node":
        (base_directory / "custom_nodes").unlink()
        wrong_node_root = tmp_path / "wrong-node-root"
        wrong_node_root.mkdir()
        (base_directory / "custom_nodes").symlink_to(
            wrong_node_root, target_is_directory=True
        )
    elif drift == "frontend":
        argv[argv.index("--front-end-root") + 1] = roots["node_implementations"]
    elif drift == "model":
        outside_model = tmp_path / "outside-model.bin"
        outside_model.write_bytes(Path(component["path"]).read_bytes())
        outside_link = models_directory / "outside-model.bin"
        outside_link.symlink_to(outside_model)
        model_files = ({**model_files[0], "search_path": str(outside_link)},)
    else:
        workflow_path = tmp_path / "different-workflow.json"
        workflow_path.write_text("{}", encoding="utf-8")

    with pytest.raises(comfyui_runtime_pins.RuntimePinError, match=message):
        comfyui_runtime_pins.verify_runtime_launch_binding(
            approval,
            argv=argv,
            environment=environment,
            workflow_path=workflow_path,
            models_directory=models_directory,
            model_files=model_files,
        )


def test_runtime_mutation_after_upload_prevents_prompt_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = build_comfyui_bundle(tmp_path, tool_version="0.3.76")
    candidate = load_comfyui_candidate(
        bundle.declaration_path, bundle.trusted_evidence_path
    )
    approval_path, public_key_path, _ = _signed_approval(tmp_path, candidate)
    _install_signed_approval_for_test(monkeypatch, approval_path, public_key_path)
    adapter = ComfyUIAdapter(
        candidate_path=bundle.declaration_path,
        trusted_evidence_path=bundle.trusted_evidence_path,
        output_directory=tmp_path / "images",
    )
    reference_path = tmp_path / "reference.bin"
    reference_path.write_bytes(b"synthetic upload")
    prepared = adapter.resolve_execution(
        GenerationPlan(
            job_id="job_pre_dispatch_recheck",
            attempt_id="attempt_pre_dispatch_recheck",
            resolved_prompt="pre-dispatch recheck",
            seed=1,
            width=64,
            height=64,
            references=(
                ResolvedReference(
                    artifact_id="synthetic-reference",
                    content_sha256=hashlib.sha256(reference_path.read_bytes()).hexdigest(),
                    path=reference_path,
                    role="reference",
                ),
            ),
            output_slot="slot",
            output_slot_id="slot_id",
        )
    )
    envelope = json.loads(approval_path.read_text(encoding="utf-8"))
    stdlib_root = Path(envelope["payload"]["python_stdlib_paths"][0])
    runtime_file = stdlib_root / "stdlib-fixture.py"
    upload_path = reference_path
    prepared = replace(
        prepared,
        uploads=(
            comfyui._Upload(
                path=upload_path,
                filename="reference.bin",
                content_sha256=hashlib.sha256(upload_path.read_bytes()).hexdigest(),
                artifact_id="synthetic-reference",
                role="reference",
            ),
        ),
    )
    posts: list[str] = []

    class Control:
        def require_current(self) -> None:
            return None

    class Connection:
        def close(self) -> None:
            return None

    class Response:
        status = 200

        def read(self, _maximum: int) -> bytes:
            return json.dumps({"prompt_id": prepared.prompt_id}).encode("utf-8")

    def mutate_during_upload(*_args: object) -> None:
        runtime_file.write_bytes(b"XINNED_STDLIB_FIXTURE = True\n")

    def send_prompt(*_args: object, **_kwargs: object) -> Response:
        posts.append("POST /prompt")
        return Response()

    monkeypatch.setattr(adapter, "_wait_ready", lambda *_args: None)
    monkeypatch.setattr(adapter, "_verify_node_replacements", lambda *_args: None)
    monkeypatch.setattr(adapter, "_upload_reference", mutate_during_upload)
    monkeypatch.setattr(adapter, "_connection", lambda *_args: Connection())
    monkeypatch.setattr(adapter, "_request_owned", send_prompt)
    monkeypatch.setattr(adapter, "_require_owned_listener", lambda *_args: None)
    monkeypatch.setattr(adapter, "_wait_for_completion", lambda *_args: {})
    monkeypatch.setattr(adapter, "_retrieve_output", lambda *_args: None)

    try:
        with pytest.raises(BackendPreparationError):
            adapter._run_http_session(Control(), prepared)
        assert posts == []
    finally:
        adapter.cleanup_execution(prepared)
