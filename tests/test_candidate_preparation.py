from __future__ import annotations

import errno
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.request import ProxyHandler, build_opener

import pytest

from media_generation import candidate, cli
from media_generation._candidate_evaluation import _Evaluator, evaluate_candidate
from media_generation.inventory.fingerprint import build_environment_fingerprint

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
SECRET = "t07-secret-sentinel-must-not-leak"


@pytest.fixture(autouse=True)
def linux_acquisition_on_darwin(monkeypatch, tmp_path):
    """Inject Linux syscalls for Darwin tests; native qualification is separate."""
    if sys.platform == "darwin":
        from candidate_linux_fakes import inject_linux_inode_operations
        inject_linux_inode_operations(monkeypatch, tmp_path / "injected-linux-inodes")


_PROCESS_PREPARE_SCRIPT = r"""
import json
import sys
import time
from pathlib import Path

from media_generation import candidate

if sys.platform == "darwin":
    import pytest
    from candidate_linux_fakes import inject_linux_inode_operations
    inject_linux_inode_operations(pytest.MonkeyPatch(), Path(sys.argv[1]).parent / ("linux-inodes-" + str(__import__("os").getpid())))

declaration_path = Path(sys.argv[1])
trusted_evidence_path = Path(sys.argv[2])
acquisition_config_path = Path(sys.argv[3])
journal_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])
ready_path = Path(sys.argv[6])
start_path = Path(sys.argv[7])
result_path = Path(sys.argv[8])

acquisition = candidate._acquisition
real_open = acquisition.os.open
real_load_journal = acquisition._load_journal
lock_name = f".{journal_path.name}.lock"


def no_remote_access(*args, **kwargs):
    raise AssertionError("ready artifacts contacted remote during process test")


def synchronized_lock_open(path, *args, **kwargs):
    if path == lock_name and kwargs.get("dir_fd") is not None:
        ready_path.write_text("ready\n", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not start_path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting for concurrent prepare start")
            time.sleep(0.005)
    return real_open(path, *args, **kwargs)


def delayed_load_journal(target, *, declaration):
    time.sleep(0.1)
    return real_load_journal(target, declaration=declaration)


acquisition.os.open = synchronized_lock_open
acquisition._load_journal = delayed_load_journal
acquisition._open_remote = no_remote_access

trusted_evidence = candidate.parse_trusted_evidence(trusted_evidence_path)
report = candidate.prepare_candidate(
    declaration_path,
    manifest_output=manifest_path,
    journal_output=journal_path,
    acquire=True,
    acquisition_config=acquisition_config_path,
    trusted_evidence_path=trusted_evidence_path,
    trusted_evidence=trusted_evidence,
)
result_path.write_text(json.dumps(report), encoding="utf-8")
"""

_MIXED_PROCESS_PREPARE_SCRIPT = r"""
import json
import sys
import time
from pathlib import Path

from media_generation import candidate


mode = sys.argv[1]
declaration_path = Path(sys.argv[2])
if sys.platform == "darwin":
    import pytest
    from candidate_linux_fakes import inject_linux_inode_operations
    inject_linux_inode_operations(pytest.MonkeyPatch(), declaration_path.parent / ("linux-inodes-" + str(__import__("os").getpid())))
trusted_evidence_path = Path(sys.argv[3])
acquisition_config_path = Path(sys.argv[4])
journal_path = Path(sys.argv[5])
manifest_path = Path(sys.argv[6])
locked_path = Path(sys.argv[7])
attempt_path = Path(sys.argv[8])
release_path = Path(sys.argv[9])
result_path = Path(sys.argv[10])

acquisition = candidate._acquisition
real_load_journal = acquisition._load_journal


def no_remote_access(*args, **kwargs):
    raise AssertionError("ready artifacts contacted a remote test source")


def delayed_load_journal(target, *, declaration):
    if mode == "offline":
        locked_path.write_text("locked\n", encoding="utf-8")
        deadline = time.monotonic() + 10
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting to release offline prepare")
            time.sleep(0.005)
    return real_load_journal(target, declaration=declaration)


acquisition._load_journal = delayed_load_journal
acquisition._open_remote = no_remote_access
trusted_evidence = candidate.parse_trusted_evidence(trusted_evidence_path)
attempt_path.write_text("attempt\n", encoding="utf-8")
report = candidate.prepare_candidate(
    declaration_path,
    manifest_output=manifest_path,
    journal_output=journal_path,
    acquire=mode == "acquire",
    acquisition_config=(
        acquisition_config_path if mode == "acquire" else None
    ),
    trusted_evidence_path=trusted_evidence_path,
    trusted_evidence=trusted_evidence,
)
result_path.write_text(json.dumps(report), encoding="utf-8")
"""

PROVENANCE_SCHEMA = "media-generation.candidate-provenance-evidence"
LICENSE_SCHEMA = "media-generation.candidate-license-evidence"
CONVERSION_SCHEMA = "media-generation.candidate-conversion-evidence"
COMPATIBILITY_SCHEMA = "media-generation.candidate-compatibility-evidence"

SYNTHETIC_CONTENTS = {
    "engine.bin": b"synthetic-engine-build",
    "recipe.json": b'{"steps":1,"sampler":"test"}',
    "diffusion.safetensors": b"synthetic-diffusion-weights",
    "vae.safetensors": b"synthetic-vae-weights",
    "tokenizer.json": b'{"tokenizer":"test"}',
    "adapter.safetensors": b"synthetic-adapter-weights",
}

SYNTHETIC_ARTIFACT_PINS = {
    "engine.bin": (
        22,
        "a6401ef36a10391827c0cb84129425f4a215ab7f0004237f7619355b5d3bf9a2",
    ),
    "recipe.json": (
        28,
        "dfac838675ca0316092a37df827eb662759b83b4e0cad40a1625b8ba87a27311",
    ),
    "diffusion.safetensors": (
        27,
        "52f9a93d381ecdf090cbdf525999e1cfbbc2543f39d5622fe7b4c68cf916b61d",
    ),
    "vae.safetensors": (
        21,
        "11683e6bdda2e2f4708caa25d7ba10d06f6749f6bebd1bd4b7c26472cd88b812",
    ),
    "tokenizer.json": (
        20,
        "99ca0e0ec78f513969d4aec4e86402cc60d2f01442c17e8f14bbbb56f234062f",
    ),
    "adapter.safetensors": (
        25,
        "03a93a0ff3718f3b967582f034d1be09bd7aea806cc85a57b7c277cbf646cb2e",
    ),
}

SYNTHETIC_EVIDENCE_PINS = {
    "synthetic-engine-provenance.json": (
        347,
        "ca38a6e5029c3d014b41497e0532cacfe2ddc1b7e529ca6784031456d2a945b9",
    ),
    "synthetic-engine-license.json": (
        343,
        "14d03d8499f18548653050dd41ac13a6c9ec4cac4a2222e22a20d72de8a4678d",
    ),
    "diffusion-provenance.json": (
        355,
        "9b6fdd05ea023308b23dc545ce45c8d66abce90d5fae16c47ca67ac5df6f9b25",
    ),
    "diffusion-license.json": (
        348,
        "ae03294aaab3d02fc13cccb61f6d6664cabd7e50a7c9550f44ca8223c18fb7ba",
    ),
    "diffusion-conversion.json": (
        292,
        "f8912ee42c05b0a843e0583a091d919d9e7a3e97954726b9d5395111fb71d1e8",
    ),
    "vae-provenance.json": (
        331,
        "649d429f35c8955dc1f1f9e95d72e16eaf95e7c7e310c70491d939db42819762",
    ),
    "vae-license.json": (
        330,
        "07066f91f4bf204d948994ea083fffea140b657fb891435b1cc42cdd1630fb35",
    ),
    "vae-conversion.json": (
        274,
        "a71b5c7de0c4e422eaeb678abed14b05a6139a80b427f7a8a12e5fde123eb615",
    ),
    "tokenizer-provenance.json": (
        349,
        "0e381966782d188cafbc0d3b2a2f44e2b83cc122cbf3d3b2ad269e45666eee4e",
    ),
    "tokenizer-license.json": (
        342,
        "3df7f67f8329afefdaca261edfee979c437e9fc69afa7d9b1ec9d233c60cb617",
    ),
    "tokenizer-conversion.json": (
        286,
        "a51807a084a91b91a07c8caffe7129fc8a0499a783b71bf5e591e9ab9e785606",
    ),
    "style_adapter-provenance.json": (
        355,
        "aaf9037f2537c96d0a28fd15cbadb67ddd3ee46024db14243794a56d367daed8",
    ),
    "style_adapter-license.json": (
        344,
        "18fe7dc4198c29146fae51bf473f188125ffb882e8e6a329fae00dcb57fe32f0",
    ),
    "style_adapter-conversion.json": (
        288,
        "c9ceb5fb97e7125f257abde7093fbd229a75c7f6b95cb83b0a7916a52d1bf3b8",
    ),
    "compatibility.json": (
        2287,
        "ff0717a5225dcb00f6d208bf0bab6d1b1fc5b2b16af4eb9d061849fdb29c1917",
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pin(files: Path, name: str) -> dict[str, object]:
    size_bytes, sha256 = SYNTHETIC_ARTIFACT_PINS[name]
    return {
        "root": "files",
        "path": name,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def _write_json(
    files: Path,
    name: str,
    payload: object,
    *,
    literal_pin: dict[str, object] | None = None,
) -> dict[str, object]:
    data = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    (files / name).write_bytes(data)
    if literal_pin is not None:
        return literal_pin
    return {
        "root": "files",
        "path": name,
        "size_bytes": len(data),
        "sha256": _sha256(data),
    }


def _evidence_pin(name: str) -> dict[str, object]:
    size_bytes, sha256 = SYNTHETIC_EVIDENCE_PINS[name]
    return {
        "root": "files",
        "path": name,
        "size_bytes": size_bytes,
        "sha256": sha256,
    }


def _artifact_subject(
    kind: str,
    identifier: str,
    role: str,
    artifact: dict[str, object],
) -> dict[str, object]:
    return {
        "kind": kind,
        "id": identifier,
        "role": role,
        "size_bytes": artifact["size_bytes"],
        "sha256": artifact["sha256"],
    }


def _provenance(
    files: Path,
    revision: str,
    artifact: dict[str, object],
    *,
    kind: str,
    identifier: str,
    role: str,
) -> dict[str, object]:
    evidence_name = f"{identifier}-provenance.json"
    evidence = _write_json(
        files,
        evidence_name,
        {
            "schema": PROVENANCE_SCHEMA,
            "schema_version": 1,
            "publisher": "Synthetic publisher",
            "revision": revision,
            "source_url": "https://models.example/source",
            "subject": _artifact_subject(kind, identifier, role, artifact),
        },
        literal_pin=_evidence_pin(evidence_name),
    )
    return {
        "publisher": "Synthetic publisher",
        "revision": revision,
        "canonical_url": "https://models.example/source",
        "evidence": evidence,
    }


def _license(
    files: Path,
    artifact: dict[str, object],
    *,
    kind: str,
    identifier: str,
    role: str,
) -> dict[str, object]:
    evidence_name = f"{identifier}-license.json"
    evidence = _write_json(
        files,
        evidence_name,
        {
            "schema": LICENSE_SCHEMA,
            "schema_version": 1,
            "subject": _artifact_subject(kind, identifier, role, artifact),
            "license": {
                "name": "Synthetic terms",
                "spdx": "LicenseRef-Test",
                "terms_url": "https://licenses.example/terms",
            },
        },
        literal_pin=_evidence_pin(evidence_name),
    )
    return {
        "name": "Synthetic terms",
        "spdx": "LicenseRef-Test",
        "terms_url": "https://licenses.example/terms",
        "evidence": evidence,
    }


def _component(
    files: Path,
    identifier: str,
    role: str,
    filename: str,
) -> dict[str, object]:
    artifact = _pin(files, filename)
    evidence_name = f"{identifier}-conversion.json"
    conversion_evidence = _write_json(
        files,
        evidence_name,
        {
            "schema": CONVERSION_SCHEMA,
            "schema_version": 1,
            "subject": _artifact_subject("component", identifier, role, artifact),
            "conversion": {"lineage": "original", "tool": None},
        },
        literal_pin=_evidence_pin(evidence_name),
    )
    return {
        "id": identifier,
        "role": role,
        "artifact": artifact,
        "provenance": _provenance(
            files,
            f"{identifier}-revision",
            artifact,
            kind="component",
            identifier=identifier,
            role=role,
        ),
        "license": _license(
            files,
            artifact,
            kind="component",
            identifier=identifier,
            role=role,
        ),
        "precision": "bf16",
        "quantization": "none",
        "conversion": {
            "lineage": "original",
            "tool": None,
            "evidence": conversion_evidence,
        },
    }


def _compatibility_document(
    engine: dict[str, object],
    recipe: dict[str, object],
    components: list[dict[str, object]],
    adapters: list[dict[str, object]],
    claims: list[str],
) -> dict[str, object]:
    return {
        "schema": COMPATIBILITY_SCHEMA,
        "schema_version": 1,
        "claims": sorted(claims),
        "engine": {
            "id": engine["id"],
            "version": engine["version"],
            "build": engine["build"],
            "architecture_flags": dict(engine["architecture_flags"]),
            "executable": {
                "size_bytes": engine["executable"]["size_bytes"],  # type: ignore[index]
                "sha256": engine["executable"]["sha256"],  # type: ignore[index]
            },
        },
        "recipe": {
            "id": recipe["id"],
            "document": {
                "size_bytes": recipe["document"]["size_bytes"],  # type: ignore[index]
                "sha256": recipe["document"]["sha256"],  # type: ignore[index]
            },
            "pipeline_version": recipe["pipeline_version"],
            "template_version": recipe["template_version"],
        },
        "required_roles": [
            {
                "role": role,
                "components": sorted(
                    [
                        {
                            "id": component["id"],
                            "size_bytes": component["artifact"]["size_bytes"],  # type: ignore[index]
                            "sha256": component["artifact"]["sha256"],  # type: ignore[index]
                            "precision": component["precision"],
                            "quantization": component["quantization"],
                        }
                        for component in components
                        if component["role"] == role
                    ],
                    key=lambda item: str(item["id"]),
                ),
            }
            for role in recipe["required_component_roles"]  # type: ignore[union-attr]
        ],
        "components": sorted(
            [
                {
                    "id": component["id"],
                    "role": component["role"],
                    "size_bytes": component["artifact"]["size_bytes"],  # type: ignore[index]
                    "sha256": component["artifact"]["sha256"],  # type: ignore[index]
                    "precision": component["precision"],
                    "quantization": component["quantization"],
                }
                for component in components
            ],
            key=lambda item: str(item["id"]),
        ),
        "architecture_flags": recipe["architecture_flags"],
        "adapters": adapters,
    }


def _fixture(tmp_path: Path, *, with_inventory: bool = False) -> Path:
    files = tmp_path / "files"
    files.mkdir()
    for name, data in SYNTHETIC_CONTENTS.items():
        (files / name).write_bytes(data)
    (files / "engine.bin").chmod(0o755)

    roles = ("diffusion_model", "vae", "tokenizer", "adapter")
    claims = [
        "engine",
        "version",
        "recipe",
        *(f"role:{role}" for role in roles),
        "flag:qwen_image_zero_cond_t",
    ]
    engine_artifact = _pin(files, "engine.bin")
    recipe_artifact = _pin(files, "recipe.json")
    engine: dict[str, Any] = {
        "id": "synthetic-engine",
        "version": "1.2.3",
        "build": "build-42",
        "executable": engine_artifact,
        "provenance": _provenance(
            files,
            "engine-revision",
            engine_artifact,
            kind="engine",
            identifier="synthetic-engine",
            role="engine",
        ),
        "license": _license(
            files,
            engine_artifact,
            kind="engine",
            identifier="synthetic-engine",
            role="engine",
        ),
        "architecture_flags": {
            "qwen_image_zero_cond_t": True,
            "backend": "cpu-static",
        },
    }
    components = [
        _component(files, "diffusion", "diffusion_model", "diffusion.safetensors"),
        _component(files, "vae", "vae", "vae.safetensors"),
        _component(files, "tokenizer", "tokenizer", "tokenizer.json"),
        _component(files, "style_adapter", "adapter", "adapter.safetensors"),
    ]
    adapters: list[dict[str, Any]] = [
        {"component_id": "style_adapter", "order": 1, "strength": 0.75}
    ]
    recipe: dict[str, Any] = {
        "id": "synthetic-recipe",
        "document": recipe_artifact,
        "required_component_roles": list(roles),
        "engine_id": "synthetic-engine",
        "engine_version": "1.2.3",
        "pipeline_version": "synthetic-pipeline@1.0",
        "template_version": "synthetic-template@1.0",
        "architecture_flags": {
            "qwen_image_zero_cond_t": True
        },
    }
    recipe["compatibility_evidence"] = [
        {
            "claims": claims,
            "document": _write_json(
                files,
                "compatibility.json",
                _compatibility_document(
                    engine,
                    recipe,
                    components,
                    adapters,
                    claims,
                ),
            literal_pin=_evidence_pin("compatibility.json"),
            ),
        }
    ]
    declaration: dict[str, Any] = {
        "schema": "media-generation.candidate-declaration",
        "schema_version": 1,
        "id": "synthetic-candidate",
        "roots": [{"id": "files", "path": "files"}],
        "engine": engine,
        "recipe": recipe,
        "components": components,
        "adapters": adapters,
        "acquisition": {
            "sources": [
                {
                    "artifact": "component:diffusion",
                    "url": "https://downloads.example/diffusion.safetensors",
                }
            ]
        },
    }
    if with_inventory:
        host: dict[str, object] = {}
        runtimes: list[object] = []
        inventory_document = {
            "schema": "media-generation.inventory",
            "schema_version": 1,
            "run": {"mode": "replay"},
            "model_inventory": {},
            "host": host,
            "environment_fingerprint": build_environment_fingerprint(host, runtimes),
            "runtimes": runtimes,
            "bundles": [
                {
                    "id": "synthetic-bundle",
                    "engine": "synthetic-engine",
                    "recipe": {
                        "id": "synthetic-recipe",
                        "status": "observed",
                        "digest": f"sha256:{recipe_artifact['sha256']}",
                        "digest_source": "file",
                    },
                    "components": [
                        {
                            "id": f"synthetic-bundle/{item['id']}",
                            "role": item["role"],
                            "path": str(
                                (files / str(item["artifact"]["path"])).resolve()
                            ),
                            "kind": "file",
                            "size_bytes": item["artifact"]["size_bytes"],
                            "status": "observed",
                            "digest": {
                                "status": "computed",
                                "algorithm": "sha256",
                                "value": f"sha256:{item['artifact']['sha256']}",
                            },
                        }
                        for item in components
                    ],
                }
            ],
            "probes": [],
            "findings": [],
            "evidence_gate": {
                "evidence_origin": "synthetic_replay",
                "apex_verification": "unverified",
            },
        }
        declaration["inventory_evidence"] = {
            "document": _write_json(files, "inventory.json", inventory_document),
            "bundle_id": "synthetic-bundle",
        }
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(declaration), encoding="utf-8")
    return path


def _payload(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _track_journal_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    journal: Path,
) -> tuple[list[int], list[int]]:
    acquisition = candidate._acquisition
    journal_descriptors: list[int] = []
    target_parent_descriptors: list[int] = []
    real_open = acquisition.os.open
    real_open_target = acquisition._open_output_target

    def capture_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and os.fsdecode(path) == journal.name:
            journal_descriptors.append(descriptor)
        return descriptor

    def capture_target(*args: Any, **kwargs: Any) -> Any:
        target = real_open_target(*args, **kwargs)
        target_parent_descriptors.append(target.parent_fd)
        return target

    monkeypatch.setattr(acquisition.os, "open", capture_open)
    monkeypatch.setattr(acquisition, "_open_output_target", capture_target)
    return journal_descriptors, target_parent_descriptors


def _assert_descriptor_closed(descriptor: int) -> None:
    with pytest.raises(OSError) as failure:
        os.fstat(descriptor)
    assert failure.value.errno == errno.EBADF


def _rewrite(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _set_component_role(
    payload: dict[str, Any],
    component_id: str,
    role: str,
) -> None:
    component = next(
        item for item in payload["components"] if item["id"] == component_id
    )
    previous_role = component["role"]
    component["role"] = role
    recipe = payload["recipe"]
    recipe["required_component_roles"] = [
        role if existing == previous_role else existing
        for existing in recipe["required_component_roles"]
    ]
    compatibility = recipe["compatibility_evidence"][0]
    compatibility["claims"] = [
        f"role:{role}" if claim == f"role:{previous_role}" else claim
        for claim in compatibility["claims"]
    ]


def _items(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        str(item["artifact"]): item
        for item in report["items"]  # type: ignore[index]
    }


class _Response:
    def __init__(
        self,
        status: int,
        *,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        read_error: BaseException | None = None,
    ) -> None:
        self.status = status
        self.code = status
        self.headers = headers or {}
        self._body = body
        self._offset = 0
        self._read_error = read_error
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        if self._offset >= len(self._body):
            return b""
        end = (
            len(self._body)
            if size < 0
            else min(len(self._body), self._offset + size)
        )
        chunk = self._body[self._offset : end]
        self._offset = end
        return chunk

    def close(self) -> None:
        self.closed = True


def _acquisition_config(
    tmp_path: Path,
    *,
    max_attempts: int = 1,
    max_total_bytes: int = 100_000,
    timeout_seconds: object = 1,
    allowed_origins: list[str] | None = None,
    credentials: list[dict[str, object]] | None = None,
    filename: str = "acquisition.json",
) -> Path:
    path = tmp_path / filename
    path.write_text(
        json.dumps(
            {
                "schema": "media-generation.candidate-acquisition-config",
                "schema_version": 1,
                "authorized": True,
                "allowed_origins": allowed_origins or ["https://downloads.example"],
                "credentials": credentials or [],
                "timeout_seconds": timeout_seconds,
                "max_redirects": 2,
                "max_attempts": max_attempts,
                "max_total_bytes": max_total_bytes,
            }
        ),
        encoding="utf-8",
    )
    return path


def _tree_snapshot(path: Path) -> dict[str, tuple[bytes, int]]:
    return {
        str(item.relative_to(path)): (item.read_bytes(), item.stat().st_mtime_ns)
        for item in sorted(path.rglob("*"))
        if item.is_file() and not item.is_symlink()
    }


def _trusted_evidence() -> tuple[candidate.TrustedEvidence, ...]:
    """Return literal synthetic authority records, independent of observed files."""

    engine_artifact = _pin(ROOT, "engine.bin")
    recipe_artifact = _pin(ROOT, "recipe.json")
    roles = ("diffusion_model", "vae", "tokenizer", "adapter")
    claims = [
        "engine",
        "version",
        "recipe",
        *(f"role:{role}" for role in roles),
        "flag:qwen_image_zero_cond_t",
    ]
    engine: dict[str, Any] = {
        "id": "synthetic-engine",
        "version": "1.2.3",
        "build": "build-42",
        "executable": engine_artifact,
        "architecture_flags": {
            "qwen_image_zero_cond_t": True,
            "backend": "cpu-static",
        },
    }
    components = [
        {
            "id": "diffusion",
            "role": "diffusion_model",
            "artifact": _pin(ROOT, "diffusion.safetensors"),
            "precision": "bf16",
            "quantization": "none",
        },
        {
            "id": "vae",
            "role": "vae",
            "artifact": _pin(ROOT, "vae.safetensors"),
            "precision": "bf16",
            "quantization": "none",
        },
        {
            "id": "tokenizer",
            "role": "tokenizer",
            "artifact": _pin(ROOT, "tokenizer.json"),
            "precision": "bf16",
            "quantization": "none",
        },
        {
            "id": "style_adapter",
            "role": "adapter",
            "artifact": _pin(ROOT, "adapter.safetensors"),
            "precision": "bf16",
            "quantization": "none",
        },
    ]
    recipe: dict[str, Any] = {
        "id": "synthetic-recipe",
        "document": recipe_artifact,
        "required_component_roles": list(roles),
        "engine_id": "synthetic-engine",
        "engine_version": "1.2.3",
        "pipeline_version": "synthetic-pipeline@1.0",
        "template_version": "synthetic-template@1.0",
        "architecture_flags": {
            "qwen_image_zero_cond_t": True
        },
    }
    adapters = [
        {"component_id": "style_adapter", "order": 1, "strength": 0.75}
    ]
    records: list[candidate.TrustedEvidence] = []

    def add(name: str, expected: dict[str, object]) -> None:
        size_bytes, sha256 = SYNTHETIC_EVIDENCE_PINS[name]
        records.append(
            candidate.TrustedEvidence(
                authority_id=f"synthetic-authority-{len(records) + 1}",
                document_size_bytes=size_bytes,
                document_sha256=sha256,
                expected=expected,
            )
        )

    for kind, identifier, role, artifact, revision in (
        ("engine", "synthetic-engine", "engine", engine_artifact, "engine-revision"),
        (
            "component",
            "diffusion",
            "diffusion_model",
            components[0]["artifact"],
            "diffusion-revision",
        ),
        (
            "component",
            "vae",
            "vae",
            components[1]["artifact"],
            "vae-revision",
        ),
        (
            "component",
            "tokenizer",
            "tokenizer",
            components[2]["artifact"],
            "tokenizer-revision",
        ),
        (
            "component",
            "style_adapter",
            "adapter",
            components[3]["artifact"],
            "style_adapter-revision",
        ),
    ):
        subject = _artifact_subject(kind, identifier, role, artifact)
        add(
            f"{identifier}-provenance.json",
            {
                "schema": PROVENANCE_SCHEMA,
                "schema_version": 1,
                "publisher": "Synthetic publisher",
                "revision": revision,
                "source_url": "https://models.example/source",
                "subject": subject,
            },
        )
        add(
            f"{identifier}-license.json",
            {
                "schema": LICENSE_SCHEMA,
                "schema_version": 1,
                "subject": subject,
                "license": {
                    "name": "Synthetic terms",
                    "spdx": "LicenseRef-Test",
                    "terms_url": "https://licenses.example/terms",
                },
            },
        )
        if kind == "component":
            add(
                f"{identifier}-conversion.json",
                {
                    "schema": CONVERSION_SCHEMA,
                    "schema_version": 1,
                    "subject": subject,
                    "conversion": {"lineage": "original", "tool": None},
                },
            )
    add(
        "compatibility.json",
        _compatibility_document(
            engine,
            recipe,
            components,
            adapters,
            claims,
        ),
    )
    return tuple(records)


def _trust_compatibility_for_fixture(
    tmp_path: Path,
    payload: dict[str, Any],
    *,
    records: tuple[candidate.TrustedEvidence, ...] | None = None,
) -> tuple[candidate.TrustedEvidence, ...]:
    """Create separate synthetic authority for the fixture's compatibility file."""
    evidence = payload["recipe"]["compatibility_evidence"][0]
    claims = evidence["claims"]
    document = _compatibility_document(
        payload["engine"],
        payload["recipe"],
        payload["components"],
        payload["adapters"],
        claims,
    )
    pin = _write_json(tmp_path / "files", "compatibility.json", document)
    evidence["document"] = pin
    content = (tmp_path / "files" / "compatibility.json").read_bytes()
    selected_records = list(_trusted_evidence() if records is None else records)
    for index, record in enumerate(selected_records):
        if record.expected.get("schema") == COMPATIBILITY_SCHEMA:
            selected_records[index] = replace(
                record,
                document_size_bytes=len(content),
                document_sha256=_sha256(content),
                expected=document,
            )
    return tuple(selected_records)


def _mixed_adapter_lora_fixture(
    tmp_path: Path,
) -> tuple[Path, tuple[candidate.TrustedEvidence, ...]]:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    lora = next(
        component
        for component in payload["components"]
        if component["id"] == "vae"
    )
    lora["role"] = "lora"
    recipe = payload["recipe"]
    recipe["required_component_roles"] = [
        "lora" if role == "vae" else role
        for role in recipe["required_component_roles"]
    ]
    compatibility = recipe["compatibility_evidence"][0]
    compatibility["claims"] = [
        "role:lora" if claim == "role:vae" else claim
        for claim in compatibility["claims"]
    ]
    payload["adapters"].append(
        {"component_id": "vae", "order": 2, "strength": 0.4}
    )

    trusted_records = list(_trusted_evidence())
    for field in ("provenance", "license", "conversion"):
        evidence_owner = lora[field]
        evidence = evidence_owner["evidence"]
        evidence_path = tmp_path / "files" / evidence["path"]
        document = _payload(evidence_path)
        document["subject"]["role"] = "lora"
        pin = _write_json(evidence_path.parent, evidence_path.name, document)
        evidence_owner["evidence"] = pin
        for index, record in enumerate(trusted_records):
            subject = record.expected.get("subject")
            if (
                record.expected.get("schema") == document["schema"]
                and isinstance(subject, dict)
                and subject.get("id") == "vae"
            ):
                expected = dict(record.expected)
                updated_subject = dict(subject)
                updated_subject["role"] = "lora"
                expected["subject"] = updated_subject
                trusted_records[index] = replace(
                    record,
                    document_size_bytes=pin["size_bytes"],
                    document_sha256=pin["sha256"],
                    expected=expected,
                )

    trusted = _trust_compatibility_for_fixture(
        tmp_path,
        payload,
        records=tuple(trusted_records),
    )
    _rewrite(declaration, payload)
    return declaration, trusted


def _write_trusted_evidence(
    tmp_path: Path,
    records: tuple[candidate.TrustedEvidence, ...] | None = None,
) -> Path:
    """Write separate host-owned authority records for an explicit test."""
    path = tmp_path / "trusted-evidence.json"
    selected = _trusted_evidence() if records is None else records
    path.write_text(
        json.dumps(
            {
                "schema": "media-generation.candidate-trusted-evidence",
                "schema_version": 1,
                "records": [
                    {
                        "authority_id": record.authority_id,
                        "document_size_bytes": record.document_size_bytes,
                        "document_sha256": record.document_sha256,
                        "expected": record.expected,
                    }
                    for record in selected
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_ready_requires_exact_complete_files_and_reports_static_boundary(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path, with_inventory=True)
    inspection = candidate.inspect_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    verification = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    items = _items(inspection)

    assert inspection["status"] == "ready"
    assert verification["status"] == "ready"
    assert inspection["candidate_id"] == verification["candidate_id"]
    assert inspection["verification_id"] == verification["verification_id"]
    assert str(inspection["candidate_id"]).startswith("sha256:")
    assert items["engine.executable"]["status"] == "ready"
    assert items["engine.provenance.evidence"]["status"] == "ready"
    assert items["component:diffusion"]["status"] == "ready"
    assert items["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_match"
    )
    assert items["inventory.evidence.correlation"]["status"] == "ready"
    assert inspection["evidence"] == {
        "static_preparation": "ready",
        "independent_evidence_authority": "ready",
        "apex_execution": "unverified",
        "apex_execution_reason": "model_loading_and_inference_not_performed",
        "t08_execution": "required",
        "t19_qualification": "unverified",
    }


@pytest.mark.parametrize(
    ("outcome", "expected_status", "expected_code"),
    (
        ("ready", "ready", "evidence_contract_match"),
        ("invalid_json", "unverified", "evidence_contract_invalid"),
        ("contract_mismatch", "unverified", "evidence_contract_mismatch"),
        ("pin_mismatch", "corrupt", "sha256_mismatch"),
        ("authority_unavailable", "unverified", "evidence_authority_unavailable"),
    ),
)
def test_evidence_checks_do_not_retain_complete_document_bytes(
    tmp_path: Path,
    outcome: str,
    expected_status: str,
    expected_code: str,
) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    documents = []
    authorities = []
    for index in range(3):
        expected = {"index": index}
        value = {"index": index + 1} if outcome == "contract_mismatch" else expected
        tail = json.dumps(value).encode("utf-8")
        if outcome == "invalid_json":
            tail += b"["
        data = b" " * (4 * 1024 * 1024 - len(tail)) + tail
        name = f"bounded-evidence-{index}.json"
        pin = replace(
            declaration.engine.provenance.evidence,
            path=name,
            size_bytes=len(data),
            sha256=_sha256(data),
        )
        path = tmp_path / "files" / name
        path.write_bytes(data if outcome != "pin_mismatch" else data[:-1] + b"]")
        documents.append((pin, expected))
        if outcome != "authority_unavailable":
            authorities.append(
                candidate.TrustedEvidence(
                    authority_id=f"bounded-authority-{index}",
                    document_size_bytes=pin.size_bytes,
                    document_sha256=pin.sha256,
                    expected=expected,
                )
            )
    evaluator = _Evaluator(declaration, trusted_evidence=authorities)

    retained_bytes = []
    for index, (pin, expected) in enumerate(documents):
        matched = evaluator._check_contract_document(
            f"evidence[{index}]", pin, expected=expected, label="bounded evidence"
        )
        assert matched is (outcome == "ready")
        assert evaluator.items[-1].status == expected_status
        assert evaluator.items[-1].code == expected_code
        # Include both owners: clearing only the lookup cache leaves the
        # returned evaluation's observations retaining every full document.
        contents = {
            id(observation.content): len(observation.content)
            for observation in (
                *evaluator._cache.values(), *evaluator.observations.values()
            )
            if observation.content is not None
        }
        retained_bytes.append(sum(contents.values()))

    assert retained_bytes == [0, 0, 0]


def test_repeated_evidence_capture_rechecks_complete_pinned_bytes(tmp_path: Path) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    pin = declaration.engine.provenance.evidence
    authorities = _trusted_evidence()
    expected = next(
        record.expected
        for record in authorities
        if record.document_sha256 == pin.sha256
    )
    evaluator = _Evaluator(declaration, trusted_evidence=authorities)
    for index in range(2):
        assert evaluator._check_contract_document(
            f"evidence[{index}]", pin, expected=expected, label="provenance evidence"
        )
    path = tmp_path / "files" / pin.path
    data = path.read_bytes()
    path.write_bytes(data.replace(b"Synthetic publisher", b"Untrusted publisher"))
    assert path.stat().st_size == pin.size_bytes

    assert not evaluator._check_contract_document(
        "changed_evidence", pin, expected=expected, label="provenance evidence"
    )
    assert evaluator.items[-1].status == "corrupt"
    assert evaluator.items[-1].code == "sha256_mismatch"


def test_prepare_materializes_trusted_evidence_for_all_evaluations(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    evidence = _trusted_evidence()

    def once_only() -> Any:
        yield from evidence

    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        trusted_evidence=once_only(),
    )

    assert report["status"] == "ready"


def test_ready_requires_independent_trusted_evidence(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)

    report = candidate.verify_candidate(declaration)

    assert report["status"] == "unverified"
    assert _items(report)["engine.provenance.evidence"]["code"] == (
        "evidence_authority_unavailable"
    )


def test_trusted_evidence_file_is_strict_and_separate(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    authority = _write_trusted_evidence(tmp_path)

    records = candidate.parse_trusted_evidence(authority)

    assert len(records) == len(_trusted_evidence())
    assert all(isinstance(record, candidate.TrustedEvidence) for record in records)
    with pytest.raises(candidate.CandidateValidationError, match="trusted evidence"):
        candidate.parse_trusted_evidence(declaration)

    document = json.loads(authority.read_text(encoding="utf-8"))
    document["records"].append(document["records"][0])
    authority.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(candidate.CandidateValidationError, match="must be unique"):
        candidate.parse_trusted_evidence(authority)


def test_evidence_pin_mismatch_cannot_be_discarded_by_authority_match(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    compatibility = tmp_path / "files" / "compatibility.json"
    compatibility.write_bytes(compatibility.read_bytes() + b" ")

    report = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )

    assert report["status"] == "corrupt"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "size_mismatch"
    )
    assert report["evidence"]["independent_evidence_authority"] == (  # type: ignore[index]
        "unverified"
    )


def test_missing_component_is_missing_and_never_ready(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    (tmp_path / "files" / "vae.safetensors").unlink()
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "missing"
    assert _items(report)["component:vae"]["code"] == "file_missing"


def test_observations_do_not_change_stable_candidate_identity(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    before = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original = artifact.read_bytes()
    artifact.write_bytes(original[:-1] + b"X")
    after = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )

    assert after["status"] == "corrupt"
    assert after["candidate_id"] == before["candidate_id"]
    assert after["verification_id"] != before["verification_id"]
    assert _items(after)["component:diffusion"]["code"] == "sha256_mismatch"


def test_material_declared_change_changes_candidate_identity(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    before = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    payload = _payload(declaration)
    payload["id"] = "synthetic-candidate-v2"
    _rewrite(declaration, payload)
    after = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    assert after["status"] == "ready"
    assert after["candidate_id"] != before["candidate_id"]


@pytest.mark.parametrize("flag_change", ("backend", "added", "removed", "version"))
def test_engine_flags_require_refreshed_independent_compatibility_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag_change: str,
) -> None:
    declaration = _fixture(tmp_path)
    trusted = _trusted_evidence()

    def reject_network(*args, **kwargs):
        raise AssertionError("offline verification attempted network access")

    monkeypatch.setattr(candidate._acquisition, "_open_remote", reject_network)
    original = candidate.verify_candidate(declaration, trusted_evidence=trusted)
    assert original["status"] == "ready"
    payload = _payload(declaration)
    engine_flags = payload["engine"]["architecture_flags"]
    if flag_change == "backend":
        engine_flags["backend"] = "unverified-backend"
    elif flag_change == "added":
        engine_flags["model_variant"] = "unverified-architecture"
    elif flag_change == "removed":
        del engine_flags["backend"]
    else:
        engine_flags["qwen_image_zero_cond_t"] = False
    _rewrite(declaration, payload)
    before = _tree_snapshot(tmp_path / "files")
    stale = candidate.verify_candidate(declaration, trusted_evidence=trusted)
    assert stale["candidate_id"] != original["candidate_id"]
    assert _items(stale)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )
    assert stale["status"] != "ready"
    assert _tree_snapshot(tmp_path / "files") == before

    if flag_change == "version":
        payload["recipe"]["architecture_flags"]["qwen_image_zero_cond_t"] = False
    # A locally rewritten document and digest do not refresh external authority.
    refreshed_trusted = _trust_compatibility_for_fixture(
        tmp_path, payload, records=trusted
    )
    _rewrite(declaration, payload)
    self_pinned = candidate.verify_candidate(declaration, trusted_evidence=trusted)
    assert self_pinned["status"] != "ready"
    before = _tree_snapshot(tmp_path / "files")
    refreshed = candidate.verify_candidate(
        declaration, trusted_evidence=refreshed_trusted
    )
    assert refreshed["status"] == "ready"
    assert _tree_snapshot(tmp_path / "files") == before


def test_engine_executable_requires_execute_permission(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    (tmp_path / "files" / "engine.bin").chmod(0o644)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "corrupt"
    assert _items(report)["engine.executable"]["code"] == "executable_bit_missing"


def test_incomplete_required_role_is_incompatible(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"] = [
        component
        for component in payload["components"]
        if component["role"] != "tokenizer"
    ]
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "incompatible"
    assert _items(report)["recipe.role:tokenizer"]["code"] == (
        "required_role_missing"
    )


def test_version_specific_architecture_switch_must_match(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["engine"]["architecture_flags"][
        "qwen_image_zero_cond_t"
    ] = False
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "incompatible"
    item = _items(report)[
        "recipe.compatibility.flag:qwen_image_zero_cond_t"
    ]
    assert item["code"] == "architecture_flag_mismatch"


def test_recipe_architecture_flags_can_be_explicitly_empty(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    flag = "qwen_image_zero_cond_t"
    payload["recipe"]["architecture_flags"] = {}
    payload["recipe"]["compatibility_evidence"][0]["claims"].remove(f"flag:{flag}")
    _rewrite(declaration, payload)

    parsed = candidate.parse_candidate(declaration)
    assert parsed.recipe.architecture_flags == ()

    del payload["recipe"]["architecture_flags"]
    _rewrite(declaration, payload)
    with pytest.raises(candidate.CandidateValidationError):
        candidate.parse_candidate(declaration)


def test_qwen_2511_policy_requires_exact_pinned_compatibility(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["engine"]["id"] = "qwen-image-edit-2511"
    payload["recipe"]["engine_id"] = "qwen-image-edit-2511"
    payload["recipe"]["pipeline_version"] = "qwen-image-edit-2511@1.0"
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)
    items = _items(report)

    assert report["status"] == "unverified"
    assert items["recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"][
        "code"
    ] == "qwen_2511_zero_conditioning_enabled"
    assert items["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )


def test_qwen_2511_native_flag_with_trusted_evidence_is_ready(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["engine"]["build"] = "qwen-image-edit-2511"
    trusted_evidence = _trust_compatibility_for_fixture(tmp_path, payload)
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(
        declaration,
        trusted_evidence=trusted_evidence,
    )

    assert report["status"] == "ready"
    assert _items(report)[
        "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
    ]["code"] == "qwen_2511_zero_conditioning_enabled"
    assert _items(report)["recipe.compatibility.evidence[0]"]["status"] == "ready"


def test_qwen_2511_native_false_is_not_rescued_by_fabricated_flag(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    fabricated_flag = "qwen_image_edit_2511_zero_conditioning"
    payload["engine"]["build"] = "qwen-image-edit-2511"
    payload["engine"]["architecture_flags"]["qwen_image_zero_cond_t"] = False
    payload["recipe"]["architecture_flags"]["qwen_image_zero_cond_t"] = False
    payload["engine"]["architecture_flags"][fabricated_flag] = True
    payload["recipe"]["architecture_flags"][fabricated_flag] = True
    payload["recipe"]["compatibility_evidence"][0]["claims"].append(
        f"flag:{fabricated_flag}"
    )
    trusted_evidence = _trust_compatibility_for_fixture(tmp_path, payload)
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(
        declaration,
        trusted_evidence=trusted_evidence,
    )

    items = _items(report)
    assert report["status"] == "incompatible"
    assert items[
        "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
    ]["code"] == "qwen_2511_zero_conditioning_required"
    assert items["recipe.compatibility.flag:qwen_image_zero_cond_t"]["status"] == (
        "ready"
    )
    assert items[
        "recipe.compatibility.flag:qwen_image_edit_2511_zero_conditioning"
    ]["status"] == "ready"
    assert items["recipe.compatibility.evidence[0]"]["status"] == "ready"


def test_qwen_2511_split_identity_requires_zero_conditioning(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    policy_artifact = (
        "recipe.compatibility.policy:"
        "qwen-image-edit-2511-zero-conditioning"
    )
    flag = "qwen_image_zero_cond_t"

    payload["engine"]["id"] = "qwen-image-edit"
    payload["engine"]["version"] = "2511"
    payload["recipe"]["engine_id"] = "qwen-image-edit"
    payload["recipe"]["engine_version"] = "2511"
    payload["recipe"]["pipeline_version"] = "qwen-image-edit"
    payload["recipe"]["template_version"] = "2511"
    payload["engine"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"]["backend"] = "cpu-static"
    claims = payload["recipe"]["compatibility_evidence"][0]["claims"]
    claims.remove(f"flag:{flag}")
    claims.append("flag:backend")
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)
    item = _items(report)[policy_artifact]
    assert report["status"] == "incompatible"
    assert item["status"] == "incompatible"
    assert item["code"] == "qwen_2511_zero_conditioning_required"

    payload["engine"]["architecture_flags"][flag] = True
    payload["recipe"]["architecture_flags"][flag] = True
    claims.append(f"flag:{flag}")
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)
    item = _items(report)[policy_artifact]
    assert item["status"] == "ready"
    assert item["code"] == "qwen_2511_zero_conditioning_enabled"


@pytest.mark.parametrize("identity_scope", ("component-id", "provenance"))
def test_qwen_2511_component_identity_requires_zero_conditioning(
    tmp_path: Path,
    identity_scope: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    flag = "qwen_image_zero_cond_t"
    payload["engine"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"]["backend"] = "cpu-static"
    claims = payload["recipe"]["compatibility_evidence"][0]["claims"]
    claims.remove(f"flag:{flag}")
    claims.append("flag:backend")
    if identity_scope == "component-id":
        payload["components"][0]["id"] = "qwen-image-edit-2511-vae"
        payload["acquisition"]["sources"][0]["artifact"] = (
            "component:qwen-image-edit-2511-vae"
        )
    else:
        payload["components"][0]["provenance"]["publisher"] = "qwen-image-edit"
        payload["components"][0]["provenance"]["revision"] = "2511"
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)
    item = _items(report)[
        "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
    ]
    assert report["status"] == "incompatible"
    assert item["status"] == "incompatible"
    assert item["code"] == "qwen_2511_zero_conditioning_required"


def test_qwen_2511_engine_provenance_requires_zero_conditioning(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    flag = "qwen_image_zero_cond_t"
    payload["engine"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"]["backend"] = "cpu-static"
    claims = payload["recipe"]["compatibility_evidence"][0]["claims"]
    claims.remove(f"flag:{flag}")
    claims.append("flag:backend")
    payload["engine"]["provenance"]["publisher"] = "qwen-image-edit"
    payload["engine"]["provenance"]["revision"] = "2511"
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)

    assert _items(report)[
        "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
    ]["code"] == "qwen_2511_zero_conditioning_required"


def test_qwen_2511_artifact_pin_paths_do_not_trigger_policy(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    flag = "qwen_image_zero_cond_t"
    payload["engine"]["executable"]["path"] = "qwen-image-edit-2511-engine.bin"
    payload["recipe"]["document"]["path"] = "qwen-image-edit-2511-recipe.json"
    payload["components"][0]["artifact"]["path"] = (
        "qwen-image-edit-2511-diffusion.safetensors"
    )
    payload["engine"]["provenance"]["evidence"]["path"] = (
        "qwen-image-edit-2511-engine-provenance.json"
    )
    payload["components"][0]["provenance"]["evidence"]["path"] = (
        "qwen-image-edit-2511-component-provenance.json"
    )
    payload["engine"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"].pop(flag)
    payload["recipe"]["architecture_flags"]["backend"] = "cpu-static"
    claims = payload["recipe"]["compatibility_evidence"][0]["claims"]
    claims.remove(f"flag:{flag}")
    claims.append("flag:backend")
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)

    assert (
        "recipe.compatibility.policy:qwen-image-edit-2511-zero-conditioning"
        not in _items(report)
    )


def test_arbitrary_compatibility_bytes_never_become_ready(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    path = tmp_path / "files" / "compatibility.json"
    path.write_bytes(b"operator assertion")
    evidence_pin = payload["recipe"]["compatibility_evidence"][0]["document"]
    evidence_pin["size_bytes"] = path.stat().st_size
    evidence_pin["sha256"] = _sha256(path.read_bytes())
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_invalid"
    )


def test_compatibility_contract_must_bind_exact_component_bytes(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    path = tmp_path / "files" / "compatibility.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["components"][0]["sha256"] = "0" * 64
    new_pin = _write_json(tmp_path / "files", "compatibility.json", document)
    payload["recipe"]["compatibility_evidence"][0]["document"] = new_pin
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )


def test_unsupported_license_identifier_is_rejected(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"][0]["license"]["spdx"] = "DEFINITELY-NOT-SPDX"
    _rewrite(declaration, payload)
    with pytest.raises(candidate.CandidateValidationError, match="SPDX identifier"):
        candidate.parse_candidate(declaration)


def test_pinned_license_evidence_must_agree_with_declaration(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    path = tmp_path / "files" / "diffusion-license.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["license"]["spdx"] = "MIT"
    new_pin = _write_json(tmp_path / "files", path.name, document)
    payload["components"][0]["license"]["evidence"] = new_pin
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "unverified"
    assert _items(report)["component:diffusion.license.evidence"]["code"] == (
        "evidence_contract_mismatch"
    )


def test_pinned_provenance_evidence_must_bind_artifact_and_publisher(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    path = tmp_path / "files" / "diffusion-provenance.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["publisher"] = "Different publisher"
    new_pin = _write_json(tmp_path / "files", path.name, document)
    payload["components"][0]["provenance"]["evidence"] = new_pin
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "unverified"
    assert _items(report)["component:diffusion.provenance.evidence"]["code"] == (
        "evidence_contract_mismatch"
    )


def test_incomplete_compatibility_coverage_is_unverified(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["recipe"]["compatibility_evidence"][0]["claims"].remove("role:vae")
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence"]["code"] == (
        "compatibility_evidence_incomplete"
    )


def test_strict_declaration_rejects_unknown_and_duplicate_fields(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    original = declaration.read_text(encoding="utf-8")
    declaration.write_text(
        original[:-1] + ', "unexpected": true}', encoding="utf-8"
    )
    with pytest.raises(candidate.CandidateValidationError, match="unsupported fields"):
        candidate.parse_candidate(declaration)
    declaration.write_text(
        original.replace(
            '"id": "synthetic-candidate",',
            '"id": "synthetic-candidate", "id": "duplicate",',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(candidate.CandidateValidationError, match="duplicate key"):
        candidate.parse_candidate(declaration)


@pytest.mark.parametrize(
    "invalid_version",
    [True, 1.0],
    ids=["boolean", "float"],
)
def test_schema_versions_require_exact_json_integer(
    tmp_path: Path,
    invalid_version: object,
) -> None:
    declaration = _fixture(tmp_path)
    declaration_document = candidate.parse_candidate(declaration)
    declaration_payload = _payload(declaration)
    declaration_payload["schema_version"] = invalid_version
    _rewrite(declaration, declaration_payload)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="schema_version must be 1",
    ):
        candidate.parse_candidate(declaration)

    trusted_path = _write_trusted_evidence(tmp_path)
    trusted_payload = json.loads(trusted_path.read_text(encoding="utf-8"))
    trusted_payload["schema_version"] = invalid_version
    _rewrite(trusted_path, trusted_payload)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="trusted evidence schema_version must be 1",
    ):
        candidate.parse_trusted_evidence(trusted_path)

    acquisition_path = _acquisition_config(tmp_path, filename="schema-acquisition.json")
    acquisition_payload = json.loads(acquisition_path.read_text(encoding="utf-8"))
    acquisition_payload["schema_version"] = invalid_version
    _rewrite(acquisition_path, acquisition_payload)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="acquisition config schema_version must be 1",
    ):
        candidate.parse_acquisition_config(acquisition_path)

    journal = candidate._acquisition._journal_initial(declaration_document)
    journal["schema_version"] = invalid_version
    journal_path = tmp_path / "journal.json"
    candidate._acquisition._write_json_atomic(
        journal_path, journal, label="acquisition journal"
    )
    with pytest.raises(
        candidate.CandidateOutputError,
        match="acquisition journal schema_version is unsupported",
    ):
        candidate._acquisition._load_journal(
            journal_path, declaration=declaration_document
        )


def test_strict_json_loader_limits_container_nesting() -> None:
    at_limit = b"[" * 128 + b"0" + b"]" * 128
    assert isinstance(
        candidate._contract._load_strict_bytes(at_limit, label="synthetic document"),
        list,
    )

    pathological = b"[" * 100_000 + b"0" + b"]" * 100_000
    with pytest.raises(
        candidate.CandidateValidationError,
        match="synthetic document exceeds maximum JSON nesting depth 128",
    ):
        candidate._contract._load_strict_bytes(
            pathological,
            label="synthetic document",
        )


def test_strict_json_loader_ignores_brackets_inside_escaped_strings() -> None:
    literal = '\\"' + ("{}[]" * 256) + '\\"'
    document = {
        "literal": literal,
        "trailing-backslash": "\\\\",
    }
    encoded = json.dumps(document).encode("utf-8")

    assert candidate._contract._load_strict_bytes(
        encoded,
        label="synthetic document",
    ) == document


def test_control_file_change_during_read_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    original_fdopen = candidate._contract.os.fdopen
    changed = False

    class ChangingReader:
        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def __enter__(self) -> "ChangingReader":
            return self

        def read(self, size: int = -1) -> bytes:
            nonlocal changed
            data = self.handle.read(size)
            if not changed:
                declaration.write_bytes(declaration.read_bytes() + b" ")
                changed = True
            return data

        def __exit__(self, *args: object) -> None:
            self.handle.close()

    def fdopen_with_change(
        descriptor: int, mode: str, *args: object, **kwargs: object
    ) -> Any:
        handle = original_fdopen(descriptor, mode, *args, **kwargs)
        if mode == "rb":
            return ChangingReader(handle)
        return handle

    monkeypatch.setattr(candidate._contract.os, "fdopen", fdopen_with_change)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="candidate declaration changed while being read",
    ):
        candidate.parse_candidate(declaration)
    assert changed


def test_stable_control_file_symlink_is_accepted(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    symlink = tmp_path / "candidate-link.json"
    symlink.symlink_to(declaration.name)

    parsed = candidate.parse_candidate(symlink)

    assert parsed.id == "synthetic-candidate"


def test_deep_json_is_bounded_for_other_candidate_inputs(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted-evidence.json"
    trusted.write_bytes(b"[" * 100_000 + b"0" + b"]" * 100_000)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="trusted evidence exceeds maximum JSON nesting depth 128",
    ):
        candidate.parse_trusted_evidence(trusted)

    acquisition = tmp_path / "acquisition.json"
    acquisition.write_bytes(b"[" * 20_000 + b"0" + b"]" * 20_000)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="acquisition config exceeds maximum JSON nesting depth 128",
    ):
        candidate.parse_acquisition_config(acquisition)


def test_deep_compatibility_evidence_is_a_structured_contract_failure(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    path = tmp_path / "files" / "compatibility.json"
    path.write_bytes(b"[" * 100_000 + b"0" + b"]" * 100_000)
    evidence_pin = payload["recipe"]["compatibility_evidence"][0]["document"]
    evidence_pin["size_bytes"] = path.stat().st_size
    evidence_pin["sha256"] = _sha256(path.read_bytes())
    _rewrite(declaration, payload)

    report = candidate.verify_candidate(declaration)

    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_invalid"
    )


def test_cli_reports_deep_json_as_structured_validation_error(
    tmp_path: Path,
) -> None:
    declaration = tmp_path / "deep-declaration.json"
    declaration.write_bytes(b"[" * 100_000 + b"0" + b"]" * 100_000)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "inspect",
            "--declaration",
            str(declaration),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": {
            "code": "candidate_validation_error",
            "message": (
                "candidate declaration exceeds maximum JSON nesting depth 128"
            ),
        }
    }
    assert "Traceback" not in result.stderr


def test_cli_normalizes_unknown_user_path_to_validation_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    unknown_path = f"~t07-unknown-user-{os.getpid()}/candidate.json"

    exit_code = cli.main(
        ["candidate", "inspect", "--declaration", unknown_path]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == (
        "candidate_validation_error"
    )
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "parser_name",
    ("parse_candidate", "parse_trusted_evidence", "parse_acquisition_config"),
)
def test_unknown_user_control_paths_raise_candidate_validation_error(
    parser_name: str,
) -> None:
    unknown_path = Path(f"~t07-unknown-user-{os.getpid()}/control.json")

    with pytest.raises(candidate.CandidateValidationError):
        getattr(candidate, parser_name)(unknown_path)


def test_unknown_user_output_path_raises_candidate_output_error(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    unknown_output = Path(f"~t07-unknown-user-{os.getpid()}/prepared.json")

    with pytest.raises(candidate.CandidateOutputError):
        candidate.prepare_candidate(
            declaration,
            manifest_output=unknown_output,
            journal_output=tmp_path / "journal.json",
        )


def test_huge_integer_is_a_structured_candidate_validation_error(
    tmp_path: Path,
) -> None:
    declaration = tmp_path / "huge-integer-declaration.json"
    declaration.write_bytes(b'{"schema_version":' + b"9" * 5000 + b"}")

    with pytest.raises(
        candidate.CandidateValidationError,
        match="candidate declaration contains a number outside supported limits",
    ):
        candidate.parse_candidate(declaration)

    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "inspect",
            "--declaration",
            str(declaration),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": {
            "code": "candidate_validation_error",
            "message": (
                "candidate declaration contains a number outside supported limits"
            ),
        }
    }
    assert "Traceback" not in result.stderr


def test_malformed_ipv6_urls_are_candidate_validation_errors(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["engine"]["provenance"]["canonical_url"] = "https://["
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="absolute HTTPS URL",
    ):
        candidate.parse_candidate(declaration)

    config = _acquisition_config(
        tmp_path,
        allowed_origins=["https://["],
    )
    with pytest.raises(
        candidate.CandidateValidationError,
        match="HTTPS origin",
    ):
        candidate.parse_acquisition_config(config)


def test_provenance_and_license_urls_reject_out_of_range_ports(
    tmp_path: Path,
) -> None:
    cases = [
        ("provenance-port", "engine", "provenance", "canonical_url"),
        ("license-port", "components", "license", "terms_url"),
    ]
    for directory, owner, document, field in cases:
        case_root = tmp_path / directory
        case_root.mkdir()
        declaration = _fixture(case_root)
        payload = _payload(declaration)
        if owner == "components":
            payload[owner][0][document][field] = "https://example.invalid:99999/item"
        else:
            payload[owner][document][field] = "https://example.invalid:99999/item"
        _rewrite(declaration, payload)

        with pytest.raises(
            candidate.CandidateValidationError,
            match="contains an invalid port",
        ):
            candidate.parse_candidate(declaration)


def test_huge_integer_float_fields_are_bounded_before_conversion(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["adapters"][0]["strength"] = 10**400
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="strength must be between -10 and 10",
    ):
        candidate.parse_candidate(declaration)

    config = _acquisition_config(tmp_path, timeout_seconds=10**400)
    with pytest.raises(
        candidate.CandidateValidationError,
        match="timeout_seconds must be between 0.1 and 300",
    ):
        candidate.parse_acquisition_config(config)


def test_nested_declared_roots_are_rejected(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    nested = tmp_path / "files" / "nested"
    nested.mkdir()
    payload["roots"].append({"id": "nested", "path": "files/nested"})
    _rewrite(declaration, payload)

    with pytest.raises(candidate.CandidateValidationError, match="nested roots"):
        candidate.parse_candidate(declaration)


def test_t02_evidence_correlates_role_path_size_and_digest(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path, with_inventory=True)
    report = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    assert report["status"] == "ready"
    correlated = _items(report)["inventory.evidence.correlation"]["observed"]
    assert isinstance(correlated, dict)
    assert correlated["bundle_id"] == "synthetic-bundle"
    assert len(correlated["components"]) == 4  # type: ignore[arg-type]


def test_contradictory_t02_evidence_is_unverified(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path, with_inventory=True)
    payload = _payload(declaration)
    inventory_path = tmp_path / "files" / "inventory.json"
    inventory_document = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory_document["bundles"][0]["components"][0]["role"] = "vae"
    payload["inventory_evidence"]["document"] = _write_json(
        tmp_path / "files",
        "inventory.json",
        inventory_document,
    )
    _rewrite(declaration, payload)
    report = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    assert report["status"] == "unverified"
    assert _items(report)["inventory.evidence.schema"]["code"] == (
        "inventory_evidence_invalid"
    )


def test_path_escape_and_symlink_are_rejected(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"][0]["artifact"]["path"] = "../outside.bin"
    _rewrite(declaration, payload)
    with pytest.raises(candidate.CandidateValidationError, match="unsafe path component"):
        candidate.parse_candidate(declaration)

    second = tmp_path / "second"
    second.mkdir()
    declaration = _fixture(second)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    target = second / "files" / "vae.safetensors"
    target.unlink()
    target.symlink_to(outside)
    report = candidate.verify_candidate(declaration)
    assert report["status"] == "corrupt"
    assert _items(report)["component:vae"]["code"] == "symlink_or_unsafe_path"


def test_hard_linked_artifacts_are_rejected_as_physical_aliases(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    alias_root = tmp_path / "alias"
    alias_root.mkdir()
    os.link(
        tmp_path / "files" / "diffusion.safetensors",
        alias_root / "vae-alias.safetensors",
    )
    payload = _payload(declaration)
    payload["roots"].append({"id": "alias", "path": "alias"})
    vae = next(
        component
        for component in payload["components"]
        if component["id"] == "vae"
    )
    vae["artifact"]["root"] = "alias"
    vae["artifact"]["path"] = "vae-alias.safetensors"
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="physical files must be unique",
    ):
        candidate.parse_candidate(declaration)


def test_post_parse_hardlink_alias_is_rejected(tmp_path: Path) -> None:
    declaration_path = _fixture(tmp_path)
    payload = _payload(declaration_path)
    files = tmp_path / "files"
    diffusion_path = files / "diffusion.safetensors"
    vae_path = files / "vae.safetensors"
    diffusion_bytes = diffusion_path.read_bytes()
    vae_path.write_bytes(diffusion_bytes)
    assert vae_path.read_bytes() == diffusion_bytes
    assert vae_path.stat().st_ino != diffusion_path.stat().st_ino
    vae = next(
        component for component in payload["components"] if component["id"] == "vae"
    )
    vae["artifact"]["size_bytes"] = len(diffusion_bytes)
    vae["artifact"]["sha256"] = _sha256(diffusion_bytes)
    _rewrite(declaration_path, payload)

    declaration = candidate.parse_candidate(declaration_path)
    before = evaluate_candidate(declaration).report("inspect")
    assert _items(before)["component:vae"]["status"] == "ready"
    assert "candidate.physical_identity" not in _items(before)

    vae_path.unlink()
    os.link(diffusion_path, vae_path)
    after = evaluate_candidate(declaration).report("inspect")
    alias = _items(after)["candidate.physical_identity"]
    assert after["status"] == "corrupt"
    assert _items(after)["component:vae"]["status"] == "ready"
    assert alias["status"] == "corrupt"
    assert alias["code"] == "physical_alias"


def test_default_verify_is_offline_and_non_mutating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    before = _tree_snapshot(tmp_path)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("offline verification contacted network")

    monkeypatch.setattr(candidate._acquisition, "_open_remote", forbidden)
    report = candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence()
    )
    assert report["status"] == "ready"
    assert _tree_snapshot(tmp_path) == before


def test_prepare_writes_manifest_and_offline_journal(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    manifest_path = tmp_path / "prepared.json"
    journal_path = tmp_path / "journal.json"
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest_path,
        journal_output=journal_path,
        trusted_evidence=_trusted_evidence(),
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert report["status"] == "ready"
    assert manifest["candidate_id"] == report["candidate_id"]
    assert manifest["verification_id"] == report["verification_id"]
    assert journal["candidate_id"] == report["candidate_id"]
    assert journal["transfer_bytes"] == 0
    assert journal["events"][0]["code"] == "acquisition_not_requested"
    before = journal_path.read_bytes()
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest_path,
        journal_output=journal_path,
        trusted_evidence=_trusted_evidence(),
    )
    assert journal_path.read_bytes() == before


def test_prepare_output_cannot_replace_declared_or_control_files(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    with pytest.raises(candidate.CandidateOutputError, match="must not replace"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "files" / "diffusion.safetensors",
            journal_output=tmp_path / "journal.json",
        )
    with pytest.raises(candidate.CandidateOutputError, match="candidate declaration"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=declaration,
            journal_output=tmp_path / "journal.json",
        )
    config = _acquisition_config(tmp_path)
    with pytest.raises(candidate.CandidateOutputError, match="acquisition config"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=config,
            acquire=True,
            acquisition_config=config,
        )


def test_prepare_outputs_must_be_outside_git_worktrees(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    git_worktree = tmp_path / "temporary-repository"
    git_worktree.mkdir()
    (git_worktree / ".git").mkdir()
    journal_path = tmp_path / "journal.json"

    with pytest.raises(
        candidate.CandidateOutputError,
        match="outside Git worktrees",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=git_worktree / "prepared.json",
            journal_output=journal_path,
        )

    nested = git_worktree / "nested"
    nested.mkdir()
    repository_link = tmp_path / "repository-link"
    repository_link.symlink_to(git_worktree, target_is_directory=True)
    with pytest.raises(
        candidate.CandidateOutputError,
        match="outside Git worktrees",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=repository_link / "nested" / "prepared.json",
            journal_output=journal_path,
        )

    with pytest.raises(
        candidate.CandidateOutputError,
        match="outside Git worktrees",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=git_worktree / "journal.json",
        )


@pytest.mark.parametrize("git_marker", ("directory", "linked-worktree-file"))
def test_acquisition_roots_must_be_outside_git_worktrees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_marker: str,
) -> None:
    declaration = _fixture(tmp_path)
    model_root = tmp_path / "files"
    git_entry = model_root / ".git"
    if git_marker == "directory":
        git_entry.mkdir()
    else:
        git_entry.write_text(
            "gitdir: /checkout/.git/worktrees/model\n", encoding="utf-8"
        )
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("Git-backed acquisition root contacted remote")
        ),
    )
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"

    with pytest.raises(
        candidate.CandidateValidationError,
        match="acquisition root .* must be outside Git worktrees",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            acquire=True,
            acquisition_config=config,
        )

    assert not manifest.exists()
    assert not journal.exists()


def test_acquisition_rejects_nested_git_worktree_beneath_safe_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    nested_repository = tmp_path / "files" / "nested-repo"
    (nested_repository / ".git").mkdir(parents=True)
    payload["components"][0]["artifact"]["path"] = (
        "nested-repo/diffusion.safetensors"
    )
    _rewrite(declaration, payload)
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("nested Git-backed acquisition contacted remote")
        ),
    )
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"

    with pytest.raises(
        candidate.CandidateValidationError,
        match="acquisition destination .* must be outside Git worktrees",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            acquire=True,
            acquisition_config=config,
        )

    assert not manifest.exists()
    assert not journal.exists()


@pytest.mark.parametrize("output_kind", ("manifest", "journal"))
@pytest.mark.parametrize("alias_kind", ("direct", "hardlink", "symlink"))
def test_prepare_rejects_trusted_evidence_output_aliases(
    tmp_path: Path,
    output_kind: str,
    alias_kind: str,
) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    output = trusted_evidence
    if alias_kind == "hardlink":
        output = tmp_path / f"trusted-{output_kind}-hardlink.json"
        os.link(trusted_evidence, output)
    elif alias_kind == "symlink":
        output = tmp_path / f"trusted-{output_kind}-symlink.json"
        output.symlink_to(trusted_evidence)

    original_bytes = trusted_evidence.read_bytes()
    original_identity = trusted_evidence.stat()
    outputs = {
        "manifest_output": tmp_path / "prepared.json",
        "journal_output": tmp_path / "journal.json",
    }
    outputs[f"{output_kind}_output"] = output

    with pytest.raises(candidate.CandidateOutputError, match="must not replace"):
        candidate.prepare_candidate(
            declaration,
            trusted_evidence=_trusted_evidence(),
            trusted_evidence_path=trusted_evidence,
            **outputs,
        )

    current_identity = trusted_evidence.stat()
    assert (original_identity.st_dev, original_identity.st_ino) == (
        current_identity.st_dev,
        current_identity.st_ino,
    )
    assert original_identity.st_mtime_ns == current_identity.st_mtime_ns
    assert trusted_evidence.read_bytes() == original_bytes


@pytest.mark.parametrize("output_kind", ("manifest", "journal"))
@pytest.mark.parametrize("alias_kind", ("target", "hardlink", "symlink"))
def test_prepare_rejects_output_aliases_to_trusted_evidence_symlink_referent(
    tmp_path: Path,
    output_kind: str,
    alias_kind: str,
) -> None:
    declaration = _fixture(tmp_path)
    trusted_target = _write_trusted_evidence(tmp_path)
    trusted_link = tmp_path / "trusted-evidence-link.json"
    trusted_link.symlink_to(trusted_target)

    output = trusted_target
    if alias_kind == "hardlink":
        output = tmp_path / f"trusted-referent-{output_kind}-hardlink.json"
        os.link(trusted_target, output)
    elif alias_kind == "symlink":
        output = tmp_path / f"trusted-referent-{output_kind}-symlink.json"
        output.symlink_to(trusted_target)

    original_bytes = trusted_target.read_bytes()
    original_identity = trusted_target.stat()
    outputs = {
        "manifest_output": tmp_path / "prepared.json",
        "journal_output": tmp_path / "journal.json",
    }
    outputs[f"{output_kind}_output"] = output

    with pytest.raises(candidate.CandidateOutputError, match="must not replace"):
        candidate.prepare_candidate(
            declaration,
            trusted_evidence=_trusted_evidence(),
            trusted_evidence_path=trusted_link,
            **outputs,
        )

    current_identity = trusted_target.stat()
    assert (original_identity.st_dev, original_identity.st_ino) == (
        current_identity.st_dev,
        current_identity.st_ino,
    )
    assert original_identity.st_mtime_ns == current_identity.st_mtime_ns
    assert trusted_target.read_bytes() == original_bytes


def test_prepare_candidate_closes_both_targets_after_repeated_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    manifest_output = tmp_path / "prepared.json"
    journal_output = tmp_path / "journal.json"
    closed_paths: list[Path] = []
    original_close = candidate._acquisition._OutputTarget.close

    def tracking_close(target: Any) -> None:
        if target.parent_fd >= 0:
            closed_paths.append(target.path)
        original_close(target)

    def fail_evaluation(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic late evaluation failure")

    monkeypatch.setattr(candidate._acquisition._OutputTarget, "close", tracking_close)
    monkeypatch.setattr(candidate._acquisition, "evaluate_candidate", fail_evaluation)

    for _ in range(64):
        with pytest.raises(RuntimeError, match="synthetic late evaluation failure"):
            candidate.prepare_candidate(
                declaration,
                manifest_output=manifest_output,
                journal_output=journal_output,
            )

    assert closed_paths.count(manifest_output) == 64
    assert closed_paths.count(journal_output) == 64


@pytest.mark.parametrize("operation_fails", (False, True))
def test_prepare_cleanup_failure_closes_all_descriptors_and_releases_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation_fails: bool,
) -> None:
    acquisition = candidate._acquisition
    declaration_path = _fixture(tmp_path)
    manifest_output = tmp_path / "prepared.json"
    journal_output = tmp_path / "journal.json"
    descriptors: dict[str, int] = {}
    close_attempts: dict[int, int] = {}
    primary_error = candidate.CandidateOutputError("injected manifest invalidation failure")
    cleanup_error = OSError("injected manifest parent close failure")
    original_open = os.open
    original_close = os.close
    original_invalidate = acquisition._invalidate_manifest

    def capture_lock_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and os.fsdecode(path) == f".{journal_output.name}.lock":
            descriptors.update(journal_parent=dir_fd, lock=descriptor)
        return descriptor

    def invalidate_manifest(target: Any, declaration: Any) -> None:
        descriptors["manifest_parent"] = target.parent_fd
        if operation_fails:
            raise primary_error
        original_invalidate(target, declaration)

    def close_then_report_error(descriptor: int) -> None:
        if descriptor in descriptors.values():
            close_attempts[descriptor] = close_attempts.get(descriptor, 0) + 1
        original_close(descriptor)
        if descriptor == descriptors.get("manifest_parent"):
            raise cleanup_error

    monkeypatch.setattr(acquisition, "_JOURNAL_LOCK_TIMEOUT_SECONDS", 0.05)
    try:
        with monkeypatch.context() as injected:
            injected.setattr(acquisition.os, "open", capture_lock_open)
            injected.setattr(acquisition.os, "close", close_then_report_error)
            injected.setattr(acquisition, "_invalidate_manifest", invalidate_manifest)
            with pytest.raises(Exception) as failure:
                candidate.prepare_candidate(
                    declaration_path,
                    manifest_output=manifest_output,
                    journal_output=journal_output,
                    trusted_evidence=_trusted_evidence(),
                )

        assert failure.value is (primary_error if operation_fails else cleanup_error)
        assert set(descriptors) == {"manifest_parent", "journal_parent", "lock"}
        assert len(set(descriptors.values())) == 3
        assert close_attempts == {descriptor: 1 for descriptor in descriptors.values()}
        for descriptor in descriptors.values():
            _assert_descriptor_closed(descriptor)
        if operation_fails:
            assert any(
                "preparation cleanup failed" in note
                for note in primary_error.__notes__
            )

        # A fresh preparation must acquire the real journal lock without timing out.
        report = candidate.prepare_candidate(
            declaration_path,
            manifest_output=manifest_output,
            journal_output=journal_output,
            trusted_evidence=_trusted_evidence(),
        )
        assert report["status"] == "ready"
    finally:
        for descriptor in descriptors.values():
            try:
                original_close(descriptor)
            except OSError:
                pass


def test_fdopen_failure_closes_temporary_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    temporary_fd: int | None = None
    temporary_name: str | None = None
    original_temporary_file = candidate._acquisition._temporary_file

    def record_temporary_file(parent_fd: int, prefix: str) -> tuple[int, str]:
        nonlocal temporary_fd, temporary_name
        temporary_fd, temporary_name = original_temporary_file(parent_fd, prefix)
        return temporary_fd, temporary_name

    def fail_fdopen(*_args: object, **_kwargs: object) -> None:
        raise OSError("forced fdopen failure")

    monkeypatch.setattr(
        candidate._acquisition,
        "_temporary_file",
        record_temporary_file,
    )
    monkeypatch.setattr(candidate._acquisition.os, "fdopen", fail_fdopen)
    with pytest.raises(
        candidate.CandidateOutputError,
        match="output could not be published",
    ):
        candidate._acquisition._write_json_atomic(
            tmp_path / "output.json",
            {"status": "test"},
            label="output",
        )

    assert temporary_fd is not None
    assert temporary_name is not None
    with pytest.raises(OSError) as closed_error:
        os.fstat(temporary_fd)
    assert closed_error.value.errno == errno.EBADF
    assert not (tmp_path / temporary_name).exists()


def test_cli_rejects_trusted_evidence_as_manifest_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    original_bytes = trusted_evidence.read_bytes()
    original_identity = trusted_evidence.stat()

    exit_code = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--trusted-evidence",
            str(trusted_evidence),
            "--manifest-output",
            str(trusted_evidence),
            "--journal-output",
            str(tmp_path / "journal.json"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 7
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "candidate_output_error"
    current_identity = trusted_evidence.stat()
    assert (original_identity.st_dev, original_identity.st_ino) == (
        current_identity.st_dev,
        current_identity.st_ino,
    )
    assert original_identity.st_mtime_ns == current_identity.st_mtime_ns
    assert trusted_evidence.read_bytes() == original_bytes


def test_explicit_acquisition_publishes_only_missing_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    calls: list[str] = []

    def fake_open(url: str, **kwargs: object) -> _Response:
        calls.append(url)
        return _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", fake_open)
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    assert artifact.read_bytes() == body
    assert calls == ["https://downloads.example/diffusion.safetensors"]
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert [event["state"] for event in journal["events"]] == [
        "attempted",
        "succeeded",
    ]
    assert journal["events"][0]["reserved_bytes"] == len(body)
    assert journal["transfer_bytes"] == len(body)
    assert not list(artifact.parent.glob(".t07-*.part"))

    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("verified artifact downloaded again")
        ),
    )
    repeated = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared-second.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert repeated["status"] == "ready"


def test_failed_acquisition_invalidates_stale_ready_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    first = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    assert first["status"] == "ready"
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "ready"
    assert json.loads(journal.read_text(encoding="utf-8"))["status"] == "ready"

    artifact = tmp_path / "files" / "diffusion.safetensors"
    artifact.unlink()
    config = _acquisition_config(tmp_path, max_attempts=1)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(503),
    )

    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="bounded acquisition failed: http_503",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert not artifact.exists()
    refreshed_manifest = json.loads(manifest.read_text(encoding="utf-8"))
    refreshed_journal = json.loads(journal.read_text(encoding="utf-8"))
    assert refreshed_manifest["status"] == "unverified"
    assert refreshed_manifest["evidence"]["static_preparation"] == "unverified"
    assert refreshed_manifest["verification_id"] is None
    assert refreshed_manifest["verification"]["items"] == []
    assert refreshed_manifest["verification"]["observations"] == {}
    assert refreshed_journal["status"] == "unverified"
    assert refreshed_journal["events"][-1]["state"] == "failed"


def test_acquisition_hash_failure_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    expected = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    corrupt = b"X" * len(expected)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(corrupt))},
            body=corrupt,
        ),
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="response SHA-256 differs from the pinned digest",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )
    assert not artifact.exists()
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["state"] == "failed"
    assert "sha256" not in journal["events"][-1]
    assert not list(artifact.parent.glob(".t07-*.part"))


@pytest.mark.parametrize(
    "failure_point",
    ("write", "flush", "fchmod", "fsync", "descriptor_verification"),
)
def test_cli_normalizes_staging_storage_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["acquisition"]["sources"][0]["artifact"] = "engine"
    payload["acquisition"]["sources"][0]["url"] = (
        "https://downloads.example/engine.bin"
    )
    _rewrite(declaration, payload)
    artifact = tmp_path / "files" / "engine.bin"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )

    if failure_point in {"write", "flush"}:
        real_fdopen = candidate._acquisition.os.fdopen

        class FailingHandle:
            def __init__(self, handle: object) -> None:
                self.handle = handle

            def __enter__(self) -> FailingHandle:
                self.handle.__enter__()
                return self

            def __exit__(self, *args: object) -> object:
                return self.handle.__exit__(*args)

            def write(self, data: bytes) -> int:
                if failure_point == "write":
                    raise OSError("forced staging write failure")
                return self.handle.write(data)

            def flush(self) -> None:
                if failure_point == "flush":
                    raise OSError("forced staging flush failure")
                self.handle.flush()

            def __getattr__(self, name: str) -> object:
                return getattr(self.handle, name)

        def failing_fdopen(
            descriptor: int, mode: str, *args: object, **kwargs: object
        ) -> object:
            handle = real_fdopen(descriptor, mode, *args, **kwargs)
            return FailingHandle(handle) if mode == "w+b" else handle

        monkeypatch.setattr(candidate._acquisition.os, "fdopen", failing_fdopen)
    elif failure_point == "fchmod":
        monkeypatch.setattr(
            candidate._acquisition.os,
            "fchmod",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError("forced staging fchmod failure")
            ),
        )
    elif failure_point == "fsync":
        real_fsync = candidate._acquisition.os.fsync

        def failing_fsync(descriptor: int) -> None:
            if os.fstat(descriptor).st_size == len(body):
                raise OSError("forced staging fsync failure")
            real_fsync(descriptor)

        monkeypatch.setattr(candidate._acquisition.os, "fsync", failing_fsync)
    else:
        monkeypatch.setattr(
            candidate._acquisition,
            "_verify_staged_descriptor",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError("forced staging descriptor verification failure")
            ),
        )

    exit_code = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(tmp_path / "journal.json"),
            "--acquire",
            "--acquisition-config",
            str(config),
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 8
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "candidate_acquisition_error"
    assert not artifact.exists()
    assert not (tmp_path / "prepared.json").exists()
    assert not list(artifact.parent.glob(".t07-*.part"))
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["state"] == "failed"
    assert journal["events"][-1]["code"] == "acquisition_failed"


def test_interrupted_staging_is_removed_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    expected = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(expected))},
            read_error=OSError("simulated interrupted transfer"),
        ),
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="bounded acquisition failed: response_body_failed",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )
    assert not artifact.exists()
    assert not list(artifact.parent.glob(".t07-*.part"))
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["code"] == "response_body_failed"


def test_retry_is_bounded_and_succeeds_within_reserved_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        max_attempts=2,
        max_total_bytes=len(body) * 2,
    )
    responses = [
        _Response(503),
        _Response(200, headers={"Content-Length": str(len(body))}, body=body),
    ]
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *a, **k: responses.pop(0),
    )
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert [(event["state"], event["attempt"]) for event in journal["events"]] == [
        ("attempted", 1),
        ("failed", 1),
        ("attempted", 2),
        ("succeeded", 2),
    ]
    assert journal["transfer_bytes"] == len(body) * 2


def test_transfer_timeout_is_absolute_across_slow_read_and_retries(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config_path = _acquisition_config(
        tmp_path,
        max_attempts=2,
        max_total_bytes=len(body) * 2,
    )
    config = replace(
        candidate.parse_acquisition_config(config_path),
        timeout_seconds=0.05,
    )
    monkeypatch.setattr(
        candidate._acquisition,
        "parse_acquisition_config",
        lambda _path: config,
    )
    remote_calls: list[float] = []

    class SlowResponse(_Response):
        def read(self, size: int = -1) -> bytes:
            time.sleep(0.205)
            return super().read(size)

    def slow_open(
        _url: str,
        *,
        timeout_seconds: float,
        **_kwargs: object,
    ) -> _Response:
        remote_calls.append(timeout_seconds)
        return SlowResponse(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", slow_open)
    exit_code = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(tmp_path / "journal.json"),
            "--acquire",
            "--acquisition-config",
            str(config_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 8
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == {
        "code": "candidate_acquisition_error",
        "message": "bounded acquisition failed: transfer_timeout",
    }
    assert len(remote_calls) == 1
    assert 0 < remote_calls[0] <= 0.05
    assert not artifact.exists()
    assert not (tmp_path / "prepared.json").exists()
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["code"] == "transfer_timeout"


@pytest.mark.parametrize("reserved_attempts", (1, 2))
@pytest.mark.parametrize("journal_write_seconds", (0.1, 0.101))
def test_failed_event_persistence_exhausts_deadline_before_retry_reservation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    reserved_attempts: int,
    journal_write_seconds: float,
) -> None:
    acquisition = candidate._acquisition
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    size = artifact.stat().st_size
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        max_attempts=2,
        max_total_bytes=size * reserved_attempts,
        timeout_seconds=0.1,
    )
    journal_path = tmp_path / "journal.json"
    manifest_path = tmp_path / "prepared.json"
    now = 100.0
    responses: list[_Response] = []
    real_write = acquisition._write_journal

    def open_unavailable(*args: Any, **kwargs: Any) -> _Response:
        response = _Response(503)
        responses.append(response)
        return response

    def persist_then_expire(target: Any, journal: dict[str, object]) -> None:
        nonlocal now
        real_write(target, journal)
        events = journal["events"]
        if isinstance(events, list) and events and events[-1]["state"] == "failed":
            now += journal_write_seconds

    monkeypatch.setattr(acquisition.time, "monotonic", lambda: now)
    monkeypatch.setattr(acquisition, "_open_remote", open_unavailable)
    monkeypatch.setattr(acquisition, "_write_journal", persist_then_expire)
    exit_code = cli.main(
        [
            "candidate", "prepare", "--declaration", str(declaration),
            "--manifest-output", str(manifest_path),
            "--journal-output", str(journal_path), "--acquire",
            "--acquisition-config", str(config),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 8
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == {
        "code": "candidate_acquisition_error",
        "message": "bounded acquisition failed: transfer_timeout",
    }
    assert len(responses) == 1 and responses[0].closed
    assert not artifact.exists()
    assert not manifest_path.exists()
    journal = acquisition._load_journal(
        journal_path, declaration=candidate.parse_candidate(declaration)
    )
    assert journal["transfer_bytes"] == size
    assert [(event["state"], event["code"]) for event in journal["events"]] == [
        ("attempted", "transfer_started"), ("failed", "http_503"),
    ]


@pytest.mark.parametrize("framing", ("content_length", "eof", "chunked"))
def test_absolute_deadline_interrupts_periodic_socket_response_and_releases_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_property: Any,
    framing: str,
) -> None:
    """Frequent body bytes must not extend acquisition's absolute deadline."""
    acquisition = candidate._acquisition
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    original_files = _tree_snapshot(artifact.parent)
    manifest_path = tmp_path / "prepared.json"
    journal_path = tmp_path / "journal.json"
    config = _acquisition_config(
        tmp_path,
        timeout_seconds=0.1,
        max_attempts=2,
        max_total_bytes=len(body) * 2,
    )
    stop_streaming = threading.Event()
    responses: list[HTTPResponse] = []
    remote_timeouts: list[float] = []
    deadline_starts: list[float] = []
    staging_descriptors: list[int] = []
    real_open_staging = acquisition._open_staging_file

    class PeriodicHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.send_response(200)
            if framing == "content_length":
                self.send_header("Content-Length", str(len(body)))
            elif framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for offset in range(0, len(body), 2):
                    if offset and stop_streaming.wait(0.04):
                        return
                    chunk = body[offset : offset + 2]
                    if framing == "chunked":
                        chunk = f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                    self.wfile.write(chunk)
                    self.wfile.flush()
                if framing == "chunked":
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format: str, *args: object) -> None:
            pass

    opener = build_opener(ProxyHandler({}))
    with HTTPServer(("127.0.0.1", 0), PeriodicHandler) as server:
        worker = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )

        def open_local_response(
            _url: str, *, timeout_seconds: float, **_kwargs: object
        ) -> HTTPResponse:
            # Only route the transport boundary to loopback; origin validation
            # still sees the declaration's allowlisted HTTPS source.
            remote_timeouts.append(timeout_seconds)
            deadline_starts.append(_kwargs["deadline"].expires_at - 0.1)
            response = opener.open(
                f"http://127.0.0.1:{server.server_port}/artifact",
                timeout=timeout_seconds,
            )
            assert isinstance(response, HTTPResponse)
            responses.append(response)
            return response

        def capture_staging(parent_fd: int) -> Any:
            staging = real_open_staging(parent_fd)
            staging_descriptors.extend(
                (parent_fd, staging.descriptor)
            )
            return staging

        monkeypatch.setattr(acquisition, "_open_remote", open_local_response)
        monkeypatch.setattr(acquisition, "_open_staging_file", capture_staging)
        worker.start()
        try:
            with pytest.raises(
                candidate.CandidateAcquisitionError,
                match="bounded acquisition failed: transfer_timeout",
            ):
                candidate.prepare_candidate(
                    declaration,
                    manifest_output=manifest_path,
                    journal_output=journal_path,
                    acquire=True,
                    acquisition_config=config,
                    trusted_evidence=_trusted_evidence(),
                )
            # Measure the configured transfer budget independently from
            # declaration evaluation and output-path validation.
            elapsed = time.monotonic() - deadline_starts[0]
            record_property("acquisition_elapsed_seconds", elapsed)

            # The unfixed read waits about 0.52s to fill its buffer, although
            # every 40ms arrival is within the socket's inactivity timeout.
            assert elapsed < 0.35, f"absolute deadline overran: {elapsed:.3f}s"
            assert len(remote_timeouts) == 1
            assert 0 < remote_timeouts[0] <= 0.1
            assert len(responses) == 1 and responses[0].closed
            # One preflight pair and one transfer pair; neither owns a named directory.
            assert len(staging_descriptors) == 4
            for descriptor in staging_descriptors:
                _assert_descriptor_closed(descriptor)
            assert not artifact.exists()
            assert not manifest_path.exists()
            assert not list(artifact.parent.glob(".t07-*"))
            assert _tree_snapshot(artifact.parent) == original_files
            journal = _payload(journal_path)
            assert journal["status"] != "ready"
            assert journal["events"][-1]["code"] == "transfer_timeout"
            assert not any(
                event["state"] == "succeeded" for event in journal["events"]
            )
            with journal_path.with_name(".journal.json.lock").open("r+b") as lock:
                acquisition.fcntl.flock(
                    lock.fileno(), acquisition.fcntl.LOCK_EX | acquisition.fcntl.LOCK_NB
                )
                acquisition.fcntl.flock(lock.fileno(), acquisition.fcntl.LOCK_UN)
        finally:
            stop_streaming.set()
            server.shutdown()
            worker.join(timeout=2)
        assert not worker.is_alive()


def test_durable_budget_survives_failed_attempt_and_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    first_config = _acquisition_config(
        tmp_path,
        max_attempts=1,
        max_total_bytes=len(body),
        filename="first.json",
    )
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(503),
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="bounded acquisition failed: http_503",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "first-manifest.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=first_config,
        )
    before = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert before["transfer_bytes"] == len(body)

    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("restart exceeded durable budget but contacted network")
        ),
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="durable transfer byte budget is exhausted",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "second-manifest.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=first_config,
        )
    after = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert after["transfer_bytes"] == len(body)
    assert after["events"][-1]["code"] == "transfer_budget_exhausted"


def test_tampered_journal_budget_cannot_bypass_attempted_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    assert len(body) == 27
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        max_attempts=1,
        max_total_bytes=len(body),
    )
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(503),
    )

    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="bounded acquisition failed: http_503",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "first-manifest.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )

    journal_path = tmp_path / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["transfer_bytes"] == len(body)
    assert journal["events"][0]["state"] == "attempted"
    assert journal["events"][0]["reserved_bytes"] == len(body)
    journal["transfer_bytes"] = 0
    _write_json(tmp_path, "journal.json", journal)
    tampered_bytes = journal_path.read_bytes()
    network_calls: list[str] = []

    def unexpected_remote_open(url: str, **kwargs: object) -> _Response:
        network_calls.append(url)
        raise AssertionError("tampered journal reached remote acquisition")

    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        unexpected_remote_open,
    )
    second_manifest = tmp_path / "second-manifest.json"
    with pytest.raises(
        candidate.CandidateOutputError,
        match="transfer_bytes does not match attempted reservations",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=second_manifest,
            journal_output=journal_path,
            acquire=True,
            acquisition_config=config,
        )

    assert network_calls == []
    assert not second_manifest.exists()
    assert journal_path.read_bytes() == tampered_bytes


def test_stale_partial_file_is_ignored_and_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    stale = artifact.parent / ".t07-diffusion-stale.part"
    stale.write_bytes(b"stale partial bytes")
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    assert stale.read_bytes() == b"stale partial bytes"


def test_acquired_engine_has_owner_execute_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    engine = tmp_path / "files" / "engine.bin"
    body = engine.read_bytes()
    engine.unlink()
    payload = _payload(declaration)
    payload["acquisition"]["sources"] = [
        {"artifact": "engine", "url": "https://downloads.example/engine.bin"}
    ]
    _rewrite(declaration, payload)
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    assert engine.stat().st_mode & 0o111


def test_unauthorized_and_over_budget_config_never_contact_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    unauthorized = _acquisition_config(tmp_path)
    payload = json.loads(unauthorized.read_text(encoding="utf-8"))
    payload["authorized"] = False
    unauthorized.write_text(json.dumps(payload), encoding="utf-8")
    over_budget = _acquisition_config(
        tmp_path,
        max_total_bytes=1,
        filename="over-budget.json",
    )
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("transport rejection contacted remote")
        ),
    )
    with pytest.raises(candidate.CandidateValidationError, match="authorized"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "unauthorized.json",
            journal_output=tmp_path / "unauthorized-journal.json",
            acquire=True,
            acquisition_config=unauthorized,
        )
    with pytest.raises(candidate.CandidateValidationError, match="total limit"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "budget.json",
            journal_output=tmp_path / "budget-journal.json",
            acquire=True,
            acquisition_config=over_budget,
        )
    assert not artifact.exists()
    assert len(body) > 1


def test_existing_corrupt_artifact_is_never_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original = artifact.read_bytes()
    artifact.write_bytes(b"X" * len(original))
    config = _acquisition_config(tmp_path)
    called = False

    def forbidden(*args: object, **kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("corrupt destination must not trigger transfer")

    monkeypatch.setattr(candidate._acquisition, "_open_remote", forbidden)
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
    )
    assert not called
    assert report["status"] == "corrupt"
    assert artifact.read_bytes() == b"X" * len(original)
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["code"] == "existing_artifact_not_replaced"


def test_redirects_use_only_target_origin_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        allowed_origins=["https://downloads.example", "https://mirror.example"],
        credentials=[
            {
                "origin": "https://downloads.example",
                "headers": {"Authorization": f"Bearer {SECRET}"},
            },
            {
                "origin": "https://mirror.example",
                "headers": {"Authorization": "Bearer mirror-only"},
            },
        ],
    )
    seen: list[tuple[str, dict[str, str]]] = []

    def fake_open(url: str, *, headers: dict[str, str], **kwargs: object) -> _Response:
        seen.append((url, headers))
        if url == "https://downloads.example/diffusion.safetensors":
            return _Response(
                302,
                headers={"Location": "https://mirror.example/artifact"},
            )
        return _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", fake_open)
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    assert seen[0][1]["Authorization"] == f"Bearer {SECRET}"
    assert seen[1][1]["Authorization"] == "Bearer mirror-only"
    assert SECRET not in seen[1][1]["Authorization"]


def test_redirect_to_unlisted_origin_fails_without_leaking_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    (tmp_path / "files" / "diffusion.safetensors").unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            302,
            headers={"Location": "https://unlisted.example/artifact"},
        ),
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="acquisition origin is not explicitly allowed",
    ) as raised:
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )
    assert "unlisted" not in str(raised.value)
    journal_text = (tmp_path / "journal.json").read_text(encoding="utf-8")
    assert "unlisted" not in journal_text


@pytest.mark.parametrize(
    "location",
    (
        f"http://[{SECRET}",
        f"https://mirror.example:{SECRET}/artifact",
    ),
    ids=("malformed-ipv6", "invalid-port"),
)
def test_cli_normalizes_malformed_redirect_to_exit_8(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        allowed_origins=["https://downloads.example", "https://mirror.example"],
        credentials=[
            {
                "origin": "https://mirror.example",
                "headers": {"Authorization": f"Bearer {SECRET}"},
            }
        ],
    )
    calls: list[str] = []

    def redirect(url: str, **kwargs: object) -> _Response:
        calls.append(url)
        return _Response(302, headers={"Location": location})

    monkeypatch.setattr(candidate._acquisition, "_open_remote", redirect)

    exit_code = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(tmp_path / "journal.json"),
            "--acquire",
            "--acquisition-config",
            str(config),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 8
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "candidate_acquisition_error"
    assert SECRET not in captured.err
    assert calls == ["https://downloads.example/diffusion.safetensors"]
    assert not artifact.exists()
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert [event["state"] for event in journal["events"]] == [
        "attempted",
        "failed",
    ]
    assert journal["events"][-1]["code"] == "acquisition_failed"
    assert SECRET not in json.dumps(journal)


def test_transport_credentials_and_config_never_reach_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(
        tmp_path,
        credentials=[
            {
                "origin": "https://downloads.example",
                "headers": {"Authorization": f"Bearer {SECRET}"},
            }
        ],
    )

    def fake_open(url: str, **kwargs: object) -> _Response:
        return _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", fake_open)
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
    )
    manifest_text = (tmp_path / "prepared.json").read_text(encoding="utf-8")
    journal_text = (tmp_path / "journal.json").read_text(encoding="utf-8")
    report_text = json.dumps(report)
    assert SECRET not in manifest_text
    assert SECRET not in journal_text
    assert SECRET not in report_text
    assert "max_total_bytes" not in manifest_text + journal_text + report_text


def test_secret_in_acquisition_error_is_redacted_from_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    (tmp_path / "files" / "diffusion.safetensors").unlink()
    config = _acquisition_config(
        tmp_path,
        credentials=[
            {
                "origin": "https://downloads.example",
                "headers": {
                    "Authorization": f"Bearer {SECRET}",
                    "X-Short": "q7",
                },
            }
        ],
    )

    def fail_download(**kwargs: object) -> object:
        raise candidate.CandidateAcquisitionError(
            f"transport failed: {SECRET}; short secret q7"
        )

    monkeypatch.setattr(candidate._acquisition, "_download_to_staging", fail_download)
    with pytest.raises(candidate.CandidateAcquisitionError) as raised:
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )
    journal_text = (tmp_path / "journal.json").read_text(encoding="utf-8")
    report_text = str(raised.value)
    assert SECRET not in journal_text
    assert SECRET not in report_text
    assert "q7" not in journal_text
    assert "q7" not in report_text
    assert "[redacted]" in journal_text


def _write_pending_publication_journal(
    tmp_path: Path,
    declaration_path: Path,
    state: str,
) -> Path:
    declaration = candidate.parse_candidate(declaration_path)
    pin = declaration.artifact_targets()["component:diffusion"]
    journal = candidate._acquisition._journal_initial(declaration)
    journal["transfer_bytes"] = pin.size_bytes
    events: list[dict[str, object]] = [
        {
            "sequence": 1,
            "artifact": "component:diffusion",
            "state": "attempted",
            "attempt": 1,
            "reserved_bytes": pin.size_bytes,
            "code": "transfer_started",
            "message": "bounded transfer started",
        }
    ]
    if state == "publication_sync_failed":
        journal["status"] = "unverified"
        events.append(
            {
                "sequence": 2,
                "artifact": "component:diffusion",
                "state": "failed",
                "attempt": 1,
                "code": "publication_sync_failed",
                "message": "published artifact could not be synchronized",
            }
        )
    else:
        assert state == "attempted"
        journal["status"] = "missing"
    journal["events"] = events
    journal_path = tmp_path / "journal.json"
    candidate._acquisition._write_json_atomic(
        journal_path, journal, label="acquisition journal"
    )
    return journal_path


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
@pytest.mark.parametrize("existing_ready_manifest", (False, True))
def test_offline_prepare_rejects_pending_publication_recovery(
    tmp_path: Path,
    pending_state: str,
    existing_ready_manifest: bool,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    if existing_ready_manifest:
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    _write_pending_publication_journal(tmp_path, declaration, pending_state)
    before = _tree_snapshot(tmp_path)

    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="offline preparation requires authorized publication recovery",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )

    after = _tree_snapshot(tmp_path)
    expected_new_files = set() if existing_ready_manifest else {".journal.json.lock"}
    assert set(after) - set(before) == expected_new_files
    unchanged = {
        path: contents
        for path, contents in before.items()
        if not existing_ready_manifest or path != "prepared.json"
    }
    assert {path: after[path] for path in unchanged} == unchanged
    if existing_ready_manifest:
        invalidated = json.loads(manifest.read_text(encoding="utf-8"))
        assert invalidated["status"] == "unverified"
        assert invalidated["verification_id"] is None
        assert invalidated["verification"]["items"] == []
        assert invalidated["verification"]["observations"] == {}
    else:
        assert not manifest.exists()


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
def test_authorized_publication_recovery_records_verified_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_state: str,
) -> None:
    declaration = _fixture(tmp_path)
    journal_path = _write_pending_publication_journal(
        tmp_path, declaration, pending_state
    )
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original_bytes = artifact.read_bytes()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("verified artifact downloaded again")
        ),
    )
    original_sync = candidate._acquisition._sync_published_destination
    synchronized: list[str] = []

    def record_sync(
        candidate_declaration: candidate._acquisition.CandidateDeclaration,
        pin: candidate._acquisition.ArtifactPin,
        *,
        expected_identity: tuple[int, int],
    ) -> tuple[int, int, int, int, int]:
        synchronized.append(pin.path)
        return original_sync(
            candidate_declaration,
            pin,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(
        candidate._acquisition, "_sync_published_destination", record_sync
    )

    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=journal_path,
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )

    assert report["status"] == "ready"
    assert synchronized == ["diffusion.safetensors"]
    assert artifact.read_bytes() == original_bytes
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["events"][-1]["state"] == "succeeded"
    assert journal["events"][-1]["code"] == "recovered_verified_publication"


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
def test_authorized_publication_recovery_failure_does_not_emit_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_state: str,
) -> None:
    declaration = _fixture(tmp_path)
    journal_path = _write_pending_publication_journal(
        tmp_path, declaration, pending_state
    )
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original_bytes = artifact.read_bytes()
    config = _acquisition_config(tmp_path)
    manifest = tmp_path / "prepared.json"

    def fail_sync(*args: object, **kwargs: object) -> None:
        raise OSError("forced recovery synchronization failure")

    monkeypatch.setattr(candidate._acquisition, "_sync_published_file", fail_sync)

    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="published artifact could not be synchronized",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal_path,
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert not manifest.exists()
    assert artifact.read_bytes() == original_bytes
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert journal["status"] == "unverified"
    assert journal["events"][-1]["state"] == "failed"
    assert journal["events"][-1]["code"] == "publication_sync_failed"


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
@pytest.mark.parametrize("observation_failure", ("eacces", "corrupt"))
def test_pending_publication_survives_transient_initial_observation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_state: str,
    observation_failure: str,
) -> None:
    """A failed probe cannot discharge the obligation to sync a published inode."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition

    def prepare() -> dict[str, object]:
        return candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
        )

    if pending_state == "publication_sync_failed":
        artifact.unlink()

        def fail_sync(*args: object, **kwargs: object) -> None:
            raise OSError(errno.EIO, "injected publication synchronization failure")

        with monkeypatch.context() as injection:
            injection.setattr(
                acquisition, "_open_remote",
                lambda *args, **kwargs: _Response(
                    200, headers={"Content-Length": str(len(body))}, body=body,
                ),
            )
            injection.setattr(acquisition, "_sync_published_file", fail_sync)
            with pytest.raises(candidate.CandidateAcquisitionError):
                prepare()
        assert _payload(journal)["events"][-1]["code"] == "publication_sync_failed"
    else:
        _write_pending_publication_journal(tmp_path, declaration, pending_state)

    def no_download(*args: object, **kwargs: object) -> None:
        raise AssertionError("pending publication must recover without redownloading")

    monkeypatch.setattr(acquisition, "_open_remote", no_download)
    identity = acquisition._stat_identity(artifact.stat())
    synchronized: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        observed_identity = acquisition._stat_identity(os.fstat(descriptor))
        real_fsync(descriptor)
        if observed_identity == identity:
            synchronized.append(observed_identity)

    monkeypatch.setattr(acquisition.os, "fsync", record_fsync)
    real_observe = acquisition._observe_target
    real_open = acquisition.LocalObservationSource._open_beneath_fd
    probes = 0
    failures: list[str] = []
    denied_parents: list[Path] = []

    def deny_parent_probe(path: Path, root: Path, **kwargs: Any) -> int:
        # File observation opens the parent before the descriptor-relative file.
        if path == artifact.parent:
            assert kwargs.get("directory") is True
            denied_parents.append(path)
            raise PermissionError(errno.EACCES, "injected artifact parent probe denial")
        return real_open(path, root, **kwargs)

    def transient_probe(*args: Any, **kwargs: Any) -> Any:
        nonlocal probes
        probes += 1
        # The first target probe is the byte-budget preflight; the second is
        # the acquisition's initial observation after the journal is loaded.
        if probes != 2:
            return real_observe(*args, **kwargs)
        with monkeypatch.context() as injection:
            if observation_failure == "eacces":
                injection.setattr(
                    acquisition.LocalObservationSource, "_open_beneath_fd",
                    staticmethod(deny_parent_probe),
                )
            else:
                artifact.write_bytes(b"X" * len(body))
            try:
                observed = real_observe(*args, **kwargs)
                failures.append(observed.status)
                return observed
            finally:
                if observation_failure == "corrupt":
                    artifact.write_bytes(body)

    with monkeypatch.context() as injection:
        injection.setattr(acquisition, "_observe_target", transient_probe)
        with pytest.raises(candidate.CandidateAcquisitionError):
            prepare()

    assert denied_parents == ([artifact.parent] if observation_failure == "eacces" else [])
    assert failures == ["unverified" if observation_failure == "eacces" else "corrupt"]
    assert synchronized == []
    assert artifact.read_bytes() == body
    assert not manifest.exists()
    pending = _payload(journal)
    assert pending["status"] == "unverified"
    assert pending["events"][-1]["code"] == "publication_sync_failed"
    assert pending["events"][-1]["attempt"] == 1
    assert not any(event["state"] == "succeeded" for event in pending["events"])
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    assert _payload(journal) == pending
    assert prepare()["status"] == "ready"
    assert synchronized == [identity]
    recovered = _payload(journal)
    assert recovered["events"][-1]["code"] == "recovered_verified_publication"
    assert recovered["transfer_bytes"] == pending["transfer_bytes"]


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
@pytest.mark.parametrize("replacement_failure", ("conflict", "network", "budget"))
@pytest.mark.parametrize("fail_first_recovery", (False, True))
def test_pending_publication_survives_missing_probe_and_failed_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_state: str,
    replacement_failure: str,
    fail_first_recovery: bool,
) -> None:
    """A failed replacement cannot erase an older publication's sync obligation."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    saved = tmp_path / "temporarily-absent.safetensors"
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    config = _acquisition_config(
        tmp_path,
        max_attempts=2 if replacement_failure == "network" else 1,
        max_total_bytes=len(body) if replacement_failure == "budget" else 100_000,
    )
    acquisition = candidate._acquisition
    monkeypatch.setattr(
        acquisition, "_open_remote",
        lambda *args, **kwargs: _Response(
            200, headers={"Content-Length": str(len(body))}, body=body,
        ),
    )

    def prepare(*, acquire: bool = True) -> dict[str, object]:
        return candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=acquire, acquisition_config=config if acquire else None,
            trusted_evidence=_trusted_evidence(),
        )

    real_fsync = os.fsync
    interrupted: list[str] = []

    def interrupt_publication(descriptor: int) -> None:
        if artifact.exists() and acquisition._stat_identity(os.fstat(descriptor)) == (
            acquisition._stat_identity(artifact.stat())
        ):
            interrupted.append(pending_state)
            if pending_state == "attempted":
                raise KeyboardInterrupt("injected interruption before artifact fsync")
            raise OSError(errno.EIO, "injected artifact fsync failure")
        real_fsync(descriptor)

    artifact.unlink()
    with monkeypatch.context() as injection:
        injection.setattr(acquisition.os, "fsync", interrupt_publication)
        with pytest.raises(
            KeyboardInterrupt if pending_state == "attempted"
            else candidate.CandidateAcquisitionError
        ):
            prepare()
    assert interrupted == [pending_state]
    assert artifact.read_bytes() == body
    seed = _payload(journal)
    assert seed["events"][-1]["code"] == (
        "transfer_started" if pending_state == "attempted" else "publication_sync_failed"
    )

    identity = acquisition._stat_identity(artifact.stat())
    synchronized: list[tuple[int, int]] = []

    def record_fsync(descriptor: int) -> None:
        observed_identity = acquisition._stat_identity(os.fstat(descriptor))
        real_fsync(descriptor)
        if observed_identity == identity:
            synchronized.append(observed_identity)

    monkeypatch.setattr(acquisition.os, "fsync", record_fsync)
    real_observe = acquisition._observe_target
    probes = 0
    missing: list[str] = []

    def transient_absence(*args: Any, **kwargs: Any) -> Any:
        nonlocal probes
        probes += 1
        # Probe one preflights bytes; probe two starts the journaled acquisition.
        if probes != 2:
            return real_observe(*args, **kwargs)
        artifact.rename(saved)
        try:
            observed = real_observe(*args, **kwargs)
            missing.append(observed.status)
            return observed
        finally:
            saved.rename(artifact)

    with monkeypatch.context() as injection:
        injection.setattr(acquisition, "_observe_target", transient_absence)
        if replacement_failure == "network":
            injection.setattr(acquisition, "_open_remote", lambda *a, **kw: _Response(503))
        with pytest.raises(candidate.CandidateAcquisitionError):
            prepare()

    assert missing == ["missing"]
    assert synchronized == []
    assert artifact.read_bytes() == body
    assert not manifest.exists()
    pending = _payload(journal)
    assert pending["events"][:len(seed["events"])] == seed["events"]
    assert pending["events"][-1]["code"] == {
        "conflict": "acquisition_failed",
        "network": "http_503",
        "budget": "transfer_budget_exhausted",
    }[replacement_failure]
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        prepare(acquire=False)
    assert _payload(journal) == pending
    assert synchronized == []

    # A failed recovery must remain a valid journal transition even when a
    # failed replacement or exhausted budget separates it from the obligation.
    def fail_recovery(descriptor: int) -> None:
        if acquisition._stat_identity(os.fstat(descriptor)) == identity:
            raise OSError(errno.EIO, "injected recovery fsync failure")
        record_fsync(descriptor)

    if fail_first_recovery:
        with monkeypatch.context() as injection:
            injection.setattr(acquisition.os, "fsync", fail_recovery)
            with pytest.raises(candidate.CandidateAcquisitionError):
                prepare()
        assert _payload(journal)["events"][-1]["code"] == "publication_sync_failed"
        with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
            prepare(acquire=False)
    assert synchronized == []
    assert not manifest.exists()

    assert prepare()["status"] == "ready"
    assert synchronized == [identity]
    recovered = _payload(journal)
    assert recovered["events"][-1]["code"] == "recovered_verified_publication"
    assert recovered["events"][-1]["attempt"] == seed["events"][-1]["attempt"]
    assert recovered["transfer_bytes"] == pending["transfer_bytes"]
    assert prepare(acquire=False)["status"] == "ready"
    assert synchronized == [identity]


@pytest.mark.parametrize("pending_state", ("publication_sync_failed", "attempted"))
def test_pending_publication_with_absent_destination_can_publish_durably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pending_state: str,
) -> None:
    """A successful replacement can discharge recovery without stranding absence."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    journal = _write_pending_publication_journal(tmp_path, declaration, pending_state)
    artifact.unlink()
    acquisition = candidate._acquisition
    monkeypatch.setattr(
        acquisition, "_open_remote",
        lambda *args, **kwargs: _Response(
            200, headers={"Content-Length": str(len(body))}, body=body,
        ),
    )
    synchronized: list[str] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if artifact.exists() and acquisition._stat_identity(os.fstat(descriptor)) == (
            acquisition._stat_identity(artifact.stat())
        ):
            synchronized.append(artifact.name)

    monkeypatch.setattr(acquisition.os, "fsync", record_fsync)
    arguments = {
        "manifest_output": tmp_path / "prepared.json", "journal_output": journal,
        "trusted_evidence": _trusted_evidence(),
    }
    assert candidate.prepare_candidate(
        declaration, **arguments, acquire=True,
        acquisition_config=_acquisition_config(tmp_path),
    )["status"] == "ready"
    assert synchronized == [artifact.name]
    assert _payload(journal)["events"][-1]["code"] == "published_and_verified"
    assert _payload(journal)["transfer_bytes"] == len(body) * 2
    assert candidate.prepare_candidate(declaration, **arguments)["status"] == "ready"
    assert synchronized == [artifact.name]


def test_publication_sync_failure_is_not_recovered_as_ready(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )

    def fail_sync(*args: object, **kwargs: object) -> None:
        raise OSError("forced synchronization failure")

    monkeypatch.setattr(
        candidate._acquisition,
        "_sync_published_file",
        fail_sync,
    )
    arguments = [
        "candidate",
        "prepare",
        "--declaration",
        str(declaration),
        "--manifest-output",
        str(tmp_path / "prepared.json"),
        "--journal-output",
        str(tmp_path / "journal.json"),
        "--acquire",
        "--acquisition-config",
        str(config),
    ]
    assert cli.main(arguments) == 8
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"] == {
        "code": "candidate_acquisition_error",
        "message": "published artifact could not be synchronized",
    }
    assert artifact.read_bytes() == body
    assert not (tmp_path / "prepared.json").exists()
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["status"] == "unverified"
    assert journal["events"][-1]["state"] == "failed"
    assert journal["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in journal["events"])

    assert cli.main(arguments) == 8
    repeated = capsys.readouterr()
    assert json.loads(repeated.err)["error"] == {
        "code": "candidate_acquisition_error",
        "message": "published artifact could not be synchronized",
    }
    assert artifact.read_bytes() == body
    assert not (tmp_path / "prepared.json").exists()


def test_publication_journal_crash_recovers_without_redownload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    calls = 0

    def fake_open(*args: object, **kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", fake_open)
    original_append = candidate._acquisition._append_journal_event

    def crash_after_publish(*args: object, **kwargs: object) -> None:
        if kwargs.get("state") == "succeeded":
            raise candidate.CandidateOutputError("simulated journal publication crash")
        original_append(*args, **kwargs)

    monkeypatch.setattr(
        candidate._acquisition,
        "_append_journal_event",
        crash_after_publish,
    )
    with pytest.raises(candidate.CandidateOutputError):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )
    assert calls == 1
    assert artifact.read_bytes() == body

    monkeypatch.setattr(
        candidate._acquisition,
        "_append_journal_event",
        original_append,
    )
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )
    assert calls == 1
    assert report["status"] == "ready"
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["code"] == "recovered_verified_publication"


def test_publication_interposition_observes_absent_final_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )

    original_publish = candidate._acquisition._descriptor_bound_publish
    observed: list[str] = []

    def interposed_publish(source_fd: int, parent_fd: int, final_name: str) -> None:
        if final_name == ".":
            return original_publish(source_fd, parent_fd, final_name)
        with pytest.raises(FileNotFoundError):
            os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
        assert not list(artifact.parent.glob(".t07-stage-*.part"))
        observed.append(final_name)
        original_publish(source_fd, parent_fd, final_name)

    real_link = candidate._acquisition.os.link

    def reject_visible_staging_link(
        source: str,
        destination: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        if Path(source).name.startswith(".t07-stage-"):
            raise AssertionError("staging path must never be linked to final name")
        real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(
        candidate._acquisition,
        "_descriptor_bound_publish",
        interposed_publish,
    )
    monkeypatch.setattr(candidate._acquisition.os, "link", reject_visible_staging_link)

    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )

    assert observed == [artifact.name]
    assert report["status"] == "ready"
    assert artifact.read_bytes() == body
    assert not list(artifact.parent.glob(".t07-stage-*.part"))


def test_publication_sync_rejects_same_bytes_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    saved = tmp_path / "original-diffusion.safetensors"
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    monkeypatch.setattr(
        acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )
    real_sync = acquisition._sync_published_file

    def replace_before_sync(*args: object, **kwargs: object) -> None:
        artifact.replace(saved)
        artifact.write_bytes(body)
        real_sync(*args, **kwargs)

    monkeypatch.setattr(acquisition, "_sync_published_file", replace_before_sync)
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="published artifact could not be synchronized",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert artifact.stat().st_ino != saved.stat().st_ino
    assert artifact.read_bytes() == body
    assert saved.read_bytes() == body
    payload = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert payload["status"] == "unverified"
    assert payload["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in payload["events"])


@pytest.mark.parametrize("publication", ("new", "recovery"))
@pytest.mark.parametrize("replacement_point", ("directory_sync", "after_sync"))
def test_publication_success_requires_the_synchronized_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    replacement_point: str,
) -> None:
    """Identical bytes cannot substitute for file durability on the final inode."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    saved = tmp_path / "synchronized-original.safetensors"
    journal = tmp_path / "journal.json"
    manifest = tmp_path / "prepared.json"
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    if publication == "new":
        artifact.unlink()
    else:
        _write_pending_publication_journal(tmp_path, declaration, "attempted")
    monkeypatch.setattr(
        acquisition, "_open_remote",
        lambda *args, **kwargs: _Response(
            200, headers={"Content-Length": str(len(body))}, body=body,
        ),
    )
    parent_identity = acquisition._stat_identity(artifact.parent.stat())
    real_directory_sync = acquisition._fsync_directory
    real_file_sync = acquisition._sync_published_file

    def replace_artifact() -> None:
        artifact.rename(saved)
        artifact.write_bytes(body)

    def replace_during_directory_sync(descriptor: int) -> None:
        if acquisition._stat_identity(os.fstat(descriptor)) == parent_identity:
            replace_artifact()
        real_directory_sync(descriptor)

    def replace_after_sync(*args: Any, **kwargs: Any) -> tuple[int, int, int, int, int]:
        snapshot = real_file_sync(*args, **kwargs)
        replace_artifact()
        return snapshot

    with monkeypatch.context() as injection:
        if replacement_point == "directory_sync":
            injection.setattr(acquisition, "_fsync_directory", replace_during_directory_sync)
        else:
            injection.setattr(acquisition, "_sync_published_file", replace_after_sync)
        with pytest.raises(candidate.CandidateAcquisitionError):
            candidate.prepare_candidate(
                declaration, manifest_output=manifest, journal_output=journal,
                acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
            )

    assert artifact.stat().st_ino != saved.stat().st_ino
    assert artifact.read_bytes() == saved.read_bytes() == body
    assert not manifest.exists()
    payload = _payload(journal)
    assert payload["status"] == "unverified"
    assert payload["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in payload["events"])


@pytest.mark.parametrize("publication", ("new", "recovery"))
@pytest.mark.parametrize("rewrite_point", ("directory_sync", "after_sync", "final_verification"))
@pytest.mark.parametrize("restore_mtime", (False, True))
def test_publication_success_requires_unchanged_synchronized_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    rewrite_point: str,
    restore_mtime: bool,
) -> None:
    """Same-inode, same-byte writes after fsync still need another durable sync."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    journal = tmp_path / "journal.json"
    manifest = tmp_path / "prepared.json"
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    if publication == "new":
        artifact.unlink()
    else:
        _write_pending_publication_journal(tmp_path, declaration, "attempted")
    monkeypatch.setattr(
        acquisition, "_open_remote",
        lambda *args, **kwargs: _Response(
            200, headers={"Content-Length": str(len(body))}, body=body,
        ),
    )
    events: list[str] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if artifact.exists() and acquisition._stat_identity(os.fstat(descriptor)) == (
            acquisition._stat_identity(artifact.stat())
        ):
            events.append("file_fsync")

    monkeypatch.setattr(acquisition.os, "fsync", record_fsync)
    parent_identity = acquisition._stat_identity(artifact.parent.stat())
    real_directory_sync = acquisition._fsync_directory
    real_file_sync = acquisition._sync_published_file
    real_observe = acquisition._observe_target

    def rewrite_artifact() -> None:
        assert events == ["file_fsync"]
        before = artifact.stat()
        artifact.write_bytes(body)
        os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
        if restore_mtime:
            os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = artifact.stat()
        assert (after.st_dev, after.st_ino, after.st_size) == (
            before.st_dev, before.st_ino, before.st_size,
        )
        assert (after.st_mtime_ns == before.st_mtime_ns) is restore_mtime
        assert after.st_ctime_ns != before.st_ctime_ns
        assert artifact.read_bytes() == body
        events.append("rewrite")

    def rewrite_during_directory_sync(descriptor: int) -> None:
        if acquisition._stat_identity(os.fstat(descriptor)) == parent_identity:
            rewrite_artifact()
        real_directory_sync(descriptor)

    def rewrite_after_sync(*args: Any, **kwargs: Any) -> Any:
        synchronized = real_file_sync(*args, **kwargs)
        rewrite_artifact()
        return synchronized

    def rewrite_during_verification(*args: Any, **kwargs: Any) -> Any:
        observed = real_observe(*args, **kwargs)
        if events == ["file_fsync"]:
            rewrite_artifact()
        return observed

    def prepare(*, acquire: bool = True) -> dict[str, object]:
        return candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=acquire, acquisition_config=config if acquire else None,
            trusted_evidence=_trusted_evidence(),
        )

    with monkeypatch.context() as injection:
        if rewrite_point == "directory_sync":
            injection.setattr(acquisition, "_fsync_directory", rewrite_during_directory_sync)
        elif rewrite_point == "after_sync":
            injection.setattr(acquisition, "_sync_published_file", rewrite_after_sync)
        else:
            injection.setattr(acquisition, "_observe_target", rewrite_during_verification)
        with pytest.raises(candidate.CandidateAcquisitionError):
            prepare()

    assert events == ["file_fsync", "rewrite"]
    assert not manifest.exists()
    payload = _payload(journal)
    assert payload["status"] == "unverified"
    assert payload["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in payload["events"])
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        prepare(acquire=False)
    assert events == ["file_fsync", "rewrite"]
    assert prepare()["status"] == "ready"
    assert events == ["file_fsync", "rewrite", "file_fsync"]
    assert _payload(journal)["events"][-1]["code"] == "recovered_verified_publication"


@pytest.mark.parametrize("publication", ("new", "recovery"))
@pytest.mark.parametrize("final_change", ("missing", "eacces", "nonregular"))
def test_publication_requires_final_metadata_to_remain_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    final_change: str,
) -> None:
    """A successful hash cannot hide a failed final metadata observation."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    saved = tmp_path / "saved-publication.safetensors"
    journal = tmp_path / "journal.json"
    manifest = tmp_path / "prepared.json"
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    if publication == "new":
        artifact.unlink()
    else:
        _write_pending_publication_journal(tmp_path, declaration, "attempted")
    monkeypatch.setattr(
        acquisition, "_open_remote",
        lambda *args, **kwargs: _Response(
            200, headers={"Content-Length": str(len(body))}, body=body,
        ),
    )
    real_fsync = os.fsync
    synchronized: list[str] = []

    def record_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if artifact.exists() and acquisition._stat_identity(os.fstat(descriptor)) == (
            acquisition._stat_identity(artifact.stat())
        ):
            synchronized.append(artifact.name)

    monkeypatch.setattr(acquisition.os, "fsync", record_fsync)
    real_observe = acquisition._observe_target
    real_open = acquisition.LocalObservationSource._open_beneath_fd
    verification_finished = False

    def change_after_hash(*args: Any, **kwargs: Any) -> Any:
        nonlocal verification_finished
        observed = real_observe(*args, **kwargs)
        if synchronized:
            assert observed.status == "ready"
            verification_finished = True
            if final_change != "eacces":
                artifact.rename(saved)
                if final_change == "nonregular":
                    artifact.mkdir()
        return observed

    def deny_parent_after_hash(path: Path, root: Path, **kwargs: Any) -> int:
        if verification_finished and path == artifact.parent and final_change == "eacces":
            raise PermissionError(errno.EACCES, "injected final parent observation denial")
        return real_open(path, root, **kwargs)

    def prepare(*, acquire: bool = True) -> dict[str, object]:
        return candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=acquire, acquisition_config=config if acquire else None,
            trusted_evidence=_trusted_evidence(),
        )

    try:
        with monkeypatch.context() as injection:
            injection.setattr(acquisition, "_observe_target", change_after_hash)
            injection.setattr(
                acquisition.LocalObservationSource, "_open_beneath_fd",
                staticmethod(deny_parent_after_hash),
            )
            with pytest.raises(candidate.CandidateAcquisitionError, match="after synchronization"):
                prepare()
    finally:
        if saved.exists():
            if final_change == "nonregular":
                artifact.rmdir()
            saved.rename(artifact)

    assert verification_finished
    assert synchronized == [artifact.name]
    assert artifact.read_bytes() == body
    assert not manifest.exists()
    pending = _payload(journal)
    assert pending["status"] == "unverified"
    assert pending["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in pending["events"])
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        prepare(acquire=False)
    assert synchronized == [artifact.name]
    assert prepare()["status"] == "ready"
    assert synchronized == [artifact.name, artifact.name]


@pytest.mark.parametrize("failure_point", ("metadata", "verification"))
@pytest.mark.parametrize("close_failure", ("none", "file", "parent", "both"))
def test_publication_failure_closes_owned_descriptors_preserving_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    close_failure: str,
) -> None:
    acquisition = candidate._acquisition
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    pin = next(item.artifact for item in declaration.components if item.id == "diffusion")
    artifact = tmp_path / "files" / pin.path
    original_content = artifact.read_bytes()
    descriptors = {
        "parent": os.open(artifact.parent, os.O_RDONLY | os.O_DIRECTORY),
        "file": os.open(artifact, os.O_RDONLY),
    }
    staged = acquisition._StagedArtifact(
        parent_fd=descriptors["parent"],
        verified_fd=descriptors["file"],
        final_name="published.safetensors",
        path=artifact.parent / "published.safetensors",
        pin=pin,
    )
    close_calls: list[int] = []
    real_fstat = os.fstat
    real_close = os.close
    primary = (
        OSError(errno.EIO, "injected publication metadata failure")
        if failure_point == "metadata"
        else candidate.CandidateAcquisitionError("injected publication verification failure")
    )

    verified_fd = staged.verified_fd

    def fail_file_metadata(descriptor: int) -> os.stat_result:
        facts = real_fstat(descriptor)
        if descriptor == verified_fd and failure_point == "metadata":
            raise primary
        return facts

    def fail_verification(*args: Any, **kwargs: Any) -> None:
        raise primary

    def close_then_fail(descriptor: int) -> None:
        close_calls.append(descriptor)
        real_close(descriptor)
        if (
            descriptor == descriptors.get(close_failure)
            or (close_failure == "both" and descriptor in descriptors.values())
        ):
            raise OSError(errno.EIO, "injected publication descriptor close failure")

    try:
        for descriptor in descriptors.values():
            assert real_fstat(descriptor).st_ino > 0
        with monkeypatch.context() as injection:
            injection.setattr(acquisition.os, "fstat", fail_file_metadata)
            injection.setattr(acquisition.os, "close", close_then_fail)
            injection.setattr(acquisition, "_verify_staged_descriptor", fail_verification)
            with pytest.raises(Exception) as failure:
                acquisition._publish_staged(staged)

        for descriptor in descriptors.values():
            _assert_descriptor_closed(descriptor)
            assert close_calls.count(descriptor) == 1
        if failure_point == "metadata":
            assert failure.value is primary or failure.value.__cause__ is primary
        else:
            assert failure.value is primary
        if close_failure != "none":
            notes = failure.value.__notes__
            assert len(notes) == (2 if close_failure == "both" else 1)
            assert all("injected publication descriptor close failure" in note for note in notes)
        assert not staged.path.exists()
        assert artifact.read_bytes() == original_content
    finally:
        for descriptor in descriptors.values():
            try:
                real_close(descriptor)
            except OSError:
                pass


def test_concurrent_prepare_processes_serialize_journal_transactions(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    acquisition_config = _acquisition_config(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )

    worker_count = 3
    start = tmp_path / "start-processes"
    ready = [tmp_path / f"ready-{index}" for index in range(worker_count)]
    results = [tmp_path / f"result-{index}.json" for index in range(worker_count)]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    processes: list[subprocess.Popen[str]] = []
    completed: dict[int, tuple[int, str, str]] = {}
    try:
        for index in range(worker_count):
            command = [
                sys.executable,
                "-c",
                _PROCESS_PREPARE_SCRIPT,
                str(declaration),
                str(trusted_evidence),
                str(acquisition_config),
                str(journal),
                str(tmp_path / f"prepared-process-{index}.json"),
                str(ready[index]),
                str(start),
                str(results[index]),
            ]
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            )

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if all(path.exists() for path in ready):
                break
            if any(process.poll() is not None for process in processes):
                break
            time.sleep(0.01)

        if not all(path.exists() for path in ready):
            for process in processes:
                if process.poll() is None:
                    process.kill()
                stdout, stderr = process.communicate()
                completed[process.pid] = (process.returncode, stdout, stderr)
            diagnostics = "\n".join(
                f"pid={pid} returncode={status}\nstdout={stdout}\nstderr={stderr}"
                for pid, (status, stdout, stderr) in completed.items()
            )
            pytest.fail(f"prepare processes did not reach the lock barrier\n{diagnostics}")

        start.write_text("start\n", encoding="utf-8")
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            completed[process.pid] = (process.returncode, stdout, stderr)
    finally:
        for process in processes:
            if process.pid in completed:
                continue
            if process.poll() is None:
                process.kill()
            stdout, stderr = process.communicate()
            completed[process.pid] = (process.returncode, stdout, stderr)

    failures = [
        f"pid={pid} returncode={status}\nstdout={stdout}\nstderr={stderr}"
        for pid, (status, stdout, stderr) in completed.items()
        if status != 0
    ]
    assert not failures, "\n".join(failures)
    assert all(json.loads(path.read_text(encoding="utf-8"))["status"] == "ready" for path in results)

    payload = json.loads(journal.read_text(encoding="utf-8"))
    assert payload["status"] == "ready"
    assert payload["transfer_bytes"] == 0
    assert [event["code"] for event in payload["events"]] == [
        "acquisition_not_requested",
        *("already_present" for _ in range(worker_count)),
    ]


def test_concurrent_prepare_preserves_journal_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("ready artifacts contacted remote during concurrency test")
        ),
    )
    real_replace = candidate._acquisition.os.replace
    barrier = threading.Barrier(2)

    def synchronized_replace(
        source: str,
        destination: str,
        *args: object,
        **kwargs: object,
    ) -> None:
        if destination == journal.name:
            try:
                barrier.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
        real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(
        candidate._acquisition.os,
        "replace",
        synchronized_replace,
    )
    errors: list[BaseException] = []

    def prepare(index: int) -> None:
        try:
            candidate.prepare_candidate(
                declaration,
                manifest_output=tmp_path / f"prepared-{index}.json",
                journal_output=journal,
                acquire=True,
                acquisition_config=config,
                trusted_evidence=_trusted_evidence(),
            )
        except BaseException as error:
            errors.append(error)

    workers = [threading.Thread(target=prepare, args=(index,)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)

    assert not errors
    payload = json.loads(journal.read_text(encoding="utf-8"))
    already_present = [
        event
        for event in payload["events"]
        if event["code"] == "already_present"
    ]
    assert len(already_present) == 2


def test_atomic_publication_crash_retries_without_redownload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    calls = 0

    def fake_open(*args: object, **kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        )

    monkeypatch.setattr(candidate._acquisition, "_open_remote", fake_open)
    original_publish = candidate._acquisition._descriptor_bound_publish

    def crash_after_atomic_publication(
        source_fd: int, parent_fd: int, final_name: str
    ) -> None:
        original_publish(source_fd, parent_fd, final_name)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        candidate._acquisition,
        "_descriptor_bound_publish",
        crash_after_atomic_publication,
    )
    with pytest.raises(KeyboardInterrupt):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert calls == 1
    assert artifact.read_bytes() == body
    assert not list(artifact.parent.glob(".t07-stage-*.part"))
    pending_snapshot = _tree_snapshot(tmp_path)
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="offline preparation requires authorized publication recovery",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            trusted_evidence=_trusted_evidence(),
        )
    assert _tree_snapshot(tmp_path) == pending_snapshot

    monkeypatch.setattr(
        candidate._acquisition,
        "_descriptor_bound_publish",
        original_publish,
    )
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("verified artifact downloaded again")
        ),
    )
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json",
        acquire=True,
        acquisition_config=config,
        trusted_evidence=_trusted_evidence(),
    )

    assert calls == 1
    assert report["status"] == "ready"
    journal = json.loads((tmp_path / "journal.json").read_text(encoding="utf-8"))
    assert journal["events"][-1]["code"] == "recovered_verified_publication"


def test_unsupported_atomic_publication_is_structured_exit_8(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )
    monkeypatch.setattr(candidate._acquisition.sys, "platform", "unsupported")

    exit_code = cli.main(
        [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(tmp_path / "journal.json"),
            "--acquire",
            "--acquisition-config",
            str(config),
        ]
    )

    captured = capsys.readouterr()
    failure = json.loads(captured.err)
    assert exit_code == 8
    assert captured.out == ""
    assert failure["error"]["code"] == "candidate_acquisition_error"
    assert "descriptor-bound publication unsupported" in failure["error"]["message"]
    assert not artifact.exists()
    assert not list(artifact.parent.glob(".t07-stage-*.part"))
def test_rejected_atomic_publication_primitive_never_exposes_final(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )

    def reject_primitive(
        source_fd: int, parent_fd: int, final_name: str
    ) -> None:
        raise OSError(
            candidate._acquisition.errno.ENOTSUP,
            "filesystem does not support descriptor publication",
        )

    monkeypatch.setattr(
        candidate._acquisition,
        "_descriptor_bound_publish",
        reject_primitive,
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="filesystem rejected the atomic publication primitive",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )

    assert not artifact.exists()
    assert not list(artifact.parent.glob(".t07-stage-*.part"))
    assert not (tmp_path / "journal.json").exists()


def test_publication_conflict_does_not_replace_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(
            200,
            headers={"Content-Length": str(len(body))},
            body=body,
        ),
    )
    original_publish = candidate._acquisition._descriptor_bound_publish

    def create_conflict(
        source_fd: int, parent_fd: int, final_name: str
    ) -> None:
        if final_name != ".":
            artifact.write_bytes(b"conflict")
        original_publish(source_fd, parent_fd, final_name)

    monkeypatch.setattr(
        candidate._acquisition,
        "_descriptor_bound_publish",
        create_conflict,
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="destination exists and was not replaced",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            acquire=True,
            acquisition_config=config,
        )
    assert artifact.read_bytes() == b"conflict"
    assert not list(artifact.parent.glob(".t07-stage-*.part"))
@pytest.mark.parametrize(
    "invalid_tail",
    (
        (
            {
                "artifact": "undeclared-artifact",
                "state": "skipped",
                "attempt": 0,
                "code": "unexpected_artifact",
                "message": "not part of the declared candidate",
            },
        ),
        (
            {
                "artifact": "component:diffusion",
                "state": "failed",
                "attempt": 1,
                "code": "network_error",
                "message": "terminal event lacks an attempted event",
            },
        ),
        (
            {
                "artifact": "component:diffusion",
                "state": "attempted",
                "attempt": 1,
                "reserved_bytes": 27,
                "code": "transfer_started",
                "message": "bounded transfer started",
            },
            {
                "artifact": "component:diffusion",
                "state": "failed",
                "attempt": 999,
                "code": "unrelated_failure",
                "message": "terminal event does not match its attempt",
            },
        ),
        (
            {
                "artifact": "component:diffusion",
                "state": "succeeded",
                "attempt": 0,
                "code": "recovered_verified_publication",
                "message": "success omits the verified bytes and digest",
            },
        ),
    ),
    ids=("unknown-artifact", "orphan-terminal", "attempt-mismatch", "missing-proof"),
)
def test_prepare_rejects_invalid_artifact_journal_records(
    tmp_path: Path,
    invalid_tail: tuple[dict[str, object], ...],
) -> None:
    declaration = _fixture(tmp_path)
    journal_path = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal_path,
        trusted_evidence=_trusted_evidence(),
    )
    payload = json.loads(journal_path.read_text(encoding="utf-8"))
    events = payload["events"]
    for event in invalid_tail:
        event["sequence"] = len(events) + 1
        events.append(event)
    if any(event["state"] == "attempted" for event in invalid_tail):
        payload["transfer_bytes"] = 27
    journal_path.write_text(json.dumps(payload), encoding="utf-8")
    corrupt_bytes = journal_path.read_bytes()
    manifest = tmp_path / "must-not-publish.json"

    with pytest.raises(candidate.CandidateOutputError, match="acquisition journal"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal_path,
            trusted_evidence=_trusted_evidence(),
        )

    assert not manifest.exists()
    assert journal_path.read_bytes() == corrupt_bytes


@pytest.mark.parametrize(
    ("field", "mismatch"),
    (("precision", "fp32"), ("quantization", "int8")),
)
def test_ready_requires_compatibility_evidence_to_bind_component_format(
    tmp_path: Path,
    field: str,
    mismatch: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"][0][field] = mismatch
    compatibility_path = tmp_path / "files" / "compatibility.json"
    compatibility = _payload(compatibility_path)
    for component in compatibility["components"]:  # type: ignore[assignment]
        component.pop("precision", None)
        component.pop("quantization", None)
    for role in compatibility["required_roles"]:  # type: ignore[assignment]
        for component in role["components"]:  # type: ignore[assignment]
            component.pop("precision", None)
            component.pop("quantization", None)
    compatibility_pin = _write_json(
        tmp_path / "files",
        "compatibility.json",
        compatibility,
    )
    payload["recipe"]["compatibility_evidence"][0]["document"] = compatibility_pin
    _rewrite(declaration, payload)
    records = list(_trusted_evidence())
    for index, record in enumerate(records):
        if record.expected.get("schema") == COMPATIBILITY_SCHEMA:
            records[index] = replace(
                record,
                document_size_bytes=len(compatibility_path.read_bytes()),
                document_sha256=_sha256(compatibility_path.read_bytes()),
                expected=compatibility,
            )

    report = candidate.verify_candidate(
        declaration,
        trusted_evidence=tuple(records),
    )

    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )


@pytest.mark.parametrize("location", ("components", "required_roles"))
@pytest.mark.parametrize("field", ("precision", "quantization"))
@pytest.mark.parametrize("variation", ("absent", "unknown", "mismatch"))
def test_compatibility_contract_rejects_each_component_format_variation(
    tmp_path: Path,
    location: str,
    field: str,
    variation: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    compatibility_path = tmp_path / "files" / "compatibility.json"
    compatibility = _payload(compatibility_path)
    if location == "components":
        targets = compatibility["components"]
    else:
        targets = [
            component
            for role in compatibility["required_roles"]
            for component in role["components"]
        ]
    assert isinstance(targets, list)
    for component in targets:
        assert isinstance(component, dict)
        if variation == "absent":
            component.pop(field, None)
        elif variation == "unknown":
            component[field] = "unknown"
        else:
            component[field] = "fp32" if field == "precision" else "int8"
    compatibility_pin = _write_json(
        tmp_path / "files",
        "compatibility.json",
        compatibility,
    )
    payload["recipe"]["compatibility_evidence"][0]["document"] = compatibility_pin
    _rewrite(declaration, payload)
    records = list(_trusted_evidence())
    for index, record in enumerate(records):
        if record.expected.get("schema") == COMPATIBILITY_SCHEMA:
            records[index] = replace(
                record,
                document_size_bytes=len(compatibility_path.read_bytes()),
                document_sha256=_sha256(compatibility_path.read_bytes()),
                expected=compatibility,
            )

    report = candidate.verify_candidate(
        declaration,
        trusted_evidence=tuple(records),
    )

    assert report["status"] == "unverified"
    assert _items(report)["recipe.compatibility.evidence[0]"]["code"] == (
        "evidence_contract_mismatch"
    )


@pytest.mark.parametrize("field", ("precision", "quantization"))
@pytest.mark.parametrize("value", ("unknown", "auto", "default", ""))
def test_unknown_component_format_is_rejected_before_readiness(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"][0][field] = value
    _rewrite(declaration, payload)

    with pytest.raises(candidate.CandidateValidationError, match=field):
        candidate.verify_candidate(declaration)


@pytest.mark.parametrize("field", ("precision", "quantization"))
def test_absent_component_format_is_rejected_before_readiness(
    tmp_path: Path,
    field: str,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["components"][0].pop(field)
    _rewrite(declaration, payload)

    with pytest.raises(candidate.CandidateValidationError, match=field):
        candidate.verify_candidate(declaration)


def test_prepare_invalidates_manifest_before_journal_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    artifact = tmp_path / "files" / "diffusion.safetensors"
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    real_write = candidate._acquisition._write_journal
    checked = False

    def checked_write(
        target: candidate._acquisition._OutputTarget,
        payload: dict[str, object],
    ) -> None:
        nonlocal checked
        if payload["status"] == "unverified" and not checked:
            checked = True
            pending = json.loads(manifest.read_text(encoding="utf-8"))
            assert pending["status"] == "unverified"
            assert pending["verification_id"] is None
            assert pending["verification"]["items"] == []
            assert pending["verification"]["observations"] == {}
        real_write(target, payload)

    monkeypatch.setattr(candidate._acquisition, "_write_journal", checked_write)
    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        lambda *args, **kwargs: _Response(503),
    )

    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="bounded acquisition failed: http_503",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert checked
    pending = json.loads(manifest.read_text(encoding="utf-8"))
    assert pending["status"] == "unverified"
    assert pending["verification_id"] is None
    assert pending["verification"]["items"] == []
    assert pending["verification"]["observations"] == {}


def test_ready_manifest_is_published_only_after_ready_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    real_write = candidate._acquisition._write_journal

    def fail_ready_journal(
        target: candidate._acquisition._OutputTarget,
        payload: dict[str, object],
    ) -> None:
        if payload["status"] == "ready":
            raise candidate.CandidateOutputError("forced ready journal failure")
        real_write(target, payload)

    monkeypatch.setattr(candidate._acquisition, "_write_journal", fail_ready_journal)
    with pytest.raises(candidate.CandidateOutputError, match="forced ready journal"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )

    failed = json.loads(manifest.read_text(encoding="utf-8"))
    assert failed["status"] == "unverified"
    assert failed["verification_id"] is None
    assert failed["verification"]["items"] == []
    assert failed["verification"]["observations"] == {}


def test_manifest_invalidation_failure_prevents_journal_or_acquisition_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    journal_before = journal.read_bytes()
    artifact_before = (tmp_path / "files" / "diffusion.safetensors").read_bytes()
    acquisition = candidate._acquisition

    def fail_invalidation(
        target: acquisition._OutputTarget,
        candidate_declaration: acquisition.CandidateDeclaration,
    ) -> None:
        raise candidate.CandidateOutputError("forced manifest invalidation failure")

    monkeypatch.setattr(acquisition, "_invalidate_manifest", fail_invalidation)
    monkeypatch.setattr(
        acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("acquisition started after invalidation failure")
        ),
    )

    with pytest.raises(
        candidate.CandidateOutputError,
        match="forced manifest invalidation failure",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            acquire=True,
            acquisition_config=_acquisition_config(tmp_path),
            trusted_evidence=_trusted_evidence(),
        )

    assert journal.read_bytes() == journal_before
    assert (tmp_path / "files" / "diffusion.safetensors").read_bytes() == artifact_before
    assert json.loads(manifest.read_text(encoding="utf-8"))["status"] == "ready"


@pytest.mark.parametrize(
    "crash_boundary",
    ("after-invalidate", "after-pending-journal", "after-ready-journal"),
)
def test_crash_boundaries_never_leave_ready_manifest_with_new_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_boundary: str,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    acquisition = candidate._acquisition
    argument_options: dict[str, object] = {}

    if crash_boundary == "after-invalidate":
        def crash_load(*args: object, **kwargs: object) -> dict[str, object]:
            raise KeyboardInterrupt

        monkeypatch.setattr(acquisition, "_load_journal", crash_load)
        argument_options.update(
            acquire=True,
            acquisition_config=_acquisition_config(tmp_path),
        )
    elif crash_boundary == "after-pending-journal":
        real_write = acquisition._write_journal
        crashed = False

        def crash_pending(
            target: acquisition._OutputTarget,
            payload: dict[str, object],
        ) -> None:
            nonlocal crashed
            real_write(target, payload)
            if not crashed and payload["status"] == "unverified":
                crashed = True
                raise KeyboardInterrupt

        monkeypatch.setattr(acquisition, "_write_journal", crash_pending)
        argument_options.update(
            acquire=True,
            acquisition_config=_acquisition_config(tmp_path),
        )
    else:
        real_write_json = acquisition._write_json_atomic

        def crash_ready_manifest(
            target: object,
            payload: object,
            *,
            label: str,
            **kwargs: Any,
        ) -> None:
            if (
                label == "preparation manifest"
                and isinstance(payload, dict)
                and payload.get("status") == "ready"
            ):
                raise KeyboardInterrupt
            real_write_json(target, payload, label=label, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(
            acquisition,
            "_write_json_atomic",
            crash_ready_manifest,
        )

    with pytest.raises(KeyboardInterrupt):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
            **argument_options,
        )

    pending = json.loads(manifest.read_text(encoding="utf-8"))
    assert pending["status"] == "unverified"
    assert pending["verification_id"] is None
    assert pending["verification"] == {"items": [], "observations": {}}
    assert pending["evidence"]["static_preparation"] == "unverified"
    assert pending["evidence"]["independent_evidence_authority"] == "unverified"

@pytest.mark.parametrize("existing_manifest", (False, True))
@pytest.mark.parametrize("replacement_kind", ("journal", "journal-parent"))
@pytest.mark.parametrize("boundary", ("before-publish", "after-publish"))
def test_manifest_publication_rejects_late_journal_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_manifest: bool,
    replacement_kind: str,
    boundary: str,
) -> None:
    """Journal replacement during publication revokes only the new manifest."""
    declaration = _fixture(tmp_path)
    parent = tmp_path / "journal-state"
    parent.mkdir()
    replacement = tmp_path / "pending-state"
    replacement.mkdir()
    pending = _write_pending_publication_journal(replacement, declaration, "attempted")
    pending_bytes = pending.read_bytes()
    journal = parent / "journal.json"
    manifest = tmp_path / "prepared.json"
    if existing_manifest:
        assert candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )["status"] == "ready"
    acquisition = candidate._acquisition
    real_write = acquisition._write_json_atomic
    publishing_manifest = False
    published: list[tuple[int, int]] = []

    def mark_manifest(target: Any, value: Any, **kwargs: Any) -> None:
        nonlocal publishing_manifest
        publishing_manifest = kwargs["label"] == "preparation manifest" and value["status"] == "ready"
        try:
            real_write(target, value, **kwargs)
        finally:
            publishing_manifest = False

    def replace_journal() -> None:
        if replacement_kind == "journal":
            pending.replace(journal)
        else:
            parent.rename(tmp_path / "displaced-state")
            replacement.rename(parent)

    publication_call = "replace" if existing_manifest else "link"
    real_publish = getattr(acquisition.os, publication_call)

    def publish_with_replacement(source: Any, destination: Any, **kwargs: Any) -> None:
        if not publishing_manifest or destination != manifest.name:
            return real_publish(source, destination, **kwargs)
        if boundary == "before-publish":
            replace_journal()
        real_publish(source, destination, **kwargs)
        published.append(acquisition._stat_identity(manifest.stat()))
        if boundary == "after-publish":
            replace_journal()

    with monkeypatch.context() as injection:
        injection.setattr(acquisition, "_write_json_atomic", mark_manifest)
        injection.setattr(acquisition.os, publication_call, publish_with_replacement)
        with pytest.raises(candidate.CandidateOutputError, match="(journal|parent).*changed"):
            candidate.prepare_candidate(
                declaration, manifest_output=manifest, journal_output=journal,
                trusted_evidence=_trusted_evidence(),
            )

    assert published == [acquisition._stat_identity(manifest.stat())]
    assert manifest.read_bytes() == b""
    assert journal.read_bytes() == pending_bytes
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    assert journal.read_bytes() == pending_bytes
    assert _payload(manifest)["status"] == "unverified"

    artifact = tmp_path / "files" / "diffusion.safetensors"
    artifact_bytes = artifact.read_bytes()
    real_sync = acquisition._sync_published_destination
    synchronized: list[tuple[int, int]] = []

    def record_sync(*args: Any, **kwargs: Any) -> Any:
        result = real_sync(*args, **kwargs)
        synchronized.append(result[:2])
        return result

    def no_download(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("pending publication must be synchronized without downloading")

    monkeypatch.setattr(acquisition, "_sync_published_destination", record_sync)
    monkeypatch.setattr(acquisition, "_open_remote", no_download)
    report = candidate.prepare_candidate(
        declaration, manifest_output=manifest, journal_output=journal,
        acquire=True, acquisition_config=_acquisition_config(tmp_path),
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == _payload(manifest)["status"] == "ready"
    assert synchronized == [acquisition._stat_identity(artifact.stat())]
    assert artifact.read_bytes() == artifact_bytes
    recovered = _payload(journal)
    assert recovered["events"][-1]["code"] == "recovered_verified_publication"
    assert recovered["transfer_bytes"] == json.loads(pending_bytes)["transfer_bytes"]


@pytest.mark.parametrize("replacement_kind", ("entry", "parent"))
def test_manifest_rollback_preserves_replacement_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """Rollback uses the published descriptor even after its path is displaced."""
    declaration = _fixture(tmp_path)
    protected = tmp_path / "existing-ready.json"
    journal = tmp_path / "journal.json"
    assert candidate.prepare_candidate(
        declaration, manifest_output=protected, journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )["status"] == "ready"
    protected_bytes = protected.read_bytes()
    protected_identity = (protected.stat().st_dev, protected.stat().st_ino)
    pending_parent = tmp_path / "pending-state"
    pending_parent.mkdir()
    pending = _write_pending_publication_journal(pending_parent, declaration, "attempted")
    pending_bytes = pending.read_bytes()
    parent = tmp_path / "manifest-state"
    parent.mkdir()
    manifest = parent / "prepared.json"
    displaced = tmp_path / "displaced-manifest"
    acquisition = candidate._acquisition
    real_link = os.link
    published: list[tuple[int, int]] = []

    def replace_after_link(source: Any, destination: Any, **kwargs: Any) -> None:
        real_link(source, destination, **kwargs)
        if destination != manifest.name:
            return
        published.append(acquisition._stat_identity(manifest.stat()))
        if replacement_kind == "entry":
            manifest.rename(displaced)
        else:
            parent.rename(displaced)
            parent.mkdir()
        real_link(protected, manifest)
        pending.replace(journal)

    with monkeypatch.context() as injection:
        injection.setattr(acquisition.os, "link", replace_after_link)
        with pytest.raises(candidate.CandidateOutputError, match="changed"):
            candidate.prepare_candidate(
                declaration, manifest_output=manifest, journal_output=journal,
                trusted_evidence=_trusted_evidence(),
            )

    owned_manifest = displaced if replacement_kind == "entry" else displaced / manifest.name
    assert published == [acquisition._stat_identity(owned_manifest.stat())]
    assert owned_manifest.read_bytes() == b""
    assert manifest.read_bytes() == protected.read_bytes() == protected_bytes
    assert acquisition._stat_identity(manifest.stat()) == protected_identity
    assert acquisition._stat_identity(protected.stat()) == protected_identity
    assert journal.read_bytes() == pending_bytes


def test_ready_journal_write_reconciles_fresh_file_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    acquisition = candidate._acquisition
    real_write = acquisition._write_journal
    changed = False

    def mutate_after_ready(
        target: acquisition._OutputTarget,
        payload: dict[str, object],
    ) -> None:
        nonlocal changed
        real_write(target, payload)
        if payload["status"] == "ready" and not changed:
            changed = True
            artifact.write_bytes(b"X" * artifact.stat().st_size)

    monkeypatch.setattr(acquisition, "_write_journal", mutate_after_ready)
    report = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )

    assert changed
    assert report["status"] == "corrupt"
    prepared = json.loads(manifest.read_text(encoding="utf-8"))
    current_journal = json.loads(journal.read_text(encoding="utf-8"))
    assert prepared["status"] == "corrupt"
    assert prepared["verification_id"] == report["verification_id"]
    assert current_journal["status"] == "corrupt"
    assert current_journal["candidate_id"] == report["candidate_id"]


@pytest.mark.parametrize("failure_kind", ("storage", "timeout"))
@pytest.mark.parametrize("mode", ("offline", "acquire"))
def test_cli_reports_journal_lock_failure_as_structured_output_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    mode: str,
) -> None:
    declaration = _fixture(tmp_path)
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    real_flock = acquisition.fcntl.flock

    def failing_flock(descriptor: int, operation: int) -> None:
        if operation & acquisition.fcntl.LOCK_EX:
            if failure_kind == "timeout":
                raise BlockingIOError(errno.EAGAIN, "journal lock busy")
            raise OSError(errno.ENOLCK, "journal lock storage failure")
        real_flock(descriptor, operation)

    if failure_kind == "timeout":
        monkeypatch.setattr(acquisition, "_JOURNAL_LOCK_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(acquisition.fcntl, "flock", failing_flock)

    arguments = [
        "candidate",
        "prepare",
        "--declaration",
        str(declaration),
        "--manifest-output",
        str(tmp_path / "prepared.json"),
        "--journal-output",
        str(tmp_path / "journal.json"),
    ]
    if mode == "acquire":
        arguments.extend(["--acquire", "--acquisition-config", str(config)])
    exit_code = cli.main(arguments)

    captured = capsys.readouterr()
    assert exit_code == 7
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "candidate_output_error"


def test_offline_and_acquire_prepare_serialize_journal_transactions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    config = _acquisition_config(tmp_path)
    acquisition = candidate._acquisition
    offline_loaded = threading.Event()
    release_offline = threading.Event()
    acquire_at_lock = threading.Event()
    acquire_done = threading.Event()
    errors: list[BaseException] = []
    real_load = acquisition._load_journal
    real_flock = acquisition.fcntl.flock

    def observed_load(target: object, *, declaration: object) -> dict[str, object]:
        loaded = real_load(target, declaration=declaration)  # type: ignore[arg-type]
        if threading.current_thread().name == "offline-prepare":
            offline_loaded.set()
            assert release_offline.wait(timeout=3)
        return loaded

    def observed_flock(descriptor: int, operation: int) -> None:
        if threading.current_thread().name == "acquire-prepare" and (
            operation & acquisition.fcntl.LOCK_EX
        ):
            acquire_at_lock.set()
        real_flock(descriptor, operation)

    monkeypatch.setattr(acquisition, "_load_journal", observed_load)
    monkeypatch.setattr(acquisition.fcntl, "flock", observed_flock)
    monkeypatch.setattr(
        acquisition,
        "_open_remote",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("verified artifacts contacted remote")
        ),
    )

    def offline_prepare() -> None:
        try:
            candidate.prepare_candidate(
                declaration,
                manifest_output=tmp_path / "offline.json",
                journal_output=journal,
                trusted_evidence=_trusted_evidence(),
            )
        except BaseException as error:
            errors.append(error)

    def acquire_prepare() -> None:
        try:
            candidate.prepare_candidate(
                declaration,
                manifest_output=tmp_path / "acquire.json",
                journal_output=journal,
                acquire=True,
                acquisition_config=config,
                trusted_evidence=_trusted_evidence(),
            )
        except BaseException as error:
            errors.append(error)
        finally:
            acquire_done.set()

    offline = threading.Thread(target=offline_prepare, name="offline-prepare")
    acquire = threading.Thread(target=acquire_prepare, name="acquire-prepare")
    offline.start()
    assert offline_loaded.wait(timeout=3)
    acquire.start()
    assert acquire_at_lock.wait(timeout=3)
    acquire_done.wait(timeout=0.25)
    release_offline.set()
    offline.join(timeout=5)
    acquire.join(timeout=5)

    assert not offline.is_alive()
    assert not acquire.is_alive()
    assert not errors
    payload = json.loads(journal.read_text(encoding="utf-8"))
    codes = [event["code"] for event in payload["events"]]
    assert codes.count("acquisition_not_requested") == 1
    assert codes.count("already_present") == 1


@pytest.mark.parametrize("alias_kind", ("exact", "normalized", "hard_link"))
def test_manifest_output_cannot_replace_active_journal_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alias_kind: str,
) -> None:
    declaration = _fixture(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    lock_path = journal.with_name(f".{journal.name}.lock")
    if alias_kind == "normalized":
        manifest_output = lock_path.parent / "nested" / ".." / lock_path.name
    elif alias_kind == "hard_link":
        manifest_output = tmp_path / "manifest-lock-alias"
        candidate._acquisition.os.link(lock_path, manifest_output)
    else:
        manifest_output = lock_path
    lock_bytes = lock_path.read_bytes()
    lock_identity = lock_path.stat()
    manifest_path = Path(os.path.abspath(manifest_output))
    manifest_bytes = manifest_path.read_bytes()
    manifest_identity = manifest_path.stat()
    journal_bytes = journal.read_bytes()

    acquisition = candidate._acquisition
    monkeypatch.setattr(acquisition, "_JOURNAL_LOCK_TIMEOUT_SECONDS", 0.0)
    target = acquisition._open_output_target(
        journal, label="journal output", allow_existing=True
    )
    try:
        held_lock = acquisition._JournalLock.acquire(target)
        try:
            with pytest.raises(candidate.CandidateOutputError, match="lock timed out"):
                acquisition._JournalLock.acquire(target)

            with pytest.raises(
                acquisition.CandidateOutputError,
                match="manifest output must not replace acquisition journal lock",
            ):
                candidate.prepare_candidate(
                    declaration,
                    manifest_output=manifest_output,
                    journal_output=journal,
                    trusted_evidence=_trusted_evidence(),
                )

            assert lock_path.read_bytes() == lock_bytes
            current_lock_identity = lock_path.stat()
            assert (current_lock_identity.st_dev, current_lock_identity.st_ino) == (
                lock_identity.st_dev,
                lock_identity.st_ino,
            )
            assert manifest_path.read_bytes() == manifest_bytes
            current_manifest_identity = manifest_path.stat()
            assert (
                current_manifest_identity.st_dev,
                current_manifest_identity.st_ino,
            ) == (manifest_identity.st_dev, manifest_identity.st_ino)
            assert journal.read_bytes() == journal_bytes

            with pytest.raises(candidate.CandidateOutputError, match="lock timed out"):
                acquisition._JournalLock.acquire(target)
        finally:
            held_lock.close()
    finally:
        target.close()


def test_mixed_offline_and_acquire_processes_serialize_journal_transactions(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    acquisition_config = _acquisition_config(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    locked = tmp_path / "offline-locked"
    acquire_attempt = tmp_path / "acquire-attempt"
    release = tmp_path / "release-offline"
    offline_result = tmp_path / "offline-result.json"
    acquire_result = tmp_path / "acquire-result.json"
    acquired_before_release = False

    def start(mode: str, result: Path) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [
                sys.executable,
                "-c",
                _MIXED_PROCESS_PREPARE_SCRIPT,
                mode,
                str(declaration),
                str(trusted_evidence),
                str(acquisition_config),
                str(journal),
                str(tmp_path / f"{mode}-manifest.json"),
                str(locked),
                str(acquire_attempt),
                str(release),
                str(result),
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    offline = start("offline", offline_result)
    acquire: subprocess.Popen[str] | None = None
    try:
        deadline = time.monotonic() + 10
        while not locked.exists() and time.monotonic() < deadline:
            if offline.poll() is not None:
                break
            time.sleep(0.01)
        assert locked.exists(), "offline process did not acquire its journal lock"

        acquire = start("acquire", acquire_result)
        deadline = time.monotonic() + 10
        while not acquire_attempt.exists() and time.monotonic() < deadline:
            if acquire.poll() is not None:
                break
            time.sleep(0.01)
        assert acquire_attempt.exists(), "acquire process did not begin preparation"

        blocked_until = time.monotonic() + 0.5
        while time.monotonic() < blocked_until:
            if acquire_result.exists():
                acquired_before_release = True
                break
            time.sleep(0.01)
        assert not acquired_before_release
        release.write_text("release\n", encoding="utf-8")
        offline_stdout, offline_stderr = offline.communicate(timeout=20)
        acquire_stdout, acquire_stderr = acquire.communicate(timeout=20)
    finally:
        if offline.poll() is None:
            offline.kill()
            offline.communicate()
        if acquire is not None and acquire.poll() is None:
            acquire.kill()
            acquire.communicate()

    assert not acquired_before_release
    assert offline.returncode == 0, offline_stderr
    assert acquire.returncode == 0, acquire_stderr
    assert offline_stdout == ""
    assert acquire_stdout == ""
    assert json.loads(offline_result.read_text(encoding="utf-8"))["status"] == "ready"
    assert json.loads(acquire_result.read_text(encoding="utf-8"))["status"] == "ready"
    payload = json.loads(journal.read_text(encoding="utf-8"))
    assert [event["code"] for event in payload["events"]] == [
        "acquisition_not_requested",
        "already_present",
    ]


@pytest.mark.parametrize(
    "damage",
    (
        "status-list",
        "status-object",
        "events-object",
        "candidate-id-list",
        "transfer-bytes-list",
        "event-entry-list",
        "event-state-object",
        "event-attempt-object",
        "event-artifact-list",
        "event-message-object",
    ),
)
def test_prepare_rejects_malformed_journal_types_without_type_error(
    tmp_path: Path,
    damage: str,
) -> None:
    declaration = _fixture(tmp_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=tmp_path / "seed.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    payload = json.loads(journal.read_text(encoding="utf-8"))
    if damage == "status-list":
        payload["status"] = []
    elif damage == "status-object":
        payload["status"] = {}
    elif damage == "events-object":
        payload["events"] = {}
    elif damage == "candidate-id-list":
        payload["candidate_id"] = []
    elif damage == "transfer-bytes-list":
        payload["transfer_bytes"] = []
    elif damage == "event-entry-list":
        payload["events"][0] = []
    elif damage == "event-state-object":
        payload["events"][0]["state"] = {}
    elif damage == "event-attempt-object":
        payload["events"][0]["attempt"] = {}
    elif damage == "event-artifact-list":
        payload["events"][0]["artifact"] = []
    else:
        assert damage == "event-message-object"
        payload["events"][0]["message"] = {}
    _rewrite(journal, payload)

    with pytest.raises(candidate.CandidateOutputError, match="acquisition journal"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "must-not-publish.json",
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )


@pytest.mark.parametrize("journal_action", ("delete", "ready-rewrite"))
def test_journal_manipulation_cannot_override_current_pins_or_manifest(
    tmp_path: Path,
    journal_action: str,
) -> None:
    declaration = _fixture(tmp_path)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    ready = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    artifact = tmp_path / "files" / "diffusion.safetensors"
    current = artifact.read_bytes()
    artifact.write_bytes(b"X" * len(current))
    if journal_action == "delete":
        journal.unlink()
    else:
        payload = json.loads(journal.read_text(encoding="utf-8"))
        payload["status"] = "ready"
        _rewrite(journal, payload)

    report = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )

    assert report["status"] == "corrupt"
    pending = json.loads(manifest.read_text(encoding="utf-8"))
    assert pending["status"] == "corrupt"
    assert pending["verification_id"] != ready["verification_id"]
    assert json.loads(journal.read_text(encoding="utf-8"))["status"] == "corrupt"


def test_journal_event_history_is_bounded(tmp_path: Path) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = candidate._acquisition._journal_initial(declaration)
    journal["events"] = [None] * 10_001

    with pytest.raises(candidate.CandidateOutputError, match="too many events"):
        candidate._acquisition._validate_journal_events(
            journal["events"],
            declaration,
        )


def _journal_with_skipped_events(declaration: Any, count: int) -> dict[str, object]:
    """Build a valid history without consuming transfer reservations."""
    journal = candidate._acquisition._journal_initial(declaration)
    journal["events"] = [
        {
            "sequence": sequence,
            "artifact": "component:diffusion",
            "state": "skipped",
            "attempt": 0,
            "code": "acquisition_not_requested",
            "message": "offline preparation did not contact a remote source",
        }
        for sequence in range(1, count + 1)
    ]
    return journal


@pytest.mark.parametrize(
    ("event_count", "first_status", "requests", "succeeds"),
    (
        (9_998, 200, 1, True),
        (9_999, 200, 0, False),
        (10_000, 200, 0, False),
        (9_997, 503, 1, False),
        (9_998, 503, 1, False),
    ),
)
def test_acquisition_preflights_journal_capacity_before_each_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_count: int,
    first_status: int,
    requests: int,
    succeeds: bool,
) -> None:
    acquisition = candidate._acquisition
    declaration_path = _fixture(tmp_path)
    declaration = candidate.parse_candidate(declaration_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    journal_path = tmp_path / "journal.json"
    journal = _journal_with_skipped_events(declaration, event_count)
    _rewrite(journal_path, journal)
    assert acquisition._load_journal(journal_path, declaration=declaration) == journal
    config = _acquisition_config(tmp_path, max_attempts=2)
    responses: list[_Response] = []

    def open_response(*args: Any, **kwargs: Any) -> _Response:
        status = first_status if not responses else 200
        response = _Response(
            status, headers={"Content-Length": str(len(body))}, body=body
        )
        responses.append(response)
        return response

    monkeypatch.setattr(acquisition, "_open_remote", open_response)
    arguments = {
        "manifest_output": tmp_path / "prepared.json",
        "journal_output": journal_path,
        "acquire": True,
        "acquisition_config": config,
        "trusted_evidence": _trusted_evidence(),
    }
    if succeeds:
        report = candidate.prepare_candidate(declaration_path, **arguments)
        assert report["status"] == "ready"
        assert artifact.read_bytes() == body
    else:
        with pytest.raises(candidate.CandidateOutputError, match="journal.*capacity"):
            candidate.prepare_candidate(declaration_path, **arguments)
        assert not artifact.exists()
        assert not (tmp_path / "prepared.json").exists()
    assert len(responses) == requests
    assert all(response.closed for response in responses)
    assert not list(artifact.parent.glob(".t07-*"))
    loaded = acquisition._load_journal(journal_path, declaration=declaration)
    assert loaded["events"][:event_count] == journal["events"]
    assert len(loaded["events"]) == event_count + requests * 2
    assert loaded["transfer_bytes"] == len(body) * requests


@pytest.mark.parametrize("event_count", (9_999, 10_000))
@pytest.mark.parametrize("pending_state", ("attempted", "publication_sync_failed"))
def test_publication_recovery_preflights_journal_capacity_before_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event_count: int,
    pending_state: str,
) -> None:
    acquisition = candidate._acquisition
    declaration_path = _fixture(tmp_path)
    declaration = candidate.parse_candidate(declaration_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original_bytes = artifact.read_bytes()
    original_stat = artifact.stat()
    journal_path = _write_pending_publication_journal(
        tmp_path, declaration_path, pending_state
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    pending_events = journal["events"]
    events = _journal_with_skipped_events(
        declaration, event_count - len(pending_events)
    )["events"]
    for event in pending_events:
        event["sequence"] = len(events) + 1
        events.append(event)
    journal["events"] = events
    _rewrite(journal_path, journal)
    assert acquisition._load_journal(journal_path, declaration=declaration) == journal

    synchronized: list[str] = []
    real_sync = acquisition._sync_published_destination

    def record_sync(*args: Any, **kwargs: Any) -> tuple[int, int, int, int, int]:
        synchronized.append(args[1].path)
        return real_sync(*args, **kwargs)

    def reject_download(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("publication recovery must not download an artifact")

    monkeypatch.setattr(acquisition, "_sync_published_destination", record_sync)
    monkeypatch.setattr(acquisition, "_open_remote", reject_download)
    manifest_path = tmp_path / "prepared.json"
    arguments = {
        "manifest_output": manifest_path,
        "journal_output": journal_path,
        "acquire": True,
        "acquisition_config": _acquisition_config(tmp_path),
        "trusted_evidence": _trusted_evidence(),
    }
    if event_count == 10_000:
        with pytest.raises(candidate.CandidateOutputError, match="journal.*capacity"):
            candidate.prepare_candidate(declaration_path, **arguments)
        assert synchronized == []
        assert not manifest_path.exists()
    else:
        report = candidate.prepare_candidate(declaration_path, **arguments)
        assert report["status"] == "ready"
        assert synchronized == ["diffusion.safetensors"]

    loaded = acquisition._load_journal(journal_path, declaration=declaration)
    assert len(loaded["events"]) == 10_000
    assert loaded["events"][:event_count] == journal["events"]
    assert loaded["transfer_bytes"] == len(original_bytes)
    if event_count == 9_999:
        assert loaded["events"][-1]["code"] == "recovered_verified_publication"
    else:
        assert loaded["status"] == "unverified"
    assert artifact.read_bytes() == original_bytes
    current_stat = artifact.stat()
    assert (current_stat.st_dev, current_stat.st_ino) == (
        original_stat.st_dev, original_stat.st_ino
    )
    assert not list(artifact.parent.glob(".t07-*"))


def test_journal_append_rejects_full_history_before_memory_or_disk_mutation(
    tmp_path: Path,
) -> None:
    acquisition = candidate._acquisition
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = _journal_with_skipped_events(declaration, 10_000)
    path = tmp_path / "journal.json"
    _rewrite(path, journal)
    original_bytes = path.read_bytes()
    target = acquisition._open_output_target(
        path, label="acquisition journal", allow_existing=True
    )
    try:
        with pytest.raises(candidate.CandidateOutputError, match="journal.*capacity"):
            acquisition._append_journal_event(
                target, journal, artifact="component:diffusion", state="skipped",
                attempt=0, code="acquisition_not_requested",
                message="offline preparation did not contact a remote source",
            )
    finally:
        target.close()
    assert len(journal["events"]) == 10_000
    assert path.read_bytes() == original_bytes
    assert acquisition._load_journal(path, declaration=declaration) == journal


@pytest.mark.parametrize("replacement_kind", ("different-bytes", "same-bytes"))
def test_published_file_recovery_rejects_replacement_before_sync_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    declaration = _fixture(tmp_path)
    journal = _write_pending_publication_journal(tmp_path, declaration, "attempted")
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original_bytes = artifact.read_bytes()
    saved = tmp_path / "saved-original.safetensors"
    config = _acquisition_config(tmp_path)
    real_sync = candidate._acquisition._sync_published_destination

    def substitute_during_sync(
        candidate_declaration: candidate._acquisition.CandidateDeclaration,
        pin: candidate._acquisition.ArtifactPin,
        *,
        expected_identity: tuple[int, int],
    ) -> tuple[int, int, int, int, int]:
        artifact.replace(saved)
        artifact.write_bytes(
            original_bytes
            if replacement_kind == "same-bytes"
            else b"X" * len(original_bytes)
        )
        try:
            return real_sync(
                candidate_declaration,
                pin,
                expected_identity=expected_identity,
            )
        finally:
            artifact.unlink()
            saved.replace(artifact)

    monkeypatch.setattr(
        candidate._acquisition,
        "_sync_published_destination",
        substitute_during_sync,
    )
    with pytest.raises(
        candidate.CandidateAcquisitionError,
        match="published artifact could not be synchronized",
    ):
        candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=journal,
            acquire=True,
            acquisition_config=config,
            trusted_evidence=_trusted_evidence(),
        )

    assert artifact.read_bytes() == original_bytes
    payload = json.loads(journal.read_text(encoding="utf-8"))
    assert payload["status"] == "unverified"
    assert payload["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in payload["events"])


@pytest.mark.parametrize("source_kind", ("fifo", "device"))
def test_published_file_sync_rejects_nonregular_input_without_blocking(
    tmp_path: Path,
    source_kind: str,
) -> None:
    if source_kind == "fifo":
        parent = tmp_path / "published-parent"
        parent.mkdir()
        final_name = "published.fifo"
        os.mkfifo(parent / final_name)
    else:
        parent = Path("/dev")
        final_name = "zero"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    script = r"""
import os
import sys

from media_generation import _candidate_acquisition as acquisition


parent_fd = os.open(
    sys.argv[1],
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)
try:
    try:
        acquisition._sync_published_file(
            parent_fd,
            sys.argv[2],
            acquisition.ArtifactPin(
                root="files",
                path=sys.argv[2],
                size_bytes=0,
                sha256="0" * 64,
            ),
            expected_identity=(0, 0),
        )
    except acquisition.CandidateAcquisitionError:
        raise SystemExit(0)
    raise SystemExit(9)
finally:
    os.close(parent_fd)
"""

    result = subprocess.run(
        [sys.executable, "-c", script, str(parent), final_name],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )

    assert result.returncode == 0, result.stderr


def test_default_verify_is_offline_and_does_not_mutate_candidate_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    before = _tree_snapshot(tmp_path)

    def reject_remote_access(*args: object, **kwargs: object) -> object:
        raise AssertionError("offline verification attempted acquisition")

    monkeypatch.setattr(
        candidate._acquisition,
        "_open_remote",
        reject_remote_access,
    )

    result = cli.main(
        ["candidate", "verify", "--declaration", str(declaration)]
    )
    output = capsys.readouterr()

    assert result == 4
    assert json.loads(output.out)["status"] == "unverified"
    assert output.err == ""
    assert _tree_snapshot(tmp_path) == before


def test_candidate_control_fifo_fails_without_blocking(tmp_path: Path) -> None:
    declaration = tmp_path / "candidate.fifo"
    os.mkfifo(declaration)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "inspect",
            "--declaration",
            str(declaration),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )

    assert result.returncode == 2
    assert json.loads(result.stderr)["error"]["code"] == "candidate_validation_error"


@pytest.mark.parametrize("control", ("trusted-evidence", "acquisition-config"))
@pytest.mark.parametrize("source_kind", ("fifo", "device"))
def test_candidate_nonregular_controls_fail_without_blocking(
    tmp_path: Path,
    control: str,
    source_kind: str,
) -> None:
    declaration = _fixture(tmp_path)
    if source_kind == "fifo":
        control_path = tmp_path / f"{control}.input"
        os.mkfifo(control_path)
    else:
        control_path = Path("/dev/null")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    if control == "trusted-evidence":
        arguments = [
            "candidate",
            "inspect",
            "--declaration",
            str(declaration),
            "--trusted-evidence",
            str(control_path),
        ]
    else:
        arguments = [
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(tmp_path / "journal.json"),
            "--acquire",
            "--acquisition-config",
            str(control_path),
        ]

    result = subprocess.run(
        [sys.executable, "-m", "media_generation", *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )

    assert result.returncode == 2
    assert json.loads(result.stderr)["error"]["code"] == "candidate_validation_error"


def test_journal_fifo_fails_without_blocking(tmp_path: Path) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    journal = tmp_path / "journal.fifo"
    os.mkfifo(journal)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--trusted-evidence",
            str(trusted_evidence),
            "--manifest-output",
            str(tmp_path / "prepared.json"),
            "--journal-output",
            str(journal),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )

    assert result.returncode == 7
    assert json.loads(result.stderr)["error"]["code"] == "candidate_output_error"


def test_cli_distinguishes_missing_from_failed_acquisition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    artifact.unlink()
    common = [
        "candidate",
        "prepare",
        "--declaration",
        str(declaration),
        "--manifest-output",
        str(tmp_path / "missing.json"),
        "--journal-output",
        str(tmp_path / "journal.json"),
    ]
    assert cli.main(common) == 5
    missing_output = capsys.readouterr()
    assert json.loads(missing_output.out)["status"] == "missing"
    assert missing_output.err == ""

    config = _acquisition_config(tmp_path)

    def unavailable(*args: object, **kwargs: object) -> object:
        raise OSError("simulated offline acquisition")

    monkeypatch.setattr(candidate._acquisition, "_open_remote", unavailable)
    failed_arguments = [
        *common[:-4],
        "--manifest-output",
        str(tmp_path / "failed.json"),
        "--journal-output",
        str(tmp_path / "journal.json"),
        "--acquire",
        "--acquisition-config",
        str(config),
    ]
    assert cli.main(failed_arguments) == 8
    failure_output = capsys.readouterr()
    assert failure_output.out == ""
    assert json.loads(failure_output.err) == {
        "error": {
            "code": "candidate_acquisition_error",
            "message": "bounded acquisition failed: network_error",
        }
    }
    assert not artifact.exists()


def test_cli_uses_distinct_actionable_exit_codes(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    trusted_evidence = _write_trusted_evidence(tmp_path)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = f"{SOURCE_ROOT}{os.pathsep}{ROOT / 'tests'}"
    verify = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "verify",
            "--declaration",
            str(declaration),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify.returncode == 4, verify.stderr
    assert json.loads(verify.stdout)["status"] == "unverified"

    ready = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "verify",
            "--declaration",
            str(declaration),
            "--trusted-evidence",
            str(trusted_evidence),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ready.returncode == 0, ready.stderr
    ready_report = json.loads(ready.stdout)
    assert ready_report["status"] == "ready"
    assert ready_report["evidence"]["apex_execution"] == "unverified"

    payload = _payload(declaration)
    payload["components"] = [
        component
        for component in payload["components"]
        if component["role"] != "tokenizer"
    ]
    _rewrite(declaration, payload)
    incompatible = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "verify",
            "--declaration",
            str(declaration),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert incompatible.returncode == 3
    assert json.loads(incompatible.stdout)["status"] == "incompatible"

    output_error = subprocess.run(
        [
            sys.executable,
            "-m",
            "media_generation",
            "candidate",
            "prepare",
            "--declaration",
            str(declaration),
            "--manifest-output",
            str(tmp_path / "files" / "engine.bin"),
            "--journal-output",
            str(tmp_path / "journal.json"),
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert output_error.returncode == 7
    assert json.loads(output_error.stderr)["error"]["code"] == (
        "candidate_output_error"
    )


def test_load_journal_closes_descriptor_after_malformed_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = tmp_path / "journal.json"
    journal.write_text("{", encoding="utf-8")
    journal_descriptors, parent_descriptors = _track_journal_descriptors(
        monkeypatch,
        journal,
    )

    with pytest.raises(
        candidate.CandidateOutputError,
        match="acquisition journal is not readable or valid",
    ):
        candidate._acquisition._load_journal(journal, declaration=declaration)

    assert len(journal_descriptors) == 1
    assert len(parent_descriptors) == 1
    _assert_descriptor_closed(journal_descriptors[0])
    _assert_descriptor_closed(parent_descriptors[0])


def test_load_journal_closes_descriptor_after_early_read_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = tmp_path / "journal.json"
    journal.write_text("{}", encoding="utf-8")
    journal_descriptors, parent_descriptors = _track_journal_descriptors(
        monkeypatch,
        journal,
    )
    real_fdopen = candidate._acquisition.os.fdopen

    class FailedReader:
        def __enter__(self) -> FailedReader:
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def read(self, _limit: int) -> bytes:
            raise OSError("injected early journal read failure")

    def fail_journal_read(descriptor: int, *args: Any, **kwargs: Any) -> Any:
        if descriptor in journal_descriptors:
            return FailedReader()
        return real_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(
        candidate._acquisition.os,
        "fdopen",
        fail_journal_read,
    )

    with pytest.raises(
        candidate.CandidateOutputError,
        match="acquisition journal is not readable or valid",
    ):
        candidate._acquisition._load_journal(journal, declaration=declaration)

    assert len(journal_descriptors) == 1
    assert len(parent_descriptors) == 1
    _assert_descriptor_closed(journal_descriptors[0])
    _assert_descriptor_closed(parent_descriptors[0])


def test_load_journal_closes_descriptor_after_metadata_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = tmp_path / "journal.json"
    journal.write_text("{}", encoding="utf-8")
    journal_descriptors, parent_descriptors = _track_journal_descriptors(
        monkeypatch,
        journal,
    )
    real_fstat = candidate._acquisition.os.fstat

    def fail_journal_metadata(descriptor: int) -> os.stat_result:
        if descriptor in journal_descriptors:
            raise OSError("injected journal metadata failure")
        return real_fstat(descriptor)

    with monkeypatch.context() as controlled_failure:
        controlled_failure.setattr(
            candidate._acquisition.os,
            "fstat",
            fail_journal_metadata,
        )
        with pytest.raises(
            candidate.CandidateOutputError,
            match="acquisition journal is not readable or valid",
        ):
            candidate._acquisition._load_journal(journal, declaration=declaration)

    assert len(journal_descriptors) == 1
    assert len(parent_descriptors) == 1
    _assert_descriptor_closed(journal_descriptors[0])
    _assert_descriptor_closed(parent_descriptors[0])


def test_load_journal_cleanup_error_does_not_mask_validation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    journal = tmp_path / "journal.json"
    journal.write_text("{", encoding="utf-8")
    journal_descriptors, parent_descriptors = _track_journal_descriptors(
        monkeypatch,
        journal,
    )
    real_open = candidate._acquisition.os.open
    real_close = candidate._acquisition.os.close
    real_open_target = candidate._acquisition._open_output_target
    opened: list[tuple[int, int]] = []
    generations: dict[int, int] = {}
    owned_lifetimes: set[tuple[int, int]] = set()
    close_attempts: dict[tuple[int, int], int] = {}

    def record_open(*args: Any, **kwargs: Any) -> int:
        descriptor = real_open(*args, **kwargs)
        # Revalidation may close a temporary parent before the kernel reuses
        # its number for the journal; track each open's ownership separately.
        generations[descriptor] = len(opened)
        opened.append((descriptor, generations[descriptor]))
        if kwargs.get("dir_fd") is not None and os.fsdecode(args[0]) == journal.name:
            owned_lifetimes.add(opened[-1])
        return descriptor

    def record_target(*args: Any, **kwargs: Any) -> Any:
        target = real_open_target(*args, **kwargs)
        owned_lifetimes.add((target.parent_fd, generations[target.parent_fd]))
        return target

    def close_then_report_error(descriptor: int) -> None:
        lifetime = (descriptor, generations[descriptor])
        close_attempts[lifetime] = close_attempts.get(lifetime, 0) + 1
        real_close(descriptor)
        # A reused number does not inherit an earlier open's cleanup failure.
        if lifetime in owned_lifetimes:
            raise OSError("injected acquisition journal cleanup failure")

    monkeypatch.setattr(candidate._acquisition.os, "open", record_open)
    monkeypatch.setattr(candidate._acquisition.os, "close", close_then_report_error)
    monkeypatch.setattr(candidate._acquisition, "_open_output_target", record_target)

    with pytest.raises(
        candidate.CandidateOutputError,
        match="acquisition journal is not readable or valid",
    ) as failure:
        candidate._acquisition._load_journal(journal, declaration=declaration)

    assert any(
        "acquisition journal cleanup failed" in note
        for note in failure.value.__notes__
    )
    assert len(journal_descriptors) == 1
    assert len(parent_descriptors) == 1
    assert len(owned_lifetimes) == 2
    assert close_attempts == {lifetime: 1 for lifetime in opened}
    _assert_descriptor_closed(journal_descriptors[0])
    _assert_descriptor_closed(parent_descriptors[0])


def test_load_journal_closes_owned_fds_and_preserves_borrowed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declaration_path = _fixture(tmp_path)
    declaration = candidate.parse_candidate(declaration_path)
    journal = tmp_path / "journal.json"
    candidate.prepare_candidate(
        declaration_path,
        manifest_output=tmp_path / "prepared.json",
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    journal_descriptors, parent_descriptors = _track_journal_descriptors(
        monkeypatch,
        journal,
    )

    loaded = candidate._acquisition._load_journal(journal, declaration=declaration)

    assert loaded["candidate_id"] == declaration.stable_candidate_id()
    assert len(journal_descriptors) == 1
    assert len(parent_descriptors) == 1
    _assert_descriptor_closed(journal_descriptors[0])
    _assert_descriptor_closed(parent_descriptors[0])

    borrowed = candidate._acquisition._open_output_target(
        journal,
        label="acquisition journal",
        allow_existing=True,
    )
    borrowed_parent_fd = borrowed.parent_fd
    try:
        candidate._acquisition._load_journal(borrowed, declaration=declaration)

        assert os.fstat(borrowed_parent_fd).st_ino > 0
        assert os.stat(
            borrowed.name,
            dir_fd=borrowed.parent_fd,
            follow_symlinks=False,
        ).st_size > 0
        assert len(journal_descriptors) == 2
        _assert_descriptor_closed(journal_descriptors[1])
    finally:
        borrowed.close()


def test_parse_candidate_accepts_lora_with_adapter_configuration(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "style_adapter", "lora")
    _rewrite(declaration, payload)

    parsed = candidate.parse_candidate(declaration)

    assert [adapter.to_dict() for adapter in parsed.adapters] == [
        {"component_id": "style_adapter", "order": 1, "strength": 0.75}
    ]


def test_parse_candidate_accepts_mixed_adapter_and_lora_configuration(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "vae", "lora")
    payload["adapters"].append(
        {"component_id": "vae", "order": 2, "strength": 0.4}
    )
    _rewrite(declaration, payload)

    parsed = candidate.parse_candidate(declaration)

    assert [adapter.to_dict() for adapter in parsed.adapters] == [
        {"component_id": "style_adapter", "order": 1, "strength": 0.75},
        {"component_id": "vae", "order": 2, "strength": 0.4},
    ]


def test_parse_candidate_does_not_require_lora_without_lora_components(
    tmp_path: Path,
) -> None:
    parsed = candidate.parse_candidate(_fixture(tmp_path))

    assert all(component.role != "lora" for component in parsed.components)
    assert len(parsed.adapters) == 1


def test_parse_candidate_rejects_lora_without_adapter_configuration(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "style_adapter", "lora")
    payload["adapters"] = []
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="every adapter- or lora-role component must have exactly one",
    ):
        candidate.parse_candidate(declaration)


def test_parse_candidate_rejects_duplicate_adapter_configuration(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "style_adapter", "lora")
    payload["adapters"].append(
        {"component_id": "style_adapter", "order": 2, "strength": 0.5}
    )
    _rewrite(declaration, payload)

    with pytest.raises(candidate.CandidateValidationError, match="must be unique"):
        candidate.parse_candidate(declaration)


@pytest.mark.parametrize("order", (1, 3))
def test_parse_candidate_rejects_noncontiguous_adapter_and_lora_order(
    tmp_path: Path,
    order: int,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "vae", "lora")
    payload["adapters"].append(
        {"component_id": "vae", "order": order, "strength": 0.4}
    )
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="adapter order values must be contiguous from 1",
    ):
        candidate.parse_candidate(declaration)


@pytest.mark.parametrize("strength", (True, -10.1, 10.1))
def test_parse_candidate_rejects_invalid_lora_strength(
    tmp_path: Path,
    strength: bool | float,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    _set_component_role(payload, "style_adapter", "lora")
    payload["adapters"][0]["strength"] = strength
    _rewrite(declaration, payload)
    expected_message = (
        "strength must be a number"
        if isinstance(strength, bool)
        else "strength must be between -10 and 10"
    )

    with pytest.raises(candidate.CandidateValidationError, match=expected_message):
        candidate.parse_candidate(declaration)


def test_parse_candidate_rejects_adapter_configuration_for_wrong_role(
    tmp_path: Path,
) -> None:
    declaration = _fixture(tmp_path)
    payload = _payload(declaration)
    payload["adapters"].append(
        {"component_id": "tokenizer", "order": 2, "strength": 0.4}
    )
    _rewrite(declaration, payload)

    with pytest.raises(
        candidate.CandidateValidationError,
        match="must name an adapter- or lora-role component",
    ):
        candidate.parse_candidate(declaration)


@pytest.mark.parametrize(
    "changed_configuration",
    ("strength", "order"),
)
def test_lora_configuration_is_bound_to_identity_manifest_and_trusted_evidence(
    tmp_path: Path,
    changed_configuration: str,
) -> None:
    declaration, trusted = _mixed_adapter_lora_fixture(tmp_path)
    manifest_path = tmp_path / "prepared.json"
    prepared = candidate.prepare_candidate(
        declaration,
        manifest_output=manifest_path,
        journal_output=tmp_path / "journal.json",
        trusted_evidence=trusted,
    )
    assert prepared["status"] == "ready"
    initial_id = prepared["candidate_id"]
    manifest = _payload(manifest_path)
    assert manifest["adapters"] == [
        {"component_id": "style_adapter", "order": 1, "strength": 0.75},
        {"component_id": "vae", "order": 2, "strength": 0.4},
    ]
    compatibility_record = next(
        record
        for record in trusted
        if record.expected.get("schema") == COMPATIBILITY_SCHEMA
    )
    assert compatibility_record.expected["adapters"] == manifest["adapters"]
    assert candidate.parse_candidate(declaration).stable_candidate_id() == initial_id

    payload = _payload(declaration)
    if changed_configuration == "strength":
        payload["adapters"][1]["strength"] = 0.8
    else:
        payload["adapters"] = [
            {"component_id": "vae", "order": 1, "strength": 0.4},
            {"component_id": "style_adapter", "order": 2, "strength": 0.75},
        ]
    _rewrite(declaration, payload)
    stale = candidate.verify_candidate(declaration, trusted_evidence=trusted)
    assert stale["status"] != "ready"
    assert stale["candidate_id"] != initial_id

    updated_trusted = _trust_compatibility_for_fixture(
        tmp_path,
        payload,
        records=trusted,
    )
    _rewrite(declaration, payload)
    reverified = candidate.verify_candidate(
        declaration,
        trusted_evidence=updated_trusted,
    )

    assert reverified["status"] == "ready"
    assert reverified["candidate_id"] != stale["candidate_id"]
