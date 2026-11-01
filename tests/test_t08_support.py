"""Imported test support for synthetic T07 bundles and conformance engines.

This module is imported by backend execution tests. It intentionally contains
no pytest-collectable tests; the test_* filename keeps the helper within the
run's authorized test scope. Every artifact is tiny, generated inside a pytest
temporary directory, and pinned to actual bytes. Separately authorized evidence
records are built from the same generated documents. Nothing is model-sized and
no private data enters the repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from media_generation import candidate
from media_generation.privacy import LOCAL_INFERENCE_ENGINE_VERSION

PROVENANCE_SCHEMA = "media-generation.candidate-provenance-evidence"
LICENSE_SCHEMA = "media-generation.candidate-license-evidence"
CONVERSION_SCHEMA = "media-generation.candidate-conversion-evidence"
COMPATIBILITY_SCHEMA = "media-generation.candidate-compatibility-evidence"

CONFORMANCE_SOURCE = Path(__file__).resolve().parent / "fixtures" / "conformance-engine.py"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(files: Path, name: str, payload: object) -> dict[str, object]:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    (files / name).write_bytes(data)
    return {
        "root": "files",
        "path": name,
        "size_bytes": len(data),
        "sha256": _sha256(data),
    }


def _pin(files: Path, name: str) -> dict[str, object]:
    data = (files / name).read_bytes()
    return {
        "root": "files",
        "path": name,
        "size_bytes": len(data),
        "sha256": _sha256(data),
    }


def _subject(kind: str, identifier: str, role: str, artifact: dict[str, object]) -> dict[str, object]:
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
) -> tuple[dict[str, object], dict[str, object]]:
    evidence_name = f"{identifier}-provenance.json"
    document = {
        "schema": PROVENANCE_SCHEMA,
        "schema_version": 1,
        "publisher": "Synthetic publisher",
        "revision": revision,
        "source_url": "https://models.example/source",
        "subject": _subject(kind, identifier, role, artifact),
    }
    pin = _write_json(files, evidence_name, document)
    declaration = {
        "publisher": "Synthetic publisher",
        "revision": revision,
        "canonical_url": "https://models.example/source",
        "evidence": pin,
    }
    return declaration, document


def _license(
    files: Path,
    artifact: dict[str, object],
    *,
    kind: str,
    identifier: str,
    role: str,
) -> tuple[dict[str, object], dict[str, object]]:
    evidence_name = f"{identifier}-license.json"
    document = {
        "schema": LICENSE_SCHEMA,
        "schema_version": 1,
        "subject": _subject(kind, identifier, role, artifact),
        "license": {
            "name": "Synthetic terms",
            "spdx": "LicenseRef-Test",
            "terms_url": "https://licenses.example/terms",
        },
    }
    pin = _write_json(files, evidence_name, document)
    declaration = {
        "name": "Synthetic terms",
        "spdx": "LicenseRef-Test",
        "terms_url": "https://licenses.example/terms",
        "evidence": pin,
    }
    return declaration, document


def _component(
    files: Path,
    identifier: str,
    role: str,
    filename: str,
    data: bytes,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    (files / filename).write_bytes(data)
    artifact = _pin(files, filename)
    provenance, provenance_document = _provenance(
        files,
        f"{identifier}-revision",
        artifact,
        kind="component",
        identifier=identifier,
        role=role,
    )
    license_declaration, license_document = _license(
        files,
        artifact,
        kind="component",
        identifier=identifier,
        role=role,
    )
    conversion_name = f"{identifier}-conversion.json"
    conversion_document = {
        "schema": CONVERSION_SCHEMA,
        "schema_version": 1,
        "subject": _subject("component", identifier, role, artifact),
        "conversion": {"lineage": "original", "tool": None},
    }
    conversion_pin = _write_json(files, conversion_name, conversion_document)
    declaration = {
        "id": identifier,
        "role": role,
        "artifact": artifact,
        "provenance": provenance,
        "license": license_declaration,
        "precision": "bf16",
        "quantization": "none",
        "conversion": {
            "lineage": "original",
            "tool": None,
            "evidence": conversion_pin,
        },
    }
    expected = {
        "provenance": provenance_document,
        "license": license_document,
        "conversion": conversion_document,
    }
    return declaration, expected, artifact


def _compatibility_document(
    engine: dict[str, Any],
    recipe: dict[str, Any],
    components: list[dict[str, Any]],
    adapters: list[dict[str, Any]],
    claims: list[str],
) -> dict[str, Any]:
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
                "size_bytes": engine["executable"]["size_bytes"],
                "sha256": engine["executable"]["sha256"],
            },
        },
        "recipe": {
            "id": recipe["id"],
            "document": {
                "size_bytes": recipe["document"]["size_bytes"],
                "sha256": recipe["document"]["sha256"],
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
                            "size_bytes": component["artifact"]["size_bytes"],
                            "sha256": component["artifact"]["sha256"],
                            "precision": component["precision"],
                            "quantization": component["quantization"],
                        }
                        for component in components
                        if component["role"] == role
                    ],
                    key=lambda item: str(item["id"]),
                ),
            }
            for role in recipe["required_component_roles"]
        ],
        "components": sorted(
            [
                {
                    "id": component["id"],
                    "role": component["role"],
                    "size_bytes": component["artifact"]["size_bytes"],
                    "sha256": component["artifact"]["sha256"],
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


@dataclass(frozen=True, slots=True)
class EngineBundle:
    """Paths and declarations for one synthetic ready T07 bundle."""

    tmp_path: Path
    files: Path
    declaration_path: Path
    trusted_evidence_path: Path
    engine_path: Path
    recipe_path: Path
    component_paths: dict[str, Path]
    recipe_document: dict[str, Any]
    declaration: dict[str, Any]

    def set_mode(self, **settings: object) -> None:
        """Configure the conformance executable's observable behavior."""
        (self.files / "conformance-mode.json").write_text(
            json.dumps(settings), encoding="utf-8"
        )


def default_recipe_document(
    *,
    recipe_id: str = "qwen-image-edit-2511-recipe",
    roles: tuple[str, ...] = ("diffusion_model", "vae", "text_encoder"),
    edit_model_args: tuple[str, ...] = ("qwen_image_zero_cond_t=true",),
    sampling: dict[str, object] | None = None,
) -> dict[str, Any]:
    """Return the documented invocation recipe used by the bundle builder."""
    values: dict[str, object] = {
        "sampling_method": "euler",
        "steps": 8,
        "cfg_scale": 2.5,
        "flow_shift": 3.0,
        "strength": None,
    }
    if sampling is not None:
        values.update(sampling)
    return {
        "schema": "media-generation.sd-cpp-recipe",
        "schema_version": 1,
        "id": recipe_id,
        "engine_id": "stable-diffusion.cpp",
        "operations": {
            "generate": {
                "required_component_roles": list(roles),
                "model_args": [],
                "sampling": dict(values),
            },
            "edit": {
                "required_component_roles": list(roles),
                "model_args": list(edit_model_args),
                "sampling": dict(values),
            },
        },
        "limits": {
            "max_width": 512,
            "max_height": 512,
            "max_references": 3,
            "max_source_images": 1,
        },
    }


def build_bundle(
    tmp_path: Path,
    *,
    cli_contract: str = "model-args/v1",
    engine_cli_contract: str | None = None,
    recipe_cli_contract: str | None = None,
    backend: str = "rocm",
    include_vision: bool = False,
    include_tokenizer: bool = False,
    component_roles: tuple[str, ...] | None = None,
    extra_component_roles: tuple[str, ...] = (),
    adapters: list[dict[str, object]] | None = None,
    recipe_document: dict[str, Any] | None = None,
    trusted_evidence: bool = True,
) -> EngineBundle:
    """Create a tiny, pinned T07 candidate and its separate evidence file."""
    root = tmp_path / "bundle"
    files = root / "files"
    files.mkdir(parents=True)
    engine_path = files / "conformance-engine.py"
    engine_path.write_bytes(CONFORMANCE_SOURCE.read_bytes())
    engine_path.chmod(0o755)

    roles = (
        list(component_roles)
        if component_roles is not None
        else ["diffusion_model", "vae", "text_encoder"]
    )
    if include_vision:
        roles.append("vision_encoder")
    if include_tokenizer:
        roles.append("tokenizer")
    declared_roles = list(roles) + list(extra_component_roles)
    recipe_payload = recipe_document or default_recipe_document(roles=tuple(roles))
    recipe_path = _write_json(files, "recipe.json", recipe_payload)
    (files / "recipe.json").write_bytes(
        (json.dumps(recipe_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    recipe_path = _pin(files, "recipe.json")

    components: list[dict[str, Any]] = []
    expected_documents: dict[str, dict[str, object]] = {}
    component_paths: dict[str, Path] = {}
    contents = {
        "diffusion_model": (
            "qwen-image-edit-2511-diffusion.gguf",
            b"synthetic-qwen-edit-2511-diffusion-weights",
        ),
        "vae": ("qwen_image_vae.safetensors", b"synthetic-qwen-image-vae-weights"),
        "text_encoder": ("qwen2.5-vl-7b.gguf", b"synthetic-qwen25-vl-weights"),
        "vision_encoder": ("qwen2.5-vl-mmproj.gguf", b"synthetic-mmproj-weights"),
        "tokenizer": ("tokenizer.json", b'{"tokenizer":"synthetic"}'),
    }
    for role in declared_roles:
        identifier = f"qwen-image-edit-2511-{role.replace('_', '-')}"
        filename, data = contents[role]
        declaration, expected, artifact = _component(
            files, identifier, role, filename, data
        )
        components.append(declaration)
        component_paths[role] = files / filename
        expected_documents[identifier] = expected

    engine_artifact = _pin(files, "conformance-engine.py")
    engine_provenance, engine_provenance_document = _provenance(
        files,
        "engine-revision",
        engine_artifact,
        kind="engine",
        identifier="stable-diffusion.cpp",
        role="engine",
    )
    engine_license, engine_license_document = _license(
        files,
        engine_artifact,
        kind="engine",
        identifier="stable-diffusion.cpp",
        role="engine",
    )
    engine_flags: dict[str, object] = {
        "sd_cpp_cli_contract": engine_cli_contract or cli_contract,
        "qwen_image_zero_cond_t": True,
        "backend": backend,
    }
    engine: dict[str, Any] = {
        "id": "stable-diffusion.cpp",
        "version": LOCAL_INFERENCE_ENGINE_VERSION,
        "build": "rocm-6.4",
        "executable": engine_artifact,
        "provenance": engine_provenance,
        "license": engine_license,
        "architecture_flags": engine_flags,
    }
    recipe_flags: dict[str, object] = {
        "sd_cpp_cli_contract": recipe_cli_contract or cli_contract,
        "qwen_image_zero_cond_t": True,
    }
    claims = [
        "engine",
        "version",
        "recipe",
        *(f"role:{role}" for role in roles),
        *(f"flag:{name}" for name in recipe_flags),
    ]
    recipe: dict[str, Any] = {
        "id": recipe_payload["id"],
        "document": recipe_path,
        "required_component_roles": roles,
        "engine_id": "stable-diffusion.cpp",
        "engine_version": LOCAL_INFERENCE_ENGINE_VERSION,
        "pipeline_version": "qwen-image-edit-2511-pipeline@1",
        "template_version": "qwen-edit-reference@1",
        "architecture_flags": recipe_flags,
    }
    adapters = [] if adapters is None else adapters
    compatibility = _compatibility_document(engine, recipe, components, adapters, claims)
    compatibility_pin = _write_json(files, "compatibility.json", compatibility)
    recipe["compatibility_evidence"] = [
        {"claims": claims, "document": compatibility_pin}
    ]
    declaration: dict[str, Any] = {
        "schema": "media-generation.candidate-declaration",
        "schema_version": 1,
        "id": "t08-qwen-edit-2511-candidate",
        "roots": [{"id": "files", "path": "files"}],
        "engine": engine,
        "recipe": recipe,
        "components": components,
        "adapters": adapters,
    }
    declaration_path = root / "candidate.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")

    records: list[candidate.TrustedEvidence] = []

    def add(document: dict[str, object]) -> None:
        data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        records.append(
            candidate.TrustedEvidence(
                authority_id=f"t08-authority-{len(records) + 1}",
                document_size_bytes=len(data),
                document_sha256=_sha256(data),
                expected=json.loads(data),
            )
        )

    for _, documents in sorted(expected_documents.items()):
        add(documents["provenance"])
        add(documents["license"])
        add(documents["conversion"])
    add(engine_provenance_document)
    add(engine_license_document)
    add(compatibility)
    trusted_path = root / "trusted-evidence.json"
    trusted_path.write_text(
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
                    for record in records
                ],
            }
        ),
        encoding="utf-8",
    )
    return EngineBundle(
        tmp_path=tmp_path,
        files=files,
        declaration_path=declaration_path,
        trusted_evidence_path=trusted_path,
        engine_path=engine_path,
        recipe_path=files / "recipe.json",
        component_paths=component_paths,
        recipe_document=recipe_payload,
        declaration=declaration,
    )


def heavy_admission_profile():
    """Return deterministic capacity evidence that admits heavyweight jobs."""
    from media_generation.admission import build_admission_profile, parse_admission_policy
    from test_resource_admission import GIB, inventory_report

    return build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 8 * GIB},
            }
        ),
    )


def heavy_workload_demand():
    """Return explicit known memory demand that fits the synthetic profile."""
    from media_generation.admission import parse_workload_demand
    from test_resource_admission import workload_demand

    return parse_workload_demand(workload_demand())
