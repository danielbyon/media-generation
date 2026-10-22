"""Strict, versioned declarations for configured inventory work.

A manifest names deliberate model roots and component paths.  It never supplies
command lines, search hooks, or network retrieval instructions.  Runtime
entries may enable one fixed version probe from the built-in catalog.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .catalog import RUNTIME_CATALOG
from .schema import (
    MANIFEST_SCHEMA_NAME,
    MANIFEST_SCHEMA_VERSION,
    InventoryValidationError,
    digest_value,
    load_strict_json,
    reject_unknown_keys,
    require_list,
    require_mapping,
    require_string,
)


MAX_MANIFEST_BYTES = 1024 * 1024
ROLES = frozenset(
    {
        "checkpoint",
        "diffusion_model",
        "text_encoder",
        "vision_encoder",
        "tokenizer",
        "vae",
        "adapter",
        "upscaler",
        "controlnet",
        "projector",
        "other",
    }
)
CAPABILITY_SUPPORT = frozenset({"advertised", "declared"})
SOURCE_KINDS = frozenset({"url", "file", "operator"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TASK = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True, slots=True)
class ModelRoot:
    """One operator-declared directory that may contain model components."""

    id: str
    path: Path


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    """Advertised or operator-declared task support with attribution."""

    task: str
    support: str
    source: dict[str, str]
    notes: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON-compatible declaration."""
        payload: dict[str, object] = {
            "task": self.task,
            "support": self.support,
            "source": dict(self.source),
            "local_execution": "not_performed",
            "qualification": "unqualified",
        }
        if self.notes is not None:
            payload["notes"] = self.notes
        return payload


@dataclass(frozen=True, slots=True)
class ComponentDeclaration:
    """One model component path and its declared role."""

    id: str
    role: str
    path: Path


@dataclass(frozen=True, slots=True)
class RecipeDeclaration:
    """Recipe identity declared inline or by a bounded on-disk file."""

    id: str
    source: dict[str, str] | None
    parameters: dict[str, Any] | None
    path: Path | None


@dataclass(frozen=True, slots=True)
class BundleDeclaration:
    """One engine, recipe, and component set to inspect."""

    id: str
    engine: str
    recipe: RecipeDeclaration
    components: tuple[ComponentDeclaration, ...]
    capabilities: tuple[CapabilityDeclaration, ...]


@dataclass(frozen=True, slots=True)
class RuntimeDeclaration:
    """An explicit runtime path and optional fixed version probe."""

    id: str
    path: Path | None
    probe_version: bool
    capabilities: tuple[CapabilityDeclaration, ...]


@dataclass(frozen=True, slots=True)
class ProbePolicy:
    """Opt-in switches for external device tooling."""

    device_queries: bool = False
    timeout_seconds: float = 5.0


@dataclass(frozen=True, slots=True)
class InventoryManifest:
    """Validated manifest plus its source identity."""

    path: Path
    digest: str
    description: str | None
    model_roots: tuple[ModelRoot, ...]
    runtimes: tuple[RuntimeDeclaration, ...]
    bundles: tuple[BundleDeclaration, ...]
    policy: ProbePolicy


def _identifier(value: object, *, label: str) -> str:
    """Validate one stable declaration identifier."""
    text = require_string(value, label=label)
    if not _IDENTIFIER.match(text):
        raise InventoryValidationError(f"{label} must match {_IDENTIFIER.pattern}")
    return text


def _resolve_path(value: object, *, base: Path, label: str) -> Path:
    """Resolve a declared path relative to the manifest directory."""
    raw = require_string(value, label=label)
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return Path(os.path.abspath(candidate))


def _beneath(candidate: Path, root: Path) -> bool:
    """Return whether ``candidate`` is lexically at or below ``root``."""
    try:
        return os.path.commonpath((str(candidate), str(root))) == str(root)
    except ValueError:  # pragma: no cover - different drives on Windows
        return False


def _resolved_path(path: Path) -> Path | None:
    """Resolve existing symlink ancestors without requiring the final path."""
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def within_model_roots(path: Path, roots: tuple[ModelRoot, ...]) -> bool:
    """Return whether lexical and resolved paths stay inside a model root."""
    real_path = _resolved_path(path)
    if real_path is None:
        return False
    for root in roots:
        real_root = _resolved_path(root.path)
        if real_root is None:
            continue
        if _beneath(path, root.path) and _beneath(real_path, real_root):
            return True
    return False


def _parse_capabilities(value: object, *, label: str) -> tuple[CapabilityDeclaration, ...]:
    """Validate advertised or declared capability attribution."""
    items = require_list(value, label=label)
    result: list[CapabilityDeclaration] = []
    for index, raw in enumerate(items):
        item_label = f"{label}[{index}]"
        item = require_mapping(raw, label=item_label)
        reject_unknown_keys(item, {"task", "support", "source", "notes"}, label=item_label)
        task = require_string(item.get("task"), label=f"{item_label}.task")
        if not _TASK.match(task):
            raise InventoryValidationError(f"{item_label}.task must be a lowercase slug")
        support = require_string(item.get("support"), label=f"{item_label}.support")
        if support not in CAPABILITY_SUPPORT:
            raise InventoryValidationError(
                f"{item_label}.support must be advertised or declared; "
                "tested support cannot be declared"
            )
        source = require_mapping(item.get("source"), label=f"{item_label}.source")
        reject_unknown_keys(
            source,
            {"kind", "value", "retrieved_at", "note"},
            label=f"{item_label}.source",
        )
        kind = require_string(source.get("kind"), label=f"{item_label}.source.kind")
        if kind not in SOURCE_KINDS:
            raise InventoryValidationError(
                f"{item_label}.source.kind must be one of {sorted(SOURCE_KINDS)}"
            )
        source_value = require_string(source.get("value"), label=f"{item_label}.source.value")
        normalized_source = {"kind": kind, "value": source_value}
        for optional in ("retrieved_at", "note"):
            optional_value = source.get(optional)
            if optional_value is not None:
                normalized_source[optional] = require_string(
                    optional_value, label=f"{item_label}.source.{optional}"
                )
        notes = item.get("notes")
        result.append(
            CapabilityDeclaration(
                task=task,
                support=support,
                source=normalized_source,
                notes=require_string(notes, label=f"{item_label}.notes")
                if notes is not None
                else None,
            )
        )
    return tuple(result)


def _parse_recipe(
    raw: object,
    *,
    base: Path,
    roots: tuple[ModelRoot, ...],
    label: str,
) -> RecipeDeclaration:
    """Validate one inline or file-backed recipe declaration."""
    item = require_mapping(raw, label=label)
    reject_unknown_keys(
        item,
        {"id", "source", "parameters", "path"},
        label=label,
    )
    recipe_id = _identifier(item.get("id"), label=f"{label}.id")
    source_raw = item.get("source")
    source: dict[str, str] | None = None
    if source_raw is not None:
        source_item = require_mapping(source_raw, label=f"{label}.source")
        reject_unknown_keys(
            source_item,
            {"kind", "value", "retrieved_at", "note"},
            label=f"{label}.source",
        )
        kind = require_string(source_item.get("kind"), label=f"{label}.source.kind")
        if kind not in SOURCE_KINDS:
            raise InventoryValidationError(
                f"{label}.source.kind must be one of {sorted(SOURCE_KINDS)}"
            )
        source = {
            "kind": kind,
            "value": require_string(
                source_item.get("value"), label=f"{label}.source.value"
            ),
        }
    parameters_raw = item.get("parameters")
    parameters = None
    if parameters_raw is not None:
        parameters = require_mapping(parameters_raw, label=f"{label}.parameters")
    path_raw = item.get("path")
    path = None
    if path_raw is not None:
        path = _resolve_path(path_raw, base=base, label=f"{label}.path")
        if not within_model_roots(path, roots):
            raise InventoryValidationError(f"{label}.path is outside declared model roots")
    if path is not None and (source is not None or parameters is not None):
        raise InventoryValidationError(
            f"{label} must declare either inline recipe fields or a recipe path"
        )
    if path is None and source is None and parameters is None:
        raise InventoryValidationError(
            f"{label} must declare a source, parameters, or a recipe path"
        )
    return RecipeDeclaration(id=recipe_id, source=source, parameters=parameters, path=path)


def parse_manifest(path: Path) -> InventoryManifest:
    """Load and validate one manifest, returning resolved declarations."""
    source_path = Path(os.path.abspath(path.expanduser()))
    try:
        size = source_path.stat().st_size
    except OSError as error:
        raise InventoryValidationError(f"manifest is not readable: {source_path}") from error
    if size > MAX_MANIFEST_BYTES:
        raise InventoryValidationError(
            f"manifest is too large: {size} bytes exceeds {MAX_MANIFEST_BYTES}"
        )
    payload = load_strict_json(
        source_path, label="manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    data = require_mapping(payload, label="manifest")
    reject_unknown_keys(
        data,
        {
            "schema",
            "schema_version",
            "description",
            "model_roots",
            "runtimes",
            "bundles",
            "probe_policy",
        },
        label="manifest",
    )
    if data.get("schema") != MANIFEST_SCHEMA_NAME:
        raise InventoryValidationError(f"manifest schema must be {MANIFEST_SCHEMA_NAME!r}")
    if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise InventoryValidationError(
            f"unsupported manifest schema_version: {data.get('schema_version')!r}"
        )
    description_raw = data.get("description")
    description = (
        require_string(description_raw, label="manifest.description")
        if description_raw is not None
        else None
    )
    base = source_path.parent
    roots: list[ModelRoot] = []
    for index, raw in enumerate(require_list(data.get("model_roots", []), label="model_roots")):
        label = f"model_roots[{index}]"
        item = require_mapping(raw, label=label)
        reject_unknown_keys(item, {"id", "path"}, label=label)
        roots.append(
            ModelRoot(
                id=_identifier(item.get("id"), label=f"{label}.id"),
                path=_resolve_path(item.get("path"), base=base, label=f"{label}.path"),
            )
        )
    root_ids = [root.id for root in roots]
    if len(root_ids) != len(set(root_ids)):
        raise InventoryValidationError("model_roots ids must be unique")

    runtimes: list[RuntimeDeclaration] = []
    for index, raw in enumerate(require_list(data.get("runtimes", []), label="runtimes")):
        label = f"runtimes[{index}]"
        item = require_mapping(raw, label=label)
        reject_unknown_keys(
            item,
            {"id", "path", "probe_version", "declared_capabilities"},
            label=label,
        )
        runtime_id = require_string(item.get("id"), label=f"{label}.id")
        if runtime_id not in RUNTIME_CATALOG:
            raise InventoryValidationError(
                f"{label}.id is not a supported runtime: {runtime_id!r}"
            )
        path_raw = item.get("path")
        if "path" in item and RUNTIME_CATALOG[runtime_id].kind == "python_distribution":
            raise InventoryValidationError(
                f"{label}.path is not supported for Python distributions"
            )
        runtime_path = (
            _resolve_path(path_raw, base=base, label=f"{label}.path")
            if path_raw is not None
            else None
        )
        probe_version = item.get("probe_version", False)
        if not isinstance(probe_version, bool):
            raise InventoryValidationError(f"{label}.probe_version must be a boolean")
        if probe_version and RUNTIME_CATALOG[runtime_id].version_argv is None:
            raise InventoryValidationError(
                f"{label} cannot enable a version probe for {runtime_id!r}"
            )
        capabilities = _parse_capabilities(
            item.get("declared_capabilities", []),
            label=f"{label}.declared_capabilities",
        )
        runtimes.append(
            RuntimeDeclaration(
                id=runtime_id,
                path=runtime_path,
                probe_version=probe_version,
                capabilities=capabilities,
            )
        )
    runtime_ids = [runtime.id for runtime in runtimes]
    if len(runtime_ids) != len(set(runtime_ids)):
        raise InventoryValidationError("runtime ids must be unique")

    bundles: list[BundleDeclaration] = []
    for index, raw in enumerate(require_list(data.get("bundles", []), label="bundles")):
        label = f"bundles[{index}]"
        item = require_mapping(raw, label=label)
        reject_unknown_keys(
            item,
            {"id", "engine", "recipe", "components", "declared_capabilities"},
            label=label,
        )
        bundle_id = _identifier(item.get("id"), label=f"{label}.id")
        engine = require_string(item.get("engine"), label=f"{label}.engine")
        if engine not in RUNTIME_CATALOG:
            raise InventoryValidationError(
                f"{label}.engine is not a supported runtime: {engine!r}"
            )
        if not roots:
            raise InventoryValidationError(
                f"{label} requires at least one declared model root"
            )
        recipe = _parse_recipe(item.get("recipe"), base=base, roots=tuple(roots), label=f"{label}.recipe")
        component_items = require_list(item.get("components"), label=f"{label}.components")
        if not component_items:
            raise InventoryValidationError(f"{label}.components must not be empty")
        components: list[ComponentDeclaration] = []
        for component_index, component_raw in enumerate(component_items):
            component_label = f"{label}.components[{component_index}]"
            component = require_mapping(component_raw, label=component_label)
            reject_unknown_keys(component, {"id", "role", "path"}, label=component_label)
            role = require_string(component.get("role"), label=f"{component_label}.role")
            if role not in ROLES:
                raise InventoryValidationError(
                    f"{component_label}.role must be one of {sorted(ROLES)}"
                )
            component_path = _resolve_path(
                component.get("path"), base=base, label=f"{component_label}.path"
            )
            if not within_model_roots(component_path, tuple(roots)):
                raise InventoryValidationError(
                    f"{component_label}.path is outside declared model roots"
                )
            components.append(
                ComponentDeclaration(
                    id=_identifier(component.get("id"), label=f"{component_label}.id"),
                    role=role,
                    path=component_path,
                )
            )
        component_ids = [component.id for component in components]
        if len(component_ids) != len(set(component_ids)):
            raise InventoryValidationError(f"{label}.components ids must be unique")
        bundles.append(
            BundleDeclaration(
                id=bundle_id,
                engine=engine,
                recipe=recipe,
                components=tuple(components),
                capabilities=_parse_capabilities(
                    item.get("declared_capabilities", []),
                    label=f"{label}.declared_capabilities",
                ),
            )
        )
    bundle_ids = [bundle.id for bundle in bundles]
    if len(bundle_ids) != len(set(bundle_ids)):
        raise InventoryValidationError("bundle ids must be unique")

    policy_raw = data.get("probe_policy", {})
    policy_item = require_mapping(policy_raw, label="probe_policy")
    reject_unknown_keys(
        policy_item,
        {"device_queries", "timeout_seconds"},
        label="probe_policy",
    )
    device_queries = policy_item.get("device_queries", False)
    if not isinstance(device_queries, bool):
        raise InventoryValidationError("probe_policy.device_queries must be a boolean")
    timeout_seconds = policy_item.get("timeout_seconds", 5.0)
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise InventoryValidationError("probe_policy.timeout_seconds must be a number")
    if not 1.0 <= float(timeout_seconds) <= 30.0:
        raise InventoryValidationError("probe_policy.timeout_seconds must be between 1 and 30")
    return InventoryManifest(
        path=source_path,
        digest=digest_value(data),
        description=description,
        model_roots=tuple(roots),
        runtimes=tuple(runtimes),
        bundles=tuple(bundles),
        policy=ProbePolicy(
            device_queries=device_queries,
            timeout_seconds=float(timeout_seconds),
        ),
    )


def empty_manifest() -> InventoryManifest:
    """Return the explicit not-configured state used when no manifest is given."""
    return InventoryManifest(
        path=Path(""),
        digest="",
        description=None,
        model_roots=(),
        runtimes=(),
        bundles=(),
        policy=ProbePolicy(),
    )
