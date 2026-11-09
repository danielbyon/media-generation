"""Bind ComfyUI node registrations to deterministic source bundles.

The module parses Python source without importing it, builds canonical ZIP
components, and verifies those components against independently signed
ComfyUI source roots. Production callers still need a trusted runtime pin and
a T07 candidate component; this module does not create either authority.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import stat
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from .backend_provenance import canonical_json


NODE_AUTHORITY_SCHEMA = "media-generation.comfyui-node-implementations"
NODE_AUTHORITY_SCHEMA_VERSION = 3
NODE_AUTHORITY_MANIFEST_SCHEMA = "media-generation.comfyui-node-sources-manifest"
NODE_AUTHORITY_MANIFEST_SCHEMA_VERSION = 1

MAX_NODE_AUTHORITY_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_NODE_AUTHORITY_MANIFEST_BYTES = 256 * 1024
MAX_NODE_SOURCES = 64
MAX_NODE_SOURCE_BYTES = 8 * 1024 * 1024
MAX_NODE_SOURCE_PATH_BYTES = 1024
MAX_NODE_SOURCE_DEPTH = 8
MAX_NODE_CLASSES = 256

_SHA256_LENGTH = 64
_NODE_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_REGISTRATION_APIS = frozenset({"INPUT_TYPES", "define_schema"})
_INPUT_CATEGORIES = ("required", "optional", "hidden")
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
_ZIP_MODE = stat.S_IFREG | 0o644
_READ_CHUNK_BYTES = 1024 * 1024


class NodeAuthorityError(ValueError):
    """A node-authority document, source bundle, or signed root is invalid."""


@dataclass(frozen=True, slots=True)
class SourcePin:
    path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class NodeInputs:
    required: tuple[str, ...]
    optional: tuple[str, ...]
    hidden: tuple[str, ...]

    @property
    def graph_inputs(self) -> frozenset[str]:
        return frozenset((*self.required, *self.optional))

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "required": list(self.required),
            "optional": list(self.optional),
            "hidden": list(self.hidden),
        }


@dataclass(frozen=True, slots=True)
class NodePin:
    component_id: str
    component_sha256: str
    source_path: str
    registration_api: str
    inputs: NodeInputs


@dataclass(frozen=True, slots=True)
class NodeAuthority:
    tool_id: str
    tool_version: str
    source_root_sha256: str
    component_id: str
    component_size_bytes: int
    component_sha256: str
    sources: tuple[SourcePin, ...]
    nodes: Mapping[str, NodePin]


@dataclass(frozen=True, slots=True)
class GeneratedNodeAuthority:
    archive: bytes
    document: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _ManifestNode:
    source_path: str
    registration_api: str
    inputs: NodeInputs


def parse_node_authority(value: object) -> NodeAuthority:
    """Validate the exact node-authority v3 document shape."""

    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "schema_version",
        "tool_id",
        "tool_version",
        "source_root_sha256",
        "component",
        "sources",
        "nodes",
    }:
        raise NodeAuthorityError("node-authority v3 fields are invalid")
    if (
        value.get("schema") != NODE_AUTHORITY_SCHEMA
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != NODE_AUTHORITY_SCHEMA_VERSION
    ):
        raise NodeAuthorityError("node-authority schema or version is unsupported")
    tool_id = value.get("tool_id")
    tool_version = value.get("tool_version")
    if not isinstance(tool_id, str) or not tool_id:
        raise NodeAuthorityError("node-authority tool id is invalid")
    if not isinstance(tool_version, str) or not tool_version:
        raise NodeAuthorityError("node-authority tool version is invalid")
    source_root_sha256 = _sha256(value.get("source_root_sha256"), label="source root")
    component = value.get("component")
    if not isinstance(component, Mapping) or set(component) != {
        "id",
        "size_bytes",
        "sha256",
    }:
        raise NodeAuthorityError("node-authority component is invalid")
    component_id = component.get("id")
    component_size = component.get("size_bytes")
    if not isinstance(component_id, str) or not component_id:
        raise NodeAuthorityError("node-authority component id is invalid")
    if (
        type(component_size) is not int
        or not 1 <= component_size <= MAX_NODE_AUTHORITY_ARCHIVE_BYTES
    ):
        raise NodeAuthorityError("node-authority component size is invalid")
    component_sha256 = _sha256(component.get("sha256"), label="component")
    sources = _parse_sources(value.get("sources"))
    nodes = _parse_nodes(
        value.get("nodes"),
        sources=sources,
        component_id=component_id,
        component_sha256=component_sha256,
    )
    return NodeAuthority(
        tool_id=tool_id,
        tool_version=tool_version,
        source_root_sha256=source_root_sha256,
        component_id=component_id,
        component_size_bytes=component_size,
        component_sha256=component_sha256,
        sources=sources,
        nodes=MappingProxyType(nodes),
    )


def generate_node_authority(
    *,
    source_root: Path,
    source_paths: Sequence[str],
    classes: Sequence[str],
    source_root_sha256: str,
    tool_id: str,
    tool_version: str,
    component_id: str,
) -> GeneratedNodeAuthority:
    """Generate a canonical node bundle and its v3 authority document.

    Callers provide the independently signed source-root and T07 component
    identities. This function returns bytes and a document for review; it does
    not publish or activate either one.
    """

    if not isinstance(tool_id, str) or not tool_id:
        raise NodeAuthorityError("node-authority tool id is invalid")
    if not isinstance(tool_version, str) or not tool_version:
        raise NodeAuthorityError("node-authority tool version is invalid")
    if not isinstance(component_id, str) or not component_id:
        raise NodeAuthorityError("node-authority component id is invalid")
    root_digest = _sha256(source_root_sha256, label="source root")
    root = _resolve_source_root(source_root)
    paths = _parse_source_path_list(source_paths)
    class_names = _parse_class_list(classes)
    source_bytes = {
        path: _read_relative_source(root / path, maximum=MAX_NODE_SOURCE_BYTES)
        for path in paths
    }
    manifest_nodes = _parse_registrations(source_bytes, class_names)
    source_pins = tuple(
        SourcePin(
            path=path,
            size_bytes=len(source_bytes[path]),
            sha256=hashlib.sha256(source_bytes[path]).hexdigest(),
        )
        for path in paths
    )
    manifest = {
        "schema": NODE_AUTHORITY_MANIFEST_SCHEMA,
        "schema_version": NODE_AUTHORITY_MANIFEST_SCHEMA_VERSION,
        "source_root_sha256": root_digest,
        "sources": [_source_to_dict(item) for item in source_pins],
        "nodes": {
            name: _manifest_node_to_dict(manifest_nodes[name])
            for name in class_names
        },
    }
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")
    if len(manifest_bytes) > MAX_NODE_AUTHORITY_MANIFEST_BYTES:
        raise NodeAuthorityError("node-authority manifest exceeds its size limit")
    archive = _build_archive(manifest_bytes, source_bytes)
    component_sha256 = hashlib.sha256(archive).hexdigest()
    nodes = {
        name: {
            "component_id": component_id,
            "component_sha256": component_sha256,
            **_manifest_node_to_dict(manifest_nodes[name]),
        }
        for name in class_names
    }
    document = {
        "schema": NODE_AUTHORITY_SCHEMA,
        "schema_version": NODE_AUTHORITY_SCHEMA_VERSION,
        "tool_id": tool_id,
        "tool_version": tool_version,
        "source_root_sha256": root_digest,
        "component": {
            "id": component_id,
            "size_bytes": len(archive),
            "sha256": component_sha256,
        },
        "sources": [_source_to_dict(item) for item in source_pins],
        "nodes": nodes,
    }
    parse_node_authority(document)
    return GeneratedNodeAuthority(
        archive=archive,
        document=document,
    )


def verify_node_authority(
    authority: NodeAuthority,
    archive: bytes,
    *,
    expected_component_id: str,
    expected_component_size_bytes: int,
    expected_component_sha256: str,
    source_root: Path,
    signed_source_root_sha256: str,
) -> None:
    """Verify a ZIP, its AST contracts, T07 identity, and signed source root."""

    if not isinstance(authority, NodeAuthority):
        raise TypeError("authority must be a NodeAuthority")
    signed_root = _sha256(signed_source_root_sha256, label="signed source root")
    if authority.source_root_sha256 != signed_root:
        raise NodeAuthorityError(
            "node-authority source root does not match the signed source root"
        )
    verify_node_authority_component(
        authority,
        archive,
        expected_component_id=expected_component_id,
        expected_component_size_bytes=expected_component_size_bytes,
        expected_component_sha256=expected_component_sha256,
    )
    _verify_sources(authority, source_root=source_root)


def verify_node_authority_component(
    authority: NodeAuthority,
    archive: bytes,
    *,
    expected_component_id: str,
    expected_component_size_bytes: int,
    expected_component_sha256: str,
) -> None:
    """Verify a node ZIP against an independently pinned T07 component."""

    if not isinstance(authority, NodeAuthority):
        raise TypeError("authority must be a NodeAuthority")
    if authority.component_id != expected_component_id:
        raise NodeAuthorityError("node-authority component id does not match T07")
    if authority.component_size_bytes != expected_component_size_bytes:
        raise NodeAuthorityError("node-authority component size does not match T07")
    expected_component_sha256 = _sha256(
        expected_component_sha256, label="component"
    )
    if authority.component_sha256 != expected_component_sha256:
        raise NodeAuthorityError("node-authority component sha256 does not match T07")
    manifest, source_bytes = _verify_archive(authority, archive)
    _verify_manifest(authority, manifest)
    _verify_registrations(source_bytes, authority)


def _parse_sources(value: object) -> tuple[SourcePin, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_NODE_SOURCES
    ):
        raise NodeAuthorityError("node-authority source pins are incomplete")
    pins: list[SourcePin] = []
    casefolded: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {
            "path",
            "size_bytes",
            "sha256",
        }:
            raise NodeAuthorityError("node-authority source pin is malformed")
        path = _source_path(raw.get("path"))
        size = raw.get("size_bytes")
        if type(size) is not int or not 0 <= size <= MAX_NODE_SOURCE_BYTES:
            raise NodeAuthorityError("node-authority source size is invalid")
        folded = path.casefold()
        if folded in casefolded:
            raise NodeAuthorityError("node-authority source paths are duplicate")
        casefolded.add(folded)
        pins.append(
            SourcePin(
                path=path,
                size_bytes=size,
                sha256=_sha256(raw.get("sha256"), label="source"),
            )
        )
    if tuple(item.path for item in pins) != tuple(
        sorted((item.path for item in pins), key=_path_order)
    ):
        raise NodeAuthorityError("node-authority sources must be sorted")
    return tuple(pins)


def _parse_nodes(
    value: object,
    *,
    sources: Sequence[SourcePin],
    component_id: str,
    component_sha256: str,
) -> dict[str, NodePin]:
    if not isinstance(value, Mapping) or not value or len(value) > MAX_NODE_CLASSES:
        raise NodeAuthorityError("node-authority nodes are incomplete")
    source_paths = {item.path for item in sources}
    result: dict[str, NodePin] = {}
    for class_name, raw in value.items():
        if not isinstance(class_name, str) or _NODE_CLASS.fullmatch(class_name) is None:
            raise NodeAuthorityError("node-authority class name is invalid")
        if not isinstance(raw, Mapping) or set(raw) != {
            "component_id",
            "component_sha256",
            "source_path",
            "registration_api",
            "inputs",
        }:
            raise NodeAuthorityError("node-authority node pin is malformed")
        if raw.get("component_id") != component_id:
            raise NodeAuthorityError("node-authority node component id disagrees")
        if raw.get("component_sha256") != component_sha256:
            raise NodeAuthorityError("node-authority node component sha256 disagrees")
        source_path = _source_path(raw.get("source_path"))
        if source_path not in source_paths:
            raise NodeAuthorityError("node-authority node source path is missing")
        registration_api = raw.get("registration_api")
        if registration_api not in _REGISTRATION_APIS:
            raise NodeAuthorityError("node-authority registration API is unsupported")
        inputs = _parse_inputs(raw.get("inputs"))
        result[class_name] = NodePin(
            component_id=component_id,
            component_sha256=component_sha256,
            source_path=source_path,
            registration_api=str(registration_api),
            inputs=inputs,
        )
    if {item.source_path for item in result.values()} != source_paths:
        raise NodeAuthorityError("node-authority sources contain unreferenced entries")
    return {name: result[name] for name in sorted(result)}


def _parse_inputs(value: object) -> NodeInputs:
    if not isinstance(value, Mapping) or set(value) != set(_INPUT_CATEGORIES):
        raise NodeAuthorityError("node-authority input categories are invalid")
    parsed: dict[str, tuple[str, ...]] = {}
    seen: set[str] = set()
    for category in _INPUT_CATEGORIES:
        raw_names = value.get(category)
        if not isinstance(raw_names, list) or any(
            not isinstance(name, str) or not name for name in raw_names
        ):
            raise NodeAuthorityError("node-authority input names are invalid")
        if tuple(raw_names) != tuple(sorted(raw_names)):
            raise NodeAuthorityError("node-authority input names must be sorted")
        if len(raw_names) != len(set(raw_names)):
            raise NodeAuthorityError("node-authority input names are duplicated")
        for name in raw_names:
            if name in seen:
                raise NodeAuthorityError(
                    "node-authority input categories are not disjoint"
                )
            seen.add(name)
        parsed[category] = tuple(raw_names)
    return NodeInputs(**parsed)


def _parse_manifest_node(value: object) -> _ManifestNode:
    if not isinstance(value, Mapping) or set(value) != {
        "source_path",
        "registration_api",
        "inputs",
    }:
        raise NodeAuthorityError("node-authority manifest node is malformed")
    registration_api = value.get("registration_api")
    if registration_api not in _REGISTRATION_APIS:
        raise NodeAuthorityError("node-authority registration API is unsupported")
    return _ManifestNode(
        source_path=_source_path(value.get("source_path")),
        registration_api=str(registration_api),
        inputs=_parse_inputs(value.get("inputs")),
    )


def _verify_archive(
    authority: NodeAuthority, archive: bytes
) -> tuple[dict[str, object], dict[str, bytes]]:
    if not isinstance(archive, bytes) or not archive:
        raise NodeAuthorityError("node-authority archive is missing")
    if len(archive) > MAX_NODE_AUTHORITY_ARCHIVE_BYTES:
        raise NodeAuthorityError("node-authority archive exceeds its size limit")
    actual_sha256 = hashlib.sha256(archive).hexdigest()
    if actual_sha256 != authority.component_sha256:
        raise NodeAuthorityError("node-authority component sha256 does not match archive")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as bundle:
            if bundle.comment:
                raise NodeAuthorityError("node-authority archive comment is unsupported")
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            if names != sorted(names, key=_path_order):
                raise NodeAuthorityError("node-authority archive members must be sorted")
            if len(names) != len(set(names)) or len({name.casefold() for name in names}) != len(names):
                raise NodeAuthorityError("node-authority archive member paths are duplicate")
            expected = ["manifest.json"] + [
                f"sources/{item.path}" for item in authority.sources
            ]
            if names != expected:
                raise NodeAuthorityError("node-authority archive member set is invalid")
            contents: dict[str, bytes] = {}
            for info in infos:
                _validate_zip_info(info, manifest=info.filename == "manifest.json")
                contents[info.filename] = _read_zip_member(bundle, info)
    except NodeAuthorityError:
        raise
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as error:
        raise NodeAuthorityError("node-authority archive is malformed") from error

    manifest_bytes = contents["manifest.json"]
    manifest = _strict_json(manifest_bytes, label="node-authority manifest")
    if not isinstance(manifest, dict):
        raise NodeAuthorityError("node-authority manifest must be an object")
    if manifest_bytes != (canonical_json(manifest) + "\n").encode("utf-8"):
        raise NodeAuthorityError("node-authority manifest is not canonical JSON")
    source_bytes = {
        item.path: contents[f"sources/{item.path}"] for item in authority.sources
    }
    rebuilt = _build_archive(manifest_bytes, source_bytes)
    if rebuilt != archive:
        raise NodeAuthorityError("node-authority archive is not deterministic")
    return manifest, source_bytes


def _validate_zip_info(info: zipfile.ZipInfo, *, manifest: bool) -> None:
    name = info.filename
    if info.flag_bits & 0x1:
        raise NodeAuthorityError("node-authority archive encryption is unsupported")
    if info.compress_type != zipfile.ZIP_STORED or info.compress_size != info.file_size:
        raise NodeAuthorityError("node-authority archive compression is unsupported")
    if info.create_system != 3:
        raise NodeAuthorityError("node-authority archive platform is unsupported")
    if info.date_time != _ZIP_EPOCH:
        raise NodeAuthorityError("node-authority archive timestamp is not fixed")
    if info.extra or info.comment:
        raise NodeAuthorityError("node-authority archive metadata is unsupported")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) != 0o644:
        raise NodeAuthorityError("node-authority archive member is special or linked")
    if _utf8_length(name) > MAX_NODE_SOURCE_PATH_BYTES:
        raise NodeAuthorityError("node-authority archive member path is too long")
    if manifest:
        if info.file_size > MAX_NODE_AUTHORITY_MANIFEST_BYTES:
            raise NodeAuthorityError("node-authority manifest exceeds its size limit")
        return
    relative = name.removeprefix("sources/")
    _source_path(relative)
    if info.file_size > MAX_NODE_SOURCE_BYTES:
        raise NodeAuthorityError("node-authority source size is invalid")


def _read_zip_member(bundle: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with bundle.open(info, "r") as stream:
        data = stream.read(info.file_size + 1)
    if len(data) != info.file_size:
        raise NodeAuthorityError("node-authority archive member size is invalid")
    if zlib.crc32(data) & 0xFFFFFFFF != info.CRC:
        raise NodeAuthorityError("node-authority archive member CRC is invalid")
    return data


def _verify_manifest(
    authority: NodeAuthority, manifest: Mapping[str, object]
) -> None:
    if set(manifest) != {
        "schema",
        "schema_version",
        "source_root_sha256",
        "sources",
        "nodes",
    } or (
        manifest.get("schema") != NODE_AUTHORITY_MANIFEST_SCHEMA
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version")
        != NODE_AUTHORITY_MANIFEST_SCHEMA_VERSION
    ):
        raise NodeAuthorityError("node-authority manifest schema is unsupported")
    if manifest.get("source_root_sha256") != authority.source_root_sha256:
        raise NodeAuthorityError("node-authority manifest source root disagrees")
    manifest_sources = _parse_sources(manifest.get("sources"))
    if manifest_sources != authority.sources:
        raise NodeAuthorityError("node-authority manifest sources disagree")
    raw_nodes = manifest.get("nodes")
    if not isinstance(raw_nodes, Mapping) or set(raw_nodes) != set(authority.nodes):
        raise NodeAuthorityError("node-authority manifest node coverage disagrees")
    for class_name, pin in authority.nodes.items():
        manifest_node = _parse_manifest_node(raw_nodes[class_name])
        if (
            manifest_node.source_path != pin.source_path
            or manifest_node.registration_api != pin.registration_api
            or manifest_node.inputs != pin.inputs
        ):
            raise NodeAuthorityError(
                "node-authority manifest registration contract disagrees"
            )


def _verify_registrations(
    source_bytes: Mapping[str, bytes], authority: NodeAuthority
) -> None:
    registrations = _parse_registrations(source_bytes, tuple(authority.nodes))
    for class_name, expected in authority.nodes.items():
        actual = registrations[class_name]
        if (
            actual.source_path != expected.source_path
            or actual.registration_api != expected.registration_api
            or actual.inputs != expected.inputs
        ):
            raise NodeAuthorityError(
                "node-authority AST registration contract disagrees"
            )


def _parse_registrations(
    source_bytes: Mapping[str, bytes], class_names: Sequence[str]
) -> dict[str, _ManifestNode]:
    expected = set(class_names)
    class_definitions: dict[str, tuple[str, ast.ClassDef, ast.Module]] = {}
    mappings: dict[str, list[ast.expr | None]] = {}
    extension_lists: dict[str, list[ast.expr]] = {}
    for path, data in source_bytes.items():
        node_class_mappings_seen = False
        try:
            tree = ast.parse(data.decode("utf-8"), filename=path, mode="exec")
        except (UnicodeError, SyntaxError) as error:
            raise NodeAuthorityError(
                "node-authority source cannot be parsed without imports"
            ) from error
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name in expected:
                if node.name in class_definitions:
                    raise NodeAuthorityError(
                        "node-authority class definitions are duplicated"
                    )
                class_definitions[node.name] = (path, node, tree)
            if isinstance(node, ast.Assign):
                mapping_targets = [
                    target
                    for target in node.targets
                    if isinstance(target, ast.Name)
                    and target.id == "NODE_CLASS_MAPPINGS"
                ]
                if mapping_targets:
                    if node_class_mappings_seen or len(mapping_targets) != 1:
                        raise NodeAuthorityError(
                            "node-authority NODE_CLASS_MAPPINGS assignment is duplicated"
                        )
                    node_class_mappings_seen = True
                    if isinstance(node.value, ast.Dict):
                        _collect_mapping(mappings, node.value)
            if isinstance(node, ast.ClassDef) and any(
                _qualified_name(base) == "ComfyExtension" for base in node.bases
            ):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name == "get_node_list":
                        returned = _single_return(method, label="extension get_node_list")
                        if not isinstance(returned, ast.List):
                            raise NodeAuthorityError(
                                "node-authority extension get_node_list must return a list"
                            )
                        for item in returned.elts:
                            name = _name(item)
                            extension_lists.setdefault(name, []).append(item)

    result: dict[str, _ManifestNode] = {}
    for class_name in class_names:
        definition = class_definitions.get(class_name)
        if definition is None:
            raise NodeAuthorityError("node-authority class registration is missing")
        path, class_node, _tree = definition
        methods = {
            item.name: item
            for item in class_node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        legacy_mapped = [
            value
            for value in mappings.get(class_name, [])
            if isinstance(value, ast.Name) and value.id == class_name
        ]
        modern_decorated = any(
            _qualified_name(base) == "io.ComfyNode" for base in class_node.bases
        )
        extension_count = len(extension_lists.get(class_name, []))
        has_input_types = "INPUT_TYPES" in methods
        has_define_schema = "define_schema" in methods
        if has_input_types and len(legacy_mapped) == 1 and not modern_decorated and extension_count == 0:
            inputs = _legacy_inputs(methods["INPUT_TYPES"])
            api = "INPUT_TYPES"
        elif (
            modern_decorated
            and has_define_schema
            and len(legacy_mapped) == 0
            and extension_count == 1
            and not has_input_types
        ):
            schema_node_id, inputs = _modern_inputs(methods["define_schema"])
            if schema_node_id != class_name:
                raise NodeAuthorityError(
                    "node-authority io.Schema.node_id disagrees with its class"
                )
            api = "define_schema"
        else:
            raise NodeAuthorityError(
                "node-authority class registration is ambiguous or incomplete"
            )
        result[class_name] = _ManifestNode(
            source_path=path,
            registration_api=api,
            inputs=inputs,
        )
    if set(result) != expected:
        raise NodeAuthorityError("node-authority class coverage is incomplete")
    return result


def _legacy_inputs(method: ast.FunctionDef | ast.AsyncFunctionDef) -> NodeInputs:
    returned = _single_return(method, label="INPUT_TYPES")
    if not isinstance(returned, ast.Dict):
        raise NodeAuthorityError("node-authority INPUT_TYPES must return an object")
    categories: dict[str, dict[str, object]] = {name: {} for name in _INPUT_CATEGORIES}
    seen_categories: set[str] = set()
    for key_node, value_node in zip(returned.keys, returned.values, strict=True):
        category = _literal_string(key_node)
        if category not in _INPUT_CATEGORIES or not isinstance(value_node, ast.Dict):
            raise NodeAuthorityError("node-authority INPUT_TYPES category is invalid")
        if category in seen_categories:
            raise NodeAuthorityError(
                "node-authority INPUT_TYPES category keys are duplicated"
            )
        seen_categories.add(category)
        for raw_name, _raw_definition in zip(
            value_node.keys, value_node.values, strict=True
        ):
            name = _literal_string(raw_name)
            if name in categories[category]:
                raise NodeAuthorityError("node-authority input names are duplicated")
            categories[category][name] = True
    return NodeInputs(
        required=tuple(sorted(categories["required"])),
        optional=tuple(sorted(categories["optional"])),
        hidden=tuple(sorted(categories["hidden"])),
    )


def _modern_inputs(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, NodeInputs]:
    returned = _single_return(method, label="define_schema")
    if not isinstance(returned, ast.Call) or _qualified_name(returned.func) != "io.Schema":
        raise NodeAuthorityError("node-authority define_schema must return io.Schema")
    keywords = {keyword.arg: keyword.value for keyword in returned.keywords if keyword.arg}
    if len(keywords) != len(returned.keywords):
        raise NodeAuthorityError("node-authority io.Schema keywords are invalid")
    node_id = _literal_string(keywords.get("node_id"))
    raw_inputs = keywords.get("inputs")
    if not isinstance(raw_inputs, ast.List):
        raise NodeAuthorityError("node-authority io.Schema.inputs must be a literal list")
    required: list[str] = []
    optional: list[str] = []
    hidden: list[str] = []
    for expression in raw_inputs.elts:
        if (
            not isinstance(expression, ast.Call)
            or not isinstance(expression.func, ast.Attribute)
            or expression.func.attr != "Input"
        ):
            raise NodeAuthorityError("node-authority io input registration is invalid")
        if not expression.args:
            raise NodeAuthorityError("node-authority io input name is missing")
        name = _literal_string(expression.args[0])
        input_keywords = {
            keyword.arg: keyword.value
            for keyword in expression.keywords
            if keyword.arg is not None
        }
        is_optional = _boolean_keyword(input_keywords, "optional")
        is_hidden = _boolean_keyword(input_keywords, "hidden")
        if is_hidden and is_optional:
            raise NodeAuthorityError("node-authority input cannot be hidden and optional")
        target = hidden if is_hidden else optional if is_optional else required
        target.append(name)
    return node_id, NodeInputs(
        required=tuple(sorted(_unique_input_names(required))),
        optional=tuple(sorted(_unique_input_names(optional))),
        hidden=tuple(sorted(_unique_input_names(hidden))),
    )


def _boolean_keyword(keywords: Mapping[str, ast.expr], name: str) -> bool:
    value = keywords.get(name)
    if value is None:
        return False
    if isinstance(value, ast.Constant) and type(value.value) is bool:
        return bool(value.value)
    raise NodeAuthorityError(
        f"node-authority input {name} flag must be a literal boolean"
    )


def _unique_input_names(names: Sequence[str]) -> list[str]:
    if len(names) != len(set(names)):
        raise NodeAuthorityError("node-authority input names are duplicated")
    return list(names)


def _collect_mapping(
    destination: dict[str, list[ast.expr | None]], mapping: ast.Dict
) -> None:
    for key_node, value_node in zip(mapping.keys, mapping.values, strict=True):
        key = _literal_string(key_node) if key_node is not None else None
        if key is not None:
            destination.setdefault(key, []).append(value_node)


def _single_return(
    method: ast.FunctionDef | ast.AsyncFunctionDef, *, label: str
) -> ast.expr:
    returns = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Return) and node.value is not None
    ]
    if len(returns) != 1:
        raise NodeAuthorityError(
            f"node-authority {label} must have one literal return"
        )
    return returns[0].value


def _qualified_name(value: ast.expr | None) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        parent = _qualified_name(value.value)
        return None if parent is None else f"{parent}.{value.attr}"
    return None


def _name(value: ast.expr) -> str:
    if isinstance(value, ast.Name):
        return value.id
    raise NodeAuthorityError("node-authority registration name must be a symbol")


def _literal_string(value: ast.expr | None) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
        return value.value
    raise NodeAuthorityError("node-authority registration names must be literals")


def _verify_sources(
    authority: NodeAuthority, *, source_root: Path
) -> None:
    root = _resolve_source_root(source_root)
    for expected in authority.sources:
        data = _read_relative_source(root / expected.path, maximum=MAX_NODE_SOURCE_BYTES)
        if (
            len(data) != expected.size_bytes
            or hashlib.sha256(data).hexdigest() != expected.sha256
        ):
            raise NodeAuthorityError(
                "signed ComfyUI source bytes do not match the node authority"
            )


def _build_archive(manifest: bytes, sources: Mapping[str, bytes]) -> bytes:
    entries = [("manifest.json", manifest), *((f"sources/{path}", data) for path, data in sources.items())]
    entries.sort(key=lambda item: _path_order(item[0]))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as bundle:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = _ZIP_MODE << 16
            info.extra = b""
            info.comment = b""
            bundle.writestr(info, data)
    archive = output.getvalue()
    if len(archive) > MAX_NODE_AUTHORITY_ARCHIVE_BYTES:
        raise NodeAuthorityError("node-authority archive exceeds its size limit")
    return archive


def _read_relative_source(path: Path, *, maximum: int) -> bytes:
    try:
        with open(path, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise NodeAuthorityError("node-authority source size or type is invalid")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
    except NodeAuthorityError:
        raise
    except OSError as error:
        raise NodeAuthorityError("node-authority source cannot be read safely") from error
    if (
        len(data) != before.st_size
        or len(data) > maximum
        or _stat_identity(before) != _stat_identity(after)
    ):
        raise NodeAuthorityError("node-authority source changed while being read")
    return data


def _resolve_source_root(path: Path) -> Path:
    try:
        root = Path(path).resolve(strict=True)
    except OSError as error:
        raise NodeAuthorityError("node-authority source root is unavailable") from error
    if not root.is_dir():
        raise NodeAuthorityError("node-authority source root is not a directory")
    return root


def _parse_source_path_list(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > MAX_NODE_SOURCES:
        raise NodeAuthorityError("node-authority source path list is invalid")
    paths = tuple(_source_path(value) for value in values)
    if len(paths) != len({path.casefold() for path in paths}):
        raise NodeAuthorityError("node-authority source paths are duplicate")
    return tuple(sorted(paths, key=_path_order))


def _parse_class_list(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values or len(values) > MAX_NODE_CLASSES:
        raise NodeAuthorityError("node-authority class list is invalid")
    names = tuple(values)
    if (
        len(names) != len(set(names))
        or any(not isinstance(name, str) or _NODE_CLASS.fullmatch(name) is None for name in names)
    ):
        raise NodeAuthorityError("node-authority class list is invalid or duplicated")
    return tuple(sorted(names))


def _source_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise NodeAuthorityError("node-authority source path is invalid")
    if _utf8_length(value) > MAX_NODE_SOURCE_PATH_BYTES:
        raise NodeAuthorityError("node-authority source path is too long")
    if (
        value.startswith("/")
        or "\\" in value
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise NodeAuthorityError("node-authority source path contains unsafe characters")
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(path.parts) > MAX_NODE_SOURCE_DEPTH
        or (len(path.parts[0]) == 2 and path.parts[0][1] == ":")
    ):
        raise NodeAuthorityError("node-authority source path is unsafe")
    return value


def _source_to_dict(pin: SourcePin) -> dict[str, object]:
    return {
        "path": pin.path,
        "size_bytes": pin.size_bytes,
        "sha256": pin.sha256,
    }


def _manifest_node_to_dict(node: _ManifestNode) -> dict[str, object]:
    return {
        "source_path": node.source_path,
        "registration_api": node.registration_api,
        "inputs": node.inputs.to_dict(),
    }


def _sha256(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise NodeAuthorityError(f"node-authority {label} sha256 is invalid")
    return value


def _path_order(value: str) -> bytes:
    return value.encode("utf-8")


def _utf8_length(value: str) -> int:
    return len(value.encode("utf-8"))


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _strict_json(raw: bytes, *, label: str) -> object:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise NodeAuthorityError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise NodeAuthorityError(f"{label} contains a non-finite number")

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except NodeAuthorityError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise NodeAuthorityError(f"{label} is not strict JSON") from error
