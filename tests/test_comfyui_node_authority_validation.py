"""Boundary tests for ComfyUI node-authority validation and AST parsing."""

from __future__ import annotations

import hashlib
import json
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from media_generation import _comfyui_node_authority as node_authority
from test_comfyui_node_authority import (
    COMPONENT_ID,
    NODE_CONTRACTS,
    SOURCE_ROOT_SHA256,
    _craft_archive,
    _generate,
    _members,
    _verify_with_document,
    _with_archive_identity,
)

SOURCE_PATHS = tuple(sorted({contract[0] for contract in NODE_CONTRACTS.values()}))


def _parse_legacy(
    return_value: str = '{"required": {"x": ("INT",)}}',
    *,
    mapping: str = '{"Node": Node}',
) -> dict[str, node_authority._ManifestNode]:
    source = (
        "class Node:\n"
        "    @classmethod\n"
        "    def INPUT_TYPES(cls):\n"
        f"        return {return_value}\n\n"
        f"NODE_CLASS_MAPPINGS = {mapping}\n"
    )
    return node_authority._parse_registrations({"nodes.py": source.encode()}, ("Node",))


def _parse_modern(
    schema_arguments: str = 'node_id="Node", inputs=[io.Node.Input("x")]',
    *,
    extension_return: str = "[Node]",
) -> dict[str, node_authority._ManifestNode]:
    source = (
        "class Node(io.ComfyNode):\n"
        "    @classmethod\n"
        "    def define_schema(cls):\n"
        f"        return io.Schema({schema_arguments})\n\n"
        "class Extension(ComfyExtension):\n"
        "    @classmethod\n"
        "    async def get_node_list(cls):\n"
        f"        return {extension_return}\n"
    )
    return node_authority._parse_registrations({"nodes.py": source.encode()}, ("Node",))


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("not_mapping", "fields"),
        ("fields", "fields"),
        ("schema", "schema or version"),
        ("schema_version", "schema or version"),
        ("tool_id", "tool id"),
        ("tool_version", "tool version"),
        ("source_root_sha256", "source root sha256"),
    ],
)
def test_v3_rejects_invalid_top_level_identity(
    tmp_path: Path, case: str, match: str
) -> None:
    generated, _root = _generate(tmp_path)
    document: object = deepcopy(generated.document)
    if case == "not_mapping":
        document = None
    elif case == "fields":
        assert isinstance(document, dict)
        document["extra"] = True
    else:
        assert isinstance(document, dict)
        document[case] = {
            "schema": "wrong",
            "schema_version": True,
            "tool_id": "",
            "tool_version": None,
            "source_root_sha256": "G" * 64,
        }[case]
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("not_mapping", "component"),
        ("fields", "component"),
        ("id", "component id"),
        ("size_type", "component size"),
        ("size_zero", "component size"),
        ("size_large", "component size"),
    ],
)
def test_v3_rejects_invalid_component_identity(
    tmp_path: Path, case: str, match: str
) -> None:
    generated, _root = _generate(tmp_path)
    document = deepcopy(generated.document)
    component = document["component"]
    assert isinstance(component, dict)
    if case == "not_mapping":
        document["component"] = None
    elif case == "fields":
        component["extra"] = True
    elif case == "id":
        component["id"] = ""
    elif case == "size_type":
        component["size_bytes"] = True
    elif case == "size_zero":
        component["size_bytes"] = 0
    else:
        component["size_bytes"] = node_authority.MAX_NODE_AUTHORITY_ARCHIVE_BYTES + 1
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("not_list", "incomplete"),
        ("empty", "incomplete"),
        ("too_many", "incomplete"),
        ("not_mapping", "malformed"),
        ("fields", "malformed"),
        ("size_type", "size"),
        ("size_large", "size"),
        ("sha", "sha256"),
    ],
)
def test_v3_rejects_invalid_source_pin_shape(
    tmp_path: Path, case: str, match: str
) -> None:
    generated, _root = _generate(tmp_path)
    document = deepcopy(generated.document)
    sources = document["sources"]
    assert isinstance(sources, list)
    if case == "not_list":
        document["sources"] = None
    elif case == "empty":
        document["sources"] = []
    elif case == "too_many":
        document["sources"] = sources * (node_authority.MAX_NODE_SOURCES + 1)
    elif case == "not_mapping":
        sources[0] = None
    elif case == "fields":
        sources[0]["extra"] = True
    elif case == "size_type":
        sources[0]["size_bytes"] = True
    elif case == "size_large":
        sources[0]["size_bytes"] = node_authority.MAX_NODE_SOURCE_BYTES + 1
    else:
        sources[0]["sha256"] = "G" * 64
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("empty", "incomplete"),
        ("class", "class name"),
        ("pin_fields", "pin.*malformed"),
        ("component_id", "component id"),
        ("component_sha", "component sha256"),
        ("source_path", "source path.*missing"),
        ("registration", "registration"),
        ("unreferenced", "unreferenced"),
        ("input_categories", "input categories"),
        ("input_names", "input names are invalid"),
        ("input_order", "input names must be sorted"),
        ("input_duplicate", "input names.*duplicated"),
        ("input_overlap", "not disjoint"),
    ],
)
def test_v3_rejects_invalid_node_pin_relationships(
    tmp_path: Path, case: str, match: str
) -> None:
    generated, _root = _generate(tmp_path)
    document = deepcopy(generated.document)
    nodes = document["nodes"]
    assert isinstance(nodes, dict)
    if case == "empty":
        document["nodes"] = {}
    elif case == "class":
        nodes["bad class"] = deepcopy(nodes["UNETLoader"])
    elif case == "pin_fields":
        nodes["UNETLoader"].pop("registration_api")
    elif case == "component_id":
        nodes["UNETLoader"]["component_id"] = "other"
    elif case == "component_sha":
        nodes["UNETLoader"]["component_sha256"] = "b" * 64
    elif case == "source_path":
        nodes["UNETLoader"]["source_path"] = "missing.py"
    elif case == "registration":
        nodes["UNETLoader"]["registration_api"] = "guess"
    elif case == "unreferenced":
        document["nodes"] = {
            name: pin for name, pin in nodes.items() if pin["source_path"] != "nodes.py"
        }
    elif case == "input_categories":
        nodes["CLIPLoader"]["inputs"]["extra"] = []
    elif case == "input_names":
        nodes["CLIPLoader"]["inputs"]["required"].append(7)
    elif case == "input_order":
        nodes["CLIPLoader"]["inputs"]["required"].reverse()
    elif case == "input_duplicate":
        nodes["CLIPLoader"]["inputs"]["required"] = ["clip_name", "clip_name", "type"]
    else:
        nodes["CLIPLoader"]["inputs"]["optional"] = ["clip_name"]
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("tool_id", "tool id"),
        ("tool_version", "tool version"),
        ("component_id", "component id"),
        ("source_paths", "source path list.*invalid"),
        ("classes", "class list.*invalid"),
        ("duplicate_classes", "class list.*duplicated"),
    ],
)
def test_v3_generator_rejects_invalid_identity_inputs(
    tmp_path: Path, case: str, match: str
) -> None:
    _generated, root = _generate(tmp_path)
    values: dict[str, object] = {
        "source_root": root,
        "source_paths": SOURCE_PATHS,
        "classes": tuple(sorted(NODE_CONTRACTS)),
        "source_root_sha256": SOURCE_ROOT_SHA256,
        "tool_id": "comfyui",
        "tool_version": "synthetic-v3",
        "component_id": COMPONENT_ID,
    }
    if case in {"tool_id", "tool_version", "component_id"}:
        values[case] = ""
    elif case == "source_paths":
        values["source_paths"] = ()
    elif case == "classes":
        values["classes"] = ()
    else:
        values["classes"] = ("UNETLoader", "UNETLoader")
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        node_authority.generate_node_authority(**values)  # type: ignore[arg-type]


def test_v3_generator_enforces_manifest_and_archive_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generated, root = _generate(tmp_path)
    arguments = {
        "source_root": root,
        "source_paths": SOURCE_PATHS,
        "classes": tuple(sorted(NODE_CONTRACTS)),
        "source_root_sha256": SOURCE_ROOT_SHA256,
        "tool_id": "comfyui",
        "tool_version": "synthetic-v3",
        "component_id": COMPONENT_ID,
    }
    manifest_limit = node_authority.MAX_NODE_AUTHORITY_MANIFEST_BYTES
    monkeypatch.setattr(node_authority, "MAX_NODE_AUTHORITY_MANIFEST_BYTES", 1)
    with pytest.raises(node_authority.NodeAuthorityError, match="manifest exceeds"):
        node_authority.generate_node_authority(**arguments)
    monkeypatch.setattr(
        node_authority,
        "MAX_NODE_AUTHORITY_MANIFEST_BYTES",
        manifest_limit,
    )
    monkeypatch.setattr(node_authority, "MAX_NODE_AUTHORITY_ARCHIVE_BYTES", 1)
    with pytest.raises(node_authority.NodeAuthorityError, match="archive exceeds"):
        node_authority.generate_node_authority(**arguments)
    assert generated.archive


@pytest.mark.parametrize(
    ("return_value", "mapping", "match"),
    [
        ('["x"]', '{"Node": Node}', "INPUT_TYPES must return"),
        (
            '{"required": {"x": ("ANY",)}, "bogus": {}}',
            '{"Node": Node}',
            "category.*invalid",
        ),
        (
            '{"required": {"x": ("ANY",), "x": ("ANY",)}}',
            '{"Node": Node}',
            "input names.*duplicated",
        ),
        (
            '{"required": {name: ("ANY",)}}',
            '{"Node": Node}',
            "names must be literals",
        ),
        ('{"required": {"x": ("ANY",)}}', '{"Node": Other}', "ambiguous"),
        ('{"required": {"x": ("ANY",)}}', '{"Node": Node, "Node": Node}', "ambiguous"),
    ],
)
def test_legacy_ast_registration_contracts_fail_closed(
    return_value: str, mapping: str, match: str
) -> None:
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        _parse_legacy(return_value, mapping=mapping)


@pytest.mark.parametrize(
    ("schema_arguments", "extension_return", "match"),
    [
        ('node_id="Other", inputs=[io.Node.Input("x")]', "[Node]", "node_id disagrees"),
        ('node_id="Node", inputs=io.Node.Input("x")', "[Node]", "inputs must"),
        ('node_id="Node", inputs=[thing]', "[Node]", "input registration.*invalid"),
        ('node_id="Node", inputs=[io.Node.Input()]', "[Node]", "input name.*missing"),
        (
            'node_id="Node", inputs=[io.Node.Input("x", optional=True, hidden=True)]',
            "[Node]",
            "hidden and optional",
        ),
        (
            'node_id="Node", inputs=[io.Node.Input("x", optional=flag)]',
            "[Node]",
            "literal boolean",
        ),
        (
            'node_id="Node", inputs=[io.Node.Input("x"), io.Node.Input("x")]',
            "[Node]",
            "input names.*duplicated",
        ),
        (
            'node_id="Node", inputs=[io.Node.Input("x")], **kwargs',
            "[Node]",
            "keywords are invalid",
        ),
        ('node_id="Node", inputs=[io.Node.Input("x")]', "(Node,)", "must return.*list"),
        ('node_id="Node", inputs=[io.Node.Input("x")]', "[]", "ambiguous"),
        ('node_id="Node", inputs=[io.Node.Input("x")]', '["Node"]', "must be a symbol"),
    ],
)
def test_modern_ast_registration_contracts_fail_closed(
    schema_arguments: str, extension_return: str, match: str
) -> None:
    with pytest.raises(node_authority.NodeAuthorityError, match=match):
        _parse_modern(schema_arguments, extension_return=extension_return)


def test_ast_registration_rejects_repeated_node_class_mappings_assignment() -> None:
    source = (
        "class Node:\n"
        "    @classmethod\n"
        "    def INPUT_TYPES(cls):\n"
        '        return {"required": {"safe": ("STRING",)}}\n'
        "\n"
        'NODE_CLASS_MAPPINGS = {"Node": Node}\n'
        "NODE_CLASS_MAPPINGS = {}\n"
    )

    with pytest.raises(
        node_authority.NodeAuthorityError,
        match="NODE_CLASS_MAPPINGS.*duplicated",
    ):
        node_authority._parse_registrations({"nodes.py": source.encode()}, ("Node",))


@pytest.mark.parametrize("category", ("required", "optional", "hidden"))
def test_legacy_inputs_rejects_duplicate_category_keys(category: str) -> None:
    return_value = (
        f'{{"{category}": {{"safe": ("STRING",)}}, '
        f'"{category}": {{"remote_backend": ("STRING",)}}}}'
    )

    with pytest.raises(node_authority.NodeAuthorityError, match="category.*duplicated"):
        _parse_legacy(return_value)


def test_ast_registration_rejects_duplicate_class_and_ambiguous_return() -> None:
    duplicate = (
        "class Node:\n"
        "    @classmethod\n"
        "    def INPUT_TYPES(cls):\n"
        '        return {"required": {"x": ("ANY",)}}\n'
        "class Node:\n"
        "    pass\n"
        'NODE_CLASS_MAPPINGS = {"Node": Node}\n'
    )
    with pytest.raises(node_authority.NodeAuthorityError, match="duplicated"):
        node_authority._parse_registrations({"nodes.py": duplicate.encode()}, ("Node",))

    multiple_returns = (
        "class Node:\n"
        "    @classmethod\n"
        "    def INPUT_TYPES(cls):\n"
        "        if True:\n"
        '            return {"required": {"x": ("ANY",)}}\n'
        '        return {"required": {"x": ("ANY",)}}\n'
        'NODE_CLASS_MAPPINGS = {"Node": Node}\n'
    )
    with pytest.raises(node_authority.NodeAuthorityError, match="literal return"):
        node_authority._parse_registrations({"nodes.py": multiple_returns.encode()}, ("Node",))


def test_v3_verifier_rejects_component_identity_mismatches(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    authority = node_authority.parse_node_authority(generated.document)
    component = generated.document["component"]
    assert isinstance(component, dict)
    common = {
        "expected_component_id": str(component["id"]),
        "expected_component_size_bytes": int(component["size_bytes"]),
        "expected_component_sha256": str(component["sha256"]),
        "source_root": root,
        "signed_source_root_sha256": SOURCE_ROOT_SHA256,
    }
    for field, replacement, match in (
        ("expected_component_id", "other", "component id"),
        ("expected_component_size_bytes", len(generated.archive) + 1, "component size"),
        ("expected_component_sha256", "b" * 64, "component sha256"),
    ):
        arguments = {**common, field: replacement}
        with pytest.raises(node_authority.NodeAuthorityError, match=match):
            node_authority.verify_node_authority(authority, generated.archive, **arguments)
    with pytest.raises(TypeError, match="NodeAuthority"):
        node_authority.verify_node_authority_component(None, generated.archive, **{
            "expected_component_id": str(component["id"]),
            "expected_component_size_bytes": int(component["size_bytes"]),
            "expected_component_sha256": str(component["sha256"]),
        })


def test_v3_verifier_rejects_invalid_archive_and_manifest_encodings(
    tmp_path: Path,
) -> None:
    generated, root = _generate(tmp_path)
    authority = node_authority.parse_node_authority(generated.document)
    component = generated.document["component"]
    assert isinstance(component, dict)
    with pytest.raises(node_authority.NodeAuthorityError, match="archive.*missing"):
        node_authority.verify_node_authority_component(
            authority,
            b"",
            expected_component_id=str(component["id"]),
            expected_component_size_bytes=int(component["size_bytes"]),
            expected_component_sha256=str(component["sha256"]),
        )

    manifest, sources = _members(generated.archive)
    decoded = json.loads(manifest)
    noncanonical = (
        json.dumps(decoded, ensure_ascii=False, sort_keys=True, separators=(", ", ": "))
        + "\n"
    ).encode()
    for replacement, match in (
        (noncanonical, "canonical"),
        (b"[]\n", "manifest must be an object"),
        (b'{"x": NaN}\n', "non-finite number"),
    ):
        archive = _craft_archive(replacement, sources)
        document = _with_archive_identity(generated.document, archive)
        with pytest.raises(node_authority.NodeAuthorityError, match=match):
            _verify_with_document(document, archive, root)

    def add_comment(bundle: zipfile.ZipFile) -> None:
        bundle.comment = b"comment"

    archive = _craft_archive(manifest, sources, additional=add_comment)
    document = _with_archive_identity(generated.document, archive)
    with pytest.raises(node_authority.NodeAuthorityError, match="comment"):
        _verify_with_document(document, archive, root)


def test_v3_verifier_rejects_duplicate_manifest_keys(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    manifest, sources = _members(generated.archive)
    duplicate = manifest[:-2] + b',"schema":"duplicate"}\n'
    archive = _craft_archive(duplicate, sources)
    document = _with_archive_identity(generated.document, archive)
    with pytest.raises(node_authority.NodeAuthorityError, match="duplicate key"):
        _verify_with_document(document, archive, root)
