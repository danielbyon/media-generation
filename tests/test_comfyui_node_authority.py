"""Focused software-contract tests for ComfyUI node-authority bundles."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import struct
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

import pytest

from media_generation import _comfyui_node_authority as node_authority


TOOL_VERSION = "synthetic-unqualified-comfyui/v3"
COMPONENT_ID = "synthetic-qwen-node-authority"
SOURCE_ROOT_SHA256 = "a" * 64

# Class, source file, registration API, required, optional, hidden.
NODE_CONTRACTS: dict[
    str, tuple[str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]
] = {
    "UNETLoader": ("nodes.py", "INPUT_TYPES", ("unet_name", "weight_dtype"), (), ()),
    "CLIPLoader": ("nodes.py", "INPUT_TYPES", ("clip_name", "type"), ("device",), ()),
    "VAELoader": ("nodes.py", "INPUT_TYPES", ("vae_name",), (), ()),
    "LoadImage": ("nodes.py", "INPUT_TYPES", ("image",), (), ()),
    "VAEEncode": ("nodes.py", "INPUT_TYPES", ("pixels", "vae"), (), ()),
    "EmptyLatentImage": (
        "nodes.py",
        "INPUT_TYPES",
        ("width", "height", "batch_size"),
        (),
        (),
    ),
    "KSampler": (
        "nodes.py",
        "INPUT_TYPES",
        (
            "model",
            "seed",
            "steps",
            "cfg",
            "sampler_name",
            "scheduler",
            "positive",
            "negative",
            "latent_image",
            "denoise",
        ),
        (),
        (),
    ),
    "VAEDecode": ("nodes.py", "INPUT_TYPES", ("samples", "vae"), (), ()),
    "ImageScale": (
        "nodes.py",
        "INPUT_TYPES",
        ("image", "upscale_method", "width", "height", "crop"),
        (),
        (),
    ),
    "SaveImage": (
        "nodes.py",
        "INPUT_TYPES",
        ("images", "filename_prefix"),
        (),
        ("prompt", "extra_pnginfo"),
    ),
    "CFGNorm": (
        "comfy_extras/nodes_cfg.py",
        "define_schema",
        ("model", "strength"),
        ("pre_cfg",),
        (),
    ),
    "FluxKontextImageScale": (
        "comfy_extras/nodes_flux.py",
        "define_schema",
        ("image",),
        (),
        (),
    ),
    "FluxKontextMultiReferenceLatentMethod": (
        "comfy_extras/nodes_flux.py",
        "define_schema",
        ("conditioning", "reference_latents_method"),
        (),
        (),
    ),
    "ModelSamplingAuraFlow": (
        "comfy_extras/nodes_model_advanced.py",
        "INPUT_TYPES",
        ("model", "shift"),
        ("sampling",),
        (),
    ),
    "TextEncodeQwenImageEditPlus": (
        "comfy_extras/nodes_qwen.py",
        "define_schema",
        ("clip", "prompt"),
        ("vae", "image1", "image2", "image3"),
        (),
    ),
}


def _legacy_class(
    name: str,
    required: tuple[str, ...],
    optional: tuple[str, ...],
    hidden: tuple[str, ...],
) -> str:
    registration: dict[str, dict[str, tuple[str, ...]]] = {}
    if required:
        registration["required"] = {item: ("ANY",) for item in required}
    if optional:
        registration["optional"] = {item: ("ANY",) for item in optional}
    if hidden:
        registration["hidden"] = {item: item.upper() for item in hidden}
    return (
        f"class {name}:\n"
        "    @classmethod\n"
        "    def INPUT_TYPES(cls):\n"
        f"        return {registration!r}\n\n"
    )


def _modern_class(
    name: str,
    required: tuple[str, ...],
    optional: tuple[str, ...],
) -> str:
    inputs = [f'io.Node.Input({item!r})' for item in required]
    inputs.extend(f'io.Node.Input({item!r}, optional=True)' for item in optional)
    rendered_inputs = ", ".join(inputs)
    return (
        f"class {name}(io.ComfyNode):\n"
        "    @classmethod\n"
        "    def define_schema(cls):\n"
        f"        return io.Schema(node_id={name!r}, inputs=[{rendered_inputs}])\n\n"
    )


def _source_files() -> dict[str, bytes]:
    grouped: dict[str, list[str]] = {}
    for name, (path, api, required, optional, hidden) in NODE_CONTRACTS.items():
        if api == "INPUT_TYPES":
            grouped.setdefault(path, []).append(
                _legacy_class(name, required, optional, hidden)
            )
        else:
            grouped.setdefault(path, []).append(
                _modern_class(name, required, optional)
            )

    for path, classes in grouped.items():
        if path == "comfy_extras/nodes_cfg.py":
            classes.append(
                "class CfgExtension(ComfyExtension):\n"
                "    async def get_node_list(self):\n"
                "        return [CFGNorm]\n"
            )
        elif path == "comfy_extras/nodes_flux.py":
            names = [
                name
                for name, (source, *_rest) in NODE_CONTRACTS.items()
                if source == path
            ]
            rendered = ", ".join(names)
            classes.append(
                "class FluxExtension(ComfyExtension):\n"
                "    async def get_node_list(self):\n"
                f"        return [{rendered}]\n"
            )
        elif path == "comfy_extras/nodes_qwen.py":
            classes.append(
                "class QwenExtension(ComfyExtension):\n"
                "    async def get_node_list(self):\n"
                "        return [TextEncodeQwenImageEditPlus]\n"
            )

    for path in ("nodes.py", "comfy_extras/nodes_model_advanced.py"):
        names = [
            name
            for name, (source, *_rest) in NODE_CONTRACTS.items()
            if source == path
        ]
        mapping = "\n".join(f"    {name!r}: {name}," for name in names)
        grouped[path].append(f"NODE_CLASS_MAPPINGS = {{\n{mapping}\n}}\n")

    return {
        path: "\n".join(classes).encode("utf-8")
        for path, classes in grouped.items()
    }


def _write_source_root(tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
    root = tmp_path / "comfyui-source"
    sources = _source_files()
    for relative_path, data in sources.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root, sources


def _generate(tmp_path: Path) -> tuple[node_authority.GeneratedNodeAuthority, Path]:
    root, _sources = _write_source_root(tmp_path)
    generated = node_authority.generate_node_authority(
        source_root=root,
        source_paths=tuple(sorted(_source_files())),
        classes=tuple(sorted(NODE_CONTRACTS)),
        source_root_sha256=SOURCE_ROOT_SHA256,
        tool_id="comfyui",
        tool_version=TOOL_VERSION,
        component_id=COMPONENT_ID,
    )
    return generated, root


def _component(generated: node_authority.GeneratedNodeAuthority) -> dict[str, object]:
    component = generated.document["component"]
    assert isinstance(component, dict)
    return component


def _with_archive_identity(
    document: dict[str, object] | Any, archive: bytes
) -> dict[str, object]:
    updated = deepcopy(document)
    component = updated["component"]
    component["size_bytes"] = len(archive)
    component["sha256"] = hashlib.sha256(archive).hexdigest()
    for pin in updated["nodes"].values():
        pin["component_sha256"] = component["sha256"]
    return updated


def _verify_with_document(
    document: dict[str, object], archive: bytes, root: Path
) -> None:
    authority = node_authority.parse_node_authority(document)
    component = document["component"]
    assert isinstance(component, dict)
    node_authority.verify_node_authority(
        authority,
        archive,
        expected_component_id=str(component["id"]),
        expected_component_size_bytes=int(component["size_bytes"]),
        expected_component_sha256=str(component["sha256"]),
        source_root=root,
        signed_source_root_sha256=SOURCE_ROOT_SHA256,
    )


def _verify(
    generated: node_authority.GeneratedNodeAuthority,
    root: Path,
    *,
    signed_source_root_sha256: str = SOURCE_ROOT_SHA256,
    expected_component: dict[str, object] | None = None,
) -> None:
    component = _component(generated)
    expected = expected_component or component
    node_authority.verify_node_authority(
        node_authority.parse_node_authority(generated.document),
        generated.archive,
        expected_component_id=str(expected["id"]),
        expected_component_size_bytes=int(expected["size_bytes"]),
        expected_component_sha256=str(expected["sha256"]),
        source_root=root,
        signed_source_root_sha256=signed_source_root_sha256,
    )


def _members(archive: bytes) -> tuple[bytes, dict[str, bytes]]:
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        manifest = bundle.read("manifest.json")
        sources = {
            info.filename.removeprefix("sources/"): bundle.read(info.filename)
            for info in bundle.infolist()
            if info.filename.startswith("sources/")
        }
    return manifest, sources


def _craft_archive(
    manifest: bytes,
    sources: dict[str, bytes],
    *,
    compression: int = zipfile.ZIP_STORED,
    additional: Callable[[zipfile.ZipFile], None] | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as bundle:
        for name, data in sorted(
            (("manifest.json", manifest),
             *((f"sources/{path}", data) for path, data in sources.items())),
            key=lambda item: item[0].encode("utf-8"),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(info, data)
        if additional is not None:
            additional(bundle)
    return output.getvalue()


def _replace_source(
    generated: node_authority.GeneratedNodeAuthority,
    path: str,
    data: bytes,
) -> bytes:
    manifest, sources = _members(generated.archive)
    sources[path] = data
    return _craft_archive(manifest, sources)


def test_v3_round_trip_binds_all_qwen_graph_classes_and_is_deterministic(
    tmp_path: Path,
) -> None:
    first, root = _generate(tmp_path)
    second = node_authority.generate_node_authority(
        source_root=root,
        source_paths=tuple(sorted(_source_files())),
        classes=tuple(sorted(NODE_CONTRACTS)),
        source_root_sha256=SOURCE_ROOT_SHA256,
        tool_id="comfyui",
        tool_version=TOOL_VERSION,
        component_id=COMPONENT_ID,
    )

    assert first.archive == second.archive
    assert first.document == second.document
    assert first.document["schema_version"] == 3
    assert first.document["source_root_sha256"] == SOURCE_ROOT_SHA256
    assert [item["path"] for item in first.document["sources"]] == sorted(
        _source_files()
    )
    assert set(first.document["nodes"]) == set(NODE_CONTRACTS)
    assert len(first.document["nodes"]) == 15
    parsed = node_authority.parse_node_authority(first.document)
    assert parsed.nodes["SaveImage"].inputs.hidden == (
        "extra_pnginfo",
        "prompt",
    )
    assert parsed.nodes["CLIPLoader"].inputs.optional == ("device",)
    assert parsed.nodes["CFGNorm"].registration_api == "define_schema"
    _verify(first, root)


def test_v3_rejects_unknown_or_unsorted_source_metadata(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    document = deepcopy(generated.document)
    sources = document["sources"]
    assert isinstance(sources, list)
    sources.reverse()
    with pytest.raises(node_authority.NodeAuthorityError, match="sorted"):
        node_authority.parse_node_authority(document)

    document = deepcopy(generated.document)
    document["extra"] = True
    with pytest.raises(node_authority.NodeAuthorityError, match="fields"):
        node_authority.parse_node_authority(document)

    document = deepcopy(generated.document)
    nodes = document["nodes"]
    assert isinstance(nodes, dict)
    nodes["UNETLoader"]["registration_api"] = "guess"
    with pytest.raises(node_authority.NodeAuthorityError, match="registration"):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize(
    "path",
    [
        "../nodes.py",
        "/nodes.py",
        "comfy_extras\\nodes_qwen.py",
        "control\x00.py",
        "line\nbreak.py",
        "a/b/c/d/e/f/g/h/i.py",
    ],
)
def test_v3_rejects_unsafe_source_paths(tmp_path: Path, path: str) -> None:
    generated, _root = _generate(tmp_path)
    document = deepcopy(generated.document)
    sources = document["sources"]
    assert isinstance(sources, list)
    sources[0]["path"] = path
    with pytest.raises(node_authority.NodeAuthorityError, match="path"):
        node_authority.parse_node_authority(document)


def test_v3_rejects_casefold_duplicate_and_oversized_source_pins(
    tmp_path: Path,
) -> None:
    generated, _root = _generate(tmp_path)
    document = deepcopy(generated.document)
    sources = document["sources"]
    assert isinstance(sources, list)
    duplicate = deepcopy(sources[0])
    duplicate["path"] = str(duplicate["path"]).upper()
    sources.append(duplicate)
    sources.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    with pytest.raises(node_authority.NodeAuthorityError, match="duplicate"):
        node_authority.parse_node_authority(document)

    document = deepcopy(generated.document)
    sources = document["sources"]
    assert isinstance(sources, list)
    sources[0]["size_bytes"] = node_authority.MAX_NODE_SOURCE_BYTES + 1
    with pytest.raises(node_authority.NodeAuthorityError, match="size"):
        node_authority.parse_node_authority(document)


@pytest.mark.parametrize("kind", ["compressed", "directory", "symlink", "special"])
def test_v3_rejects_noncanonical_zip_member_types(
    tmp_path: Path, kind: str
) -> None:
    generated, root = _generate(tmp_path)
    manifest, sources = _members(generated.archive)
    if kind == "compressed":
        archive = _craft_archive(manifest, sources, compression=zipfile.ZIP_DEFLATED)
    else:
        def additional(bundle: zipfile.ZipFile) -> None:
            if kind == "directory":
                bundle.writestr("sources/empty/", b"")
                return
            info = zipfile.ZipInfo(
                "sources/unexpected.py",
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.create_system = 3
            mode = stat.S_IFLNK | 0o777 if kind == "symlink" else stat.S_IFIFO | 0o644
            info.external_attr = mode << 16
            bundle.writestr(info, b"unsafe")

        archive = _craft_archive(manifest, sources, additional=additional)
    with pytest.raises(node_authority.NodeAuthorityError):
        node_authority.verify_node_authority(
            node_authority.parse_node_authority(generated.document),
            archive,
            expected_component_id=COMPONENT_ID,
            expected_component_size_bytes=len(archive),
            expected_component_sha256=hashlib.sha256(archive).hexdigest(),
            source_root=root,
            signed_source_root_sha256=SOURCE_ROOT_SHA256,
        )


def test_v3_rejects_encrypted_zip_flag(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    archive = bytearray(generated.archive)
    central = archive.find(b"PK\x01\x02")
    assert central >= 0
    flags_offset = central + 8
    flags = struct.unpack_from("<H", archive, flags_offset)[0]
    struct.pack_into("<H", archive, flags_offset, flags | 1)
    document = _with_archive_identity(generated.document, bytes(archive))
    with pytest.raises(node_authority.NodeAuthorityError, match="encrypt"):
        _verify_with_document(document, bytes(archive), root)


@pytest.mark.parametrize("mutation", ["extra", "missing", "duplicate_casefold"])
def test_v3_rejects_member_set_anomalies(tmp_path: Path, mutation: str) -> None:
    generated, root = _generate(tmp_path)
    manifest, sources = _members(generated.archive)
    if mutation == "extra":
        sources["unexpected.py"] = b"extra"
    elif mutation == "missing":
        sources.pop(next(iter(sources)))
    else:
        sources["NODES.py"] = sources["nodes.py"]
    archive = _craft_archive(manifest, sources)
    document = _with_archive_identity(generated.document, archive)
    with pytest.raises(node_authority.NodeAuthorityError):
        _verify_with_document(document, archive, root)


def test_v3_rejects_archive_source_and_component_tampering(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    tampered_archive = _replace_source(
        generated,
        "nodes.py",
        generated.archive and _members(generated.archive)[1]["nodes.py"] + b"\n",
    )
    with pytest.raises(node_authority.NodeAuthorityError):
        node_authority.verify_node_authority(
            node_authority.parse_node_authority(generated.document),
            tampered_archive,
            expected_component_id=COMPONENT_ID,
            expected_component_size_bytes=len(tampered_archive),
            expected_component_sha256=hashlib.sha256(tampered_archive).hexdigest(),
            source_root=root,
            signed_source_root_sha256=SOURCE_ROOT_SHA256,
        )

    component = _component(generated)
    component["sha256"] = "b" * 64
    with pytest.raises(node_authority.NodeAuthorityError, match="component"):
        node_authority.verify_node_authority(
            node_authority.parse_node_authority(generated.document),
            generated.archive,
            expected_component_id=COMPONENT_ID,
            expected_component_size_bytes=len(generated.archive),
            expected_component_sha256=str(component["sha256"]),
            source_root=root,
            signed_source_root_sha256=SOURCE_ROOT_SHA256,
        )


def test_v3_rejects_signed_root_mismatch_and_source_mutation(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    with pytest.raises(node_authority.NodeAuthorityError, match="signed source root"):
        _verify(generated, root, signed_source_root_sha256="c" * 64)

    nodes = root / "nodes.py"
    original = nodes.read_bytes()
    nodes.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(node_authority.NodeAuthorityError, match="bytes"):
        _verify(generated, root)


def test_v3_rejects_ast_contract_mismatch(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    manifest, sources = _members(generated.archive)
    decoded_manifest = json.loads(manifest)
    decoded_manifest["nodes"]["SaveImage"]["inputs"]["hidden"] = ["prompt"]
    changed_manifest = (
        json.dumps(
            decoded_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    archive = _craft_archive(changed_manifest, sources)
    document = deepcopy(generated.document)
    nodes = document["nodes"]
    assert isinstance(nodes, dict)
    nodes["SaveImage"]["inputs"]["hidden"] = ["prompt"]
    document = _with_archive_identity(document, archive)
    with pytest.raises(node_authority.NodeAuthorityError, match="registration"):
        _verify_with_document(document, archive, root)


def test_v3_rejects_malformed_python_without_importing_it(tmp_path: Path) -> None:
    generated, root = _generate(tmp_path)
    manifest, sources = _members(generated.archive)
    sources["nodes.py"] = b"raise RuntimeError('must never execute')\n"
    decoded_manifest = json.loads(manifest)
    source_pin = next(
        item for item in decoded_manifest["sources"] if item["path"] == "nodes.py"
    )
    source_pin["size_bytes"] = len(sources["nodes.py"])
    source_pin["sha256"] = hashlib.sha256(sources["nodes.py"]).hexdigest()
    changed_manifest = (
        json.dumps(
            decoded_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    archive = _craft_archive(changed_manifest, sources)
    document = _with_archive_identity(generated.document, archive)
    document_sources = document["sources"]
    assert isinstance(document_sources, list)
    source_pin = next(item for item in document_sources if item["path"] == "nodes.py")
    source_pin["size_bytes"] = len(sources["nodes.py"])
    source_pin["sha256"] = hashlib.sha256(sources["nodes.py"]).hexdigest()
    with pytest.raises(node_authority.NodeAuthorityError, match="registration"):
        _verify_with_document(document, archive, root)
