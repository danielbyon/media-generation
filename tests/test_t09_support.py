"""Synthetic ComfyUI T07 bundles for software-contract tests only."""

from __future__ import annotations

import os
import hashlib
import json
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from media_generation import candidate
from media_generation.comfyui_runtime_pins import COMFYUI_CLOSED_PATH, _tree_sha256
from media_generation._comfyui_node_authority import generate_node_authority
from media_generation.privacy import (
    COMFYUI_CONFIGURATION_VERSION,
    COMFYUI_TOOL_ID,
)

from test_t08_support import (
    _compatibility_document,
    _component,
    _license,
    _pin,
    _provenance,
    _write_json,
)
from test_t08_support import heavy_admission_profile, heavy_workload_demand

COMFYUI_SOURCE = Path(__file__).resolve().parent / "fixtures" / "comfyui-server.py"
COMFYUI_NODE_BUNDLE_ID = "comfyui-local-node-bundle"
SYNTHETIC_COMFYUI_TOOL_VERSION = "synthetic-unqualified-comfyui/v1"
COMFYUI_QWEN_POLICY_CLAIM = (
    "backend-policy:comfyui/"
    "qwen-image-edit-2511-reference-latent-timestep-zero/v1"
)
COMFYUI_NODE_INPUTS = {
    "UNETLoader": ["unet_name", "weight_dtype"],
    "CLIPLoader": ["clip_name", "type"],
    "VAELoader": ["vae_name"],
    "CLIPTextEncode": ["clip", "text"],
    "TextEncodeQwenImageEditPlus": ["clip", "image1", "prompt", "vae"],
    "FluxKontextImageScale": ["image"],
    "FluxKontextMultiReferenceLatentMethod": [
        "conditioning",
        "reference_latents_method",
    ],
    "CFGNorm": ["model", "pre_cfg", "strength"],
    "ModelSamplingAuraFlow": ["model", "shift"],
    "EmptyLatentImage": ["batch_size", "height", "width"],
    "KSampler": [
        "cfg",
        "denoise",
        "latent_image",
        "model",
        "negative",
        "positive",
        "sampler_name",
        "scheduler",
        "seed",
        "steps",
    ],
    "VAEDecode": ["samples", "vae"],
    "SaveImage": ["filename_prefix", "images"],
    "LoadImage": ["image"],
    "ImageScale": ["crop", "height", "image", "upscale_method", "width"],
    "VAEEncode": ["pixels", "vae"],
}

COMFYUI_NODE_OPTIONAL_INPUTS = {
    "CLIPLoader": ("device",),
    "CFGNorm": ("pre_cfg",),
    "ModelSamplingAuraFlow": ("sampling",),
    "TextEncodeQwenImageEditPlus": ("vae", "image1", "image2", "image3"),
}
COMFYUI_NODE_HIDDEN_INPUTS = {
    "SaveImage": ("prompt", "extra_pnginfo"),
}
COMFYUI_QWEN_NODE_CLASSES = tuple(
    name for name in COMFYUI_NODE_INPUTS if name != "CLIPTextEncode"
)
COMFYUI_NODE_SOURCE_PATHS = (
    "comfy_extras/nodes_cfg.py",
    "comfy_extras/nodes_flux.py",
    "comfy_extras/nodes_model_advanced.py",
    "comfy_extras/nodes_qwen.py",
    "nodes.py",
)


_COMFYUI_LEGACY_NODE_CLASSES = frozenset(
    {
        "CLIPLoader",
        "EmptyLatentImage",
        "ImageScale",
        "KSampler",
        "LoadImage",
        "ModelSamplingAuraFlow",
        "SaveImage",
        "UNETLoader",
        "VAEDecode",
        "VAEEncode",
        "VAELoader",
    }
)
_COMFYUI_MODERN_NODE_CLASSES = frozenset(
    set(COMFYUI_QWEN_NODE_CLASSES) - _COMFYUI_LEGACY_NODE_CLASSES
)
_COMFYUI_NODE_SOURCE_FILES = {
    "CFGNorm": "comfy_extras/nodes_cfg.py",
    "FluxKontextImageScale": "comfy_extras/nodes_flux.py",
    "FluxKontextMultiReferenceLatentMethod": "comfy_extras/nodes_flux.py",
    "ModelSamplingAuraFlow": "comfy_extras/nodes_model_advanced.py",
    "TextEncodeQwenImageEditPlus": "comfy_extras/nodes_qwen.py",
    **{
        name: "nodes.py"
        for name in _COMFYUI_LEGACY_NODE_CLASSES - {"ModelSamplingAuraFlow"}
    },
}


def _synthetic_node_categories(
    name: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    optional = COMFYUI_NODE_OPTIONAL_INPUTS.get(name, ())
    hidden = COMFYUI_NODE_HIDDEN_INPUTS.get(name, ())
    required = tuple(
        item
        for item in COMFYUI_NODE_INPUTS[name]
        if item not in optional and item not in hidden
    )
    return required, optional, hidden


def _synthetic_node_sources() -> dict[str, bytes]:
    grouped: dict[str, list[str]] = {
        path: [] for path in COMFYUI_NODE_SOURCE_PATHS
    }
    for name in COMFYUI_QWEN_NODE_CLASSES:
        required, optional, hidden = _synthetic_node_categories(name)
        path = _COMFYUI_NODE_SOURCE_FILES[name]
        if name in _COMFYUI_LEGACY_NODE_CLASSES:
            registration: dict[str, dict[str, tuple[str, ...]]] = {}
            if required:
                registration["required"] = {item: ("ANY",) for item in required}
            if optional:
                registration["optional"] = {item: ("ANY",) for item in optional}
            if hidden:
                registration["hidden"] = {item: item.upper() for item in hidden}
            grouped[path].append(
                f"class {name}:\n"
                "    @classmethod\n"
                "    def INPUT_TYPES(cls):\n"
                f"        return {registration!r}\n"
            )
        else:
            inputs = [f"io.Node.Input({item!r})" for item in required]
            inputs.extend(
                f"io.Node.Input({item!r}, optional=True)" for item in optional
            )
            grouped[path].append(
                f"class {name}(io.ComfyNode):\n"
                "    @classmethod\n"
                "    def define_schema(cls):\n"
                f"        return io.Schema(node_id={name!r}, inputs=[{', '.join(inputs)}])\n"
            )
    for path in ("nodes.py", "comfy_extras/nodes_model_advanced.py"):
        names = [
            name
            for name in COMFYUI_QWEN_NODE_CLASSES
            if _COMFYUI_NODE_SOURCE_FILES[name] == path
        ]
        mapping = "\n".join(f"    {name!r}: {name}," for name in names)
        grouped[path].append(f"NODE_CLASS_MAPPINGS = {{\n{mapping}\n}}\n")
    for path, extension, names in (
        ("comfy_extras/nodes_cfg.py", "CfgExtension", ("CFGNorm",)),
        (
            "comfy_extras/nodes_flux.py",
            "FluxExtension",
            (
                "FluxKontextImageScale",
                "FluxKontextMultiReferenceLatentMethod",
            ),
        ),
        (
            "comfy_extras/nodes_qwen.py",
            "QwenExtension",
            ("TextEncodeQwenImageEditPlus",),
        ),
    ):
        grouped[path].append(
            f"class {extension}(ComfyExtension):\n"
            "    async def get_node_list(self):\n"
            f"        return [{', '.join(names)}]\n"
        )
    return {
        path: "\n".join(parts).encode("utf-8")
        for path, parts in grouped.items()
    }


def synthetic_comfyui_runtime_roots_for_tests(
    candidate: Any | None = None,
) -> list[dict[str, str]]:
    """Build all six runtime roots required by synthetic ComfyUI launches."""
    python_home = Path(sys.base_prefix).resolve()
    python_imports = Path(sysconfig.get_paths()["purelib"]).resolve()
    native_dependencies = Path(
        sysconfig.get_config_var("LIBDIR") or sys.base_prefix
    ).resolve()
    if candidate is None:
        source_root = COMFYUI_SOURCE.parent.resolve()
        frontend_root = source_root
    else:
        declaration = candidate.declaration
        root_index = declaration.root_index
        source_root = declaration.engine.executable.resolved_path(root_index).parent.resolve()
        frontend_root = (
            declaration.recipe.document.resolved_path(root_index).parent / "frontend"
        ).resolve()
    return [
        {"role": "comfyui_source", "path": str(source_root)},
        {"role": "python_home", "path": str(python_home)},
        {"role": "python_imports", "path": str(python_imports)},
        {"role": "native_dependencies", "path": str(native_dependencies)},
        {"role": "frontend", "path": str(frontend_root)},
        {"role": "node_implementations", "path": str(source_root)},
    ]


def _synthetic_python_runtime_paths_for_tests() -> dict[str, object]:
    stdlib = Path(sysconfig.get_path("stdlib")).resolve()
    dynload = Path(
        sysconfig.get_config_var("DESTSHARED") or stdlib / "lib-dynload"
    ).resolve()
    return {
        "python_base_prefix": str(Path(sys.base_prefix).resolve()),
        "python_stdlib_paths": list(dict.fromkeys((str(stdlib), str(dynload)))),
    }


def synthetic_runtime_approval_for_tests() -> SimpleNamespace:
    """Return a complete synthetic runtime approval for ComfyUI tests."""
    return SimpleNamespace(
        tool_version=SYNTHETIC_COMFYUI_TOOL_VERSION,
        configuration_version=COMFYUI_CONFIGURATION_VERSION,
        manifest_sha256="0" * 64,
        public_key_sha256="0" * 64,
        payload={
            "interpreter": {"path": sys.executable},
            "roots": synthetic_comfyui_runtime_roots_for_tests(),
            **_synthetic_python_runtime_paths_for_tests(),
        },
    )


def allow_synthetic_runtime_for_tests(
    candidate: Any, approval: Any = None, **_launch_inputs: Any
) -> Any:
    """Permit launch checks only for synthetic test candidates."""
    version = candidate.declaration.engine.version
    if version != SYNTHETIC_COMFYUI_TOOL_VERSION or not version.startswith("synthetic-"):
        raise AssertionError("test runtime override accepts only synthetic fixtures")
    if approval is not None:
        payload = getattr(approval, "payload", None)
        if not isinstance(payload, dict):
            raise AssertionError("test runtime approval payload must be mutable")
        payload["roots"] = synthetic_comfyui_runtime_roots_for_tests(candidate)
        declaration = candidate.declaration
        launch = declaration.engine.launch
        if launch is None or launch.kind != "python-script":
            raise AssertionError(
                "synthetic ComfyUI candidate must declare Python-script launch"
            )
        interpreter = launch.interpreter.resolved_path(declaration.root_index)
        payload["interpreter"] = {
            "path": str(interpreter.resolve(strict=True)),
            "size_bytes": launch.interpreter.size_bytes,
            "sha256": launch.interpreter.sha256,
        }
        entrypoint = declaration.engine.executable.resolved_path(
            declaration.root_index
        )
        payload["entrypoint"] = {
            "path": str(entrypoint.resolve(strict=True)),
            "size_bytes": declaration.engine.executable.size_bytes,
            "sha256": declaration.engine.executable.sha256,
        }
    return approval


def synthetic_child_environment_for_tests(
    names: Any, approval: Any = None
) -> dict[str, str]:
    """Use the synthetic approval roots for the test server's launch paths."""
    environment = {name: value for name in names if (value := os.environ.get(name))}
    if approval is None:
        return environment
    payload = getattr(approval, "payload", None)
    if not isinstance(payload, dict) or not isinstance(payload.get("roots"), list):
        raise AssertionError("test runtime approval must provide signed roots")
    roots = {
        item.get("role"): item.get("path")
        for item in payload["roots"]
        if isinstance(item, dict)
    }
    if not all(
        isinstance(roots.get(role), str)
        for role in ("python_home", "native_dependencies")
    ):
        raise AssertionError("test runtime approval is missing launch roots")
    environment.update(
        {
            "LD_LIBRARY_PATH": roots["native_dependencies"],
            "PATH": COMFYUI_CLOSED_PATH,
        }
    )
    return environment


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object) -> str:
    data = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return _sha256(data)


def _graph(*, edit: bool) -> dict[str, object]:
    graph: dict[str, object] = {
        "1": {
            "class_type": "UNETLoader",
            "inputs": {"unet_name": "synthetic-qwen-image-edit-2511.safetensors"},
        },
        "2": {
            "class_type": "CLIPLoader",
            "inputs": {
                "clip_name": "synthetic-comfyui-text.safetensors",
                "type": "qwen_image",
            },
        },
        "3": {
            "class_type": "VAELoader",
            "inputs": {"vae_name": "synthetic-comfyui-vae.safetensors"},
        },
        "4": {
            "class_type": "CLIPTextEncode",
            "inputs": {"clip": ["2", 0], "text": "$prompt"},
        },
        "5": {
            "class_type": "ModelSamplingAuraFlow",
            "inputs": {"model": ["1", 0], "shift": "$flow_shift"},
        },
        "7": {
            "class_type": "KSampler",
            "inputs": {
                "model": ["5", 0],
                "positive": ["4", 0],
                "negative": ["4", 0],
                "seed": "$seed",
                "steps": "$steps",
                "cfg": "$cfg_scale",
                "sampler_name": "euler",
                "scheduler": "simple",
                "denoise": 1.0,
            },
        },
        "8": {
            "class_type": "VAEDecode",
            "inputs": {"samples": ["7", 0], "vae": ["3", 0]},
        },
        "9": {
            "class_type": "SaveImage",
            "inputs": {"images": ["8", 0], "filename_prefix": "$output_basename"},
        },
    }
    if edit:
        graph["6"] = {
            "class_type": "LoadImage",
            "inputs": {"image": "$artifact:0"},
        }
        graph["10"] = {
            "class_type": "ImageScale",
            "inputs": {
                "image": ["6", 0],
                "upscale_method": "lanczos",
                "width": "$width",
                "height": "$height",
                "crop": "center",
            },
        }
        graph["11"] = {
            "class_type": "VAEEncode",
            "inputs": {"pixels": ["10", 0], "vae": ["3", 0]},
        }
        graph["7"]["inputs"]["latent_image"] = ["11", 0]  # type: ignore[index]
    else:
        graph["6"] = {
            "class_type": "EmptyLatentImage",
            "inputs": {"width": "$width", "height": "$height", "batch_size": 1},
        }
        graph["7"]["inputs"]["latent_image"] = ["6", 0]  # type: ignore[index]
    return graph


def _qwen_profile_graph(
    *,
    edit: bool,
    reference_latents_method: str = "index_timestep_zero",
) -> dict[str, object]:
    graph: dict[str, object] = {
        "1": {
            "class_type": "UNETLoader",
            "inputs": {
                "unet_name": "synthetic-qwen-image-edit-2511.safetensors",
                "weight_dtype": "default",
            },
        },
        "2": {
            "class_type": "CLIPLoader",
            "inputs": {
                "clip_name": "synthetic-comfyui-text.safetensors",
                "type": "qwen_image",
            },
        },
        "3": {
            "class_type": "VAELoader",
            "inputs": {"vae_name": "synthetic-comfyui-vae.safetensors"},
        },
        "4": {
            "class_type": "LoadImage",
            "inputs": {"image": "$artifact:0"},
        },
        "5": {
            "class_type": "FluxKontextImageScale",
            "inputs": {"image": ["4", 0]},
        },
        "6": {
            "class_type": "TextEncodeQwenImageEditPlus",
            "inputs": {
                "clip": ["2", 0],
                "vae": ["3", 0],
                "image1": ["5", 0],
                "prompt": "$prompt",
            },
        },
        "7": {
            "class_type": "TextEncodeQwenImageEditPlus",
            "inputs": {
                "clip": ["2", 0],
                "vae": ["3", 0],
                "image1": ["5", 0],
                "prompt": "",
            },
        },
        "8": {
            "class_type": "FluxKontextMultiReferenceLatentMethod",
            "inputs": {
                "conditioning": ["6", 0],
            "reference_latents_method": reference_latents_method,
            },
        },
        "9": {
            "class_type": "FluxKontextMultiReferenceLatentMethod",
            "inputs": {
                "conditioning": ["7", 0],
            "reference_latents_method": reference_latents_method,
            },
        },
        "10": {
            "class_type": "ModelSamplingAuraFlow",
            "inputs": {"model": ["1", 0], "shift": "$flow_shift"},
        },
        "11": {
            "class_type": "CFGNorm",
            "inputs": {"model": ["10", 0], "strength": 1.0, "pre_cfg": False},
        },
    }
    latent_id = "12"
    sampler_id = "13"
    if edit:
        graph[latent_id] = {
            "class_type": "VAEEncode",
            "inputs": {"pixels": ["5", 0], "vae": ["3", 0]},
        }
    else:
        graph[latent_id] = {
            "class_type": "EmptyLatentImage",
            "inputs": {"width": "$width", "height": "$height", "batch_size": 1},
        }
    graph[sampler_id] = {
        "class_type": "KSampler",
        "inputs": {
            "model": ["11", 0],
            "positive": ["8", 0],
            "negative": ["9", 0],
            "latent_image": [latent_id, 0],
            "seed": "$seed",
            "steps": "$steps",
            "cfg": "$cfg_scale",
            "sampler_name": "euler",
            "scheduler": "simple",
            "denoise": 1.0,
        },
    }
    graph["14"] = {
        "class_type": "VAEDecode",
        "inputs": {"samples": [sampler_id, 0], "vae": ["3", 0]},
    }
    if edit:
        graph["15"] = {
            "class_type": "ImageScale",
            "inputs": {
                "image": ["14", 0],
                "upscale_method": "lanczos",
                "width": "$width",
                "height": "$height",
                "crop": "center",
            },
        }
        output_source = ["15", 0]
    else:
        output_source = ["14", 0]
    graph["16"] = {
        "class_type": "SaveImage",
        "inputs": {"images": output_source, "filename_prefix": "$output_basename"},
    }
    return graph


def recipe_document(
    *,
    node_sha256: str,
    tool_version: str = SYNTHETIC_COMFYUI_TOOL_VERSION,
    profile_version: int = 1,
    initial_port: int = 0,
    request_timeout_seconds: float = 5.0,
    readiness_timeout_seconds: float = 5.0,
    poll_timeout_seconds: float = 2.0,
    reference_latents_method: str = "index_timestep_zero",
) -> dict[str, object]:
    required = ["diffusion_model", "vae", "text_encoder", "other"]
    generate_graph = (
        _qwen_profile_graph(
            edit=False,
            reference_latents_method=reference_latents_method,
        )
        if profile_version == 2
        else _graph(edit=False)
    )
    edit_graph = (
        _qwen_profile_graph(
            edit=True,
            reference_latents_method=reference_latents_method,
        )
        if profile_version == 2
        else _graph(edit=True)
    )
    if profile_version == 2:
        node_names = {
            str(node["class_type"])
            for graph in (generate_graph, edit_graph)
            for node in graph.values()
        }
    else:
        node_names = set(COMFYUI_NODE_INPUTS)
    nodes = {
        name: {
            "component_id": COMFYUI_NODE_BUNDLE_ID,
            "sha256": node_sha256,
        }
        for name in node_names
    }
    sampling = (
        {
            "sampling_method": "euler",
            "steps": 40,
            "cfg_scale": 4.0,
            "flow_shift": 3.1,
            "strength": None,
        }
        if profile_version == 2
        else {
            "sampling_method": "euler",
            "steps": 8,
            "cfg_scale": 2.5,
            "flow_shift": 3.0,
            "strength": None,
        }
    )
    return {
        "schema": "media-generation.comfyui-recipe",
        "schema_version": profile_version,
        "id": "synthetic-comfyui-qwen-edit-recipe",
        "engine_id": COMFYUI_TOOL_ID,
        "model_family": "qwen_image_edit_2511",
        "sampling": sampling,
        "operations": {
            "generate": {
                "required_component_roles": required,
                "references": ["reference"] if profile_version == 2 else [],
                "graph": generate_graph,
            },
            "edit": {
                "required_component_roles": required,
                "references": ["source"],
                "graph": edit_graph,
            },
        },
        "limits": {"max_width": 512, "max_height": 512},
        "nodes": nodes,
        "server": {
            "host": "127.0.0.1",
            "port": initial_port,
            "argv": [
                "--listen",
                "$host",
                "--port",
                "$port",
                "--base-directory",
                "$base_directory",
                "--disable-all-custom-nodes",
                "--disable-auto-launch",
                "--offline",
                "--front-end-root",
                "$frontend_root",
                "--feature-flag",
                "enable_telemetry=false",
                "--output-directory",
                "$output_directory",
                "--temp-directory",
                "$temp_directory",
                "--input-directory",
                "$input_directory",
            ],
            "environment_names": ["PATH", "PYTHONHASHSEED"],
            "readiness_path": "/system_stats",
            "identity_path": ["system", "comfyui_version"],
            "identity_value": tool_version,
            "shutdown_timeout_seconds": 1.0,
        },
        "api": {
            "prompt_path": "/prompt",
            "jobs_path": "/api/jobs?limit=1000",
            "queue_path": "/queue",
            "node_replacements_path": "/node_replacements",
            "history_path_template": "/history/{prompt_id}",
            "view_path": "/view",
            "upload_path": "/upload/image",
            "request_timeout_seconds": request_timeout_seconds,
            "poll_timeout_seconds": poll_timeout_seconds,
            "readiness_timeout_seconds": readiness_timeout_seconds,
            "max_output_bytes": 1024 * 1024,
        },
        "output": {
            "node_id": "16" if profile_version == 2 else "9",
            "field": "images",
        },
    }


@dataclass(frozen=True, slots=True)
class ComfyUIBundle:
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
        (self.files / "comfy-mode.json").write_text(
            json.dumps(settings, sort_keys=True), encoding="utf-8"
        )


def build_comfyui_bundle(
    tmp_path: Path,
    *,
    tool_version: str = SYNTHETIC_COMFYUI_TOOL_VERSION,
    python_interpreter: Path | None = None,
    profile_version: int | None = None,
    node_authority_version: int = 2,
    node_authority_classes: tuple[str, ...] | None = None,
    include_unused_vision_encoder: bool = False,
    initial_port: int = 0,
    request_timeout_seconds: float = 5.0,
    readiness_timeout_seconds: float = 5.0,
    poll_timeout_seconds: float = 2.0,
    tamper_node_sha: bool = False,
    omit_trusted_evidence: bool = False,
    omit_node_authority: bool = False,
    omit_workflow_authority: bool = False,
    tamper_workflow_sha: bool = False,
    alter_recipe: dict[str, object] | None = None,
    reference_latents_method: str = "index_timestep_zero",
) -> ComfyUIBundle:
    if profile_version is None:
        profile_version = (
            1 if tool_version.startswith("synthetic-") else 2
        )
    if node_authority_version not in {2, 3}:
        raise ValueError("node_authority_version must be 2 or 3")
    if node_authority_version == 3 and profile_version != 2:
        raise ValueError("node authority v3 requires the Qwen graph profile v2")
    root = tmp_path / "bundle"
    files = root / "files"
    files.mkdir(parents=True)
    interpreter_path = (
        Path(sys.executable).resolve(strict=True)
        if python_interpreter is None
        else python_interpreter.resolve(strict=True)
    )
    interpreter_bytes = interpreter_path.read_bytes()
    source_root = files / "comfyui-source"
    source_root.mkdir()
    engine_path = source_root / "comfyui-server.py"
    engine_path.write_bytes(COMFYUI_SOURCE.read_bytes())
    engine_path.chmod(0o444)
    node_authority_generated = None
    if node_authority_version == 3:
        for relative_path, data in _synthetic_node_sources().items():
            target = source_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        node_authority_generated = generate_node_authority(
            source_root=source_root,
            source_paths=COMFYUI_NODE_SOURCE_PATHS,
            classes=node_authority_classes or COMFYUI_QWEN_NODE_CLASSES,
            source_root_sha256=_tree_sha256(source_root)[0],
            tool_id=COMFYUI_TOOL_ID,
            tool_version=tool_version,
            component_id=COMFYUI_NODE_BUNDLE_ID,
        )
    frontend_root = files / "frontend"
    frontend_root.mkdir()
    (frontend_root / "index.html").write_text(
        "<!doctype html><title>synthetic frontend</title>\n", encoding="utf-8"
    )

    components: list[dict[str, Any]] = []
    component_paths: dict[str, Path] = {}
    expected_documents: dict[str, dict[str, object]] = {}
    contents = {
        "diffusion_model": ("synthetic-qwen-image-edit-2511.safetensors", b"synthetic-comfyui-diffusion"),
        "vae": ("synthetic-comfyui-vae.safetensors", b"synthetic-comfyui-vae"),
        "text_encoder": ("synthetic-comfyui-text.safetensors", b"synthetic-comfyui-text"),
        "other": (
            "synthetic-comfyui-nodes.bin",
            (
                node_authority_generated.archive
                if node_authority_generated is not None
                else b"synthetic-comfyui-node-bundle-v1"
            ),
        ),
    }
    identifiers = {
        "diffusion_model": "synthetic-comfyui-diffusion-model",
        "vae": "synthetic-comfyui-vae",
        "text_encoder": "synthetic-comfyui-text-encoder",
        "other": COMFYUI_NODE_BUNDLE_ID,
    }
    for role, (filename, data) in contents.items():
        identifier = identifiers[role]
        declaration, expected, artifact = _component(files, identifier, role, filename, data)
        components.append(declaration)
        component_paths[role] = files / filename
        expected_documents[identifier] = expected
    node_sha = components[-1]["artifact"]["sha256"]
    if include_unused_vision_encoder:
        identifier = "synthetic-comfyui-unused-vision-encoder"
        declaration, expected, _ = _component(
            files,
            identifier,
            "vision_encoder",
            "synthetic-comfyui-unused-vision-encoder.bin",
            b"synthetic-comfyui-unused-vision-encoder",
        )
        components.append(declaration)
        component_paths["vision_encoder"] = files / declaration["artifact"]["path"]
        expected_documents[identifier] = expected

    recipe_payload = recipe_document(
        node_sha256="0" * 64 if tamper_node_sha else node_sha,
        tool_version=tool_version,
        profile_version=profile_version,
        initial_port=initial_port,
        request_timeout_seconds=request_timeout_seconds,
        readiness_timeout_seconds=readiness_timeout_seconds,
        poll_timeout_seconds=poll_timeout_seconds,
        reference_latents_method=reference_latents_method,
    )
    if alter_recipe is not None:
        for key, value in alter_recipe.items():
            recipe_payload[key] = value
    (files / "recipe.json").write_bytes(
        (json.dumps(recipe_payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    recipe_path = _pin(files, "recipe.json")

    engine_artifact = _pin(files, "comfyui-source/comfyui-server.py")
    engine_provenance, engine_provenance_document = _provenance(
        files,
        "synthetic-comfyui-engine-revision",
        engine_artifact,
        kind="engine",
        identifier=COMFYUI_TOOL_ID,
        role="engine",
    )
    engine_license, engine_license_document = _license(
        files,
        engine_artifact,
        kind="engine",
        identifier=COMFYUI_TOOL_ID,
        role="engine",
    )
    interpreter_pin = {
        "root": "python",
        "path": interpreter_path.name,
        "size_bytes": len(interpreter_bytes),
        "sha256": _sha256(interpreter_bytes),
    }
    interpreter_identifier = f"{COMFYUI_TOOL_ID}-python-interpreter"
    interpreter_provenance, interpreter_provenance_document = _provenance(
        files,
        "synthetic-test-python-interpreter-revision",
        interpreter_pin,
        kind="engine",
        identifier=interpreter_identifier,
        role="python-interpreter",
    )
    interpreter_license, interpreter_license_document = _license(
        files,
        interpreter_pin,
        kind="engine",
        identifier=interpreter_identifier,
        role="python-interpreter",
    )
    launch = {
        "schema": "media-generation.engine-launch",
        "schema_version": 1,
        "kind": "python-script",
        "interpreter": interpreter_pin,
        "provenance": interpreter_provenance,
        "license": interpreter_license,
    }
    engine = {
        "id": COMFYUI_TOOL_ID,
        "version": tool_version,
        "build": "synthetic-test-only",
        "executable": engine_artifact,
        "provenance": engine_provenance,
        "license": engine_license,
        "architecture_flags": {"comfyui_api_contract": f"v{profile_version}"},
        "launch": launch,
    }
    required_roles = ["diffusion_model", "vae", "text_encoder", "other"]
    recipe_flags = {"comfyui_api_contract": f"v{profile_version}"}
    claims = [
        "engine",
        "version",
        "recipe",
        *(f"role:{role}" for role in required_roles),
        "flag:comfyui_api_contract",
        COMFYUI_QWEN_POLICY_CLAIM,
    ]
    recipe = {
        "id": recipe_payload["id"],
        "document": recipe_path,
        "required_component_roles": required_roles,
        "engine_id": COMFYUI_TOOL_ID,
        "engine_version": tool_version,
        "pipeline_version": f"qwen-image-edit-2511-pipeline@{profile_version}",
        "template_version": f"comfyui-qwen-edit@{profile_version}",
        "architecture_flags": recipe_flags,
        "compatibility_evidence": [],
    }
    compatibility = _compatibility_document(engine, recipe, components, [], claims)
    compatibility["engine"]["launch"] = launch
    compatibility_pin = _write_json(files, "compatibility.json", compatibility)
    recipe["compatibility_evidence"] = [{"claims": claims, "document": compatibility_pin}]
    declaration = {
        "schema": "media-generation.candidate-declaration",
        "schema_version": 1,
        "id": "t09-synthetic-comfyui-candidate",
        "roots": [
            {"id": "files", "path": "files"},
            {"id": "python", "path": str(interpreter_path.parent)},
        ],
        "engine": engine,
        "recipe": recipe,
        "components": components,
        "adapters": [],
    }
    declaration_path = root / "candidate.json"
    declaration_path.write_text(json.dumps(declaration), encoding="utf-8")

    records: list[candidate.TrustedEvidence] = []

    def add(document: dict[str, object]) -> None:
        data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        records.append(
            candidate.TrustedEvidence(
                authority_id=f"t09-authority-{len(records) + 1}",
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
    add(interpreter_provenance_document)
    add(interpreter_license_document)
    add(compatibility)
    node_authority = (
        dict(node_authority_generated.document)
        if node_authority_generated is not None
        else {
            "schema": "media-generation.comfyui-node-implementations",
            "schema_version": 2,
            "tool_id": COMFYUI_TOOL_ID,
            "tool_version": tool_version,
            "nodes": {
                name: {
                    **recipe_payload["nodes"][name],
                    "inputs": COMFYUI_NODE_INPUTS[name],
                }
                for name in recipe_payload["nodes"]
            },
        }
    )
    if not omit_node_authority and not omit_trusted_evidence:
        add(node_authority)
    workflow_authority = {
        "schema": "media-generation.comfyui-workflow-approval",
        "schema_version": 1,
        "tool_id": COMFYUI_TOOL_ID,
        "tool_version": tool_version,
        "recipe_document_sha256": recipe_path["sha256"],
        "operations": {
            operation_name: {
                "graph_sha256": (
                    "0" * 64
                    if tamper_workflow_sha
                    else _digest(operation["graph"])
                ),
                "nodes": {
                    node_name: {
                        "component_id": recipe_payload["nodes"][node_name][
                            "component_id"
                        ],
                        "sha256": recipe_payload["nodes"][node_name]["sha256"],
                    }
                    for node_name in {
                        str(node["class_type"])
                        for node in operation["graph"].values()
                    }
                },
            }
            for operation_name, operation in recipe_payload["operations"].items()
        },
    }
    if not omit_workflow_authority and not omit_trusted_evidence:
        add(workflow_authority)
    trusted_path = root / "trusted-evidence.json"
    if not omit_trusted_evidence:
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
            },
            sort_keys=True,
        ),
            encoding="utf-8",
        )
    return ComfyUIBundle(
        tmp_path=tmp_path,
        files=source_root,
        declaration_path=declaration_path,
        trusted_evidence_path=trusted_path,
        engine_path=engine_path,
        recipe_path=files / "recipe.json",
        component_paths=component_paths,
        recipe_document=recipe_payload,
        declaration=declaration,
    )
