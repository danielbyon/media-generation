"""Fixed catalog of runtimes the collector may identify passively.

Adding a runtime here is an explicit code change: manifests select catalog
entries but cannot inject executable names, argv vectors, or search hooks.
Known paths are bounded, conventional install locations checked without
recursive traversal.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    """Static identity rules for one supported engine or Python package."""

    id: str
    kind: str
    names: tuple[str, ...] = ()
    known_paths: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    version_argv: tuple[str, ...] | None = None
    version_file: str | None = None
    git_head: bool = False


RUNTIME_CATALOG: dict[str, RuntimeSpec] = {
    "stable-diffusion.cpp": RuntimeSpec(
        id="stable-diffusion.cpp",
        kind="binary",
        names=("sd", "stable-diffusion.cpp"),
        known_paths=(
            "~/stable-diffusion.cpp/build/bin/sd",
            "~/src/stable-diffusion.cpp/build/bin/sd",
            "/opt/stable-diffusion.cpp/build/bin/sd",
        ),
        version_argv=("--help",),
    ),
    "comfyui": RuntimeSpec(
        id="comfyui",
        kind="directory",
        known_paths=(
            "~/ComfyUI",
            "~/comfyui",
            "~/Projects/ComfyUI",
            "~/projects/ComfyUI",
            "/opt/ComfyUI",
            "~/ComfyUI_windows_portable/ComfyUI",
        ),
        markers=("main.py",),
        version_file="comfyui_version.py",
        git_head=True,
    ),
    "invokeai": RuntimeSpec(
        id="invokeai",
        kind="binary",
        names=("invokeai",),
        known_paths=("~/.local/bin/invokeai", "/usr/local/bin/invokeai"),
        version_argv=("--version",),
    ),
    "ollama": RuntimeSpec(
        id="ollama",
        kind="binary",
        names=("ollama",),
        known_paths=("~/.local/bin/ollama", "/usr/local/bin/ollama", "/usr/bin/ollama"),
        version_argv=("--version",),
    ),
    "llama.cpp": RuntimeSpec(
        id="llama.cpp",
        kind="binary",
        names=("llama-server", "llama-cli"),
        known_paths=(
            "~/llama.cpp/build/bin/llama-server",
            "~/src/llama.cpp/build/bin/llama-server",
            "/opt/llama.cpp/build/bin/llama-server",
        ),
        version_argv=("--version",),
    ),
    "diffusers": RuntimeSpec(id="diffusers", kind="python_distribution", names=("diffusers",)),
    "torch": RuntimeSpec(id="torch", kind="python_distribution", names=("torch",)),
    "transformers": RuntimeSpec(id="transformers", kind="python_distribution", names=("transformers",)),
    "rocm": RuntimeSpec(id="rocm", kind="python_distribution", names=("rocm",)),
}


def runtime_specs() -> tuple[RuntimeSpec, ...]:
    """Return the catalog in a stable, human-readable order."""
    return tuple(RUNTIME_CATALOG[key] for key in (
        "stable-diffusion.cpp",
        "comfyui",
        "invokeai",
        "ollama",
        "llama.cpp",
        "diffusers",
        "torch",
        "transformers",
        "rocm",
    ))
