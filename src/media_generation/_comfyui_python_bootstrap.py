"""Check Python's signed venv and import roots before launching ComfyUI."""

from __future__ import annotations

import sys


def _normal_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SystemExit(f"ComfyUI Python bootstrap: {label} is invalid")
    if sys.platform == "win32":
        value = value.replace("\\", "/")
        absolute = value.startswith("//") or (
            len(value) >= 3 and value[1] == ":" and value[2] == "/"
        )
        prefix = "//" if value.startswith("//") else ""
        body = value[2:] if prefix else value
    else:
        absolute = value.startswith("/") and "\\" not in value
        prefix = "/" if absolute else ""
        body = value[1:] if prefix else value
    if not absolute:
        raise SystemExit(f"ComfyUI Python bootstrap: {label} is not absolute")
    components = body.split("/")
    if any(part in {"", ".", ".."} for part in components):
        raise SystemExit(f"ComfyUI Python bootstrap: {label} is not normalized")
    normalized = prefix + "/".join(components)
    if sys.platform == "win32" and len(normalized) == 2 and normalized[1] == ":":
        normalized += "/"
    return normalized


def _path_key(path: str) -> str:
    return path.casefold() if sys.platform == "win32" else path


def _within(path: str, root: str) -> bool:
    path_key = _path_key(path)
    root_key = _path_key(root)
    if path_key == root_key:
        return True
    boundary = root_key if root_key.endswith("/") else root_key + "/"
    return path_key.startswith(boundary)


def _check_paths(paths: list[str], roots: tuple[str, ...], *, label: str) -> None:
    if not paths:
        raise SystemExit(f"ComfyUI Python bootstrap: {label} is empty")
    for index, value in enumerate(paths):
        path = _normal_path(value, label=f"{label}[{index}]")
        if not any(_within(path, root) for root in roots):
            raise SystemExit(
                f"ComfyUI Python bootstrap: {label}[{index}] is outside signed runtime roots"
            )


def _main() -> None:
    if not sys.flags.safe_path or not sys.flags.no_user_site or not sys.flags.no_site:
        raise SystemExit("ComfyUI Python bootstrap: isolated startup flags are required")
    arguments = sys.argv[1:]
    if len(arguments) < 9 or arguments[2] != "--stdlib-paths":
        raise SystemExit("ComfyUI Python bootstrap: launch arguments are invalid")
    try:
        imports_marker = arguments.index("--import-roots", 3)
        separator = arguments.index("--", imports_marker + 1)
    except ValueError as error:
        raise SystemExit("ComfyUI Python bootstrap: launch arguments are invalid") from error
    if imports_marker == 3 or len(arguments[imports_marker + 1 : separator]) != 2:
        raise SystemExit("ComfyUI Python bootstrap: launch arguments are invalid")

    python_home = _normal_path(arguments[0], label="signed Python home")
    python_base_prefix = _normal_path(arguments[1], label="signed Python base prefix")
    python_stdlib_paths = tuple(
        _normal_path(value, label=f"signed Python standard library root[{index}]")
        for index, value in enumerate(arguments[3:imports_marker])
    )
    if not python_stdlib_paths:
        raise SystemExit("ComfyUI Python bootstrap: signed standard library roots are empty")
    python_imports = _normal_path(
        arguments[imports_marker + 1], label="signed Python imports"
    )
    comfyui_source = _normal_path(
        arguments[imports_marker + 2], label="signed ComfyUI source"
    )
    signed_roots = (
        python_base_prefix,
        *python_stdlib_paths,
        python_imports,
        comfyui_source,
    )
    for label, value in (
        ("sys.prefix", sys.prefix),
        ("sys.exec_prefix", sys.exec_prefix),
        ("sys.base_prefix", sys.base_prefix),
        ("sys.base_exec_prefix", sys.base_exec_prefix),
    ):
        expected = python_base_prefix if label.startswith("sys.base_") else python_home
        if _path_key(_normal_path(value, label=label)) != _path_key(expected):
            signed_home = "signed Python base prefix" if label.startswith("sys.base_") else "signed Python home"
            raise SystemExit(
                f"ComfyUI Python bootstrap: {label} does not match the {signed_home}"
            )
    if any(not _within(path, python_base_prefix) for path in python_stdlib_paths):
        raise SystemExit(
            "ComfyUI Python bootstrap: standard library root is outside the signed base prefix"
        )

    _check_paths(sys.path, (python_base_prefix,), label="initial sys.path")
    effective_paths = [*python_stdlib_paths, python_imports, comfyui_source]
    sys.path = effective_paths
    _check_paths(sys.path, signed_roots, label="effective sys.path")

    if len(arguments) <= separator + 1:
        raise SystemExit("ComfyUI Python bootstrap: launch arguments are invalid")
    entrypoint = _normal_path(arguments[separator + 1], label="ComfyUI entrypoint")
    if not _within(entrypoint, comfyui_source):
        raise SystemExit(
            "ComfyUI Python bootstrap: entrypoint is outside signed ComfyUI source"
        )

    import runpy

    _check_paths(sys.path, signed_roots, label="effective sys.path")
    sys.argv = [entrypoint, *arguments[separator + 2 :]]
    runpy.run_path(entrypoint, run_name="__main__")


if __name__ == "__main__":
    _main()
