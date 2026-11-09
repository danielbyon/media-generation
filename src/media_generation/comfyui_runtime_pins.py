"""Verify host-approved ComfyUI runtime identities before an execution starts."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .backend_provenance import canonical_json
from .images import InputValidationError, open_regular
from .privacy import is_valid_python_hash_seed


RUNTIME_APPROVAL_ENV = "MEDIA_GENERATION_COMFYUI_RUNTIME_APPROVAL_PATH"
# macOS exposes /etc through a symlink; use its canonical host path there.
_HOST_TRUST_KEY_PATH = Path(
    "/private/etc/media-generation/comfyui-runtime-public-key"
    if sys.platform == "darwin"
    else "/etc/media-generation/comfyui-runtime-public-key"
)
RUNTIME_APPROVAL_SCHEMA = "media-generation.comfyui-runtime-pin-approval"
RUNTIME_PIN_SET_SCHEMA = "media-generation.comfyui-runtime-pin-set"
RUNTIME_PIN_SCHEMA_VERSION = 5
COMFYUI_PYTHON_BOOTSTRAP_PATH = Path(__file__).with_name(
    "_comfyui_python_bootstrap.py"
).resolve()
COMFYUI_CLOSED_PATH = os.pathsep.join(("/usr/bin", "/bin", "/usr/sbin", "/sbin"))
_MAX_APPROVAL_BYTES = 2 * 1024 * 1024
_MAX_PUBLIC_KEY_BYTES = 256
_MAX_JSON_DEPTH = 48
_MAX_ROOT_ENTRIES = 100_000
_MAX_TREE_DEPTH = 64
_MAX_PINNED_FILE_BYTES = 32 * 1024**3
_MAX_ROOT_BYTES = 8 * 1024**3
_MAX_TOTAL_ROOT_BYTES = 16 * 1024**3
_MAX_TOTAL_PINNED_FILE_BYTES = 64 * 1024**3
_HASH_CHUNK_BYTES = 1024 * 1024
_ROOT_ROLES = frozenset(
    {
        "comfyui_source",
        "python_home",
        "python_imports",
        "native_dependencies",
        "frontend",
        "node_implementations",
    }
)
_SHA256_LENGTH = 64


class RuntimePinError(ValueError):
    """A signed runtime approval is missing, unsafe, or does not match."""


@dataclass(frozen=True, slots=True)
class RuntimePinApproval:
    """Authenticated runtime pins and the identity of their trust inputs."""

    payload: Mapping[str, object]
    manifest_sha256: str
    public_key_sha256: str

    @property
    def tool_version(self) -> str:
        return str(self.payload["tool_version"])

    @property
    def configuration_version(self) -> str:
        return str(self.payload["configuration_version"])

    @property
    def candidate_id(self) -> str:
        return str(self.payload["candidate_id"])


def load_runtime_pin_approval(*, verify_paths: bool = True) -> RuntimePinApproval:
    """Load the canonical manifest and verify it with the application trust key.

    The manifest path comes from the host environment. The trust key always
    comes from a fixed host path with root-owned, protected, symlink-free
    components. Runtime roots are hashed when ``verify_paths`` is true.
    """

    approval_path = _configured_path(RUNTIME_APPROVAL_ENV)
    raw_approval = _read_external_file(
        approval_path, maximum=_MAX_APPROVAL_BYTES, label="runtime approval"
    )
    raw_public_key = _read_host_trust_key()
    public_key = _decode_public_key(raw_public_key)
    envelope = _parse_json(raw_approval, label="runtime approval")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise RuntimePinError("ComfyUI runtime approval envelope is invalid")
    if (canonical_json(envelope) + "\n").encode("utf-8") != raw_approval:
        raise RuntimePinError("ComfyUI runtime approval is not canonical JSON")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise RuntimePinError("ComfyUI runtime approval payload is invalid")
    signature = _decode_signature(envelope.get("signature"))
    payload_bytes = canonical_json(payload).encode("utf-8")
    if not _verify_ed25519(public_key, signature, payload_bytes):
        raise RuntimePinError("ComfyUI runtime approval signature is invalid")

    _validate_payload(payload)
    if verify_paths:
        _verify_runtime_paths(payload)
    return RuntimePinApproval(
        payload=MappingProxyType(payload),
        manifest_sha256=hashlib.sha256(raw_approval).hexdigest(),
        public_key_sha256=hashlib.sha256(public_key).hexdigest(),
    )


def verify_candidate_binding(
    approval: RuntimePinApproval,
    *,
    tool_id: str,
    tool_version: str,
    configuration_version: str,
    candidate_id: str,
    interpreter: Mapping[str, object],
    entrypoint: Mapping[str, object],
    workflow: Mapping[str, object],
    components: list[Mapping[str, object]],
    trusted_evidence: list[Mapping[str, object]],
    frontend_root: Path,
) -> None:
    """Require the signed approval to identify one exact ComfyUI candidate."""

    payload = approval.payload
    expected_workflow_root = str(_external_runtime_path(frontend_root))
    roots = payload["roots"]
    frontend_roots = [root for root in roots if root["role"] == "frontend"]
    expected = {
        "tool_id": tool_id,
        "tool_version": tool_version,
        "configuration_version": configuration_version,
        "candidate_id": candidate_id,
        "interpreter": dict(interpreter),
        "entrypoint": dict(entrypoint),
        "workflow": dict(workflow),
        "components": sorted(
            (dict(item) for item in components), key=lambda item: str(item["component_id"])
        ),
        "trusted_evidence": sorted(
            (dict(item) for item in trusted_evidence),
            key=lambda item: str(item["authority_id"]),
        ),
    }
    for key, value in expected.items():
        actual = payload.get(key)
        if key == "components" and isinstance(actual, list):
            actual = sorted(actual, key=lambda item: str(item.get("component_id")))
        elif key == "trusted_evidence" and isinstance(actual, list):
            actual = sorted(actual, key=lambda item: str(item.get("authority_id")))
        if actual != value:
            raise RuntimePinError(f"ComfyUI runtime approval does not bind candidate {key}")
    if len(frontend_roots) != 1 or frontend_roots[0]["path"] != expected_workflow_root:
        raise RuntimePinError("ComfyUI frontend path does not match its signed pin")


def verify_runtime_launch_binding(
    approval: RuntimePinApproval,
    *,
    argv: Sequence[str],
    environment: Mapping[str, str],
    workflow_path: Path,
    models_directory: Path,
    model_files: Sequence[Mapping[str, object]],
) -> None:
    """Match the child Python prefixes and import roots to the signed approval."""

    payload = approval.payload
    root_pins = payload.get("roots")
    if not isinstance(root_pins, list):
        raise RuntimePinError("ComfyUI runtime root pins are unavailable")
    roots: dict[str, Path] = {}
    for item in root_pins:
        if not isinstance(item, Mapping):
            raise RuntimePinError("ComfyUI runtime root pin is malformed")
        role = item.get("role")
        path = item.get("path")
        if not isinstance(role, str):
            raise RuntimePinError("ComfyUI runtime root role must be a string")
        if not isinstance(path, str) or role in roots:
            raise RuntimePinError("ComfyUI runtime root roles are malformed")
        roots[role] = Path(path)
    if set(roots) != _ROOT_ROLES:
        raise RuntimePinError("ComfyUI runtime root roles are incomplete")
    if not argv or not all(isinstance(value, str) and value for value in argv):
        raise RuntimePinError("ComfyUI child command is invalid")

    interpreter = payload.get("interpreter")
    if (
        not isinstance(interpreter, Mapping)
        or not argv
        or argv[0] != interpreter.get("path")
    ):
        raise RuntimePinError("ComfyUI child command does not use its signed interpreter")
    entrypoint = payload.get("entrypoint")
    if not isinstance(entrypoint, Mapping):
        raise RuntimePinError("ComfyUI signed entrypoint is unavailable")
    python_base_prefix = _external_runtime_path(
        Path(str(payload.get("python_base_prefix")))
    )
    raw_stdlib_paths = payload.get("python_stdlib_paths")
    if not isinstance(raw_stdlib_paths, list):
        raise RuntimePinError("ComfyUI signed Python standard library roots are unavailable")
    python_stdlib_paths = tuple(
        _external_runtime_path(Path(path))
        for path in raw_stdlib_paths
        if isinstance(path, str)
    )
    if len(python_stdlib_paths) != len(raw_stdlib_paths):
        raise RuntimePinError("ComfyUI signed Python standard library roots are malformed")
    if (
        len(argv) < 13 + len(python_stdlib_paths)
        or tuple(argv[1:4]) != ("-P", "-s", "-S")
        or argv[4] != str(COMFYUI_PYTHON_BOOTSTRAP_PATH)
        or argv[7] != "--stdlib-paths"
    ):
        raise RuntimePinError("ComfyUI child command does not use the isolated Python bootstrap")
    imports_marker = 8 + len(python_stdlib_paths)
    delimiter_index = imports_marker + 3
    entrypoint_index = delimiter_index + 1
    if (
        argv[imports_marker] != "--import-roots"
        or argv[delimiter_index] != "--"
    ):
        raise RuntimePinError("ComfyUI child command does not use the isolated Python bootstrap")
    try:
        executable_path = _external_runtime_path(Path(argv[0]))
        python_home = _external_runtime_path(roots["python_home"])
        stdlib_paths = tuple(
            path.resolve(strict=True) for path in python_stdlib_paths
        )
        python_imports = _external_runtime_path(roots["python_imports"])
        source_root = _external_runtime_path(roots["comfyui_source"])
        entrypoint_path = _external_runtime_path(Path(argv[entrypoint_index]))
        resolved_workflow = workflow_path.resolve(strict=True)
        resolved_models = models_directory.resolve(strict=True)
    except OSError as error:
        raise RuntimePinError("A signed ComfyUI launch path is unavailable") from error
    if str(executable_path) != argv[0]:
        raise RuntimePinError("ComfyUI child command does not use an exact executable path")
    if str(entrypoint_path) != argv[entrypoint_index]:
        raise RuntimePinError("ComfyUI child command does not use an exact entrypoint path")
    if (
        argv[5] != str(python_home)
        or argv[6] != str(python_base_prefix)
        or tuple(argv[8:imports_marker])
        != tuple(str(path) for path in stdlib_paths)
        or tuple(argv[imports_marker + 1 : imports_marker + 3])
        != (str(python_imports), str(source_root))
    ):
        raise RuntimePinError("ComfyUI Python roots do not match their signed pins")
    if any(not path.is_relative_to(python_base_prefix) for path in stdlib_paths):
        raise RuntimePinError("ComfyUI Python standard library root is outside its signed base prefix")
    if not entrypoint_path.is_relative_to(source_root):
        raise RuntimePinError("ComfyUI entrypoint is outside its signed source root")

    if environment.get("PATH") != COMFYUI_CLOSED_PATH:
        raise RuntimePinError("ComfyUI child PATH does not match the fixed system policy")
    if (
        any(
            name.upper().startswith("PYTHON")
            and name.upper() != "PYTHONHASHSEED"
            for name in environment
        )
        or (
            "PYTHONHASHSEED" in environment
            and not is_valid_python_hash_seed(environment["PYTHONHASHSEED"])
        )
    ):
        raise RuntimePinError("ComfyUI child environment contains an unapproved Python setting")
    if environment.get("LD_LIBRARY_PATH") != str(roots["native_dependencies"]):
        raise RuntimePinError("ComfyUI native library path does not match its signed root")

    def option_value(option: str) -> str:
        positions = [index for index, value in enumerate(argv) if value == option]
        if len(positions) != 1 or positions[0] + 1 >= len(argv):
            raise RuntimePinError(f"ComfyUI child command must bind {option} exactly once")
        return argv[positions[0] + 1]

    if option_value("--front-end-root") != str(roots["frontend"]):
        raise RuntimePinError("ComfyUI frontend command path does not match its signed root")
    base_directory = Path(option_value("--base-directory"))
    try:
        resolved_base = base_directory.resolve(strict=True)
    except OSError as error:
        raise RuntimePinError("ComfyUI model base directory is unavailable") from error
    if resolved_models != resolved_base / "models":
        raise RuntimePinError("ComfyUI model search path does not match its child command")
    try:
        signed_node_root = _external_runtime_path(roots["node_implementations"])
        child_node_root = (resolved_base / "custom_nodes").resolve(strict=True)
    except OSError as error:
        raise RuntimePinError("ComfyUI node implementation path is unavailable") from error
    if not child_node_root.is_dir() or child_node_root != signed_node_root:
        raise RuntimePinError(
            "ComfyUI node implementation path does not match its signed root"
        )

    workflow_pin = payload.get("workflow")
    if (
        not isinstance(workflow_pin, Mapping)
        or resolved_workflow != Path(str(workflow_pin.get("path")))
    ):
        raise RuntimePinError("ComfyUI workflow path does not match its signed pin")

    approved_components = {
        str(item["component_id"]): item
        for item in payload["components"]
        if isinstance(item, Mapping) and isinstance(item.get("component_id"), str)
    }
    for model_file in model_files:
        component_id = model_file.get("component_id")
        component = approved_components.get(str(component_id))
        if component is None:
            raise RuntimePinError("ComfyUI model search path has no signed component")
        search_path = Path(str(model_file.get("search_path")))
        component_path = Path(str(component.get("path")))
        try:
            target_path = search_path.resolve(strict=True)
            expected_component_path = component_path.resolve(strict=True)
        except OSError as error:
            raise RuntimePinError("ComfyUI model search binding is unavailable") from error
        if (
            not search_path.is_absolute()
            or not search_path.is_relative_to(resolved_models)
            or not search_path.is_symlink()
            or target_path != expected_component_path
            or model_file.get("role") != component.get("role")
            or model_file.get("sha256") != component.get("sha256")
        ):
            raise RuntimePinError("ComfyUI model search path does not match its signed component")


def _configured_path(environment_name: str) -> Path:
    raw = os.environ.get(environment_name)
    if not isinstance(raw, str) or not raw:
        raise RuntimePinError("ComfyUI runtime approval or host trust key is not configured")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts or "\x00" in raw:
        raise RuntimePinError("ComfyUI runtime approval paths must be absolute and normalized")
    return path


def _read_host_trust_key() -> bytes:
    """Read the public key from the fixed application-owned host location."""

    path = _HOST_TRUST_KEY_PATH
    _validate_host_trust_root(path)
    return _read_external_file(
        path, maximum=_MAX_PUBLIC_KEY_BYTES, label="runtime public key"
    )


def _validate_host_trust_root(path: Path) -> None:
    """Reject trust keys exposed through user-owned, writable, or linked paths."""

    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise RuntimePinError("ComfyUI host trust key path is invalid")
    _reject_symlink_components(path)
    for parent in reversed(path.parents):
        try:
            info = parent.lstat()
        except OSError as error:
            raise RuntimePinError("ComfyUI host trust key path is unavailable") from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RuntimePinError("ComfyUI host trust key parent is not root-owned and protected")
    try:
        info = path.lstat()
    except OSError as error:
        raise RuntimePinError("ComfyUI host trust key is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise RuntimePinError("ComfyUI host trust key is not root-owned and protected")


def _external_runtime_path(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise RuntimePinError("ComfyUI runtime paths must be absolute and normalized")
    repository_root = Path(__file__).resolve().parents[2]
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimePinError("A pinned ComfyUI runtime path is unavailable") from error
    if resolved == repository_root or repository_root in resolved.parents:
        raise RuntimePinError("ComfyUI approvals and runtime pins must be outside the repository")
    _reject_symlink_components(path)
    return resolved


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise RuntimePinError("A pinned ComfyUI runtime path is unavailable") from error
        if stat.S_ISLNK(info.st_mode):
            raise RuntimePinError("ComfyUI runtime paths cannot contain symlinks")


def _read_external_file(path: Path, *, maximum: int, label: str) -> bytes:
    _external_runtime_path(path)
    try:
        with open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
                raise RuntimePinError(f"ComfyUI {label} has an unsupported file type or size")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
    except (OSError, InputValidationError) as error:
        raise RuntimePinError(f"ComfyUI {label} cannot be read safely") from error
    if (
        len(data) != before.st_size
        or len(data) > maximum
        or _stat_identity(before) != _stat_identity(after)
    ):
        raise RuntimePinError(f"ComfyUI {label} changed while being read")
    return data


def _parse_json(raw: bytes, *, label: str) -> object:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimePinError(f"ComfyUI {label} contains a duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise RuntimePinError(f"ComfyUI {label} contains a non-finite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise RuntimePinError(f"ComfyUI {label} is not strict JSON") from error
    _check_depth(value, 0)
    return value


def _check_depth(value: object, depth: int) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise RuntimePinError("ComfyUI runtime approval exceeds its JSON nesting limit")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise RuntimePinError("ComfyUI runtime approval keys must be strings")
            _check_depth(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_depth(child, depth + 1)
    elif isinstance(value, float):
        raise RuntimePinError("ComfyUI runtime approval does not allow floating-point values")


def _decode_public_key(raw: bytes) -> bytes:
    value = raw[:-1] if raw.endswith(b"\n") else raw
    if not value or b"\n" in value or b"\r" in value:
        raise RuntimePinError("ComfyUI trust key must be one base64 encoded Ed25519 key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise RuntimePinError("ComfyUI trust key encoding is invalid") from error
    if len(decoded) != 32 or base64.b64encode(decoded) != value:
        raise RuntimePinError("ComfyUI trust key must contain exactly 32 raw Ed25519 bytes")
    return decoded


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise RuntimePinError("ComfyUI runtime approval signature is missing")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, base64.binascii.Error) as error:
        raise RuntimePinError("ComfyUI runtime approval signature encoding is invalid") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise RuntimePinError("ComfyUI runtime approval signature has an invalid length")
    return decoded


def _verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify Ed25519 through the OpenSSL library already loaded by Python ssl."""

    try:
        import _ssl

        library = ctypes.CDLL(_ssl.__file__)
        library.OBJ_txt2nid.argtypes = [ctypes.c_char_p]
        library.OBJ_txt2nid.restype = ctypes.c_int
        library.EVP_PKEY_new_raw_public_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
        library.EVP_MD_CTX_new.argtypes = []
        library.EVP_MD_CTX_new.restype = ctypes.c_void_p
        library.EVP_DigestVerifyInit.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.EVP_DigestVerifyInit.restype = ctypes.c_int
        library.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_DigestVerify.restype = ctypes.c_int
        library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        library.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        key_type = library.OBJ_txt2nid(b"ED25519")
        key_buffer = ctypes.create_string_buffer(public_key)
        signature_buffer = ctypes.create_string_buffer(signature)
        message_buffer = ctypes.create_string_buffer(message)
        key = library.EVP_PKEY_new_raw_public_key(
            key_type, None, ctypes.cast(key_buffer, ctypes.c_void_p), len(public_key)
        )
        if not key:
            return False
        context = library.EVP_MD_CTX_new()
        if not context:
            library.EVP_PKEY_free(key)
            return False
        try:
            digest_context = ctypes.c_void_p()
            if library.EVP_DigestVerifyInit(
                context, ctypes.byref(digest_context), None, None, key
            ) != 1:
                return False
            return (
                library.EVP_DigestVerify(
                    context,
                    ctypes.cast(signature_buffer, ctypes.c_void_p),
                    len(signature),
                    ctypes.cast(message_buffer, ctypes.c_void_p),
                    len(message),
                )
                == 1
            )
        finally:
            library.EVP_MD_CTX_free(context)
            library.EVP_PKEY_free(key)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _validate_payload(payload: Mapping[str, object]) -> None:
    expected_keys = {
        "schema",
        "schema_version",
        "tool_id",
        "tool_version",
        "configuration_version",
        "candidate_id",
        "roots",
        "python_base_prefix",
        "python_stdlib_paths",
        "python_stdlib_pins",
        "interpreter",
            "entrypoint",
        "workflow",
        "components",
        "trusted_evidence",
    }
    if set(payload) != expected_keys:
        raise RuntimePinError("ComfyUI runtime pin payload has unsupported fields")
    if (
        payload.get("schema") != RUNTIME_PIN_SET_SCHEMA
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != RUNTIME_PIN_SCHEMA_VERSION
        or payload.get("tool_id") != "comfyui"
    ):
        raise RuntimePinError("ComfyUI runtime pin schema or tool identity is unsupported")
    for name in ("tool_version", "configuration_version"):
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise RuntimePinError(f"ComfyUI runtime pin {name} is invalid")
        if value.lower().startswith(("synthetic-", "placeholder", "test-")):
            raise RuntimePinError("ComfyUI runtime pin cannot approve a synthetic version")
    candidate_id = payload.get("candidate_id")
    if (
        not isinstance(candidate_id, str)
        or not candidate_id.startswith("sha256:")
        or not _is_sha256(candidate_id.removeprefix("sha256:"))
    ):
        raise RuntimePinError("ComfyUI runtime pin candidate identity is invalid")
    _validate_roots(payload.get("roots"))
    _validate_python_runtime_paths(payload)
    _validate_file_pin(payload.get("interpreter"), label="interpreter")
    _validate_file_pin(payload.get("entrypoint"), label="entrypoint")
    _validate_file_pin(payload.get("workflow"), label="workflow", workflow=True)
    _validate_components(payload.get("components"))
    _validate_trusted_evidence(payload.get("trusted_evidence"))


def _validate_roots(value: object) -> None:
    if not isinstance(value, list) or len(value) != len(_ROOT_ROLES):
        raise RuntimePinError("ComfyUI runtime root pins are incomplete")
    roles: set[str] = set()
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"role", "path", "sha256"}:
            raise RuntimePinError("ComfyUI runtime root pin is malformed")
        role = item.get("role")
        path = item.get("path")
        if not isinstance(role, str):
            raise RuntimePinError("ComfyUI runtime root role must be a string")
        if role not in _ROOT_ROLES or role in roles:
            raise RuntimePinError("ComfyUI runtime root roles are incomplete or duplicated")
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise RuntimePinError("ComfyUI runtime root path is invalid")
        _validate_sha256(item.get("sha256"), label="runtime root")
        roles.add(role)
        paths.add(path)
    if roles != _ROOT_ROLES or len(paths) != len(value):
        raise RuntimePinError("ComfyUI runtime root roles or paths are incomplete")


def _validate_python_runtime_paths(payload: Mapping[str, object]) -> None:
    """Validate standard-library paths and their signed tree metadata."""

    base_prefix = payload.get("python_base_prefix")
    stdlib_paths = payload.get("python_stdlib_paths")
    stdlib_pins = payload.get("python_stdlib_pins")
    if (
        not isinstance(base_prefix, str)
        or not Path(base_prefix).is_absolute()
        or ".." in Path(base_prefix).parts
        or "\x00" in base_prefix
        or str(Path(base_prefix)) != base_prefix
    ):
        raise RuntimePinError("ComfyUI Python base prefix is invalid")
    if (
        not isinstance(stdlib_paths, list)
        or not stdlib_paths
        or len(stdlib_paths) > 16
        or not all(isinstance(path, str) for path in stdlib_paths)
    ):
        raise RuntimePinError("ComfyUI Python standard library roots are invalid")
    if (
        not isinstance(stdlib_pins, list)
        or len(stdlib_pins) != len(stdlib_paths)
    ):
        raise RuntimePinError("ComfyUI Python standard library pins are invalid")
    base_path = Path(base_prefix)
    paths: set[str] = set()
    expected_pin_fields = {"path", "sha256", "size_bytes", "entry_count"}
    for raw_path, pin in zip(stdlib_paths, stdlib_pins, strict=True):
        path = Path(raw_path)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or "\x00" in raw_path
            or str(path) != raw_path
            or not path.is_relative_to(base_path)
            or raw_path in paths
        ):
            raise RuntimePinError(
                "ComfyUI Python standard library path is invalid or outside its signed base prefix"
            )
        if (
            not isinstance(pin, dict)
            or set(pin) != expected_pin_fields
            or pin.get("path") != raw_path
        ):
            raise RuntimePinError("ComfyUI Python standard library tree pin is malformed")
        size_bytes = pin.get("size_bytes")
        entry_count = pin.get("entry_count")
        if (
            type(size_bytes) is not int
            or not 0 <= size_bytes <= _MAX_ROOT_BYTES
            or type(entry_count) is not int
            or not 0 <= entry_count <= _MAX_ROOT_ENTRIES
        ):
            raise RuntimePinError(
                "ComfyUI Python standard library tree size or entry count is invalid"
            )
        _validate_sha256(pin.get("sha256"), label="Python standard library tree")
        paths.add(raw_path)


def _validate_file_pin(
    value: object, *, label: str, workflow: bool = False
) -> None:
    expected = {"id", "path", "size_bytes", "sha256"} if workflow else {
        "path",
        "size_bytes",
        "sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise RuntimePinError(f"ComfyUI {label} pin is malformed")
    if workflow and (not isinstance(value.get("id"), str) or not value["id"].strip()):
        raise RuntimePinError("ComfyUI workflow id is invalid")
    if not isinstance(value.get("path"), str) or not Path(value["path"]).is_absolute():
        raise RuntimePinError(f"ComfyUI {label} path is invalid")
    size = value.get("size_bytes")
    if type(size) is not int or size < 0:
        raise RuntimePinError(f"ComfyUI {label} size is invalid")
    _validate_sha256(value.get("sha256"), label=label)


def _validate_components(value: object) -> None:
    if not isinstance(value, list) or not value or len(value) > 4096:
        raise RuntimePinError("ComfyUI runtime component pins are incomplete")
    identifiers: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "component_id",
            "role",
            "path",
            "size_bytes",
            "sha256",
        }:
            raise RuntimePinError("ComfyUI runtime component pin is malformed")
        identifier = item.get("component_id")
        role = item.get("role")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise RuntimePinError("ComfyUI runtime component ids are invalid or duplicated")
        if not isinstance(role, str) or not role:
            raise RuntimePinError("ComfyUI runtime component role is invalid")
        identifiers.add(identifier)
        _validate_file_pin(
            {key: item[key] for key in ("path", "size_bytes", "sha256")},
            label="component",
        )


def _validate_trusted_evidence(value: object) -> None:
    if not isinstance(value, list) or not value or len(value) > 4096:
        raise RuntimePinError("ComfyUI trusted evidence pins are incomplete")
    authority_ids: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "authority_id",
            "document_size_bytes",
            "document_sha256",
        }:
            raise RuntimePinError("ComfyUI trusted evidence pin is malformed")
        identifier = item.get("authority_id")
        size = item.get("document_size_bytes")
        if not isinstance(identifier, str) or not identifier or identifier in authority_ids:
            raise RuntimePinError("ComfyUI trusted evidence authorities are invalid")
        if type(size) is not int or size < 1:
            raise RuntimePinError("ComfyUI trusted evidence size is invalid")
        _validate_sha256(item.get("document_sha256"), label="trusted evidence")
        authority_ids.add(identifier)


def _validate_sha256(value: object, *, label: str) -> None:
    if not _is_sha256(value):
        raise RuntimePinError(f"ComfyUI {label} SHA-256 pin is invalid")


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != _SHA256_LENGTH:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _verify_runtime_paths(payload: Mapping[str, object]) -> None:
    roots = payload["roots"]
    base_prefix = _external_runtime_path(Path(payload["python_base_prefix"]))
    if not base_prefix.is_dir():
        raise RuntimePinError("ComfyUI Python base prefix is not a directory")
    files = [
        payload["interpreter"],
        payload["entrypoint"],
        payload["workflow"],
        *payload["components"],
    ]
    total_pinned_file_bytes = sum(int(file_pin["size_bytes"]) for file_pin in files)
    if total_pinned_file_bytes > _MAX_TOTAL_PINNED_FILE_BYTES:
        raise RuntimePinError("ComfyUI pinned files exceed their aggregate byte limit")
    total_size = 0
    for root_pin in roots:
        root_path = _external_runtime_path(Path(root_pin["path"]))
        remaining_root_bytes = _MAX_TOTAL_ROOT_BYTES - total_size
        if remaining_root_bytes < 0:
            raise RuntimePinError("ComfyUI runtime roots exceed their total verification bound")
        actual_digest, size, entries = _tree_sha256(
            root_path, maximum_bytes=remaining_root_bytes
        )
        total_size += size
        if entries > _MAX_ROOT_ENTRIES or size > _MAX_ROOT_BYTES:
            raise RuntimePinError("ComfyUI runtime root exceeds its verification bound")
        if actual_digest != root_pin["sha256"]:
            raise RuntimePinError("ComfyUI runtime root bytes changed after approval")
    for raw_path, stdlib_pin in zip(
        payload["python_stdlib_paths"], payload["python_stdlib_pins"], strict=True
    ):
        stdlib_path = _external_runtime_path(Path(raw_path))
        if not stdlib_path.is_dir() or not stdlib_path.is_relative_to(base_prefix):
            raise RuntimePinError(
                "ComfyUI Python standard library path is unavailable or outside its signed base prefix"
            )
        remaining_root_bytes = _MAX_TOTAL_ROOT_BYTES - total_size
        if remaining_root_bytes < 0:
            raise RuntimePinError("ComfyUI runtime roots exceed their total verification bound")
        actual_digest, size, entries = _tree_sha256(
            stdlib_path, maximum_bytes=remaining_root_bytes
        )
        total_size += size
        if entries > _MAX_ROOT_ENTRIES or size > _MAX_ROOT_BYTES:
            raise RuntimePinError(
                "ComfyUI Python standard library tree exceeds its verification bound"
            )
        if (
            actual_digest != stdlib_pin["sha256"]
            or size != stdlib_pin["size_bytes"]
            or entries != stdlib_pin["entry_count"]
        ):
            raise RuntimePinError(
                "ComfyUI Python standard library tree changed after approval"
            )
    for file_pin in files:
        path = _external_runtime_path(Path(file_pin["path"]))
        _verify_file_pin(path, file_pin)


def _verify_file_pin(path: Path, pin: Mapping[str, object]) -> None:
    try:
        with open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size != pin["size_bytes"]
                or before.st_size > _MAX_PINNED_FILE_BYTES
            ):
                raise RuntimePinError("ComfyUI runtime file size or type changed")
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(stream.fileno())
    except (OSError, InputValidationError) as error:
        raise RuntimePinError("ComfyUI runtime file cannot be read safely") from error
    if size != pin["size_bytes"] or digest.hexdigest() != pin["sha256"]:
        raise RuntimePinError("ComfyUI runtime file bytes changed after approval")
    if _stat_identity(before) != _stat_identity(after):
        raise RuntimePinError("ComfyUI runtime file changed while being verified")


def _tree_sha256(
    root: Path, *, maximum_bytes: int | None = None
) -> tuple[str, int, int]:
    """Hash one bounded directory tree without following raced symlinks."""

    byte_limit = _MAX_ROOT_BYTES if maximum_bytes is None else min(
        _MAX_ROOT_BYTES, maximum_bytes
    )
    if byte_limit < 0:
        raise RuntimePinError("ComfyUI runtime tree has no remaining byte budget")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimePinError("ComfyUI runtime tree cannot be opened without symlink following")

    root = Path(root)
    entries: list[dict[str, object]] = []
    total_size = 0
    entry_count = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW

    def visit(directory_fd: int, relative: Path, depth: int) -> None:
        nonlocal entry_count, total_size
        before_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(before_directory.st_mode):
            raise RuntimePinError("ComfyUI runtime tree contains an unsafe directory")
        pending_directories: list[tuple[str, Path, int, tuple[int, int, int, int]]] = []
        with os.scandir(directory_fd) as children:
            for child in children:
                if entry_count >= _MAX_ROOT_ENTRIES:
                    raise RuntimePinError("ComfyUI runtime tree exceeds its entry limit")
                entry_count += 1
                name = child.name
                child_relative = relative / name
                info = child.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child_depth = depth + 1
                    if child_depth > _MAX_TREE_DEPTH:
                        raise RuntimePinError("ComfyUI runtime tree exceeds its depth limit")
                    identity = _stat_identity(info)
                    entries.append(
                        {"path": child_relative.as_posix(), "kind": "directory"}
                    )
                    pending_directories.append(
                        (name, child_relative, child_depth, identity)
                    )
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimePinError(
                        "ComfyUI runtime tree contains a symlink or special file"
                    )
                if info.st_size > _MAX_PINNED_FILE_BYTES:
                    raise RuntimePinError("ComfyUI runtime file exceeds its byte limit")
                if info.st_size > byte_limit - total_size:
                    raise RuntimePinError("ComfyUI runtime tree exceeds its byte limit")

                descriptor = os.open(name, file_flags, dir_fd=directory_fd)
                try:
                    before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or _stat_identity(before) != _stat_identity(info)
                    ):
                        raise RuntimePinError(
                            "ComfyUI runtime tree changed while being opened"
                        )
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        read_limit = min(
                            _HASH_CHUNK_BYTES,
                            _MAX_PINNED_FILE_BYTES - size + 1,
                            byte_limit - total_size + 1,
                        )
                        chunk = os.read(descriptor, read_limit)
                        if not chunk:
                            break
                        next_size = size + len(chunk)
                        next_total = total_size + len(chunk)
                        if next_size > _MAX_PINNED_FILE_BYTES:
                            raise RuntimePinError(
                                "ComfyUI runtime file exceeds its byte limit"
                            )
                        if next_total > byte_limit:
                            raise RuntimePinError(
                                "ComfyUI runtime tree exceeds its byte limit"
                            )
                        digest.update(chunk)
                        size = next_size
                        total_size = next_total
                    after = os.fstat(descriptor)
                    current_path = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        _stat_identity(before) != _stat_identity(after)
                        or _stat_identity(info) != _stat_identity(current_path)
                        or size != info.st_size
                    ):
                        raise RuntimePinError(
                            "ComfyUI runtime file changed while being verified"
                        )
                finally:
                    os.close(descriptor)
                entries.append(
                    {
                        "path": child_relative.as_posix(),
                        "kind": "file",
                        "size_bytes": size,
                        "sha256": digest.hexdigest(),
                    }
                )

        after_directory = os.fstat(directory_fd)
        if _stat_identity(before_directory) != _stat_identity(after_directory):
            raise RuntimePinError("ComfyUI runtime directory changed while being verified")

        for name, child_relative, child_depth, identity in pending_directories:
            descriptor = os.open(name, directory_flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _stat_identity(opened) != identity
                ):
                    raise RuntimePinError(
                        "ComfyUI runtime tree changed while being opened"
                    )
                visit(descriptor, child_relative, child_depth)
            finally:
                os.close(descriptor)
            current_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _stat_identity(current_path) != identity:
                raise RuntimePinError("ComfyUI runtime directory changed while being verified")

    try:
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise RuntimePinError("A pinned ComfyUI runtime root is unavailable")
        root_descriptor = os.open(root, directory_flags)
        try:
            opened_root = os.fstat(root_descriptor)
            if _stat_identity(opened_root) != _stat_identity(root_info):
                raise RuntimePinError("ComfyUI runtime root changed while being opened")
            visit(root_descriptor, Path(), 0)
        finally:
            os.close(root_descriptor)
        if _stat_identity(root.lstat()) != _stat_identity(root_info):
            raise RuntimePinError("ComfyUI runtime root changed while being verified")
        entries.sort(key=lambda item: str(item["path"]))
        digest = hashlib.sha256(canonical_json(entries).encode("utf-8")).hexdigest()
        return digest, total_size, entry_count
    except (OSError, InputValidationError, ValueError) as error:
        if isinstance(error, RuntimePinError):
            raise
        raise RuntimePinError("ComfyUI runtime tree cannot be verified safely") from error


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
