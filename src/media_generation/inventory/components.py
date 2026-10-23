"""Bounded model-component inspection and bundle identity.

Recognized safetensors and GGUF headers are parsed from a capped prefix; no
tensor data is read and serialized pickle-like formats are never unpickled.
Content digests are opt-in and streamed.  Declared component paths are resolved
inside explicit model roots before this module sees them.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat as stat_module
import struct
from collections import Counter
from pathlib import Path
from typing import Any

from .manifest import BundleDeclaration, InventoryManifest, ModelRoot, within_model_roots
from .probes import ProbeLedger, ProbeSpec
from .schema import (
    Finding,
    Observation,
    ProbeStatus,
    Severity,
    digest_value,
)


MAX_METADATA_BYTES = 1024 * 1024
MAX_SIDECAR_BYTES = 256 * 1024
MAX_DIRECTORY_ENTRIES = 100
MAX_TENSOR_ENTRIES = 100_000
MAX_GGUF_ARRAY_ITEMS = 4096
MAX_GGUF_DEPTH = 3
MAX_RECIPE_BYTES = 256 * 1024
MAX_MODEL_PATH_LINKS = 64

# Values from llama.cpp's ``llama_ftype`` enum in ``include/llama.h``, which is
# stored in GGUF metadata as ``general.file_type``. Removed values (4, 5, 6 and
# 33-35) are intentionally omitted. The ``LLAMA_FTYPE_GUESSED`` sentinel (1024)
# is not a quantization and stays unclassified while the raw enum is retained.
GGUF_FILE_TYPES: dict[int, str] = {
    0: "ALL_F32",
    1: "MOSTLY_F16",
    2: "Q4_0",
    3: "Q4_1",
    7: "Q8_0",
    8: "Q5_0",
    9: "Q5_1",
    10: "Q2_K",
    11: "Q3_K_S",
    12: "Q3_K_M",
    13: "Q3_K_L",
    14: "Q4_K_S",
    15: "Q4_K_M",
    16: "Q5_K_S",
    17: "Q5_K_M",
    18: "Q6_K",
    19: "IQ2_XXS",
    20: "IQ2_XS",
    21: "Q2_K_S",
    22: "IQ3_XS",
    23: "IQ3_XXS",
    24: "IQ1_S",
    25: "IQ4_NL",
    26: "IQ3_S",
    27: "IQ3_M",
    28: "IQ2_S",
    29: "IQ2_M",
    30: "IQ4_XS",
    31: "IQ1_M",
    32: "BF16",
    36: "TQ1_0",
    37: "TQ2_0",
    38: "MXFP4_MOE",
    39: "NVFP4",
    40: "Q1_0",
    41: "Q2_0",
}


class _GgufReader:
    """Cursor over a bounded GGUF prefix."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        """Return exactly ``size`` bytes or raise ``EOFError``."""
        if size < 0 or self.offset + size > len(self.data):
            raise EOFError
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def string(self) -> str:
        length = self.u64()
        if length > MAX_METADATA_BYTES:
            raise ValueError("string_too_large")
        return self.take(length).decode("utf-8", errors="replace")


def _gguf_skip_value(reader: _GgufReader, value_type: int, depth: int) -> None:
    """Advance over one GGUF value without retaining unbounded content."""
    if depth > MAX_GGUF_DEPTH:
        raise ValueError("nesting_too_deep")
    fixed = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
    if value_type in fixed:
        reader.take(fixed[value_type])
        return
    if value_type == 8:
        reader.string()
        return
    if value_type == 9:
        inner = reader.u32()
        count = reader.u64()
        if count > MAX_GGUF_ARRAY_ITEMS:
            raise ValueError("array_too_large")
        for _ in range(count):
            _gguf_skip_value(reader, inner, depth + 1)
        return
    raise ValueError("unknown_value_type")


def _gguf_value(reader: _GgufReader, value_type: int, depth: int) -> object:
    """Read one scalar/string GGUF value; arrays are skipped and reported as count."""
    if value_type == 8:
        return reader.string()
    if value_type == 9:
        inner = reader.u32()
        count = reader.u64()
        if count > MAX_GGUF_ARRAY_ITEMS:
            raise ValueError("array_too_large")
        for _ in range(count):
            _gguf_skip_value(reader, inner, depth + 1)
        return {"array_length": count, "element_type": inner}
    if value_type == 0:
        return reader.take(1)[0]
    if value_type == 1:
        return struct.unpack("<b", reader.take(1))[0]
    if value_type == 2:
        return struct.unpack("<H", reader.take(2))[0]
    if value_type == 3:
        return struct.unpack("<h", reader.take(2))[0]
    if value_type == 4:
        return reader.u32()
    if value_type == 5:
        return struct.unpack("<i", reader.take(4))[0]
    if value_type == 6:
        return struct.unpack("<f", reader.take(4))[0]
    if value_type == 7:
        return reader.take(1)[0] != 0
    if value_type == 10:
        return reader.u64()
    if value_type == 11:
        return reader.i64()
    if value_type == 12:
        return struct.unpack("<d", reader.take(8))[0]
    raise ValueError("unknown_value_type")


def inspect_gguf(data: bytes, *, file_truncated: bool) -> dict[str, object]:
    """Parse bounded GGUF metadata without reading tensor payloads."""
    if len(data) < 24 or data[:4] != b"GGUF":
        return {"status": "malformed", "format": "gguf", "reason": "invalid_magic_or_header"}
    reader = _GgufReader(data)
    reader.take(4)
    version = reader.u32()
    tensor_count = reader.u64()
    kv_count = reader.u64()
    if version not in {1, 2, 3}:
        return {
            "status": "unknown",
            "format": "gguf",
            "version": version,
            "reason": "unsupported_version",
        }
    selected: dict[str, object] = {}
    wanted = {
        "general.architecture",
        "general.name",
        "general.file_type",
        "split.count",
        "split.no",
    }
    metadata_keys = 0
    try:
        for _ in range(kv_count):
            if reader.offset >= len(data):
                raise EOFError
            key = reader.string()
            value_type = reader.u32()
            metadata_keys += 1
            if key in wanted:
                selected[key] = _gguf_value(reader, value_type, 0)
            else:
                _gguf_skip_value(reader, value_type, 0)
    except EOFError:
        return {
            "status": "truncated" if file_truncated else "malformed",
            "format": "gguf",
            "version": version,
            "tensor_count": tensor_count,
            "reason": "metadata_limit_reached" if file_truncated else "unexpected_end_of_data",
            "metadata_keys_read": metadata_keys,
        }
    except ValueError as error:
        return {
            "status": "malformed",
            "format": "gguf",
            "version": version,
            "reason": str(error),
            "metadata_keys_read": metadata_keys,
        }
    file_type = selected.get("general.file_type")
    enum_value = file_type if isinstance(file_type, int) and not isinstance(file_type, bool) else None
    quantization = GGUF_FILE_TYPES.get(enum_value) if enum_value is not None else None
    return {
        "status": "observed",
        "format": "gguf",
        "version": version,
        "tensor_count": tensor_count,
        "metadata_key_count": kv_count,
        "metadata_keys_read": metadata_keys,
        "architecture": selected.get("general.architecture"),
        "model_name": selected.get("general.name"),
        "quantization": quantization,
        "quantization_enum": enum_value,
        "split": {
            key: selected[key]
            for key in ("split.count", "split.no")
            if key in selected
        },
        "metadata_truncated": reader.offset < len(data) and file_truncated,
    }


def inspect_safetensors(data: bytes, *, file_truncated: bool) -> dict[str, object]:
    """Parse a bounded safetensors header, retaining dtype counts and safe metadata."""
    if len(data) < 8:
        return {"status": "malformed", "format": "safetensors", "reason": "short_header"}
    header_length = int.from_bytes(data[:8], "little")
    if header_length <= 0 or header_length > MAX_METADATA_BYTES:
        return {
            "status": "malformed",
            "format": "safetensors",
            "reason": "header_length_out_of_bounds",
        }
    if 8 + header_length > len(data):
        return {
            "status": "truncated" if file_truncated else "malformed",
            "format": "safetensors",
            "reason": "metadata_limit_reached" if file_truncated else "header_truncated",
        }
    try:
        header = json.loads(data[8 : 8 + header_length].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "malformed", "format": "safetensors", "reason": "invalid_header_json"}
    if not isinstance(header, dict):
        return {"status": "malformed", "format": "safetensors", "reason": "header_not_object"}
    metadata = header.get("__metadata__")
    metadata_keys: list[str] = []
    safe_metadata: dict[str, object] = {}
    if isinstance(metadata, dict):
        for key in sorted(metadata)[:32]:
            metadata_keys.append(str(key))
            if key in {"architecture", "model_type", "format", "quantization", "name"}:
                value = metadata.get(key)
                if isinstance(value, (str, int, float, bool)):
                    safe_metadata[str(key)] = str(value)[:128]
    dtypes: Counter[str] = Counter()
    tensor_count = 0
    for key, value in header.items():
        if key == "__metadata__" or not isinstance(value, dict):
            continue
        tensor_count += 1
        if tensor_count > MAX_TENSOR_ENTRIES:
            return {
                "status": "malformed",
                "format": "safetensors",
                "reason": "tensor_count_limit_exceeded",
            }
        dtype = value.get("dtype")
        if isinstance(dtype, str):
            dtypes[dtype] += 1
    quantization = safe_metadata.get("quantization")
    return {
        "status": "observed",
        "format": "safetensors",
        "tensor_count": tensor_count,
        "dtype_summary": dict(sorted(dtypes.items())),
        "metadata_keys": metadata_keys,
        "metadata": safe_metadata,
        "architecture": safe_metadata.get("architecture") or safe_metadata.get("model_type"),
        "quantization": str(quantization) if quantization is not None else None,
        "metadata_truncated": file_truncated,
    }


def _selected_sidecar_keys(payload: dict[str, Any]) -> dict[str, object]:
    """Retain a small allowlist of descriptive sidecar configuration fields."""
    selected: dict[str, object] = {}
    for key in ("_class_name", "architectures", "model_type", "torch_dtype", "quantization_config"):
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, (str, int, float, bool)):
            selected[key] = value
        elif isinstance(value, list):
            selected[key] = [str(item)[:128] for item in value[:16]]
        elif isinstance(value, dict):
            selected[key] = {
                str(inner_key)[:64]: str(inner_value)[:128]
                for inner_key, inner_value in list(value.items())[:16]
                if isinstance(inner_value, (str, int, float, bool))
            }
    return selected


def _model_root_for(path: Path, roots: tuple[ModelRoot, ...]) -> ModelRoot | None:
    """Return the declared root containing path lexically and physically."""
    for root in roots:
        try:
            path.relative_to(root.path)
        except ValueError:
            continue
        return root
    return None


def _model_path_problem(path: Path, roots: tuple[ModelRoot, ...]) -> str | None:
    """Return a reason when path is unsafe to read from a declared root.

    The declared root itself may be a symlink and is trusted.  Every entry
    below it must be a real directory, so an intermediate link cannot redirect
    a read outside the declared tree.  The final entry must not be a symlink.
    Callers also open files with O_NOFOLLOW.  The checks and the read are
    separate filesystem operations, so this narrows replacement races; a
    failed recheck always produces an unavailable or skipped record.
    """
    if not roots:
        return "model_roots_not_configured"
    root = _model_root_for(path, roots)
    if root is None:
        return "outside_model_root"
    current = path
    for _ in range(MAX_MODEL_PATH_LINKS):
        if current == root.path:
            break
        try:
            facts = current.lstat()
        except FileNotFoundError:
            if current == path:
                current = current.parent
                continue
            return "ancestor_unavailable"
        except OSError:
            return "ancestor_unavailable"
        if stat_module.S_ISLNK(facts.st_mode):
            if current == path:
                return "symlink_not_followed"
            return "symlink_ancestor_not_followed"
        if current != path and not stat_module.S_ISDIR(facts.st_mode):
            return "ancestor_not_directory"
        current = current.parent
    else:
        return "model_path_depth_exceeded"
    if not within_model_roots(path, (root,)):
        return "outside_model_root"
    return None


def _read_sidecar(
    ledger: ProbeLedger,
    *,
    component_id: str,
    path: Path,
    roots: tuple[ModelRoot, ...],
) -> dict[str, object]:
    """Read one approved small sidecar config if it exists."""
    problem = _model_path_problem(path, roots)
    root = _model_root_for(path, roots)
    if problem is not None or root is None:
        return {
            "path": str(path),
            "status": "skipped",
            "reason": problem or "outside_model_root",
        }
    stat = ledger.stat(ProbeSpec(f"component:{component_id}:sidecar-stat", "model"), path)
    if not stat.ok:
        return {"path": str(path), "status": stat.status, "reason": stat.reason}
    try:
        facts = json.loads(stat.text)
    except (TypeError, json.JSONDecodeError):
        facts = {}
    if not isinstance(facts, dict):
        return {"path": str(path), "status": "malformed", "reason": "sidecar_stat_malformed"}
    if facts.get("kind") != "file" or facts.get("symlink"):
        return {"path": str(path), "status": "skipped", "reason": "not_a_regular_file"}
    observation = ledger.read(
        ProbeSpec(f"component:{component_id}:sidecar", "model"),
        path,
        limit=MAX_SIDECAR_BYTES,
        follow_final_symlink=False,
        root=root.path,
    )
    if not observation.ok:
        return {
            "path": str(path),
            "status": observation.status,
            "reason": observation.reason,
        }
    if observation.truncated:
        return {"path": str(path), "status": "truncated", "reason": "sidecar_limit_reached"}
    try:
        payload = json.loads(observation.text)
    except json.JSONDecodeError:
        return {"path": str(path), "status": "malformed", "reason": "invalid_json"}
    if not isinstance(payload, dict):
        return {"path": str(path), "status": "malformed", "reason": "not_an_object"}
    return {
        "path": str(path),
        "status": "observed",
        "selected_keys": _selected_sidecar_keys(payload),
    }


def _inspect_model_metadata(
    ledger: ProbeLedger,
    *,
    component_id: str,
    path: Path,
    suffix: str,
    root: Path | None = None,
) -> dict[str, object]:
    """Inspect one recognized model format from a capped prefix."""
    if suffix in {".ckpt", ".pt", ".pth", ".bin"}:
        return {
            "status": "not_inspected",
            "format": "pickle_like",
            "reason": "unsafe_serialization_not_read",
        }
    if suffix not in {".safetensors", ".gguf"}:
        return {
            "status": "unsupported",
            "format": suffix or "unknown",
            "reason": "unrecognized_format",
        }
    observation, data = ledger.read_prefix(
        ProbeSpec(f"component:{component_id}:header", "model"),
        path,
        limit=MAX_METADATA_BYTES + 16,
        follow_final_symlink=False,
        root=root,
    )
    if not observation.ok:
        return {
            "status": observation.status,
            "format": suffix[1:],
            "reason": observation.reason,
        }
    if suffix == ".safetensors":
        return inspect_safetensors(data, file_truncated=observation.truncated)
    return inspect_gguf(data, file_truncated=observation.truncated)


def _component_digest(
    ledger: ProbeLedger,
    *,
    component_id: str,
    path: Path,
    enabled: bool,
    limit: int,
    root: Path | None = None,
) -> dict[str, object]:
    """Return declared digest state, computing only when explicitly enabled."""
    if not enabled:
        return {
            "status": "unchecked",
            "algorithm": "sha256",
            "value": None,
            "reason": "not_requested",
        }
    observation, digest = ledger.sha256(
        ProbeSpec(f"component:{component_id}:digest", "model"),
        path,
        limit=limit,
        follow_final_symlink=False,
        root=root,
    )
    if digest is not None:
        return {"status": "computed", "algorithm": "sha256", "value": digest}
    return {
        "status": "skipped"
        if observation.status == ProbeStatus.SKIPPED.value
        else "unavailable",
        "algorithm": "sha256",
        "value": None,
        "reason": observation.reason,
    }


def _stat_payload(observation: Observation) -> dict[str, Any] | None:
    """Decode one stat observation into a mapping."""
    if not observation.ok:
        return None
    try:
        payload = json.loads(observation.text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _inspect_component(
    ledger: ProbeLedger,
    *,
    component_id: str,
    role: str,
    path: Path,
    roots: tuple[ModelRoot, ...],
    hash_components: bool,
    hash_limit_bytes: int,
) -> tuple[dict[str, object], bool]:
    """Inspect one declared component and return whether it degraded the run."""
    base: dict[str, object] = {
        "id": component_id,
        "role": role,
        "path": str(path),
        "kind": None,
        "size_bytes": None,
        "mtime": None,
        "status": "unavailable",
        "reason": None,
        "digest": {
            "status": "unavailable",
            "algorithm": "sha256",
            "value": None,
            "reason": None,
        },
        "metadata": {"status": "not_inspected", "reason": "component_unavailable"},
    }
    problem = _model_path_problem(path, roots)
    if problem is not None:
        skipped = "symlink" in problem
        base["status"] = "skipped" if skipped else "unavailable"
        base["reason"] = problem
        base["digest"] = {
            "status": "skipped" if skipped else "unavailable",
            "algorithm": "sha256",
            "value": None,
            "reason": problem,
        }
        base["metadata"] = {"status": "not_inspected", "reason": problem}
        return base, True
    root = _model_root_for(path, roots)
    observation = ledger.stat(ProbeSpec(f"component:{component_id}:stat", "model"), path)
    payload = _stat_payload(observation)
    base["reason"] = observation.reason
    base["digest"]["reason"] = observation.reason
    if payload is None:
        return base, True
    base["kind"] = payload.get("kind")
    base["size_bytes"] = payload.get("size_bytes")
    base["mtime"] = payload.get("mtime")
    if payload.get("symlink"):
        base["status"] = "skipped"
        base["reason"] = "symlink_not_followed"
        base["digest"] = {
            "status": "skipped",
            "algorithm": "sha256",
            "value": None,
            "reason": "symlink_not_followed",
        }
        return base, True
    if payload.get("kind") == "directory":
        listing = ledger.list_dir(
            ProbeSpec(f"component:{component_id}:listing", "model"),
            path,
            limit=MAX_DIRECTORY_ENTRIES,
            root=root.path if root is not None else None,
        )
        if not listing.ok:
            base["status"] = listing.status
            base["reason"] = listing.reason
            base["digest"] = {
                "status": "unavailable",
                "algorithm": "sha256",
                "value": None,
                "reason": "directory_listing_unavailable",
            }
            base["metadata"] = {
                "status": listing.status,
                "format": "directory",
                "reason": listing.reason,
            }
            return base, True
        try:
            parsed = json.loads(listing.text)
        except json.JSONDecodeError:
            parsed = None
        if not isinstance(parsed, list):
            base["status"] = "malformed"
            base["reason"] = "directory_listing_malformed"
            base["digest"] = {
                "status": "unavailable",
                "algorithm": "sha256",
                "value": None,
                "reason": "directory_listing_malformed",
            }
            base["metadata"] = {
                "status": "malformed",
                "format": "directory",
                "reason": "directory_listing_malformed",
            }
            return base, True
        entries: list[object] = parsed
        base["status"] = "observed"
        base["reason"] = None
        base["digest"] = {
            "status": "unchecked",
            "algorithm": "sha256",
            "value": None,
            "reason": "directory_digest_not_defined",
        }
        base["metadata"] = {
            "status": "observed",
            "format": "directory",
            "entry_count": len(entries),
            "entries": entries,
            "truncated": listing.truncated,
        }
        for name in ("model_index.json", "config.json"):
            sidecar_path = path / name
            sidecar = _read_sidecar(
                ledger,
                component_id=f"{component_id}:{name}",
                path=sidecar_path,
                roots=roots,
            )
            if sidecar.get("status") == "observed":
                base["metadata"]["sidecar"] = sidecar  # type: ignore[index]
                break
        return base, listing.truncated
    if payload.get("kind") != "file":
        base["status"] = "unavailable"
        base["reason"] = "not_a_regular_file"
        return base, True
    suffix = Path(str(payload.get("realpath") or path)).suffix.lower()
    base["status"] = "observed"
    base["reason"] = None
    base["digest"] = _component_digest(
        ledger,
        component_id=component_id,
        path=path,
        enabled=hash_components,
        limit=hash_limit_bytes,
        root=root.path if root is not None else None,
    )
    base["metadata"] = _inspect_model_metadata(
        ledger,
        component_id=component_id,
        path=path,
        suffix=suffix,
        root=root.path if root is not None else None,
    )
    verification = ledger.stat(
        ProbeSpec(f"component:{component_id}:post-inspection", "model"), path
    )
    verified = _stat_payload(verification)
    if verified is None or any(
        verified.get(key) != payload.get(key)
        for key in ("kind", "size_bytes", "mtime", "realpath")
    ):
        base["status"] = "skipped"
        base["reason"] = "component_replaced_during_inspection"
        base["digest"] = {
            "status": "unavailable",
            "algorithm": "sha256",
            "value": None,
            "reason": "component_replaced_during_inspection",
        }
        base["metadata"] = {
            "status": "skipped",
            "format": suffix[1:],
            "reason": "component_replaced_during_inspection",
        }
        return base, True
    if suffix in {".safetensors", ".gguf"}:
        sidecar = _read_sidecar(
            ledger,
            component_id=f"{component_id}:config",
            path=path.with_name("config.json"),
            roots=roots,
        )
        if sidecar.get("status") == "observed":
            base["metadata"]["sidecar"] = sidecar  # type: ignore[index]
    metadata = base.get("metadata")
    metadata_status = metadata.get("status") if isinstance(metadata, dict) else None
    return base, metadata_status not in {"observed", "not_inspected", "unsupported"}


def _recipe_record(
    ledger: ProbeLedger,
    *,
    bundle_id: str,
    recipe: Any,
    roots: tuple[ModelRoot, ...],
) -> tuple[dict[str, object], bool]:
    """Return declared recipe identity and whether it degraded the bundle."""
    if recipe.path is not None:
        problem = _model_path_problem(recipe.path, roots)
        if problem is not None:
            return (
                {
                    "id": recipe.id,
                    "status": "skipped",
                    "path": str(recipe.path),
                    "digest": None,
                    "reason": problem,
                },
                True,
            )
        root = _model_root_for(recipe.path, roots)
        observation, digest = ledger.sha256(
            ProbeSpec(f"bundle:{bundle_id}:recipe-digest", "model"),
            recipe.path,
            limit=MAX_RECIPE_BYTES,
            follow_final_symlink=False,
            root=root.path if root is not None else None,
        )
        if digest is None:
            return (
                {
                    "id": recipe.id,
                    "status": observation.status,
                    "path": str(recipe.path),
                    "digest": None,
                    "reason": observation.reason,
                },
                True,
            )
        return (
            {
                "id": recipe.id,
                "status": "observed",
                "path": str(recipe.path),
                "digest": digest,
                "digest_source": "file",
            },
            False,
        )
    payload = {
        "id": recipe.id,
        "source": recipe.source,
        "parameters": recipe.parameters,
    }
    return (
        {
            "id": recipe.id,
            "status": "declared",
            "digest": digest_value(payload),
            "digest_source": "inline",
            "source": recipe.source,
            "parameters_digest": digest_value(recipe.parameters)
            if recipe.parameters is not None
            else None,
        },
        False,
    )


def _bundle_identity(
    *, engine: str, recipe: dict[str, object], components: list[dict[str, object]]
) -> dict[str, object]:
    """Describe component and recipe identity without implying qualification."""
    component_set = [
        {
            "id": component.get("id"),
            "role": component.get("role"),
            "kind": component.get("kind"),
            "size_bytes": component.get("size_bytes"),
            "status": component.get("status"),
            "digest_status": (component.get("digest") or {}).get("status")
            if isinstance(component.get("digest"), dict)
            else None,
            "digest": (component.get("digest") or {}).get("value")
            if isinstance(component.get("digest"), dict)
            else None,
        }
        for component in components
    ]
    component_set_digest = digest_value(component_set)
    digests = [
        (component.get("digest") or {}).get("status")
        if isinstance(component.get("digest"), dict)
        else None
        for component in components
    ]
    unavailable = any(component.get("status") != "observed" for component in components)
    computed = sum(1 for status in digests if status == "computed")
    if unavailable or recipe.get("status") not in {"observed", "declared"}:
        identity_status = "unavailable"
    elif computed == len(components):
        identity_status = "complete"
    elif computed == 0:
        identity_status = "declared"
    else:
        identity_status = "partial"
    digest = None
    reason: str | None = None
    if identity_status == "complete":
        digest = digest_value(
            {
                "engine": engine,
                "recipe_digest": recipe.get("digest"),
                "component_set_digest": component_set_digest,
            }
        )
    elif identity_status == "declared":
        reason = "component_digests_not_computed"
    elif identity_status == "partial":
        reason = "some_component_digests_not_computed"
    else:
        reason = "component_or_recipe_unavailable"
    return {
        "status": identity_status,
        "digest": digest,
        "component_set_digest": component_set_digest,
        "recipe_digest": recipe.get("digest"),
        "reason": reason,
    }


def inspect_bundles(
    ledger: ProbeLedger,
    manifest: InventoryManifest,
    *,
    hash_components: bool,
    hash_limit_bytes: int,
) -> tuple[list[dict[str, object]], list[Finding], bool]:
    """Inspect every declared bundle and return explicit identity states."""
    records: list[dict[str, object]] = []
    findings: list[Finding] = []
    degraded = False
    for bundle in manifest.bundles:
        recipe, recipe_degraded = _recipe_record(
            ledger,
            bundle_id=bundle.id,
            recipe=bundle.recipe,
            roots=manifest.model_roots,
        )
        components: list[dict[str, object]] = []
        for component in bundle.components:
            record, component_degraded = _inspect_component(
                ledger,
                component_id=f"{bundle.id}/{component.id}",
                role=component.role,
                path=component.path,
                roots=manifest.model_roots,
                hash_components=hash_components,
                hash_limit_bytes=hash_limit_bytes,
            )
            components.append(record)
            if component_degraded:
                degraded = True
                findings.append(
                    Finding(
                        code="component_unavailable",
                        severity=Severity.WARNING.value,
                        subject=f"bundle:{bundle.id}",
                        message=(
                            f"Component {component.id!r} was not inspected; "
                            f"reason: {record.get('reason') or 'unknown'}."
                        ),
                    )
                )
        degraded = degraded or recipe_degraded
        identity = _bundle_identity(engine=bundle.engine, recipe=recipe, components=components)
        if identity["status"] != "complete":
            findings.append(
                Finding(
                    code="bundle_identity_incomplete",
                    severity=Severity.INFO.value,
                    subject=f"bundle:{bundle.id}",
                    message=(
                        "Bundle identity is not complete; component or recipe content "
                        "digests were not all computed."
                    ),
                )
            )
        records.append(
            {
                "id": bundle.id,
                "engine": bundle.engine,
                "recipe": recipe,
                "components": components,
                "capabilities": {
                    "status": "configured" if bundle.capabilities else "not_configured",
                    "items": [item.to_dict() for item in bundle.capabilities],
                },
                "identity": identity,
            }
        )
    if not manifest.bundles:
        findings.append(
            Finding(
                code="bundles_not_configured",
                severity=Severity.INFO.value,
                subject="bundles",
                message="No model roots or component bundles were declared in the manifest.",
            )
        )
    return records, findings, degraded
