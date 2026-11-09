"""Versioned records for one declared backend execution attempt.

The records in this module describe what the application asked a local
inference executable to do, that the executable was actually started, and what
the application-owned supervisor observed while the direct child ran. They are
stored as strict JSON in the execution database and are revalidated whenever
they are read back.

Three distinct stages exist:

"resolved"
    The immutable pre-dispatch plan. It names the candidate, engine, recipe,
    components, request conditioning, exact argument vector, environment
    allowlist, and runtime fingerprint. It is inserted once and never updated.

"launched"
    The fact that the application started one direct child process. A resolved
    record alone never proves a launch.

"observed"
    Supervisor-owned facts about the direct child after it was reaped. The
    record keeps byte counts, complete stream digests, and a bounded text-free
    classification instead of captured output, because subprocess output can
    contain prompts and credentials. It reports only whether an inherited
    stream still had a live writer: nothing here identifies, counts, or
    terminates descendant processes, and no containment claim is made.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ._candidate_contract import COMPONENT_ROLES
from .errors import BackendEvidenceError
from .privacy import (
    COMFYUI_ADAPTER_ID,
    COMFYUI_SAFE_ENVIRONMENT_NAMES,
    PrivacyControl,
    is_valid_python_hash_seed,
    validate_comfyui_resolved_privacy_evidence,
)

_COMFYUI_PYTHON_BOOTSTRAP_PATH = str(
    Path(__file__).with_name("_comfyui_python_bootstrap.py").resolve()
)

RECORD_SCHEMA_VERSION = 2
RESOLVED_RECORD_SCHEMA_VERSION = 4
LEGACY_COMFYUI_RESOLVED_RECORD_SCHEMA_VERSION = 3
COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS = frozenset(
    {LEGACY_COMFYUI_RESOLVED_RECORD_SCHEMA_VERSION, RESOLVED_RECORD_SCHEMA_VERSION}
)
RESOLVED_SCHEMA = "media-generation.backend-execution-resolved"
LAUNCH_SCHEMA = "media-generation.backend-execution-launch"
OBSERVED_SCHEMA = "media-generation.backend-execution-observed"
EFFECTIVE_EXECUTION_SCHEMA = "media-generation.comfyui-effective-execution"
EFFECTIVE_EXECUTION_SCHEMA_VERSION = 2
RESOURCE_RELEASE_DECLARATION_KEY = "resource_release"
RESOURCE_RELEASE_DECLARATION_SCHEMA = "media-generation.resource-release"
RESOURCE_RELEASE_DECLARATION_VERSION = 1
DIRECT_CHILD_RESOURCE_RELEASE_SCOPE = "direct-child"
PROCESS_TREE_RESOURCE_RELEASE_SCOPE = "process-tree"
COMFYUI_RESOLVED_BACKEND_KIND = "comfyui-local-http"
COMFYUI_RESOLVED_INVOCATION_CONTRACT = "comfyui-http/v1"
COMFYUI_RESOLVED_CLI_CONTRACT = "comfyui-api/v1"

MAX_EFFECTIVE_EXECUTION_BYTES = 256 * 1024
MAX_RESOLVED_RECORD_BYTES = 512 * 1024
MAX_EVIDENCE_NODES = 2048
MAX_EVIDENCE_STRING_CHARS = 4096
MAX_EVIDENCE_COLLECTION_ITEMS = 4096
MAX_EVIDENCE_DEPTH = 64

EXECUTION_STATES = ("resolved", "launched", "observed")
MAX_RECORDED_OUTPUT_LINES = 64
"""Largest line count still classified as bounded output."""

OUTPUT_CLASSIFICATIONS = ("empty", "truncated", "non_utf8", "utf8")
"""Closed encoding classification recorded for one captured output stream.

"empty" means the stream produced no bytes. "truncated" means the retained
prefix is shorter than the bytes the supervisor read. "non_utf8" means the
retained prefix is not valid UTF-8 text. "utf8" means the complete capture
decoded as UTF-8.
"""

OUTPUT_CODES = (
    "blank",
    "contains_absolute_path",
    "contains_url",
    "lines_bounded",
    "many_lines",
    "non_utf8",
    "prompt_echo_detected",
    "secret_like_material_detected",
    "truncated",
)
"""Closed taxonomy describing captured output without reproducing it."""

_URL_PATTERN = re.compile(r"(?i)\b(?:https?|ftp|wss?)://")
_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?:^|[\s(=:,])(?:/(?:[\w.-]+)(?:/[\w.-]+)*|[A-Za-z]:\\)"
)
_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(?:authorization|bearer|access[_-]?token|api[_-]?key|"
        r"client[_-]?secret|password|passwd|secret|token)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_MINIMUM_PROMPT_MARKER_CHARS = 6
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OUTPUT_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_REMOTE_URL = re.compile(r"(?i)[a-z][a-z0-9+.-]*://")
_DATA_URL = re.compile(r"(?i)data:image/")
_SECRET_KEY = re.compile(
    r"(?i)(?:authorization|bearer|access[_-]?token|api[_-]?key|client[_-]?secret|"
    r"password|passwd|credential|private[_-]?key|secret|session[_-]?token|cookie)"
)


def configuration_requires_process_tree_resource_release(
    configuration: Mapping[str, object],
    *,
    adapter_id: str,
) -> bool:
    """Return whether adapter configuration requires process-tree evidence.

    The immutable admitted adapter identity selects the policy before the
    configuration is read. ComfyUI always requires process-tree evidence, so
    a missing, historical, malformed, or unsupported declaration cannot fall
    back to direct-child release. Other adapters created before this
    declaration existed retain their direct-child behavior; malformed or
    unsupported declarations fail closed for them as well.
    """
    if not isinstance(adapter_id, str) or not adapter_id:
        return True
    if adapter_id == COMFYUI_ADAPTER_ID:
        return True
    declaration = configuration.get(RESOURCE_RELEASE_DECLARATION_KEY)
    if declaration is None:
        return False
    if not isinstance(declaration, Mapping):
        return True
    if set(declaration) != {"schema", "schema_version", "required_scope"}:
        return True
    if declaration.get("schema") != RESOURCE_RELEASE_DECLARATION_SCHEMA:
        return True
    schema_version = declaration.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != RESOURCE_RELEASE_DECLARATION_VERSION
    ):
        return True
    scope = declaration.get("required_scope")
    if scope == DIRECT_CHILD_RESOURCE_RELEASE_SCOPE:
        return False
    if scope == PROCESS_TREE_RESOURCE_RELEASE_SCOPE:
        return True
    return True
COMFYUI_APP_MIN_DIMENSION = 64
COMFYUI_APP_MAX_DIMENSION = 2048
COMFYUI_APP_DIMENSION_MULTIPLE = 8
_COMFYUI_OUTPUT_PREFIX = "media-generation-output"
_COMFYUI_MODEL_DIRECTORIES = {
    "checkpoint": "checkpoints",
    "diffusion_model": "diffusion_models",
    "text_encoder": "text_encoders",
    "vae": "vae",
    "lora": "loras",
    "controlnet": "controlnet",
    "adapter": "adapters",
    "projector": "clip_vision",
}
_COMFYUI_MODEL_SELECTOR_ROLES = {
    ("CheckpointLoaderSimple", "ckpt_name"): frozenset({"checkpoint"}),
    ("UNETLoader", "unet_name"): frozenset({"diffusion_model"}),
    ("CLIPLoader", "clip_name"): frozenset({"text_encoder"}),
    ("VAELoader", "vae_name"): frozenset({"vae"}),
    ("LoraLoader", "lora_name"): frozenset({"lora"}),
    ("LoraLoaderModelOnly", "lora_name"): frozenset({"lora"}),
    ("ControlNetLoader", "control_net_name"): frozenset({"controlnet"}),
    ("CLIPVisionLoader", "clip_name"): frozenset({"projector"}),
}
_COMFYUI_MODEL_SELECTOR_INPUTS = frozenset(
    input_name for _, input_name in _COMFYUI_MODEL_SELECTOR_ROLES
)
COMFYUI_WORKFLOW_APPROVAL_SCHEMA = "media-generation.comfyui-workflow-approval/v1"
MAX_COMFYUI_WORKFLOW_APPROVAL_BYTES = 256 * 1024

_DEFAULT_ROCM_ROOT = "/opt/rocm"
"""Installation root used when ROCM_PATH does not name a readable marker."""

_ROCM_VERSION_RELATIVE_PATH = ".info/version"
"""Path below a ROCm installation root that names the installed release."""

_AMDGPU_VERSION_MARKER = "/sys/module/amdgpu/version"
"""Preferred read-only amdgpu kernel-module version marker."""

_AMDGPU_SRCVERSION_MARKER = "/sys/module/amdgpu/srcversion"
"""Fallback loaded-module build identifier exposed by the kernel.

Some kernels do not publish /sys/module/amdgpu/version. The srcversion file is
usable only as an opaque identifier of the loaded module build. It is not a
semantic driver version and must never be parsed, ordered, or compared with
version strings.
"""

RECORDED_ENVIRONMENT_VALUES = ("HIP_VISIBLE_DEVICES", "HSA_OVERRIDE_GFX_VERSION")
"""Environment names whose values are copied into durable evidence.

Every other allowlisted variable contributes only its name, so credentials and
host-specific paths never enter the database.
"""


def environment_record(environment: Mapping[str, str]) -> dict[str, object]:
    """Describe one child environment as names plus selected non-sensitive values."""
    return {
        "names": sorted(environment),
        "values": {
            name: environment[name]
            for name in RECORDED_ENVIRONMENT_VALUES
            if name in environment
        },
    }


def canonical_json(value: object) -> str:
    """Serialize evidence deterministically as strict JSON.

    The same helper is used when a record is written and when its digest is
    recomputed after reopening the database, so canonicalization cannot drift
    between writer and reader.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value: object) -> str:
    """Return the SHA-256 digest of the canonical JSON form of a value."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def backend_digest(value: object) -> str:
    """Return the digest used as the identity of a stored backend record.

    This named entry point keeps persistence and validation coupled to one
    definition. The digest covers the canonical JSON form rather than the raw
    SQLite text, so reopening a database cannot change the identity of a
    record that parsed to the same value.
    """

    return digest(value)


@dataclass(frozen=True, slots=True)
class OutputClassification:
    """Bounded, text-free description of one captured output stream.

    The execution record keeps no raw process text. A reader can still see
    whether the stream produced nothing, was truncated at the capture limit,
    or was not valid UTF-8, and which risk classes the retained bytes matched.
    Codes never carry the text that produced them.
    """

    classification: str
    codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.classification not in OUTPUT_CLASSIFICATIONS:
            raise ValueError("unsupported output classification")
        if not self.codes:
            raise ValueError("output classification requires at least one code")
        if any(code not in OUTPUT_CODES for code in self.codes):
            raise ValueError("unsupported output code")
        if self.codes != tuple(sorted(set(self.codes))):
            raise ValueError("output codes must be sorted and unique")


def classify_output(
    data: bytes,
    *,
    total_bytes: int,
    prompt_markers: Sequence[str] = (),
) -> OutputClassification:
    """Return a bounded, text-free description of captured process output.

    The "data" argument is the retained prefix of one stream and
    "total_bytes" is the number of bytes the supervisor read from that
    stream. Prompt markers are compared in memory so a request echo can be
    reported as a code; the marker text never becomes part of the result.
    """

    if isinstance(total_bytes, bool) or not isinstance(total_bytes, int):
        raise ValueError("total_bytes must be an integer")
    if total_bytes < 0:
        raise ValueError("total_bytes must not be negative")
    if total_bytes == 0:
        return OutputClassification("empty", ("blank",))
    codes: set[str] = set()
    truncated = len(data) < total_bytes
    if truncated:
        codes.add("truncated")
    try:
        text = data.decode("utf-8")
        encoded = "utf8"
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        encoded = "non_utf8"
        codes.add("non_utf8")
    if not text.strip():
        codes.add("blank")
    line_count = text.count("\n") + (0 if text.endswith("\n") else 1)
    codes.add(
        "lines_bounded" if line_count <= MAX_RECORDED_OUTPUT_LINES else "many_lines"
    )
    if _URL_PATTERN.search(text):
        codes.add("contains_url")
    if _ABSOLUTE_PATH_PATTERN.search(text):
        codes.add("contains_absolute_path")
    if any(pattern.search(text) for pattern in _SECRET_PATTERNS):
        codes.add("secret_like_material_detected")
    if _echoes_prompt(text, prompt_markers):
        codes.add("prompt_echo_detected")
    classification = "truncated" if truncated else encoded
    return OutputClassification(classification, tuple(sorted(codes)))


def _echoes_prompt(text: str, markers: Sequence[str]) -> bool:
    """Return whether captured text repeats one request text marker."""
    folded = text.casefold()
    return any(
        len(candidate) >= _MINIMUM_PROMPT_MARKER_CHARS and candidate in folded
        for candidate in (item.strip().casefold() for item in markers)
    )



def _read_runtime_text(path: str, *, limit: int = 256) -> str | None:
    """Read a small read-only runtime marker without failing when it is absent."""

    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        return None
    value = data.decode("utf-8", errors="replace").strip()
    return value or None


def _first_readable_runtime_text(paths: Sequence[str]) -> str | None:
    """Return the first readable marker value, or None when none is readable."""

    for path in paths:
        value = _read_runtime_text(path)
        if value is not None:
            return value
    return None


def _rocm_version_marker(rocm_path: str | None) -> str | None:
    """Read the ROCm release marker for the active installation root.

    An explicitly configured ROCM_PATH is consulted first because it names the
    installation the runtime and compiler toolchain use. If that marker is
    absent or unreadable, the standard /opt/rocm installation remains the
    documented fallback. The lookup returns None rather than guessing when
    neither marker is readable.
    """

    candidates: list[str] = []
    if rocm_path:
        candidates.append(os.path.join(rocm_path, _ROCM_VERSION_RELATIVE_PATH))
    candidates.append(os.path.join(_DEFAULT_ROCM_ROOT, _ROCM_VERSION_RELATIVE_PATH))
    return _first_readable_runtime_text(candidates)


def _amdgpu_version_marker() -> str | None:
    """Return the preferred module version or the opaque srcversion fallback.

    /sys/module/amdgpu/version is the preferred semantic marker. Some kernels
    omit it; in that case /sys/module/amdgpu/srcversion is recorded under the
    same field as an opaque loaded-module build identifier. A srcversion value
    is not a semantic driver version, and callers must not interpret it as one.
    """

    value = _read_runtime_text(_AMDGPU_VERSION_MARKER)
    if value is not None:
        return value
    return _read_runtime_text(_AMDGPU_SRCVERSION_MARKER)


def capture_runtime_fingerprint() -> dict[str, str | None]:
    """Return the documented read-only runtime facts used for dispatch policy.

    Every value is read from a read-only source and may be None when the source
    is absent. The ROCm release marker comes from ROCM_PATH/.info/version when
    ROCM_PATH is set and that file is readable, then from
    /opt/rocm/.info/version. The amdgpu field comes from
    /sys/module/amdgpu/version when readable, then from
    /sys/module/amdgpu/srcversion, which is an opaque loaded-module build
    identifier rather than a semantic driver version. The field name and record
    schema stay unchanged for the srcversion fallback.

    A caller must not treat None as evidence of a capable runtime; the engine
    module refuses ROCm execution when the version markers are missing.
    """

    rocm_path = os.environ.get("ROCM_PATH") or None
    return {
        "platform": platform.system().strip().lower() or None,
        "machine": platform.machine().strip() or None,
        "rocm_path": rocm_path,
        "rocm_version": _rocm_version_marker(rocm_path),
        "amdgpu_version": _amdgpu_version_marker(),
        "hsa_override_gfx_version": os.environ.get("HSA_OVERRIDE_GFX_VERSION") or None,
        "hip_visible_devices": os.environ.get("HIP_VISIBLE_DEVICES") or None,
    }


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BackendEvidenceError(f"{label} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise BackendEvidenceError(f"{label} has invalid fields: {'; '.join(details)}")


def _string(value: object, *, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise BackendEvidenceError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label=label)


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BackendEvidenceError(f"{label} must be an integer of at least {minimum}")
    return value


def _comfyui_dimension(value: object, *, label: str) -> int:
    """Validate one resolution value against the application contract."""
    result = _integer(value, label=label, minimum=COMFYUI_APP_MIN_DIMENSION)
    if result > COMFYUI_APP_MAX_DIMENSION:
        raise BackendEvidenceError(f"{label} exceeds the maximum dimension")
    if result % COMFYUI_APP_DIMENSION_MULTIPLE:
        raise BackendEvidenceError(f"{label} does not satisfy the dimension multiple")
    return result


def _optional_integer(value: object, *, label: str, minimum: int = 0) -> int | None:
    if value is None:
        return None
    return _integer(value, label=label, minimum=minimum)


def _number(value: object, *, label: str, minimum: float, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BackendEvidenceError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise BackendEvidenceError(f"{label} must be a finite number of at least {minimum}")
    if maximum is not None and result > maximum:
        raise BackendEvidenceError(f"{label} must not exceed {maximum}")
    return result


def _sha256(value: object, *, label: str) -> str:
    text = _string(value, label=label)
    if not _SHA256.fullmatch(text):
        raise BackendEvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _digest_identity(value: object, *, label: str) -> str:
    """Validate a T07 stable identity of the form ``sha256:<hex>``."""
    text = _string(value, label=label)
    prefix = "sha256:"
    if not text.startswith(prefix) or not _SHA256.fullmatch(text[len(prefix) :]):
        raise BackendEvidenceError(f"{label} must be a sha256:<lowercase hex> identity")
    return text


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise BackendEvidenceError(f"{label} must be a boolean")
    return value


def _validate_resolved_record_v2(value: object) -> None:
    """Validate the historical resolved execution record contract."""

    record = _mapping(value, label="resolved backend execution")
    _exact_keys(
        record,
        {
            "schema",
            "schema_version",
            "attempt_id",
            "backend_kind",
            "candidate_id",
            "verification_id",
            "declaration_sha256",
            "engine",
            "recipe",
            "components",
            "adapters",
            "prompt",
            "seed",
            "width",
            "height",
            "sampling",
            "conditioning",
            "argv",
            "environment",
            "output_basename",
            "invocation_contract",
            "cli_contract",
            "runtime",
            "privacy",
            "verification_window",
        },
        label="resolved backend execution",
    )
    if record["schema"] != RESOLVED_SCHEMA or record["schema_version"] != RECORD_SCHEMA_VERSION:
        raise BackendEvidenceError("resolved backend execution has an unsupported schema")
    _string(record["attempt_id"], label="resolved.attempt_id")
    _string(record["backend_kind"], label="resolved.backend_kind")
    _digest_identity(record["candidate_id"], label="resolved.candidate_id")
    _digest_identity(record["verification_id"], label="resolved.verification_id")
    _sha256(record["declaration_sha256"], label="resolved.declaration_sha256")

    engine = _mapping(record["engine"], label="resolved.engine")
    _exact_keys(engine, {"id", "version", "build", "executable_sha256"}, label="resolved.engine")
    for name in ("id", "version", "build"):
        _string(engine[name], label=f"resolved.engine.{name}")
    _sha256(engine["executable_sha256"], label="resolved.engine.executable_sha256")

    recipe = _mapping(record["recipe"], label="resolved.recipe")
    _exact_keys(recipe, {"id", "document_sha256"}, label="resolved.recipe")
    _string(recipe["id"], label="resolved.recipe.id")
    _sha256(recipe["document_sha256"], label="resolved.recipe.document_sha256")

    components = record["components"]
    if not isinstance(components, list):
        raise BackendEvidenceError("resolved.components must be a list")
    for index, item in enumerate(components):
        label = f"resolved.components[{index}]"
        component = _mapping(item, label=label)
        _exact_keys(
            component,
            {"id", "role", "sha256", "precision", "quantization"},
            label=label,
        )
        _string(component["id"], label=f"{label}.id")
        role = _string(component["role"], label=f"{label}.role")
        if role not in COMPONENT_ROLES:
            raise BackendEvidenceError(f"{label}.role is not a recognized component role")
        _sha256(component["sha256"], label=f"{label}.sha256")
        _string(component["precision"], label=f"{label}.precision")
        _string(component["quantization"], label=f"{label}.quantization")

    adapters = record["adapters"]
    if not isinstance(adapters, list):
        raise BackendEvidenceError("resolved.adapters must be a list")
    for index, item in enumerate(adapters):
        label = f"resolved.adapters[{index}]"
        adapter = _mapping(item, label=label)
        _exact_keys(adapter, {"component_id", "order", "strength"}, label=label)
        _string(adapter["component_id"], label=f"{label}.component_id")
        _integer(adapter["order"], label=f"{label}.order")
        _number(adapter["strength"], label=f"{label}.strength", minimum=0.0, maximum=1.0)

    _string(record["prompt"], label="resolved.prompt")
    _integer(record["seed"], label="resolved.seed")
    _integer(record["width"], label="resolved.width", minimum=1)
    _integer(record["height"], label="resolved.height", minimum=1)

    sampling = _mapping(record["sampling"], label="resolved.sampling")
    _exact_keys(
        sampling,
        {"sampling_method", "steps", "cfg_scale", "flow_shift", "strength"},
        label="resolved.sampling",
    )
    _string(sampling["sampling_method"], label="resolved.sampling.sampling_method")
    _integer(sampling["steps"], label="resolved.sampling.steps", minimum=1)
    _number(sampling["cfg_scale"], label="resolved.sampling.cfg_scale", minimum=0.0)
    _number(sampling["flow_shift"], label="resolved.sampling.flow_shift", minimum=0.0)
    if sampling["strength"] is not None:
        _number(sampling["strength"], label="resolved.sampling.strength", minimum=0.0, maximum=1.0)

    conditioning = record["conditioning"]
    if not isinstance(conditioning, list):
        raise BackendEvidenceError("resolved.conditioning must be a list")
    for index, item in enumerate(conditioning):
        label = f"resolved.conditioning[{index}]"
        entry = _mapping(item, label=label)
        _exact_keys(entry, {"artifact_id", "role", "content_sha256"}, label=label)
        _string(entry["artifact_id"], label=f"{label}.artifact_id")
        if entry["role"] not in {"reference", "source"}:
            raise BackendEvidenceError(f"{label}.role must be reference or source")
        _sha256(entry["content_sha256"], label=f"{label}.content_sha256")

    argv = record["argv"]
    if not isinstance(argv, list) or not argv:
        raise BackendEvidenceError("resolved.argv must be a non-empty list")
    for index, item in enumerate(argv):
        _string(item, label=f"resolved.argv[{index}]")

    environment = _mapping(record["environment"], label="resolved.environment")
    _exact_keys(environment, {"names", "values"}, label="resolved.environment")
    names = environment["names"]
    values = _mapping(environment["values"], label="resolved.environment.values")
    if not isinstance(names, list) or any(not isinstance(name, str) or not name for name in names):
        raise BackendEvidenceError("resolved.environment.names must be a list of names")
    if names != sorted(set(names)):
        raise BackendEvidenceError("resolved.environment.names must be sorted and unique")
    if not set(values) <= set(names):
        raise BackendEvidenceError("resolved.environment.values may only name allowlisted keys")
    for name, item in values.items():
        _string(name, label="resolved.environment.values key")
        if not isinstance(item, str):
            raise BackendEvidenceError("resolved.environment.values must contain strings")

    basename = _string(record["output_basename"], label="resolved.output_basename")
    if not _OUTPUT_BASENAME.fullmatch(basename):
        raise BackendEvidenceError("resolved.output_basename is not a safe file name")
    _string(record["invocation_contract"], label="resolved.invocation_contract")
    _string(record["cli_contract"], label="resolved.cli_contract")

    runtime = _mapping(record["runtime"], label="resolved.runtime")
    _exact_keys(
        runtime,
        {
            "platform",
            "machine",
            "rocm_path",
            "rocm_version",
            "amdgpu_version",
            "hsa_override_gfx_version",
            "hip_visible_devices",
        },
        label="resolved.runtime",
    )
    for name, item in runtime.items():
        _optional_string(item, label=f"resolved.runtime.{name}")

    privacy = _mapping(record["privacy"], label="resolved.privacy")
    _exact_keys(
        privacy,
        {control.value for control in PrivacyControl},
        label="resolved.privacy",
    )
    for name, item in privacy.items():
        if item is not None and not isinstance(item, bool):
            raise BackendEvidenceError(
                f"resolved.privacy.{name} must be boolean or null"
            )

    verification = _mapping(
        record["verification_window"], label="resolved.verification_window"
    )
    _exact_keys(
        verification,
        {
            "verified_before_launch",
            "engine_may_open_different_bytes_after_launch",
            "statement",
        },
        label="resolved.verification_window",
    )
    if verification["verified_before_launch"] is not True:
        raise BackendEvidenceError(
            "resolved.verification_window.verified_before_launch must be true"
        )
    if verification["engine_may_open_different_bytes_after_launch"] is not True:
        raise BackendEvidenceError(
            "resolved.verification_window."
            "engine_may_open_different_bytes_after_launch must be true"
        )
    _string(
        verification["statement"],
        label="resolved.verification_window.statement",
    )


def _bounded_json(value: object, *, label: str) -> None:
    """Reject evidence values that cannot be stored and inspected safely."""
    active: set[int] = set()

    def visit(item: object, *, depth: int) -> None:
        if depth > MAX_EVIDENCE_DEPTH:
            raise BackendEvidenceError(f"{label} exceeds the maximum JSON depth")
        if isinstance(item, str):
            if len(item) > MAX_EVIDENCE_STRING_CHARS:
                raise BackendEvidenceError(f"{label} contains an oversized string")
            return
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise BackendEvidenceError(f"{label} contains a non-finite number")
            return
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                raise BackendEvidenceError(f"{label} contains a recursive JSON value")
            if len(item) > MAX_EVIDENCE_COLLECTION_ITEMS:
                raise BackendEvidenceError(f"{label} contains an oversized object")
            active.add(identity)
            try:
                for key, child in item.items():
                    if not isinstance(key, str) or not key:
                        raise BackendEvidenceError(
                            f"{label} object keys must be non-empty strings"
                        )
                    if len(key) > MAX_EVIDENCE_STRING_CHARS:
                        raise BackendEvidenceError(f"{label} contains an oversized object key")
                    visit(child, depth=depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                raise BackendEvidenceError(f"{label} contains a recursive JSON value")
            if len(item) > MAX_EVIDENCE_COLLECTION_ITEMS:
                raise BackendEvidenceError(f"{label} contains an oversized array")
            active.add(identity)
            try:
                for child in item:
                    visit(child, depth=depth + 1)
            finally:
                active.remove(identity)
            return
        raise BackendEvidenceError(f"{label} contains an unsupported JSON value")

    visit(value, depth=0)


def _validate_workflow_approval(value: object, *, label: str) -> Mapping[str, object]:
    """Validate the bounded T07 workflow authority embedded in v3 evidence."""
    approval = _mapping(value, label=label)
    _exact_keys(
        approval,
        {
            "schema",
            "authority_id",
            "document_sha256",
            "document_size_bytes",
            "document",
            "component_id",
            "component_sha256",
        },
        label=label,
    )
    if approval["schema"] != COMFYUI_WORKFLOW_APPROVAL_SCHEMA:
        raise BackendEvidenceError(f"{label} has an unsupported schema")
    _string(approval["authority_id"], label=f"{label}.authority_id")
    document_sha256 = _sha256(
        approval["document_sha256"], label=f"{label}.document_sha256"
    )
    document_size = _integer(
        approval["document_size_bytes"],
        label=f"{label}.document_size_bytes",
        minimum=1,
    )
    if document_size > MAX_COMFYUI_WORKFLOW_APPROVAL_BYTES:
        raise BackendEvidenceError(f"{label} exceeds the workflow approval size limit")
    document = _mapping(approval["document"], label=f"{label}.document")
    _bounded_json(document, label=f"{label}.document")
    try:
        encoded = (canonical_json(document) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise BackendEvidenceError(f"{label}.document is not bounded canonical JSON") from error
    if len(encoded) != document_size or hashlib.sha256(encoded).hexdigest() != document_sha256:
        raise BackendEvidenceError(f"{label} document digest or size does not match")
    _exact_keys(
        document,
        {
            "schema",
            "schema_version",
            "tool_id",
            "tool_version",
            "recipe_document_sha256",
            "operations",
        },
        label=f"{label}.document",
    )
    if (
        document["schema"] != "media-generation.comfyui-workflow-approval"
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise BackendEvidenceError(f"{label}.document identity is unsupported")
    _string(document["tool_id"], label=f"{label}.document.tool_id")
    _string(document["tool_version"], label=f"{label}.document.tool_version")
    recipe_sha256 = _sha256(
        document["recipe_document_sha256"],
        label=f"{label}.document.recipe_document_sha256",
    )
    _string(approval["component_id"], label=f"{label}.component_id")
    component_sha256 = _sha256(
        approval["component_sha256"], label=f"{label}.component_sha256"
    )
    if component_sha256 != recipe_sha256:
        raise BackendEvidenceError(f"{label} is not bound to its approved recipe component")
    operations = _mapping(document["operations"], label=f"{label}.document.operations")
    _exact_keys(
        operations,
        {"generate", "edit"},
        label=f"{label}.document.operations",
    )
    for operation_name, raw_operation in operations.items():
        operation_label = f"{label}.document.operations.{operation_name}"
        operation = _mapping(raw_operation, label=operation_label)
        _exact_keys(
            operation,
            {"graph_sha256", "nodes"},
            label=operation_label,
        )
        _sha256(
            operation["graph_sha256"],
            label=f"{operation_label}.graph_sha256",
        )
        nodes = _mapping(operation["nodes"], label=f"{operation_label}.nodes")
        if not nodes or len(nodes) > MAX_EVIDENCE_NODES:
            raise BackendEvidenceError(f"{operation_label}.nodes must be bounded and non-empty")
        for class_name, raw_pin in nodes.items():
            _string(class_name, label=f"{operation_label}.nodes key")
            if _NODE_ID.fullmatch(class_name) is None:
                raise BackendEvidenceError(f"{operation_label}.nodes has an invalid class name")
            pin_label = f"{operation_label}.nodes.{class_name}"
            pin = _mapping(raw_pin, label=pin_label)
            _exact_keys(pin, {"component_id", "sha256"}, label=pin_label)
            _string(pin["component_id"], label=f"{pin_label}.component_id")
            _sha256(pin["sha256"], label=f"{pin_label}.sha256")
    _validate_comfyui_private_value(approval, label=label)
    return approval


def validate_comfyui_source_conditioning_path(
    graph: Mapping[str, object],
    *,
    output_node_id: str,
    output_field: str,
    source_node_id: str | None = None,
    require_artifact_placeholder: bool = False,
    label: str = "ComfyUI source edit graph",
) -> str:
    """Require the source image to reach the approved sampler and image output."""

    def fail(detail: str) -> None:
        raise BackendEvidenceError(f"{label} source conditioning path {detail}")

    def node(node_id: str, expected_class: str, purpose: str) -> Mapping[str, object]:
        raw = graph.get(node_id)
        if not isinstance(raw, Mapping) or raw.get("class_type") != expected_class:
            fail(f"does not contain the expected {purpose} node")
        inputs = raw.get("inputs")
        if not isinstance(inputs, Mapping):
            fail(f"has malformed {purpose} inputs")
        return raw

    def linked_node(
        consumer_id: str,
        input_name: str,
        expected_class: str,
        purpose: str,
    ) -> str:
        consumer = _mapping(graph.get(consumer_id), label=f"{label}.{consumer_id}")
        inputs = _mapping(consumer.get("inputs"), label=f"{label}.{consumer_id}.inputs")
        link = inputs.get(input_name)
        if (
            not isinstance(link, list)
            or len(link) != 2
            or not isinstance(link[0], str)
            or type(link[1]) is not int
            or link[1] != 0
        ):
            fail(f"has no approved {purpose} output link")
        source_id = link[0]
        node(source_id, expected_class, purpose)
        return source_id

    if output_field != "images":
        fail("uses an unsupported output field")
    if source_node_id is None:
        source_nodes = [
            node_id
            for node_id, raw in graph.items()
            if isinstance(raw, Mapping)
            and raw.get("class_type") == "LoadImage"
            and isinstance(raw.get("inputs"), Mapping)
            and raw["inputs"].get("image") == "$artifact:0"
        ]
        if len(source_nodes) != 1:
            fail("must bind exactly one LoadImage to $artifact:0")
        source_node_id = source_nodes[0]
    source = node(source_node_id, "LoadImage", "source image")
    source_inputs = _mapping(source["inputs"], label=f"{label}.{source_node_id}.inputs")
    image_value = source_inputs.get("image")
    if require_artifact_placeholder:
        if image_value != "$artifact:0":
            fail("does not bind LoadImage.image to $artifact:0")
    elif (
        not isinstance(image_value, str)
        or not image_value
        or image_value in {".", ".."}
        or "/" in image_value
        or "\\" in image_value
        or "\x00" in image_value
        or _REMOTE_URL.search(image_value)
    ):
        fail("does not use a private run-scoped source filename")

    output = node(output_node_id, "SaveImage", "approved image output")
    output_inputs = _mapping(output["inputs"], label=f"{label}.{output_node_id}.inputs")
    if output_field not in output_inputs:
        fail("does not connect the approved image output")
    output_source = output_inputs[output_field]
    if (
        not isinstance(output_source, list)
        or len(output_source) != 2
        or not isinstance(output_source[0], str)
        or type(output_source[1]) is not int
        or output_source[1] != 0
    ):
        fail("has no approved image output link")
    decoder_id = linked_node(output_node_id, output_field, "VAEDecode", "VAE decode")
    decoder_inputs = _mapping(
        graph[decoder_id]["inputs"], label=f"{label}.{decoder_id}.inputs"
    )
    sampler_id = linked_node(decoder_id, "samples", "KSampler", "sampler")
    encoder_id = linked_node(sampler_id, "latent_image", "VAEEncode", "source latent")
    encoder_inputs = _mapping(
        graph[encoder_id]["inputs"], label=f"{label}.{encoder_id}.inputs"
    )
    pixel_source_id = linked_node_from = encoder_inputs.get("pixels")
    if (
        not isinstance(linked_node_from, list)
        or len(linked_node_from) != 2
        or not isinstance(linked_node_from[0], str)
        or type(linked_node_from[1]) is not int
        or linked_node_from[1] != 0
    ):
        fail("does not connect source pixels to VAEEncode")
    pixel_source_id = linked_node_from[0]
    pixel_source = _mapping(graph.get(pixel_source_id), label=f"{label}.{pixel_source_id}")
    if pixel_source.get("class_type") == "ImageScale":
        if linked_node(pixel_source_id, "image", "LoadImage", "source image") != source_node_id:
            fail("routes VAEEncode pixels from a different image")
    elif pixel_source.get("class_type") != "LoadImage" or pixel_source_id != source_node_id:
        fail("routes VAEEncode pixels from a non-source node")

    encoder_vae = linked_node(encoder_id, "vae", "VAELoader", "source VAE")
    decoder_vae = linked_node(decoder_id, "vae", "VAELoader", "output VAE")
    if encoder_vae != decoder_vae:
        fail("uses different VAE nodes for source encoding and output decoding")
    return source_node_id


def validate_comfyui_qwen_conditioning_graph(
    graph: Mapping[str, object],
    *,
    operation: str,
    output_node_id: str,
    output_field: str,
    expected_prompt: object,
    expected_width: object,
    expected_height: object,
    source_node_id: str | None = None,
    require_artifact_placeholder: bool = False,
    label: str = "ComfyUI Qwen graph",
) -> str:
    """Require the approved Qwen reference or source conditioning topology."""
    if operation not in {"generate", "edit"}:
        raise BackendEvidenceError(f"{label} operation unsupported")
    if output_field != "images":
        raise BackendEvidenceError(f"{label} uses an unsupported output field")

    def fail(detail: str) -> None:
        raise BackendEvidenceError(f"{label} {detail}")

    def inputs_for(
        node_id: str, expected: set[str], purpose: str
    ) -> Mapping[str, object]:
        raw = _mapping(graph.get(node_id), label=f"{label}.{node_id}")
        inputs = _mapping(raw.get("inputs"), label=f"{label}.{node_id}.inputs")
        if set(inputs) != expected:
            fail(f"{purpose} inputs do not match the approved {operation} profile")
        return inputs

    def linked(node_id: str, input_name: str, purpose: str) -> str:
        raw = _mapping(graph.get(node_id), label=f"{label}.{node_id}")
        inputs = _mapping(raw.get("inputs"), label=f"{label}.{node_id}.inputs")
        link = inputs.get(input_name)
        if (
            not isinstance(link, list)
            or len(link) != 2
            or not isinstance(link[0], str)
            or type(link[1]) is not int
            or link[1] != 0
            or link[0] not in graph
        ):
            fail(f"{purpose} uses no approved slot-0 link")
        return link[0]

    by_class: dict[str, list[str]] = {}
    for node_id, raw_node in graph.items():
        node = _mapping(raw_node, label=f"{label}.{node_id}")
        class_type = _string(
            node.get("class_type"), label=f"{label}.{node_id}.class_type"
        )
        by_class.setdefault(class_type, []).append(str(node_id))

    common_classes = {
        "CLIPLoader",
        "CFGNorm",
        "FluxKontextImageScale",
        "FluxKontextMultiReferenceLatentMethod",
        "KSampler",
        "LoadImage",
        "ModelSamplingAuraFlow",
        "SaveImage",
        "TextEncodeQwenImageEditPlus",
        "UNETLoader",
        "VAEDecode",
        "VAELoader",
    }
    expected_classes = (
        common_classes | {"EmptyLatentImage"}
        if operation == "generate"
        else common_classes | {"ImageScale", "VAEEncode"}
    )
    if set(by_class) != expected_classes:
        fail(f"node classes do not match the approved {operation} profile")

    def exactly_one(class_type: str) -> str:
        nodes = by_class.get(class_type, [])
        if len(nodes) != 1:
            fail(f"requires exactly one {class_type} node")
        return nodes[0]

    def exactly_two(class_type: str) -> tuple[str, str]:
        nodes = by_class.get(class_type, [])
        if len(nodes) != 2:
            fail(f"requires exactly two {class_type} nodes")
        return nodes[0], nodes[1]

    source = exactly_one("LoadImage")
    source_inputs = inputs_for(source, {"image"}, "source image")
    image_value = source_inputs["image"]
    if require_artifact_placeholder:
        if image_value != "$artifact:0":
            fail("does not bind LoadImage.image to $artifact:0")
    elif (
        not isinstance(image_value, str)
        or not image_value
        or image_value in {".", ".."}
        or "/" in image_value
        or "\\" in image_value
        or "\x00" in image_value
        or _REMOTE_URL.search(image_value)
    ):
        fail("does not use a private run-scoped image filename")
    if source_node_id is not None and source != source_node_id:
        fail("uses a different image node than its approved template")

    scaled = exactly_one("FluxKontextImageScale")
    if linked(scaled, "image", "FluxKontext image scale") != source:
        fail("does not scale the approved image input")

    unet = exactly_one("UNETLoader")
    unet_inputs = inputs_for(
        unet, {"unet_name", "weight_dtype"}, "UNET loader"
    )
    if unet_inputs["weight_dtype"] != "default":
        fail("uses an unsupported UNET weight type")
    clip = exactly_one("CLIPLoader")
    clip_inputs = inputs_for(clip, {"clip_name", "type"}, "CLIP loader")
    if clip_inputs["type"] != "qwen_image":
        fail("does not use the Qwen image text encoder contract")
    vae = exactly_one("VAELoader")
    inputs_for(vae, {"vae_name"}, "VAE loader")

    sampling_model = exactly_one("ModelSamplingAuraFlow")
    inputs_for(sampling_model, {"model", "shift"}, "model sampling")
    if linked(sampling_model, "model", "model sampling") != unet:
        fail("model sampling does not consume the pinned UNET loader")
    cfg_norm = exactly_one("CFGNorm")
    if linked(cfg_norm, "model", "CFG normalization") != sampling_model:
        fail("CFG normalization does not follow model sampling")
    cfg_inputs = inputs_for(
        cfg_norm, {"model", "pre_cfg", "strength"}, "CFG normalization"
    )
    if cfg_inputs["strength"] != 1.0 or isinstance(cfg_inputs["strength"], bool):
        fail("CFG normalization strength differs the approved value")
    if cfg_inputs["pre_cfg"] is not False:
        fail("CFG normalization must run after CFG")

    sampler = exactly_one("KSampler")
    sampler_inputs = inputs_for(
        sampler,
        {
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
        },
        "sampler",
    )
    if linked(sampler, "model", "sampler model") != cfg_norm:
        fail("sampler does not consume the approved base model branch")
    if (
        sampler_inputs["sampler_name"] != "euler"
        or sampler_inputs["scheduler"] != "simple"
    ):
        fail("sampler identity differs the approved Qwen profile")
    if sampler_inputs["denoise"] != 1.0 or isinstance(
        sampler_inputs["denoise"], bool
    ):
        fail("sampler denoise differs the approved Qwen profile")

    reference_methods = exactly_two("FluxKontextMultiReferenceLatentMethod")
    qwen_encoders = set(exactly_two("TextEncodeQwenImageEditPlus"))
    positive_method = linked(sampler, "positive", "positive conditioning")
    negative_method = linked(sampler, "negative", "negative conditioning")
    if positive_method == negative_method:
        fail("positive and negative conditioning reuse one reference-latent branch")
    if {positive_method, negative_method} != set(reference_methods):
        fail("sampler conditioning does not use both approved reference-latent branches")

    def encoder_for(method_id: str, expected_prompt_value: object) -> str:
        method_inputs = inputs_for(
            method_id,
            {"conditioning", "reference_latents_method"},
            "reference-latent method",
        )
        if method_inputs["reference_latents_method"] != "index_timestep_zero":
            fail("reference-latent method differs index_timestep_zero")
        encoder = linked(method_id, "conditioning", "reference-latent conditioning")
        encoder_node = _mapping(graph.get(encoder), label=f"{label}.{encoder}")
        if encoder_node.get("class_type") != "TextEncodeQwenImageEditPlus":
            fail("reference-latent method does not consume TextEncodeQwenImageEditPlus")
        encoder_inputs = inputs_for(
            encoder,
            {"clip", "image1", "prompt", "vae"},
            "Qwen image conditioning",
        )
        if linked(encoder, "clip", "Qwen conditioning CLIP") != clip:
            fail("Qwen conditioning does not use the approved text encoder")
        if linked(encoder, "vae", "Qwen conditioning VAE") != vae:
            fail("Qwen conditioning does not use the approved VAE")
        if linked(encoder, "image1", "Qwen conditioning image") != scaled:
            fail("Qwen conditioning does not use the approved scaled image")
        if encoder_inputs["prompt"] != expected_prompt_value:
            fail("Qwen conditioning prompt differs the approved profile")
        return encoder

    positive_encoder = encoder_for(positive_method, expected_prompt)
    negative_encoder = encoder_for(negative_method, "")
    if {positive_encoder, negative_encoder} != qwen_encoders:
        fail("sampler conditioning does not use both approved Qwen encoder branches")

    decoder = exactly_one("VAEDecode")
    inputs_for(decoder, {"samples", "vae"}, "VAE decode")
    if linked(decoder, "samples", "VAE decode samples") != sampler:
        fail("VAE decode does not consume sampler output")
    if linked(decoder, "vae", "VAE decode VAE") != vae:
        fail("VAE decode does not use the conditioning VAE")

    output = exactly_one("SaveImage")
    if output != output_node_id:
        fail("does not use the declared SaveImage output")
    inputs_for(output, {"filename_prefix", "images"}, "SaveImage output")
    output_source = linked(output, "images", "SaveImage image output")

    if operation == "generate":
        latent = exactly_one("EmptyLatentImage")
        latent_inputs = inputs_for(
            latent, {"batch_size", "height", "width"}, "generate latent"
        )
        if (
            latent_inputs["width"] != expected_width
            or latent_inputs["height"] != expected_height
        ):
            fail("generate latent dimensions differ the approved dimensions")
        if latent_inputs["batch_size"] != 1 or isinstance(
            latent_inputs["batch_size"], bool
        ):
            fail("generate latent batch size differs the approved value")
        if linked(sampler, "latent_image", "generate latent") != latent:
            fail("sampler does not consume the approved generate latent")
        if output_source != decoder:
            fail("generate output does not come directly from VAE decode")
    else:
        encoder = exactly_one("VAEEncode")
        inputs_for(encoder, {"pixels", "vae"}, "source latent")
        if linked(encoder, "pixels", "source latent pixels") != scaled:
            fail("source latent does not use the scaled source image")
        if linked(encoder, "vae", "source latent VAE") != vae:
            fail("source latent does not use the conditioning VAE")
        if linked(sampler, "latent_image", "source latent") != encoder:
            fail("sampler does not consume the approved source latent")
        output_scale = exactly_one("ImageScale")
        scale_inputs = inputs_for(
            output_scale,
            {"crop", "height", "image", "upscale_method", "width"},
            "post-decode output scale",
        )
        if (
            scale_inputs["width"] != expected_width
            or scale_inputs["height"] != expected_height
        ):
            fail("post-decode output dimensions differ the approved dimensions")
        if (
            scale_inputs["upscale_method"] != "lanczos"
            or scale_inputs["crop"] != "center"
        ):
            fail("post-decode sizing differs the approved image scale")
        if linked(output_scale, "image", "post-decode scale") != decoder:
            fail("post-decode sizing does not consume the decoder output")
        if output_source != output_scale:
            fail("SaveImage does not consume the post-decode sized image")

    return source


_COMFYUI_GRAPH_LINK_FIELDS = {
    "consumer",
    "consumer_class",
    "input",
    "source",
    "source_class",
    "output",
}


def _comfyui_graph_links(
    graph: Mapping[str, object],
    *,
    pins: Mapping[str, object],
    label: str,
) -> list[dict[str, object]]:
    """Validate one graph's structure and return its canonical link topology."""
    node_classes: dict[str, str] = {}
    node_inputs: dict[str, Mapping[str, object]] = {}
    for node_id, raw_node in graph.items():
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            raise BackendEvidenceError(f"{label} invalid node ID")
        node = _mapping(raw_node, label=f"{label}.{node_id}")
        _exact_keys(node, {"class_type", "inputs"}, label=f"{label}.{node_id}")
        class_type = _string(node["class_type"], label=f"{label}.{node_id}.class_type")
        if class_type not in pins or _NODE_ID.fullmatch(class_type) is None:
            raise BackendEvidenceError(f"{label}.{node_id}.class_type not permitted")
        pin = _mapping(pins[class_type], label=f"effective nodes.{class_type}")
        if pin.get("class") != class_type:
            raise BackendEvidenceError(
                f"{label}.{node_id}.class_type does not match its node pin"
            )
        allowed_inputs = pin.get("inputs")
        if (
            not isinstance(allowed_inputs, list)
            or not allowed_inputs
            or any(
                not isinstance(name, str) or not name or _SECRET_KEY.search(name)
                for name in allowed_inputs
            )
            or len(allowed_inputs) != len(set(allowed_inputs))
        ):
            raise BackendEvidenceError("effective node input pins are malformed")
        inputs = _mapping(node["inputs"], label=f"{label}.{node_id}.inputs")
        if not set(inputs) <= set(allowed_inputs):
            raise BackendEvidenceError(f"{label}.{node_id}.inputs has an unsupported shape")
        if any(
            not isinstance(name, str) or not name or _SECRET_KEY.search(name)
            for name in inputs
        ):
            raise BackendEvidenceError(f"{label}.{node_id} has a prohibited input name")
        node_classes[node_id] = class_type
        node_inputs[node_id] = inputs

    links: list[dict[str, object]] = []
    for node_id in sorted(node_inputs):
        for input_name in sorted(node_inputs[node_id]):
            value = node_inputs[node_id][input_name]
            if not isinstance(value, list):
                continue
            if (
                len(value) != 2
                or not isinstance(value[0], str)
                or value[0] not in node_classes
                or isinstance(value[1], bool)
                or not isinstance(value[1], int)
                or value[1] < 0
            ):
                raise BackendEvidenceError(
                    f"{label}.{node_id}.inputs.{input_name} is not a valid node link"
                )
            links.append(
                {
                    "consumer": node_id,
                    "consumer_class": node_classes[node_id],
                    "input": input_name,
                    "source": value[0],
                    "source_class": node_classes[value[0]],
                    "output": value[1],
                }
            )
    return links


def _validate_effective_graph(
    graph: object,
    *,
    pins: Mapping[str, object],
    record: Mapping[str, object],
    configuration: Mapping[str, object],
    expected_workflow_approval: object | None = None,
) -> dict[str, tuple[str, Mapping[str, object]]]:
    """Validate the exact approved graph and all model-facing values."""
    nodes = _mapping(graph, label="effective_execution.graph")
    if not nodes or len(nodes) > MAX_EVIDENCE_NODES:
        raise BackendEvidenceError(
            "effective_execution.graph must contain a bounded non-empty node map"
        )
    node_by_id: dict[str, Mapping[str, object]] = {}
    class_nodes: dict[str, list[tuple[str, Mapping[str, object]]]] = {}
    input_values: dict[str, list[object]] = {}
    for node_id, raw_node in nodes.items():
        if not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id):
            raise BackendEvidenceError("effective_execution.graph has an invalid node ID")
        node = _mapping(raw_node, label=f"effective_execution.graph.{node_id}")
        _exact_keys(
            node,
            {"class_type", "inputs"},
            label=f"effective_execution.graph.{node_id}",
        )
        class_type = _string(
            node["class_type"],
            label=f"effective_execution.graph.{node_id}.class_type",
        )
        if class_type not in pins or _NODE_ID.fullmatch(class_type) is None:
            raise BackendEvidenceError(
                f"effective_execution.graph.{node_id}.class_type is not permitted"
            )
        pin = _mapping(
            pins[class_type],
            label=f"effective_execution.configuration.nodes.{class_type}",
        )
        if pin.get("class") != class_type:
            raise BackendEvidenceError(
                f"effective_execution.graph.{node_id}.class_type does not match its node pin"
            )
        allowed_inputs = pin.get("inputs")
        if (
            not isinstance(allowed_inputs, list)
            or not allowed_inputs
            or any(
                not isinstance(name, str) or not name or _SECRET_KEY.search(name)
                for name in allowed_inputs
            )
            or len(allowed_inputs) != len(set(allowed_inputs))
        ):
            raise BackendEvidenceError("effective_execution node input pins are malformed")
        inputs = _mapping(
            node["inputs"], label=f"effective_execution.graph.{node_id}.inputs"
        )
        if not set(inputs) <= set(allowed_inputs):
            raise BackendEvidenceError(
                f"effective_execution.graph.{node_id}.inputs has an unsupported shape"
            )
        for input_name, input_value in inputs.items():
            if (
                not isinstance(input_name, str)
                or not input_name
                or _SECRET_KEY.search(input_name)
            ):
                raise BackendEvidenceError(
                    f"effective_execution.graph.{node_id} has a prohibited input name"
                )
            _validate_comfyui_private_value(
                input_value,
                label=f"effective_execution.graph.{node_id}.inputs.{input_name}",
            )
            if isinstance(input_value, list):
                if (
                    len(input_value) != 2
                    or not isinstance(input_value[0], str)
                    or input_value[0] not in nodes
                    or isinstance(input_value[1], bool)
                    or not isinstance(input_value[1], int)
                    or input_value[1] < 0
                ):
                    raise BackendEvidenceError(
                        f"effective_execution.graph.{node_id}.inputs.{input_name} "
                        "is not a valid node link"
                    )
            else:
                input_values.setdefault(input_name, []).append(input_value)
        node_by_id[node_id] = inputs
        class_nodes.setdefault(class_type, []).append((node_id, inputs))

    if set(class_nodes) != set(pins):
        raise BackendEvidenceError(
            "effective_execution graph does not use every independently pinned node class"
        )

    workflow = _mapping(
        configuration["workflow"], label="effective_execution.configuration.workflow"
    )
    profile_version: int | None = None
    workflow_keys = {
        "id",
        "document_sha256",
        "operation",
        "template_sha256",
        "template",
        "approval",
        "links",
        "limits",
    }
    if "profile_version" in workflow:
        profile_version = _integer(
            workflow["profile_version"],
            label="effective workflow profile version",
            minimum=2,
        )
        if profile_version != 2:
            raise BackendEvidenceError("effective workflow profile version is unsupported")
        workflow_keys.update(
            {"profile_version", "sampling_resolution", "output_dimensions"}
        )
    _exact_keys(
        workflow,
        workflow_keys,
        label="effective_execution.configuration.workflow",
    )
    if (
        workflow["id"] != record["recipe"]["id"]
        or workflow["document_sha256"] != record["recipe"]["document_sha256"]
        or workflow["operation"] not in {"generate", "edit"}
    ):
        raise BackendEvidenceError("effective workflow differs from resolved recipe")
    approval = _validate_workflow_approval(
        workflow["approval"], label="effective workflow approval"
    )
    if expected_workflow_approval is not None:
        expected_approval = _validate_workflow_approval(
            expected_workflow_approval,
            label="persisted adapter workflow approval",
        )
        if dict(approval) != dict(expected_approval):
            raise BackendEvidenceError(
                "resolved workflow approval differs from persisted adapter approval"
            )
    approval_document = _mapping(
        approval["document"], label="effective workflow approval document"
    )
    if (
        approval["component_id"] != workflow["id"]
        or approval["component_sha256"] != workflow["document_sha256"]
        or approval_document["tool_id"] != record["engine"]["id"]
        or approval_document["tool_version"] != record["engine"]["version"]
    ):
        raise BackendEvidenceError(
            "effective workflow approval is not bound to its approved component and engine"
        )
    template_sha256 = _sha256(
        workflow["template_sha256"], label="effective workflow template digest"
    )
    approved_operations = _mapping(
        approval_document["operations"],
        label="effective workflow approval operations",
    )
    approved_operation = _mapping(
        approved_operations[workflow["operation"]],
        label=f"effective workflow approval operations.{workflow['operation']}",
    )
    if approved_operation["graph_sha256"] != template_sha256:
        raise BackendEvidenceError(
            "effective workflow template digest differs from independent workflow approval"
        )
    template = _mapping(workflow["template"], label="effective workflow template")
    if not template or len(template) > MAX_EVIDENCE_NODES:
        raise BackendEvidenceError(
            "effective workflow template must contain a bounded non-empty node map"
        )
    if digest(template) != template_sha256:
        raise BackendEvidenceError(
            "effective workflow template bytes do not match independent workflow approval"
        )
    template_classes = {
        _string(
            _mapping(node, label=f"effective workflow template.{node_id}")["class_type"],
            label=f"effective workflow template.{node_id}.class_type",
        )
        for node_id, node in template.items()
    }
    approved_nodes = _mapping(
        approved_operation["nodes"], label="effective workflow approved node pins"
    )
    if set(approved_nodes) != template_classes:
        raise BackendEvidenceError(
            "effective workflow node classes differ from independent workflow approval"
        )
    for class_name, approved_pin_value in approved_nodes.items():
        approved_pin = _mapping(
            approved_pin_value,
            label=f"effective workflow approved node pins.{class_name}",
        )
        effective_pin = _mapping(
            pins.get(class_name), label=f"effective node pins.{class_name}"
        )
        if (
            effective_pin.get("component_id") != approved_pin["component_id"]
            or effective_pin.get("sha256") != approved_pin["sha256"]
        ):
            raise BackendEvidenceError(
                "effective node pin differs from independent workflow approval"
            )
    expected_links = _comfyui_graph_links(
        template,
        pins=pins,
        label="effective workflow template graph",
    )
    persisted_links = workflow["links"]
    if not isinstance(persisted_links, list) or len(persisted_links) > MAX_EVIDENCE_COLLECTION_ITEMS:
        raise BackendEvidenceError("effective workflow link topology must be a bounded list")
    for index, raw_link in enumerate(persisted_links):
        link = _mapping(raw_link, label=f"effective workflow links[{index}]")
        _exact_keys(
            link,
            _COMFYUI_GRAPH_LINK_FIELDS,
            label=f"effective workflow links[{index}]",
        )
        for field in ("consumer", "consumer_class", "input", "source", "source_class"):
            _string(link[field], label=f"effective workflow links[{index}].{field}")
        _integer(link["output"], label=f"effective workflow links[{index}].output")
    if persisted_links != expected_links:
        raise BackendEvidenceError(
            "effective workflow link topology differs from its approved template"
        )
    _validate_graph_against_template(
        nodes,
        template,
        expected_links=expected_links,
        label="effective_execution.graph",
    )
    operation = workflow["operation"]
    limits = _mapping(workflow["limits"], label="effective workflow limits")
    max_width = _integer(limits["max_width"], label="effective workflow maximum width")
    max_height = _integer(
        limits["max_height"], label="effective workflow maximum height"
    )
    width = _comfyui_dimension(record["width"], label="resolved.width")
    height = _comfyui_dimension(record["height"], label="resolved.height")
    if width > max_width:
        raise BackendEvidenceError("effective resolution exceeds the maximum dimension")
    if height > max_height:
        raise BackendEvidenceError("effective resolution exceeds the maximum dimension")

    if profile_version == 2:
        sampling_resolution = _mapping(
            workflow["sampling_resolution"],
            label="effective workflow sampling resolution",
        )
        _exact_keys(
            sampling_resolution,
            {"mode", "width", "height"},
            label="effective workflow sampling resolution",
        )
        expected_sampling = (
            {
                "mode": "requested-empty-latent",
                "width": width,
                "height": height,
            }
            if operation == "generate"
            else {"mode": "flux-kontext-image-scale", "width": None, "height": None}
        )
        if dict(sampling_resolution) != expected_sampling:
            raise BackendEvidenceError(
                "effective workflow sampling resolution differs the Qwen profile"
            )
        output_dimensions = _mapping(
            workflow["output_dimensions"],
            label="effective workflow output dimensions",
        )
        _exact_keys(
            output_dimensions,
            {"mode", "width", "height"},
            label="effective workflow output dimensions",
        )
        expected_output = {
            "mode": (
                "post-decode-image-scale"
                if operation == "edit"
                else "decoder-native"
            ),
            "width": width,
            "height": height,
        }
        if dict(output_dimensions) != expected_output:
            raise BackendEvidenceError(
                "effective workflow output dimensions differ the Qwen profile"
            )
    model_facing = _mapping(
        configuration["model_facing"],
        label="effective_execution.configuration.model_facing",
    )
    if model_facing != {
        "prompt": record["prompt"],
        "seed": record["seed"],
        "width": record["width"],
        "height": record["height"],
        "sampling": record["sampling"],
        "adapters": record["adapters"],
        "conditioning": record["conditioning"],
    }:
        raise BackendEvidenceError(
            "effective model-facing configuration differs from resolved request"
        )

    raw_model_files = configuration["model_files"]
    if not isinstance(raw_model_files, list):
        raise BackendEvidenceError("effective_execution model_files must be a list")
    model_files: dict[str, Mapping[str, object]] = {}
    for index, raw_file in enumerate(raw_model_files):
        label = f"effective_execution.configuration.model_files[{index}]"
        model_file = _mapping(raw_file, label=label)
        _exact_keys(
            model_file,
            {"component_id", "role", "path", "resolved_path", "search_path", "sha256"},
            label=label,
        )
        role = _string(model_file["role"], label=f"{label}.role")
        if role in model_files:
            raise BackendEvidenceError("effective_execution has duplicate model-file roles")
        _string(model_file["component_id"], label=f"{label}.component_id")
        path = _string(model_file["path"], label=f"{label}.path")
        relative = PurePosixPath(path)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise BackendEvidenceError("effective_execution model path is not a safe relative path")
        _sha256(model_file["sha256"], label=f"{label}.sha256")
        resolved_path = _string(model_file["resolved_path"], label=f"{label}.resolved_path")
        search_path = _string(model_file["search_path"], label=f"{label}.search_path")
        category = _COMFYUI_MODEL_DIRECTORIES.get(role)
        if (
            category is None
            or not os.path.isabs(resolved_path)
            or not os.path.isabs(search_path)
            or os.path.basename(os.path.normpath(resolved_path))
            != os.path.basename(os.path.normpath(search_path))
            or os.path.dirname(os.path.normpath(search_path))
            != os.path.join(
                os.path.normpath(
                    _string(
                        _mapping(
                            configuration["server"],
                            label="effective_execution.configuration.server",
                        )["base_directory"],
                        label="effective server base directory",
                    )
                ),
                "models",
                category,
            )
        ):
            raise BackendEvidenceError(
                "effective model search path is not bound inside the run-scoped base"
            )
        model_files[role] = model_file

    raw_resolved_components = record["components"]
    if not isinstance(raw_resolved_components, list):
        raise BackendEvidenceError("resolved.components must be a list")
    resolved_components = {
        item["role"]: item
        for item in raw_resolved_components
        if isinstance(item, Mapping)
    }
    expected_model_roles = set(resolved_components) - {"other"}
    if set(model_files) != expected_model_roles:
        raise BackendEvidenceError(
            "effective model-file identities differ from resolved components"
        )
    for role, model_file in model_files.items():
        component = resolved_components[role]
        if (
            model_file["component_id"] != component["id"]
            or model_file["sha256"] != component["sha256"]
        ):
            raise BackendEvidenceError(
                "effective model file does not match its resolved component"
            )
    selected_model_files: set[tuple[str, str]] = set()
    for node_id, raw_node in nodes.items():
        node = _mapping(raw_node, label=f"effective_execution.graph.{node_id}")
        class_type = _string(
            node["class_type"], label=f"effective_execution.graph.{node_id}.class_type"
        )
        inputs = _mapping(
            node["inputs"], label=f"effective_execution.graph.{node_id}.inputs"
        )
        for input_name, raw_value in inputs.items():
            if input_name not in _COMFYUI_MODEL_SELECTOR_INPUTS:
                continue
            roles = _COMFYUI_MODEL_SELECTOR_ROLES.get((class_type, input_name))
            if roles is None:
                raise BackendEvidenceError(
                    "effective graph model selector role is not approved for its node class"
                )
            value = _string(
                raw_value,
                label=f"effective_execution.graph.{node_id}.inputs.{input_name}",
            )
            matches = [
                model_file
                for model_role, model_file in model_files.items()
                if model_role in roles
                and os.path.basename(
                    os.path.normpath(str(model_file["search_path"]))
                )
                == value
            ]
            if len(matches) != 1:
                raise BackendEvidenceError(
                    "effective graph model selector is unbound or ambiguous"
                )
            selected_model_files.add((str(matches[0]["role"]), str(value)))
    for role, model_file in model_files.items():
        search_name = os.path.basename(
            os.path.normpath(str(model_file["search_path"]))
        )
        if (role, search_name) not in selected_model_files:
            raise BackendEvidenceError(
                "effective graph does not select each resolved model artifact"
            )

    prompt = record["prompt"]
    if prompt not in (
        input_values.get("text", []) + input_values.get("prompt", [])
    ):
        raise BackendEvidenceError(
            "effective_execution prompt differs from resolved prompt"
        )

    seed_values = input_values.get("seed", [])
    step_values = input_values.get("steps", [])
    cfg_values = input_values.get("cfg", [])
    shift_values = input_values.get("shift", [])
    if not seed_values or any(
        type(value) is not type(record["seed"]) or value != record["seed"]
        for value in seed_values
    ):
        raise BackendEvidenceError(
            "effective sampler seed differs from model-facing configuration or has an inexact JSON type"
        )
    if not step_values or any(
        type(value) is not type(record["sampling"]["steps"])
        or value != record["sampling"]["steps"]
        for value in step_values
    ):
        raise BackendEvidenceError(
            "effective sampler steps differ from model-facing configuration or have an inexact JSON type"
        )
    if not cfg_values or any(
        type(value) is not type(record["sampling"]["cfg_scale"])
        or value != record["sampling"]["cfg_scale"]
        for value in cfg_values
    ):
        raise BackendEvidenceError(
            "effective sampler cfg differs from model-facing configuration or has an inexact JSON type"
        )
    if not shift_values or any(
        type(value) is not type(record["sampling"]["flow_shift"])
        or value != record["sampling"]["flow_shift"]
        for value in shift_values
    ):
        raise BackendEvidenceError(
            "effective sampler shift differs from model-facing configuration or has an inexact JSON type"
        )

    width_values = input_values.get("width", [])
    height_values = input_values.get("height", [])
    if (
        not width_values
        or not height_values
        or any(
            _comfyui_dimension(value, label="effective graph width") != width
            for value in width_values
        )
        or any(
            _comfyui_dimension(value, label="effective graph height") != height
            for value in height_values
        )
    ):
        raise BackendEvidenceError(
            "effective_execution dimensions differ from the resolved request"
        )

    if operation not in {"generate", "edit"}:
        raise BackendEvidenceError("effective_execution workflow operation is unsupported")
    conditioning = record["conditioning"]
    if not isinstance(conditioning, list):
        raise BackendEvidenceError("resolved.conditioning must be a list")
    if profile_version == 2:
        expected_role = "source" if operation == "edit" else "reference"
        images = [
            item
            for item in conditioning
            if isinstance(item, Mapping) and item.get("role") == expected_role
        ]
        if len(conditioning) != 1 or len(images) != 1:
            raise BackendEvidenceError(
                f"effective Qwen {operation} graph requires exactly one {expected_role} image"
            )
        image = images[0]
    elif operation == "edit":
        sources = [
            item
            for item in conditioning
            if isinstance(item, Mapping) and item.get("role") == "source"
        ]
        if len(conditioning) != 1 or len(sources) != 1:
            raise BackendEvidenceError(
                "effective edit graph requires exactly one source image"
            )
        image = sources[0]
    elif conditioning:
        raise BackendEvidenceError("generate graph cannot contain image conditioning")
    else:
        image = None
    if image is not None:
        expected_filename = f"mg-{str(image['content_sha256'])[:24]}.png"
        image_values: list[object] = []
        for name in ("image", "image1", "image2", "image3"):
            image_values.extend(input_values.get(name, []))
        if expected_filename not in image_values:
            raise BackendEvidenceError(
                "effective graph does not bind its conditioning image"
            )

    output = _mapping(
        configuration["output"], label="effective_execution.configuration.output"
    )
    _exact_keys(
        output,
        {"node_id", "field"},
        label="effective_execution.configuration.output",
    )
    output_node = _string(output["node_id"], label="effective output node ID")
    output_field = _string(output["field"], label="effective output field")
    if output_node not in node_by_id:
        raise BackendEvidenceError("effective output node does not exist")
    output_value = node_by_id[output_node].get(output_field)
    if not isinstance(output_value, list) or len(output_value) != 2:
        raise BackendEvidenceError("effective output identity does not match the graph")
    if (
        not isinstance(output_value[0], str)
        or output_value[0] not in nodes
        or output_field != "images"
    ):
        raise BackendEvidenceError("effective output identity does not match the graph")
    return {
        class_type: class_nodes[class_type][0]
        for class_type in class_nodes
    }

def _require_graph_link(
    value: object,
    *,
    expected: Mapping[str, object],
    actual_source_class: str,
    label: str,
) -> None:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or value != [expected["source"], expected["output"]]
        or isinstance(value[1], bool)
        or actual_source_class != expected["source_class"]
    ):
        raise BackendEvidenceError(
            f"effective_execution {label} link topology differs from approved template"
        )


def _validate_graph_against_template(
    graph: Mapping[str, object],
    template: Mapping[str, object],
    *,
    expected_links: Sequence[Mapping[str, object]],
    label: str,
) -> None:
    """Require substituted graph structure, constants, and links match the pin."""
    if set(graph) != set(template):
        raise BackendEvidenceError(
            f"{label} link topology differs from approved template node identity"
        )
    links_by_input = {
        (str(link["consumer"]), str(link["input"])): link for link in expected_links
    }
    for node_id in sorted(template):
        actual_node = _mapping(graph[node_id], label=f"{label}.{node_id}")
        template_node = _mapping(template[node_id], label=f"workflow template.{node_id}")
        _exact_keys(actual_node, {"class_type", "inputs"}, label=f"{label}.{node_id}")
        _exact_keys(
            template_node,
            {"class_type", "inputs"},
            label=f"workflow template.{node_id}",
        )
        if actual_node["class_type"] != template_node["class_type"]:
            raise BackendEvidenceError(
                f"{label} link topology differs from approved template class"
            )
        actual_inputs = _mapping(actual_node["inputs"], label=f"{label}.{node_id}.inputs")
        template_inputs = _mapping(
            template_node["inputs"],
            label=f"workflow template.{node_id}.inputs",
        )
        if set(actual_inputs) != set(template_inputs):
            raise BackendEvidenceError(
                f"{label} link topology differs from approved template inputs"
            )
        for input_name, template_value in template_inputs.items():
            actual_value = actual_inputs[input_name]
            if not (
                isinstance(template_value, str) and template_value.startswith("$")
            ) and type(actual_value) is not type(template_value):
                raise BackendEvidenceError(
                    f"{label} {node_id}.inputs.{input_name} has an inexact JSON type"
                )
            if isinstance(template_value, list):
                link = links_by_input.get((node_id, str(input_name)))
                if link is None:
                    raise BackendEvidenceError(
                        f"{label} link topology lacks approved template edge"
                    )
                source_class = str(
                    _mapping(
                        template[str(link["source"])],
                        label=f"workflow template.{link['source']}",
                    )["class_type"]
                )
                _require_graph_link(
                    actual_value,
                    expected=link,
                    actual_source_class=source_class,
                    label=f"{node_id}.inputs.{input_name}",
                )
            elif not (
                isinstance(template_value, str)
                and template_value.startswith("$")
            ) and actual_value != template_value:
                raise BackendEvidenceError(
                    f"{label} {node_id}.inputs.{input_name} differs from approved template"
                )


def _validate_comfyui_private_value(value: object, *, label: str) -> None:
    """Reject credentials and network-bearing strings throughout v3 evidence."""
    if isinstance(value, str):
        if _REMOTE_URL.search(value) or _DATA_URL.search(value):
            raise BackendEvidenceError(f"{label} contains a remote or data URI")
        if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
            raise BackendEvidenceError(f"{label} contains credential-like material")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or _SECRET_KEY.search(key):
                raise BackendEvidenceError(f"{label} contains a credential-like field")
            _validate_comfyui_private_value(child, label=f"{label}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_comfyui_private_value(child, label=f"{label}[{index}]")


def _validate_effective_execution(
    payload: object,
    *,
    record: Mapping[str, object],
    expected_workflow_approval: object | None = None,
) -> None:
    """Validate the complete ComfyUI payload and effective launch binding.

    Effective schema v2 binds the recorded argv and full safe environment to
    the server endpoint, run directories, frontend, engine executable, and
    runtime fingerprint. This stricter nested version applies only to resolved
    ComfyUI v3 records; the historical resolved-record v2 validator is unchanged.
    """
    effective = _mapping(payload, label="resolved.effective_execution")
    _exact_keys(
        effective,
        {
            "schema",
            "schema_version",
            "api_format",
            "prompt_id",
            "client_id",
            "request_body",
            "request_body_sha256",
            "graph",
            "graph_sha256",
            "configuration",
            "configuration_sha256",
        },
        label="resolved.effective_execution",
    )
    if (
        effective["schema"] != EFFECTIVE_EXECUTION_SCHEMA
        or type(effective["schema_version"]) is not int
        or effective["schema_version"] != EFFECTIVE_EXECUTION_SCHEMA_VERSION
    ):
        raise BackendEvidenceError("resolved.effective_execution has an unsupported schema")
    if effective["api_format"] != "comfyui-api-prompt/v1":
        raise BackendEvidenceError("resolved.effective_execution has an unsupported API format")
    prompt_id = _string(effective["prompt_id"], label="resolved.effective_execution.prompt_id")
    if not _UUID.fullmatch(prompt_id):
        raise BackendEvidenceError(
            "resolved.effective_execution.prompt_id must be a canonical UUID"
        )
    attempt_id = _string(record["attempt_id"], label="resolved.attempt_id")
    if effective["client_id"] != attempt_id:
        raise BackendEvidenceError(
            "resolved.effective_execution.client_id must bind the attempt"
        )

    configuration = _mapping(
        effective["configuration"],
        label="resolved.effective_execution.configuration",
    )
    _exact_keys(
        configuration,
        {
            "engine",
            "workflow",
            "server",
            "nodes",
            "components",
            "model_files",
            "model_facing",
            "api",
            "output",
        },
        label="resolved.effective_execution.configuration",
    )
    nodes = _mapping(
        configuration["nodes"],
        label="resolved.effective_execution.configuration.nodes",
    )
    if not nodes:
        raise BackendEvidenceError(
            "resolved.effective_execution.configuration.nodes must not be empty"
        )
    node_components = {
        component["id"]: component["sha256"]
        for component in record["components"]
        if component["role"] == "other"
    }
    if not node_components:
        raise BackendEvidenceError("resolved node implementation component is missing")
    for class_type, raw_pin in nodes.items():
        class_name = _string(
            class_type, label="resolved.effective_execution.configuration.nodes key"
        )
        if _NODE_ID.fullmatch(class_name) is None:
            raise BackendEvidenceError("effective node class name is malformed")
        pin = _mapping(
            raw_pin,
            label=f"resolved.effective_execution.configuration.nodes.{class_type}",
        )
        _exact_keys(
            pin,
            {"class", "component_id", "sha256", "inputs"},
            label=f"resolved.effective_execution.configuration.nodes.{class_type}",
        )
        pin_class = _string(
            pin["class"],
            label=f"resolved.effective_execution.configuration.nodes.{class_type}.class",
        )
        if pin_class != class_name:
            raise BackendEvidenceError(
                "effective node pin class does not match its graph class key"
            )
        component_id = _string(
            pin["component_id"],
            label=f"resolved.effective_execution.configuration.nodes.{class_type}.component_id",
        )
        node_sha = _sha256(
            pin["sha256"],
            label=f"resolved.effective_execution.configuration.nodes.{class_type}.sha256",
        )
        raw_inputs = pin["inputs"]
        if (
            node_components.get(component_id) != node_sha
            or not isinstance(raw_inputs, list)
            or not raw_inputs
            or any(
                not isinstance(name, str)
                or not name
                or _SECRET_KEY.search(name)
                for name in raw_inputs
            )
            or len(raw_inputs) != len(set(raw_inputs))
        ):
            raise BackendEvidenceError(
                "effective node pin is not bound to the resolved trusted node artifact and inputs"
            )

    engine = _mapping(
        configuration["engine"], label="resolved.effective_execution.configuration.engine"
    )
    _exact_keys(
        engine,
        {
            "id",
            "version",
            "build",
            "executable_sha256",
            "executable_path",
            "runtime_fingerprint_sha256",
        },
        label="resolved.effective_execution.configuration.engine",
    )
    engine_identity = {
        key: engine[key]
        for key in ("id", "version", "build", "executable_sha256")
    }
    if engine_identity != record["engine"]:
        raise BackendEvidenceError("effective engine differs from resolved engine")
    executable_path = _string(
        engine["executable_path"],
        label="resolved.effective_execution.configuration.engine.executable_path",
    )
    if (
        not os.path.isabs(executable_path)
        or _REMOTE_URL.search(executable_path)
        or "\x00" in executable_path
        or ".." in executable_path.replace("\\", "/").split("/")
    ):
        raise BackendEvidenceError("effective engine executable path is not a local absolute path")
    if engine["runtime_fingerprint_sha256"] != digest(record["runtime"]):
        raise BackendEvidenceError("effective engine runtime identity differs from resolved runtime")

    workflow = _mapping(
        configuration["workflow"], label="resolved.effective_execution.configuration.workflow"
    )
    workflow_keys = {
        "id",
        "document_sha256",
        "operation",
        "template_sha256",
        "template",
        "approval",
        "links",
        "limits",
    }
    if "profile_version" in workflow:
        workflow_keys.update(
            {"profile_version", "sampling_resolution", "output_dimensions"}
        )
    _exact_keys(
        workflow,
        workflow_keys,
        label="resolved.effective_execution.configuration.workflow",
    )
    workflow_operation = _string(
        workflow["operation"], label="effective workflow operation"
    )
    if (
        workflow["id"] != record["recipe"]["id"]
        or workflow["document_sha256"] != record["recipe"]["document_sha256"]
        or workflow_operation not in {"generate", "edit"}
    ):
        raise BackendEvidenceError("effective workflow differs from resolved recipe")
    limits = _mapping(workflow["limits"], label="effective workflow limits")
    _exact_keys(
        limits,
        {
            "min_width",
            "min_height",
            "max_width",
            "max_height",
            "dimension_multiple",
        },
        label="effective workflow limits",
    )
    if (
        _integer(limits["min_width"], label="effective workflow minimum width")
        != COMFYUI_APP_MIN_DIMENSION
        or _integer(limits["min_height"], label="effective workflow minimum height")
        != COMFYUI_APP_MIN_DIMENSION
        or _integer(
            limits["dimension_multiple"], label="effective workflow dimension multiple"
        )
        != COMFYUI_APP_DIMENSION_MULTIPLE
        or _integer(limits["max_width"], label="effective workflow maximum width")
        > COMFYUI_APP_MAX_DIMENSION
        or _integer(limits["max_height"], label="effective workflow maximum height")
        > COMFYUI_APP_MAX_DIMENSION
    ):
        raise BackendEvidenceError("effective workflow dimension limits are unsupported")

    server = _mapping(
        configuration["server"], label="resolved.effective_execution.configuration.server"
    )
    _exact_keys(
        server,
        {
            "host", "offline", "base_directory", "models_directory",
            "frontend_root", "frontend_root_sha256",
            "output_directory", "temp_directory", "input_directory", "port",
            "argv", "environment",
        },
        label="resolved.effective_execution.configuration.server",
    )
    if server["host"] != "127.0.0.1" or server["offline"] is not True:
        raise BackendEvidenceError("effective ComfyUI server is not restricted to loopback offline mode")
    _integer(server["port"], label="resolved.effective_execution.configuration.server.port", minimum=1)
    if server["port"] > 65535:
        raise BackendEvidenceError("effective ComfyUI server port is out of range")
    frontend_root = _string(server["frontend_root"], label="effective server frontend root")
    base_directory = _string(server["base_directory"], label="effective server base directory")
    models_directory = _string(
        server["models_directory"], label="effective server models directory"
    )
    if (
        not os.path.isabs(frontend_root)
        or _REMOTE_URL.search(frontend_root)
        or not os.path.isabs(base_directory)
        or _REMOTE_URL.search(base_directory)
        or ".." in base_directory.replace("\\", "/").split("/")
        or os.path.normpath(models_directory)
        != os.path.join(os.path.normpath(base_directory), "models")
    ):
        raise BackendEvidenceError("effective frontend root is not a local absolute path")
    _sha256(server["frontend_root_sha256"], label="effective server frontend root digest")
    private_directories: dict[str, str] = {}
    for name in ("output_directory", "temp_directory", "input_directory"):
        directory = _string(
            server[name],
            label=f"resolved.effective_execution.configuration.server.{name}",
        )
        if (
            not os.path.isabs(directory)
            or _REMOTE_URL.search(directory)
            or ".." in directory.replace("\\", "/").split("/")
        ):
            raise BackendEvidenceError("effective run directory is not a private local path")
        private_directories[name] = os.path.normpath(directory)
    if (
        len({os.path.dirname(path) for path in private_directories.values()}) != 1
        or {os.path.basename(path) for path in private_directories.values()}
        != {"output", "temp", "input"}
        or os.path.normpath(base_directory)
        != os.path.dirname(next(iter(private_directories.values())))
    ):
        raise BackendEvidenceError("effective server directories are not one private run scope")

    raw_argv = record["argv"]
    if (
        not isinstance(raw_argv, list)
        or any(not isinstance(token, str) or not token for token in raw_argv)
        or len(raw_argv) < 14
        or server["argv"] != raw_argv
    ):
        raise BackendEvidenceError(
            "resolved launch argv differs from effective server configuration"
        )
    interpreter_path = raw_argv[0]
    if (
        not os.path.isabs(interpreter_path)
        or _REMOTE_URL.search(interpreter_path)
        or "\x00" in interpreter_path
        or ".." in interpreter_path.replace("\\", "/").split("/")
    ):
        raise BackendEvidenceError(
            "resolved Python interpreter path is not a local absolute path"
        )
    try:
        stdlib_marker = raw_argv.index("--stdlib-paths")
        imports_marker = raw_argv.index("--import-roots", stdlib_marker + 1)
        separator = raw_argv.index("--", imports_marker + 1)
    except ValueError as error:
        raise BackendEvidenceError(
            "resolved launch argv does not use the isolated Python bootstrap"
        ) from error
    entrypoint_index = separator + 1
    if (
        raw_argv[1:5]
        != ["-P", "-s", "-S", _COMFYUI_PYTHON_BOOTSTRAP_PATH]
        or stdlib_marker != 7
        or imports_marker <= stdlib_marker + 1
        or separator != imports_marker + 3
        or entrypoint_index >= len(raw_argv)
    ):
        raise BackendEvidenceError(
            "resolved launch argv does not use the isolated Python bootstrap"
        )
    stdlib_paths = raw_argv[stdlib_marker + 1 : imports_marker]
    import_roots = raw_argv[imports_marker + 1 : imports_marker + 3]
    python_roots = [*raw_argv[5:7], *stdlib_paths, *import_roots]
    if any(
        not Path(path).is_absolute()
        or str(Path(path)) != path
        or ".." in Path(path).parts
        or _REMOTE_URL.search(path)
        or "\x00" in path
        for path in python_roots
    ):
        raise BackendEvidenceError(
            "resolved Python roots are not local normalized absolute paths"
        )
    if any(not Path(path).is_relative_to(Path(raw_argv[6])) for path in stdlib_paths):
        raise BackendEvidenceError(
            "resolved Python standard library path is outside the signed base prefix"
        )
    if raw_argv[entrypoint_index] != executable_path:
        raise BackendEvidenceError(
            "resolved launch argv does not use the effective ComfyUI engine"
        )
    expected_argv = [
        interpreter_path,
        "-P",
        "-s",
        "-S",
        _COMFYUI_PYTHON_BOOTSTRAP_PATH,
        *raw_argv[5:7],
        "--stdlib-paths",
        *stdlib_paths,
        "--import-roots",
        *import_roots,
        "--",
        executable_path,
        "--listen",
        "127.0.0.1",
        "--port",
        str(server["port"]),
        "--base-directory",
        os.path.normpath(base_directory),
        "--disable-all-custom-nodes",
        "--disable-auto-launch",
        "--offline",
        "--front-end-root",
        frontend_root,
        "--feature-flag",
        "enable_telemetry=false",
        "--output-directory",
        private_directories["output_directory"],
        "--temp-directory",
        private_directories["temp_directory"],
        "--input-directory",
        private_directories["input_directory"],
    ]
    if raw_argv != expected_argv:
        raise BackendEvidenceError(
            "resolved launch argv does not match the effective ComfyUI engine and privacy settings"
        )

    environment = _mapping(record["environment"], label="resolved.environment")
    names = environment["names"]
    values = _mapping(environment["values"], label="resolved.environment.values")
    effective_environment = _mapping(
        server["environment"],
        label="resolved.effective_execution.configuration.server.environment",
    )
    if (
        not isinstance(names, list)
        or any(not isinstance(name, str) for name in names)
        or names != sorted(set(names))
        or set(values) != set(names)
        or not set(names) <= COMFYUI_SAFE_ENVIRONMENT_NAMES
        or any(not isinstance(value, str) or not value for value in values.values())
        or effective_environment != values
        or "PYTHONHOME" in values
        or (
            "PYTHONHASHSEED" in values
            and not is_valid_python_hash_seed(values["PYTHONHASHSEED"])
        )
        or any(
            name.upper().startswith("PYTHON")
            and name.upper() != "PYTHONHASHSEED"
            for name in names
        )
    ):
        raise BackendEvidenceError(
            "resolved environment is incomplete, prohibited, or differs from effective configuration"
        )
    _validate_comfyui_private_value(
        {"argv": raw_argv, "environment": effective_environment},
        label="resolved ComfyUI launch",
    )

    components = record["components"]
    if not isinstance(components, list):
        raise BackendEvidenceError("resolved.components must be a list")
    component_ids = [component["id"] for component in components]
    component_roles = [component["role"] for component in components]
    if len(component_ids) != len(set(component_ids)) or len(component_roles) != len(
        set(component_roles)
    ):
        raise BackendEvidenceError("resolved.components contains duplicate role or ID")
    if set(component_roles) != {"diffusion_model", "vae", "text_encoder", "other"}:
        raise BackendEvidenceError("resolved.components contains an unexpected role or component")
    if configuration["components"] != components:
        raise BackendEvidenceError("effective model components differ from resolved pins")
    api = _mapping(configuration["api"], label="resolved.effective_execution.configuration.api")
    _exact_keys(
        api,
        {"prompt", "jobs", "queue", "node_replacements", "history", "view", "upload"},
        label="effective API",
    )
    if api != {
        "prompt": "/prompt",
        "jobs": "/api/jobs?limit=1000",
        "queue": "/queue",
        "node_replacements": "/node_replacements",
        "history": "/history/{prompt_id}",
        "view": "/view",
        "upload": "/upload/image",
    }:
        raise BackendEvidenceError("effective API endpoints do not match the application contract")

    _validate_comfyui_private_value(
        {"graph": effective["graph"], "configuration": configuration},
        label="resolved.effective_execution",
    )
    graph = effective["graph"]
    _validate_effective_graph(
        graph,
        pins=nodes,
        record=record,
        configuration=configuration,
        expected_workflow_approval=expected_workflow_approval,
    )
    effective_workflow = _mapping(
        configuration["workflow"], label="effective_execution.configuration.workflow"
    )
    workflow_profile_version = effective_workflow.get("profile_version")
    if workflow_profile_version == 2:
        output = _mapping(
            configuration["output"], label="effective_execution.configuration.output"
        )
        template = _mapping(
            effective_workflow["template"],
            label="effective_execution.configuration.workflow.template",
        )
        output_node_id = _string(
            output["node_id"], label="effective_execution.configuration.output.node_id"
        )
        output_field = _string(
            output["field"], label="effective_execution.configuration.output.field"
        )
        source_node_id = validate_comfyui_qwen_conditioning_graph(
            template,
            operation=str(effective_workflow["operation"]),
            output_node_id=output_node_id,
            output_field=output_field,
            expected_prompt="$prompt",
            expected_width="$width",
            expected_height="$height",
            require_artifact_placeholder=True,
            label="approved ComfyUI Qwen profile v2 template",
        )
        validate_comfyui_qwen_conditioning_graph(
            _mapping(graph, label="effective_execution.graph"),
            operation=str(effective_workflow["operation"]),
            output_node_id=output_node_id,
            output_field=output_field,
            expected_prompt=record["prompt"],
            expected_width=record["width"],
            expected_height=record["height"],
            source_node_id=source_node_id,
            label="effective ComfyUI Qwen profile v2 graph",
        )
    elif effective_workflow["operation"] == "edit":
        output = _mapping(
            configuration["output"], label="effective_execution.configuration.output"
        )
        template = _mapping(
            effective_workflow["template"],
            label="effective_execution.configuration.workflow.template",
        )
        source_node_id = validate_comfyui_source_conditioning_path(
            template,
            output_node_id=_string(
                output["node_id"], label="effective_execution.configuration.output.node_id"
            ),
            output_field=_string(
                output["field"], label="effective_execution.configuration.output.field"
            ),
            require_artifact_placeholder=True,
            label="approved ComfyUI edit template",
        )
        validate_comfyui_source_conditioning_path(
            _mapping(graph, label="effective_execution.graph"),
            output_node_id=_string(
                output["node_id"], label="effective_execution.configuration.output.node_id"
            ),
            output_field=_string(
                output["field"], label="effective_execution.configuration.output.field"
            ),
            source_node_id=source_node_id,
            label="effective ComfyUI edit graph",
        )
    if effective["graph_sha256"] != digest(graph):
        raise BackendEvidenceError("resolved.effective_execution graph digest does not match")
    if effective["configuration_sha256"] != digest(configuration):
        raise BackendEvidenceError(
            "resolved.effective_execution configuration digest does not match"
        )
    request_body = _mapping(
        effective["request_body"],
        label="resolved.effective_execution.request_body",
    )
    _exact_keys(
        request_body,
        {"prompt", "prompt_id", "client_id"},
        label="resolved.effective_execution.request_body",
    )
    if request_body["prompt"] != graph:
        raise BackendEvidenceError(
            "resolved.effective_execution request body does not contain the exact graph"
        )
    if request_body["prompt_id"] != prompt_id or request_body["client_id"] != attempt_id:
        raise BackendEvidenceError(
            "resolved.effective_execution request identity does not match"
        )
    if effective["request_body_sha256"] != digest(request_body):
        raise BackendEvidenceError(
            "resolved.effective_execution request body digest does not match"
        )
    _bounded_json(effective, label="resolved.effective_execution")
    if len(canonical_json(effective).encode("utf-8")) > MAX_EFFECTIVE_EXECUTION_BYTES:
        raise BackendEvidenceError(
            "resolved.effective_execution exceeds the bounded evidence size"
        )


def validate_resolved_record(
    value: object,
    *,
    expected_workflow_approval: object | None = None,
) -> None:
    """Validate a supported resolved record version or fail closed."""
    record = _mapping(value, label="resolved backend execution")
    version = record.get("schema_version")
    if type(version) is not int:
        raise BackendEvidenceError("resolved backend execution has an unsupported schema")
    if version == RECORD_SCHEMA_VERSION:
        if expected_workflow_approval is not None:
            raise BackendEvidenceError(
                "historical resolved v2 record cannot bind a v3 workflow approval"
            )
        _validate_resolved_record_v2(record)
        return
    if version not in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS:
        raise BackendEvidenceError("resolved backend execution has an unsupported schema")
    keys = {
        "schema",
        "schema_version",
        "attempt_id",
        "backend_kind",
        "candidate_id",
        "verification_id",
        "declaration_sha256",
        "engine",
        "recipe",
        "components",
        "adapters",
        "prompt",
        "seed",
        "width",
        "height",
        "sampling",
        "conditioning",
        "argv",
        "environment",
        "output_basename",
        "invocation_contract",
        "cli_contract",
        "runtime",
        "privacy",
        "verification_window",
        "effective_execution",
    }
    if version == RESOLVED_RECORD_SCHEMA_VERSION:
        keys.add("privacy_evidence")
    _exact_keys(record, keys, label="resolved backend execution")
    common = dict(record)
    common["schema_version"] = RECORD_SCHEMA_VERSION
    common.pop("effective_execution")
    common.pop("privacy_evidence", None)
    _validate_resolved_record_v2(common)
    if (
        record["backend_kind"] != COMFYUI_RESOLVED_BACKEND_KIND
        or record["invocation_contract"] != COMFYUI_RESOLVED_INVOCATION_CONTRACT
        or record["cli_contract"] != COMFYUI_RESOLVED_CLI_CONTRACT
    ):
        raise BackendEvidenceError(
            "resolved ComfyUI execution record does not identify the supported backend contract"
        )
    _string(record["attempt_id"], label="resolved.attempt_id")
    _validate_effective_execution(
        record["effective_execution"],
        record=record,
        expected_workflow_approval=expected_workflow_approval,
    )
    if version == RESOLVED_RECORD_SCHEMA_VERSION:
        evidence = _mapping(record["privacy_evidence"], label="resolved.privacy_evidence")
        try:
            validate_comfyui_resolved_privacy_evidence(evidence)
        except (TypeError, ValueError) as error:
            raise BackendEvidenceError(
                "resolved privacy evidence is invalid"
            ) from error
        effective = _mapping(
            record["effective_execution"], label="resolved.effective_execution"
        )
        engine = _mapping(record["engine"], label="resolved.engine")
        if (
            evidence["effective_configuration_sha256"]
            != effective["configuration_sha256"]
            or evidence["engine_id"] != engine["id"]
            or evidence["engine_version"] != engine["version"]
        ):
            raise BackendEvidenceError(
                "resolved privacy evidence does not match effective execution"
            )
        privacy = _mapping(record["privacy"], label="resolved.privacy")
        expected_status = (
            "fail"
            if any(item is True for item in privacy.values())
            else "unverified"
            if any(item is None for item in privacy.values())
            else "pass"
        )
        if evidence["status"] != expected_status:
            raise BackendEvidenceError(
                "resolved privacy evidence status differs from resolved controls"
            )
    _bounded_json(record, label="resolved backend execution")
    if len(canonical_json(record).encode("utf-8")) > MAX_RESOLVED_RECORD_BYTES:
        raise BackendEvidenceError("resolved backend execution exceeds the bounded evidence size")


def serialize_resolved_record(value: Mapping[str, object]) -> str:
    """Validate and serialize one supported resolved record canonically."""
    validate_resolved_record(value)
    return canonical_json(value)


def validate_launch_record(value: object) -> None:
    """Validate one launch record or raise BackendEvidenceError."""

    record = _mapping(value, label="launch record")
    _exact_keys(
        record,
        {
            "schema",
            "schema_version",
            "attempt_id",
            "listener_pid",
            "monotonic_start_ns",
            "launched",
            "argv",
            "environment",
        },
        label="launch record",
    )
    if record["schema"] != LAUNCH_SCHEMA or record["schema_version"] != RECORD_SCHEMA_VERSION:
        raise BackendEvidenceError("launch record has an unsupported schema")
    _string(record["attempt_id"], label="launch.attempt_id")
    _integer(record["listener_pid"], label="launch.listener_pid", minimum=1)
    _integer(record["monotonic_start_ns"], label="launch.monotonic_start_ns")
    if record["launched"] is not True:
        raise BackendEvidenceError("launch.launched must be true")
    argv = record["argv"]
    if not isinstance(argv, list) or not argv:
        raise BackendEvidenceError("launch.argv must be a non-empty list")
    for index, item in enumerate(argv):
        _string(item, label=f"launch.argv[{index}]")
    environment = _mapping(record["environment"], label="launch.environment")
    for name, value in environment.items():
        _string(name, label="launch.environment key")
        if not isinstance(value, str):
            raise BackendEvidenceError("launch.environment values must be strings")


def validate_observed_record(value: object) -> None:
    """Validate one supervisor observation or raise BackendEvidenceError."""

    record = _mapping(value, label="observation record")
    _exact_keys(
        record,
        {
            "schema",
            "schema_version",
            "attempt_id",
            "exit_code",
            "signal",
            "direct_child_reaped",
            "duration_seconds",
            "stdout_bytes",
            "stderr_bytes",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_classification",
            "stderr_classification",
            "stdout_codes",
            "stderr_codes",
            "process_tree_containment",
            "inherited_streams_retained_after_reap",
            "stream_state_unknown",
        },
        label="observation record",
    )
    if record["schema"] != OBSERVED_SCHEMA or record["schema_version"] != RECORD_SCHEMA_VERSION:
        raise BackendEvidenceError("observation record has an unsupported schema")
    _string(record["attempt_id"], label="observed.attempt_id")
    exit_code = _optional_integer(record["exit_code"], label="observed.exit_code")
    signal = _optional_integer(record["signal"], label="observed.signal", minimum=1)
    if (exit_code is None) == (signal is None):
        raise BackendEvidenceError("observed record requires exactly one exit_code or signal")
    _boolean(record["direct_child_reaped"], label="observed.direct_child_reaped")
    _number(record["duration_seconds"], label="observed.duration_seconds", minimum=0.0)
    _integer(record["stdout_bytes"], label="observed.stdout_bytes")
    _integer(record["stderr_bytes"], label="observed.stderr_bytes")
    _sha256(record["stdout_sha256"], label="observed.stdout_sha256")
    _sha256(record["stderr_sha256"], label="observed.stderr_sha256")
    for name in ("stdout_classification", "stderr_classification"):
        if record[name] not in OUTPUT_CLASSIFICATIONS:
            raise BackendEvidenceError(
                f"observed.{name} must be a known output classification"
            )
    for name in ("stdout_codes", "stderr_codes"):
        codes = record[name]
        if not isinstance(codes, list) or not codes:
            raise BackendEvidenceError(f"observed.{name} must be a non-empty list")
        if any(code not in OUTPUT_CODES for code in codes):
            raise BackendEvidenceError(f"observed.{name} contains an unknown code")
        if codes != sorted(set(codes)):
            raise BackendEvidenceError(f"observed.{name} must be sorted and unique")
    if record["process_tree_containment"] is not False:
        raise BackendEvidenceError("observed.process_tree_containment must be false")
    _boolean(
        record["inherited_streams_retained_after_reap"],
        label="observed.inherited_streams_retained_after_reap",
    )
    _boolean(record["stream_state_unknown"], label="observed.stream_state_unknown")


def observation_proves_reaped_child(value: object) -> bool:
    """Return whether an observation proves the direct child was reaped.

    The record is validated first. A reaped direct child is necessary but not
    sufficient: an inherited pipe that still had a live writer past the bounded
    post-reap drain shows that some other process still held the child's
    streams, so the attempt stays ambiguous. A read failure that left a stream
    state unknown has the same effect, because an unsuccessful read is not
    evidence that the pipe reached end of stream.

    This predicate describes one direct child and the streams it inherited. A
    true result means "the direct child was reaped and no descendant kept its
    pipes open". It does not mean "no descendant is running": a descendant that
    closes or redirects stdout and stderr leaves no observable trace here, and
    descendant processes are never tracked, counted, or killed.
    """

    validate_observed_record(value)
    record = _mapping(value, label="observation record")
    return (
        record["direct_child_reaped"] is True
        and record["inherited_streams_retained_after_reap"] is False
        and record["stream_state_unknown"] is False
    )


def record_state(value: Mapping[str, object]) -> str:
    """Return the persisted state name for one complete execution row."""

    state = value.get("state")
    if state not in EXECUTION_STATES:
        raise BackendEvidenceError("backend execution row has an unknown state")
    return str(state)
