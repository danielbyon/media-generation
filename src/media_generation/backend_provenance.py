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

from ._candidate_contract import COMPONENT_ROLES
from .errors import BackendEvidenceError
from .privacy import PrivacyControl

RECORD_SCHEMA_VERSION = 2
RESOLVED_SCHEMA = "media-generation.backend-execution-resolved"
LAUNCH_SCHEMA = "media-generation.backend-execution-launch"
OBSERVED_SCHEMA = "media-generation.backend-execution-observed"

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


def validate_resolved_record(value: object) -> None:
    """Validate one resolved execution record or raise BackendEvidenceError."""

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
