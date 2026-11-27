"""Prepare and supervise one direct local llama.cpp invocation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from .inference import (
    InferenceKind,
    ResponseCategory,
    ResponseResult,
    response_contract,
    response_schema,
    validate_text_response,
    validate_vision_response,
)
from .privacy import (
    LLAMA_CPP_ADAPTER_ID,
    LLAMA_CPP_CONFIGURATION_VERSION,
    LLAMA_CPP_SOURCE_VERSION,
    LLAMA_CPP_TOOL_ID,
    invocation_privacy_settings,
)
from .supervisor import CapturedStdout, ProcessObservation, ProcessSupervisor

LLAMA_CPP_SOURCE_COMMIT = "1a03cf47f67be591699d1f0f7ca28e1ed6eb8c7e"
_EXPECTED_SOURCE_VERSION = f"{LLAMA_CPP_SOURCE_COMMIT}+single-turn-v1"
_PROMPT_VERSION = "llama.cpp-mtmd-prompt/v1"
_SCHEMA_VERSION = "json-schema-draft-2020-12/v1"
_MAX_GENERATION_TOKENS = 512
MAX_CONTEXT_TOKENS = 4096
MAX_INFERENCE_IMAGE_PIXELS = 8_388_608
_DEFAULT_GENERATION_TOKENS = 512
_MAX_RESPONSE_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_STREAM_STDOUT_CONTRACT = "single-json-document"
_STREAM_STDERR_CONTRACT = "diagnostics-only"
_PRIVACY_SETTING_NAMES = frozenset(
    {
        "external_api",
        "cloud_inference",
        "telemetry",
        "content_upload",
        "automatic_network_fetch_or_update",
        "remote_endpoint_or_proxy",
        "cloud_fallback",
    }
)

if LLAMA_CPP_SOURCE_VERSION != _EXPECTED_SOURCE_VERSION:
    raise RuntimeError("llama.cpp source version does not match the invocation patch")


class RuntimeQualificationError(RuntimeError):
    """Reject dispatch when qualification records are absent or mismatched."""


def _digest(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _local_file(path: Path | str, field_name: str) -> Path:
    if not isinstance(path, (Path, str)):
        raise TypeError(f"{field_name} must be a local filesystem path")
    candidate = Path(path)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError(f"{field_name} must name an existing local file") from error
    if not resolved.is_absolute() or not resolved.is_file():
        raise ValueError(f"{field_name} must name an existing local file")
    return resolved


def _private_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("workspace must be an existing private directory") from error
    if not resolved.is_dir() or stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise ValueError("workspace permissions must exclude group and other users")
    return resolved


def _write_private_file(path: Path, contents: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(contents)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _contract_mapping(kind: InferenceKind) -> dict[str, str]:
    contract = response_contract(kind)
    schema = response_schema(kind)
    canonical_schema = json.dumps(
        schema,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    schema_sha256 = hashlib.sha256(canonical_schema).hexdigest()
    if contract.get("schema_sha256") != schema_sha256:
        raise RuntimeError("response schema digest does not match its contract")
    for key in ("validator_id", "validator_package_version"):
        value = contract.get(key)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"response contract is missing {key}")
    return {
        "schema_version": _SCHEMA_VERSION,
        "schema_sha256": schema_sha256,
        "prompt_version": _PROMPT_VERSION,
        "validator_id": contract["validator_id"],
        "validator_package_version": contract["validator_package_version"],
    }


@dataclass(frozen=True, slots=True)
class LlamaCppComponent:
    """Reference one local component already checked by candidate preparation."""

    role: str
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if self.role not in {"checkpoint", "vision_encoder", "projector"}:
            raise ValueError("component role is not supported by the runtime")
        object.__setattr__(self, "path", _local_file(self.path, "component path"))
        _digest(self.sha256, "component sha256")


@dataclass(frozen=True, slots=True)
class LlamaCppConfiguration:
    """Hold the exact local paths and finite generation limit for execution."""

    executable_path: Path
    model_component: LlamaCppComponent
    projector_component: LlamaCppComponent
    max_tokens: int = _DEFAULT_GENERATION_TOKENS
    hardware_fingerprint_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "executable_path",
            _local_file(self.executable_path, "runtime executable"),
        )
        if not isinstance(self.model_component, LlamaCppComponent):
            raise TypeError("model_component must be a LlamaCppComponent")
        if self.model_component.role != "checkpoint":
            raise ValueError("model component must use the checkpoint role")
        if not isinstance(self.projector_component, LlamaCppComponent):
            raise TypeError("projector_component must be a LlamaCppComponent")
        if self.projector_component.role not in {"vision_encoder", "projector"}:
            raise ValueError("projector component must use a vision or projector role")
        if (
            isinstance(self.max_tokens, bool)
            or not isinstance(self.max_tokens, int)
            or not 1 <= self.max_tokens <= _MAX_GENERATION_TOKENS
        ):
            raise ValueError(
                f"max_tokens must be between 1 and {_MAX_GENERATION_TOKENS}"
            )
        if self.hardware_fingerprint_sha256 is not None:
            _digest(self.hardware_fingerprint_sha256, "hardware fingerprint sha256")


@dataclass(frozen=True, slots=True)
class LlamaCppRequest:
    """Describe one text or image prompt without placing it in process arguments."""

    kind: InferenceKind
    prompt: str = field(repr=False)
    image_path: Path | None = None
    source_text: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, InferenceKind):
            raise TypeError("kind must be an InferenceKind")
        if not isinstance(self.prompt, str) or not self.prompt:
            raise ValueError("prompt must be non-empty text")
        if "\x00" in self.prompt:
            raise ValueError("prompt cannot contain a NUL character")
        try:
            self.prompt.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("prompt must be valid UTF-8 text") from error
        if self.image_path is not None and not isinstance(self.image_path, (Path, str)):
            raise TypeError("image_path must be a local filesystem path")
        if self.source_text is not None:
            if not isinstance(self.source_text, str):
                raise TypeError("source_text must be text or None")
            if "\x00" in self.source_text:
                raise ValueError("source_text cannot contain NUL character")
            try:
                self.source_text.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("source_text must be valid UTF-8 text") from error


@dataclass(frozen=True, slots=True)
class PreparedInvocation:
    """Hold immutable process inputs and response provenance for one request."""

    runtime_config: LlamaCppConfiguration
    request: LlamaCppRequest = field(repr=False)
    workspace: Path
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    schema_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.runtime_config, LlamaCppConfiguration):
            raise TypeError("runtime_config must be a LlamaCppConfiguration")
        if not isinstance(self.request, LlamaCppRequest):
            raise TypeError("request must be a LlamaCppRequest")
        object.__setattr__(self, "workspace", Path(self.workspace))
        object.__setattr__(self, "argv", tuple(self.argv))
        if not isinstance(self.environment, Mapping):
            raise TypeError("environment must map names to strings")
        if any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, str)
            for name, value in self.environment.items()
        ):
            raise TypeError("environment must map names to strings")
        object.__setattr__(
            self,
            "environment",
            MappingProxyType(dict(self.environment)),
        )
        _digest(self.schema_sha256, "schema_sha256")

    @property
    def adapter_id(self) -> str:
        """Return the application-owned privacy registration identifier."""
        return LLAMA_CPP_ADAPTER_ID

    @property
    def configuration(self) -> dict[str, object]:
        """Build the application privacy mapping from the exact process inputs."""
        response_contracts = {
            kind.value: _contract_mapping(kind) for kind in InferenceKind
        }
        privacy = invocation_privacy_settings(self.argv, self.environment)
        if set(privacy) != _PRIVACY_SETTING_NAMES or any(
            type(value) is not bool for value in privacy.values()
        ):
            raise RuntimeError("invocation privacy settings are not fully classified")
        return {
            "adapter_id": LLAMA_CPP_ADAPTER_ID,
            "backend_kind": "local-inference",
            "invocation_contract": "llama-cpp-mtmd-exec-v1",
            "cli_contract": "mtmd-cli-single-turn/v1",
            "configuration_version": LLAMA_CPP_CONFIGURATION_VERSION,
            "engine": {
                "id": LLAMA_CPP_TOOL_ID,
                "version": LLAMA_CPP_SOURCE_VERSION,
            },
            "source_commit": LLAMA_CPP_SOURCE_COMMIT,
            "runtime": {"executable_path": str(self.runtime_config.executable_path)},
            "components": {
                "model": {
                    "role": self.runtime_config.model_component.role,
                    "path": str(self.runtime_config.model_component.path),
                    "sha256": self.runtime_config.model_component.sha256,
                },
                "projector": {
                    "role": self.runtime_config.projector_component.role,
                    "path": str(self.runtime_config.projector_component.path),
                    "sha256": self.runtime_config.projector_component.sha256,
                },
            },
        "context_tokens": MAX_CONTEXT_TOKENS,
        "image_limits": {
            "max_pixels": (
                MAX_INFERENCE_IMAGE_PIXELS
                if self.request.kind is InferenceKind.VISION
                else None
            )
        },
        "generation": {"max_tokens": self.runtime_config.max_tokens},
            "responses": response_contracts,
            "privacy": privacy,
            "offline": True,
            "dispatch_readiness": "requires-evidence",
        }


@dataclass(frozen=True, slots=True)
class RuntimeBuildEvidence:
    """Identify one built binary and its source and build records."""

    executable_path: Path
    source_version: str
    binary_sha256: str
    build_id: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "executable_path", _local_file(self.executable_path, "build executable")
        )
        if self.source_version != LLAMA_CPP_SOURCE_VERSION:
            raise ValueError("build source version does not match the configured source")
        _digest(self.binary_sha256, "binary sha256")
        _digest(self.evidence_sha256, "build evidence sha256")
        if not isinstance(self.build_id, str) or not self.build_id.strip():
            raise ValueError("build_id must identify the runtime build")


@dataclass(frozen=True, slots=True)
class ResponseStreamVerification:
    """Record an observed stdout and stderr contract for one exact runtime."""

    executable_sha256: str
    source_version: str
    model_sha256: str
    projector_sha256: str
    inference_kind: InferenceKind
    schema_sha256: str
    stdout_contract: str
    stderr_contract: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if self.source_version != LLAMA_CPP_SOURCE_VERSION:
            raise ValueError("stream evidence source version does not match")
        if not isinstance(self.inference_kind, InferenceKind):
            raise TypeError("stream evidence inference_kind must be an InferenceKind")
        for field_name in (
            "executable_sha256",
            "model_sha256",
            "projector_sha256",
            "schema_sha256",
            "evidence_sha256",
        ):
            _digest(getattr(self, field_name), field_name)
        if self.stdout_contract != _STREAM_STDOUT_CONTRACT:
            raise ValueError("stream evidence must verify one JSON document on stdout")
        if self.stderr_contract != _STREAM_STDERR_CONTRACT:
            raise ValueError("stream evidence must verify diagnostics-only stderr")


@dataclass(frozen=True, slots=True)
class HardwareCompatibilityEvidence:
    """Bind a compatibility assessment to one runtime and component pair."""

    executable_sha256: str
    model_sha256: str
    projector_sha256: str
    hardware_fingerprint_sha256: str
    assessment: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        for field_name in (
            "executable_sha256",
            "model_sha256",
            "projector_sha256",
            "hardware_fingerprint_sha256",
            "evidence_sha256",
        ):
            _digest(getattr(self, field_name), field_name)
        if self.assessment != "compatible":
            raise ValueError("hardware evidence must report compatible")


@dataclass(frozen=True, slots=True)
class ResourceDemandEvidence:
    """Bind measured resource demand to the same runtime and execution bounds."""

    executable_sha256: str
    model_sha256: str
    projector_sha256: str
    hardware_fingerprint_sha256: str
    max_tokens: int
    context_tokens: int
    max_image_pixels: int | None
    measured_peak_bytes: int
    available_memory_bytes: int
    evidence_sha256: str

    def __post_init__(self) -> None:
        for field_name in (
            "executable_sha256",
            "model_sha256",
            "projector_sha256",
            "hardware_fingerprint_sha256",
            "evidence_sha256",
        ):
            _digest(getattr(self, field_name), field_name)
        for field_name in (
            "max_tokens",
            "context_tokens",
            "measured_peak_bytes",
            "available_memory_bytes",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if self.measured_peak_bytes > self.available_memory_bytes:
            raise ValueError("measured resource demand exceeds available memory")
        if self.max_image_pixels is not None and (
            isinstance(self.max_image_pixels, bool)
            or not isinstance(self.max_image_pixels, int)
            or self.max_image_pixels <= 0
        ):
            raise ValueError("max_image_pixels must be a positive integer or None")


@dataclass(frozen=True, slots=True)
class RuntimeQualification:
    """Require separate build, stream, hardware, and resource evidence."""

    build: RuntimeBuildEvidence
    response_stream: ResponseStreamVerification
    hardware: HardwareCompatibilityEvidence
    resources: ResourceDemandEvidence

    def __post_init__(self) -> None:
        expected = (
            ("build", self.build, RuntimeBuildEvidence),
            ("response_stream", self.response_stream, ResponseStreamVerification),
            ("hardware", self.hardware, HardwareCompatibilityEvidence),
            ("resources", self.resources, ResourceDemandEvidence),
        )
        for name, record, record_type in expected:
            if not isinstance(record, record_type):
                raise TypeError(f"{name} must be an explicit evidence record")

    def require_for(
        self,
        configuration: LlamaCppConfiguration,
        prepared: PreparedInvocation,
    ) -> "DispatchQualificationReceipt":
        """Reject any evidence set that does not match this exact invocation."""
        if not isinstance(configuration, LlamaCppConfiguration):
            raise TypeError("configuration must be a LlamaCppConfiguration")
        if not isinstance(prepared, PreparedInvocation):
            raise TypeError("prepared must be a PreparedInvocation")
        if prepared.runtime_config != configuration:
            raise RuntimeQualificationError("qualification is bound to another configuration")

        binary_sha256 = _sha256_file(configuration.executable_path)
        model_sha256 = configuration.model_component.sha256
        projector_sha256 = configuration.projector_component.sha256
        build = self.build
        if (
            build.executable_path != configuration.executable_path
            or build.source_version != LLAMA_CPP_SOURCE_VERSION
            or build.binary_sha256 != binary_sha256
        ):
            raise RuntimeQualificationError("runtime build evidence does not match binary")

        stream = self.response_stream
        if (
            stream.executable_sha256 != binary_sha256
            or stream.source_version != LLAMA_CPP_SOURCE_VERSION
            or stream.model_sha256 != model_sha256
            or stream.projector_sha256 != projector_sha256
            or stream.inference_kind is not prepared.request.kind
            or stream.schema_sha256 != prepared.schema_sha256
        ):
            raise RuntimeQualificationError("response stream evidence does not match invocation")

        hardware = self.hardware
        resources = self.resources
        if configuration.hardware_fingerprint_sha256 is None:
            raise RuntimeQualificationError("hardware fingerprint evidence is required")
        if (
            hardware.executable_sha256 != binary_sha256
            or hardware.model_sha256 != model_sha256
            or hardware.projector_sha256 != projector_sha256
            or hardware.hardware_fingerprint_sha256
            != configuration.hardware_fingerprint_sha256
            or hardware.assessment != "compatible"
        ):
            raise RuntimeQualificationError("hardware compatibility evidence does not match")
        if (
            resources.executable_sha256 != binary_sha256
            or resources.model_sha256 != model_sha256
            or resources.projector_sha256 != projector_sha256
            or resources.hardware_fingerprint_sha256
            != configuration.hardware_fingerprint_sha256
            or resources.max_tokens != configuration.max_tokens
            or resources.context_tokens != MAX_CONTEXT_TOKENS
            or resources.max_image_pixels
            != (
                MAX_INFERENCE_IMAGE_PIXELS
                if prepared.request.kind is InferenceKind.VISION
                else None
            )
            or resources.measured_peak_bytes > resources.available_memory_bytes
        ):
            raise RuntimeQualificationError(
                "resource evidence does not match invocation bounds"
            )

        return DispatchQualificationReceipt(
            source_version=build.source_version,
            build_id=build.build_id,
            executable_sha256=binary_sha256,
            model_sha256=model_sha256,
            projector_sha256=projector_sha256,
            hardware_fingerprint_sha256=hardware.hardware_fingerprint_sha256,
            stream_evidence_sha256=stream.evidence_sha256,
            build_evidence_sha256=build.evidence_sha256,
            hardware_evidence_sha256=hardware.evidence_sha256,
            resource_evidence_sha256=resources.evidence_sha256,
        )


@dataclass(frozen=True, slots=True)
class DispatchQualificationReceipt:
    """Summarize the records that authorized one exact direct invocation."""

    source_version: str
    build_id: str
    executable_sha256: str
    model_sha256: str
    projector_sha256: str
    hardware_fingerprint_sha256: str
    stream_evidence_sha256: str
    build_evidence_sha256: str
    hardware_evidence_sha256: str
    resource_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class LlamaCppOutcome:
    """Return validated output beside text-free supervisor evidence."""

    response: ResponseResult
    observation: ProcessObservation
    qualification: DispatchQualificationReceipt
    stdout_prefix: bytes
    stdout_bytes: int
    stdout_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.stdout_prefix, bytes):
            raise TypeError("stdout_prefix must be bytes")
        if len(self.stdout_prefix) > _MAX_RESPONSE_BYTES:
            raise ValueError("stdout_prefix exceeds the capture limit")
        if (
            isinstance(self.stdout_bytes, bool)
            or not isinstance(self.stdout_bytes, int)
            or self.stdout_bytes < len(self.stdout_prefix)
        ):
            raise ValueError("stdout_bytes must include the captured prefix")
        _digest(self.stdout_sha256, "stdout_sha256")
        if (
            self.stdout_bytes != self.observation.stdout_bytes
            or self.stdout_sha256 != self.observation.stdout_sha256
        ):
            raise ValueError("stdout capture does not match supervisor observation")
        if (
            self.stdout_bytes == len(self.stdout_prefix)
            and self.stdout_sha256
            != hashlib.sha256(self.stdout_prefix).hexdigest()
        ):
            raise ValueError("complete stdout digest does not match captured bytes")

    @property
    def stdout_prefix_sha256(self) -> str:
        """Return a digest for the retained prefix, including partial captures."""
        return hashlib.sha256(self.stdout_prefix).hexdigest()

    @property
    def capture_record(self) -> dict[str, object]:
        """Return the bounded response data and hashes for attempt persistence."""
        return {
            "response_bytes": self.stdout_prefix,
            "response_size": self.stdout_bytes,
            "response_sha256": self.stdout_sha256,
        }


@contextmanager
def private_workspace(parent: Path | None = None) -> Iterator[Path]:
    """Create a private directory for prompt and schema files."""
    parent_path = None
    if parent is not None:
        parent_path = Path(parent).resolve(strict=True)
        if not parent_path.is_dir():
            raise ValueError("workspace parent must be a directory")
    with tempfile.TemporaryDirectory(
        prefix="llama-inference-",
        dir=str(parent_path) if parent_path is not None else None,
    ) as temporary_path:
        workspace = Path(temporary_path)
        os.chmod(workspace, 0o700)
        yield workspace
def prepare_invocation(
    configuration: LlamaCppConfiguration,
    request: LlamaCppRequest,
    *,
    workspace: Path,
) -> PreparedInvocation:
    """Write private inputs and build an argv vector for the pinned CLI."""
    if not isinstance(configuration, LlamaCppConfiguration):
        raise TypeError("configuration must be a LlamaCppConfiguration")
    if not isinstance(request, LlamaCppRequest):
        raise TypeError("request must be a LlamaCppRequest")
    _verify_component_hashes(configuration)
    private_path = _private_directory(Path(workspace))
    image_path: Path | None = None
    if request.kind is InferenceKind.VISION:
        if request.image_path is None:
            raise ValueError("vision inference requires an image")
        image_path = _local_file(request.image_path, "local image")
        if "," in str(image_path):
            raise ValueError("local image path cannot contain a comma")
    elif request.image_path is not None:
        raise ValueError("text inference cannot include an image")

    contract = _contract_mapping(request.kind)
    schema = response_schema(request.kind)
    schema_text = json.dumps(
        schema,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    prompt_path = private_path / "prompt.txt"
    schema_path = private_path / "response-schema.json"
    _write_private_file(prompt_path, request.prompt)
    _write_private_file(schema_path, schema_text)

    argv = _build_argv(
        configuration,
        request,
        prompt_path=prompt_path,
        schema_path=schema_path,
        image_path=image_path,
    )
    environment = _owned_environment()
    return PreparedInvocation(
        runtime_config=configuration,
        request=request,
        workspace=private_path,
        argv=tuple(argv),
        environment=environment,
        schema_sha256=contract["schema_sha256"],
    )


def execute_invocation(
    prepared: PreparedInvocation,
    supervisor: ProcessSupervisor,
    *,
    qualification: RuntimeQualification | None,
) -> LlamaCppOutcome:
    """Run once after all evidence matches, then validate the captured JSON."""
    if not isinstance(prepared, PreparedInvocation):
        raise TypeError("prepared must be a PreparedInvocation")
    _validate_prepared_invocation(prepared)
    if not isinstance(qualification, RuntimeQualification):
        raise RuntimeQualificationError(
            "explicit build, stream, hardware, and resource evidence is required"
        )
    if not isinstance(supervisor, ProcessSupervisor):
        raise TypeError("supervisor must be a ProcessSupervisor")
    receipt = qualification.require_for(prepared.runtime_config, prepared)
    captured = supervisor.run_capturing_stdout(
        prepared.argv,
        env=prepared.environment,
        cwd=prepared.workspace,
        max_stdout_bytes=_MAX_RESPONSE_BYTES,
    )
    response = _validate_captured(prepared, captured)
    return LlamaCppOutcome(
        response=response,
        observation=captured.observation,
        qualification=receipt,
        stdout_prefix=captured.stdout_prefix,
        stdout_bytes=captured.observation.stdout_bytes,
        stdout_sha256=captured.observation.stdout_sha256,
    )


def _owned_environment() -> Mapping[str, str]:
    return MappingProxyType(
        {
            "PATH": os.defpath,
            "LLAMA_OFFLINE": "1",
            "LC_ALL": "C",
        }
    )


def _build_argv(
    configuration: LlamaCppConfiguration,
    request: LlamaCppRequest,
    *,
    prompt_path: Path,
    schema_path: Path,
    image_path: Path | None,
) -> tuple[str, ...]:
    argv = [
        str(configuration.executable_path),
        "--model",
        str(configuration.model_component.path),
        "--mmproj",
        str(configuration.projector_component.path),
        "--ctx-size",
        str(MAX_CONTEXT_TOKENS),
        "--offline",
        "--file",
        str(prompt_path),
        "--json-schema-file",
        str(schema_path),
        "--predict",
        str(configuration.max_tokens),
        "--no-perf",
    ]
    if image_path is not None:
        argv.extend(("--image", str(image_path)))
    if request.prompt in argv:
        raise ValueError("prompt must not appear in process arguments")
    return tuple(argv)


def _validate_prepared_invocation(prepared: PreparedInvocation) -> None:
    """Check generated files and process inputs again immediately before spawn."""
    workspace = _private_directory(prepared.workspace)
    if workspace != prepared.workspace:
        raise RuntimeQualificationError("prepared invocation workspace changed")
    prompt_path = workspace / "prompt.txt"
    schema_path = workspace / "response-schema.json"
    try:
        prompt_mode = stat.S_IMODE(prompt_path.stat().st_mode)
        schema_mode = stat.S_IMODE(schema_path.stat().st_mode)
        prompt = prompt_path.read_text(encoding="utf-8")
        schema_text = schema_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RuntimeQualificationError("prepared invocation files are unavailable") from error
    if prompt_mode != 0o600 or schema_mode != 0o600:
        raise RuntimeQualificationError("prepared invocation files are not private")
    if prompt != prepared.request.prompt:
        raise RuntimeQualificationError("prepared prompt file changed")
    try:
        _verify_component_hashes(prepared.runtime_config)
    except ValueError as error:
        raise RuntimeQualificationError(
            "model or projector component hash no longer matches its pin"
        ) from error

    schema = response_schema(prepared.request.kind)
    expected_schema_text = json.dumps(
        schema,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    contract = _contract_mapping(prepared.request.kind)
    if (
        schema_text != expected_schema_text
        or prepared.schema_sha256 != contract["schema_sha256"]
    ):
        raise RuntimeQualificationError("prepared response schema changed")

    image_path = None
    if prepared.request.kind is InferenceKind.VISION:
        if prepared.request.image_path is None:
            raise RuntimeQualificationError("vision invocation has no local image")
        image_path = _local_file(prepared.request.image_path, "local image")
    elif prepared.request.image_path is not None:
        raise RuntimeQualificationError("text invocation includes an image")
    expected_argv = _build_argv(
        prepared.runtime_config,
        prepared.request,
        prompt_path=prompt_path,
        schema_path=schema_path,
        image_path=image_path,
    )
    if prepared.argv != expected_argv:
        raise RuntimeQualificationError("prepared invocation arguments changed")
    if dict(prepared.environment) != dict(_owned_environment()):
        raise RuntimeQualificationError("prepared invocation environment changed")
    privacy = invocation_privacy_settings(prepared.argv, prepared.environment)
    if set(privacy) != _PRIVACY_SETTING_NAMES or any(
        value is not False for value in privacy.values()
    ):
        raise RuntimeQualificationError("prepared invocation privacy settings are unverified")


def _validate_captured(
    prepared: PreparedInvocation,
    captured: CapturedStdout,
) -> ResponseResult:
    if captured.observation.stdout_bytes != len(captured.stdout_prefix):
        return ResponseResult(ResponseCategory.RESPONSE_CAPTURE_OVERFLOW)
    if captured.observation.exit_code != 0:
        return ResponseResult(ResponseCategory.RUNTIME_FAILURE)
    try:
        raw_response = captured.stdout_prefix.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ResponseResult(
            ResponseCategory.MALFORMED_JSON_UNKNOWN_TERMINATION,
            detail="response stream is not valid UTF-8",
        )
    if prepared.request.kind is InferenceKind.TEXT:
        source_text = prepared.request.source_text
        if source_text is None:
            source_text = prepared.request.prompt
        return validate_text_response(raw_response, source_text)
    return validate_vision_response(raw_response)


def _verify_component_hashes(configuration: LlamaCppConfiguration) -> None:
    for name, component in (
        ("model", configuration.model_component),
        ("projector", configuration.projector_component),
    ):
        if _sha256_file(component.path) != component.sha256:
            raise ValueError(f"{name} component hash does not match its declared pin")


def restore_response_prefix(
    response_bytes: bytes,
    *,
    response_size: int,
    response_sha256: str,
) -> bytes:
    """Check a stored complete response prefix before using it for one repair."""
    if not isinstance(response_bytes, bytes):
        raise TypeError("response_bytes must be bytes")
    if len(response_bytes) > _MAX_RESPONSE_BYTES:
        raise ValueError("stored response prefix exceeds the capture limit")
    if (
        isinstance(response_size, bool)
        or not isinstance(response_size, int)
        or response_size != len(response_bytes)
    ):
        raise ValueError("stored response capture is incomplete")
    _digest(response_sha256, "response_sha256")
    if response_sha256 != hashlib.sha256(response_bytes).hexdigest():
        raise ValueError("stored response capture digest does not match its bytes")
    return response_bytes
