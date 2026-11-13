"""Non-root systemd service entrypoint for one pinned engine attempt."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Mapping

from .backend_provenance import environment_record
from .errors import BackendEvidenceError
from .supervisor import (
    ExecutionEvidenceAuthority,
    LaunchFact,
    ProcessObservation,
    ProcessSupervisor,
)
from .systemd_attempts import AttemptUnitIdentity


class _BrokerPipeAuthority(ExecutionEvidenceAuthority):
    """Forward only typed engine evidence to the root broker over the unit pipe."""

    def __init__(self, identity: AttemptUnitIdentity) -> None:
        self._identity = identity

    @property
    def attempt_id(self) -> str:
        return self._identity.attempt_id

    def verify_current(self) -> bool:
        response = _exchange({"operation": "verify_current"})
        return response.get("current") is True

    def record_launch(self, fact: LaunchFact) -> None:
        if fact.attempt_id != self.attempt_id:
            raise BackendEvidenceError("runner launch fact names another attempt")
        _exchange({"operation": "record_launch", "fact": fact.to_mapping()})

    def record_observation(self, fact: ProcessObservation) -> None:
        if fact.attempt_id != self.attempt_id:
            raise BackendEvidenceError("runner observation names another attempt")
        _exchange({"operation": "record_observation", "fact": fact.to_mapping()})


def main() -> int:
    """Read one broker manifest, supervise its engine child, and report facts."""
    try:
        manifest = _read_object(sys.stdin.buffer.readline())
        identity = AttemptUnitIdentity.from_mapping(manifest["identity"])
        argv = _text_list(manifest.get("argv"), "argv")
        environment = _environment(manifest.get("environment"))
        cwd = _absolute_directory(manifest.get("scratch_directory"))
        resolved = _object(manifest.get("resolved_record"), "resolved_record")
        _validate_manifest(identity, argv, environment, cwd, resolved)
        if os.geteuid() != identity.runner_uid or os.getegid() != identity.runner_gid:
            raise BackendEvidenceError("runner service identity does not match the attempt")
        if _current_cgroup() != identity.cgroup_path:
            raise BackendEvidenceError("runner is outside its authenticated systemd cgroup")

        supervisor = ProcessSupervisor(
            _BrokerPipeAuthority(identity),
            expected_argv=tuple(argv),
            expected_environment=environment,
        )
        observation = supervisor.run(argv, env=environment, cwd=cwd)
        _write_object(
            {
                "operation": "complete",
                "runner_exit_code": 0,
                "engine_observation": observation.to_mapping(),
                "stream_complete": not observation.stream_state_unknown,
            }
        )
        return 0
    except Exception as error:
        code = getattr(error, "code", None)
        if not isinstance(code, str) or not code:
            code = "runner_failed"
        try:
            _write_object(
                {
                    "operation": "runner_error",
                    "error_code": code,
                    "runner_exit_code": 1,
                    "stream_complete": False,
                }
            )
        except (BrokenPipeError, OSError):
            return 1
        return 1


def _validate_manifest(
    identity: AttemptUnitIdentity,
    argv: list[str],
    environment: dict[str, str],
    cwd: Path,
    resolved: Mapping[str, object],
) -> None:
    if resolved.get("attempt_id") != identity.attempt_id:
        raise BackendEvidenceError("resolved invocation names another attempt")
    if resolved.get("argv") != argv:
        raise BackendEvidenceError("runner argv differs from durable resolution")
    if resolved.get("environment") != environment_record(environment):
        raise BackendEvidenceError("runner environment differs from durable resolution")
    output = resolved.get("output_basename")
    if not isinstance(output, str) or not output or Path(output).name != output:
        raise BackendEvidenceError("resolved output basename is invalid")
    try:
        output_index = argv.index("-o")
        output_path = Path(argv[output_index + 1]).absolute()
    except (ValueError, IndexError) as error:
        raise BackendEvidenceError("resolved invocation has no output path") from error
    if (
        output_path.parent != cwd
        or output_path.name != output
        or output_path.exists()
        or output_path.is_symlink()
    ):
        raise BackendEvidenceError("resolved output path is outside attempt scratch")


def _current_cgroup() -> str:
    try:
        entries = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise BackendEvidenceError("runner cgroup identity is unavailable") from error
    unified = [entry[3:] for entry in entries if entry.startswith("0::")]
    if len(unified) != 1:
        raise BackendEvidenceError("runner does not have one unified cgroup identity")
    return unified[0]


def _exchange(request: Mapping[str, object]) -> dict[str, object]:
    _write_object(request)
    response = _read_object(sys.stdin.buffer.readline())
    if response.get("ok") is not True:
        raise BackendEvidenceError("broker rejected the engine evidence operation")
    return response


def _read_object(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > 1024 * 1024:
        raise BackendEvidenceError("broker control message is missing or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackendEvidenceError("broker control message is malformed") from error
    return _object(value, "control message")


def _write_object(value: Mapping[str, object]) -> None:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(raw) > 1024 * 1024:
        raise BackendEvidenceError("runner control message is oversized")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise BackendEvidenceError(f"{label} must be an object")
    return dict(value)


def _text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or "\x00" in item for item in value
    ):
        raise BackendEvidenceError(f"{label} must be a list of text values")
    return value


def _environment(value: object) -> dict[str, str]:
    mapping = _object(value, "environment")
    if any(
        not isinstance(key, str)
        or not key
        or "=" in key
        or "\x00" in key
        or not isinstance(item, str)
        or "\x00" in item
        for key, item in mapping.items()
    ):
        raise BackendEvidenceError("runner environment has invalid entries")
    return dict(mapping)  # type: ignore[return-value]


def _absolute_directory(value: object) -> Path:
    if not isinstance(value, str):
        raise BackendEvidenceError("scratch directory is missing")
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise BackendEvidenceError("scratch directory is unavailable")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
