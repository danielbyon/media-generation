"""Identity and termination records for one systemd-contained attempt.

Engine observations describe the runner's direct child.  These records
describe the separate systemd service invocation and its whole-cgroup state.
Neither record can stand in for the other.
"""

from __future__ import annotations

import hashlib
import array
import fcntl
import json
import os
import re
import socket
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping


SYSTEMD_CGROUP_CONTAINMENT_CONTRACT = "systemd-cgroup-v2/v1"

_ATTEMPT_ID = re.compile(r"att_[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_IDENTITY_FIELDS = frozenset(
    {
        "version",
        "job_id",
        "attempt_id",
        "owner_id",
        "claim_epoch",
        "resolved_digest",
        "boot_id",
        "unit_name",
        "invocation_id",
        "cgroup_path",
        "cgroup_device",
        "cgroup_inode",
        "runner_uid",
        "runner_gid",
    }
)
_TERMINATION_FIELDS = frozenset(
    {"version", "identity", "source", "populated", "observed_monotonic_ns", "observed_at"}
)


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_positive_int(value: object, field: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{field} must be a {qualifier} integer")
    return value


@dataclass(frozen=True)
class AttemptUnitIdentity:
    """Immutable identity of one runner service and its cgroup incarnation."""

    version: int
    job_id: str
    attempt_id: str
    owner_id: str
    claim_epoch: int
    resolved_digest: str
    boot_id: str
    unit_name: str
    invocation_id: str
    cgroup_path: str
    cgroup_device: int
    cgroup_inode: int
    runner_uid: int
    runner_gid: int

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or self.version != 1:
            raise ValueError("unsupported attempt-unit identity version")
        _require_text(self.job_id, "job_id")
        if not isinstance(self.attempt_id, str) or not _ATTEMPT_ID.fullmatch(self.attempt_id):
            raise ValueError("attempt_id is not a canonical attempt identifier")
        _require_text(self.owner_id, "owner_id")
        _require_positive_int(self.claim_epoch, "claim_epoch", allow_zero=True)
        if not isinstance(self.resolved_digest, str) or not _SHA256.fullmatch(
            self.resolved_digest
        ):
            raise ValueError("resolved_digest must be a lowercase SHA-256 digest")
        if not isinstance(self.boot_id, str) or not _BOOT_ID.fullmatch(self.boot_id):
            raise ValueError("boot_id must be a canonical Linux boot identifier")
        expected_unit = f"media-generation-attempt-{self.attempt_id[4:]}.service"
        if self.unit_name != expected_unit:
            raise ValueError("unit_name does not identify this attempt")
        if not isinstance(self.invocation_id, str) or not _INVOCATION_ID.fullmatch(
            self.invocation_id
        ):
            raise ValueError("invocation_id must be a 128-bit lowercase hexadecimal ID")
        expected_cgroup = f"/system.slice/{expected_unit}"
        if self.cgroup_path != expected_cgroup:
            raise ValueError("cgroup_path does not match the attempt service")
        _require_positive_int(self.cgroup_device, "cgroup_device")
        _require_positive_int(self.cgroup_inode, "cgroup_inode")
        _require_positive_int(self.runner_uid, "runner_uid")
        _require_positive_int(self.runner_gid, "runner_gid")

    def to_mapping(self) -> dict[str, object]:
        """Return the stable, versioned identity record used by SQLite and RPC."""
        return {
            "version": self.version,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "owner_id": self.owner_id,
            "claim_epoch": self.claim_epoch,
            "resolved_digest": self.resolved_digest,
            "boot_id": self.boot_id,
            "unit_name": self.unit_name,
            "invocation_id": self.invocation_id,
            "cgroup_path": self.cgroup_path,
            "cgroup_device": self.cgroup_device,
            "cgroup_inode": self.cgroup_inode,
            "runner_uid": self.runner_uid,
            "runner_gid": self.runner_gid,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> AttemptUnitIdentity:
        """Parse an exact identity shape and reject unknown or missing fields."""
        if not isinstance(value, Mapping) or set(value) != _IDENTITY_FIELDS:
            raise ValueError("attempt-unit identity has an unexpected field set")
        return cls(**dict(value))  # type: ignore[arg-type]


@dataclass(frozen=True)
class CgroupTerminationEvidence:
    """Kernel observation that the identified cgroup and descendants are empty."""

    identity: AttemptUnitIdentity
    populated: int
    observed_monotonic_ns: int
    observed_at: str
    version: int = 1
    source: str = "cgroup.events"

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or self.version != 1:
            raise ValueError("unsupported cgroup termination evidence version")
        if not isinstance(self.identity, AttemptUnitIdentity):
            raise ValueError("termination evidence must carry a validated unit identity")
        if isinstance(self.populated, bool) or self.populated != 0:
            raise ValueError("termination evidence requires cgroup.events populated=0")
        _require_positive_int(self.observed_monotonic_ns, "observed_monotonic_ns")
        if self.source != "cgroup.events":
            raise ValueError("termination evidence source must be cgroup.events")
        _require_text(self.observed_at, "observed_at")
        try:
            timestamp = datetime.fromisoformat(self.observed_at)
        except ValueError as error:
            raise ValueError("observed_at must be an ISO-8601 timestamp") from error
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")

    def to_mapping(self) -> dict[str, object]:
        """Return a proof record that cannot be confused with engine exit data."""
        return {
            "version": self.version,
            "identity": self.identity.to_mapping(),
            "source": self.source,
            "populated": self.populated,
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> CgroupTerminationEvidence:
        """Parse an exact proof shape and validate its embedded identity."""
        if not isinstance(value, Mapping) or set(value) != _TERMINATION_FIELDS:
            raise ValueError("cgroup termination evidence has an unexpected field set")
        identity_value = value["identity"]
        if not isinstance(identity_value, Mapping):
            raise ValueError("cgroup termination evidence is missing its identity")
        return cls(
            identity=AttemptUnitIdentity.from_mapping(identity_value),
            populated=value["populated"],  # type: ignore[arg-type]
            observed_monotonic_ns=value["observed_monotonic_ns"],  # type: ignore[arg-type]
            observed_at=value["observed_at"],  # type: ignore[arg-type]
            version=value["version"],  # type: ignore[arg-type]
            source=value["source"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True)
class SystemdAttemptCompletion:
    """Authenticated broker result with separate runner, engine, and cgroup facts."""

    identity: AttemptUnitIdentity
    runner_exit_code: int | None
    launcher_exit_code: int | None
    unit_result: str
    engine_observation: Mapping[str, object] | None
    termination_evidence: CgroupTerminationEvidence | None
    stream_complete: bool
    output_fd: int | None = None
    error_code: str | None = None
    runner_exit_signal: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, AttemptUnitIdentity):
            raise ValueError("completion must include a validated unit identity")
        for field, value in (
            ("runner_exit_code", self.runner_exit_code),
            ("launcher_exit_code", self.launcher_exit_code),
            ("runner_exit_signal", self.runner_exit_signal),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
            ):
                raise ValueError(f"{field} must be an integer or None")
        _require_text(self.unit_result, "unit_result")
        if self.engine_observation is not None and not isinstance(
            self.engine_observation, Mapping
        ):
            raise ValueError("engine_observation must be a mapping or None")
        if self.termination_evidence is not None and (
            self.termination_evidence.identity != self.identity
        ):
            raise ValueError("completion termination evidence names another unit")
        if not isinstance(self.stream_complete, bool):
            raise ValueError("stream_complete must be a boolean")
        if self.output_fd is not None and (
            isinstance(self.output_fd, bool)
            or not isinstance(self.output_fd, int)
            or self.output_fd < 0
        ):
            raise ValueError("output_fd must be a file descriptor or None")
        if self.error_code is not None:
            _require_text(self.error_code, "error_code")
        if self.runner_exit_code is not None and self.runner_exit_signal is not None:
            raise ValueError("runner exit cannot be both an exit code and a signal")
        if self.runner_exit_signal is not None and self.runner_exit_signal <= 0:
            raise ValueError("runner_exit_signal must be a positive signal number")


class SystemdAttemptRunner:
    """Typed client for the root-owned systemd attempt broker.

    The client speaks a small local SOCK_SEQPACKET protocol. The broker owns
    all unit construction and systemd operations; no request contains unit
    properties, an execution identity, or an arbitrary command.
    """

    containment_contract = SYSTEMD_CGROUP_CONTAINMENT_CONTRACT

    def __init__(
        self,
        socket_path: Path,
        *,
        scratch_root: Path,
        runner_uid: int,
        runner_gid: int,
    ) -> None:
        if isinstance(runner_uid, bool) or not isinstance(runner_uid, int) or runner_uid <= 0:
            raise ValueError("runner_uid must identify a non-root account")
        if isinstance(runner_gid, bool) or not isinstance(runner_gid, int) or runner_gid <= 0:
            raise ValueError("runner_gid must identify a non-root group")
        self.socket_path = Path(socket_path).expanduser().absolute()
        self.scratch_root = Path(scratch_root).expanduser().absolute()
        self.runner_uid = runner_uid
        self.runner_gid = runner_gid

    def prepare_attempt(self, claim: object) -> Path:
        """Ask the broker for the private scratch directory for this claim."""
        response, descriptor = self._request(
            {
                "operation": "prepare",
                "job_id": _require_text(getattr(claim, "job_id"), "job_id"),
                "attempt_id": _require_text(
                    getattr(claim, "attempt_id"), "attempt_id"
                ),
                "owner_id": _require_text(getattr(claim, "owner_id"), "owner_id"),
                "claim_epoch": _require_positive_int(
                    getattr(claim, "claim_epoch"), "claim_epoch"
                ),
            },
        )
        try:
            value = response.get("scratch_directory")
            if not isinstance(value, str):
                raise ValueError("broker response omitted scratch_directory")
            scratch = Path(value).absolute()
            if not scratch.is_relative_to(self.scratch_root):
                raise ValueError("broker scratch directory escaped its configured root")
            return scratch
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def execute_attempt(self, claim: object, prepared: object) -> SystemdAttemptCompletion:
        """Run the exact resolved invocation and receive its output only after proof."""
        resolved_record = getattr(prepared, "resolved_record")
        argv = getattr(prepared, "argv")
        environment = getattr(prepared, "environment")
        scratch = Path(getattr(prepared, "scratch_directory")).absolute()
        if not scratch.is_relative_to(self.scratch_root):
            raise ValueError("resolved scratch directory is outside broker scratch root")
        if not isinstance(resolved_record, Mapping):
            raise ValueError("prepared invocation has no resolved record")
        response, output_fd = self._request(
            {
                "operation": "execute",
                "job_id": getattr(claim, "job_id"),
                "attempt_id": getattr(claim, "attempt_id"),
                "owner_id": getattr(claim, "owner_id"),
                "claim_epoch": getattr(claim, "claim_epoch"),
                "resolved_digest": identity_digest_from_record(resolved_record),
                "resolved_record": dict(resolved_record),
                "argv": list(argv),
                "environment": dict(environment),
                "scratch_directory": str(scratch),
                "runner_uid": self.runner_uid,
                "runner_gid": self.runner_gid,
            },
        )
        try:
            identity = AttemptUnitIdentity.from_mapping(response["identity"])
            raw_termination = response.get("termination_evidence")
            termination = (
                None
                if raw_termination is None
                else CgroupTerminationEvidence.from_mapping(raw_termination)
            )
            raw_observation = response.get("engine_observation")
            observation = (
                None
                if raw_observation is None
                else _exact_mapping(raw_observation, "engine_observation")
            )
            completion = SystemdAttemptCompletion(
                identity=identity,
                runner_exit_code=response.get("runner_exit_code"),
                launcher_exit_code=response.get("launcher_exit_code"),
                unit_result=_require_text(response.get("unit_result"), "unit_result"),
                engine_observation=observation,
                termination_evidence=termination,
                stream_complete=response.get("stream_complete"),
                output_fd=output_fd,
                error_code=(
                    None
                    if response.get("error_code") is None
                    else _require_text(response.get("error_code"), "error_code")
                ),
                runner_exit_signal=response.get("runner_exit_signal"),
            )
            if (
                identity.attempt_id != getattr(claim, "attempt_id")
                or identity.job_id != getattr(claim, "job_id")
                or identity.owner_id != getattr(claim, "owner_id")
                or identity.claim_epoch != getattr(claim, "claim_epoch")
                or identity.resolved_digest
                != identity_digest_from_record(resolved_record)
                or identity.runner_uid != self.runner_uid
                or identity.runner_gid != self.runner_gid
            ):
                raise ValueError("broker completion is bound to another attempt or runner")
            if output_fd is not None:
                descriptor_flags = fcntl.fcntl(output_fd, fcntl.F_GETFL)
                descriptor_stat = os.fstat(output_fd)
                if (
                    not stat.S_ISREG(descriptor_stat.st_mode)
                    or descriptor_flags & os.O_ACCMODE != os.O_RDONLY
                    or not completion.stream_complete
                    or completion.termination_evidence is None
                ):
                    raise ValueError(
                        "broker output descriptor lacks read-only validated termination proof"
                    )
            return completion
        except Exception:
            if output_fd is not None:
                os.close(output_fd)
            raise

    def cancel_attempt(self, claim: object) -> str:
        """Request stop for the exact current attempt; never select a unit by prefix."""
        response, descriptor = self._request(
            {
                "operation": "cancel",
                "job_id": getattr(claim, "job_id"),
                "attempt_id": getattr(claim, "attempt_id"),
                "owner_id": getattr(claim, "owner_id"),
                "claim_epoch": getattr(claim, "claim_epoch"),
            }
        )
        if descriptor is not None:
            os.close(descriptor)
        result = response.get("outcome")
        if result not in {"requested", "acknowledged", "too_late"}:
            raise ValueError("broker returned an invalid cancellation outcome")
        return str(result)

    def acknowledge_output(self, identity: AttemptUnitIdentity, *, validated: bool) -> None:
        """Request scratch cleanup after validation or terminal failure.

        The broker requires durable whole-cgroup termination evidence for either path.
        """
        if not isinstance(validated, bool):
            raise ValueError("validated must be a boolean")
        response, descriptor = self._request(
            {
                "operation": "output_ack",
                "identity": identity.to_mapping(),
                "validated": validated,
            }
        )
        if descriptor is not None:
            os.close(descriptor)
        if response.get("acknowledged") is not True:
            raise RuntimeError("broker did not acknowledge output cleanup")

    def cleanup_after_recovery(self, identity: AttemptUnitIdentity) -> None:
        """Remove private scratch after recovery has fenced publication and proved exit."""
        response, descriptor = self._request(
            {
                "operation": "recovery_cleanup",
                "identity": identity.to_mapping(),
            }
        )
        if descriptor is not None:
            os.close(descriptor)
        if response.get("acknowledged") is not True:
            raise RuntimeError("broker did not acknowledge recovery cleanup")

    def _request(self, request: Mapping[str, object]) -> tuple[dict[str, object], int | None]:
        if not sys_platform_linux():
            raise OSError("systemd attempt broker is available only on Linux")
        _validate_broker_socket(self.socket_path)
        payload = json.dumps(
            request, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(payload) > 1024 * 1024:
            raise ValueError("systemd broker request exceeds the protocol limit")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            client.connect(str(self.socket_path))
            sent = client.sendmsg([payload])
            if sent != len(payload):
                raise OSError("systemd broker packet was not sent atomically")
            response_data, ancillary, flags, _ = client.recvmsg(
                1024 * 1024, socket.CMSG_SPACE(array.array("i").itemsize)
            )
        finally:
            client.close()
        if flags & getattr(socket, "MSG_TRUNC", 0):
            raise ValueError("systemd broker response exceeded the protocol limit")
        output_fd: int | None = None
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors = array.array("i")
                descriptors.frombytes(raw[: len(raw) - (len(raw) % descriptors.itemsize)])
                if len(descriptors) != 1 or output_fd is not None:
                    for descriptor in descriptors:
                        os.close(descriptor)
                    if output_fd is not None:
                        os.close(output_fd)
                    raise ValueError("broker sent an unexpected descriptor set")
                output_fd = descriptors[0]
        try:
            response = json.loads(response_data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            if output_fd is not None:
                os.close(output_fd)
            raise ValueError("systemd broker returned malformed JSON") from error
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            if output_fd is not None:
                os.close(output_fd)
            raise ValueError("systemd broker response has an invalid envelope")
        if not response["ok"]:
            if output_fd is not None:
                os.close(output_fd)
            raise RuntimeError(str(response.get("error", "systemd broker rejected request")))
        return response, output_fd


def identity_digest_from_record(record: Mapping[str, object]) -> str:
    """Return the backend digest used by the durable resolved invocation."""
    from .backend_provenance import backend_digest

    return backend_digest(record)


def _exact_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with text keys")
    return dict(value)


def _validate_broker_socket(path: Path) -> None:
    for parent in path.parents:
        try:
            parent_stat = parent.lstat()
        except OSError as error:
            raise PermissionError("systemd broker socket parent is unavailable") from error
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != 0
            or (
                parent_stat.st_mode & 0o022
                and not parent_stat.st_mode & stat.S_ISVTX
            )
        ):
            raise PermissionError("systemd broker socket parent is not root-controlled")
    try:
        observed = path.lstat()
    except OSError as error:
        raise OSError("root-owned systemd attempt broker socket is unavailable") from error
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISSOCK(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_mode & 0o007
    ):
        raise PermissionError("systemd broker socket is not a restricted root-owned socket")


def sys_platform_linux() -> bool:
    return os.name == "posix" and Path("/proc/sys/kernel/osrelease").exists()


def identity_digest(identity: AttemptUnitIdentity) -> str:
    """Hash every immutable unit and cgroup field using canonical JSON."""
    payload = json.dumps(
        identity.to_mapping(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()
