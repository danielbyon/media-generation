"""Root broker for narrowly authorized per-attempt systemd services.

The broker accepts typed attempt operations from the worker account. Every
unit name, command, identity, device property, and systemd property is built
from broker configuration and durable attempt evidence. The worker never
receives systemd management privileges.
"""

from __future__ import annotations

import array
import errno
import json
import os
import pwd
import grp
import select
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .backend_provenance import backend_digest, environment_record
from .engine import ENVIRONMENT_ALLOWLIST
from .errors import BackendEvidenceError
from .store import ExecutionClaim, SQLiteStore
from .systemd_evidence import SystemdEvidenceLedger
from .systemd_protocol import encode_json_line, read_json_line
from .systemd_attempts import (
    SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
    AttemptUnitIdentity,
    CgroupTerminationEvidence,
)


_CONFIG_KEYS = frozenset(
    {
        "database_path",
        "socket_path",
        "scratch_root",
        "runner_executable",
        "runner_uid",
        "runner_gid",
        "runner_supplementary_gids",
        "worker_uid",
        "worker_gid",
        "scratch_gid",
        "model_read_gid",
        "device_allow",
        "read_roots",
        "environment_path_allowlist",
        "empty_timeout_seconds",
    }
)
_REQUESTS = {
    "prepare": frozenset(
        {"operation", "job_id", "attempt_id", "owner_id", "claim_epoch"}
    ),
    "execute": frozenset(
        {
            "operation", "job_id", "attempt_id", "owner_id", "claim_epoch",
            "resolved_digest", "resolved_record", "argv", "environment",
            "scratch_directory", "runner_uid", "runner_gid",
        }
    ),
    "cancel": frozenset(
        {"operation", "job_id", "attempt_id", "owner_id", "claim_epoch"}
    ),
    "output_ack": frozenset({"operation", "identity", "validated"}),
    "recovery_cleanup": frozenset({"operation", "identity"}),
}
_MAX_PACKET = 1024 * 1024
_MAX_OUTPUT_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class BrokerConfiguration:
    """Root-owned policy for the runner, GPU, readable data, and search paths."""

    database_path: Path
    socket_path: Path
    scratch_root: Path
    runner_executable: Path
    runner_uid: int
    runner_gid: int
    runner_supplementary_gids: tuple[int, ...]
    worker_uid: int
    worker_gid: int
    scratch_gid: int
    model_read_gid: int
    device_allow: tuple[Path, ...]
    read_roots: tuple[Path, ...]
    environment_path_allowlist: tuple[Path, ...]
    empty_timeout_seconds: float = 30.0

    @classmethod
    def from_file(cls, path: Path) -> BrokerConfiguration:
        """Load exact broker configuration from a root-owned, non-writable file."""
        config_path = Path(path)
        _require_root_owned_ancestors(config_path)
        observed = config_path.lstat()
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_mode & 0o022
        ):
            raise PermissionError("broker configuration must be a root-owned regular file")
        raw = config_path.read_bytes()
        if len(raw) > 64 * 1024:
            raise ValueError("broker configuration exceeds 64 KiB")
        value = _json_object(raw, "broker configuration")
        if set(value) != _CONFIG_KEYS:
            raise ValueError("broker configuration has an unexpected field set")
        numeric = (
            "runner_uid",
            "runner_gid",
            "worker_uid",
            "worker_gid",
            "scratch_gid",
            "model_read_gid",
        )
        for key in numeric:
            if type(value[key]) is not int or value[key] < 0:
                raise ValueError(f"{key} must be a non-negative integer")
        if value["runner_uid"] == 0 or value["runner_gid"] == 0:
            raise ValueError("systemd runner must use a non-root user and group")
        if value["worker_uid"] == 0:
            raise ValueError("worker RPC must be owned by a non-root account")
        supplementary = _int_tuple(value["runner_supplementary_gids"], "runner_supplementary_gids")
        devices = _path_tuple(value["device_allow"], "device_allow")
        roots = _path_tuple(value["read_roots"], "read_roots")
        environment_paths = _path_tuple(
            value["environment_path_allowlist"], "environment_path_allowlist"
        )
        timeout = value["empty_timeout_seconds"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("empty_timeout_seconds must be positive")
        config = cls(
            database_path=_absolute_path(value["database_path"], "database_path"),
            socket_path=_absolute_path(value["socket_path"], "socket_path"),
            scratch_root=_absolute_path(value["scratch_root"], "scratch_root"),
            runner_executable=_absolute_path(value["runner_executable"], "runner_executable"),
            runner_uid=value["runner_uid"],
            runner_gid=value["runner_gid"],
            runner_supplementary_gids=supplementary,
            worker_uid=value["worker_uid"],
            worker_gid=value["worker_gid"],
            scratch_gid=value["scratch_gid"],
            model_read_gid=value["model_read_gid"],
            device_allow=devices,
            read_roots=roots,
            environment_path_allowlist=environment_paths,
            empty_timeout_seconds=float(timeout),
        )
        config.validate_host_paths()
        return config

    @property
    def runner_groups(self) -> frozenset[int]:
        return frozenset((self.runner_gid, *self.runner_supplementary_gids))

    @property
    def worker_groups(self) -> frozenset[int]:
        """Return keyed worker groups only when they match the broker policy."""
        worker = pwd.getpwuid(self.worker_uid)
        if worker.pw_uid != self.worker_uid or worker.pw_gid != self.worker_gid:
            raise PermissionError("worker account identity differs from broker policy")
        expected = frozenset((self.worker_gid, self.model_read_gid))
        return _account_group_ids(
            worker.pw_name,
            primary_gid=self.worker_gid,
            expected=expected,
            label="worker",
        )

    def validate_host_paths(self) -> None:
        """Fail closed unless configured identities and host paths are exact."""
        runner = pwd.getpwuid(self.runner_uid)
        worker = pwd.getpwuid(self.worker_uid)
        if runner.pw_uid != self.runner_uid:
            raise ValueError("NSS account UID does not match runner configuration")
        if worker.pw_uid != self.worker_uid:
            raise ValueError("NSS account UID does not match worker configuration")
        if runner.pw_gid != self.runner_gid:
            raise ValueError("configured runner name, UID, and primary group do not agree")
        if worker.pw_gid != self.worker_gid:
            raise ValueError("configured worker UID and primary group do not agree")
        if (
            self.model_read_gid <= 0
            or self.model_read_gid
            in {self.runner_gid, self.worker_gid, self.scratch_gid}
        ):
            raise ValueError("model-read group must be dedicated and non-root")
        if self.scratch_gid <= 0 or self.scratch_gid in {
            self.runner_gid,
            self.worker_gid,
        }:
            raise ValueError("scratch group must be dedicated and non-root")
        group_ids = {
            self.runner_gid,
            self.worker_gid,
            self.scratch_gid,
            self.model_read_gid,
            *self.runner_supplementary_gids,
        }
        for gid in sorted(group_ids):
            try:
                group = grp.getgrgid(gid)
            except (KeyError, OSError) as error:
                raise ValueError(f"keyed group lookup failed for configured GID {gid}") from error
            if group.gr_gid != gid:
                raise ValueError("keyed group identity differs from broker policy")
        try:
            _account_group_ids(
                runner.pw_name,
                primary_gid=self.runner_gid,
                expected=self.runner_groups,
                label="runner",
            )
        except PermissionError as error:
            raise ValueError("runner account groups differ from broker policy") from error
        try:
            self.worker_groups
        except PermissionError as error:
            raise ValueError("worker account groups differ from broker policy") from error
        if self.model_read_gid not in self.runner_supplementary_gids:
            raise ValueError("runner is not configured for the private model-read group")
        if self.scratch_gid not in self.runner_groups:
            raise ValueError("runner is not configured for the private scratch group")
        if self.scratch_gid in self.worker_groups:
            raise ValueError("worker account must not have access to runner scratch")
        if (
            self.worker_gid == self.runner_gid
            or self.worker_gid in self.runner_supplementary_gids
        ):
            raise ValueError("runner must not join the worker's publication group")
        _require_no_extended_posix_acl_ancestors(self.scratch_root)
        _require_root_directory(self.scratch_root)
        scratch_info = self.scratch_root.lstat()
        if (
            scratch_info.st_gid != self.scratch_gid
            or not (scratch_info.st_mode & 0o010)
        ):
            raise PermissionError("scratch root must grant traversal to the dedicated scratch group")
        _require_root_executable(self.runner_executable)
        executable_info = self.runner_executable.stat()
        if not _mode_allows(
            executable_info, self.runner_uid, self.runner_groups, read=True, execute=True
        ):
            raise PermissionError("configured runner account cannot execute the runner binary")
        if not self.read_roots:
            raise ValueError("at least one exact engine/model read root is required")
        for root in self.read_roots:
            _require_root_directory(root)
        for path in self.environment_path_allowlist:
            _require_root_directory(path)
        if not self.device_allow:
            raise ValueError("GPU execution requires an explicit device allowlist")
        for device in self.device_allow:
            info = device.stat(follow_symlinks=False)
            if not stat.S_ISCHR(info.st_mode):
                raise ValueError("configured GPU device is not a character device")
            if not _mode_allows(info, self.runner_uid, self.runner_groups, read=True, write=True):
                raise PermissionError(f"runner lacks read/write access to GPU device {device}")
        if self.runner_uid == self.worker_uid:
            raise ValueError("worker and engine runner accounts must be distinct")
        _require_root_owned_ancestors(self.database_path)
        try:
            database_info = self.database_path.lstat()
        except FileNotFoundError:
            database_info = None
        if database_info is not None and (
            stat.S_ISLNK(database_info.st_mode)
            or not stat.S_ISREG(database_info.st_mode)
        ):
            raise PermissionError("broker database path must be a regular file")
        evidence_path = SystemdEvidenceLedger.path_for(self.database_path)
        _require_no_extended_posix_acl_ancestors(evidence_path.parent)
        _require_root_directory(evidence_path.parent)
        try:
            evidence_path.lstat()
        except FileNotFoundError:
            pass
        else:
            _require_no_extended_posix_acl_ancestors(evidence_path)
        SystemdEvidenceLedger(evidence_path).validate_worker_access(
            self.worker_gid
        )


@dataclass
class _ActiveAttempt:
    identity: AttemptUnitIdentity
    process: subprocess.Popen[bytes]
    cgroup_events_fd: int
    scratch_directory: Path
    owner_id: str
    claim_epoch: int
    lock: threading.RLock
    done: threading.Event


class SystemdAttemptBroker:
    """Serve fixed attempt operations and retain authority over each unit."""

    def __init__(self, configuration: BrokerConfiguration) -> None:
        self.configuration = configuration
        self.store = SQLiteStore(configuration.database_path)
        self.store.initialize_systemd_evidence_ledger(
            worker_gid=configuration.worker_gid
        )
        self._active: dict[str, _ActiveAttempt] = {}
        self._active_lock = threading.RLock()
        self._server: socket.socket | None = None

    def serve_forever(self) -> None:
        """Run the privileged broker; installation remains a separate host action."""
        if os.geteuid() != 0:
            raise PermissionError("systemd attempt broker must run as root")
        if not _linux_cgroup_v2():
            raise RuntimeError("systemd attempt broker requires unified cgroup v2")
        self._open_server_socket()
        assert self._server is not None
        while True:
            connection, _ = self._server.accept()
            threading.Thread(
                target=self._serve_connection,
                args=(connection,),
                name="systemd-attempt-rpc",
                daemon=True,
            ).start()

    def _open_server_socket(self) -> None:
        path = self.configuration.socket_path
        _require_root_directory(path.parent)
        _require_no_extended_posix_acl_ancestors(path.parent)
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            raise FileExistsError("attempt broker socket path is already in use")
        os.chown(path.parent, 0, self.configuration.worker_gid)
        os.chmod(path.parent, 0o750)
        _require_root_directory(path.parent)
        _require_no_extended_posix_acl_ancestors(path.parent)
        parent_info = path.parent.lstat()
        if (
            parent_info.st_uid != 0
            or parent_info.st_gid != self.configuration.worker_gid
            or stat.S_IMODE(parent_info.st_mode) != 0o750
        ):
            raise PermissionError("broker socket directory ownership or mode is invalid")
        _require_directory_traversal(
            path.parent,
            self.configuration.worker_uid,
            self.configuration.worker_groups,
            label="configured worker cannot traverse the broker socket directory",
        )
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.bind(str(path))
        os.chmod(path, 0o660)
        os.chown(path, 0, self.configuration.worker_gid)
        server.listen(32)
        self._server = server

    def _serve_connection(self, connection: socket.socket) -> None:
        with connection:
            try:
                pid, uid, gid = _peer_credentials(connection)
                if uid != self.configuration.worker_uid or gid != self.configuration.worker_gid:
                    raise PermissionError("worker RPC peer has an unauthorized identity")
                _require_process_credentials(
                    pid,
                    uid=self.configuration.worker_uid,
                    gid=self.configuration.worker_gid,
                    supplementary_gids=frozenset(
                        {self.configuration.model_read_gid}
                    ),
                )
                packet, _ancillary, flags, _address = connection.recvmsg(_MAX_PACKET)
                if flags & getattr(socket, "MSG_TRUNC", 0):
                    raise ValueError("broker request exceeds the protocol limit")
                operation, request = _validated_request(packet)
                if operation == "prepare":
                    response = self._prepare(request)
                    _send(connection, response)
                elif operation == "execute":
                    response, output_fd = self._execute(connection, request)
                    try:
                        _send(connection, response, output_fd=output_fd)
                    finally:
                        if output_fd is not None:
                            os.close(output_fd)
                elif operation == "cancel":
                    _send(connection, self._cancel(request))
                elif operation == "output_ack":
                    _send(connection, self._output_ack(request))
                else:
                    _send(connection, self._recovery_cleanup(request))
            except Exception as error:
                try:
                    _send(
                        connection,
                        {"ok": False, "error": _safe_error_code(error)},
                    )
                except OSError:
                    pass

    def _prepare(self, request: Mapping[str, object]) -> dict[str, object]:
        job, attempt, owner, epoch = _claim_fields(request)
        self._require_current_claim(job, attempt, owner, epoch)
        scratch = self.configuration.scratch_root / attempt
        try:
            scratch.lstat()
        except FileNotFoundError:
            pass
        else:
            raise PermissionError("attempt scratch path already exists and cannot be reused")
        return {"ok": True, "scratch_directory": str(scratch)}

    def _execute(
        self, worker: socket.socket, request: Mapping[str, object]
    ) -> tuple[dict[str, object], int | None]:
        job, attempt, owner, epoch = _claim_fields(request)
        self._require_current_claim(job, attempt, owner, epoch)
        if (
            request.get("runner_uid") != self.configuration.runner_uid
            or request.get("runner_gid") != self.configuration.runner_gid
        ):
            raise PermissionError("requested runner identity differs from broker policy")
        resolved_record = _json_mapping(request.get("resolved_record"), "resolved_record")
        stored = self.store.get_backend_execution(job, attempt)
        if stored is None or stored.get("state") != "resolved":
            raise BackendEvidenceError("durable resolved invocation is unavailable")
        durable = stored.get("resolved")
        if not isinstance(durable, Mapping) or dict(durable) != dict(resolved_record):
            raise BackendEvidenceError("request differs from the exact durable resolved invocation")
        resolved_digest = backend_digest(durable)
        if request.get("resolved_digest") != resolved_digest or stored.get("resolved_digest") != resolved_digest:
            raise BackendEvidenceError("resolved invocation digest does not match SQLite")
        argv = _text_list(request.get("argv"), "argv")
        if argv != durable.get("argv"):
            raise BackendEvidenceError("argv differs from durable resolution")
        environment = _environment(request.get("environment"))
        if (
            not set(environment).issubset(ENVIRONMENT_ALLOWLIST)
            or environment_record(environment) != durable.get("environment")
        ):
            raise BackendEvidenceError("environment differs from durable resolution")
        self._validate_engine_environment(environment)
        scratch = self.configuration.scratch_root / attempt
        if request.get("scratch_directory") != str(scratch):
            raise PermissionError("scratch directory is not the broker-created attempt directory")
        self._validate_engine_paths(argv)
        unit = f"media-generation-attempt-{attempt[4:]}.service"
        if _unit_properties(unit) is not None:
            raise BackendEvidenceError("attempt unit name already exists and cannot be reused")
        self._create_attempt_scratch(attempt)
        try:
            runner_can_access = _mode_allows(
                scratch.stat(), self.configuration.runner_uid,
                self.configuration.runner_groups, read=True, write=True,
            )
            if not runner_can_access:
                raise PermissionError("runner cannot access attempt scratch")
        except Exception:
            self._remove_scratch(attempt)
            raise
        try:
            process = _start_systemd_run(self.configuration, unit, scratch)
        except Exception:
            self._remove_scratch(attempt)
            raise
        identity: AttemptUnitIdentity | None = None
        events_fd: int | None = None
        try:
            identity, events_fd = self._wait_for_containment(
                process, unit, job, attempt, owner, epoch, resolved_digest
            )
            if _read_populated(events_fd) != 1:
                raise BackendEvidenceError(
                    "runner service did not remain in its cgroup"
                )
            if not _unit_identity_live(identity):
                raise BackendEvidenceError(
                    "systemd unit identity changed during setup"
                )
        except Exception as setup_error:
            _stop_unit(unit)
            if identity is not None and events_fd is not None:
                try:
                    cleaned = self._cleanup_failed_containment_setup(
                        process, identity, events_fd
                    )
                except Exception:
                    cleaned = False
                finally:
                    os.close(events_fd)
                if not cleaned:
                    raise BackendEvidenceError(
                        "containment setup is unverified; scratch is retained and "
                        "capacity remains quarantined"
                    ) from setup_error
            raise
        assert identity is not None and events_fd is not None
        active = _ActiveAttempt(
            identity=identity,
            process=process,
            cgroup_events_fd=events_fd,
            scratch_directory=scratch,
            owner_id=owner,
            claim_epoch=epoch,
            lock=threading.RLock(),
            done=threading.Event(),
        )
        with self._active_lock:
            if attempt in self._active:
                os.close(events_fd)
                _stop_unit(unit)
                raise BackendEvidenceError("attempt already has a live broker session")
            self._active[attempt] = active
        payload = {
            "identity": identity.to_mapping(),
            "argv": argv,
            "environment": environment,
            "scratch_directory": str(scratch),
            "resolved_record": dict(durable),
        }
        lost = threading.Event()
        monitor_stop = threading.Event()
        monitor = threading.Thread(
            target=self._watch_worker_disconnect,
            args=(worker, active, lost, monitor_stop),
            name=f"attempt-worker-watch-{attempt}",
            daemon=True,
        )
        engine_observation: dict[str, object] | None = None
        runner_error: str | None = None
        runner_exit_code: int | None = None
        stream_complete = False
        monitor_started = False
        force_runner_stop = False
        runner_exit_properties: dict[str, str] | None = None
        try:
            monitor.start()
            monitor_started = True
            # Once the active record exists, every pipe setup failure must
            # follow the same stop, cgroup proof, and descriptor cleanup path.
            _write_line(process.stdin, payload)
            while True:
                message = _read_line(process.stdout)
                operation = message.get("operation")
                if operation == "verify_current":
                    current = self.store.assert_attempt_authority(job, attempt, owner, epoch)
                    _write_line(process.stdin, {"ok": True, "current": current})
                elif operation == "record_launch":
                    fact = _json_mapping(message.get("fact"), "launch fact")
                    self.store.mark_execution_launched(
                        job_id=job, attempt_id=attempt, owner_id=owner,
                        claim_epoch=epoch, record=fact, timestamp=_timestamp(),
                    )
                    _write_line(process.stdin, {"ok": True})
                elif operation == "record_observation":
                    fact = _json_mapping(message.get("fact"), "engine observation")
                    self.store.mark_execution_observed(
                        job_id=job, attempt_id=attempt, owner_id=owner,
                        claim_epoch=epoch, record=fact, timestamp=_timestamp(),
                    )
                    engine_observation = fact
                    _write_line(process.stdin, {"ok": True})
                elif operation == "complete":
                    engine_observation = _optional_mapping(
                        message.get("engine_observation"), "engine observation"
                    )
                    runner_exit_code = _optional_exit_code(
                        message.get("runner_exit_code"), "runner_exit_code"
                    )
                    stream_complete = message.get("stream_complete") is True
                    break
                elif operation == "runner_error":
                    runner_error = _safe_error_code(message)
                    runner_exit_code = _optional_exit_code(
                        message.get("runner_exit_code"), "runner_exit_code"
                    )
                    break
                else:
                    raise BackendEvidenceError("runner sent an unknown control operation")
        except Exception as error:
            runner_error = _safe_error_code(error)
            force_runner_stop = True
            _stop_unit(unit)
        finally:
            monitor_stop.set()
            if monitor_started:
                monitor.join(timeout=1.0)

        if lost.is_set():
            try:
                self.store.fence_attempt_for_recovery(
                    job, attempt, timestamp=_timestamp()
                )
            except Exception as error:
                runner_error = runner_error or _safe_error_code(error)
            finally:
                force_runner_stop = True
                _stop_unit(unit)
        if force_runner_stop:
            _stop_unit(unit)
        else:
            try:
                runner_exit_properties = self._wait_for_runner_exit(
                    identity, timeout=self.configuration.empty_timeout_seconds
                )
            except Exception as error:
                runner_error = runner_error or _safe_error_code(error)
                _stop_unit(unit)
        if runner_exit_properties is not None:
            # A successful transient service stays loaded with RemainAfterExit.
            # Capture its verified exit result before StopUnit can unload it.
            _stop_unit(unit)
        # On cancellation, worker loss, or an incomplete runner result, the
        # pinned cgroup event remains the termination authority even if systemd
        # has already unloaded the stopped unit. populated=0 cannot occur until
        # the runner and every other process in the cgroup have exited.
        empty = _wait_cgroup_empty(
            active.cgroup_events_fd,
            timeout=self.configuration.empty_timeout_seconds,
        )
        if not empty:
            _stop_unit(unit)
            empty = _wait_cgroup_empty(
                active.cgroup_events_fd,
                timeout=self.configuration.empty_timeout_seconds,
            )
        # This event descriptor was opened only after the exact unit
        # invocation and cgroup inode were validated. It pins that cgroup
        # object across StopUnit and systemd garbage collection.
        termination = None
        if empty:
            try:
                termination = _record_pinned_empty_event(
                    self.store, identity, active.cgroup_events_fd
                )
            except Exception as error:
                runner_error = runner_error or _safe_error_code(error)
        unit_result = (
            "unknown"
            if runner_exit_properties is None
            else runner_exit_properties.get("Result", "unknown")
        )
        runner_status = (
            None
            if runner_exit_properties is None
            else _int_property(runner_exit_properties.get("ExecMainStatus"))
        )
        runner_exit_signal: int | None = None
        runner_code_kind = (
            None
            if runner_exit_properties is None
            else _int_property(runner_exit_properties.get("ExecMainCode"))
        )
        if runner_code_kind == 1 and runner_status is not None:
            if runner_exit_code is not None and runner_exit_code != runner_status:
                runner_error = runner_error or "runner_exit_status_mismatch"
            runner_exit_code = runner_status
        elif runner_code_kind in {2, 3} and runner_status is not None:
            if runner_exit_code is not None:
                runner_error = runner_error or "runner_exit_status_mismatch"
            runner_exit_code = None
            runner_exit_signal = runner_status
            runner_error = runner_error or "runner_signaled"
        elif runner_exit_properties is not None:
            runner_error = runner_error or "runner_did_not_exit_cleanly"
            runner_exit_code = None
        _stop_unit(unit)
        launcher_exit_code: int | None
        try:
            launcher_exit_code = process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            launcher_exit_code = None
            try:
                process.terminate()
            except OSError:
                pass
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
            os.close(active.cgroup_events_fd)
            active.done.set()
            if termination is None:
                with self._active_lock:
                    self._active.pop(attempt, None)

        if engine_observation is not None:
            persisted = self.store.get_backend_execution(job, attempt)
            if (
                persisted is None
                or persisted.get("state") != "observed"
                or persisted.get("observed") != engine_observation
            ):
                raise BackendEvidenceError("runner completion differs from durable engine evidence")
        output_fd = None
        if (
            termination is not None
            and runner_error is None
            and runner_exit_code == 0
            and launcher_exit_code == 0
            and unit_result == "success"
            and stream_complete
            and engine_observation is not None
            and engine_observation.get("exit_code") == 0
            and engine_observation.get("signal") is None
        ):
            try:
                output_fd = self._open_output(scratch, durable, identity)
            except Exception as error:
                # The worker receives a failed completion and acknowledges
                # scratch cleanup after it has observed durable termination.
                runner_error = _safe_error_code(error)
        response = {
            "ok": True,
            "identity": identity.to_mapping(),
            "runner_exit_code": runner_exit_code,
            "runner_exit_signal": runner_exit_signal,
            "launcher_exit_code": launcher_exit_code,
            "unit_result": unit_result,
            "engine_observation": engine_observation,
            "termination_evidence": None if termination is None else termination.to_mapping(),
            "stream_complete": stream_complete,
            "error_code": runner_error,
        }
        return response, output_fd

    def _wait_for_runner_exit(
        self, identity: AttemptUnitIdentity, *, timeout: float
    ) -> dict[str, str]:
        """Observe the exact service main-process exit before cgroup proof."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            properties = _unit_properties(identity.unit_name)
            if properties is None:
                raise BackendEvidenceError(
                    "attempt unit disappeared before runner exit was verified"
                )
            if (
                properties.get("InvocationID") != identity.invocation_id
                or properties.get("ControlGroup") != identity.cgroup_path
            ):
                raise BackendEvidenceError(
                    "attempt unit identity changed before runner exit"
                )
            main_pid = _int_property(properties.get("MainPID"))
            main_code = _int_property(properties.get("ExecMainCode"))
            if main_pid == 0 and main_code in {1, 2, 3}:
                return properties
            time.sleep(0.02)
        raise TimeoutError("systemd did not report runner process exit")

    def _wait_for_containment(
        self,
        process: subprocess.Popen[bytes],
        unit: str,
        job: str,
        attempt: str,
        owner: str,
        epoch: int,
        resolved_digest: str,
    ) -> tuple[AttemptUnitIdentity, int]:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("systemd launcher exited before containment was established")
            properties = _unit_properties(unit)
            if properties is None:
                time.sleep(0.02)
                continue
            _validate_unit_policy(properties, self.configuration)
            invocation = properties.get("InvocationID", "")
            cgroup = properties.get("ControlGroup", "")
            expected_cgroup = f"/system.slice/{unit}"
            if not _is_invocation_id(invocation) or cgroup != expected_cgroup:
                time.sleep(0.02)
                continue
            main_pid = _int_property(properties.get("MainPID"))
            if main_pid is None or main_pid <= 0:
                time.sleep(0.02)
                continue
            _require_process_credentials(
                main_pid,
                uid=self.configuration.runner_uid,
                gid=self.configuration.runner_gid,
                supplementary_gids=frozenset(
                    self.configuration.runner_supplementary_gids
                ),
                cgroup_path=cgroup,
            )
            cgroup_directory = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
            directory_fd = os.open(
                cgroup_directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                observed = os.fstat(directory_fd)
                if not stat.S_ISDIR(observed.st_mode):
                    raise BackendEvidenceError("systemd cgroup path is not a directory")
                events_fd = os.open(
                    "cgroup.events",
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            finally:
                os.close(directory_fd)
            identity = AttemptUnitIdentity(
                version=1,
                job_id=job,
                attempt_id=attempt,
                owner_id=owner,
                claim_epoch=epoch,
                resolved_digest=resolved_digest,
                boot_id=_boot_id(),
                unit_name=unit,
                invocation_id=invocation,
                cgroup_path=cgroup,
                cgroup_device=observed.st_dev,
                cgroup_inode=observed.st_ino,
                runner_uid=self.configuration.runner_uid,
                runner_gid=self.configuration.runner_gid,
            )
            try:
                self.store.bind_attempt_containment(identity, timestamp=_timestamp())
            except Exception:
                os.close(events_fd)
                raise
            return identity, events_fd
        raise TimeoutError("systemd attempt did not establish its unit identity")

    def _cleanup_failed_containment_setup(
        self,
        process: subprocess.Popen[bytes],
        identity: AttemptUnitIdentity,
        events_fd: int,
    ) -> bool:
        """Remove setup scratch only after durable empty-cgroup and launcher proof."""
        stored = self.store.attempt_containment_identity(
            identity.job_id, identity.attempt_id
        )
        if stored != identity:
            return False
        empty = _wait_cgroup_empty(
            events_fd, timeout=self.configuration.empty_timeout_seconds
        )
        if not empty:
            _stop_unit(identity.unit_name)
            empty = _wait_cgroup_empty(
                events_fd, timeout=self.configuration.empty_timeout_seconds
            )
        if not empty:
            return False
        _record_pinned_empty_event(self.store, identity, events_fd)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                process.terminate()
            except OSError:
                pass
            try:
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                return False
        except OSError:
            return False
        for stream_name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, stream_name, None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        self._remove_scratch(identity.attempt_id)
        return True

    def _watch_worker_disconnect(
        self,
        worker: socket.socket,
        active: _ActiveAttempt,
        lost: threading.Event,
        stop: threading.Event,
    ) -> None:
        while not stop.wait(0.05):
            try:
                readable, _, _ = select.select([worker], [], [], 0)
            except (OSError, ValueError):
                readable = [worker]
            if not readable:
                continue
            try:
                unexpected = worker.recv(1, socket.MSG_PEEK)
            except OSError:
                unexpected = b""
            if unexpected == b"":
                lost.set()
                try:
                    self.store.fence_attempt_for_recovery(
                        active.identity.job_id,
                        active.identity.attempt_id,
                        timestamp=_timestamp(),
                    )
                except Exception:
                    pass
                finally:
                    _stop_unit(active.identity.unit_name)
                return
            # The request is one packet; extra data is a protocol violation.
            lost.set()
            try:
                self.store.fence_attempt_for_recovery(
                    active.identity.job_id,
                    active.identity.attempt_id,
                    timestamp=_timestamp(),
                )
            except Exception:
                pass
            finally:
                _stop_unit(active.identity.unit_name)
            return

    def _cancel(self, request: Mapping[str, object]) -> dict[str, object]:
        job, attempt, owner, epoch = _claim_fields(request)
        identity = self.store.attempt_containment_identity(job, attempt)
        if identity is None or identity.owner_id != owner or identity.claim_epoch != epoch:
            raise BackendEvidenceError("cancel request does not match a bound attempt")
        if self.store.attempt_termination_proven(job, attempt):
            return {"ok": True, "outcome": "acknowledged"}
        active = self._active_for(identity)
        if active is not None:
            _stop_unit(identity.unit_name)
            if not active.done.wait(self.configuration.empty_timeout_seconds * 2):
                return {"ok": True, "outcome": "requested"}
            return {
                "ok": True,
                "outcome": (
                    "acknowledged"
                    if self.store.attempt_termination_proven(job, attempt)
                    else "requested"
                ),
            }
        termination = self._stop_and_record(identity)
        return {
            "ok": True,
            "outcome": "acknowledged" if termination else "requested",
        }

    def _stop_and_record(
        self, identity: AttemptUnitIdentity
    ) -> CgroupTerminationEvidence | None:
        if identity.boot_id != _boot_id():
            return None
        properties = _unit_properties(identity.unit_name)
        if properties is None or (
            properties.get("InvocationID") != identity.invocation_id
            or properties.get("ControlGroup") != identity.cgroup_path
        ):
            return None
        cgroup = Path("/sys/fs/cgroup") / identity.cgroup_path.lstrip("/")
        directory_fd: int | None = None
        events_fd: int | None = None
        try:
            directory_fd = os.open(
                cgroup,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            observed = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(observed.st_mode)
                or (observed.st_dev, observed.st_ino)
                != (identity.cgroup_device, identity.cgroup_inode)
            ):
                return None
            events_fd = os.open(
                "cgroup.events",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            pinned = os.fstat(directory_fd)
            if (pinned.st_dev, pinned.st_ino) != (
                identity.cgroup_device,
                identity.cgroup_inode,
            ):
                return None
            # StopUnit accepts only a unit name. Re-read the exact invocation
            # immediately before calling it so a reused name is never stopped.
            current_properties = _unit_properties(identity.unit_name)
            if current_properties is None or (
                current_properties.get("InvocationID") != identity.invocation_id
                or current_properties.get("ControlGroup") != identity.cgroup_path
            ):
                return None
            current = os.fstat(directory_fd)
            if (current.st_dev, current.st_ino) != (
                identity.cgroup_device,
                identity.cgroup_inode,
            ):
                return None
            _stop_unit(identity.unit_name)
            if not _wait_cgroup_empty(
                events_fd,
                timeout=self.configuration.empty_timeout_seconds,
            ):
                return None
            # The event FD remains attached to the verified cgroup even if
            # StopUnit unloads the unit or removes its pathname.
            return _record_pinned_empty_event(self.store, identity, events_fd)
        except OSError:
            return None
        finally:
            if events_fd is not None:
                os.close(events_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    def _output_ack(self, request: Mapping[str, object]) -> dict[str, object]:
        identity = AttemptUnitIdentity.from_mapping(
            _json_mapping(request.get("identity"), "identity")
        )
        validated = request.get("validated")
        if type(validated) is not bool:
            raise ValueError("validated must be a boolean")
        self._require_identity(identity)
        if not self.store.systemd_output_cleanup_authorized(
            identity, validated=validated
        ):
            raise BackendEvidenceError(
                "validated scratch cleanup requires committed success evidence"
                if validated
                else "unvalidated scratch cleanup requires terminal attempt and reconciled publication"
            )
        self._cleanup_pinned_scratch(identity)
        return {"ok": True, "acknowledged": True}

    def _create_attempt_scratch(self, attempt: str) -> None:
        """Create the attempt directory only after durable resolution is checked."""
        scratch = self.configuration.scratch_root / attempt
        try:
            os.mkdir(scratch, 0o700)
            os.chown(scratch, 0, self.configuration.scratch_gid)
            os.chmod(scratch, 0o2770)
        except FileExistsError as error:
            raise PermissionError(
                "attempt scratch path already exists and cannot be reused"
            ) from error
        except Exception:
            try:
                os.rmdir(scratch)
            except OSError:
                pass
            raise

    def _recovery_cleanup(self, request: Mapping[str, object]) -> dict[str, object]:
        identity = AttemptUnitIdentity.from_mapping(
            _json_mapping(request.get("identity"), "identity")
        )
        self._require_identity(identity)
        if not self.store.attempt_termination_proven(
            identity.job_id,
            identity.attempt_id,
            require_current_attempt=False,
        ):
            raise BackendEvidenceError("recovery cleanup requires durable cgroup-empty proof")
        if not self.store.attempt_recovery_cleanup_authorized(identity):
            raise BackendEvidenceError(
                "recovery scratch cleanup requires fenced publication and reconciled journals"
            )
        self._cleanup_pinned_scratch(identity)
        return {"ok": True, "acknowledged": True}

    def _cleanup_pinned_scratch(self, identity: AttemptUnitIdentity) -> None:
        """Serialize output acknowledgement and recovery cleanup per attempt."""
        active = self._active_for(identity)
        if active is None:
            self._remove_scratch(identity.attempt_id)
            return
        if not active.done.wait(self.configuration.empty_timeout_seconds * 2):
            raise BackendEvidenceError(
                "runner launcher has not completed; scratch cleanup is deferred"
            )
        with active.lock:
            if not self.store.attempt_termination_proven(
                identity.job_id,
                identity.attempt_id,
                require_current_attempt=False,
            ):
                raise BackendEvidenceError(
                    "scratch cleanup lost its durable cgroup termination proof"
                )
            self._remove_scratch(identity.attempt_id)
            with self._active_lock:
                if self._active.get(identity.attempt_id) is active:
                    self._active.pop(identity.attempt_id, None)

    def _require_identity(self, identity: AttemptUnitIdentity) -> None:
        stored = self.store.attempt_containment_identity(
            identity.job_id, identity.attempt_id
        )
        if stored != identity:
            raise BackendEvidenceError("broker request names a stale or reused unit")

    def _require_current_claim(
        self, job: str, attempt: str, owner: str, epoch: int
    ) -> None:
        current = self.store.current_attempt(job)
        if (
            current is None
            or current.get("attempt_id") != attempt
            or current.get("owner_id") != owner
            or current.get("claim_epoch") != epoch
            or current.get("containment_contract") != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            or not self.store.assert_attempt_authority(job, attempt, owner, epoch)
        ):
            raise PermissionError("attempt claim is stale or not systemd-qualified")

    def _active_for(self, identity: AttemptUnitIdentity) -> _ActiveAttempt | None:
        with self._active_lock:
            active = self._active.get(identity.attempt_id)
            if active is None or active.identity != identity:
                return None
            return active

    def _validate_engine_paths(self, argv: list[str]) -> None:
        paths: list[tuple[Path, bool]] = [(Path(argv[0]), True)]
        for index, item in enumerate(argv[:-1]):
            if item in {
                "--diffusion-model",
                "--vae",
                "--llm",
                "--llm_vision",
                "-r",
            }:
                paths.append(
                    (
                        Path(argv[index + 1]),
                        False,
                    )
                )
        validated_paths: list[tuple[Path, bool]] = []
        for path, executable in paths:
            if not path.is_absolute():
                raise PermissionError("engine invocation contains a non-absolute input path")
            _require_no_symlink_components(path)
            resolved = path.resolve(strict=True)
            allowed = any(
                resolved.is_relative_to(root.resolve())
                for root in self.configuration.read_roots
            )
            if not allowed:
                raise PermissionError("engine input path is outside broker read roots")
            _require_no_extended_posix_acl_ancestors(resolved)
            validated_paths.append((resolved, executable))

        for resolved, executable in validated_paths:
            _require_root_owned_ancestors(resolved)
            _require_directory_traversal(
                resolved.parent,
                self.configuration.runner_uid,
                self.configuration.runner_groups,
                label="configured runner cannot traverse an engine input directory",
            )
            _require_directory_traversal(
                resolved.parent,
                self.configuration.worker_uid,
                self.configuration.worker_groups,
                label="configured worker cannot traverse an engine input directory",
            )
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode):
                raise PermissionError("engine input path is not a regular file")
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError(
                    "engine input must be root-owned and not worker-writable"
                )
            if info.st_mode & 0o004:
                raise PermissionError("private engine input must not be world-readable")
            if not _mode_allows(
                info,
                self.configuration.runner_uid,
                self.configuration.runner_groups,
                read=True,
                execute=executable,
            ):
                raise PermissionError("configured runner cannot read an engine input")
            if not _mode_allows(
                info,
                self.configuration.worker_uid,
                self.configuration.worker_groups,
                read=True,
            ):
                raise PermissionError("configured worker cannot read an engine input")

    def _validate_engine_environment(self, environment: Mapping[str, str]) -> None:
        """Allow only fixed, protected directories in executable search paths."""
        for name in ("LD_LIBRARY_PATH", "PATH"):
            value = environment.get(name)
            if value is None:
                continue
            entries = value.split(os.pathsep)
            if not value or any(not entry for entry in entries):
                raise PermissionError("engine environment search path has an empty entry")
            for entry in entries:
                self._validate_environment_path(entry, search_variable=name)

        rocm_path = environment.get("ROCM_PATH")
        if rocm_path is not None:
            self._validate_environment_path(rocm_path)
            self._validate_rocm_release_marker(Path(rocm_path))

    def _validate_environment_path(
        self, value: str, *, search_variable: str | None = None
    ) -> None:
        """Recheck one configured search directory immediately before launch."""
        path = Path(value)
        if not path.is_absolute() or str(path) != value:
            raise PermissionError("engine environment search path is not absolute and normalized")
        try:
            info = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise PermissionError("engine environment search path is unavailable") from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or resolved != path
            or path not in self.configuration.environment_path_allowlist
        ):
            raise PermissionError("engine environment search path is not authorized")
        _require_root_directory(path)
        _require_directory_traversal(
            path,
            self.configuration.runner_uid,
            self.configuration.runner_groups,
            label="configured runner cannot traverse an engine environment directory",
        )
        _require_directory_traversal(
            path,
            self.configuration.worker_uid,
            self.configuration.worker_groups,
            label="configured worker cannot traverse an engine environment directory",
        )
        if search_variable is not None:
            _require_no_extended_posix_acl_ancestors(resolved)
            self._validate_environment_search_files(path, search_variable=search_variable)

    def _validate_environment_search_files(
        self, directory: Path, *, search_variable: str
    ) -> None:
        """Check every loader-visible runtime file and directory before launch."""
        if search_variable not in {"LD_LIBRARY_PATH", "PATH"}:
            raise ValueError("unsupported engine environment search variable")

        def inspect(candidate: Path, *, inspect_subdirectories: bool) -> None:
            try:
                info = candidate.lstat()
            except OSError as error:
                raise PermissionError("engine environment search file is unavailable") from error
            is_symlink = stat.S_ISLNK(info.st_mode)
            if is_symlink:
                info = self._resolve_protected_environment_entry(candidate)
            else:
                _require_no_extended_posix_acl(candidate)
            if stat.S_ISDIR(info.st_mode):
                if not inspect_subdirectories:
                    return
                if is_symlink:
                    raise PermissionError(
                        "engine runtime search subdirectory symlinks are not allowed"
                    )
                if info.st_uid != 0:
                    raise PermissionError(
                        "engine runtime search directory must be root-owned"
                    )
                if (
                    info.st_mode & 0o022
                    or _mode_allows(
                        info,
                        self.configuration.worker_uid,
                        self.configuration.worker_groups,
                        write=True,
                    )
                    or _mode_allows(
                        info,
                        self.configuration.runner_uid,
                        self.configuration.runner_groups,
                        write=True,
                    )
                ):
                    raise PermissionError(
                        "engine runtime search directory is worker-writable"
                    )
                for uid, groups, label in (
                    (
                        self.configuration.runner_uid,
                        self.configuration.runner_groups,
                        "runner",
                    ),
                    (
                        self.configuration.worker_uid,
                        self.configuration.worker_groups,
                        "worker",
                    ),
                ):
                    if not _mode_allows(
                        info, uid, groups, read=True, execute=True
                    ):
                        raise PermissionError(
                            f"configured {label} cannot search an engine runtime directory"
                        )
                try:
                    nested = sorted(
                        candidate.iterdir(), key=lambda item: item.name
                    )
                except OSError as error:
                    raise PermissionError(
                        "engine runtime subdirectory cannot be inspected"
                    ) from error
                for item in nested:
                    inspect(item, inspect_subdirectories=True)
                return
            if not stat.S_ISREG(info.st_mode):
                raise PermissionError("engine environment search entry is not a regular file")
            if info.st_uid != 0:
                raise PermissionError("engine environment search file must be root-owned")
            if (
                info.st_mode & 0o022
                or _mode_allows(
                    info,
                    self.configuration.worker_uid,
                    self.configuration.worker_groups,
                    write=True,
                )
                or _mode_allows(
                    info,
                    self.configuration.runner_uid,
                    self.configuration.runner_groups,
                    write=True,
                )
            ):
                raise PermissionError(
                    "engine environment search file is worker-writable"
                )

            if search_variable == "LD_LIBRARY_PATH":
                if not _mode_allows(
                    info,
                    self.configuration.runner_uid,
                    self.configuration.runner_groups,
                    read=True,
                ):
                    raise PermissionError(
                        "configured runner cannot read an engine runtime search file"
                    )
                if not _mode_allows(
                    info,
                    self.configuration.worker_uid,
                    self.configuration.worker_groups,
                    read=True,
                ):
                    raise PermissionError(
                        "configured worker cannot read an engine runtime search file"
                    )
            elif info.st_mode & 0o111 and not _mode_allows(
                info,
                self.configuration.runner_uid,
                self.configuration.runner_groups,
                execute=True,
            ):
                raise PermissionError(
                    "configured runner cannot execute an engine PATH search file"
                )

        try:
            candidates = sorted(directory.iterdir(), key=lambda candidate: candidate.name)
        except OSError as error:
            raise PermissionError("engine environment search directory cannot be inspected") from error
        for candidate in candidates:
            inspect(
                candidate,
                inspect_subdirectories=search_variable == "LD_LIBRARY_PATH",
            )

    def _resolve_protected_environment_entry(self, path: Path) -> os.stat_result:
        """Resolve symlinks while checking every path component for replacement."""
        if not path.is_absolute():
            raise PermissionError("engine environment symlink target is not absolute")
        current = Path(path.anchor)
        pending = list(path.parts[1:])
        symlink_count = 0
        while pending:
            component = pending.pop(0)
            if component in {"", "."}:
                continue
            if component == "..":
                current = current.parent
                continue
            entry = current / component
            try:
                info = entry.lstat()
            except OSError as error:
                raise PermissionError(
                    "engine environment symlink target cannot be verified"
                ) from error
            if stat.S_ISLNK(info.st_mode):
                symlink_count += 1
                if symlink_count > 40:
                    raise PermissionError("engine environment symlink chain is too deep")
                if info.st_uid != 0:
                    raise PermissionError("engine environment symlink must be root-owned")
                try:
                    target = Path(os.readlink(entry))
                except OSError as error:
                    raise PermissionError(
                        "engine environment symlink cannot be read"
                    ) from error
                if target.is_absolute():
                    current = Path(target.anchor)
                    pending = [*target.parts[1:], *pending]
                else:
                    pending = [*target.parts, *pending]
                continue
            _require_no_extended_posix_acl(entry)
            if stat.S_ISDIR(info.st_mode):
                sticky_protected = bool(info.st_mode & stat.S_ISVTX)
                if info.st_uid != 0 or (info.st_mode & 0o022 and not sticky_protected):
                    raise PermissionError(
                        "engine environment symlink directory is replaceable"
                    )
                if not _mode_allows(
                    info,
                    self.configuration.runner_uid,
                    self.configuration.runner_groups,
                    execute=True,
                ) or not _mode_allows(
                    info,
                    self.configuration.worker_uid,
                    self.configuration.worker_groups,
                    execute=True,
                ):
                    raise PermissionError(
                        "engine environment symlink target directory cannot be traversed"
                    )
                current = entry
                continue
            return info
        try:
            info = current.lstat()
            if not stat.S_ISLNK(info.st_mode):
                _require_no_extended_posix_acl(current)
            return info
        except OSError as error:
            raise PermissionError(
                "engine environment symlink target cannot be verified"
            ) from error

    def _validate_rocm_release_marker(self, rocm_path: Path) -> None:
        marker = rocm_path / ".info" / "version"
        try:
            _require_root_owned_ancestors(marker)
            _require_no_extended_posix_acl_ancestors(marker)
            info = marker.lstat()
        except OSError as error:
            raise PermissionError("configured ROCm release marker is unavailable") from error
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not info.st_mode & 0o444
            or info.st_size <= 0
            or info.st_size > 256
        ):
            raise PermissionError("configured ROCm release marker is unsafe or unreadable")
        if not _mode_allows(
            info, self.configuration.worker_uid, self.configuration.worker_groups, read=True
        ) or not _mode_allows(
            info, self.configuration.runner_uid, self.configuration.runner_groups, read=True
        ):
            raise PermissionError("configured worker or runner cannot read the ROCm marker")
        _require_directory_traversal(
            marker.parent,
            self.configuration.worker_uid,
            self.configuration.worker_groups,
            label="configured worker cannot traverse the ROCm release marker directory",
        )
        _require_directory_traversal(
            marker.parent,
            self.configuration.runner_uid,
            self.configuration.runner_groups,
            label="configured runner cannot traverse the ROCm release marker directory",
        )
        try:
            if not marker.read_text(encoding="utf-8").strip():
                raise PermissionError("configured ROCm release marker is empty")
        except (OSError, UnicodeError) as error:
            raise PermissionError("configured ROCm release marker is unreadable") from error

    def _open_output(
        self,
        scratch: Path,
        resolved: Mapping[str, object],
        identity: AttemptUnitIdentity,
    ) -> int:
        basename = resolved.get("output_basename")
        if not isinstance(basename, str) or Path(basename).name != basename:
            raise BackendEvidenceError("resolved output basename is malformed")
        output_path = scratch / basename
        descriptor = os.open(
            output_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != identity.runner_uid
            or info.st_gid not in self.configuration.runner_groups
            or info.st_nlink != 1
            or info.st_size <= 0
            or info.st_size > _MAX_OUTPUT_BYTES
        ):
            os.close(descriptor)
            raise BackendEvidenceError("runner output is not a bounded regular scratch file")
        return descriptor

    def _remove_scratch(self, attempt: str) -> None:
        scratch = self.configuration.scratch_root / attempt
        if scratch.parent != self.configuration.scratch_root or not _safe_attempt_id(attempt):
            raise PermissionError("scratch cleanup path is not attempt-scoped")
        try:
            observed = scratch.lstat()
        except FileNotFoundError:
            return
        if (
            not stat.S_ISDIR(observed.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or observed.st_uid != 0
            or observed.st_gid != self.configuration.scratch_gid
        ):
            raise PermissionError("scratch directory ownership changed")
        if not shutil.rmtree.avoids_symlink_attacks:
            raise RuntimeError("safe descriptor-relative scratch removal is unavailable")
        shutil.rmtree(scratch)


def _start_systemd_run(
    config: BrokerConfiguration, unit: str, scratch: Path
) -> subprocess.Popen[bytes]:
    """Start only the fixed runner with broker-owned properties and identity."""
    command = [
        "/usr/bin/systemd-run",
        "--system",
        "--quiet",
        "--pipe",
        "--wait",
        f"--unit={unit}",
        "--service-type=exec",
        f"--working-directory={scratch}",
        f"--property=User={config.runner_uid}",
        f"--property=Group={config.runner_gid}",
        "--property=RemainAfterExit=yes",
        "--property=KillMode=control-group",
        "--property=Delegate=no",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateDevices=no",
        "--property=DevicePolicy=closed",
        f"--property=ReadWritePaths={scratch}",
        "--property=CapabilityBoundingSet=",
        "--property=RestrictSUIDSGID=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectControlGroups=yes",
        "--property=RestrictNamespaces=yes",
        "--property=UMask=0077",
    ]
    if config.runner_supplementary_gids:
        groups = " ".join(str(gid) for gid in config.runner_supplementary_gids)
        command.append(f"--property=SupplementaryGroups={groups}")
    for device in config.device_allow:
        command.append(f"--property=DeviceAllow={device} rw")
    command.extend(["--", str(config.runner_executable)])
    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        bufsize=0,
    )


def _unit_properties(unit: str) -> dict[str, str] | None:
    if not unit.startswith("media-generation-attempt-") or not unit.endswith(".service"):
        raise ValueError("unit name is outside the attempt broker namespace")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/systemctl", "show", "--no-pager",
                "--property=InvocationID", "--property=ControlGroup",
                "--property=User", "--property=Group",
                "--property=KillMode", "--property=Delegate",
                "--property=RemainAfterExit", "--property=DevicePolicy",
                "--property=ProtectSystem", "--property=ProtectHome",
                "--property=NoNewPrivileges",
                "--property=MainPID", "--property=ExecMainPID",
                "--property=Result", "--property=ExecMainCode",
                "--property=ExecMainStatus", unit,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )


def _stop_unit(unit: str) -> bool:
    if not unit.startswith("media-generation-attempt-") or not unit.endswith(".service"):
        raise ValueError("refusing to stop a unit outside the attempt namespace")
    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "stop", "--no-block", unit],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _unit_identity_live(identity: AttemptUnitIdentity) -> bool:
    """Require the live unit and cgroup inode to match before recording proof."""
    properties = _unit_properties(identity.unit_name)
    if (
        properties is None
        or properties.get("InvocationID") != identity.invocation_id
        or properties.get("ControlGroup") != identity.cgroup_path
    ):
        return False
    directory = Path("/sys/fs/cgroup") / identity.cgroup_path.lstrip("/")
    try:
        info = directory.stat(follow_symlinks=False)
    except OSError:
        return False
    return (info.st_dev, info.st_ino) == (
        identity.cgroup_device,
        identity.cgroup_inode,
    )


def _wait_cgroup_empty(descriptor: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    poller = selectors.DefaultSelector()
    try:
        poller.register(descriptor, selectors.EVENT_READ)
        while True:
            try:
                if _read_populated(descriptor) == 0:
                    return True
            except OSError:
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            poller.select(min(remaining, 0.25))
    finally:
        poller.close()


def _read_populated(descriptor: int) -> int:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 4096).decode("ascii")
    values = [line.partition(" ")[2] for line in raw.splitlines() if line.startswith("populated ")]
    if len(values) != 1 or values[0] not in {"0", "1"}:
        raise BackendEvidenceError("cgroup.events lacks one valid populated value")
    return int(values[0])


def _record_pinned_empty_event(
    store: SQLiteStore, identity: AttemptUnitIdentity, events_fd: int
) -> CgroupTerminationEvidence | None:
    """Persist empty-state evidence from the descriptor pinned to this cgroup.

    The caller must have opened the descriptor only after validating the live
    systemd invocation and cgroup device/inode. Once pinned, the descriptor
    remains the authority even if StopUnit lets systemd unload the unit and
    remove its pathname. A missing descriptor or nonempty event never proves
    termination.
    """
    try:
        if _read_populated(events_fd) != 0:
            return None
    except OSError:
        return None
    proof = CgroupTerminationEvidence(
        identity=identity,
        populated=0,
        observed_monotonic_ns=time.monotonic_ns(),
        observed_at=_timestamp(),
    )
    store.record_attempt_termination_evidence(
        identity, proof, timestamp=_timestamp()
    )
    return proof


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def _read_process_credentials(
    pid: int, *, proc_root: Path = Path("/proc")
) -> tuple[tuple[int, ...], tuple[int, ...], frozenset[int], str]:
    """Read one pinned process's kernel UID, GID, groups, and cgroup identity."""
    if type(pid) is not int or pid <= 0:
        raise PermissionError("process ID is invalid")
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    process_fd = os.open(Path(proc_root) / str(pid), directory_flags)
    try:
        def read_at(name: str) -> str:
            descriptor = os.open(name, file_flags, dir_fd=process_fd)
            try:
                contents = bytearray()
                while len(contents) <= 1024 * 1024:
                    chunk = os.read(
                        descriptor,
                        min(65536, 1024 * 1024 + 1 - len(contents)),
                    )
                    if not chunk:
                        break
                    contents.extend(chunk)
                if len(contents) > 1024 * 1024:
                    raise PermissionError("process status exceeds the verification limit")
            finally:
                os.close(descriptor)
            try:
                return contents.decode("ascii")
            except UnicodeError as error:
                raise PermissionError("process status is not valid ASCII") from error

        status = read_at("status")
        cgroup = read_at("cgroup")
    finally:
        os.close(process_fd)

    fields: dict[str, tuple[int, ...]] = {}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if key not in {"Pid", "Uid", "Gid", "Groups"}:
            continue
        if not separator or key in fields:
            raise PermissionError("process status identity fields are malformed")
        try:
            values = tuple(int(token, 10) for token in value.split())
        except ValueError as error:
            raise PermissionError("process status contains an invalid identity field") from error
        if any(item < 0 for item in values):
            raise PermissionError("process status contains a negative identity value")
        fields[key] = values

    if (
        fields.get("Pid") != (pid,)
        or len(fields.get("Uid", ())) != 4
        or len(fields.get("Gid", ())) != 4
        or "Groups" not in fields
    ):
        raise PermissionError("process status omits complete kernel credentials")
    cgroups = [line[3:] for line in cgroup.splitlines() if line.startswith("0::")]
    if len(cgroups) != 1 or not cgroups[0].startswith("/"):
        raise PermissionError("process unified cgroup identity is unavailable")
    return (
        fields["Uid"],
        fields["Gid"],
        frozenset(fields["Groups"]),
        cgroups[0],
    )


def _require_process_credentials(
    pid: int,
    *,
    uid: int,
    gid: int,
    supplementary_gids: frozenset[int],
    cgroup_path: str | None = None,
) -> None:
    """Require live kernel credentials to match the broker's service policy."""
    try:
        uids, gids, groups, observed_cgroup = _read_process_credentials(pid)
    except (OSError, ValueError) as error:
        raise PermissionError("process credentials cannot be verified") from error
    if uids != (uid, uid, uid, uid) or gids != (gid, gid, gid, gid):
        raise PermissionError("process UID or GID credentials differ from broker policy")
    if groups != supplementary_gids:
        raise PermissionError("process supplementary groups differ from broker policy")
    if cgroup_path is not None and observed_cgroup != cgroup_path:
        raise PermissionError("process cgroup differs from broker unit identity")


def _validated_request(packet: bytes) -> tuple[str, dict[str, object]]:
    """Parse one exact operation shape; worker input cannot carry unit policy."""
    request = _json_object(packet, "broker request")
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in _REQUESTS:
        raise ValueError("broker operation is not supported")
    if set(request) != _REQUESTS[operation]:
        raise ValueError("broker request has an unexpected field set")
    return operation, request


def _validate_unit_policy(
    properties: Mapping[str, str], configuration: BrokerConfiguration
) -> None:
    """Require systemd's live identity and containment settings to match policy."""
    expected = {
        "User": str(configuration.runner_uid),
        "Group": str(configuration.runner_gid),
        "KillMode": "control-group",
        "Delegate": "no",
        "RemainAfterExit": "yes",
        "DevicePolicy": "closed",
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "NoNewPrivileges": "yes",
    }
    if any(properties.get(key) != value for key, value in expected.items()):
        raise BackendEvidenceError(
            "transient service identity or containment policy differs from broker configuration"
        )


def _send(connection: socket.socket, response: Mapping[str, object], *, output_fd: int | None = None) -> None:
    payload = json.dumps(
        response, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(payload) > _MAX_PACKET:
        raise ValueError("broker response exceeds the protocol limit")
    ancillary = []
    if output_fd is not None:
        descriptors = array.array("i", [output_fd])
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]
    sent = connection.sendmsg([payload], ancillary)
    if sent != len(payload):
        raise OSError("broker response packet was not sent atomically")


def _write_line(stream, value: Mapping[str, object]) -> None:
    if stream is None:
        raise BrokenPipeError("systemd runner pipe is unavailable")
    stream.write(encode_json_line(value))
    stream.flush()


def _read_line(stream) -> dict[str, object]:
    if stream is None:
        raise EOFError("systemd runner pipe is unavailable")
    return read_json_line(stream)


def _json_object(raw: bytes, label: str) -> dict[str, object]:
    """Decode one non-line-framed JSON object used by the worker socket."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is malformed") from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _json_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _optional_mapping(value: object, label: str) -> dict[str, object] | None:
    return None if value is None else _json_mapping(value, label)


def _text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of text")
    return value


def _environment(value: object) -> dict[str, str]:
    mapping = _json_mapping(value, "environment")
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in mapping.items()):
        raise ValueError("environment must contain text names and values")
    return dict(mapping)


def _claim_fields(request: Mapping[str, object]) -> tuple[str, str, str, int]:
    job = _text(request.get("job_id"), "job_id")
    attempt = _text(request.get("attempt_id"), "attempt_id")
    owner = _text(request.get("owner_id"), "owner_id")
    epoch = request.get("claim_epoch")
    if not _safe_attempt_id(attempt) or isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise ValueError("attempt claim identity is malformed")
    return job, attempt, owner, epoch


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text")
    return value


def _int_tuple(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(type(item) is not int or item < 1 for item in value):
        raise ValueError(f"{label} must be a list of positive integers")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} contains duplicates")
    return tuple(value)


def _path_tuple(value: object, label: str) -> tuple[Path, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty path list")
    return tuple(_absolute_path(item, label) for item in value)


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if "\x00" in value:
        raise ValueError(f"{label} contains a NUL")
    return Path(value)


def _account_group_ids(
    name: str,
    *,
    primary_gid: int,
    expected: frozenset[int],
    label: str,
) -> frozenset[int]:
    """Check keyed NSS membership for one service account against policy."""
    try:
        actual = frozenset(os.getgrouplist(name, primary_gid))
    except (AttributeError, OSError) as error:
        raise PermissionError(
            f"{label} supplementary group membership cannot be verified"
        ) from error
    if actual != expected:
        raise PermissionError(f"{label} account groups differ from broker policy")
    return actual


def _require_directory_traversal(
    path: Path,
    uid: int,
    gids: frozenset[int],
    *,
    label: str,
) -> None:
    """Require a service identity to search every directory in one path."""
    for directory in (path, *path.parents):
        try:
            info = directory.stat()
        except OSError as error:
            raise PermissionError(label) from error
        if not stat.S_ISDIR(info.st_mode) or not _mode_allows(
            info, uid, gids, execute=True
        ):
            raise PermissionError(label)


def _mode_allows(
    info: os.stat_result,
    uid: int,
    gids: frozenset[int],
    *,
    read: bool = False,
    write: bool = False,
    execute: bool = False,
) -> bool:
    needed = (4 if read else 0) | (2 if write else 0) | (1 if execute else 0)
    if uid == info.st_uid:
        allowed = (info.st_mode >> 6) & 7
    elif info.st_gid in gids:
        allowed = (info.st_mode >> 3) & 7
    else:
        allowed = info.st_mode & 7
    return allowed & needed == needed


def _require_no_extended_posix_acl(path: Path) -> None:
    """Reject POSIX ACLs where mode-bit checks define the access policy."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        if sys.platform != "linux":
            return
        raise PermissionError("POSIX ACL state cannot be verified")
    try:
        info = path.lstat()
    except OSError as error:
        raise PermissionError("POSIX ACL state cannot be verified") from error
    if stat.S_ISLNK(info.st_mode):
        return

    missing_or_unsupported = {
        errno.ENODATA,
        getattr(errno, "ENOATTR", errno.ENODATA),
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
    }
    attributes = ["system.posix_acl_access"]
    if stat.S_ISDIR(info.st_mode):
        attributes.append("system.posix_acl_default")
    for attribute in attributes:
        try:
            getxattr(path, attribute, follow_symlinks=False)
        except OSError as error:
            if error.errno in missing_or_unsupported:
                continue
            raise PermissionError("POSIX ACL state cannot be verified") from error
        raise PermissionError("extended POSIX ACLs are not allowed on protected paths")


def _require_no_extended_posix_acl_ancestors(path: Path) -> None:
    for ancestor in reversed(path.parents):
        _require_no_extended_posix_acl(ancestor)
    _require_no_extended_posix_acl(path)


def _require_no_symlink_components(path: Path) -> None:
    """Reject engine input paths whose lexical components can be retargeted."""
    current = Path(path.anchor)
    for component in path.parts[1:]:
        if component in {".", ".."}:
            raise PermissionError("engine input path must be normalized")
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise PermissionError("engine input path component cannot be verified") from error
        if stat.S_ISLNK(info.st_mode):
            raise PermissionError("engine input path must not contain symlink components")


def _require_root_directory(path: Path) -> None:
    _require_root_owned_ancestors(path)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
    ):
        raise PermissionError("broker directory must be real, root-owned, and not world-writable")


def _require_root_executable(path: Path) -> None:
    _require_root_owned_ancestors(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or not info.st_mode & 0o111
    ):
        raise PermissionError("runner executable must be a root-owned non-writable file")


def _require_root_owned_ancestors(path: Path) -> None:
    """Reject broker paths that an unprivileged parent can rename or replace."""
    ancestor = Path(path).absolute().parent
    while True:
        info = ancestor.lstat()
        writable = bool(info.st_mode & 0o022)
        sticky_protected = bool(info.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or (writable and not sticky_protected)
        ):
            raise PermissionError(
                "broker path ancestor must be root-owned and not replaceable"
            )
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise BackendEvidenceError("Linux boot identity is unavailable")
    return value


def _is_invocation_id(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def _safe_attempt_id(value: str) -> bool:
    return (
        len(value) == 36
        and value.startswith("att_")
        and all(character in "0123456789abcdef" for character in value[4:])
    )


def _int_property(value: str | None) -> int | None:
    try:
        return None if value is None else int(value)
    except ValueError:
        return None


def _optional_exit_code(value: object, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer or None")
    return value


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _linux_cgroup_v2() -> bool:
    return Path("/sys/fs/cgroup/cgroup.controllers").is_file()


def _safe_error_code(error: object) -> str:
    code = getattr(error, "code", None)
    if isinstance(code, str) and code and code.replace("_", "").isalnum():
        return code
    if isinstance(error, Mapping):
        nested = error.get("error_code")
        if isinstance(nested, str) and nested and nested.replace("_", "").isalnum():
            return nested
    return "broker_operation_failed"


def main(argv: list[str] | None = None) -> int:
    """Start the broker from a root-owned JSON configuration file."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: media-generation-systemd-broker CONFIG.json", file=sys.stderr)
        return 2
    try:
        configuration = BrokerConfiguration.from_file(Path(arguments[0]))
        SystemdAttemptBroker(configuration).serve_forever()
    except Exception as error:
        print(_safe_error_code(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
