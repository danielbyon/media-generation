from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import os
import socket
import sqlite3
import stat
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import engine
from media_generation import service as service_module
from media_generation import store as store_module
from media_generation import systemd_broker as broker_module
from media_generation.backend_provenance import backend_digest
from media_generation.errors import BackendEvidenceError, RetryableGenerationError
from media_generation.comfyui import ComfyUIAdapter
from media_generation.systemd_evidence import SystemdEvidenceLedger
from media_generation.service import (
    GenerationService,
    _StoreExecutionAuthority,
    _lease_deadline,
    _now,
)
from media_generation.supervisor import ProcessSupervisor
from media_generation.systemd_broker import (
    BrokerConfiguration,
    SystemdAttemptBroker,
    _mode_allows,
    _record_pinned_empty_event,
    _start_systemd_run,
    _require_root_directory,
    _unit_identity_live,
    _validated_request,
    _validate_unit_policy,
)
from media_generation.systemd_attempts import (
    SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
    AttemptUnitIdentity,
    CgroupTerminationEvidence,
    SystemdAttemptCompletion,
    SystemdAttemptRunner,
    _validate_broker_socket,
)
from test_backend_evidence import (
    RUNTIME,
    _launch,
    _observed,
    _plan,
    _raw_connection,
    _request,
    _service,
)
from test_t08_support import build_bundle, heavy_workload_demand


@pytest.fixture(autouse=True)
def _report_test_evidence_ledger_as_root_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_lstat = Path.lstat

    def lstat(path: Path):
        info = original_lstat(path)
        if path.name.endswith(".systemd-evidence.sqlite3"):
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_uid=0,
                st_gid=info.st_gid,
            )
        return info

    monkeypatch.setattr(Path, "lstat", lstat)


class _SyntheticSystemdAttemptRunner(SystemdAttemptRunner):
    """Run the real adapter child while replacing only the host broker boundary."""

    def __init__(
        self,
        scratch_root,
        *,
        record_engine: bool = True,
        record_cgroup: bool = True,
        runner_exit_code: int = 0,
        runner_exit_signal: int | None = None,
        launcher_exit_code: int = 0,
        engine_exit_code: int | None = None,
        observation_delta: dict[str, object] | None = None,
        unlink_output_before_return: bool = False,
        acknowledgement_error: Exception | None = None,
        fence_before_return: bool = False,
        cancel_before_return: bool = False,
    ) -> None:
        scratch_root.mkdir(parents=True, exist_ok=True)
        super().__init__(
            scratch_root / "unused.sock",
            scratch_root=scratch_root,
            runner_uid=2301,
            runner_gid=2301,
        )
        self.store = None
        self.record_engine = record_engine
        self.record_cgroup = record_cgroup
        self.runner_exit_code = runner_exit_code
        self.runner_exit_signal = runner_exit_signal
        self.launcher_exit_code = launcher_exit_code
        self.engine_exit_code = engine_exit_code
        self.observation_delta = observation_delta
        self.unlink_output_before_return = unlink_output_before_return
        self.acknowledgement_error = acknowledgement_error
        self.fence_before_return = fence_before_return
        self.cancel_before_return = cancel_before_return
        self.scratch_directory = None
        self.scratch_directories: dict[str, Path] = {}
        self.acknowledgements: list[bool] = []

    def prepare_attempt(self, claim) -> Path:
        directory = self.scratch_root / claim.attempt_id
        self.scratch_directory = directory
        self.scratch_directories[claim.attempt_id] = directory
        return directory

    def execute_attempt(self, claim, prepared) -> SystemdAttemptCompletion:
        assert self.store is not None
        resolved_digest = backend_digest(prepared.resolved_record)
        unit_name = (
            f"media-generation-attempt-{claim.attempt_id[4:]}.service"
        )
        identity = AttemptUnitIdentity(
            version=1,
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id=claim.owner_id,
            claim_epoch=claim.claim_epoch,
            resolved_digest=resolved_digest,
            boot_id="01234567-89ab-cdef-0123-456789abcdef",
            unit_name=unit_name,
            invocation_id="b" * 32,
            cgroup_path=f"/system.slice/{unit_name}",
            cgroup_device=42,
            cgroup_inode=731,
            runner_uid=self.runner_uid,
            runner_gid=self.runner_gid,
        )
        self.store.bind_attempt_containment(identity, timestamp=_now())
        prepared.scratch_directory.mkdir(mode=0o700)
        observation = None
        if self.record_engine:
            if self.engine_exit_code is None:
                supervisor = ProcessSupervisor(
                    _StoreExecutionAuthority(self.store, claim),
                    expected_argv=prepared.argv,
                    expected_environment=prepared.environment,
                )
                observation = supervisor.run(
                    prepared.argv,
                    env=prepared.environment,
                    cwd=prepared.scratch_directory,
                ).to_mapping()
            else:
                self.store.mark_execution_launched(
                    job_id=claim.job_id,
                    attempt_id=claim.attempt_id,
                    owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    record=_launch(prepared),
                    timestamp=_now(),
                )
                observation = _observed(claim.attempt_id)
                observation["exit_code"] = self.engine_exit_code
                self.store.mark_execution_observed(
                    job_id=claim.job_id,
                    attempt_id=claim.attempt_id,
                    owner_id=claim.owner_id,
                    claim_epoch=claim.claim_epoch,
                    record=observation,
                    timestamp=_now(),
                )
        termination = None
        if self.record_cgroup:
            termination = CgroupTerminationEvidence(
                identity=identity,
                populated=0,
                observed_monotonic_ns=987654321,
                observed_at=datetime.now(timezone.utc).isoformat(),
            )
            self.store.record_attempt_termination_evidence(
                identity, termination, timestamp=_now()
            )
        if self.cancel_before_return:
            self.store.cancel_execution(claim.job_id, _now())
        if self.fence_before_return:
            self.store.fence_attempt_for_recovery(
                claim.job_id, claim.attempt_id, timestamp=_now()
            )
            raise OSError("synthetic worker lost the runner completion")
        output_fd = (
            os.open(prepared.output_path, os.O_RDONLY)
            if (
                observation is not None
                and observation.get("exit_code") == 0
                and termination is not None
            )
            else None
        )
        if output_fd is not None and self.unlink_output_before_return:
            Path(prepared.output_path).unlink()
        reported_observation = (
            None if observation is None else dict(observation)
        )
        if reported_observation is not None and self.observation_delta:
            reported_observation.update(self.observation_delta)
        return SystemdAttemptCompletion(
            identity=identity,
            runner_exit_code=(
                None if self.runner_exit_signal is not None else self.runner_exit_code
            ),
            launcher_exit_code=self.launcher_exit_code,
            unit_result=(
                "success"
                if self.runner_exit_signal is None and self.runner_exit_code == 0
                else "signal"
                if self.runner_exit_signal is not None
                else "exit-code"
            ),
            engine_observation=reported_observation,
            termination_evidence=termination,
            stream_complete=observation is not None,
            output_fd=output_fd,
            error_code=(
                "runner_signaled"
                if self.runner_exit_signal is not None
                else None
                if self.runner_exit_code == 0
                else "runner_failed"
            ),
            runner_exit_signal=self.runner_exit_signal,
        )

    def acknowledge_output(self, identity, *, validated: bool) -> None:
        self.acknowledgements.append(validated)
        if self.acknowledgement_error is not None:
            raise self.acknowledgement_error
        scratch = self.scratch_directories.get(identity.attempt_id)
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)

    def cancel_attempt(self, claim) -> str:
        assert self.store is not None
        identity = self.store.attempt_containment_identity(
            claim.job_id, claim.attempt_id
        )
        if identity is not None and self.store.attempt_termination_proven(
            claim.job_id, claim.attempt_id
        ):
            return "acknowledged"
        return "requested"

    def cleanup_after_recovery(self, identity) -> None:
        if self.scratch_directory is not None:
            shutil.rmtree(self.scratch_directory, ignore_errors=True)


@pytest.fixture(autouse=True)
def synthetic_rocm_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "capture_runtime_fingerprint", lambda: dict(RUNTIME))


def _identity() -> AttemptUnitIdentity:
    attempt_id = "att_0123456789abcdef0123456789abcdef"
    unit_name = "media-generation-attempt-0123456789abcdef0123456789abcdef.service"
    return AttemptUnitIdentity(
        version=1,
        job_id="job_0123456789abcdef0123456789abcdef",
        attempt_id=attempt_id,
        owner_id="worker_0123456789abcdef0123456789abcdef",
        claim_epoch=7,
        resolved_digest="a" * 64,
        boot_id="01234567-89ab-cdef-0123-456789abcdef",
        unit_name=unit_name,
        invocation_id="b" * 32,
        cgroup_path=f"/system.slice/{unit_name}",
        cgroup_device=42,
        cgroup_inode=731,
        runner_uid=2301,
        runner_gid=2301,
    )


def _broker_configuration(tmp_path) -> BrokerConfiguration:
    return BrokerConfiguration(
        database_path=tmp_path / "studio.sqlite3",
        socket_path=tmp_path / "broker.sock",
        scratch_root=tmp_path / "scratch",
        runner_executable=tmp_path / "runner",
        runner_uid=2301,
        runner_gid=2301,
        runner_supplementary_gids=(2302,),
        worker_uid=2300,
        worker_gid=2300,
        scratch_gid=2302,
        device_allow=(Path("/dev/kfd"),),
        read_roots=(tmp_path,),
    )


def test_attempt_unit_identity_round_trips_its_incarnation_fields() -> None:
    identity = _identity()

    assert AttemptUnitIdentity.from_mapping(identity.to_mapping()) == identity


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("invocation_id", "not-an-invocation"),
        ("unit_name", "media-generation-attempt-reused.service"),
        ("cgroup_path", "/system.slice/reused.service"),
        ("cgroup_inode", 0),
        ("boot_id", "not-a-boot-id"),
    ],
)
def test_attempt_unit_identity_rejects_reused_or_mismatched_incarnation(
    field: str, value: object
) -> None:
    with pytest.raises(ValueError):
        replace(_identity(), **{field: value})


@pytest.mark.parametrize("field", ["runner_uid", "runner_gid"])
def test_attempt_unit_identity_rejects_root_runner(field: str) -> None:
    with pytest.raises(ValueError):
        replace(_identity(), **{field: 0})


def test_cgroup_termination_evidence_is_bound_to_the_exact_unit_identity() -> None:
    evidence = CgroupTerminationEvidence(
        identity=_identity(),
        populated=0,
        observed_monotonic_ns=123456789,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    assert CgroupTerminationEvidence.from_mapping(evidence.to_mapping()) == evidence


@pytest.mark.parametrize(
    ("field", "value"),
    [("populated", 1), ("populated", True), ("observed_monotonic_ns", 0)],
)
def test_cgroup_termination_evidence_rejects_nonempty_or_missing_event(
    field: str, value: object
) -> None:
    evidence = CgroupTerminationEvidence(
        identity=_identity(),
        populated=0,
        observed_monotonic_ns=123456789,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    with pytest.raises(ValueError):
        replace(evidence, **{field: value})


def test_pinned_empty_event_survives_unit_and_cgroup_path_removal(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, _claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    event_path = tmp_path / "cgroup.events"
    event_path.write_text("populated 0\nfrozen 0\n", encoding="ascii")
    descriptor = event_path.open("rb")
    event_path.unlink()

    try:
        evidence = _record_pinned_empty_event(store, identity, descriptor.fileno())
    finally:
        descriptor.close()

    assert evidence is not None
    assert evidence.identity == identity
    assert store.attempt_termination_proven(identity.job_id, identity.attempt_id)


def test_unit_disappearance_before_cgroup_pin_is_not_termination_proof(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    monkeypatch.setattr(broker_module, "_unit_properties", lambda _unit: None)

    assert _unit_identity_live(identity) is False
    assert store.attempt_containment_identity(claim.job_id, claim.attempt_id) is None
    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id) is False


def test_populated_cgroup_event_is_not_termination_proof(tmp_path) -> None:
    event_path = tmp_path / "cgroup.events"
    event_path.write_text("populated 1\nfrozen 0\n", encoding="ascii")
    descriptor = event_path.open("rb")

    try:
        proof = _record_pinned_empty_event(object(), _identity(), descriptor.fileno())
    finally:
        descriptor.close()

    assert proof is None


def test_broker_rejects_worker_supplied_systemd_properties() -> None:
    request = {
        "operation": "execute",
        "job_id": "job_0123456789abcdef0123456789abcdef",
        "attempt_id": "att_0123456789abcdef0123456789abcdef",
        "owner_id": "owner_0123456789abcdef0123456789abcdef",
        "claim_epoch": 1,
        "resolved_digest": "a" * 64,
        "resolved_record": {},
        "argv": [],
        "environment": {},
        "scratch_directory": "/srv/media/scratch/attempt",
        "runner_uid": 2301,
        "runner_gid": 2301,
        "unit_properties": {"ExecStart": "/bin/sh"},
        "user": "root",
    }

    with pytest.raises(ValueError, match="unexpected field set"):
        _validated_request(json.dumps(request).encode("utf-8"))


@pytest.mark.parametrize(
    ("ancestor_uid", "ancestor_mode"),
    [
        (1001, stat.S_IFDIR | 0o755),
        (0, stat.S_IFDIR | 0o777),
    ],
    ids=["worker-owned", "root-owned-writable"],
)
def test_broker_rejects_replaceable_privileged_path_ancestors(
    tmp_path, monkeypatch: pytest.MonkeyPatch, ancestor_uid: int, ancestor_mode: int
) -> None:
    path = tmp_path / "broker-control"
    leaf = os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    ancestor = os.stat_result(
        (ancestor_mode, 1, 1, 1, ancestor_uid, 0, 0, 0, 0, 0)
    )
    original_lstat = Path.lstat

    def fake_lstat(candidate: Path):
        if candidate == path:
            return leaf
        if candidate == path.parent:
            return ancestor
        return original_lstat(candidate)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(PermissionError, match="ancestor"):
        _require_root_directory(path)


def test_worker_accepts_root_owned_broker_beneath_sticky_ancestor(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "attempt.sock"
    sticky_ancestor = socket_path.parent.parent

    def fake_lstat(path: Path):
        if path == socket_path:
            return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)
        if path == sticky_ancestor:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | stat.S_ISVTX | 0o777, st_uid=0
            )
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    _validate_broker_socket(socket_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [("User", "0"), ("Group", "0"), ("KillMode", "process")],
)
def test_broker_rejects_wrong_service_identity_or_termination_policy(
    tmp_path, field: str, value: str
) -> None:
    configuration = _broker_configuration(tmp_path)
    properties = {
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
    properties[field] = value

    with pytest.raises(BackendEvidenceError, match="identity or containment policy"):
        _validate_unit_policy(properties, configuration)


def test_broker_rejects_gpu_device_without_runner_read_write_access() -> None:
    inaccessible_mode = stat.S_IFCHR | 0o600
    info = os.stat_result((inaccessible_mode, 1, 1, 1, 0, 0, 0, 0, 0, 0))

    assert not _mode_allows(
        info,
        2301,
        frozenset({2301, 2302}),
        read=True,
        write=True,
    )


def test_broker_rejects_runner_database_groups_outside_allowlist(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = _broker_configuration(tmp_path)
    runner = SimpleNamespace(pw_name="engine-runner", pw_gid=configuration.runner_gid)
    worker = SimpleNamespace(pw_name="generation-worker", pw_gid=configuration.worker_gid)
    monkeypatch.setattr(
        broker_module.pwd,
        "getpwuid",
        lambda uid: runner if uid == configuration.runner_uid else worker,
    )
    monkeypatch.setattr(
        broker_module.grp, "getgrgid", lambda gid: SimpleNamespace(gr_gid=gid)
    )
    monkeypatch.setattr(
        broker_module.grp, "getgrall", lambda: [SimpleNamespace(gr_gid=0, gr_mem=[]) ]
    )
    monkeypatch.setattr(
        broker_module.os,
        "getgrouplist",
        lambda name, _gid: (
            [configuration.runner_gid, configuration.worker_gid]
            if name == runner.pw_name
            else [configuration.worker_gid]
        ),
    )

    with pytest.raises(ValueError, match="supplementary groups outside the broker allowlist"):
        configuration.validate_host_paths()


@pytest.mark.parametrize("component_flag", ["--llm", "--llm_vision"])
def test_engine_component_paths_must_be_inside_broker_read_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component_flag: str,
) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    executable = allowed_root / "engine"
    executable.write_bytes(b"engine")
    model = outside_root / "model.gguf"
    model.write_bytes(b"model")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(allowed_root,),
        runner_uid=os.getuid(),
        runner_groups=frozenset({os.getgid()}),
    )
    monkeypatch.setattr(
        broker_module, "_mode_allows", lambda *_args, **_kwargs: True
    )

    with pytest.raises(PermissionError, match="outside broker read roots"):
        broker._validate_engine_paths(
            [str(executable), component_flag, str(model)]
        )


def test_systemd_command_uses_only_fixed_runner_and_broker_properties(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(broker_module.subprocess, "Popen", fake_popen)
    configuration = _broker_configuration(tmp_path)
    scratch = configuration.scratch_root / _identity().attempt_id

    process = _start_systemd_run(
        configuration, _identity().unit_name, scratch
    )

    command = captured["command"]
    assert process is not None
    assert isinstance(command, list)
    assert command[0:3] == ["/usr/bin/systemd-run", "--system", "--quiet"]
    assert f"--property=User={configuration.runner_uid}" in command
    assert f"--property=Group={configuration.runner_gid}" in command
    assert "--property=KillMode=control-group" in command
    assert "--property=DevicePolicy=closed" in command
    assert f"--property=DeviceAllow={configuration.device_allow[0]} rw" in command
    assert command[-2:] == ["--", str(configuration.runner_executable)]


@pytest.mark.parametrize(
    ("operation", "runner_status_available", "reported_exit_code", "expected_exit_code", "expected_error"),
    [
        ("complete", True, 0, 0, None),
        ("runner_error", False, None, None, "runner_failed"),
    ],
    ids=["successful-runner-exit", "unit-status-lost-but-cgroup-proof-remains"],
)
def test_broker_waits_for_runner_exit_before_cgroup_proof_and_starts_watcher_once(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    runner_status_available: bool,
    reported_exit_code: int | None,
    expected_exit_code: int | None,
    expected_error: str | None,
) -> None:
    identity = _identity()
    configuration = _broker_configuration(tmp_path)
    configuration.scratch_root.mkdir()
    scratch = configuration.scratch_root / identity.attempt_id
    resolved = {
        "attempt_id": identity.attempt_id,
        "argv": ["/engine"],
        "environment": broker_module.environment_record({}),
    }
    events: list[str] = []
    watcher_instances = []

    class _Store:
        def get_backend_execution(self, _job_id, _attempt_id):
            return {
                "state": "resolved",
                "resolved": resolved,
                "resolved_digest": identity.resolved_digest,
            }

    class _Pipe:
        def write(self, value: bytes) -> int:
            return len(value)

        def flush(self) -> None:
            pass

        def close(self) -> None:
            pass

    class _Process:
        stdin = _Pipe()
        stdout = _Pipe()

        def wait(self, timeout: float) -> int:
            return 0

        def terminate(self) -> None:
            pass

    class _Thread:
        def __init__(self, **_kwargs) -> None:
            self.starts = 0
            watcher_instances.append(self)

        def start(self) -> None:
            self.starts += 1

        def join(self, timeout: float) -> None:
            pass

    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker.store = _Store()
    broker._active = {}
    broker._active_lock = threading.RLock()
    broker._require_current_claim = lambda *_args: None
    broker._validate_engine_paths = lambda _argv: None
    broker._create_attempt_scratch = lambda _attempt: scratch.mkdir(mode=0o700)
    broker._wait_for_containment = lambda *_args: (
        identity,
        os.open(tmp_path / "pinned-events", os.O_RDONLY | os.O_CREAT, 0o600),
    )
    monkeypatch.setattr(broker_module, "_read_populated", lambda _fd: 1)
    monkeypatch.setattr(broker_module, "_unit_identity_live", lambda _identity: True)
    def wait_for_runner_exit(observed, *, timeout):
        events.append("runner-exit")
        if not runner_status_available:
            raise BackendEvidenceError("attempt unit disappeared before runner exit")
        return {
            "InvocationID": observed.invocation_id,
            "ControlGroup": observed.cgroup_path,
            "MainPID": "0",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "Result": "success",
        }

    broker._wait_for_runner_exit = wait_for_runner_exit
    monkeypatch.setattr(broker_module, "backend_digest", lambda _record: identity.resolved_digest)
    monkeypatch.setattr(broker_module, "_mode_allows", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(broker_module, "_unit_properties", lambda _unit: None)
    monkeypatch.setattr(broker_module, "_start_systemd_run", lambda *_args: _Process())
    control_message = (
        {
            "operation": "complete",
            "runner_exit_code": reported_exit_code,
            "engine_observation": None,
            "stream_complete": True,
        }
        if operation == "complete"
        else {
            "operation": "runner_error",
            "runner_exit_code": None,
            "error_code": "runner_failed",
            "stream_complete": False,
        }
    )
    monkeypatch.setattr(broker_module, "_read_line", lambda _stream: control_message)
    monkeypatch.setattr(broker_module, "_stop_unit", lambda _unit: events.append("stop"))
    monkeypatch.setattr(
        broker_module,
        "_wait_cgroup_empty",
        lambda *_args, **_kwargs: events.append("cgroup-empty") or True,
    )
    monkeypatch.setattr(
        broker_module,
        "_record_pinned_empty_event",
        lambda _store, observed, _fd: CgroupTerminationEvidence(
            identity=observed,
            populated=0,
            observed_monotonic_ns=987654321,
            observed_at=datetime.now(timezone.utc).isoformat(),
        ),
    )
    monkeypatch.setattr(broker_module.threading, "Thread", _Thread)
    request = {
        "job_id": identity.job_id,
        "attempt_id": identity.attempt_id,
        "owner_id": identity.owner_id,
        "claim_epoch": identity.claim_epoch,
        "resolved_digest": identity.resolved_digest,
        "resolved_record": resolved,
        "argv": ["/engine"],
        "environment": {},
        "scratch_directory": str(scratch),
        "runner_uid": identity.runner_uid,
        "runner_gid": identity.runner_gid,
    }

    response, output_fd = broker._execute(object(), request)

    assert output_fd is None
    assert response["termination_evidence"] is not None
    assert response["runner_exit_code"] == expected_exit_code
    assert response["error_code"] == expected_error
    assert [event for event in events if event in {"runner-exit", "cgroup-empty"}] == [
        "runner-exit",
        "cgroup-empty",
    ]
    assert len(watcher_instances) == 1
    assert watcher_instances[0].starts == 1


def test_wait_for_runner_exit_requires_matching_unit_and_exited_main_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    pending = {
        "InvocationID": identity.invocation_id,
        "ControlGroup": identity.cgroup_path,
        "MainPID": "2345",
        "ExecMainCode": "0",
        "ExecMainStatus": "0",
    }
    exited = {
        **pending,
        "MainPID": "0",
        "ExecMainCode": "1",
        "ExecMainStatus": "0",
        "Result": "success",
    }
    observed = iter((pending, exited))
    broker = object.__new__(SystemdAttemptBroker)
    monkeypatch.setattr(
        broker_module, "_unit_properties", lambda _unit: next(observed)
    )
    monkeypatch.setattr(broker_module.time, "sleep", lambda _seconds: None)

    result = broker._wait_for_runner_exit(identity, timeout=1.0)

    assert result == exited


def test_prepare_returns_scratch_path_without_creating_directory(tmp_path) -> None:
    store, claim, _identity = _claimed_systemd_attempt(tmp_path)
    configuration = _broker_configuration(tmp_path)
    configuration.scratch_root.mkdir()
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker.store = store
    request = {
        "job_id": claim.job_id,
        "attempt_id": claim.attempt_id,
        "owner_id": claim.owner_id,
        "claim_epoch": claim.claim_epoch,
    }

    result = broker._prepare(request)

    assert result["scratch_directory"] == str(
        configuration.scratch_root / claim.attempt_id
    )
    assert not (configuration.scratch_root / claim.attempt_id).exists()


def test_worker_disconnect_fences_and_stops_exact_live_attempt(monkeypatch) -> None:
    identity = _identity()
    events: list[tuple[object, ...]] = []

    class _Store:
        def fence_attempt_for_recovery(self, job_id, attempt_id, *, timestamp):
            events.append(("fence", job_id, attempt_id))
            return {"job_id": job_id, "attempt_id": attempt_id}

    broker = object.__new__(SystemdAttemptBroker)
    broker.store = _Store()
    monkeypatch.setattr(
        broker_module, "_stop_unit", lambda unit: events.append(("stop", unit))
    )
    worker, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.close()
    lost = threading.Event()
    stop = threading.Event()
    active = type("Active", (), {"identity": identity})()
    monitor = threading.Thread(
        target=broker._watch_worker_disconnect,
        args=(worker, active, lost, stop),
    )
    monitor.start()
    try:
        assert lost.wait(2)
    finally:
        stop.set()
        monitor.join(timeout=1)
        worker.close()

    assert not monitor.is_alive()
    assert events == [
        ("fence", identity.job_id, identity.attempt_id),
        ("stop", identity.unit_name),
    ]


def _claimed_systemd_attempt(tmp_path):
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle)
    queued = service.enqueue(
        "systemd-containment", _request(), workload_demand=heavy_workload_demand()
    )
    # Bind this store-focused fixture to the new trusted contract. Production
    # admission gets this value only from the configured systemd runner.
    with _raw_connection(service.database_path) as connection:
        connection.execute(
            "UPDATE execution_jobs SET containment_contract = ? WHERE job_id = ?",
            (SYSTEMD_CGROUP_CONTAINMENT_CONTRACT, queued.job_id),
        )
    attempt_id = "att_0123456789abcdef0123456789abcdef"
    owner_id = "owner_0123456789abcdef0123456789abcdef"
    _, configuration_json, _, privacy_json = service._current_privacy_snapshot()
    claim = service._store.claim_next_execution(
        attempt_id=attempt_id,
        owner_id=owner_id,
        adapter_id=service.adapter.adapter_id,
        adapter_configuration_json=configuration_json,
        privacy_compliance_json=privacy_json,
        resolved_output_directory=str(service.output_directory),
        process_contained=True,
        containment_contract=SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
        timestamp=_now(),
        lease_expires_at=_lease_deadline(service._lease),
        job_id=queued.job_id,
    )
    assert claim is not None
    prepared = service.adapter.resolve_execution(_plan(claim))
    resolved_digest = service._store.insert_resolved_execution(
        job_id=claim.job_id,
        attempt_id=claim.attempt_id,
        owner_id=owner_id,
        claim_epoch=claim.claim_epoch,
        record=dict(prepared.resolved_record),
        timestamp=_now(),
    )
    unit_name = f"media-generation-attempt-{attempt_id[4:]}.service"
    identity = AttemptUnitIdentity(
        version=1,
        job_id=claim.job_id,
        attempt_id=attempt_id,
        owner_id=owner_id,
        claim_epoch=claim.claim_epoch,
        resolved_digest=resolved_digest,
        boot_id="01234567-89ab-cdef-0123-456789abcdef",
        unit_name=unit_name,
        invocation_id="b" * 32,
        cgroup_path=f"/system.slice/{unit_name}",
        cgroup_device=42,
        cgroup_inode=731,
        runner_uid=2301,
        runner_gid=2301,
    )
    return service._store, claim, identity


def _systemd_service(tmp_path, runner):
    bundle = build_bundle(tmp_path)
    service = _service(tmp_path, bundle, attempt_runner=runner)
    runner.store = service._store
    return service, runner


def test_post_fence_cgroup_evidence_is_idempotent_and_does_not_create_engine_observation(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    root = tmp_path / "allocated-publication-root"
    root.mkdir()
    root_identity = root.stat()
    publication_id = "pub_recovery_cleanup_allocated"
    store.create_publication(
        {
            "publication_id": publication_id,
            "artifact_id": "art_recovery_cleanup_allocated",
            "root": str(root),
            "root_dev": root_identity.st_dev,
            "root_ino": root_identity.st_ino,
            "root_token": "test-root-token",
            "stage_name": f".{publication_id}.stage",
            "state": "allocated",
            "job_id": claim.job_id,
            "attempt_id": claim.attempt_id,
            "sources_json": "[]",
            "created_at": _now(),
        },
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
    )
    assert store.attempt_recovery_cleanup_authorized(identity) is False

    assert store.cancel_execution(claim.job_id, _now()) == "requested"
    assert store.attempt_recovery_cleanup_authorized(identity) is False
    store.abandon_publication(publication_id, "recovery test revoked allocation")
    assert store.attempt_recovery_cleanup_authorized(identity) is True
    evidence = CgroupTerminationEvidence(
        identity=identity,
        populated=0,
        observed_monotonic_ns=987654321,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    store.record_attempt_termination_evidence(
        identity, evidence, timestamp=_now()
    )
    store.record_attempt_termination_evidence(
        identity, evidence, timestamp=_now()
    )

    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id)
    assert store.termination_evidence_proven(claim.job_id, claim.attempt_id) is False
    store.acknowledge_execution_cancellation(
        claim.job_id, claim.attempt_id, timestamp=_now()
    )
    assert store.cancel_execution(claim.job_id, _now()) == "acknowledged"


def test_cancellation_fence_rejects_late_engine_observation_writer(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    assert store.cancel_execution(claim.job_id, _now()) == "requested"

    with pytest.raises(BackendEvidenceError, match="authority is stale"):
        store.mark_execution_observed(
            job_id=claim.job_id,
            attempt_id=claim.attempt_id,
            owner_id=claim.owner_id,
            claim_epoch=claim.claim_epoch,
            record=_observed(claim.attempt_id),
            timestamp=_now(),
        )

    assert store.get_backend_execution(claim.job_id, claim.attempt_id)["state"] == "resolved"


def test_post_fence_termination_rejects_reused_unit_invocation(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    stale_identity = replace(identity, invocation_id="c" * 32)
    evidence = CgroupTerminationEvidence(
        identity=stale_identity,
        populated=0,
        observed_monotonic_ns=987654321,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    with pytest.raises(BackendEvidenceError):
        store.record_attempt_termination_evidence(
            stale_identity, evidence, timestamp=_now()
        )

    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id) is False


def test_worker_process_cannot_bind_or_forge_cgroup_termination(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    monkeypatch.setattr(store_module.os, "geteuid", lambda: identity.runner_uid)

    with pytest.raises(PermissionError, match="broker-owned"):
        store.bind_attempt_containment(identity, timestamp=_now())
    with pytest.raises(PermissionError, match="broker-owned"):
        store.record_attempt_termination_evidence(
            identity,
            CgroupTerminationEvidence(
                identity=identity,
                populated=0,
                observed_monotonic_ns=987654321,
                observed_at=datetime.now(timezone.utc).isoformat(),
            ),
            timestamp=_now(),
        )
    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id) is False


def test_cgroup_proof_releases_canceled_attempt_without_engine_observation(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    assert store.cancel_execution(claim.job_id, _now()) == "requested"
    store.record_attempt_termination_evidence(
        identity,
        CgroupTerminationEvidence(
            identity=identity,
            populated=0,
            observed_monotonic_ns=987654321,
            observed_at=datetime.now(timezone.utc).isoformat(),
        ),
        timestamp=_now(),
    )

    assert store.termination_evidence_proven(claim.job_id, claim.attempt_id) is False
    assert store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "canceled after verified cgroup stop",
        _now(),
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="canceled",
        termination_proven=True,
    )

    assert store.resource_snapshot()["state"] == "available"
    assert store.get_job(claim.job_id).status == "failed"
    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id)
    assert store.termination_evidence_proven(claim.job_id, claim.attempt_id) is False


def test_missing_cgroup_proof_keeps_canceled_capacity_quarantined(tmp_path) -> None:
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    assert store.cancel_execution(claim.job_id, _now()) == "requested"

    assert store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "cgroup stop is unverified",
        _now(),
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="canceled",
        termination_proven=False,
    )

    assert store.resource_snapshot()["state"] == "quarantined"
    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id) is False


def test_late_cgroup_proof_releases_quarantine_without_engine_observation(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    assert store.cancel_execution(claim.job_id, _now()) == "requested"
    assert store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "cgroup stop is unverified",
        _now(),
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="canceled",
        termination_proven=False,
    )
    assert store.resource_snapshot()["state"] == "quarantined"

    store.record_attempt_termination_evidence(
        identity,
        CgroupTerminationEvidence(
            identity=identity,
            populated=0,
            observed_monotonic_ns=987654321,
            observed_at=datetime.now(timezone.utc).isoformat(),
        ),
        timestamp=_now(),
    )

    assert store.termination_evidence_proven(claim.job_id, claim.attempt_id) is False
    assert store.release_quarantined_attempt(
        claim.job_id, claim.attempt_id, timestamp=_now()
    )
    assert store.resource_snapshot()["state"] == "available"


def test_unit_disappearance_after_durable_proof_allows_recovery_cleanup(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    assert store.cancel_execution(claim.job_id, _now()) == "requested"
    assert store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "worker lost before proof persistence",
        _now(),
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="canceled",
        termination_proven=False,
    )
    store.record_attempt_termination_evidence(
        identity,
        CgroupTerminationEvidence(
            identity=identity,
            populated=0,
            observed_monotonic_ns=987654321,
            observed_at=datetime.now(timezone.utc).isoformat(),
        ),
        timestamp=_now(),
    )
    configuration = _broker_configuration(tmp_path)
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker.store = store
    broker._active = {}
    broker._active_lock = threading.RLock()
    cleaned: list[str] = []
    monkeypatch.setattr(broker, "_remove_scratch", cleaned.append)
    monkeypatch.setattr(broker_module, "_unit_properties", lambda _unit: None)

    result = broker._recovery_cleanup({"identity": identity.to_mapping()})

    assert result == {"ok": True, "acknowledged": True}
    assert cleaned == [claim.attempt_id]


def test_systemd_runner_streams_validated_scratch_into_existing_publication(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, runner = _systemd_service(tmp_path, runner)
    events: list[str] = []
    complete_execution = service._store.complete_execution
    acknowledge_output = runner.acknowledge_output
    stream_systemd_execution = service.adapter.stream_systemd_execution

    def record_output_copy(*args, **kwargs):
        result = stream_systemd_execution(*args, **kwargs)
        events.append("output_copy_completed")
        return result

    def record_commit(*args, **kwargs):
        result = complete_execution(*args, **kwargs)
        events.append("publication_committed")
        return result

    def record_ack(identity, *, validated):
        events.append("scratch_cleanup_acknowledged")
        return acknowledge_output(identity, validated=validated)

    monkeypatch.setattr(service._store, "complete_execution", record_commit)
    monkeypatch.setattr(runner, "acknowledge_output", record_ack)
    monkeypatch.setattr(
        service.adapter, "stream_systemd_execution", record_output_copy
    )

    queued = service.enqueue(
        "systemd-success", _request(), workload_demand=heavy_workload_demand()
    )
    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "succeeded"
    assert len(service._store.artifacts()) == 1
    assert service._store.resource_snapshot()["state"] == "available"
    assert service._store.attempt_termination_proven(
        queued.job_id, service._store.current_attempt(queued.job_id)["attempt_id"]
    )
    assert runner.acknowledgements == [True]
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False
    assert events == [
        "output_copy_completed",
        "publication_committed",
        "scratch_cleanup_acknowledged",
    ]


@pytest.mark.parametrize("proof_state", ("missing", "conflicting"))
def test_systemd_publication_rejects_missing_or_conflicting_transaction_proof(
    tmp_path, monkeypatch: pytest.MonkeyPatch, proof_state: str
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, _runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        f"systemd-atomic-proof-{proof_state}",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    complete_execution = service._store.complete_execution
    validate_cgroup_proof = service._store._attempt_cgroup_termination_evidence

    def missing_or_conflicting_proof(connection, job_id, attempt_id):
        if proof_state == "missing":
            return False
        raise BackendEvidenceError("injected conflicting cgroup proof")

    def inject_proof_state(*args, **kwargs):
        service._store._attempt_cgroup_termination_evidence = (
            missing_or_conflicting_proof
        )
        try:
            return complete_execution(*args, **kwargs)
        finally:
            service._store._attempt_cgroup_termination_evidence = validate_cgroup_proof

    monkeypatch.setattr(service._store, "complete_execution", inject_proof_state)

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] != "succeeded"
    assert service._store.artifacts() == []


def test_recovery_pins_cgroup_events_fd_across_path_substitution(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = _identity()
    cgroup_path = Path("/sys/fs/cgroup") / template.cgroup_path.lstrip("/")
    original_cgroup = tmp_path / "original-cgroup"
    replacement_cgroup = tmp_path / "replacement-cgroup"
    original_cgroup.mkdir()
    replacement_cgroup.mkdir()
    (original_cgroup / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    (replacement_cgroup / "cgroup.events").write_text("populated 1\n", encoding="ascii")
    moved_cgroup = tmp_path / "moved-original-cgroup"
    original_open = os.open
    original_fstat = os.fstat
    original_stat = Path.stat
    cgroup_stat = original_stat(original_cgroup)
    template = replace(
        template,
        cgroup_device=cgroup_stat.st_dev,
        cgroup_inode=cgroup_stat.st_ino,
    )
    substituted = False
    relative_event_opened = False
    pinned_directory_fd: int | None = None

    def substitute_path() -> None:
        nonlocal substituted
        if substituted:
            return
        original_cgroup.rename(moved_cgroup)
        replacement_cgroup.rename(original_cgroup)
        substituted = True

    def fake_open(path, flags, *args, dir_fd=None):
        nonlocal pinned_directory_fd, relative_event_opened
        if dir_fd is not None and path == "cgroup.events":
            relative_event_opened = True
            return original_open(path, flags, *args, dir_fd=dir_fd)
        if dir_fd is None and Path(path) == cgroup_path:
            pinned_directory_fd = original_open(original_cgroup, flags, *args)
            return pinned_directory_fd
        if dir_fd is None and Path(path) == cgroup_path / "cgroup.events":
            assert substituted
            return original_open(original_cgroup / "cgroup.events", flags, *args)
        return original_open(path, flags, *args, dir_fd=dir_fd)

    def fake_fstat(descriptor: int):
        observed = original_fstat(descriptor)
        if descriptor == pinned_directory_fd:
            substitute_path()
        return observed

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if path == cgroup_path:
            observed = original_stat(original_cgroup, follow_symlinks=follow_symlinks)
            substitute_path()
            return observed
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(broker_module.os, "open", fake_open)
    monkeypatch.setattr(broker_module.os, "fstat", fake_fstat)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_boot_id", lambda: template.boot_id)
    monkeypatch.setattr(
        broker_module,
        "_unit_properties",
        lambda _unit: {
            "InvocationID": template.invocation_id,
            "ControlGroup": template.cgroup_path,
        },
    )
    monkeypatch.setattr(broker_module, "_stop_unit", lambda _unit: None)
    monkeypatch.setattr(
        broker_module,
        "_wait_cgroup_empty",
        lambda events_fd, *, timeout: broker_module._read_populated(events_fd) == 0,
    )
    proof = CgroupTerminationEvidence(
        identity=template,
        populated=0,
        observed_monotonic_ns=987654321,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )
    monkeypatch.setattr(
        broker_module,
        "_record_pinned_empty_event",
        lambda _store, _identity, _events_fd: proof,
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(empty_timeout_seconds=0.1)
    broker.store = object()
    termination = broker._stop_and_record(template)

    assert substituted is True
    assert relative_event_opened is True
    assert termination == proof


def test_worker_writable_database_cannot_forge_cgroup_termination(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    forged = CgroupTerminationEvidence(
        identity=identity,
        populated=0,
        observed_monotonic_ns=987654321,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    with store._connection(transaction=True) as connection:
        connection.execute(
            """UPDATE execution_containment
               SET termination_json = ?, termination_at = ?
               WHERE job_id = ? AND attempt_id = ?""",
            (
                store_module.backend_canonical_json(forged.to_mapping()),
                _now(),
                claim.job_id,
                claim.attempt_id,
            ),
        )

    assert store.cancel_execution(claim.job_id, _now()) == "requested"
    assert store.fail_execution(
        claim.job_id,
        claim.attempt_id,
        "canceled with forged cgroup proof",
        _now(),
        attempt_owner_id=claim.owner_id,
        claim_epoch=claim.claim_epoch,
        failure_class="canceled",
        termination_proven=True,
    )
    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id) is False
    assert store.resource_snapshot()["state"] == "quarantined"
    assert store.release_quarantined_attempt(
        claim.job_id, claim.attempt_id, timestamp=_now()
    ) is False


def test_root_ledger_proof_survives_failed_job_database_mirror(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    with store._connection(transaction=True) as connection:
        connection.execute(
            """CREATE TRIGGER reject_termination_mirror
               BEFORE UPDATE OF termination_json ON execution_containment
               BEGIN SELECT RAISE(ABORT, 'simulated mirror failure'); END"""
        )
    evidence = CgroupTerminationEvidence(
        identity=identity,
        populated=0,
        observed_monotonic_ns=987654321,
        observed_at=datetime.now(timezone.utc).isoformat(),
    )

    with pytest.raises(sqlite3.IntegrityError, match="simulated mirror failure"):
        store.record_attempt_termination_evidence(
            identity, evidence, timestamp=_now()
        )

    assert store.attempt_termination_proven(claim.job_id, claim.attempt_id)


def test_systemd_evidence_ledger_rejects_worker_owned_or_writable_files() -> None:
    worker_owned = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o640,
        st_uid=os.getuid(),
    )
    group_writable = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o660,
        st_uid=0,
    )

    with pytest.raises(PermissionError, match="root-owned and non-writable"):
        SystemdEvidenceLedger._require_trusted_file(
            worker_owned, require_root=True
        )
    with pytest.raises(PermissionError, match="root-owned and non-writable"):
        SystemdEvidenceLedger._require_trusted_file(
            group_writable, require_root=True
        )


def test_systemd_evidence_ledger_requires_worker_group_read_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = SystemdEvidenceLedger(tmp_path / "attempt-evidence.sqlite3")
    ledger.path.touch()
    worker_gid = 81231
    facts = {
        "st_mode": stat.S_IFREG | 0o640,
        "st_uid": 0,
        "st_gid": worker_gid,
    }
    original_lstat = Path.lstat

    def lstat(path: Path):
        if path == ledger.path:
            return SimpleNamespace(**facts)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    ledger.validate_worker_access(worker_gid)

    facts["st_gid"] = worker_gid + 1
    with pytest.raises(PermissionError, match="readable by the worker group"):
        ledger.validate_worker_access(worker_gid)
    facts["st_gid"] = worker_gid
    facts["st_mode"] = stat.S_IFREG | 0o600
    with pytest.raises(PermissionError, match="readable by the worker group"):
        ledger.validate_worker_access(worker_gid)


def test_worker_scratch_membership_uses_nss_group_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(pw_name="media-worker", pw_gid=81230)
    scratch_gid = 81231
    monkeypatch.setattr(broker_module.grp, "getgrall", lambda: [])
    monkeypatch.setattr(
        broker_module.os,
        "getgrouplist",
        lambda name, primary_gid: [primary_gid, scratch_gid],
    )

    assert broker_module._member_of_group(user, scratch_gid)


def test_worker_scratch_membership_fails_closed_when_nss_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(pw_name="media-worker", pw_gid=81230)

    def unavailable(_name: str, _primary_gid: int) -> list[int]:
        raise OSError("NSS group lookup unavailable")

    monkeypatch.setattr(broker_module.os, "getgrouplist", unavailable)

    with pytest.raises(ValueError, match="worker supplementary group membership"):
        broker_module._member_of_group(user, 81231)


def test_systemd_runner_rejects_comfyui_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = object.__new__(ComfyUIAdapter)
    runner = SystemdAttemptRunner(
        tmp_path / "broker.sock",
        scratch_root=tmp_path / "scratch",
        runner_uid=2301,
        runner_gid=2301,
    )
    monkeypatch.setattr(
        service_module,
        "application_privacy_policy",
        lambda _adapter: object(),
    )
    monkeypatch.setattr(GenerationService, "_current_privacy_snapshot", lambda _self: None)

    with pytest.raises(ValueError, match="StableDiffusionCppAdapter"):
        GenerationService(
            tmp_path / "media.sqlite3",
            tmp_path / "images",
            adapter=adapter,
            attempt_runner=runner,
        )


def test_control_only_runner_can_recover_but_cannot_claim_execution(
    tmp_path: Path,
) -> None:
    runner = SystemdAttemptRunner(
        tmp_path / "broker.sock",
        scratch_root=tmp_path / "scratch",
        runner_uid=2301,
        runner_gid=2301,
    )
    service = GenerationService(
        tmp_path / "control.sqlite3",
        tmp_path / "images",
        attempt_runner=runner,
    )
    queued = service.enqueue("control-only", _request())

    with pytest.raises(ValueError, match="StableDiffusionCppAdapter"):
        service.work()

    assert service.get_job(queued.job_id).execution_status == "queued"
    assert service._store.current_attempt(queued.job_id) is None
    assert service._store.resource_snapshot()["state"] == "available"


@pytest.mark.parametrize(
    ("stored_identity", "cgroup_empty", "launcher_reaped", "cleaned"),
    [
        (True, True, True, True),
        (False, True, True, False),
        (True, False, True, False),
        (True, True, False, False),
    ],
)
def test_setup_failure_scratch_cleanup_requires_identity_termination_and_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stored_identity: bool,
    cgroup_empty: bool,
    launcher_reaped: bool,
    cleaned: bool,
) -> None:
    identity = _identity()
    events: list[str] = []
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(empty_timeout_seconds=0.1)
    broker.store = SimpleNamespace(
        attempt_containment_identity=lambda _job, _attempt: (
            identity if stored_identity else None
        )
    )
    broker._remove_scratch = lambda _attempt: events.append("scratch_removed")
    monkeypatch.setattr(
        broker_module,
        "_stop_unit",
        lambda _unit: events.append("unit_stopped"),
    )
    monkeypatch.setattr(
        broker_module,
        "_wait_cgroup_empty",
        lambda _fd, timeout: events.append("cgroup_checked") or cgroup_empty,
    )
    monkeypatch.setattr(
        broker_module,
        "_record_pinned_empty_event",
        lambda _store, _identity, _fd: events.append("proof_recorded"),
    )

    class Launcher:
        def wait(self, *, timeout: float) -> int:
            events.append("launcher_waited")
            if not launcher_reaped:
                raise OSError("launcher could not be reaped")
            return 1

        @staticmethod
        def terminate() -> None:
            events.append("launcher_terminated")

    fd = os.open("/dev/null", os.O_RDONLY)
    try:
        result = broker._cleanup_failed_containment_setup(
            Launcher(), identity, fd
        )
    finally:
        os.close(fd)

    assert result is cleaned
    assert ("proof_recorded" in events) is (stored_identity and cgroup_empty)
    assert ("scratch_removed" in events) is cleaned
    if cleaned:
        assert events.index("proof_recorded") < events.index("scratch_removed")
        assert events.index("launcher_waited") < events.index("scratch_removed")


def test_resolution_failure_leaves_no_broker_scratch_directory(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, runner = _systemd_service(tmp_path, runner)

    def refuse_resolution(*_args, **_kwargs):
        raise RuntimeError("synthetic resolution failure")

    monkeypatch.setattr(service.adapter, "resolve_execution", refuse_resolution)
    queued = service.enqueue(
        "systemd-resolution-failure",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_worker_validates_pinned_output_after_scratch_name_disappears(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", unlink_output_before_return=True
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-pinned-output", _request(), workload_demand=heavy_workload_demand()
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "succeeded"
    assert len(service._store.artifacts()) == 1
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_completion_observation_must_match_durable_engine_evidence(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", observation_delta={"stdout_bytes": 1}
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-mismatched-observation",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert service._store.artifacts() == []
    assert service._store.resource_snapshot()["state"] == "available"
    assert runner.acknowledgements == [False]


def test_engine_failure_with_successful_launcher_cannot_publish(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", engine_exit_code=23
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-engine-failed", _request(), workload_demand=heavy_workload_demand()
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert service.get_execution(queued.job_id)["observed"]["exit_code"] == 23
    assert service._store.resource_snapshot()["state"] == "available"
    assert service._store.artifacts() == []


def test_launcher_failure_with_successful_engine_cannot_publish(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", launcher_exit_code=7
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-launcher-failed", _request(), workload_demand=heavy_workload_demand()
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert service.get_execution(queued.job_id)["state"] == "observed"
    assert service._store.resource_snapshot()["state"] == "available"
    assert service._store.artifacts() == []


def test_signaled_runner_with_successful_engine_cannot_publish(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", runner_exit_signal=9
    )
    service, _runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-runner-signal", _request(), workload_demand=heavy_workload_demand()
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert service._store.artifacts() == []
    assert service._store.resource_snapshot()["state"] == "available"


def test_output_ack_failure_preserves_committed_success_and_leaves_recovery_scratch(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", acknowledgement_error=OSError("broker unavailable")
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-output-ack-failure",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "succeeded"
    assert len(service._store.artifacts()) == 1
    assert runner.acknowledgements == [True]
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists()
    pending = service._store.pending_systemd_output_cleanups(
        attempt_id=service._store.current_attempt(queued.job_id)["attempt_id"]
    )
    assert len(pending) == 1
    assert pending[0].validated is True

    runner.acknowledgement_error = None
    recovered = service.recover()

    assert recovered["resource_state"] == "available"
    assert recovered["scratch_cleanups"] == 1
    assert runner.acknowledgements == [True, True]
    assert runner.scratch_directory.exists() is False
    assert service._store.pending_systemd_output_cleanups() == ()


def test_bounded_recovery_cleans_old_attempt_after_retry_becomes_current(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch",
        acknowledgement_error=OSError("broker unavailable"),
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-old-attempt-cleanup",
        _request(),
        max_attempts=2,
        workload_demand=heavy_workload_demand(),
    )
    stream = service.adapter.stream_systemd_execution
    stream_count = 0

    def fail_first_stream(*args, **kwargs):
        nonlocal stream_count
        stream_count += 1
        if stream_count == 1:
            raise RetryableGenerationError("injected retryable stream failure")
        return stream(*args, **kwargs)

    monkeypatch.setattr(service.adapter, "stream_systemd_execution", fail_first_stream)
    first = service.work(limit=1)

    assert first["processed"] == 1
    first_attempt = service._store.current_attempt(queued.job_id)
    assert first_attempt is not None
    first_attempt_id = str(first_attempt["attempt_id"])
    first_scratch = runner.scratch_directory
    assert first_scratch is not None and first_scratch.exists()
    assert len(
        service._store.pending_systemd_output_cleanups(attempt_id=first_attempt_id)
    ) == 1

    runner.acknowledgement_error = None
    second = service.work(limit=1)

    assert second["processed"] == 1
    second_attempt = service._store.current_attempt(queued.job_id)
    assert second_attempt is not None
    assert second_attempt["attempt_id"] != first_attempt_id
    old_identity = service._store.attempt_containment_identity(
        queued.job_id, first_attempt_id
    )
    assert old_identity is not None
    assert service._store.systemd_output_cleanup_authorized(
        old_identity, validated=False
    ) is True

    recovered = service.recover()

    assert recovered["scratch_cleanups"] == 1
    assert first_scratch.exists() is False


@pytest.mark.parametrize("checkpoint", ("before_file_sync", "before_commit"))
def test_systemd_scratch_survives_until_publication_boundary_is_reconciled(
    tmp_path, monkeypatch: pytest.MonkeyPatch, checkpoint: str
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        f"systemd-cleanup-{checkpoint}",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    reached: list[str] = []

    def interrupt(name: str) -> None:
        if name == checkpoint:
            reached.append(name)
            assert runner.scratch_directory is not None
            assert runner.scratch_directory.exists()
            assert runner.acknowledgements == []
            raise RuntimeError(f"injected publication interruption at {name}")

    service._publication.checkpoint = interrupt
    report = service.work()

    assert report["processed"] == 1
    assert reached == [checkpoint]
    assert service.get_provenance(queued.job_id)["status"] != "succeeded"
    assert service._store.artifacts() == []
    assert runner.scratch_directory is not None
    assert runner.acknowledgements in ([], [False])
    assert runner.scratch_directory.exists() == (runner.acknowledgements == [])


def test_systemd_scratch_survives_after_durable_commit_until_cleanup_ack(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-cleanup-after-commit",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    reached: list[str] = []

    def interrupt(name: str) -> None:
        if name == "after_commit":
            reached.append(name)
            assert runner.scratch_directory is not None
            assert runner.scratch_directory.exists()
            assert runner.acknowledgements == []
            raise RuntimeError("injected interruption after durable commit")

    service._publication.checkpoint = interrupt
    report = service.work()

    assert report["processed"] == 1
    assert reached == ["after_commit"]
    assert service.get_provenance(queued.job_id)["status"] == "succeeded"
    assert len(service._store.artifacts()) == 1
    assert runner.acknowledgements == [True]
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_concurrent_cancellation_at_publication_commit_fences_scratch_cleanup(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(tmp_path / "broker-scratch")
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-cancel-at-publication-commit",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    reached: list[str] = []
    cancellation_finished = threading.Event()
    cancellation_result: list[str] = []

    def cancel_before_commit(name: str) -> None:
        if name == "before_commit":
            reached.append(name)
            assert runner.scratch_directory is not None
            assert runner.scratch_directory.exists()
            assert runner.acknowledgements == []
            def cancel() -> None:
                cancellation_result.append(
                    service._store.cancel_execution(queued.job_id, _now())
                )
                cancellation_finished.set()

            cancellation_thread = threading.Thread(target=cancel)
            cancellation_thread.start()
            assert cancellation_finished.wait(timeout=5)
            cancellation_thread.join(timeout=5)
            assert cancellation_thread.is_alive() is False

    service._publication.checkpoint = cancel_before_commit
    report = service.work()

    assert report["processed"] == 1
    assert reached == ["before_commit"]
    assert cancellation_result == ["requested"]
    assert service.get_provenance(queued.job_id)["status"] == "canceled"
    assert service._store.artifacts() == []
    assert runner.acknowledgements == [False]
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_missing_engine_observation_cannot_succeed_but_cgroup_proof_releases(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", record_engine=False
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-no-engine-observation",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    report = service.work()

    assert report["processed"] == 1
    attempt = service._store.current_attempt(queued.job_id)
    assert attempt is not None
    assert attempt["status"] == "failed"
    assert service.get_provenance(queued.job_id)["status"] == "failed"
    assert service.get_execution(queued.job_id)["state"] == "resolved"
    assert service._store.termination_evidence_proven(
        queued.job_id, str(attempt["attempt_id"])
    ) is False
    assert service._store.attempt_termination_proven(
        queued.job_id, str(attempt["attempt_id"])
    )
    assert service._store.resource_snapshot()["state"] == "available"
    assert service._store.artifacts() == []
    assert runner.acknowledgements == [False]


def test_runner_exit_without_cgroup_proof_quarantines_and_publishes_nothing(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", record_cgroup=False
    )
    service, _runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-no-cgroup-proof",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    report = service.work()

    assert report["processed"] == 1
    attempt = service._store.current_attempt(queued.job_id)
    assert attempt is not None
    assert service.get_execution(queued.job_id)["state"] == "observed"
    assert service._store.termination_evidence_proven(
        queued.job_id, str(attempt["attempt_id"])
    )
    assert service._store.attempt_termination_proven(
        queued.job_id, str(attempt["attempt_id"])
    ) is False
    assert service._store.resource_snapshot()["state"] == "quarantined"
    assert service._store.artifacts() == []
    assert runner.acknowledgements == []


def test_force_killed_runner_with_empty_cgroup_releases_failed_attempt(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch",
        record_engine=False,
        runner_exit_code=137,
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-killed-runner",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    report = service.work()

    assert report["processed"] == 1
    attempt = service._store.current_attempt(queued.job_id)
    assert attempt is not None
    assert service.get_execution(queued.job_id)["state"] == "resolved"
    assert service._store.termination_evidence_proven(
        queued.job_id, str(attempt["attempt_id"])
    ) is False
    assert service._store.attempt_termination_proven(
        queued.job_id, str(attempt["attempt_id"])
    )
    assert service._store.resource_snapshot()["state"] == "available"
    assert service._store.artifacts() == []
    assert runner.acknowledgements == [False]


def test_cancellation_after_runner_completion_cannot_publish_stale_output(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", cancel_before_return=True
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-cancel-before-publication",
        _request(),
        workload_demand=heavy_workload_demand(),
    )
    report = service.work()

    assert report["processed"] == 1
    assert service.get_provenance(queued.job_id)["status"] == "canceled"
    assert service._store.artifacts() == []
    assert service._store.resource_snapshot()["state"] == "available"
    # The worker may finish validation after cancellation, but publication
    # authority is fenced and the existing publisher refuses the commit.
    assert runner.acknowledgements == [False]
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_worker_loss_before_result_retrieval_recovers_from_cgroup_proof(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", fence_before_return=True
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-worker-loss",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    work = service.work()
    assert work["processed"] == 1
    assert service._store.resource_snapshot()["state"] == "claimed"
    assert service._store.artifacts() == []

    recovered = service.recover()

    assert recovered["resource_state"] == "available"
    assert service._store.attempt_termination_proven(
        queued.job_id, service._store.current_attempt(queued.job_id)["attempt_id"]
    )
    assert service._store.artifacts() == []
    assert runner.scratch_directory is not None
    assert runner.scratch_directory.exists() is False


def test_unvalidated_output_ack_cannot_remove_live_attempt_scratch(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    store, claim, identity = _claimed_systemd_attempt(tmp_path)
    store.bind_attempt_containment(identity, timestamp=_now())
    store.record_attempt_termination_evidence(
        identity,
        CgroupTerminationEvidence(
            identity=identity,
            populated=0,
            observed_monotonic_ns=987654321,
            observed_at=datetime.now(timezone.utc).isoformat(),
        ),
        timestamp=_now(),
    )
    configuration = _broker_configuration(tmp_path)
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker.store = store
    broker._active = {}
    broker._active_lock = threading.RLock()

    with pytest.raises(BackendEvidenceError, match="unvalidated scratch cleanup"):
        broker._output_ack({"identity": identity.to_mapping(), "validated": False})

    assert store.current_attempt(claim.job_id)["status"] == "running"


def test_containment_event_descriptor_stays_bound_to_opened_cgroup(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = _identity()
    cgroup_path = Path("/sys/fs/cgroup") / template.cgroup_path.lstrip("/")
    original_cgroup = tmp_path / "original-cgroup"
    replacement_cgroup = tmp_path / "replacement-cgroup"
    original_cgroup.mkdir()
    replacement_cgroup.mkdir()
    (original_cgroup / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    (replacement_cgroup / "cgroup.events").write_text("populated 1\n", encoding="ascii")
    original_stat = Path.stat
    original_open = os.open

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if path == cgroup_path:
            return original_stat(original_cgroup, follow_symlinks=follow_symlinks)
        return original_stat(path, follow_symlinks=follow_symlinks)

    def fake_open(path, flags, *args, dir_fd=None):
        if dir_fd is not None:
            return original_open(path, flags, *args, dir_fd=dir_fd)
        if Path(path) == cgroup_path:
            return original_open(original_cgroup, flags, *args)
        if Path(path) == cgroup_path / "cgroup.events":
            return original_open(replacement_cgroup / "cgroup.events", flags, *args)
        return original_open(path, flags, *args)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module.os, "open", fake_open)
    monkeypatch.setattr(
        broker_module,
        "_unit_properties",
        lambda _unit: {
            "InvocationID": template.invocation_id,
            "ControlGroup": template.cgroup_path,
        },
    )
    monkeypatch.setattr(broker_module, "_validate_unit_policy", lambda *_args: None)
    monkeypatch.setattr(broker_module, "_boot_id", lambda: template.boot_id)
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        runner_uid=template.runner_uid, runner_gid=template.runner_gid
    )
    broker.store = SimpleNamespace(bind_attempt_containment=lambda *_args, **_kwargs: None)

    identity, events_fd = broker._wait_for_containment(
        SimpleNamespace(poll=lambda: None),
        template.unit_name,
        template.job_id,
        template.attempt_id,
        template.owner_id,
        template.claim_epoch,
        template.resolved_digest,
    )
    try:
        assert (identity.cgroup_device, identity.cgroup_inode) == (
            original_stat(original_cgroup).st_dev,
            original_stat(original_cgroup).st_ino,
        )
        assert broker_module._read_populated(events_fd) == 0
    finally:
        os.close(events_fd)
