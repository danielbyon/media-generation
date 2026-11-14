from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import io
import json
import os
import socket
import sqlite3
import stat
import shutil
import sys
import struct
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import attempt_runner as attempt_runner_module
from media_generation import engine
from media_generation import service as service_module
from media_generation import store as store_module
from media_generation import systemd_broker as broker_module
from media_generation.attempt_runner import _validate_manifest
from media_generation.backend_provenance import backend_digest, environment_record
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
            fields = list(info)
            fields[4] = 0
            return os.stat_result(fields)
        if path.name == "systemd-evidence":
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o750
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
        if path.name.startswith("pytest-") and path.parent.name.startswith(
            "pytest-of-"
        ):
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o755
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
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
        runner_supplementary_gids=(2302, 2303, 2304),
        worker_uid=2300,
        worker_gid=2300,
        scratch_gid=2302,
        model_read_gid=2303,
        device_allow=(Path("/dev/kfd"),),
        read_roots=(tmp_path,),
        environment_path_allowlist=(tmp_path,),
    )


def test_broker_creates_attempt_scratch_as_root_scratch_mode_2770(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = _broker_configuration(tmp_path)
    configuration.scratch_root.mkdir()
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    changes: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        broker_module.os,
        "chown",
        lambda path, uid, gid: changes.append(("chown", path, uid, gid)),
    )
    monkeypatch.setattr(
        broker_module.os,
        "chmod",
        lambda path, mode: changes.append(("chmod", path, mode)),
    )

    broker._create_attempt_scratch(_identity().attempt_id)

    scratch = configuration.scratch_root / _identity().attempt_id
    assert changes == [
        ("chown", scratch, 0, configuration.scratch_gid),
        ("chmod", scratch, 0o2770),
    ]


def test_broker_configuration_accepts_private_model_read_group_and_path_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "broker.json"
    runtime = tmp_path / "rocm-runtime"
    payload = {
        "database_path": str(tmp_path / "jobs.sqlite3"),
        "socket_path": str(tmp_path / "attempt-broker.sock"),
        "scratch_root": str(tmp_path / "scratch"),
        "runner_executable": str(tmp_path / "attempt-runner"),
        "runner_uid": 2301,
        "runner_gid": 2301,
        "runner_supplementary_gids": [2302, 2303, 990],
        "worker_uid": 2300,
        "worker_gid": 2300,
        "scratch_gid": 2302,
        "model_read_gid": 2303,
        "device_allow": ["/dev/kfd", "/dev/dri/renderD128"],
        "read_roots": [str(tmp_path / "candidate")],
        "environment_path_allowlist": [
            "/usr/bin",
            str(runtime),
            str(runtime / "lib"),
        ],
        "empty_timeout_seconds": 30,
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        if path == config_path:
            return os.stat_result(
                (stat.S_IFREG | 0o640, 1, 1, 1, 0, 0, 4096, 0, 0, 0)
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(BrokerConfiguration, "validate_host_paths", lambda _self: None)

    configuration = BrokerConfiguration.from_file(config_path)

    assert configuration.model_read_gid == 2303
    assert configuration.environment_path_allowlist == (
        Path("/usr/bin"),
        runtime,
        runtime / "lib",
    )


def _install_valid_broker_host_mocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    configuration: BrokerConfiguration | None = None,
    extra_group_member_gid: int | None = None,
    extra_primary_member_gid: int | None = None,
) -> BrokerConfiguration:
    if configuration is None:
        configuration = _broker_configuration(tmp_path)
    runner = SimpleNamespace(pw_name="engine-runner", pw_gid=configuration.runner_gid)
    worker = SimpleNamespace(pw_name="generation-worker", pw_gid=configuration.worker_gid)
    groups = {
        configuration.runner_gid: {runner.pw_name},
        configuration.worker_gid: {worker.pw_name},
        configuration.scratch_gid: {runner.pw_name},
        configuration.model_read_gid: {runner.pw_name, worker.pw_name},
    }
    if extra_group_member_gid is not None:
        groups[extra_group_member_gid].add("unapproved-user")
    primary_users = [runner, worker]
    if extra_primary_member_gid is not None:
        primary_users.append(
            SimpleNamespace(pw_name="unapproved-user", pw_gid=extra_primary_member_gid)
        )
    scratch_info = os.stat_result(
        (
            stat.S_IFDIR | 0o710,
            1,
            1,
            1,
            0,
            configuration.scratch_gid,
            0,
            0,
            0,
            0,
        )
    )
    runner_info = os.stat_result(
        (
            stat.S_IFREG | 0o750,
            2,
            1,
            1,
            0,
            configuration.model_read_gid,
            1,
            0,
            0,
            0,
        )
    )
    device_info = os.stat_result(
        (
            stat.S_IFCHR | 0o660,
            3,
            1,
            1,
            0,
            2304,
            0,
            0,
            0,
            0,
        )
    )
    original_lstat = Path.lstat
    original_stat = Path.stat

    def fake_lstat(path: Path):
        if path == configuration.scratch_root:
            return scratch_info
        return original_lstat(path)

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if path == configuration.runner_executable:
            return runner_info
        if path in configuration.device_allow:
            return device_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(
        broker_module.pwd,
        "getpwuid",
        lambda uid: runner if uid == configuration.runner_uid else worker,
    )
    monkeypatch.setattr(
        broker_module.pwd, "getpwall", lambda: primary_users
    )
    monkeypatch.setattr(
        broker_module,
        "_complete_account_members",
        lambda: tuple((entry.pw_name, entry.pw_gid) for entry in primary_users),
        raising=False,
    )

    def fake_group(gid: int) -> SimpleNamespace:
        return SimpleNamespace(gr_gid=gid, gr_mem=sorted(groups.get(gid, set())))

    monkeypatch.setattr(broker_module.grp, "getgrgid", fake_group)
    monkeypatch.setattr(
        broker_module.os,
        "getgrouplist",
        lambda name, _gid: (
            [configuration.runner_gid, *configuration.runner_supplementary_gids]
            if name == runner.pw_name
            else [configuration.worker_gid, configuration.model_read_gid]
        ),
    )
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(broker_module, "_require_root_executable", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_no_extended_posix_acl_ancestors", lambda _path: None
    )
    monkeypatch.setattr(
        SystemdEvidenceLedger, "validate_worker_access", lambda *_args: None
    )

    return configuration


def test_broker_validates_shared_read_group_and_scratch_root_0710(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)
    configuration.validate_host_paths()


@pytest.mark.parametrize(
    "ledger_exists", (False, True), ids=("first-start", "existing-ledger")
)
def test_broker_validates_evidence_directory_before_optional_ledger_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ledger_exists: bool,
) -> None:
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)
    ledger_path = SystemdEvidenceLedger.path_for(configuration.database_path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if ledger_exists:
        ledger_path.touch()
    else:
        assert not ledger_path.exists()

    checked_paths: list[Path] = []

    def check_acl_path(path: Path) -> None:
        path = Path(path)
        if path in {ledger_path, ledger_path.parent}:
            checked_paths.append(path)
            path.lstat()

    monkeypatch.setattr(
        broker_module, "_require_no_extended_posix_acl_ancestors", check_acl_path
    )

    configuration.validate_host_paths()

    assert ledger_path.parent in checked_paths
    assert (ledger_path in checked_paths) is ledger_exists


@pytest.mark.parametrize(
    ("group_field", "member_source"),
    [
        ("runner_gid", "supplementary"),
        ("model_read_gid", "supplementary"),
        ("scratch_gid", "supplementary"),
        ("worker_gid", "supplementary"),
        ("runner_gid", "primary"),
        ("model_read_gid", "primary"),
        ("scratch_gid", "primary"),
        ("worker_gid", "primary"),
    ],
    ids=[
        "runner-extra-supplementary",
        "model-read-extra-supplementary",
        "scratch-extra-supplementary",
        "worker-extra-supplementary",
        "runner-extra-primary",
        "model-read-extra-primary",
        "scratch-extra-primary",
        "worker-extra-primary",
    ],
)
def test_broker_rejects_unapproved_member_of_private_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    group_field: str,
    member_source: str,
) -> None:
    configuration = _broker_configuration(tmp_path)
    gid = getattr(configuration, group_field)
    configuration = _install_valid_broker_host_mocks(
        tmp_path,
        monkeypatch,
        configuration=configuration,
        extra_group_member_gid=gid if member_source == "supplementary" else None,
        extra_primary_member_gid=gid if member_source == "primary" else None,
    )

    with pytest.raises(PermissionError, match="group membership"):
        configuration.validate_host_paths()


def test_broker_fails_closed_when_protected_group_membership_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)

    def unavailable_accounts():
        raise OSError("NSS account enumeration failed")

    monkeypatch.setattr(
        broker_module, "_complete_account_members", unavailable_accounts, raising=False
    )

    with pytest.raises(PermissionError, match="host group membership cannot be verified"):
        configuration.validate_host_paths()


@pytest.mark.parametrize(
    "enumerated_accounts",
    [[], [SimpleNamespace(pw_name="runner", pw_gid=970)]],
    ids=["empty-getpwall", "partial-getpwall"],
)
def test_broker_account_primary_group_check_uses_complete_passwd_file(
    monkeypatch: pytest.MonkeyPatch,
    enumerated_accounts: list[SimpleNamespace],
) -> None:
    passwd_text = """\
root:x:0:0:root:/root:/bin/sh
runner:x:970:970:runner:/nonexistent:/usr/sbin/nologin
worker:x:972:972:worker:/nonexistent:/usr/sbin/nologin
unapproved:x:1888:971:unapproved:/nonexistent:/usr/sbin/nologin
"""
    monkeypatch.setattr(broker_module.sys, "platform", "linux")
    monkeypatch.setattr(broker_module.pwd, "getpwall", lambda: enumerated_accounts)
    monkeypatch.setattr(
        broker_module,
        "_read_protected_nss_file",
        lambda path: (
            "passwd: files\ngroup: files\n"
            if path.name == "nsswitch.conf"
            else passwd_text
        ),
        raising=False,
    )

    members = broker_module._complete_account_members()

    assert members == (
        ("root", 0),
        ("runner", 970),
        ("worker", 972),
        ("unapproved", 971),
    )
    assert {name for name, gid in members if gid == 971} == {"unapproved"}


def test_broker_rejects_incomplete_nss_sources_for_protected_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(broker_module.sys, "platform", "linux")
    monkeypatch.setattr(
        broker_module,
        "_read_protected_nss_file",
        lambda path: (
            "passwd: files systemd sss\ngroup: files systemd sss\n"
            if path.name == "nsswitch.conf"
            else "runner:x:970:970:runner:/nonexistent:/usr/sbin/nologin\n"
        ),
        raising=False,
    )

    with pytest.raises(PermissionError, match="complete local NSS sources"):
        broker_module._complete_account_members()


def test_broker_configuration_surfaces_external_nss_membership_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete_account_members = broker_module._complete_account_members
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)
    monkeypatch.setattr(broker_module.sys, "platform", "linux")
    monkeypatch.setattr(
        broker_module,
        "_read_protected_nss_file",
        lambda path: (
            "passwd: files systemd sss\ngroup: files systemd sss\n"
            if path.name == "nsswitch.conf"
            else ""
        ),
    )
    monkeypatch.setattr(
        broker_module, "_complete_account_members", complete_account_members
    )

    with pytest.raises(PermissionError, match="complete local NSS sources"):
        configuration.validate_host_paths()


def test_broker_rejects_primary_group_member_hidden_by_getpwall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete_account_members = broker_module._complete_account_members
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)
    passwd_text = """\
root:x:0:0:root:/root:/bin/sh
engine-runner:x:2301:2301:runner:/nonexistent:/sbin/nologin
generation-worker:x:2300:2300:worker:/nonexistent:/sbin/nologin
unapproved:x:2400:2303:user:/nonexistent:/sbin/nologin
"""
    monkeypatch.setattr(broker_module.sys, "platform", "linux")
    monkeypatch.setattr(
        broker_module.pwd,
        "getpwall",
        lambda: [
            SimpleNamespace(pw_name="engine-runner", pw_gid=2301),
            SimpleNamespace(pw_name="generation-worker", pw_gid=2300),
        ],
    )
    monkeypatch.setattr(
        broker_module,
        "_read_protected_nss_file",
        lambda path: (
            "passwd: files\ngroup: files\n"
            if path.name == "nsswitch.conf"
            else passwd_text
        ),
    )
    monkeypatch.setattr(
        broker_module, "_complete_account_members", complete_account_members
    )

    with pytest.raises(PermissionError, match="model-read group membership differs"):
        configuration.validate_host_paths()


def test_broker_rejects_default_acl_on_scratch_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import errno

    require_no_extended_acl = broker_module._require_no_extended_posix_acl_ancestors
    configuration = _install_valid_broker_host_mocks(tmp_path, monkeypatch)

    def fake_getxattr(path, name: str, *, follow_symlinks: bool = True) -> bytes:
        if Path(path) == configuration.scratch_root and name == "system.posix_acl_default":
            return b"inherited-acl"
        raise OSError(errno.ENODATA, "attribute not present")

    monkeypatch.setattr(broker_module.os, "getxattr", fake_getxattr, raising=False)
    monkeypatch.setattr(
        broker_module,
        "_require_no_extended_posix_acl_ancestors",
        require_no_extended_acl,
    )

    with pytest.raises(PermissionError, match="extended POSIX ACLs"):
        configuration.validate_host_paths()


@pytest.mark.parametrize(
    ("mode", "expected_to_pass"),
    [(0o710, True), (0o770, False)],
    ids=["root-scratch-traversable", "group-writable-rejected"],
)
def test_scratch_root_is_root_owned_non_group_writable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
    expected_to_pass: bool,
) -> None:
    scratch_root = tmp_path / "scratch"
    info = os.stat_result(
        (stat.S_IFDIR | mode, 1, 1, 1, 0, 2302, 0, 0, 0, 0)
    )
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(Path, "lstat", lambda _path: info)

    if expected_to_pass:
        _require_root_directory(scratch_root)
    else:
        with pytest.raises(PermissionError, match="not world-writable"):
            _require_root_directory(scratch_root)


def test_broker_socket_is_connectable_by_worker_through_checked_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("the broker uses Linux AF_UNIX/SOCK_SEQPACKET sockets")
    socket_path = tmp_path / "run" / "attempt-broker.sock"
    socket_path.parent.mkdir()
    worker_uid = os.getuid()
    worker_gid = os.getgid()
    groups = frozenset((*os.getgroups(), worker_gid))
    configuration = SimpleNamespace(
        socket_path=socket_path,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
        worker_groups=groups,
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker._server = None
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module.os,
        "chown",
        lambda path, uid, gid: calls.append(("chown", path, uid, gid)),
    )
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        info = original_lstat(path)
        if path == socket_path.parent:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o750
            fields[4] = 0
            fields[5] = worker_gid
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    broker._open_server_socket()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        client.connect(str(socket_path))
        accepted, _address = broker._server.accept()
        accepted.close()
        assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o660
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o750
        assert calls == [
            ("chown", socket_path.parent, 0, worker_gid),
            ("chown", socket_path, 0, worker_gid),
        ]
    finally:
        client.close()
        assert broker._server is not None
        broker._server.close()


def test_broker_prepares_systemd_runtime_directory_inside_main_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "run" / "attempt-broker.sock"
    socket_path.parent.mkdir()
    socket_path.parent.chmod(0o700)
    worker_uid = os.getuid()
    worker_gid = os.getgid()
    groups = frozenset((*os.getgroups(), worker_gid))
    configuration = SimpleNamespace(
        socket_path=socket_path,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
        worker_groups=groups,
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker._server = None
    operations: list[tuple[object, ...]] = []
    original_chmod = os.chmod

    class FakeSocket:
        def bind(self, path: str) -> None:
            Path(path).touch()
            operations.append(("bind",))

        def listen(self, _backlog: int) -> None:
            operations.append(("listen",))

        def close(self) -> None:
            operations.append(("close",))

    monkeypatch.setattr(
        broker_module.socket,
        "socket",
        lambda *_args: FakeSocket(),
    )

    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module,
        "_require_no_extended_posix_acl_ancestors",
        lambda _path: None,
    )
    monkeypatch.setattr(
        broker_module.os,
        "chown",
        lambda path, uid, gid: operations.append(("chown", path, uid, gid)),
    )
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        if path == socket_path.parent:
            return SimpleNamespace(
                st_uid=0,
                st_gid=worker_gid,
                st_mode=stat.S_IFDIR | 0o750,
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    def record_chmod(path: Path, mode: int) -> None:
        operations.append(("chmod", path, mode))
        original_chmod(path, mode)

    monkeypatch.setattr(broker_module.os, "chmod", record_chmod)

    def record_traversal(path, uid, gids, *, label):
        operations.append(("traversal", path, uid, gids))

    monkeypatch.setattr(broker_module, "_require_directory_traversal", record_traversal)

    broker._open_server_socket()
    assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o750
    assert operations[:3] == [
        ("chown", socket_path.parent, 0, worker_gid),
        ("chmod", socket_path.parent, 0o750),
        ("traversal", socket_path.parent, worker_uid, groups),
    ]
    assert operations.index(("bind",)) > operations.index(("traversal", socket_path.parent, worker_uid, groups))
    assert broker._server is not None


def test_broker_does_not_bind_socket_when_worker_cannot_traverse_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "run" / "attempt-broker.sock"
    socket_path.parent.mkdir()
    configuration = SimpleNamespace(
        socket_path=socket_path,
        worker_uid=2300,
        worker_gid=2300,
        worker_groups=frozenset({2300}),
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = configuration
    broker._server = None
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(broker_module.os, "chown", lambda *_args: None)
    monkeypatch.setattr(broker_module.os, "chmod", lambda *_args: None)
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        if path == socket_path.parent:
            return SimpleNamespace(
                st_uid=0,
                st_gid=configuration.worker_gid,
                st_mode=stat.S_IFDIR | 0o750,
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    def reject_worker_traversal(
        path: Path, uid: int, _gids: frozenset[int], *, label: str
    ) -> None:
        assert path == socket_path.parent
        assert uid == configuration.worker_uid
        raise PermissionError(label)

    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", reject_worker_traversal
    )

    with pytest.raises(PermissionError, match="worker cannot traverse"):
        broker._open_server_socket()
    assert not socket_path.exists()


@pytest.mark.parametrize(
    ("peer_uid", "peer_gid", "authorized"),
    [(2300, 2300, True), (2301, 2300, False), (2300, 2301, False)],
    ids=["worker", "wrong-user", "wrong-primary-group"],
)
def test_broker_authenticates_worker_socket_peer(
    monkeypatch: pytest.MonkeyPatch,
    peer_uid: int,
    peer_gid: int,
    authorized: bool,
) -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("the broker uses Linux AF_UNIX/SOCK_SEQPACKET sockets")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(worker_uid=2300, worker_gid=2300)
    validation_calls: list[bytes] = []
    monkeypatch.setattr(
        broker_module,
        "_peer_credentials",
        lambda _connection: (42, peer_uid, peer_gid),
    )
    monkeypatch.setattr(
        broker_module,
        "_validated_request",
        lambda packet: (validation_calls.append(packet) or ("output_ack", {})),
    )
    monkeypatch.setattr(
        broker, "_output_ack", lambda _request: {"ok": True, "acknowledged": True}
    )
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        client.send(b"request")
        broker._serve_connection(server)
        response = json.loads(client.recv(4096))
    finally:
        client.close()

    assert (response.get("ok") is True) is authorized
    assert len(validation_calls) == int(authorized)


def test_broker_peer_authorization_uses_linux_credential_field_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(worker_uid=2300, worker_gid=2300)
    responses: list[dict[str, object]] = []

    class PeerConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def recvmsg(_limit):
            return b"request", (), 0, None

    connection = PeerConnection()
    monkeypatch.setattr(
        broker_module,
        "_peer_credentials",
        lambda _connection: (42, 2300, 2300),
    )
    monkeypatch.setattr(
        broker_module, "_validated_request", lambda _packet: ("output_ack", {})
    )
    monkeypatch.setattr(
        broker,
        "_output_ack",
        lambda _request: {"ok": True, "acknowledged": True},
    )
    monkeypatch.setattr(
        broker_module,
        "_send",
        lambda _connection, response, **_kwargs: responses.append(dict(response)),
    )

    broker._serve_connection(connection)

    assert responses == [{"ok": True, "acknowledged": True}]


def test_systemd_attempt_runner_launches_engine_from_root_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    scratch = tmp_path / "private-scratch"
    scratch.mkdir()
    engine_script = tmp_path / "cwd-check.py"
    engine_script.write_text(
        "import os, sys\n"
        "sys.exit(0 if os.getcwd() == '/' else 71)\n",
        encoding="utf-8",
    )
    output = scratch / "output.png"
    argv = [sys.executable, str(engine_script), "-o", str(output)]
    environment: dict[str, str] = {}
    manifest = {
        "identity": identity.to_mapping(),
        "argv": argv,
        "environment": environment,
        "scratch_directory": str(scratch),
        "resolved_record": {
            "attempt_id": identity.attempt_id,
            "argv": argv,
            "environment": environment_record(environment),
            "output_basename": output.name,
        },
    }
    control_output = io.BytesIO()
    monkeypatch.setattr(
        attempt_runner_module.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(json.dumps(manifest).encode() + b"\n")),
    )
    monkeypatch.setattr(
        attempt_runner_module.sys, "stdout", SimpleNamespace(buffer=control_output)
    )
    monkeypatch.setattr(
        attempt_runner_module.os, "geteuid", lambda: identity.runner_uid
    )
    monkeypatch.setattr(
        attempt_runner_module.os, "getegid", lambda: identity.runner_gid
    )
    monkeypatch.setattr(
        attempt_runner_module, "_current_cgroup", lambda: identity.cgroup_path
    )
    monkeypatch.setattr(
        attempt_runner_module,
        "_exchange",
        lambda request: {"ok": True, "current": True},
    )

    assert attempt_runner_module.main() == 0

    completion = json.loads(control_output.getvalue())
    assert completion["operation"] == "complete"
    assert completion["engine_observation"]["exit_code"] == 0
    assert completion["engine_observation"]["signal"] is None
    assert completion["engine_observation"]["direct_child_reaped"] is True
    assert not output.exists()


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
    group_members = {
        configuration.runner_gid: [runner.pw_name],
        configuration.worker_gid: [worker.pw_name],
        configuration.scratch_gid: [runner.pw_name],
        configuration.model_read_gid: [runner.pw_name, worker.pw_name],
    }
    monkeypatch.setattr(
        broker_module.pwd,
        "getpwuid",
        lambda uid: runner if uid == configuration.runner_uid else worker,
    )
    monkeypatch.setattr(
        broker_module.pwd, "getpwall", lambda: [runner, worker]
    )
    monkeypatch.setattr(
        broker_module,
        "_complete_account_members",
        lambda: ((runner.pw_name, runner.pw_gid), (worker.pw_name, worker.pw_gid)),
        raising=False,
    )
    monkeypatch.setattr(
        broker_module.grp,
        "getgrgid",
        lambda gid: SimpleNamespace(gr_gid=gid, gr_mem=group_members.get(gid, [])),
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
            else [configuration.worker_gid, configuration.model_read_gid]
        ),
    )

    with pytest.raises(ValueError, match="supplementary groups outside the broker allowlist"):
        configuration.validate_host_paths()


def test_broker_rejects_worker_supplementary_groups(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = _broker_configuration(tmp_path)
    runner = SimpleNamespace(pw_name="engine-runner", pw_gid=configuration.runner_gid)
    worker = SimpleNamespace(pw_name="generation-worker", pw_gid=configuration.worker_gid)
    group_members = {
        configuration.runner_gid: [runner.pw_name],
        configuration.worker_gid: [worker.pw_name],
        configuration.scratch_gid: [runner.pw_name],
        configuration.model_read_gid: [runner.pw_name, worker.pw_name],
    }
    monkeypatch.setattr(
        broker_module.pwd,
        "getpwuid",
        lambda uid: runner if uid == configuration.runner_uid else worker,
    )
    monkeypatch.setattr(
        broker_module.pwd, "getpwall", lambda: [runner, worker]
    )
    monkeypatch.setattr(
        broker_module,
        "_complete_account_members",
        lambda: ((runner.pw_name, runner.pw_gid), (worker.pw_name, worker.pw_gid)),
        raising=False,
    )
    monkeypatch.setattr(
        broker_module.grp,
        "getgrgid",
        lambda gid: SimpleNamespace(gr_gid=gid, gr_mem=group_members.get(gid, [])),
    )
    monkeypatch.setattr(
        broker_module,
        "_require_runner_group_allowlist",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        broker_module.os,
        "getgrouplist",
        lambda name, gid: (
            [configuration.runner_gid, *configuration.runner_supplementary_gids]
            if name == runner.pw_name
            else [gid, 9999]
        ),
    )

    with pytest.raises(ValueError, match="worker account has supplementary groups"):
        configuration.validate_host_paths()


@pytest.mark.parametrize(
    ("worker_groups", "model_mode", "expected_to_pass", "expected_error"),
    [
        (frozenset({2300}), 0o640, False, "worker"),
        (frozenset({2300, 2303}), 0o640, True, None),
        (frozenset({2300, 2303}), 0o644, False, "world-readable"),
    ],
    ids=["worker-missing-read-group", "worker-read-group", "model-world-readable"],
)
def test_engine_and_model_paths_require_read_access_for_the_worker_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    worker_groups: frozenset[int],
    model_mode: int,
    expected_to_pass: bool,
    expected_error: str | None,
) -> None:
    read_root = tmp_path / "candidate"
    engine = read_root / "bin" / "sd-cli"
    model = read_root / "models" / "diffusion.gguf"
    engine.parent.mkdir(parents=True)
    model.parent.mkdir(parents=True)
    engine.write_bytes(b"engine")
    model.write_bytes(b"model")
    model_read_gid = 2303
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(read_root,),
        runner_uid=2301,
        runner_groups=frozenset({2301, model_read_gid}),
        worker_uid=2300,
        worker_groups=worker_groups,
        model_read_gid=model_read_gid,
    )
    directory_info = os.stat_result(
        (stat.S_IFDIR | 0o2750, 1, 1, 1, 0, model_read_gid, 0, 0, 0, 0)
    )
    engine_info = os.stat_result(
        (stat.S_IFREG | 0o750, 2, 1, 1, 0, model_read_gid, 6, 0, 0, 0)
    )
    model_info = os.stat_result(
        (stat.S_IFREG | model_mode, 3, 1, 1, 0, model_read_gid, 5, 0, 0, 0)
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if path == engine:
            return engine_info
        if path == model:
            return model_info
        if os.path.isdir(path):
            return directory_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)

    if expected_to_pass:
        broker._validate_engine_paths(
            [str(engine), "--diffusion-model", str(model)]
        )
    else:
        assert expected_error is not None
        with pytest.raises(PermissionError, match=expected_error):
            broker._validate_engine_paths(
                [str(engine), "--diffusion-model", str(model)]
            )


@pytest.mark.parametrize(
    ("worker_groups", "expected_to_pass"),
    [
        (frozenset({2300}), False),
        (frozenset({2300, 2303}), True),
    ],
    ids=["worker-missing-read-group", "worker-read-group"],
)
def test_runtime_path_requires_traversal_for_both_service_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    worker_groups: frozenset[int],
    expected_to_pass: bool,
) -> None:
    runtime = tmp_path / "rocm-runtime"
    runtime.mkdir()
    model_read_gid = 2303
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(runtime,),
        runner_uid=2301,
        runner_groups=frozenset({2301, model_read_gid}),
        worker_uid=2300,
        worker_groups=worker_groups,
        model_read_gid=model_read_gid,
    )
    directory_info = os.stat_result(
        (stat.S_IFDIR | 0o2750, 1, 1, 1, 0, model_read_gid, 0, 0, 0, 0)
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if os.path.isdir(path):
            return directory_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)

    if expected_to_pass:
        broker._validate_environment_path(str(runtime))
    else:
        with pytest.raises(PermissionError, match="worker"):
            broker._validate_environment_path(str(runtime))


def test_broker_accepts_public_search_path_for_both_service_identities() -> None:
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(Path("/usr/bin"),),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )

    broker._validate_environment_path("/usr/bin")


@pytest.mark.parametrize(
    ("directory_mode", "expected_to_pass"),
    [(0o700, False), (0o2750, True)],
    ids=["marker-directory-inaccessible", "marker-directory-readable"],
)
def test_rocm_marker_requires_service_group_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    directory_mode: int,
    expected_to_pass: bool,
) -> None:
    rocm_path = tmp_path / "rocm"
    marker = rocm_path / ".info" / "version"
    marker.parent.mkdir(parents=True)
    marker.write_text("10.1.0\n", encoding="utf-8")
    model_read_gid = 2303
    worker = SimpleNamespace(pw_name="generation-worker", pw_gid=2300)
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        worker_uid=2300,
        worker_gid=2300,
        worker_groups=frozenset({2300, model_read_gid}),
        runner_uid=2301,
        runner_groups=frozenset({2301, model_read_gid}),
        model_read_gid=model_read_gid,
    )
    directory_info = os.stat_result(
        (
            stat.S_IFDIR | directory_mode,
            1,
            1,
            1,
            0,
            model_read_gid if directory_mode == 0o2750 else 0,
            0,
            0,
            0,
            0,
        )
    )
    marker_info = os.stat_result(
        (stat.S_IFREG | 0o640, 2, 1, 1, 0, model_read_gid, 7, 0, 0, 0)
    )
    original_lstat = Path.lstat
    original_stat = Path.stat

    def fake_lstat(path: Path):
        if path == marker:
            return marker_info
        return original_lstat(path)

    def fake_stat(path: Path, *, follow_symlinks: bool = True):
        if os.path.isdir(path):
            return directory_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(broker_module.pwd, "getpwuid", lambda _uid: worker)
    monkeypatch.setattr(
        broker_module.os,
        "getgrouplist",
        lambda _name, primary_gid: [primary_gid, model_read_gid],
    )

    if expected_to_pass:
        broker._validate_rocm_release_marker(rocm_path)
    else:
        with pytest.raises(PermissionError, match="worker"):
            broker._validate_rocm_release_marker(rocm_path)


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
        worker_uid=os.getuid(),
        worker_groups=frozenset({os.getgid()}),
    )
    monkeypatch.setattr(
        broker_module, "_require_root_owned_ancestors", lambda _path: None
    )
    monkeypatch.setattr(
        broker_module, "_mode_allows", lambda *_args, **_kwargs: True
    )

    with pytest.raises(PermissionError, match="outside broker read roots"):
        broker._validate_engine_paths(
            [str(executable), component_flag, str(model)]
        )


def test_broker_rejects_worker_owned_engine_files_inside_read_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    executable = allowed_root / "engine"
    executable.write_bytes(b"engine")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(allowed_root,),
        runner_uid=os.getuid(),
        runner_groups=frozenset({os.getgid()}),
        worker_uid=os.getuid(),
        worker_groups=frozenset({os.getgid()}),
    )
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_mode_allows", lambda *_args, **_kwargs: True
    )

    with pytest.raises(PermissionError, match="root-owned and not worker-writable"):
        broker._validate_engine_paths([str(executable)])


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


@pytest.mark.parametrize(
    "changed_name",
    ["LD_LIBRARY_PATH", "PATH", "ROCM_PATH"],
)
def test_broker_rejects_changed_resolved_environment_before_unit_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_name: str,
) -> None:
    identity = _identity()
    expected_environment = {
        "LD_LIBRARY_PATH": "/srv/runtime/lib",
        "PATH": "/usr/bin",
        "ROCM_PATH": "/srv/runtime/rocm",
    }
    resolved = {
        "attempt_id": identity.attempt_id,
        "argv": ["/engine"],
        "environment": broker_module.environment_record(expected_environment),
    }
    resolved_digest = backend_digest(resolved)

    class _Store:
        def get_backend_execution(self, _job_id, _attempt_id):
            return {
                "state": "resolved",
                "resolved": resolved,
                "resolved_digest": resolved_digest,
            }

    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        runner_uid=identity.runner_uid,
        runner_gid=identity.runner_gid,
        scratch_root=tmp_path / "scratch",
    )
    broker.store = _Store()
    broker._require_current_claim = lambda *_args: None
    broker._validate_engine_paths = lambda _argv: None
    monkeypatch.setattr(broker_module, "_unit_properties", lambda _unit: {})

    changed_environment = dict(expected_environment)
    changed_environment[changed_name] += ".substituted"
    request = {
        "job_id": identity.job_id,
        "attempt_id": identity.attempt_id,
        "owner_id": identity.owner_id,
        "claim_epoch": identity.claim_epoch,
        "resolved_digest": resolved_digest,
        "resolved_record": resolved,
        "argv": ["/engine"],
        "environment": changed_environment,
        "scratch_directory": str(broker.configuration.scratch_root / identity.attempt_id),
        "runner_uid": identity.runner_uid,
        "runner_gid": identity.runner_gid,
    }

    with pytest.raises(BackendEvidenceError, match="environment differs from durable resolution"):
        broker._execute(object(), request)


@pytest.mark.parametrize(
    "invalid_kind",
    ["empty-entry", "relative", "symlink-escape", "outside-allowlist"],
)
def test_broker_rejects_unsafe_library_search_path_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_kind: str,
) -> None:
    identity = _identity()
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )
    allowed = tmp_path / "runtime"
    library = allowed / "lib"
    binary = allowed / "bin"
    rocm = allowed / "rocm"
    library.mkdir(parents=True)
    binary.mkdir()
    (rocm / ".info").mkdir(parents=True)
    (rocm / ".info" / "version").write_text("10.1.0\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    symlink = allowed / "escape"
    symlink.symlink_to(outside, target_is_directory=True)
    invalid_entries = {
        "empty-entry": f"{library}:",
        "relative": f"{library}:relative/lib",
        "symlink-escape": str(symlink),
        "outside-allowlist": str(outside),
    }
    environment = {
        "LD_LIBRARY_PATH": invalid_entries[invalid_kind],
        "PATH": str(binary),
        "ROCM_PATH": str(rocm),
    }
    resolved = {
        "attempt_id": identity.attempt_id,
        "argv": ["/engine"],
        "environment": broker_module.environment_record(environment),
    }
    resolved_digest = backend_digest(resolved)

    class _Store:
        def get_backend_execution(self, _job_id, _attempt_id):
            return {
                "state": "resolved",
                "resolved": resolved,
                "resolved_digest": resolved_digest,
            }

    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        runner_uid=identity.runner_uid,
        runner_gid=identity.runner_gid,
        runner_groups=frozenset({identity.runner_gid}),
        worker_uid=identity.runner_uid,
        worker_groups=frozenset({identity.runner_gid}),
        scratch_root=tmp_path / "scratch",
        environment_path_allowlist=(library, binary, rocm),
    )
    broker.store = _Store()
    broker._require_current_claim = lambda *_args: None
    broker._validate_engine_paths = lambda _argv: None
    monkeypatch.setattr(broker_module, "_unit_properties", lambda _unit: {})
    request = {
        "job_id": identity.job_id,
        "attempt_id": identity.attempt_id,
        "owner_id": identity.owner_id,
        "claim_epoch": identity.claim_epoch,
        "resolved_digest": resolved_digest,
        "resolved_record": resolved,
        "argv": ["/engine"],
        "environment": environment,
        "scratch_directory": str(broker.configuration.scratch_root / identity.attempt_id),
        "runner_uid": identity.runner_uid,
        "runner_gid": identity.runner_gid,
    }

    with pytest.raises(PermissionError, match="environment search path"):
        broker._execute(object(), request)


def test_broker_accepts_configured_environment_search_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    library_directory = tmp_path / "lib"
    binary_directory = tmp_path / "bin"
    library_directory.mkdir()
    binary_directory.mkdir()
    library = library_directory / "libengine.so"
    optimized_directory = library_directory / "glibc-hwcaps" / "x86-64-v3"
    optimized_directory.mkdir(parents=True)
    optimized_library = optimized_directory / "libamdhip64.so.7"
    binary = binary_directory / "engine-helper"
    library.write_bytes(b"library")
    optimized_library.write_bytes(b"optimized library")
    binary.write_bytes(b"binary")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(library_directory, binary_directory),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )
    original_stat = Path.stat
    protected_directories = {
        library_directory / "glibc-hwcaps",
        optimized_directory,
    }

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        info = original_stat(path, follow_symlinks=follow_symlinks)
        if path in protected_directories:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o2750
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        file_modes = {library: 0o640, optimized_library: 0o640, binary: 0o750}
        if path in file_modes:
            fields = list(info)
            fields[0] = stat.S_IFREG | file_modes[path]
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        return info

    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        info = original_lstat(path)
        if path in protected_directories:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o2750
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        file_modes = {library: 0o640, optimized_library: 0o640, binary: 0o750}
        if path in file_modes:
            fields = list(info)
            fields[0] = stat.S_IFREG | file_modes[path]
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "lstat", fake_lstat)
    broker._validate_engine_environment(
        {"LD_LIBRARY_PATH": str(library_directory), "PATH": str(binary_directory)}
    )


def test_broker_rejects_worker_writable_nested_loader_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    library_directory = tmp_path / "lib"
    optimized_directory = library_directory / "glibc-hwcaps" / "x86-64-v3"
    optimized_directory.mkdir(parents=True)
    optimized_library = optimized_directory / "libamdhip64.so.7"
    optimized_library.write_bytes(b"worker-controlled library")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    monkeypatch.setattr(broker_module, "_require_no_extended_posix_acl", lambda _path: None)
    original_lstat = Path.lstat
    protected_directories = {
        library_directory,
        library_directory / "glibc-hwcaps",
        optimized_directory,
    }

    def fake_lstat(path: Path) -> os.stat_result:
        info = original_lstat(path)
        if path in protected_directories:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o2750
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        if path == optimized_library:
            fields = list(info)
            fields[0] = stat.S_IFREG | 0o660
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(PermissionError, match="worker-writable"):
        broker._validate_environment_search_files(
            library_directory, search_variable="LD_LIBRARY_PATH"
        )


@pytest.mark.parametrize(
    ("search_variable", "file_mode", "file_uid", "file_gid", "message"),
    [
        ("LD_LIBRARY_PATH", 0o660, 0, 2303, "worker-writable"),
        ("LD_LIBRARY_PATH", 0o600, 0, 0, "runner cannot read"),
        ("LD_LIBRARY_PATH", 0o640, 0, 2301, "worker cannot read"),
        ("LD_LIBRARY_PATH", 0o640, 2301, 2303, "root-owned"),
        ("PATH", 0o700, 0, 0, "runner cannot execute"),
    ],
    ids=[
        "group-writable-library",
        "unreadable-library",
        "worker-cannot-read-library",
        "runner-owned-writable-library",
        "unusable-path-command",
    ],
)
def test_broker_rejects_unsafe_runtime_search_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    search_variable: str,
    file_mode: int,
    file_uid: int,
    file_gid: int,
    message: str,
) -> None:
    search_path = tmp_path / "runtime"
    search_path.mkdir()
    runtime_file = search_path / "lib-or-tool"
    runtime_file.write_bytes(b"runtime")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(search_path,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        info = original_stat(path, follow_symlinks=follow_symlinks)
        if path == runtime_file:
            fields = list(info)
            fields[0] = stat.S_IFREG | file_mode
            fields[4] = file_uid
            fields[5] = file_gid
            return os.stat_result(fields)
        return info

    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result:
        info = original_lstat(path)
        if path == runtime_file:
            fields = list(info)
            fields[0] = stat.S_IFREG | file_mode
            fields[4] = file_uid
            fields[5] = file_gid
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(PermissionError, match=message):
        broker._validate_engine_environment({search_variable: str(search_path)})


@pytest.mark.parametrize(
    "target_is_directory",
    [False, True],
    ids=["file-target", "search-directory-target"],
)
def test_broker_rejects_runtime_symlink_into_worker_writable_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_is_directory: bool,
) -> None:
    search_path = tmp_path / "runtime"
    worker_directory = tmp_path / "worker-owned"
    search_path.mkdir()
    worker_directory.mkdir()
    target = worker_directory / "libengine.so.1"
    target.write_bytes(b"runtime")
    link = search_path / "libengine.so"
    link.symlink_to(
        worker_directory if target_is_directory else target,
        target_is_directory=target_is_directory,
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(search_path,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )
    original_lstat = Path.lstat
    original_stat = Path.stat
    observed_paths: list[Path] = []
    safe_directories = set(search_path.parents) | set(target.parent.parents) | {search_path}

    def fake_info(path: Path, *, follow_symlinks: bool = False) -> os.stat_result:
        info = (
            original_stat(path, follow_symlinks=follow_symlinks)
            if follow_symlinks
            else original_lstat(path)
        )
        if not follow_symlinks:
            observed_paths.append(path)
        if path == link:
            fields = list(info)
            fields[0] = (
                stat.S_IFREG | 0o640
                if follow_symlinks
                else stat.S_IFLNK | 0o777
            )
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        if path == worker_directory:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o770
            fields[4] = 2300
            fields[5] = 2300
            return os.stat_result(fields)
        if path == target:
            fields = list(info)
            fields[0] = stat.S_IFREG | 0o640
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        if path in safe_directories:
            fields = list(info)
            fields[0] = stat.S_IFDIR | 0o755
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", fake_info)
    monkeypatch.setattr(Path, "stat", lambda path, *, follow_symlinks=True: fake_info(
        path, follow_symlinks=True
    ))

    with pytest.raises(PermissionError, match="replaceable"):
        broker._validate_engine_environment({"LD_LIBRARY_PATH": str(search_path)})
    assert worker_directory in observed_paths


@pytest.mark.parametrize(
    ("target_parent_mode", "expected_error"),
    [(0o755, None), (0o700, "cannot be traversed")],
    ids=["traversable-target", "inaccessible-target-parent"],
)
def test_broker_checks_runtime_symlink_target_ancestor_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_parent_mode: int,
    expected_error: str | None,
) -> None:
    candidate_root = tmp_path / "candidate"
    search_path = candidate_root / "bin"
    library_directory = candidate_root / "lib"
    search_path.mkdir(parents=True)
    library_directory.mkdir()
    target = library_directory / "libengine.so.1"
    target.write_bytes(b"runtime")
    link = search_path / "libengine.so"
    link.symlink_to("../lib/libengine.so.1")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(search_path,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    monkeypatch.setattr(broker_module, "_require_root_directory", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )
    original_lstat = Path.lstat
    protected_directories = (
        set(search_path.parents)
        | set(library_directory.parents)
        | {search_path, library_directory}
    )

    def fake_lstat(path: Path) -> os.stat_result:
        info = original_lstat(path)
        if path == link:
            fields = list(info)
            fields[0] = stat.S_IFLNK | 0o777
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
        if path == target:
            fields = list(info)
            fields[0] = stat.S_IFREG | 0o640
            fields[4] = 0
            fields[5] = 2303
            return os.stat_result(fields)
        if path in protected_directories:
            fields = list(info)
            mode = target_parent_mode if path == library_directory else 0o755
            fields[0] = stat.S_IFDIR | mode
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    if expected_error is None:
        broker._validate_engine_environment({"LD_LIBRARY_PATH": str(search_path)})
    else:
        with pytest.raises(PermissionError, match=expected_error):
            broker._validate_engine_environment({"LD_LIBRARY_PATH": str(search_path)})


def test_broker_rechecks_environment_directory_permissions_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_directory = tmp_path / "runtime"
    runtime_directory.mkdir()
    original_lstat = Path.lstat
    observed = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)

    monkeypatch.setattr(
        broker_module,
        "_require_root_owned_ancestors",
        lambda _path: None,
    )
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: observed if path == runtime_directory else original_lstat(path),
    )
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        environment_path_allowlist=(runtime_directory,),
    )

    with pytest.raises(PermissionError, match="broker directory"):
        broker._validate_environment_path(str(runtime_directory))


def test_runner_rejects_changed_environment_binding(tmp_path: Path) -> None:
    identity = _identity()
    expected_environment = {"LD_LIBRARY_PATH": "/srv/runtime/lib"}
    resolved = {
        "attempt_id": identity.attempt_id,
        "argv": ["/engine", "-o", str(tmp_path / "output.png")],
        "environment": broker_module.environment_record(expected_environment),
        "output_basename": "output.png",
    }

    with pytest.raises(BackendEvidenceError, match="runner environment differs"):
        _validate_manifest(
            identity,
            list(resolved["argv"]),
            {"LD_LIBRARY_PATH": "/srv/runtime/other"},
            tmp_path,
            resolved,
        )


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
    SystemdEvidenceLedger.path_for(service.database_path).parent.mkdir(
        parents=True, exist_ok=True
    )
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
    SystemdEvidenceLedger.path_for(service.database_path).parent.mkdir(
        parents=True, exist_ok=True
    )
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


def test_systemd_evidence_ledger_path_is_outside_worker_writable_database_directory(
    tmp_path: Path,
) -> None:
    database = tmp_path / "db" / "jobs.sqlite3"

    ledger_path = SystemdEvidenceLedger.path_for(database)

    assert ledger_path.parent == tmp_path / "systemd-evidence"
    assert ledger_path.parent != database.parent
    assert ledger_path.name == "db-jobs.sqlite3.systemd-evidence.sqlite3"


def test_systemd_evidence_ledger_parent_must_be_root_owned_and_nonwritable() -> None:
    protected = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_uid=0,
        st_gid=0,
    )
    writable = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o775,
        st_uid=0,
        st_gid=0,
    )
    worker_owned = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_uid=972,
        st_gid=0,
    )

    SystemdEvidenceLedger._require_trusted_directory(protected)
    with pytest.raises(PermissionError, match="root-owned and non-writable"):
        SystemdEvidenceLedger._require_trusted_directory(writable)
    with pytest.raises(PermissionError, match="root-owned and non-writable"):
        SystemdEvidenceLedger._require_trusted_directory(worker_owned)


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
        if path == ledger.path.parent:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755,
                st_uid=0,
                st_gid=0,
            )
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

    active = SimpleNamespace(
        identity=old_identity,
        done=threading.Event(),
        lock=threading.RLock(),
    )
    active.done.set()
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(empty_timeout_seconds=1)
    broker._active_lock = threading.RLock()
    broker._active = {first_attempt_id: active}
    broker.store = service._store
    cleanup_calls: list[str] = []
    broker._remove_scratch = lambda attempt_id: cleanup_calls.append(attempt_id)

    broker._cleanup_pinned_scratch(old_identity)

    assert cleanup_calls == [first_attempt_id]
    assert first_attempt_id not in broker._active

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


def test_cancel_after_worker_loss_fence_preserves_recovery_convergence(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module.os, "geteuid", lambda: 0)
    runner = _SyntheticSystemdAttemptRunner(
        tmp_path / "broker-scratch", fence_before_return=True
    )
    service, runner = _systemd_service(tmp_path, runner)
    queued = service.enqueue(
        "systemd-cancel-after-worker-loss-fence",
        _request(),
        workload_demand=heavy_workload_demand(),
    )

    work = service.work()
    assert work["processed"] == 1
    attempt = service._store.current_attempt(queued.job_id)
    assert attempt is not None
    claim_epoch = int(attempt["claim_epoch"])
    assert service.get_provenance(queued.job_id)["execution"]["fence_epoch"] == (
        claim_epoch + 1
    )

    cancellation = service.cancel(queued.job_id)
    assert cancellation["outcome"] == "acknowledged"
    assert service.get_provenance(queued.job_id)["execution"]["fence_epoch"] == (
        claim_epoch + 1
    )
    identity = service._store.attempt_containment_identity(
        queued.job_id, str(attempt["attempt_id"])
    )
    assert identity is not None
    assert service._store.attempt_recovery_cleanup_authorized(identity)

    recovered = service.recover()

    assert recovered["resource_state"] == "available"
    assert service.get_provenance(queued.job_id)["status"] == "canceled"
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


@pytest.mark.parametrize(
    ("reference_mode", "expected_error"),
    [(0o644, "world-readable"), (0o660, "worker-writable")],
    ids=["world-readable", "worker-writable"],
)
def test_broker_rejects_mutable_or_world_readable_reference_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reference_mode: int,
    expected_error: str,
) -> None:
    read_root = tmp_path / "candidate"
    engine = read_root / "bin" / "sd-cli"
    reference = read_root / "references" / "input.png"
    engine.parent.mkdir(parents=True)
    reference.parent.mkdir(parents=True)
    engine.write_bytes(b"engine")
    reference.write_bytes(b"private reference")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(read_root,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    engine_info = os.stat_result(
        (stat.S_IFREG | 0o750, 1, 1, 1, 0, 2303, 6, 0, 0, 0)
    )
    reference_info = os.stat_result(
        (stat.S_IFREG | reference_mode, 2, 1, 1, 0, 2303, 17, 0, 0, 0)
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == engine:
            return engine_info
        if path == reference:
            return reference_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )

    with pytest.raises(PermissionError, match=expected_error):
        broker._validate_engine_paths([str(engine), "-r", str(reference)])


def test_broker_rejects_model_symlink_under_worker_writable_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_root = tmp_path / "candidate"
    engine = read_root / "bin" / "sd-cli"
    model_directory = read_root / "models"
    worker_directory = read_root / "worker-writable"
    model = model_directory / "diffusion.gguf"
    model_alias = worker_directory / "diffusion.gguf"
    engine.parent.mkdir(parents=True)
    model_directory.mkdir()
    worker_directory.mkdir()
    engine.write_bytes(b"engine")
    model.write_bytes(b"model")
    model_alias.symlink_to(model)
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(read_root,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    engine_info = os.stat_result(
        (stat.S_IFREG | 0o750, 1, 1, 1, 0, 2303, 6, 0, 0, 0)
    )
    model_info = os.stat_result(
        (stat.S_IFREG | 0o640, 2, 1, 1, 0, 2303, 5, 0, 0, 0)
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == engine:
            return engine_info
        if path == model:
            return model_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )

    with pytest.raises(PermissionError, match="symlink"):
        broker._validate_engine_paths(
            [str(engine), "--diffusion-model", str(model_alias)]
        )


def test_broker_rejects_extended_posix_acl_on_model_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import errno

    read_root = tmp_path / "candidate"
    engine = read_root / "bin" / "sd-cli"
    model = read_root / "models" / "diffusion.gguf"
    engine.parent.mkdir(parents=True)
    model.parent.mkdir(parents=True)
    engine.write_bytes(b"engine")
    model.write_bytes(b"model")
    broker = object.__new__(SystemdAttemptBroker)
    broker.configuration = SimpleNamespace(
        read_roots=(read_root,),
        runner_uid=2301,
        runner_groups=frozenset({2301, 2303}),
        worker_uid=2300,
        worker_groups=frozenset({2300, 2303}),
    )
    engine_info = os.stat_result(
        (stat.S_IFREG | 0o750, 1, 1, 1, 0, 2303, 6, 0, 0, 0)
    )
    model_info = os.stat_result(
        (stat.S_IFREG | 0o640, 2, 1, 1, 0, 2303, 5, 0, 0, 0)
    )
    original_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == engine:
            return engine_info
        if path == model:
            return model_info
        return original_stat(path, follow_symlinks=follow_symlinks)

    def fake_getxattr(path, name: str, *, follow_symlinks: bool = True) -> bytes:
        if Path(path) == model and name == "system.posix_acl_access":
            return b"extended-acl"
        raise OSError(errno.ENODATA, "attribute not present")

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(broker_module.os, "getxattr", fake_getxattr, raising=False)
    monkeypatch.setattr(broker_module, "_require_root_owned_ancestors", lambda _path: None)
    monkeypatch.setattr(
        broker_module, "_require_directory_traversal", lambda *_args, **_kwargs: None
    )

    with pytest.raises(PermissionError, match="ACL"):
        broker._validate_engine_paths(
            [str(engine), "--diffusion-model", str(model)]
        )


def test_broker_fails_closed_when_posix_acl_state_cannot_be_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import errno

    path = tmp_path / "model.gguf"
    path.write_bytes(b"model")

    def inaccessible_xattr(_path, _name: str, *, follow_symlinks: bool = True) -> bytes:
        raise OSError(errno.EPERM, "ACL metadata unavailable")

    monkeypatch.setattr(
        broker_module.os, "getxattr", inaccessible_xattr, raising=False
    )

    with pytest.raises(PermissionError, match="ACL state cannot be verified"):
        broker_module._require_no_extended_posix_acl(path)
