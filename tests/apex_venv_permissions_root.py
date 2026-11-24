"""Exercise broker filesystem access with real Linux credentials."""

from __future__ import annotations

import grp
import json
import os
import pwd
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from media_generation.store import SQLiteStore
from media_generation.service import _now
from media_generation.systemd_attempts import AttemptUnitIdentity, identity_digest
from media_generation.systemd_broker import SystemdAttemptBroker, _attempt_mount_properties
from media_generation.systemd_evidence import SystemdEvidenceLedger


class BrokerFilesystemPermissionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("these checks require root on Linux")

    def setUp(self) -> None:
        fixture = tempfile.TemporaryDirectory(prefix="broker-permissions-")
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name).resolve()
        self.root.chmod(0o755)
        reserved_ids = {account.pw_uid for account in pwd.getpwall()}
        reserved_ids.update(account.pw_gid for account in pwd.getpwall())
        reserved_ids.update(group.gr_gid for group in grp.getgrall())
        available = (
            number for number in range(63070, 64000) if number not in reserved_ids
        )
        self.runner_uid, self.worker_uid = next(available), next(available)

    def _open_as(self, uid: int, path: Path, mode: str) -> int:
        return subprocess.run(
            [sys._base_executable, "-c", "import sys; open(sys.argv[1], sys.argv[2]).close()",
             str(path), mode],
            user=uid,
            group=uid,
            extra_groups=[],
            capture_output=True,
            check=False,
        ).returncode

    def test_runner_private_library_and_startup_write_protection(self) -> None:
        library = self.root / "libengine.so"
        library.touch()
        os.chown(library, 0, self.runner_uid)
        library.chmod(0o640)
        broker = object.__new__(SystemdAttemptBroker)
        broker.configuration = SimpleNamespace(
            environment_path_allowlist=(self.root,),
            runner_uid=self.runner_uid,
            runner_groups=frozenset({self.runner_uid}),
        )
        broker._validate_private_runtime()
        self.assertEqual(self._open_as(self.runner_uid, library, "rb"), 0)
        self.assertNotEqual(self._open_as(self.worker_uid, library, "rb"), 0)
        self.assertNotEqual(self._open_as(self.runner_uid, library, "r+b"), 0)
        library.chmod(0o660)
        with self.assertRaisesRegex(PermissionError, "non-writable"):
            broker._validate_private_runtime()

    def test_worker_can_read_ledger_and_cannot_write_it(self) -> None:
        directory = self.root / "evidence"
        directory.mkdir()
        os.chown(directory, 0, self.worker_uid)
        directory.chmod(0o750)
        ledger = SystemdEvidenceLedger(directory / "ledger.sqlite3")
        ledger.initialize(worker_gid=self.worker_uid)
        before = ledger.path.stat()
        with self.assertRaisesRegex(PermissionError, "unexpected access permissions"):
            ledger.initialize(worker_gid=self.runner_uid)
        after = ledger.path.stat()
        self.assertEqual((after.st_gid, after.st_mode), (before.st_gid, before.st_mode))
        self.assertEqual(self._open_as(self.worker_uid, ledger.path, "rb"), 0)
        self.assertNotEqual(self._open_as(self.worker_uid, ledger.path, "r+b"), 0)
        self.assertNotEqual(self._open_as(self.runner_uid, ledger.path, "rb"), 0)


    def test_broker_binds_worker_owned_database_in_sticky_directory(self) -> None:
        protected_regular = Path("/proc/sys/fs/protected_regular")
        print(f"fs.protected_regular={protected_regular.read_text().strip()}", flush=True)
        # CI checkouts need not be traversable by the synthetic test UIDs.
        worker_uid = self.worker_uid
        worker_gid = self.worker_uid
        sudo_uid = int(os.environ.get("SUDO_UID", "0"))
        if sudo_uid:
            account = pwd.getpwuid(sudo_uid)
            worker_uid, worker_gid = account.pw_uid, account.pw_gid
        db_dir = self.root / "db"
        ledger_dir = self.root / "systemd-evidence"
        work = self.root / "worker"
        for path, uid, mode in (
            (db_dir, 0, 0o1770),
            (ledger_dir, 0, 0o750),
            (work, worker_uid, 0o700),
        ):
            path.mkdir()
            os.chown(path, uid, worker_gid)
            path.chmod(mode)
        database = db_dir / "jobs.sqlite3"

        def worker(action: str) -> str:
            result = subprocess.run(
                [sys.executable, "-B", __file__, action, str(self.root)],
                user=worker_uid, group=worker_gid, extra_groups=[],
                capture_output=True, text=True, check=False, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        identity = AttemptUnitIdentity.from_mapping(json.loads(worker("prepare-claim")))
        expected_db = (worker_uid, worker_gid, 0o660)
        original = database.stat()
        self.assertEqual((original.st_uid, original.st_gid, original.st_mode & 0o7777), expected_db)
        store = SQLiteStore(database)
        store.initialize_systemd_evidence_ledger(worker_gid=worker_gid)
        ledger = SystemdEvidenceLedger(SystemdEvidenceLedger.path_for(database))
        ledger_stat = ledger.path.stat()
        self.assertEqual((ledger_stat.st_uid, ledger_stat.st_gid, ledger_stat.st_mode & 0o7777),
                         (0, worker_gid, 0o640))
        try:
            store.bind_attempt_containment(identity, timestamp=_now())
        except sqlite3.Error as error:
            print(f"bind failed: {error.sqlite_errorname}: {error}; "
                  f"root identity committed: {ledger.read_identity(identity.job_id, identity.attempt_id) == identity}",
                  flush=True)
            raise

        self.assertEqual(ledger.read_identity(identity.job_id, identity.attempt_id), identity)
        self.assertEqual(store.attempt_containment_identity(identity.job_id, identity.attempt_id), identity)
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            containment = connection.execute(
                "SELECT identity_json, identity_digest, termination_json, termination_at "
                "FROM execution_containment WHERE job_id = ? AND attempt_id = ?",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            self.assertIsNotNone(containment)
            self.assertEqual(json.loads(containment[0]), identity.to_mapping())
            self.assertEqual(containment[1:], (identity_digest(identity), None, None))
            lifecycle = connection.execute(
                "SELECT identity_digest, stream_complete, cleanup_state "
                "FROM systemd_output_lifecycle WHERE job_id = ? AND attempt_id = ?",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
        self.assertEqual(lifecycle, (identity_digest(identity), 0, "active"))
        self.assertEqual(worker("cancel-claim").strip(), "requested")
        after = database.stat()
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode & 0o7777), expected_db)

    @unittest.skipUnless(Path("/run/systemd/system").is_dir(), "requires a live systemd manager")
    def test_transient_runner_sees_only_its_own_scratch_and_inputs(self) -> None:
        runner = pwd.getpwuid(int(os.environ["SUDO_UID"])) if "SUDO_UID" in os.environ else pwd.getpwnam("nobody")
        self.assertNotEqual(runner.pw_uid, 0)
        self.assertNotEqual(runner.pw_uid, self.worker_uid)
        attempt = "att_" + uuid.uuid4().hex
        unit = f"media-generation-test-{attempt[4:]}.service"
        storage = self.root / "scratch"
        storage.mkdir(mode=0o710)
        os.chown(storage, 0, runner.pw_gid)
        scratch = storage / attempt
        broker = object.__new__(SystemdAttemptBroker)
        broker.configuration = SimpleNamespace(scratch_root=storage, scratch_gid=runner.pw_gid)
        broker._create_attempt_scratch(attempt)
        inputs = storage / (attempt + ".inputs")
        sibling = storage / ("att_" + uuid.uuid4().hex + ".inputs")
        for directory in (inputs, sibling):
            directory.mkdir(mode=0o750)
            os.chown(directory, 0, runner.pw_gid)
            path = directory / "0.png"
            path.write_bytes(b"reference")
            os.chown(path, 0, runner.pw_gid)
            path.chmod(0o440)
        private = self.root / "artifacts"
        private.mkdir(mode=0o700)
        os.chown(private, self.worker_uid, self.worker_uid)
        artifact = private / "reference.png"
        artifact.write_bytes(b"private")
        self.assertNotEqual(self._open_as(self.worker_uid, inputs / "0.png", "rb"), 0)
        self.assertNotEqual(self._open_as(self.worker_uid, scratch / "new", "wb"), 0)
        check = """
import sys
from pathlib import Path
reference, scratch, sibling, artifact = map(Path, sys.argv[1:])
assert reference.read_bytes() == b"reference"
assert not sibling.exists()
for action in (lambda: reference.write_bytes(b"bad"), reference.unlink, artifact.read_bytes):
    try:
        action()
    except OSError:
        pass
    else:
        raise AssertionError("unexpected access")
(scratch / "runner-output").write_bytes(b"output")
"""
        result = subprocess.run(
            [
                "/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                f"--unit={unit}",
                "--service-type=exec", "--property=ProtectSystem=strict",
                f"--property=User={runner.pw_name}", f"--property=Group={runner.pw_gid}",
                f"--working-directory={scratch}",
                *(f"--property={property_}" for property_ in _attempt_mount_properties(scratch)),
                "--", "/usr/bin/python3", "-I", "-c", check, str(inputs / "0.png"),
                str(scratch), str(sibling), str(artifact),
            ],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if result.returncode:
            journal = subprocess.run(
                ["/usr/bin/journalctl", "--no-pager", "-u", unit, "-n", "20"],
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.fail(f"systemd-run exit {result.returncode}: {result.stderr}\n{journal.stdout}")
        self.assertEqual((scratch / "runner-output").read_bytes(), b"output")


def _prepare_worker_claim(root: Path) -> None:
    from media_generation import engine
    from media_generation.domain import GenerationPlan, GenerationRequest
    from media_generation.service import GenerationService, _lease_deadline
    from media_generation.systemd_attempts import (
        SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
        SystemdAttemptRunner,
    )
    from test_t08_support import build_bundle, heavy_admission_profile, heavy_workload_demand

    os.umask(0o007)
    work = root / "worker"
    output = work / "images"
    bundle = build_bundle(work)
    # The fixture resolves a synthetic invocation without executing the engine.
    engine.capture_runtime_fingerprint = lambda: {
        "platform": "linux", "machine": "x86_64", "rocm_path": "/opt/rocm",
        "rocm_version": None, "amdgpu_version": None,
        "hsa_override_gfx_version": None, "hip_visible_devices": "0",
    }
    adapter = engine.StableDiffusionCppAdapter(
        candidate_path=bundle.declaration_path,
        output_directory=output,
        trusted_evidence_path=bundle.trusted_evidence_path,
    )
    database = root / "db/jobs.sqlite3"
    runner = SystemdAttemptRunner(work / "unused.sock", scratch_root=work / "scratch",
                                 runner_uid=970, runner_gid=970)
    service = GenerationService(database, output, adapter=adapter, attempt_runner=runner,
                                admission_profile=heavy_admission_profile())
    database.chmod(0o660)
    queued = service.enqueue("containment-bind", GenerationRequest("test", seed=1, width=64, height=64),
                             workload_demand=heavy_workload_demand())
    _, configuration, _, privacy = service._current_privacy_snapshot()
    store = service._store
    attempt_id = "att_" + uuid.uuid4().hex
    owner = "owner_containment_test"
    claim = store.claim_next_execution(
        attempt_id=attempt_id, owner_id=owner, adapter_id=adapter.adapter_id,
        adapter_configuration_json=configuration, privacy_compliance_json=privacy,
        resolved_output_directory=str(output), process_contained=True,
        containment_contract=SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
        timestamp=_now(), lease_expires_at=_lease_deadline(service._lease), job_id=queued.job_id,
    )
    if claim is None:
        raise RuntimeError("fixture job was not claimed")
    plan = GenerationPlan(
        job_id=claim.job_id, attempt_id=attempt_id, resolved_prompt=claim.resolved_prompt,
        seed=claim.resolved_seed, width=claim.width, height=claim.height,
        references=claim.references, output_slot=claim.output_slot, output_slot_id=claim.output_slot_id,
    )
    resolved = adapter.resolve_execution(plan)
    digest = store.insert_resolved_execution(
        job_id=claim.job_id, attempt_id=attempt_id, owner_id=owner, claim_epoch=claim.claim_epoch,
        record=dict(resolved.resolved_record), timestamp=_now(),
    )
    unit = f"media-generation-attempt-{attempt_id[4:]}.service"
    identity = AttemptUnitIdentity(
        1, claim.job_id, attempt_id, owner, claim.claim_epoch, digest,
        "01234567-89ab-cdef-0123-456789abcdef", unit, "b" * 32,
        f"/system.slice/{unit}", 42, 731, 970, 970,
    )
    (work / "identity.json").write_text(json.dumps(identity.to_mapping()))
    print(json.dumps(identity.to_mapping()))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "prepare-claim":
        _prepare_worker_claim(Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == "cancel-claim":
        root = Path(sys.argv[2])
        job = json.loads((root / "worker/identity.json").read_text())["job_id"]
        print(SQLiteStore(root / "db/jobs.sqlite3").cancel_execution(job, _now()))
    else:
        unittest.main()
