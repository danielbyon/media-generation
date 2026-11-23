"""Exercise broker filesystem access with real Linux credentials."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

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


if __name__ == "__main__":
    unittest.main()
