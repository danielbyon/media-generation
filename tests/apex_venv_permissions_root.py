"""Exercise broker filesystem access with real Linux credentials."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from media_generation.systemd_broker import SystemdAttemptBroker
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


if __name__ == "__main__":
    unittest.main()
