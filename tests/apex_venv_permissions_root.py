from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


MANIFEST = Path(__file__).resolve().parents[1] / "docs/deployment/apex-t13-broker.md"
START = "sh -eu <<'CHECK_VENV'\n"
END = "\nCHECK_VENV\n"
FIXED_ROOT = "venv=/opt/media-generation/venv\n"


class ApexVenvPermissionManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("the APEX manifest fixture matrix must run as root")
        document = MANIFEST.read_text(encoding="utf-8")
        if document.count(START) != 1:
            raise AssertionError("deployment manifest must contain one venv check block")
        body_start = document.index(START) + len(START)
        body_end = document.index(END, body_start)
        cls.shell_body = document[body_start:body_end]
        if cls.shell_body.count(FIXED_ROOT) != 1:
            raise AssertionError("deployment venv path assignment changed unexpectedly")
        cls.shell_body = cls.shell_body.replace(
            FIXED_ROOT, 'venv="${FIXTURE_VENV:?}"\n', 1
        )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="apex-venv-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.venv = self.base / "venv"
        self.venv.mkdir(mode=0o755)
        self.lib = self.venv / "lib"
        self.lib.mkdir(mode=0o755)
        self.link = self.venv / "lib64"
        self.link.symlink_to("lib")

    def _run_check(self, *, path: str = "/usr/bin:/bin") -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["FIXTURE_VENV"] = str(self.venv)
        environment["PATH"] = path
        return subprocess.run(
            ["/bin/sh", "-eu"],
            input=self.shell_body,
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def _assert_rejected(self, message: str) -> None:
        result = self._run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"venv permission check failed: {message}", result.stderr)

    def _fail_command(self, name: str) -> str:
        command_dir = self.base / f"fail-{name}"
        command_dir.mkdir()
        command = command_dir / name
        command.write_text("#!/bin/sh\nexit 73\n", encoding="ascii")
        command.chmod(0o755)
        return f"{command_dir}:/usr/bin:/bin"

    def test_exact_root_owned_lib64_symlink_passes_and_old_check_rejects_it(self) -> None:
        result = self._run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

        old_check = subprocess.run(
            ["/usr/bin/find", "-P", str(self.venv), "-perm", "/022", "-print", "-quit"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(old_check.returncode, 0, old_check.stderr)
        self.assertEqual(old_check.stdout.strip(), str(self.link))

    def test_missing_lib64_is_rejected(self) -> None:
        self.link.unlink()
        self._assert_rejected("venv must contain exactly one symlink")

    def test_additional_symlink_is_rejected(self) -> None:
        (self.venv / "unexpected").symlink_to("lib")
        self._assert_rejected("venv must contain exactly one symlink")

    def test_escaping_link_target_is_rejected(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        self.link.unlink()
        self.link.symlink_to("../outside")
        self._assert_rejected("venv/lib64 must have the exact literal target lib")

    def test_broken_exact_target_is_rejected_by_realpath(self) -> None:
        self.lib.rmdir()
        self._assert_rejected("realpath failed for the venv/lib64 target")

    def test_wrong_internal_link_target_is_rejected(self) -> None:
        (self.venv / "libexec").mkdir(mode=0o755)
        self.link.unlink()
        self.link.symlink_to("libexec")
        self._assert_rejected("venv/lib64 must have the exact literal target lib")

    def test_non_root_owned_symlink_is_rejected(self) -> None:
        os.chown(self.link, 1001, 1001, follow_symlinks=False)
        result = self._run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertTrue(
            "venv/lib64 symlink must be owned by root:root" in result.stderr
            or "every venv entry must be owned by root" in result.stderr,
            result.stderr,
        )

    def test_non_root_owned_regular_file_is_rejected(self) -> None:
        file = self.lib / "owned-by-other"
        file.write_text("fixture", encoding="ascii")
        os.chown(file, 1001, 1001)
        self._assert_rejected("every venv entry must be owned by root")

    def test_non_root_owned_directory_is_rejected(self) -> None:
        directory = self.lib / "owned-by-other"
        directory.mkdir()
        os.chown(directory, 1001, 1001)
        self._assert_rejected("every venv entry must be owned by root")

    def test_group_or_world_writable_regular_file_is_rejected(self) -> None:
        file = self.lib / "writable-file"
        file.write_text("fixture", encoding="ascii")
        file.chmod(0o666)
        self._assert_rejected(
            "a non-symlink venv entry is group- or world-writable"
        )

    def test_group_or_world_writable_directory_is_rejected(self) -> None:
        directory = self.lib / "writable-directory"
        directory.mkdir()
        directory.chmod(0o777)
        self._assert_rejected(
            "a non-symlink venv entry is group- or world-writable"
        )

    def test_group_or_world_writable_resolved_target_is_rejected(self) -> None:
        self.lib.chmod(0o777)
        self._assert_rejected(
            "a non-symlink venv entry is group- or world-writable"
        )

    def test_find_failure_is_reported_and_fails_closed(self) -> None:
        result = self._run_check(path=self._fail_command("find"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "venv permission check failed: find failed while enumerating venv symlinks",
            result.stderr,
        )

    def test_stat_failure_is_reported_and_fails_closed(self) -> None:
        result = self._run_check(path=self._fail_command("stat"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "venv permission check failed: stat failed for the venv directory",
            result.stderr,
        )

    def test_readlink_failure_is_reported_and_fails_closed(self) -> None:
        result = self._run_check(path=self._fail_command("readlink"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "venv permission check failed: readlink failed for the venv/lib64 symlink",
            result.stderr,
        )

    def test_realpath_failure_is_reported_and_fails_closed(self) -> None:
        result = self._run_check(path=self._fail_command("realpath"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "venv permission check failed: realpath failed for the venv/lib64 target",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
