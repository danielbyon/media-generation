from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
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


PAYLOAD_NAMES = (
    "SOURCE_SHA",
    "broker.json",
    "media-generation-apex-ldd-map.jsonl",
    "media-generation-apex-python-aliases.jsonl",
    "media-generation-apex-runtime-sha256.jsonl",
    "media-generation-apex-runtime-symlinks.jsonl",
    "media-generation-apex-source-ldd.txt",
    "media-generation-systemd-broker.service",
    "media_generation-0.1.0-py3-none-any.whl",
    "pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl",
)


class ApexBundlePreflightManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("the APEX bundle fixture matrix must run as root")
        document = MANIFEST.read_text(encoding="utf-8")
        cls.shell_body = cls._extract_fenced_block(
            document,
            "After transferring the bundle into the APEX inbox, verify its provenance and all payload checksums",
            "sh",
        )
        cls.transfer_body = cls._extract_fenced_block(
            document,
            "The following owner-run transfer writes only the new inbox.",
            "sh",
        )
        command_heading = "Run the portable validator on either host with this command"
        cls.portable_command = cls._extract_fenced_block(
            document, command_heading, "sh"
        )
        cls.python_body = cls._extract_heredoc(
            cls.portable_command, "MEDIA_GENERATION_BUNDLE_VALIDATION"
        )

    @staticmethod
    def _extract_fenced_block(document: str, heading: str, language: str) -> str:
        heading_offset = document.index(heading)
        opening = f"```{language}\n"
        start = document.index(opening, heading_offset) + len(opening)
        end = document.index("\n```", start)
        return document[start:end]

    @staticmethod
    def _extract_heredoc(script: str, delimiter: str) -> str:
        opening = f"<<'{delimiter}'\n"
        start = script.index(opening) + len(opening)
        end = script.index(f"\n{delimiter}", start)
        return script[start:end]

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="apex-bundle-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bundle = self.base / "bundle"
        self.bundle.mkdir(mode=0o700)
        self.source_sha = hashlib.sha1(
            f"fixture:{self.base}".encode("utf-8")
        ).hexdigest()
        self.config = self._valid_config()
        self.unit = self._valid_unit()
        self._write_valid_bundle()

    def _valid_config(self) -> dict[str, object]:
        venv = f"/opt/media-generation/releases/{self.source_sha}/venv"
        runtime_root = "/srv/media-generation/candidates/qwen-image-edit-2511/runtime"
        return {
            "database_path": "/var/lib/media-generation-v9/db/jobs.sqlite3",
            "socket_path": "/run/media-generation/attempt-broker.sock",
            "scratch_root": "/var/lib/media-generation/scratch",
            "runner_executable": f"{venv}/bin/media-generation-attempt-runner",
            "runner_uid": 970,
            "runner_gid": 970,
            "runner_supplementary_gids": [971, 973, 990],
            "worker_uid": 972,
            "worker_gid": 972,
            "scratch_gid": 971,
            "model_read_gid": 973,
            "device_allow": ["/dev/kfd", "/dev/dri/renderD128"],
            "read_roots": [
                runtime_root,
                "/srv/media-generation/candidates/qwen-image-edit-2511/inputs",
            ],
            "environment_path_allowlist": [
                "/usr/bin",
                f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel",
                f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib",
                f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/llvm/lib",
                f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/rocm_sysdeps/lib",
            ],
            "empty_timeout_seconds": 30,
        }

    def _valid_unit(self) -> str:
        venv = f"/opt/media-generation/releases/{self.source_sha}/venv"
        config = f"/etc/media-generation/releases/{self.source_sha}/broker.json"
        return (
            "[Unit]\n"
            "Description=Media Generation systemd attempt broker\n"
            "After=local-fs.target\n"
            "RequiresMountsFor=/opt/media-generation "
            f"{venv} /etc/media-generation/releases/{self.source_sha} \\\n"
            "    /var/lib/media-generation-v9/db /var/lib/media-generation/scratch \\\n"
            "    /srv/media-generation/candidates/qwen-image-edit-2511\n"
            "\n"
            "[Service]\n"
            "Type=exec\nUser=root\nGroup=root\nUMask=0077\n"
            "WorkingDirectory=/\nRuntimeDirectory=media-generation\n"
            "RuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=no\n"
            f"ExecStart={venv}/bin/media-generation-systemd-broker {config}\n"
            "Restart=on-failure\nRestartSec=2s\n"
            "NoNewPrivileges=yes\nProtectSystem=strict\n"
            "ProtectHome=read-only\nPrivateTmp=yes\n"
            "ReadWritePaths=/run/media-generation /var/lib/media-generation-v9/db "
            "/var/lib/media-generation-v9/systemd-evidence "
            "/var/lib/media-generation/scratch\n"
        )

    def _write_valid_bundle(self) -> None:
        for name in PAYLOAD_NAMES:
            path = self.bundle / name
            if name == "SOURCE_SHA":
                path.write_text(f"{self.source_sha}\n", encoding="ascii")
            elif name == "broker.json":
                path.write_text(
                    json.dumps(self.config, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
            elif name == "media-generation-systemd-broker.service":
                path.write_text(self.unit, encoding="utf-8")
            else:
                path.write_bytes(f"fixture payload: {name}\n".encode("ascii"))
        self._write_manifest()

    def _write_manifest(self) -> None:
        lines = []
        for name in sorted(PAYLOAD_NAMES):
            digest = hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (self.bundle / "SHA256SUMS").write_text("".join(lines), encoding="ascii")
        self.expected_sums_sha = hashlib.sha256(
            (self.bundle / "SHA256SUMS").read_bytes()
        ).hexdigest()

    def _environment(self, *, path: str = "/usr/bin:/bin") -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "BUNDLE": str(self.bundle),
                "EXPECTED_SOURCE_SHA": self.source_sha,
                "EXPECTED_SUMS_SHA": self.expected_sums_sha,
                "PYTHON_BIN": sys.executable,
                "PATH": path,
            }
        )
        return environment

    def _run_shell(
        self, script: str, *, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-eu"],
            input=script,
            text=True,
            capture_output=True,
            env=environment or self._environment(),
            check=False,
        )

    def _run_preflight(
        self, *, path: str = "/usr/bin:/bin"
    ) -> subprocess.CompletedProcess[str]:
        return self._run_shell(self.shell_body, environment=self._environment(path=path))

    def _run_python(
        self,
        *,
        optimized: bool = False,
        args: tuple[str, ...] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append("-")
        command.extend(
            args
            if args is not None
            else (
                str(self.bundle),
                self.source_sha,
                self.expected_sums_sha,
                "/etc/systemd/system/media-generation-systemd-broker.service",
                f"/etc/media-generation/releases/{self.source_sha}/broker.json",
            )
        )
        return subprocess.run(
            command,
            input=self.python_body,
            text=True,
            capture_output=True,
            check=False,
        )

    def _fail_find_on_call(self, call_number: int) -> str:
        command_dir = self.base / f"find-fails-on-{call_number}"
        command_dir.mkdir()
        count_file = self.base / f"find-count-{call_number}"
        command = command_dir / "find"
        command.write_text(
            "#!/bin/sh\n"
            'count=0\n'
            'if test -f "$FIND_COUNT_FILE"; then\n'
            '  count=$(cat "$FIND_COUNT_FILE")\n'
            "fi\n"
            'count=$((count + 1))\n'
            'printf "%s\\n" "$count" > "$FIND_COUNT_FILE"\n'
            'if test "$count" -eq "$FAIL_FIND_AT"; then exit 73; fi\n'
            'exec /usr/bin/find "$@"\n',
            encoding="ascii",
        )
        command.chmod(0o755)
        self.find_count_file = count_file
        return f"{command_dir}:/usr/bin:/bin"

    def _fail_command(self, name: str) -> str:
        command_dir = self.base / f"fail-{name}"
        command_dir.mkdir()
        command = command_dir / name
        command.write_text("#!/bin/sh\nexit 73\n", encoding="ascii")
        command.chmod(0o755)
        return f"{command_dir}:/usr/bin:/bin"

    def _rewrite_config(self) -> None:
        (self.bundle / "broker.json").write_text(
            json.dumps(self.config, sort_keys=True) + "\n", encoding="utf-8"
        )
        self._write_manifest()

    def _rewrite_unit(self) -> None:
        (self.bundle / "media-generation-systemd-broker.service").write_text(
            self.unit, encoding="utf-8"
        )
        self._write_manifest()

    def _assert_preflight_rejected(self, message: str) -> None:
        result = self._run_preflight()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"bundle preflight failed: {message}", result.stderr)

    def test_valid_reviewed_bundle_passes_documented_preflight(self) -> None:
        result = self._run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_owner_transfer_uses_a_separate_inbox_and_checks_the_copy(self) -> None:
        self.assertIn(
            'apex_bundle="/var/tmp/media-generation-incoming-$EXPECTED_SOURCE_SHA"',
            self.transfer_body,
        )
        self.assertIn(
            'PACKAGE_STAGE="/var/tmp/media-generation-package-',
            self.shell_body,
        )
        self.assertIn("apex_partial=$(ssh apex", self.transfer_body)
        self.assertIn("mktemp -d", self.transfer_body)
        self.assertIn('scp "$bundle"/* "apex:$apex_partial/"', self.transfer_body)
        self.assertIn(
            "sha256sum --strict -c SHA256SUMS",
            self.transfer_body,
        )
        partial_check = self.transfer_body.index(
            "cd '$apex_partial'; sha256sum --strict -c SHA256SUMS"
        )
        publish_directory = self.transfer_body.index(
            "mv -nT -- '$apex_partial' '$apex_bundle'"
        )
        final_check = self.transfer_body.rindex(
            "cd '$apex_bundle'; sha256sum --strict -c SHA256SUMS"
        )
        self.assertLess(partial_check, publish_directory)
        self.assertLess(publish_directory, final_check)
        remote_call = self.transfer_body.index("ssh apex")
        for guard in (
            'case "$EXPECTED_SOURCE_SHA"',
            "-ne 40",
            'case "$EXPECTED_SUMS_SHA"',
            "-ne 64",
            'test "$actual_sums_sha" = "$EXPECTED_SUMS_SHA"',
        ):
            with self.subTest(guard=guard):
                self.assertLess(self.transfer_body.index(guard), remote_call)
        result = subprocess.run(
            ["/bin/sh", "-n"],
            input=self.transfer_body,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_owner_transfer_can_retry_without_publishing_partial_bundle(
        self,
    ) -> None:
        mac_bundle = self.base / "mac-release"
        shutil.copytree(self.bundle, mac_bundle)
        apex_tmp = self.base / "apex" / "var" / "tmp"
        apex_tmp.mkdir(parents=True)
        apex_bundle = apex_tmp / f"media-generation-incoming-{self.source_sha}"
        partial_prefix = f"media-generation-incoming-{self.source_sha}.partial."
        scp_marker = self.base / "scp-failed-once"
        command_dir = self.base / "transfer-command-shims"
        command_dir.mkdir()

        ssh = command_dir / "ssh"
        ssh.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import subprocess\n"
            "import sys\n"
            "if len(sys.argv) != 3 or sys.argv[1] != 'apex':\n"
            "    raise SystemExit(64)\n"
            "result = subprocess.run(('/bin/sh', '-eu', '-c', sys.argv[2]), "
            "env=os.environ.copy(), check=False)\n"
            "raise SystemExit(result.returncode)\n",
            encoding="utf-8",
        )
        ssh.chmod(0o755)

        scp = command_dir / "scp"
        scp.write_text(
            f"#!{sys.executable}\n"
            "import os\n"
            "import shutil\n"
            "import sys\n"
            "from pathlib import Path\n"
            "if len(sys.argv) < 3 or not sys.argv[-1].startswith('apex:'):\n"
            "    raise SystemExit(64)\n"
            "marker = Path(os.environ['SCP_MARKER'])\n"
            "destination = Path(sys.argv[-1][len('apex:'):])\n"
            "if not destination.is_dir():\n"
            "    raise SystemExit(66)\n"
            "if not marker.exists():\n"
            "    marker.touch()\n"
            "    source = sys.argv[1]\n"
            "    shutil.copy2(source, destination / Path(source).name)\n"
            "    raise SystemExit(73)\n"
            "for source in sys.argv[1:-1]:\n"
            "    shutil.copy2(source, destination / Path(source).name)\n",
            encoding="utf-8",
        )
        scp.chmod(0o755)

        shasum = command_dir / "shasum"
        shasum.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-a" ] && [ "$2" = "256" ]; then shift 2; fi\n'
            'exec sha256sum "$@"\n',
            encoding="ascii",
        )
        shasum.chmod(0o755)

        transfer_body = self.transfer_body.replace(
            'bundle="/var/tmp/media-generation-release-$EXPECTED_SOURCE_SHA"',
            f'bundle="{mac_bundle}"',
        ).replace(
            'apex_bundle="/var/tmp/media-generation-incoming-$EXPECTED_SOURCE_SHA"',
            f'apex_bundle="{apex_bundle}"',
        ).replace(
            "'/var/tmp/media-generation-incoming-$EXPECTED_SOURCE_SHA.partial.XXXXXXXX'",
            f"'{apex_tmp}/media-generation-incoming-$EXPECTED_SOURCE_SHA.partial.XXXXXXXX'",
        )
        environment = self._environment(
            path=f"{command_dir}:/usr/bin:/bin"
        )
        environment["SCP_MARKER"] = str(scp_marker)

        failed_transfer = self._run_shell(transfer_body, environment=environment)
        self.assertEqual(failed_transfer.returncode, 73, failed_transfer.stderr)
        self.assertFalse(apex_bundle.exists())
        first_partials = sorted(apex_tmp.glob(f"{partial_prefix}*"))
        self.assertEqual(len(first_partials), 1)
        self.assertEqual(
            [path.name for path in first_partials[0].iterdir()], ["SHA256SUMS"]
        )

        retried_transfer = self._run_shell(transfer_body, environment=environment)
        self.assertEqual(retried_transfer.returncode, 0, retried_transfer.stderr)
        self.assertTrue(apex_bundle.is_dir())
        remaining_partials = sorted(apex_tmp.glob(f"{partial_prefix}*"))
        self.assertEqual(remaining_partials, first_partials)
        self.assertEqual(
            [path.name for path in first_partials[0].iterdir()], ["SHA256SUMS"]
        )

        preflight_environment = environment.copy()
        preflight_environment.update(
            {
                "BUNDLE": str(apex_bundle),
                "PATH": "/usr/bin:/bin",
                "TMPDIR": str(self.base),
            }
        )
        stage_b = self._run_shell(
            self.shell_body, environment=preflight_environment
        )
        self.assertEqual(stage_b.returncode, 0, stage_b.stderr)
        portable_validation = self._run_shell(
            self.portable_command, environment=preflight_environment
        )
        self.assertEqual(
            portable_validation.returncode, 0, portable_validation.stderr
        )

    def test_unexpected_directory_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "unexpected").mkdir()
        self._assert_preflight_rejected("bundle contains a non-regular entry")

    def test_unexpected_symlink_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "unexpected-link").symlink_to("SOURCE_SHA")
        self._assert_preflight_rejected("bundle contains a non-regular entry")

    def test_missing_payload_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "media-generation-apex-ldd-map.jsonl").unlink()
        self._assert_preflight_rejected("bundle inventory does not match")

    def test_additional_regular_payload_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "unlisted-payload").write_text("extra", encoding="ascii")
        self._assert_preflight_rejected("bundle inventory does not match")

    def test_corrupt_checksum_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "broker.json").write_text("corrupt\n", encoding="ascii")
        self._assert_preflight_rejected(
            "SHA256SUMS does not match the canonical payload manifest"
        )

    def test_wrong_source_sha_is_rejected_with_diagnostic(self) -> None:
        environment = self._environment()
        environment["EXPECTED_SOURCE_SHA"] = "f" * 40
        result = self._run_shell(self.shell_body, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("bundle preflight failed: SOURCE_SHA does not match", result.stderr)

    def test_source_sha_with_extra_newline_is_rejected_by_both_documented_checks(self) -> None:
        source_path = self.bundle / "SOURCE_SHA"
        source_path.write_bytes(f"{self.source_sha}\n\n".encode("ascii"))
        self._write_manifest()

        original = (
            "set -eu\n"
            'source_sha=$(cat "$BUNDLE/SOURCE_SHA")\n'
            '[ "$source_sha" = "$EXPECTED_SOURCE_SHA" ]\n'
        )
        original_result = self._run_shell(original)
        self.assertEqual(original_result.returncode, 0, original_result.stderr)

        shell_result = self._run_preflight()
        self.assertNotEqual(shell_result.returncode, 0, shell_result.stdout)
        self.assertIn(
            "bundle preflight failed: SOURCE_SHA does not match EXPECTED_SOURCE_SHA exactly",
            shell_result.stderr,
        )

        python_result = self._run_shell(self.portable_command)
        self.assertNotEqual(python_result.returncode, 0, python_result.stdout)
        self.assertIn(
            "SOURCE_SHA does not match EXPECTED_SOURCE_SHA", python_result.stderr
        )

    def test_missing_manifest_is_rejected_with_diagnostic(self) -> None:
        (self.bundle / "SHA256SUMS").unlink()
        self._assert_preflight_rejected(
            "SHA256SUMS is missing, a symlink, or not a regular file"
        )

    def test_unsafe_manifest_filename_is_rejected_before_checksum_read(self) -> None:
        lines = (self.bundle / "SHA256SUMS").read_text(encoding="ascii").splitlines()
        lines[0] = f"{'0' * 64}  ../outside"
        (self.bundle / "SHA256SUMS").write_text(
            "\n".join(lines) + "\n", encoding="ascii"
        )
        self.expected_sums_sha = hashlib.sha256(
            (self.bundle / "SHA256SUMS").read_bytes()
        ).hexdigest()
        self._assert_preflight_rejected(
            "SHA256SUMS does not match the canonical payload manifest"
        )

    def test_first_find_failure_with_empty_output_fails_closed(self) -> None:
        path = self._fail_find_on_call(1)
        environment = self._environment(path=path)
        environment["FIND_COUNT_FILE"] = str(self.find_count_file)
        environment["FAIL_FIND_AT"] = "1"
        result = self._run_shell(self.shell_body, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("bundle preflight failed: find failed", result.stderr)

    def test_payload_find_failure_with_empty_output_fails_closed(self) -> None:
        path = self._fail_find_on_call(2)
        environment = self._environment(path=path)
        environment["FIND_COUNT_FILE"] = str(self.find_count_file)
        environment["FAIL_FIND_AT"] = "2"
        result = self._run_shell(self.shell_body, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("bundle preflight failed: find failed", result.stderr)

    def test_sort_failure_is_reported_instead_of_becoming_empty_inventory(self) -> None:
        result = self._run_preflight(path=self._fail_command("sort"))
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("bundle preflight failed: sort failed", result.stderr)

    def test_original_find_test_accepts_failed_empty_enumeration(self) -> None:
        path = self._fail_find_on_call(1)
        environment = self._environment(path=path)
        environment["FIND_COUNT_FILE"] = str(self.find_count_file)
        environment["FAIL_FIND_AT"] = "1"
        original = (
            "set -eu\n"
            'test -z "$(find "$BUNDLE" -mindepth 1 -maxdepth 1 '
            '! -type f -print -quit)"\n'
        )
        result = self._run_shell(original, environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_protected_broker_values_fail_under_normal_and_optimized_python(self) -> None:
        cases = (
            ("database_path", "/var/lib/other/jobs.sqlite3", "database_path"),
            ("socket_path", "/tmp/other.sock", "socket_path"),
            ("scratch_root", "/tmp/other-scratch", "scratch_root"),
            ("runner_executable", "/tmp/runner", "runner_executable"),
            ("runner_uid", 971, "runner_uid"),
            ("runner_gid", 971, "runner_gid"),
            ("runner_supplementary_gids", [971, 990], "runner_supplementary_gids"),
            ("worker_uid", 973, "worker_uid"),
            ("worker_gid", 973, "worker_gid"),
            ("scratch_gid", 990, "scratch_gid"),
            ("model_read_gid", 971, "model_read_gid"),
            ("device_allow", ["/dev/kfd", "/dev/dri/card1"], "device_allow"),
            ("read_roots", ["/"], "read_roots"),
            (
                "environment_path_allowlist",
                ["/usr/bin", "/tmp"],
                "environment_path_allowlist",
            ),
            ("empty_timeout_seconds", 31, "empty_timeout_seconds"),
            ("runner_uid", 970.0, "runner_uid"),
            (
                "runner_supplementary_gids",
                [971.0, 973, 990],
                "runner_supplementary_gids",
            ),
            ("unrecognized", True, "broker configuration field set"),
        )
        for key, value, message in cases:
            with self.subTest(key=key):
                self.config = self._valid_config()
                self.config[key] = value
                self._rewrite_config()
                for optimized in (False, True):
                    with self.subTest(optimized=optimized):
                        result = self._run_python(optimized=optimized)
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(
                            f"configuration validation failed: {message}",
                            result.stderr,
                        )

    def test_python_validator_rejects_wrong_unit_mounts_and_config_selection(self) -> None:
        bad_args = (
            (
                str(self.bundle),
                self.source_sha,
                self.expected_sums_sha,
                "/tmp/unrelated.service",
                f"/etc/media-generation/releases/{self.source_sha}/broker.json",
            ),
            (
                str(self.bundle),
                self.source_sha,
                self.expected_sums_sha,
                "/etc/systemd/system/media-generation-systemd-broker.service",
                "/tmp/unrelated.json",
            ),
        )
        for args in bad_args:
            with self.subTest(args=args[2:]):
                result = self._run_python(args=args)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("configuration validation failed:", result.stderr)

        self.unit = self.unit.replace(
            "/var/lib/media-generation-v9/db", "/var/lib/unexpected/db"
        )
        self._rewrite_unit()
        result = self._run_python()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "configuration validation failed: systemd unit does not exactly match the release-bound security template",
            result.stderr,
        )

    def test_python_validator_rejects_non_candidate_executable_normally_and_optimized(self) -> None:
        self.unit = self.unit.replace(
            f"ExecStart=/opt/media-generation/releases/{self.source_sha}/venv/"
            "bin/media-generation-systemd-broker",
            "ExecStart=/opt/media-generation/venv/bin/media-generation-systemd-broker",
        )
        self._rewrite_unit()
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self._run_python(optimized=optimized)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(
                    "configuration validation failed: systemd unit does not exactly match the release-bound security template",
                    result.stderr,
                )

    def test_valid_python_validator_passes_with_normal_and_optimized_execution(self) -> None:
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self._run_python(optimized=optimized)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_python_validator_rejects_missing_arguments_cleanly(self) -> None:
        result = self._run_python(args=())
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("usage:", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)

    def test_portable_documented_command_passes_and_rejects_wrong_revision(self) -> None:
        result = self._run_shell(self.portable_command)
        self.assertEqual(result.returncode, 0, result.stderr)

        environment = self._environment()
        environment["EXPECTED_SOURCE_SHA"] = "f" * 40
        result = self._run_shell(self.portable_command, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_portable_documented_command_rejects_missing_environment(self) -> None:
        environment = self._environment()
        del environment["EXPECTED_SUMS_SHA"]
        result = self._run_shell(self.portable_command, environment=environment)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("EXPECTED_SUMS_SHA", result.stderr)

    def test_portable_documented_command_rejects_malformed_manifest(self) -> None:
        sums = self.bundle / "SHA256SUMS"
        lines = sums.read_text(encoding="ascii").splitlines()
        lines[0] = f"{'0' * 63}g  {lines[0][66:]}"
        sums.write_text("\n".join(lines) + "\n", encoding="ascii")
        self.expected_sums_sha = hashlib.sha256(sums.read_bytes()).hexdigest()
        result = self._run_shell(self.portable_command)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("malformed SHA256SUMS entry", result.stderr)

    def test_portable_documented_command_rejects_non_lf_manifest_separators(self) -> None:
        sums_path = self.bundle / "SHA256SUMS"
        original = sums_path.read_bytes()
        mutations = (
            ("carriage return", original.replace(b"\n", b"\r\n", 1)),
            ("vertical tab", original.replace(b"\n", b"\v", 1)),
            ("form feed", original.replace(b"\n", b"\f", 1)),
            ("missing final newline", original[:-1]),
        )
        for name, contents in mutations:
            with self.subTest(separator=name):
                sums_path.write_bytes(contents)
                self.expected_sums_sha = hashlib.sha256(contents).hexdigest()
                result = self._run_shell(self.portable_command)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                if name == "missing final newline":
                    self.assertIn("must end with an LF newline", result.stderr)
                else:
                    self.assertIn("must use LF line separators", result.stderr)

    def test_shell_preflight_rejects_noncanonical_manifest_records(self) -> None:
        sums_path = self.bundle / "SHA256SUMS"
        original = sums_path.read_bytes()
        mutations = (
            ("carriage return", original.replace(b"\n", b"\r\n", 1)),
            ("vertical tab", original.replace(b"\n", b"\v", 1)),
            ("form feed", original.replace(b"\n", b"\f", 1)),
            ("missing final newline", original[:-1]),
        )
        for name, contents in mutations:
            with self.subTest(separator=name):
                sums_path.write_bytes(contents)
                self.expected_sums_sha = hashlib.sha256(contents).hexdigest()
                result = self._run_preflight()
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_old_checksum_command_accepts_missing_final_newline(self) -> None:
        sums_path = self.bundle / "SHA256SUMS"
        contents = sums_path.read_bytes()[:-1]
        sums_path.write_bytes(contents)
        self.expected_sums_sha = hashlib.sha256(contents).hexdigest()
        old_check = (
            "set -eu\n"
            'cd "$BUNDLE"\n'
            "sha256sum --strict -c SHA256SUMS\n"
        )
        old_result = self._run_shell(old_check)
        self.assertEqual(old_result.returncode, 0, old_result.stderr)

        current_result = self._run_preflight()
        self.assertNotEqual(current_result.returncode, 0, current_result.stdout)
        self.assertIn(
            "bundle preflight failed: SHA256SUMS does not match the canonical payload manifest",
            current_result.stderr,
        )

    def test_portable_documented_command_rejects_unit_security_changes(self) -> None:
        cases = (
            ("ProtectSystem=strict", "ProtectSystem=off", "ProtectSystem"),
            ("User=root", "User=media-generation-worker", "User"),
            ("NoNewPrivileges=yes", "NoNewPrivileges=no", "NoNewPrivileges"),
            (
                "ReadWritePaths=/run/media-generation",
                "ReadWritePaths=/",
                "ReadWritePaths",
            ),
        )
        for old, new, message in cases:
            with self.subTest(directive=message):
                self.unit = self._valid_unit().replace(old, new)
                self._rewrite_unit()
                result = self._run_shell(self.portable_command)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(
                    "configuration validation failed: systemd unit does not exactly match the release-bound security template",
                    result.stderr,
                )

    def test_python_validator_rejects_crlf_unit_normally_and_optimized(self) -> None:
        self.unit = self._valid_unit().replace("\n", "\r\n")
        self._rewrite_unit()
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self._run_python(optimized=optimized)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(
                    "configuration validation failed: systemd unit does not exactly match the release-bound security template",
                    result.stderr,
                )

        result = self._run_shell(self.portable_command)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "configuration validation failed: systemd unit does not exactly match the release-bound security template",
            result.stderr,
        )


class ApexSqlitePreflightManifestTests(unittest.TestCase):
    OPTIMIZATION_MODES = (
        ("normal", False, False),
        ("-O", True, False),
        ("PYTHONOPTIMIZE=1", False, True),
    )
    EXPECTED_LOGICAL_DIGEST = (
        "e17e317282ef33cbb2e76488895758ce024ccdda1838c6bf2fbd17b388bb18b9"
    )
    INSTALLATION_DATABASE_PATH = (
        'path = Path("/var/lib/media-generation-v9/db/jobs.sqlite3")'
    )

    @classmethod
    def setUpClass(cls) -> None:
        document = MANIFEST.read_text(encoding="utf-8")
        section_six_shell = ApexBundlePreflightManifestTests._extract_fenced_block(
            document, "The owner creates only the listed new paths", "sh"
        )
        cls.section_six_python = (
            ApexBundlePreflightManifestTests._extract_heredoc(
                section_six_shell, "PY"
            )
        )
        if cls.section_six_python.count(cls.INSTALLATION_DATABASE_PATH) != 1:
            raise AssertionError("installation database path changed unexpectedly")
        schema_check_start = cls.section_six_python.index(
            "with sqlite3.connect(path) as connection:"
        )
        cls.section_six_schema_check = cls.section_six_python[schema_check_start:]
        cls.upgrade_python = (
            ApexBundlePreflightManifestTests._extract_fenced_block(
                document, "Run the following check as the worker", "python"
            )
        )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="apex-sqlite-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    @property
    def repository_root(self) -> Path:
        return MANIFEST.parents[2]

    def _environment(self, *, optimize_environment: bool = False) -> dict[str, str]:
        environment = os.environ.copy()
        environment.pop("PYTHONOPTIMIZE", None)
        source_root = str(self.repository_root / "src")
        existing_pythonpath = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (source_root, existing_pythonpath) if part
        )
        if optimize_environment:
            environment["PYTHONOPTIMIZE"] = "1"
        return environment

    def _run_python(
        self,
        source: str,
        *,
        database: Path | None = None,
        optimized_flag: bool = False,
        optimize_environment: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable]
        if optimized_flag:
            command.append("-O")
        command.append("-")
        if database is not None:
            command.append(str(database))
        return subprocess.run(
            command,
            input=source,
            text=True,
            capture_output=True,
            cwd=self.repository_root,
            env=self._environment(optimize_environment=optimize_environment),
            check=False,
            timeout=30,
        )

    def _section_six_source(self, database: Path) -> str:
        return self.section_six_python.replace(
            self.INSTALLATION_DATABASE_PATH,
            f"path = Path({str(database)!r})",
            1,
        )

    def _section_six_schema_source(self) -> str:
        return (
            "import sqlite3\n"
            "import sys\n"
            "from pathlib import Path\n"
            "path = Path(sys.argv[1])\n"
            f"{self.section_six_schema_check}"
        )

    def _create_database(self, database: Path, fixture: str = "valid") -> None:
        if fixture == "missing_database":
            return
        if fixture == "invalid_database_file":
            database.write_bytes(b"not a SQLite database\n")
            return

        with sqlite3.connect(database) as connection:
            connection.executescript(
                "CREATE TABLE execution_resource (id INTEGER PRIMARY KEY, state TEXT);"
                "CREATE TABLE execution_jobs (id INTEGER PRIMARY KEY, status TEXT NOT NULL, "
                "parent_id INTEGER REFERENCES execution_jobs(id));"
                "CREATE TABLE execution_attempts (status TEXT NOT NULL);"
                "CREATE TABLE execution_cancellations (state TEXT NOT NULL);"
                "CREATE TABLE artifact_publications (state TEXT NOT NULL);"
            )
            if fixture != "missing_resource":
                resource_state = {
                    "claimed_resource": "claimed",
                    "quarantined_resource": "quarantined",
                    "malformed_resource": None,
                }.get(fixture, "available")
                connection.execute(
                    "INSERT INTO execution_resource (id, state) VALUES (1, ?)",
                    (resource_state,),
                )

            if fixture in ("wrong_schema_version", "schema_v8"):
                connection.execute("PRAGMA user_version = 8")
            elif fixture != "missing_schema_metadata":
                connection.execute("PRAGMA user_version = 9")

            if fixture in ("running_job", "ambiguous_job"):
                status = "running" if fixture == "running_job" else "ambiguous"
                connection.execute(
                    "INSERT INTO execution_jobs (status) VALUES (?)", (status,)
                )
            elif fixture == "foreign_key_violation":
                connection.execute("PRAGMA foreign_keys = OFF")
                connection.execute(
                    "INSERT INTO execution_jobs (status, parent_id) VALUES (?, ?)",
                    ("complete", 404),
                )

            if fixture in ("running_attempt", "ambiguous_attempt"):
                status = "running" if fixture == "running_attempt" else "ambiguous"
                connection.execute(
                    "INSERT INTO execution_attempts (status) VALUES (?)", (status,)
                )
            if fixture == "requested_cancellation":
                connection.execute(
                    "INSERT INTO execution_cancellations (state) VALUES (?)",
                    ("requested",),
                )
            if fixture in ("allocated_publication", "ready_publication"):
                state = "allocated" if fixture == "allocated_publication" else "ready"
                connection.execute(
                    "INSERT INTO artifact_publications (state) VALUES (?)", (state,)
                )
            if fixture == "missing_required_table":
                connection.execute("DROP TABLE artifact_publications")
            if fixture == "query_error":
                connection.execute("DROP TABLE execution_jobs")
                connection.execute("CREATE TABLE execution_jobs (id INTEGER PRIMARY KEY)")

        if fixture == "integrity_failure":
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE integrity_guard (value INTEGER, alternate INTEGER)"
                )
                connection.executemany(
                    "INSERT INTO integrity_guard VALUES (?, ?)", ((1, 10), (2, 20))
                )
                connection.execute(
                    "CREATE INDEX integrity_guard_index ON integrity_guard(value)"
                )
                connection.execute("PRAGMA writable_schema = ON")
                connection.execute(
                    "UPDATE sqlite_master SET sql = ? WHERE name = ?",
                    (
                        "CREATE INDEX integrity_guard_index ON integrity_guard(alternate)",
                        "integrity_guard_index",
                    ),
                )
                connection.execute("PRAGMA writable_schema = OFF")

    @staticmethod
    def _database_snapshot(database: Path) -> tuple[tuple[str, bytes], ...]:
        return tuple(
            (path.name, path.read_bytes())
            for path in sorted(database.parent.glob(f"{database.name}*"))
            if path.is_file()
        )

    def _run_upgrade_check(
        self, database: Path, *, optimized_flag: bool = False,
        optimize_environment: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_python(
            self.upgrade_python,
            database=database,
            optimized_flag=optimized_flag,
            optimize_environment=optimize_environment,
        )

    def test_upgrade_preflight_returns_expected_digest_for_idle_schema_v9(self) -> None:
        database = self.base / "idle-v9.sqlite3"
        self._create_database(database)
        before = self._database_snapshot(database)

        for name, optimized_flag, optimize_environment in self.OPTIMIZATION_MODES:
            with self.subTest(mode=name):
                result = self._run_upgrade_check(
                    database,
                    optimized_flag=optimized_flag,
                    optimize_environment=optimize_environment,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), self.EXPECTED_LOGICAL_DIGEST)
                self.assertEqual(result.stderr, "")
                self.assertEqual(self._database_snapshot(database), before)

    def test_upgrade_preflight_rejects_unsafe_database_states_in_all_modes(self) -> None:
        cases = (
            ("wrong_schema_version", "expected schema version 9"),
            ("missing_schema_metadata", "expected schema version 9"),
            ("integrity_failure", "integrity_check failed"),
            ("foreign_key_violation", "foreign_key_check found"),
            ("missing_resource", "resource row id=1 is missing"),
            ("claimed_resource", "resource id=1 must be available"),
            ("quarantined_resource", "resource id=1 must be available"),
            ("malformed_resource", "resource id=1 must be available"),
            ("running_job", "running or ambiguous execution jobs"),
            ("ambiguous_job", "running or ambiguous execution jobs"),
            ("running_attempt", "running or ambiguous execution attempts"),
            ("ambiguous_attempt", "running or ambiguous execution attempts"),
            ("requested_cancellation", "requested cancellation rows"),
            ("allocated_publication", "allocated or ready publication rows"),
            ("ready_publication", "allocated or ready publication rows"),
            ("missing_required_table", "artifact publications query failed"),
            ("query_error", "execution jobs query failed"),
            ("missing_database", "cannot open database read-only"),
            ("invalid_database_file", "schema version query failed"),
        )
        for fixture, diagnostic in cases:
            with self.subTest(fixture=fixture):
                database = self.base / f"{fixture}.sqlite3"
                self._create_database(database, fixture)
                before = self._database_snapshot(database)
                for name, optimized_flag, optimize_environment in self.OPTIMIZATION_MODES:
                    with self.subTest(mode=name):
                        result = self._run_upgrade_check(
                            database,
                            optimized_flag=optimized_flag,
                            optimize_environment=optimize_environment,
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertIn(
                            f"SQLite preflight failed: {diagnostic}", result.stderr
                        )
                        self.assertNotRegex(
                            result.stdout, r"(?m)^[0-9a-f]{64}$"
                        )
                        self.assertEqual(self._database_snapshot(database), before)

    def test_initialization_block_creates_schema_v9_in_all_modes(self) -> None:
        for name, optimized_flag, optimize_environment in self.OPTIMIZATION_MODES:
            with self.subTest(mode=name):
                database = self.base / f"initialized-{name}.sqlite3"
                result = self._run_python(
                    self._section_six_source(database),
                    optimized_flag=optimized_flag,
                    optimize_environment=optimize_environment,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                with sqlite3.connect(
                    f"{database.as_uri()}?mode=ro", uri=True
                ) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone(), (9,)
                    )

    def test_section_six_schema_check_rejects_wrong_version_in_all_modes(self) -> None:
        for name, optimized_flag, optimize_environment in self.OPTIMIZATION_MODES:
            with self.subTest(mode=name):
                database = self.base / f"unsupported-{name}.sqlite3"
                self._create_database(database, "schema_v8")
                before = self._database_snapshot(database)
                result = self._run_python(
                    self._section_six_schema_source(),
                    database=database,
                    optimized_flag=optimized_flag,
                    optimize_environment=optimize_environment,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(
                    "schema initialization check failed: expected user_version 9",
                    result.stderr,
                )
                self.assertEqual(self._database_snapshot(database), before)


if __name__ == "__main__":
    unittest.main()
