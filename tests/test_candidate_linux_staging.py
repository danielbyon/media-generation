"""Linux acquisition contracts, with explicit Darwin syscall injection."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from media_generation import _candidate_acquisition as acquisition
from media_generation import candidate, cli
from candidate_linux_fakes import inject_linux_inode_operations
from test_candidate_preparation import (
    _acquisition_config, _fixture, _payload, _Response, _trusted_evidence,
    _write_trusted_evidence,
    _write_pending_publication_journal,
)


@pytest.fixture(params=["native-linux" if sys.platform.startswith("linux") else "injected-linux-on-darwin"])
def linux_staging(request, monkeypatch, tmp_path):
    if request.param == "native-linux":
        return []
    return inject_linux_inode_operations(monkeypatch, tmp_path / "kernel-inodes")


def test_stage_is_unnamed_from_first_observation(tmp_path, linux_staging):
    parent = tmp_path / "destination"
    parent.mkdir()
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    stage = None
    try:
        stage = acquisition._open_staging_file(parent_fd)
        facts = os.fstat(stage.descriptor)
        assert facts.st_nlink == 0
        assert facts.st_dev == os.fstat(parent_fd).st_dev
        assert facts.st_mode & 0o777 == 0o600
        assert list(parent.iterdir()) == []
    finally:
        if stage is not None:
            os.close(stage.descriptor)
        os.close(parent_fd)
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize(
    "unsupported", ["darwin", "tmpfile", "publication"]
)
def test_capability_failure_precedes_network_and_output_mutation(
    tmp_path, monkeypatch, capsys, linux_staging, unsupported,
):
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    original_open = os.open

    def reject_tmpfile(path, flags, *args, **kwargs):
        if flags & os.O_TMPFILE == os.O_TMPFILE:
            raise OSError(errno.EOPNOTSUPP, "unsupported test filesystem")
        return original_open(path, flags, *args, **kwargs)

    def reject_publication(*args, **kwargs):
        raise OSError(errno.EOPNOTSUPP, "unsupported descriptor publication")

    if unsupported == "darwin":
        monkeypatch.setattr(acquisition.sys, "platform", "darwin")
    elif unsupported == "tmpfile":
        monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, reject_tmpfile})
        monkeypatch.setattr(os, "open", reject_tmpfile)
    else:
        monkeypatch.setattr(acquisition, "_descriptor_bound_publish", reject_publication)
    network_calls = []

    def remote(*args, **kwargs):
        network_calls.append(args)
        return _Response(200, body=body)

    monkeypatch.setattr(acquisition, "_open_remote", remote)
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    status = cli.main([
        "candidate", "prepare", "--declaration", str(declaration),
        "--manifest-output", str(tmp_path / "prepared.json"),
        "--journal-output", str(tmp_path / "journal.json"),
        "--acquire", "--acquisition-config", str(config),
    ])
    captured = capsys.readouterr()
    assert status == 8
    assert '"code":"candidate_acquisition_error"' in captured.err.replace(" ", "")
    after = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    changed = sorted(
        str(path)
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )
    assert not network_calls and before == after, (
        f"network calls: {len(network_calls)}; changed files: {changed}"
    )


@pytest.mark.parametrize("error_number", [errno.EOPNOTSUPP, errno.ENOTSUP], ids=["EOPNOTSUPP", "ENOTSUP"])
def test_unsupported_final_link_fails_closed_without_named_fallback(
    tmp_path, monkeypatch, capsys, linux_staging, error_number,
):
    """An EEXIST preflight cannot promise that a later new-name link will work."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path, max_attempts=2)
    response = _Response(200, body=body)
    before = {p.relative_to(artifact.parent): p.read_bytes() for p in artifact.parent.rglob("*") if p.is_file()}
    parent_facts = artifact.parent.stat()
    parent_identity = (parent_facts.st_dev, parent_facts.st_ino)
    real_open, real_stage = os.open, acquisition._open_staging_file
    real_link = ctypes.CDLL(None, use_errno=True).linkat
    real_link.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    real_link.restype = ctypes.c_int
    descriptors, network_calls, publication_calls, named_creations = [], [], [], []

    def observe_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            parent_fd = kwargs.get("dir_fd")
            if parent_fd is None:
                in_destination = Path(os.fsdecode(path)).parent.resolve() == artifact.parent.resolve()
            else:
                facts = os.fstat(parent_fd)
                in_destination = (facts.st_dev, facts.st_ino) == parent_identity
            if in_destination:
                named_creations.append(path)
        return real_open(path, flags, *args, **kwargs)

    def observe_stage(parent_fd):
        stage = real_stage(parent_fd)
        descriptors.extend((stage.descriptor, parent_fd))
        return stage

    class UnsupportedFinalLink:
        argtypes = ()
        restype = ctypes.c_int

        def __call__(self, source_fd, source, parent_fd, destination, flags):
            if destination == b".":
                return real_link(source_fd, source, parent_fd, destination, flags)
            publication_calls.append((source, destination, flags))
            assert os.fstat(source_fd).st_nlink == 0
            ctypes.set_errno(error_number)
            return -1

    def remote(*args, **kwargs):
        network_calls.append(args)
        return response

    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, observe_open})
    monkeypatch.setattr(os, "open", observe_open)
    monkeypatch.setattr(acquisition, "_open_staging_file", observe_stage)
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(linkat=UnsupportedFinalLink()))
    monkeypatch.setattr(acquisition, "_open_remote", remote)
    status = cli.main([
        "candidate", "prepare", "--declaration", str(declaration),
        "--manifest-output", str(tmp_path / "prepared.json"),
        "--journal-output", str(tmp_path / "journal.json"),
        "--acquire", "--acquisition-config", str(config),
    ])
    captured = capsys.readouterr()
    failure = json.loads(captured.err)["error"]
    assert status == 8
    assert captured.out == ""
    assert failure["code"] == "candidate_acquisition_error"
    assert "descriptor-bound publication unsupported" in failure["message"]
    assert len(network_calls) == 1 and response.closed
    assert publication_calls == [(b"", os.fsencode(artifact.name), 0x1000)]
    assert not named_creations
    assert not artifact.exists()
    assert not (tmp_path / "prepared.json").exists()
    assert {p.relative_to(artifact.parent): p.read_bytes() for p in artifact.parent.rglob("*") if p.is_file()} == before
    journal = _payload(tmp_path / "journal.json")
    assert journal["status"] == "unverified"
    assert [event["state"] for event in journal["events"]] == ["attempted", "failed"]
    assert journal["events"][-1]["code"] == "acquisition_failed"
    assert descriptors
    for descriptor in set(descriptors):
        with pytest.raises(OSError) as bad_fd:
            os.fstat(descriptor)
        assert bad_fd.value.errno == errno.EBADF


def test_success_binds_synced_descriptor_to_final_name(tmp_path, monkeypatch, linux_staging):
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    original_open = acquisition._open_staging_file
    identities = []

    def observe_stage(parent_fd):
        stage = original_open(parent_fd)
        facts = os.fstat(stage.descriptor)
        identities.append((facts.st_dev, facts.st_ino))
        assert facts.st_nlink == 0
        assert not list(artifact.parent.glob(".t07-*"))
        return stage

    monkeypatch.setattr(acquisition, "_open_staging_file", observe_stage)
    monkeypatch.setattr(acquisition, "_open_remote", lambda *a, **kw: _Response(200, body=body))
    report = candidate.prepare_candidate(
        declaration, manifest_output=tmp_path / "prepared.json",
        journal_output=tmp_path / "journal.json", acquire=True,
        acquisition_config=config, trusted_evidence=_trusted_evidence(),
    )
    facts = artifact.stat()
    assert (facts.st_dev, facts.st_ino) == identities[-1]
    assert artifact.read_bytes() == body
    assert report["status"] == "ready"
    assert _payload(tmp_path / "journal.json")["events"][-1]["code"] == "published_and_verified"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux O_TMPFILE qualification requires APEX")
def test_native_linux_tmpfile_no_clobber_and_last_close_cleanup(tmp_path):
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    stage = acquisition._open_staging_file(parent_fd)
    try:
        os.write(stage.descriptor, b"native-linux")
        os.fsync(stage.descriptor)
        acquisition._descriptor_bound_publish(stage.descriptor, parent_fd, "final")
        with pytest.raises(FileExistsError):
            acquisition._descriptor_bound_publish(stage.descriptor, parent_fd, "final")
        assert os.stat("final", dir_fd=parent_fd).st_ino == os.fstat(stage.descriptor).st_ino
        os.fsync(parent_fd)
    finally:
        os.close(stage.descriptor)
        os.close(parent_fd)
    assert (tmp_path / "final").read_bytes() == b"native-linux"


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="requires native Linux O_TMPFILE"
)
@pytest.mark.parametrize("interruption", ["during-transfer", "after-link"])
def test_process_interruption_recovers_without_named_staging(
    tmp_path, monkeypatch, interruption,
):
    """A killed process leaves only a journal and, after linking, its final file."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    sentinel = artifact.parent / ".t07-stage-unrelated"
    sentinel.write_bytes(b"unrelated entry")
    original_entries = {entry.name for entry in artifact.parent.iterdir()}
    config = _acquisition_config(tmp_path)
    journal = tmp_path / "journal.json"
    manifest = tmp_path / "prepared.json"

    script = r"""
import os
import sys
from pathlib import Path
from media_generation import candidate
from test_candidate_preparation import _Response

declaration, config, manifest, journal = map(Path, sys.argv[1:5])
interruption, body = sys.argv[5], bytes.fromhex(sys.argv[6])

class Response(_Response):
    def read(self, size=-1):
        if interruption == "during-transfer":
            if self._offset:
                os._exit(73)
            return super().read(1)
        return super().read(size)

candidate._acquisition._open_remote = lambda *args, **kwargs: Response(200, body=body)
publish = candidate._acquisition._descriptor_bound_publish

def interrupt_after_link(source_fd, parent_fd, name):
    publish(source_fd, parent_fd, name)
    if interruption == "after-link" and name != ".":
        os._exit(73)

candidate._acquisition._descriptor_bound_publish = interrupt_after_link
candidate.prepare_candidate(
    declaration, manifest_output=manifest, journal_output=journal,
    acquire=True, acquisition_config=config,
)
"""
    env = os.environ.copy()
    root = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root / "tests")))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    child = subprocess.run(
        [sys.executable, "-c", script, str(declaration), str(config), str(manifest),
         str(journal), interruption, body.hex()],
        env=env, capture_output=True, timeout=20, check=False,
    )
    assert child.returncode == 73, child.stderr.decode(errors="replace")
    assert _payload(journal)["events"][-1]["state"] == "attempted"
    assert sentinel.read_bytes() == b"unrelated entry"
    expected_entries = original_entries | (
        {artifact.name} if interruption == "after-link" else set()
    )
    assert {entry.name for entry in artifact.parent.iterdir()} == expected_entries
    published_inode = artifact.stat().st_ino if interruption == "after-link" else None
    requests = []

    def open_remote(*args, **kwargs):
        requests.append(args)
        return _Response(200, body=body)

    monkeypatch.setattr(acquisition, "_open_remote", open_remote)
    report = candidate.prepare_candidate(
        declaration, manifest_output=manifest, journal_output=journal,
        acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"
    assert artifact.read_bytes() == body
    assert sentinel.read_bytes() == b"unrelated entry"
    if interruption == "after-link":
        assert not requests
        assert artifact.stat().st_ino == published_inode
        assert _payload(journal)["events"][-1]["code"] == "recovered_verified_publication"
    else:
        assert len(requests) == 1
        assert any(
            event["code"] == "interrupted_attempt"
            for event in _payload(journal)["events"]
        )


def _download_fixture(tmp_path, monkeypatch, response):
    """Use synthetic bytes and the existing transport boundary for one transfer."""
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    pin = declaration.artifact_targets()["component:diffusion"]
    artifact = tmp_path / "files" / pin.path
    artifact.unlink()
    config = candidate.parse_acquisition_config(_acquisition_config(tmp_path))
    monkeypatch.setattr(acquisition, "_open_remote", lambda *a, **kw: response)
    return dict(
        source=declaration.acquisition_sources[0], pin=pin,
        root=declaration.root_index[pin.root], config=config, executable=False,
        budget=acquisition._TransferBudget(config.max_total_bytes),
        deadline=acquisition._TransferDeadline.start(config.timeout_seconds),
    )


@pytest.mark.parametrize("close_error", [False, True])
def test_first_fstat_failure_closes_only_owned_inode(
    tmp_path, monkeypatch, linux_staging, close_error,
):
    parent_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_fstat, real_close = os.fstat, os.close
    owned, closed = [], []
    primary = OSError(errno.EIO, "first inode observation failed")

    def fail_first_observation(descriptor):
        if descriptor != parent_fd:
            owned.append(descriptor)
            raise primary
        return real_fstat(descriptor)

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)
        if close_error:
            raise OSError(errno.EIO, "close reported failure")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "fstat", fail_first_observation)
            patch.setattr(os, "close", close)
            with pytest.raises(OSError) as failure:
                acquisition._open_staging_file(parent_fd)
        assert failure.value is primary
        assert len(owned) == 1 and closed == owned
        with pytest.raises(OSError) as bad_fd:
            real_fstat(owned[0])
        assert bad_fd.value.errno == errno.EBADF
        assert real_fstat(parent_fd).st_ino > 0
        if close_error:
            assert "staging descriptor cleanup failed" in primary.__notes__
    finally:
        real_close(parent_fd)


@pytest.mark.parametrize("phase", ["open", "headers", "body", "interrupt"])
@pytest.mark.parametrize("close_error", [False, True])
def test_transfer_failure_closes_descriptors_and_response(
    tmp_path, monkeypatch, linux_staging, phase, close_error,
):
    response = _Response(200, read_error=OSError("body failed"))
    arguments = _download_fixture(tmp_path, monkeypatch, response)
    owned, closed = [], []
    real_open_stage, real_close = acquisition._open_staging_file, os.close

    def observe_stage(parent_fd):
        stage = real_open_stage(parent_fd)
        owned.extend((stage.descriptor, parent_fd))
        return stage

    def fail_open(*args, **kwargs):
        raise OSError("connection failed")

    def fail_headers(*args, **kwargs):
        raise OSError("header inspection failed")

    def interrupt_read(*args, **kwargs):
        raise KeyboardInterrupt("interrupted body")

    def close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)
        if close_error and descriptor == owned[0]:
            raise OSError(errno.EIO, "close reported failure")

    monkeypatch.setattr(acquisition, "_open_staging_file", observe_stage)
    monkeypatch.setattr(os, "close", close)
    if phase == "open":
        monkeypatch.setattr(acquisition, "_open_remote", fail_open)
    elif phase == "headers":
        monkeypatch.setattr(acquisition, "_response_headers", fail_headers)
    elif phase == "interrupt":
        monkeypatch.setattr(response, "read", interrupt_read)
    with pytest.raises((acquisition._RetryableRemoteError, OSError, KeyboardInterrupt)) as failure:
        acquisition._download_to_staging(**arguments)
    assert len(owned) == 2
    for descriptor in owned:
        assert closed.count(descriptor) == 1
        with pytest.raises(OSError) as bad_fd:
            os.fstat(descriptor)
        assert bad_fd.value.errno == errno.EBADF
    if phase != "open":
        assert response.closed
    if close_error:
        assert "staging descriptor cleanup failed" in failure.value.__notes__
    assert not (tmp_path / "files/diffusion.safetensors").exists()
    assert not list((tmp_path / "files").glob(".t07-*"))


@pytest.mark.parametrize("window", ["creation-before-first-stat", "identity-before-cleanup"])
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_replacements_at_old_stage_names_are_never_adopted_or_deleted(
    tmp_path, monkeypatch, linux_staging, window, kind,
):
    """Replace a real entry at each old race boundary; acquisition cannot own it."""
    parent = tmp_path / "destination"
    parent.mkdir()
    victim = parent / ".t07-stage-victim"
    if kind == "directory":
        victim.mkdir()
    else:
        victim.write_bytes(b"original")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    real_open, real_close, real_fstat = os.open, os.close, os.fstat
    real_mkdir, real_unlink = os.mkdir, os.unlink
    replaced = []

    def replace_entry():
        victim.rename(parent / "displaced-original")
        if kind == "directory":
            real_mkdir(victim)
            (victim / "sentinel").write_bytes(b"unrelated replacement")
        else:
            victim.write_bytes(b"unrelated replacement")
        replaced.append((victim.stat().st_dev, victim.stat().st_ino))

    def open_inode(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        if flags & os.O_TMPFILE == os.O_TMPFILE and window == "creation-before-first-stat":
            replace_entry()
        return descriptor

    def forbid_named_mutation(*args, **kwargs):
        raise AssertionError("acquisition attempted named stage creation or cleanup")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", open_inode)
            patch.setattr(os, "mkdir", forbid_named_mutation)
            patch.setattr(os, "unlink", forbid_named_mutation)
            patch.setattr(os, "rmdir", forbid_named_mutation)
            stage = acquisition._open_staging_file(parent_fd)
            assert real_fstat(stage.descriptor).st_nlink == 0
            if window == "identity-before-cleanup":
                replace_entry()
            real_close(stage.descriptor)
        assert len(replaced) == 1
        facts = victim.stat()
        assert (facts.st_dev, facts.st_ino) == replaced[0]
        content = victim / "sentinel" if kind == "directory" else victim
        assert content.read_bytes() == b"unrelated replacement"
        assert (parent / "displaced-original").exists()
        assert set(p.name for p in parent.iterdir()) == {victim.name, "displaced-original"}
    finally:
        real_close(parent_fd)


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_atomic_link_conflict_preserves_unrelated_destination(
    tmp_path, monkeypatch, linux_staging, kind,
):
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    sentinel = tmp_path / "unrelated"
    sentinel.write_bytes(b"do not delete or replace")
    real_publish = acquisition._descriptor_bound_publish
    identities = []

    def conflict(source_fd, parent_fd, final_name):
        if final_name != ".":
            if kind == "file":
                artifact.write_bytes(b"unrelated file")
            elif kind == "directory":
                artifact.mkdir()
            else:
                artifact.symlink_to(sentinel)
            identities.append(artifact.lstat().st_ino)
        real_publish(source_fd, parent_fd, final_name)

    monkeypatch.setattr(acquisition, "_descriptor_bound_publish", conflict)
    monkeypatch.setattr(acquisition, "_open_remote", lambda *a, **kw: _Response(200, body=body))
    with pytest.raises(candidate.CandidateAcquisitionError, match="destination exists"):
        candidate.prepare_candidate(
            declaration, manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json", acquire=True, acquisition_config=config,
        )
    assert artifact.lstat().st_ino == identities[0]
    assert sentinel.read_bytes() == b"do not delete or replace"
    assert not (tmp_path / "prepared.json").exists()
    assert _payload(tmp_path / "journal.json")["events"][-1]["code"] == "acquisition_failed"


@pytest.mark.parametrize("window", ["creation-before-first-stat", "before-descriptor-close"])
def test_destination_directory_replacement_is_not_adopted_or_cleaned(
    tmp_path, monkeypatch, linux_staging, window,
):
    """Replacing the retained parent at either cleanup race leaves it untouched."""
    response = _Response(200, read_error=OSError("interrupted transfer"))
    arguments = _download_fixture(tmp_path, monkeypatch, response)
    parent = tmp_path / "files"
    displaced = tmp_path / "displaced-files"
    real_open, real_close = os.open, os.close
    owned, closed, replacements = [], [], []

    def replace_parent():
        parent.rename(displaced)
        parent.mkdir()
        (parent / "sentinel").write_bytes(b"unrelated replacement directory")
        replacements.append(parent.stat().st_ino)

    def open_inode(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        if flags & os.O_TMPFILE == os.O_TMPFILE:
            owned.extend((descriptor, kwargs["dir_fd"]))
            if window == "creation-before-first-stat":
                replace_parent()
        return descriptor

    def close(descriptor):
        if owned and descriptor == owned[0] and window == "before-descriptor-close":
            replace_parent()
        real_close(descriptor)
        closed.append(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", open_inode)
        patch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, open_inode})
        patch.setattr(os, "close", close)
        with pytest.raises(acquisition._RetryableRemoteError, match="response_body_failed"):
            acquisition._download_to_staging(**arguments)
    assert parent.stat().st_ino == replacements[0]
    assert set(p.name for p in parent.iterdir()) == {"sentinel"}
    assert (parent / "sentinel").read_bytes() == b"unrelated replacement directory"
    assert displaced.is_dir()
    assert not list(displaced.glob(".t07-*"))
    assert not (displaced / "diffusion.safetensors").exists()
    for descriptor in owned:
        assert closed.count(descriptor) == 1
        with pytest.raises(OSError) as bad_fd:
            os.fstat(descriptor)
        assert bad_fd.value.errno == errno.EBADF


@pytest.mark.parametrize("when", ["after-link", "during-directory-sync"])
def test_final_name_replacement_cannot_record_success(tmp_path, monkeypatch, linux_staging, when):
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files/diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    config = _acquisition_config(tmp_path)
    real_publish, real_sync = acquisition._descriptor_bound_publish, acquisition._fsync_directory
    replacement = []

    def replace_artifact():
        artifact.rename(artifact.with_suffix(".saved"))
        artifact.write_bytes(body)
        replacement.append(artifact.stat().st_ino)

    def publish(source_fd, parent_fd, final_name):
        real_publish(source_fd, parent_fd, final_name)
        if when == "after-link":
            replace_artifact()

    def sync(parent_fd):
        real_sync(parent_fd)
        if when == "during-directory-sync" and artifact.exists() and not replacement:
            replace_artifact()

    monkeypatch.setattr(acquisition, "_descriptor_bound_publish", publish)
    monkeypatch.setattr(acquisition, "_fsync_directory", sync)
    monkeypatch.setattr(acquisition, "_open_remote", lambda *a, **kw: _Response(200, body=body))
    with pytest.raises(candidate.CandidateAcquisitionError, match="could not be synchronized"):
        candidate.prepare_candidate(
            declaration, manifest_output=tmp_path / "prepared.json", acquire=True,
            journal_output=tmp_path / "journal.json", acquisition_config=config,
        )
    assert artifact.stat().st_ino == replacement[0]
    journal = _payload(tmp_path / "journal.json")
    assert journal["status"] == "unverified"
    assert journal["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in journal["events"])


def test_offline_operations_remain_available_on_darwin(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace
    declaration = _fixture(tmp_path)
    trusted = _write_trusted_evidence(tmp_path)
    monkeypatch.setattr(acquisition, "sys", SimpleNamespace(platform="darwin", exception=sys.exception))

    def no_acquisition(*args, **kwargs):
        raise AssertionError("offline operation attempted acquisition")

    monkeypatch.setattr(acquisition, "_open_staging_file", no_acquisition)
    monkeypatch.setattr(acquisition, "_open_remote", no_acquisition)
    for operation in ("inspect", "verify"):
        assert cli.main([
            "candidate", operation, "--declaration", str(declaration),
            "--trusted-evidence", str(trusted),
        ]) == 0
        assert capsys.readouterr().err == ""
    report = candidate.prepare_candidate(
        declaration, manifest_output=tmp_path / "prepared.json",
        trusted_evidence=_trusted_evidence(),
    )
    assert report["status"] == "ready"


def test_response_cleanup_failure_does_not_mask_transfer_error(tmp_path, monkeypatch, linux_staging):
    response = _Response(200, read_error=OSError("body failed"))
    arguments = _download_fixture(tmp_path, monkeypatch, response)

    def fail_close():
        raise RuntimeError("response cleanup failed")

    monkeypatch.setattr(response, "close", fail_close)
    with pytest.raises(acquisition._RetryableRemoteError, match="response_body_failed") as failure:
        acquisition._download_to_staging(**arguments)
    assert any("response cleanup failed" in note for note in failure.value.__notes__)


@pytest.mark.parametrize("sync_fails", [False, True])
def test_recovery_parent_close_failure_retains_pending_recovery(
    tmp_path, monkeypatch, linux_staging, sync_fails,
):
    """A close error must remain a recovery failure and preserve the first error."""
    declaration = _fixture(tmp_path)
    journal = _write_pending_publication_journal(tmp_path, declaration, "attempted")
    config = _acquisition_config(tmp_path)
    manifest = tmp_path / "prepared.json"
    artifact = tmp_path / "files/diffusion.safetensors"
    before = artifact.read_bytes()
    real_sync, real_close = acquisition._sync_published_file, os.close
    parents, closed = set(), []
    primary = candidate.CandidateAcquisitionError("injected recovery verification failure")

    def sync(parent_fd, *args, **kwargs):
        parents.add(parent_fd)
        if sync_fails:
            raise primary
        return real_sync(parent_fd, *args, **kwargs)

    def close(descriptor):
        real_close(descriptor)
        if descriptor in parents:
            parents.remove(descriptor)
            closed.append(descriptor)
            raise OSError(errno.EIO, "recovery parent close reported failure")

    def no_download(*args, **kwargs):
        raise AssertionError("recovery must not download an existing pinned artifact")

    def prepare(acquire=True):
        return candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=acquire, acquisition_config=config if acquire else None,
            trusted_evidence=_trusted_evidence(),
        )

    monkeypatch.setattr(acquisition, "_open_remote", no_download)
    with monkeypatch.context() as patch:
        patch.setattr(acquisition, "_sync_published_file", sync)
        patch.setattr(os, "close", close)
        with pytest.raises(candidate.CandidateAcquisitionError):
            prepare()
    assert len(closed) == 1
    with pytest.raises(OSError) as bad_fd:
        os.fstat(closed[0])
    assert bad_fd.value.errno == errno.EBADF
    assert artifact.read_bytes() == before
    assert not manifest.exists()
    pending = _payload(journal)
    assert pending["status"] == "unverified"
    assert pending["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in pending["events"])
    with pytest.raises(candidate.CandidateAcquisitionError, match="authorized publication recovery"):
        prepare(acquire=False)
    assert prepare()["status"] == "ready"
    assert _payload(journal)["events"][-1]["code"] == "recovered_verified_publication"


def test_published_descriptor_close_preserves_verification_error(
    tmp_path, monkeypatch, linux_staging,
):
    """Closing a published reader must not hide the failed pinned verification."""
    declaration = candidate.parse_candidate(_fixture(tmp_path))
    pin = declaration.artifact_targets()["component:diffusion"]
    artifact = tmp_path / "files" / pin.path
    artifact.write_bytes(b"x" * pin.size_bytes)
    parent_fd = os.open(artifact.parent, os.O_RDONLY | os.O_DIRECTORY)
    facts = artifact.stat()
    real_close = os.close
    closed = []

    def close(descriptor):
        real_close(descriptor)
        closed.append(descriptor)
        raise OSError(errno.EIO, "reader close reported failure")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "close", close)
            with pytest.raises(candidate.CandidateAcquisitionError, match="SHA-256") as failure:
                acquisition._sync_published_file(
                    parent_fd, artifact.name, pin,
                    expected_identity=(facts.st_dev, facts.st_ino),
                )
        assert len(closed) == 1
        with pytest.raises(OSError) as bad_fd:
            os.fstat(closed[0])
        assert bad_fd.value.errno == errno.EBADF
        assert any("cleanup failed" in note for note in failure.value.__notes__)
    finally:
        real_close(parent_fd)


@pytest.mark.parametrize("phase", ["metadata", "close"])
def test_preflight_io_failure_is_structured_before_outputs(tmp_path, monkeypatch, linux_staging, phase):
    declaration = _fixture(tmp_path)
    (tmp_path / "files/diffusion.safetensors").unlink()
    config = _acquisition_config(tmp_path)
    real_fstat, real_close = os.fstat, os.close
    anonymous = []

    def fstat(descriptor):
        facts = real_fstat(descriptor)
        if facts.st_nlink == 0:
            anonymous.append(descriptor)
            if phase == "metadata":
                raise OSError(errno.EIO, "preflight metadata failed")
        return facts

    def close(descriptor):
        real_close(descriptor)
        if phase == "close" and descriptor in anonymous:
            raise OSError(errno.EIO, "preflight close reported failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", fstat)
        patch.setattr(os, "close", close)
        with pytest.raises(candidate.CandidateAcquisitionError):
            candidate.prepare_candidate(
                declaration, manifest_output=tmp_path / "prepared.json",
                journal_output=tmp_path / "journal.json", acquire=True, acquisition_config=config,
            )
    assert anonymous
    for descriptor in set(anonymous):
        with pytest.raises(OSError) as bad_fd:
            real_fstat(descriptor)
        assert bad_fd.value.errno == errno.EBADF
    assert not (tmp_path / "journal.json").exists()
    assert not (tmp_path / "prepared.json").exists()
    assert not (tmp_path / ".journal.json.lock").exists()


@pytest.mark.parametrize("capability", ["procfs-fallback", "missing-procfs", "missing-linkat", "missing-tmpfile"])
def test_descriptor_publication_capabilities(tmp_path, monkeypatch, linux_staging, capability):
    import ctypes
    from types import SimpleNamespace

    real_link = ctypes.CDLL(None, use_errno=True).linkat
    real_link.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    real_link.restype = ctypes.c_int

    class RestrictedLinkAt:
        argtypes = ()
        restype = ctypes.c_int

        def __call__(self, source_fd, source, parent_fd, destination, flags):
            if flags == 0x1000:
                ctypes.set_errno(errno.EPERM)
                return -1
            if capability == "missing-procfs":
                ctypes.set_errno(errno.ENOENT)
                return -1
            return real_link(source_fd, source, parent_fd, destination, flags)

    if capability == "missing-tmpfile":
        monkeypatch.delattr(os, "O_TMPFILE")
    elif capability == "missing-linkat":
        monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace())
    else:
        monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(linkat=RestrictedLinkAt()))
    parent = tmp_path / "destination"
    parent.mkdir()
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if capability != "procfs-fallback":
            with pytest.raises(candidate.CandidateAcquisitionError, match="unsupported"):
                acquisition._open_staging_file(parent_fd)
            assert list(parent.iterdir()) == []
        else:
            stage = acquisition._open_staging_file(parent_fd)
            try:
                os.write(stage.descriptor, b"descriptor fallback")
                os.fsync(stage.descriptor)
                acquisition._descriptor_bound_publish(stage.descriptor, parent_fd, "final")
                assert os.stat("final", dir_fd=parent_fd).st_ino == os.fstat(stage.descriptor).st_ino
                assert (parent / "final").read_bytes() == b"descriptor fallback"
            finally:
                os.close(stage.descriptor)
    finally:
        os.close(parent_fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux crash cleanup requires APEX")
@pytest.mark.parametrize("publish", [False, True])
def test_native_process_exit_reclaims_unpublished_inode(tmp_path, publish):
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
from media_generation import _candidate_acquisition as acquisition
parent = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
stage = acquisition._open_staging_file(parent)
os.write(stage.descriptor, b'crash-safe bytes')
os.fsync(stage.descriptor)
if sys.argv[3] == 'publish':
    acquisition._descriptor_bound_publish(stage.descriptor, parent, 'final')
    os.fsync(parent)
os._exit(19)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[1] / "src"),
         str(tmp_path), "publish" if publish else "unpublished"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 19, result.stderr
    assert set(p.name for p in tmp_path.iterdir()) == ({"final"} if publish else set())
    if publish:
        assert (tmp_path / "final").read_bytes() == b"crash-safe bytes"
