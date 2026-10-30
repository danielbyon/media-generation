"""Directory-entry races must never turn displaced valid bytes into readiness."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from media_generation import candidate
from test_candidate_preparation import (
    _Response,
    _acquisition_config,
    _assert_descriptor_closed,
    _fixture,
    _items,
    _payload,
    _rewrite,
    _trusted_evidence,
    _write_pending_publication_journal,
    linux_acquisition_on_darwin,
)


def _replace_during_named_read(
    monkeypatch: pytest.MonkeyPatch,
    target: Path,
    replacement: Path,
    *,
    read_number: int,
    boundary: str,
    displaced_parent: Path | None = None,
) -> list[int]:
    """Replace an entry or its parent at an open/fstat boundary without sleeps."""
    real_open, real_fstat = os.open, os.fstat
    opened = 0
    selected_fd: int | None = None
    metadata_reads = 0
    descriptors: list[int] = []

    def replace_entry() -> None:
        if displaced_parent is None:
            replacement.replace(target)
        else:
            target.parent.rename(displaced_parent)
            replacement.rename(target.parent)

    def interposed_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal opened, selected_fd
        selected = False
        if Path(os.fsdecode(path)).name == target.name:
            opened += 1
            selected = opened == read_number
        if selected and boundary == "before_open":
            replace_entry()
        descriptor = real_open(path, flags, *args, **kwargs)
        if selected:
            selected_fd = descriptor
            descriptors.append(descriptor)
            if kwargs.get("dir_fd") is not None:
                descriptors.append(kwargs["dir_fd"])
            if boundary == "after_open":
                replace_entry()
        return descriptor

    def interposed_fstat(descriptor: int) -> os.stat_result:
        nonlocal metadata_reads
        facts = real_fstat(descriptor)
        if descriptor == selected_fd:
            metadata_reads += 1
            if metadata_reads == 2 and boundary == "after_final_fstat":
                replace_entry()
        return facts

    monkeypatch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, interposed_open})
    monkeypatch.setattr(os, "open", interposed_open)
    monkeypatch.setattr(os, "fstat", interposed_fstat)
    return descriptors


@pytest.mark.parametrize("operation", ("inspect", "verify", "prepare"))
@pytest.mark.parametrize("boundary", ("after_open", "after_final_fstat"))
def test_offline_evaluation_rejects_displaced_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    boundary: str,
) -> None:
    """Inspect, verify, and prepare's final evaluation must check the filename."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    corrupt_bytes = b"X" * artifact.stat().st_size
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(corrupt_bytes)
    descriptors = _replace_during_named_read(
        monkeypatch,
        artifact,
        replacement,
        read_number=2 if operation == "prepare" else 1,
        boundary=boundary,
    )

    if operation == "prepare":
        report = candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            trusted_evidence=_trusted_evidence(),
        )
        assert _payload(tmp_path / "prepared.json")["status"] == "corrupt"
        assert _payload(tmp_path / "journal.json")["status"] == "corrupt"
    else:
        evaluate = getattr(candidate, f"{operation}_candidate")
        report = evaluate(declaration, trusted_evidence=_trusted_evidence())

    assert artifact.read_bytes() == corrupt_bytes
    assert not replacement.exists()
    assert report["status"] == "corrupt"
    assert _items(report)["component:diffusion"]["code"] == "file_changed_during_hash"
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)


@pytest.mark.parametrize("operation", ("inspect", "verify", "prepare"))
@pytest.mark.parametrize("boundary", ("after_open", "after_final_fstat"))
def test_offline_evaluation_rejects_displaced_artifact_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    boundary: str,
) -> None:
    """A retained valid inode cannot qualify a replaced declared directory."""
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    original_bytes = artifact.read_bytes()
    corrupt_bytes = b"X" * len(original_bytes)
    replacement = tmp_path / "replacement-files"
    shutil.copytree(artifact.parent, replacement)
    (replacement / artifact.name).write_bytes(corrupt_bytes)
    displaced = tmp_path / "displaced-files"
    descriptors = _replace_during_named_read(
        monkeypatch,
        artifact,
        replacement,
        read_number=2 if operation == "prepare" else 1,
        boundary=boundary,
        displaced_parent=displaced,
    )

    if operation == "prepare":
        report = candidate.prepare_candidate(
            declaration,
            manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json",
            trusted_evidence=_trusted_evidence(),
        )
        assert _payload(tmp_path / "prepared.json")["status"] == "corrupt"
        assert _payload(tmp_path / "journal.json")["status"] == "corrupt"
    else:
        evaluate = getattr(candidate, f"{operation}_candidate")
        report = evaluate(declaration, trusted_evidence=_trusted_evidence())

    assert artifact.read_bytes() == corrupt_bytes
    assert (displaced / artifact.name).read_bytes() == original_bytes
    assert not replacement.exists()
    assert report["status"] == "corrupt"
    assert _items(report)["component:diffusion"]["code"] == "file_changed_during_hash"
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)


@pytest.mark.parametrize("operation", ("inspect", "verify", "prepare"))
@pytest.mark.parametrize("replaced_directory", ("root", "ancestor"))
def test_offline_evaluation_rejects_ancestor_replaced_during_final_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    replaced_directory: str,
) -> None:
    """A final traversal must recheck every directory it already passed through."""
    declaration = _fixture(tmp_path)
    root = tmp_path / "files"
    artifact = root / "ancestor" / "leaf" / "diffusion.safetensors"
    artifact.parent.mkdir(parents=True)
    (root / artifact.name).rename(artifact)
    payload = _payload(declaration)
    component = next(item for item in payload["components"] if item["id"] == "diffusion")
    component["artifact"]["path"] = artifact.relative_to(root).as_posix()
    _rewrite(declaration, payload)
    assert candidate.verify_candidate(
        declaration, trusted_evidence=_trusted_evidence(),
    )["status"] == "ready"

    ancestor = root if replaced_directory == "root" else artifact.parent.parent
    replacement = tmp_path / "replacement-ancestor"
    displaced = tmp_path / "displaced-ancestor"
    shutil.copytree(ancestor, replacement)
    original_bytes = artifact.read_bytes()
    corrupt_bytes = b"X" * len(original_bytes)
    (replacement / artifact.relative_to(ancestor)).write_bytes(corrupt_bytes)
    real_open = os.open
    traversals = 0
    displaced_descriptors: list[int] = []

    def replace_after_leaf_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal traversals
        descriptor = real_open(path, flags, *args, **kwargs)
        if os.fsdecode(path) == "leaf" and kwargs.get("dir_fd") is not None:
            traversals += 1
            if traversals == (4 if operation == "prepare" else 2):
                ancestor.rename(displaced)
                replacement.rename(ancestor)
                displaced_descriptors.extend((kwargs["dir_fd"], descriptor))
        return descriptor

    with monkeypatch.context() as injection:
        injection.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_after_leaf_open})
        injection.setattr(os, "open", replace_after_leaf_open)
        if operation == "prepare":
            report = candidate.prepare_candidate(
                declaration,
                manifest_output=tmp_path / "prepared.json",
                journal_output=tmp_path / "journal.json",
                trusted_evidence=_trusted_evidence(),
            )
            assert _payload(tmp_path / "prepared.json")["status"] == "corrupt"
            assert _payload(tmp_path / "journal.json")["status"] == "corrupt"
        else:
            report = getattr(candidate, f"{operation}_candidate")(
                declaration, trusted_evidence=_trusted_evidence(),
            )

    assert displaced_descriptors
    assert artifact.read_bytes() == corrupt_bytes
    assert (displaced / artifact.relative_to(ancestor)).read_bytes() == original_bytes
    assert report["status"] == "corrupt"
    assert _items(report)["component:diffusion"]["code"] == "file_changed_during_hash"
    for descriptor in displaced_descriptors:
        _assert_descriptor_closed(descriptor)


@pytest.mark.parametrize(
    "boundary",
    (
        "before_open",
        "after_open",
        "after_final_fstat",
        "after_validation",
        "after_reload",
        "during_final_evaluation",
    ),
)
def test_final_journal_reload_rejects_pending_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    """A pending replacement remains authoritative and prevents a ready manifest."""
    declaration = _fixture(tmp_path)
    journal = _write_pending_publication_journal(tmp_path, declaration, "attempted")
    replacement = tmp_path / "pending-journal.json"
    journal.replace(replacement)
    pending_bytes = replacement.read_bytes()
    manifest = tmp_path / "prepared.json"
    candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )
    acquisition = candidate._acquisition
    descriptors: list[int] = []

    if boundary in {"before_open", "after_open", "after_final_fstat"}:
        descriptors = _replace_during_named_read(
            monkeypatch,
            journal,
            replacement,
            read_number=2,
            boundary=boundary,
        )
    else:
        hook = {
            "after_validation": "_validate_journal_events",
            "after_reload": "_load_journal",
            "during_final_evaluation": "evaluate_candidate",
        }[boundary]
        real_operation = getattr(acquisition, hook)
        calls = 0

        def replace_after_operation(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            result = real_operation(*args, **kwargs)
            calls += 1
            if calls == 2:
                replacement.replace(journal)
            return result

        monkeypatch.setattr(acquisition, hook, replace_after_operation)

    with pytest.raises(candidate.CandidateOutputError, match="journal.*changed"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )

    assert not replacement.exists()
    assert journal.read_bytes() == pending_bytes
    pending = _payload(manifest)
    assert pending["status"] == "unverified"
    assert pending["verification_id"] is None
    assert pending["verification"] == {"items": [], "observations": {}}
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)

    # A later offline operation must honor the replacement's pending recovery.
    with pytest.raises(candidate.CandidateAcquisitionError, match="recovery"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    assert journal.read_bytes() == pending_bytes
    assert _payload(manifest)["status"] == "unverified"


@pytest.mark.parametrize("replaced_directory", ("parent", "ancestor"))
def test_final_journal_guard_rechecks_parent_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replaced_directory: str,
) -> None:
    """The post-publication guard must reject a parent displaced after open."""
    declaration = _fixture(tmp_path)
    parent = tmp_path / "journal-state" / "leaf"
    parent.mkdir(parents=True)
    journal = parent / "journal.json"
    manifest = tmp_path / "prepared.json"
    ancestor = parent if replaced_directory == "parent" else parent.parent
    replacement = tmp_path / "pending-state"
    replacement_parent = replacement / parent.relative_to(ancestor)
    replacement_parent.mkdir(parents=True)
    pending = _write_pending_publication_journal(replacement_parent, declaration, "attempted")
    pending_bytes = pending.read_bytes()
    displaced = tmp_path / "displaced-state"
    acquisition = candidate._acquisition
    real_write, real_open = acquisition._write_json_atomic, os.open
    descriptors: list[int] = []

    def replace_after_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        if Path(os.fsdecode(path)) == parent and not descriptors:
            assert _payload(manifest)["status"] == "ready"
            descriptors.append(descriptor)
            ancestor.rename(displaced)
            replacement.rename(ancestor)
        return descriptor

    def interpose_guard(*args: Any, **kwargs: Any) -> None:
        guard = kwargs.get("publication_guard")
        if guard is not None:
            def guarded() -> None:
                with monkeypatch.context() as injection:
                    injection.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_after_open})
                    injection.setattr(os, "open", replace_after_open)
                    guard()
            kwargs["publication_guard"] = guarded
        real_write(*args, **kwargs)

    monkeypatch.setattr(acquisition, "_write_json_atomic", interpose_guard)
    with pytest.raises(candidate.CandidateOutputError):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )

    assert descriptors
    assert journal.read_bytes() == pending_bytes
    assert manifest.read_bytes() == b""
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)
    with pytest.raises(candidate.CandidateAcquisitionError, match="recovery"):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    assert journal.read_bytes() == pending_bytes
    assert _payload(manifest)["status"] == "unverified"


@pytest.mark.usefixtures("linux_acquisition_on_darwin")
@pytest.mark.parametrize("publication", ("new", "recovery"))
@pytest.mark.parametrize("replaced_directory", ("parent", "ancestor", "root"))
def test_durability_rechecks_directory_after_metadata_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication: str,
    replaced_directory: str,
) -> None:
    """Pinned replacement bytes do not inherit the displaced inode's fsync."""
    declaration = _fixture(tmp_path)
    root = tmp_path / "files"
    artifact = root / "ancestor" / "leaf" / "diffusion.safetensors"
    artifact.parent.mkdir(parents=True)
    (root / artifact.name).rename(artifact)
    payload = _payload(declaration)
    component = next(item for item in payload["components"] if item["id"] == "diffusion")
    component["artifact"]["path"] = artifact.relative_to(root).as_posix()
    _rewrite(declaration, payload)
    body = artifact.read_bytes()
    ancestor = {"parent": artifact.parent, "ancestor": artifact.parent.parent, "root": root}[replaced_directory]
    replacement = tmp_path / "replacement-directory"
    shutil.copytree(ancestor, replacement)
    displaced = tmp_path / "synchronized-directory"
    journal = tmp_path / "journal.json"
    manifest = tmp_path / "prepared.json"
    config = _acquisition_config(tmp_path)
    if publication == "new":
        artifact.unlink()
    else:
        _write_pending_publication_journal(tmp_path, declaration, "attempted")
    acquisition = candidate._acquisition
    monkeypatch.setattr(acquisition, "_open_remote", lambda *a, **kw: _Response(
        200, headers={"Content-Length": str(len(body))}, body=body,
    ))
    real_verify, real_observe, real_open = (
        acquisition._verify_synchronized_destination, acquisition._observe_target, os.open,
    )
    metadata_pending = False
    descriptors: list[int] = []

    def observe_before_metadata(*args: Any, **kwargs: Any) -> Any:
        nonlocal metadata_pending
        observed = real_observe(*args, **kwargs)
        metadata_pending = True
        return observed

    def replace_after_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        if metadata_pending and os.fsdecode(path) == "leaf" and not descriptors:
            descriptors.append(descriptor)
            ancestor.rename(displaced)
            replacement.rename(ancestor)
        return descriptor

    def interpose_metadata(*args: Any, **kwargs: Any) -> None:
        with monkeypatch.context() as injection:
            injection.setattr(acquisition, "_observe_target", observe_before_metadata)
            injection.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, replace_after_open})
            injection.setattr(os, "open", replace_after_open)
            real_verify(*args, **kwargs)

    monkeypatch.setattr(acquisition, "_verify_synchronized_destination", interpose_metadata)
    with pytest.raises(candidate.CandidateAcquisitionError):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
        )

    assert descriptors
    saved = displaced / artifact.relative_to(ancestor)
    assert artifact.read_bytes() == saved.read_bytes() == body
    assert artifact.stat().st_ino != saved.stat().st_ino
    assert not manifest.exists()
    result = _payload(journal)
    assert result["status"] == "unverified"
    assert result["events"][-1]["code"] == "publication_sync_failed"
    assert not any(event["state"] == "succeeded" for event in result["events"])
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)
    with pytest.raises(candidate.CandidateAcquisitionError, match="recovery"):
        candidate.prepare_candidate(
            declaration, manifest_output=manifest, journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )


@pytest.mark.parametrize(
    "boundary",
    (
        "before_open",
        "after_open",
        "after_final_fstat",
        "after_validation",
        "after_reload",
        "during_final_evaluation",
    ),
)
def test_final_journal_reload_rejects_pending_parent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    """A displaced journal cannot hide pending recovery at the declared path."""
    declaration = _fixture(tmp_path)
    parent = tmp_path / "journal-state"
    parent.mkdir()
    replacement = tmp_path / "replacement-journal-state"
    replacement.mkdir()
    pending = _write_pending_publication_journal(replacement, declaration, "attempted")
    pending_bytes = pending.read_bytes()
    journal = parent / "journal.json"
    displaced = tmp_path / "displaced-journal-state"
    manifest = tmp_path / "prepared.json"
    assert candidate.prepare_candidate(
        declaration,
        manifest_output=manifest,
        journal_output=journal,
        trusted_evidence=_trusted_evidence(),
    )["status"] == "ready"
    ready_bytes = journal.read_bytes()
    acquisition = candidate._acquisition
    descriptors: list[int] = []

    with monkeypatch.context() as injection:
        if boundary in {"before_open", "after_open", "after_final_fstat"}:
            descriptors = _replace_during_named_read(
                injection,
                journal,
                replacement,
                read_number=2,
                boundary=boundary,
                displaced_parent=displaced,
            )
        else:
            hook = {
                "after_validation": "_validate_journal_events",
                "after_reload": "_load_journal",
                "during_final_evaluation": "evaluate_candidate",
            }[boundary]
            real_operation = getattr(acquisition, hook)
            calls = 0

            def replace_after_operation(*args: Any, **kwargs: Any) -> Any:
                nonlocal calls
                result = real_operation(*args, **kwargs)
                calls += 1
                if calls == 2:
                    parent.rename(displaced)
                    replacement.rename(parent)
                return result

            injection.setattr(acquisition, hook, replace_after_operation)

        with pytest.raises(candidate.CandidateOutputError, match="parent.*changed"):
            candidate.prepare_candidate(
                declaration,
                manifest_output=manifest,
                journal_output=journal,
                trusted_evidence=_trusted_evidence(),
            )

    assert not replacement.exists()
    assert journal.read_bytes() == pending_bytes
    assert (displaced / journal.name).read_bytes() == ready_bytes
    invalidated = _payload(manifest)
    assert invalidated["status"] == "unverified"
    assert invalidated["verification_id"] is None
    assert invalidated["verification"] == {"items": [], "observations": {}}
    for descriptor in descriptors:
        _assert_descriptor_closed(descriptor)

    with pytest.raises(candidate.CandidateAcquisitionError, match="recovery"):
        candidate.prepare_candidate(
            declaration,
            manifest_output=manifest,
            journal_output=journal,
            trusted_evidence=_trusted_evidence(),
        )
    assert journal.read_bytes() == pending_bytes
    assert _payload(manifest)["status"] == "unverified"
