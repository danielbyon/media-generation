"""Focused tests for the local text and vision inference service."""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from PIL import Image
import pytest

import media_generation.inference_service as inference_service_module
from media_generation.admission import (
    build_admission_profile,
    parse_admission_policy,
    parse_workload_demand,
)
from media_generation.inference import InferenceKind
from media_generation.llama_cpp import (
    LlamaCppComponent,
    LlamaCppConfiguration,
    LlamaCppRequest,
    prepare_invocation,
    private_workspace,
)
from media_generation.inference_service import (
    InferenceService,
    _PreflightBlocked,
    _timestamp,
    _utc_now,
)
from media_generation.privacy import PrivacyComplianceStatus
from media_generation.store import InferenceRequestPeek
from test_resource_admission import GIB, inventory_report, workload_demand
from test_llama_cpp import _qualification
from test_image_ingest import _png


def _configuration(tmp_path: Path, profile) -> LlamaCppConfiguration:
    executable = tmp_path / "mtmd-cli"
    model = tmp_path / "model.gguf"
    projector = tmp_path / "projector.gguf"
    executable.write_bytes(b"fake runtime executable")
    executable.chmod(0o700)
    model.write_bytes(b"fake checkpoint")
    projector.write_bytes(b"fake vision projector")
    fingerprint = profile.environment_fingerprint.removeprefix("sha256:")
    return LlamaCppConfiguration(
        executable_path=executable,
        model_component=LlamaCppComponent(
            role="checkpoint",
            path=model,
            sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        ),
        projector_component=LlamaCppComponent(
            role="vision_encoder",
            path=projector,
            sha256=hashlib.sha256(projector.read_bytes()).hexdigest(),
        ),
        max_tokens=32,
        hardware_fingerprint_sha256=fingerprint,
    )


def _admission(kind: InferenceKind, *, context_tokens: int = 4096):
    profile = build_admission_profile(
        inventory_report(),
        parse_admission_policy(
            {
                "schema": "media-generation.admission-policy",
                "schema_version": 1,
                "pool_headroom_bytes": {"system_ram": 0},
            }
        ),
    )
    demand_payload = workload_demand(
        kind=kind.value,
        system_ram_bytes=64 * GIB,
        accelerator_memory_bytes=0,
    )
    demand_payload["context"] = {"status": "known", "tokens": context_tokens}
    demand = parse_workload_demand(demand_payload)
    return profile, demand


def test_management_operations_do_not_require_a_runtime_configuration(
    tmp_path: Path,
) -> None:
    service = InferenceService(
        database_path=tmp_path / "management.sqlite3",
        output_directory=tmp_path / "management-output",
    )

    assert service.recover() == {"status": "complete", "resource_state": "available"}
    assert service.cancel("missing-job") == {
        "job_id": "missing-job",
        "status": "not_found",
    }
    assert service.provenance("missing-job") == {
        "job_id": "missing-job",
        "status": "not_found",
    }
    assert service.enqueue(
        "without-runtime",
        LlamaCppRequest(kind=InferenceKind.TEXT, prompt="A short source."),
    ) == {
        "status": "preflight_blocked",
        "reason": "runtime_configuration_missing",
    }


def test_constructor_rejects_unsupported_single_workload_demand_kind(
    tmp_path: Path,
) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    invalid_demand = replace(demand, kind="scoring")

    with pytest.raises(ValueError, match="workload_demand.kind must be text or vision"):
        InferenceService(
            database_path=tmp_path / "unsupported-demand.sqlite3",
            output_directory=tmp_path / "unsupported-demand-output",
            admission_profile=profile,
            workload_demand=invalid_demand,
        )


def test_enqueue_rejects_deadline_above_reviewed_ceiling(tmp_path: Path) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    service = InferenceService(
        database_path=tmp_path / "deadline.sqlite3",
        output_directory=tmp_path / "deadline-output",
        configuration=_configuration(tmp_path, profile),
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )

    result = service.enqueue(
        "deadline-above-ceiling",
        LlamaCppRequest(InferenceKind.TEXT, "A short source."),
        deadline_seconds=301,
    )

    assert result == {"status": "preflight_blocked", "reason": "deadline_invalid"}


def test_enqueue_blocks_demand_with_context_different_from_runtime(
    tmp_path: Path,
) -> None:
    profile, demand = _admission(InferenceKind.TEXT, context_tokens=2048)
    service = InferenceService(
        database_path=tmp_path / "context-demand.sqlite3",
        output_directory=tmp_path / "context-demand-output",
        configuration=_configuration(tmp_path, profile),
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )

    request = LlamaCppRequest(InferenceKind.TEXT, "A short source.")
    result = service.enqueue("context-demand-mismatch", request)

    assert result["status"] == "blocked"
    assert result["reason"] == "workload_context_mismatch"
    repeated = service.enqueue("context-demand-mismatch", request)
    assert repeated["job_id"] == result["job_id"]
    assert repeated["created"] is False
    assert repeated["status"] == "blocked"
    assert repeated["reason"] == "workload_context_mismatch"


def test_missing_apex_evidence_blocks_before_claim(tmp_path: Path) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=tmp_path / "output",
        configuration=_configuration(tmp_path, profile),
        runtime_qualification=None,
        candidate_declaration_path=None,
        candidate_trusted_evidence=(),
        admission_profile=profile,
        workload_demand=demand,
    )

    queued = service.enqueue(
        "missing-qualification",
        LlamaCppRequest(kind=InferenceKind.TEXT, prompt="A short source."),
    )
    result = service.work()

    assert result["status"] == "preflight_blocked"
    assert result["reason"] == "apex_evidence_missing"
    provenance = service.provenance(str(queued["job_id"]))
    assert provenance["attempts"] == []
    assert provenance["execution"]["resource_state"] == "available"


def test_vision_enqueue_persists_image_identity_and_redacts_public_provenance(
    tmp_path: Path,
) -> None:
    profile, demand = _admission(InferenceKind.VISION)
    configuration = _configuration(tmp_path, profile)
    image_path = tmp_path / "private-image.png"
    with Image.new("RGB", (3, 2), "blue") as image:
        image.save(image_path, format="PNG")
    prompt = "Describe this private test image."
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=tmp_path / "output",
        configuration=configuration,
        admission_profile=profile,
        workload_demand={InferenceKind.VISION: demand},
    )

    queued = service.enqueue(
        "vision-image",
        LlamaCppRequest(
            kind=InferenceKind.VISION,
            prompt=prompt,
            image_path=image_path,
        ),
    )

    assert queued["status"] == "blocked"
    assert queued["reason"] == "apex_evidence_missing"
    with service._store._connection() as connection:
        row = connection.execute(
            "SELECT request_json, request_digest FROM inference_requests WHERE job_id = ?",
            (queued["job_id"],),
        ).fetchone()
    request_json = str(row["request_json"])
    request = json.loads(request_json)
    image_identity = request["image"]
    assert request_json == json.dumps(
        request, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    assert image_identity["identity"] == str(image_path)
    assert image_identity["sha256"] == hashlib.sha256(image_path.read_bytes()).hexdigest()
    assert image_identity["size_bytes"] == image_path.stat().st_size
    request_identity = {
        key: value for key, value in request.items() if key != "deadline_at"
    }
    identity_json = json.dumps(
        request_identity,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert row["request_digest"] == hashlib.sha256(identity_json.encode()).hexdigest()

    public = json.dumps(service.provenance(str(queued["job_id"])))
    assert str(image_path) not in public
    assert str(configuration.executable_path) not in public
    assert str(configuration.model_component.path) not in public
    assert str(configuration.projector_component.path) not in public
    assert prompt not in public
    assert public.count("apex_evidence_missing") >= 1


def test_vision_enqueue_rejects_image_above_inference_pixel_limit(
    tmp_path: Path,
) -> None:
    profile, demand = _admission(InferenceKind.VISION)
    image_path = tmp_path / "above-inference-limit.png"
    width, height = 4097, 2048
    scanline = b"\x00" + bytes(width * 3)
    image_path.write_bytes(
        _png(width, height, zlib.compress(scanline * height))
    )
    service = InferenceService(
        database_path=tmp_path / "inference-image-limit.sqlite3",
        output_directory=tmp_path / "inference-image-limit-output",
        configuration=_configuration(tmp_path, profile),
        admission_profile=profile,
        workload_demand={InferenceKind.VISION: demand},
    )

    result = service.enqueue(
        "oversized-inference-image",
        LlamaCppRequest(
            InferenceKind.VISION,
            "Describe the image.",
            image_path=image_path,
        ),
    )

    assert result == {
        "status": "preflight_blocked",
        "reason": "request_validation_failed",
    }


def _preflight_inputs(service: InferenceService, request: LlamaCppRequest):
    deadline_at = _timestamp(_utc_now() + timedelta(minutes=5))
    document = service._request_document(request, deadline_at)
    request_json = json.dumps(
        document, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    peek = InferenceRequestPeek(
        job_id="test-job", request_json=request_json, deadline_at=deadline_at
    )
    request_identity = {
        key: value for key, value in document.items() if key != "deadline_at"
    }
    digest = hashlib.sha256(
        json.dumps(
            request_identity,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return document, peek, digest


def test_preflight_requires_qualification_for_the_request_kind(tmp_path: Path) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    profile = replace(profile, apex_qualification="ready", apex_evidence=True)
    configuration = _configuration(tmp_path, profile)
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=tmp_path / "output",
        configuration=configuration,
        runtime_qualification={},
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )
    request = LlamaCppRequest(InferenceKind.TEXT, "A qualified source.")
    document, peek, digest = _preflight_inputs(service, request)

    with private_workspace(service.output_directory) as workspace:
        with pytest.raises(_PreflightBlocked, match="runtime_qualification_missing"):
            service._preflight(
                peek, digest, document, request, workspace, repair=None
            )


def test_preflight_rejects_missing_candidate_before_claim(tmp_path: Path) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    profile = replace(profile, apex_qualification="ready", apex_evidence=True)
    configuration = _configuration(tmp_path, profile)
    output_directory = tmp_path / "output"
    output_directory.mkdir()
    request = LlamaCppRequest(InferenceKind.TEXT, "A qualified source.")
    with private_workspace(output_directory) as workspace:
        prepared = prepare_invocation(configuration, request, workspace=workspace)
        qualification = _qualification(configuration, prepared)
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=output_directory,
        configuration=configuration,
        runtime_qualification={InferenceKind.TEXT: qualification},
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )
    document, peek, digest = _preflight_inputs(service, request)

    with private_workspace(output_directory) as workspace:
        with pytest.raises(_PreflightBlocked, match="candidate_missing"):
            service._preflight(
                peek, digest, document, request, workspace, repair=None
            )


def test_preflight_rejects_persisted_demand_with_wrong_context(tmp_path: Path) -> None:
    profile, demand = _admission(InferenceKind.TEXT, context_tokens=2048)
    profile = replace(profile, apex_qualification="ready", apex_evidence=True)
    configuration = _configuration(tmp_path, profile)
    output_directory = tmp_path / "output"
    output_directory.mkdir()
    request = LlamaCppRequest(InferenceKind.TEXT, "A qualified source.")
    with private_workspace(output_directory) as workspace:
        prepared = prepare_invocation(configuration, request, workspace=workspace)
        qualification = _qualification(configuration, prepared)
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=output_directory,
        configuration=configuration,
        runtime_qualification={InferenceKind.TEXT: qualification},
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )
    document, peek, digest = _preflight_inputs(service, request)

    with private_workspace(output_directory) as workspace:
        with pytest.raises(_PreflightBlocked, match="workload_context_mismatch"):
            service._preflight(
                peek, digest, document, request, workspace, repair=None
            )


def test_preflight_blocks_nonpassing_application_privacy(tmp_path: Path, monkeypatch) -> None:
    profile, demand = _admission(InferenceKind.TEXT)
    profile = replace(profile, apex_qualification="ready", apex_evidence=True)
    configuration = _configuration(tmp_path, profile)
    output_directory = tmp_path / "output"
    output_directory.mkdir()
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_text("{}", encoding="utf-8")
    request = LlamaCppRequest(InferenceKind.TEXT, "A qualified source.")
    with private_workspace(output_directory) as workspace:
        prepared = prepare_invocation(configuration, request, workspace=workspace)
        qualification = _qualification(configuration, prepared)
    service = InferenceService(
        database_path=tmp_path / "inference.sqlite3",
        output_directory=output_directory,
        configuration=configuration,
        runtime_qualification={InferenceKind.TEXT: qualification},
        candidate_declaration_path=candidate_path,
        admission_profile=profile,
        workload_demand={InferenceKind.TEXT: demand},
    )
    monkeypatch.setattr(inference_service_module, "parse_candidate", lambda _: object())
    monkeypatch.setattr(
        inference_service_module,
        "verify_candidate",
        lambda *args, **kwargs: {
            "status": "ready",
            "evidence": {"independent_evidence_authority": "ready"},
        },
    )
    monkeypatch.setattr(service, "_candidate_matches_configuration", lambda _: True)
    monkeypatch.setattr(
        service,
        "_privacy_result",
        lambda _: SimpleNamespace(status=PrivacyComplianceStatus.FAIL),
    )
    document, peek, digest = _preflight_inputs(service, request)

    with private_workspace(output_directory) as workspace:
        with pytest.raises(_PreflightBlocked, match="privacy_compliance_not_pass"):
            service._preflight(
                peek, digest, document, request, workspace, repair=None
            )
