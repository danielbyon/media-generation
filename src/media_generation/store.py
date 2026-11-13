"""SQLite persistence for immutable requests and durable execution records."""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .admission import is_lightweight_cpu_adapter_id
from .backend_provenance import (
    COMFYUI_RESOLVED_BACKEND_KIND,
    EXECUTION_STATES,
    COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS,
    RESOLVED_RECORD_SCHEMA_VERSION,
    canonical_json as backend_canonical_json,
    digest as backend_digest,
    observation_proves_reaped_child,
    validate_launch_record,
    validate_observed_record,
    validate_resolved_record,
    serialize_resolved_record,
    configuration_requires_process_tree_resource_release,
)
from .admission_store import (
    AdmissionInspection,
    AdmissionPersistence,
    PendingAdmission,
)
from .domain import (
    GenerationArtifact,
    ImportedArtifact,
    ArtifactSource,
    GenerationAttempt,
    GenerationJob,
    GenerationRequest,
    GenerationRequestRecord,
    ResolvedReference,
)
from .errors import (
    BackendEvidenceError,
    GenerationError,
    IdempotencyConflictError,
    RecordNotFoundError,
    UnknownReferenceError,
)
from .privacy import COMFYUI_ADAPTER_ID, is_privacy_compliance_record
from .systemd_evidence import SystemdEvidenceLedger
from .systemd_attempts import (
    SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,
    AttemptUnitIdentity,
    CgroupTerminationEvidence,
    identity_digest,
)


def _require_systemd_broker_process() -> None:
    """Keep host termination facts writable only by the privileged broker."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise PermissionError("systemd containment evidence is broker-owned")

_RESOLVED_OUTPUT_DIRECTORY_KEY = "_resolved_output_directory"
_MALFORMED_STORED_PRIVACY_EVIDENCE = "stored privacy-compliance evidence is malformed"
_PRIVACY_CLAIM_EVIDENCE_REQUIRED = (
    "protected execution claim requires exact privacy-compliance evidence"
)
_PRIVACY_CLAIM_CONFIGURATION_REQUIRED = (
    "protected execution claim requires exact adapter-configuration evidence"
)


def _persisted_workflow_approval(value: object) -> Mapping[str, object]:
    """Return the ComfyUI T07 pin persisted with the admitted adapter config."""
    try:
        configuration = json.loads(str(value))
    except (TypeError, ValueError) as error:
        raise BackendEvidenceError(
            "persisted ComfyUI adapter configuration is not valid JSON"
        ) from error
    if (
        not isinstance(configuration, Mapping)
        or configuration.get("backend_kind") != COMFYUI_RESOLVED_BACKEND_KIND
        or not isinstance(configuration.get("workflow_approval"), Mapping)
    ):
        raise BackendEvidenceError(
            "persisted ComfyUI adapter configuration has no workflow approval pin"
        )
    return configuration["workflow_approval"]
_WRITER_EPOCH = 8
_WRITER_EPOCH_FUNCTION = "media_generation_writer_epoch"
_CURRENT_SCHEMA_VERSION = 9
_WRITER_GUARDS = (
    ("generation_requests", "INSERT"),
    ("generation_jobs", "INSERT"),
    ("generation_jobs", "UPDATE"),
    ("generation_attempts", "INSERT"),
    ("generation_attempts", "UPDATE"),
    ("generation_artifacts", "INSERT"),
    ("artifact_edges", "INSERT"),
    ("artifact_publications", "INSERT"),
    ("artifact_publications", "UPDATE"),
    ("artifact_integrity", "INSERT"),
    ("artifact_integrity", "UPDATE"),
    ("execution_admissions", "INSERT"),
    ("execution_admissions", "UPDATE"),
    ("backend_executions", "INSERT"),
    ("backend_executions", "UPDATE"),
    ("execution_containment", "INSERT"),
    ("execution_containment", "UPDATE"),
    ("systemd_output_lifecycle", "INSERT"),
    ("systemd_output_lifecycle", "UPDATE"),
    ("execution_cancellations", "INSERT"),
    ("execution_cancellations", "UPDATE"),
("generation_batches", "INSERT"),
("generation_batches", "UPDATE"),
("generation_batch_slots", "INSERT"),
("generation_batch_slots", "UPDATE"),
)


_EXECUTION_JOBS_DDL = """CREATE TABLE execution_jobs (
    job_id TEXT PRIMARY KEY REFERENCES generation_jobs(job_id),
    status TEXT NOT NULL CHECK (status IN (
        'queued','running','succeeded','failed','canceled','ambiguous')),
    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
    containment_contract TEXT,
    privacy_compliance_json TEXT NOT NULL,
    fence_epoch INTEGER NOT NULL DEFAULT 0 CHECK (fence_epoch >= 0),
    current_attempt_id TEXT REFERENCES generation_attempts(attempt_id),
    retry_eligible INTEGER NOT NULL DEFAULT 0 CHECK (retry_eligible IN (0,1)),
    failure_message TEXT,
    resolved_plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_EXECUTION_ATTEMPTS_DDL = """CREATE TABLE execution_attempts (
    attempt_id TEXT PRIMARY KEY REFERENCES generation_attempts(attempt_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    status TEXT NOT NULL CHECK (status IN (
        'running','succeeded','failed','canceled','ambiguous')),
    owner_id TEXT,
    claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    heartbeat_at TEXT,
    lease_expires_at TEXT,
    process_contained INTEGER
        CHECK (process_contained IS NULL OR process_contained IN (0,1)),
    containment_contract TEXT,
    failure_class TEXT CHECK (failure_class IS NULL OR failure_class IN (
        'retryable','terminal','canceled','ambiguous','crash')),
    termination_proven INTEGER NOT NULL DEFAULT 0
        CHECK (termination_proven IN (0,1)),
    plan_json TEXT,
    completed_at TEXT,
    UNIQUE (job_id, attempt_number)
)"""

_BACKEND_EXECUTIONS_DDL = """CREATE TABLE backend_executions (
    attempt_id TEXT PRIMARY KEY REFERENCES execution_attempts(attempt_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    backend_kind TEXT NOT NULL CHECK (length(backend_kind) BETWEEN 1 AND 64),
    candidate_id TEXT NOT NULL CHECK (
        length(candidate_id) = 71 AND substr(candidate_id, 1, 7) = 'sha256:'),
    resolved_json TEXT NOT NULL,
    resolved_digest TEXT NOT NULL CHECK (length(resolved_digest) = 64),
    resolved_at TEXT NOT NULL,
    launch_json TEXT,
    launch_at TEXT,
    observed_json TEXT,
    observed_at TEXT,
    state TEXT NOT NULL CHECK (state IN ('resolved','launched','observed')),
    CHECK ((state = 'resolved' AND launch_json IS NULL AND launch_at IS NULL
            AND observed_json IS NULL AND observed_at IS NULL)
        OR (state = 'launched' AND launch_json IS NOT NULL AND launch_at IS NOT NULL
            AND observed_json IS NULL AND observed_at IS NULL)
        OR (state = 'observed' AND launch_json IS NOT NULL AND launch_at IS NOT NULL
            AND observed_json IS NOT NULL AND observed_at IS NOT NULL))
)"""

_EXECUTION_CONTAINMENT_DDL = """CREATE TABLE execution_containment (
    attempt_id TEXT PRIMARY KEY REFERENCES execution_attempts(attempt_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    identity_json TEXT NOT NULL,
    identity_digest TEXT NOT NULL CHECK (length(identity_digest) = 64),
    termination_json TEXT,
    termination_at TEXT,
    created_at TEXT NOT NULL,
    CHECK ((termination_json IS NULL AND termination_at IS NULL)
        OR (termination_json IS NOT NULL AND termination_at IS NOT NULL))
)"""

_SYSTEMD_OUTPUT_LIFECYCLE_DDL = """CREATE TABLE systemd_output_lifecycle (
    attempt_id TEXT PRIMARY KEY REFERENCES execution_attempts(attempt_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    identity_digest TEXT NOT NULL CHECK (length(identity_digest) = 64),
    stream_complete INTEGER NOT NULL CHECK (stream_complete IN (0,1)),
    cleanup_state TEXT NOT NULL CHECK (cleanup_state IN ('active','pending','complete')),
    cleanup_validated INTEGER CHECK (cleanup_validated IN (0,1)),
    created_at TEXT NOT NULL,
    cleanup_at TEXT,
    CHECK ((cleanup_state = 'active' AND cleanup_validated IS NULL
                AND cleanup_at IS NULL)
        OR (cleanup_state = 'pending' AND cleanup_validated IS NOT NULL
                AND cleanup_at IS NULL)
        OR (cleanup_state = 'complete' AND cleanup_validated IS NOT NULL
                AND cleanup_at IS NOT NULL))
)"""

_EXECUTION_CANCELLATIONS_DDL = """CREATE TABLE execution_cancellations (
    cancellation_id INTEGER PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    attempt_id TEXT REFERENCES execution_attempts(attempt_id),
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 1),
    state TEXT NOT NULL CHECK (state IN ('requested','acknowledged','too_late')),
    requested_at TEXT,
    acknowledged_at TEXT,
    too_late_at TEXT,
    CHECK ((state = 'requested' AND requested_at IS NOT NULL
                AND acknowledged_at IS NULL AND too_late_at IS NULL)
        OR (state = 'acknowledged' AND acknowledged_at IS NOT NULL
                AND too_late_at IS NULL)
        OR (state = 'too_late' AND too_late_at IS NOT NULL
                AND acknowledged_at IS NULL)),
    UNIQUE (job_id, claim_epoch)
)"""

_EXECUTION_CONTAINMENT_STAGE_TRANSITION_DDL = """CREATE TRIGGER execution_containment_stage_transition
BEFORE UPDATE ON execution_containment
BEGIN
    SELECT RAISE(ABORT, 'containment identity is immutable')
    WHERE NEW.attempt_id IS NOT OLD.attempt_id
       OR NEW.job_id IS NOT OLD.job_id
       OR NEW.identity_json IS NOT OLD.identity_json
       OR NEW.identity_digest IS NOT OLD.identity_digest
       OR NEW.created_at IS NOT OLD.created_at;
    SELECT RAISE(ABORT, 'containment termination evidence is immutable')
    WHERE OLD.termination_json IS NOT NULL
       OR NEW.termination_json IS NULL
       OR NEW.termination_at IS NULL;
END"""

_SYSTEMD_OUTPUT_LIFECYCLE_TRANSITION_DDL = """CREATE TRIGGER systemd_output_lifecycle_transition
BEFORE UPDATE ON systemd_output_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'systemd output lifecycle identity is immutable')
    WHERE NEW.attempt_id IS NOT OLD.attempt_id
       OR NEW.job_id IS NOT OLD.job_id
       OR NEW.identity_digest IS NOT OLD.identity_digest
       OR NEW.created_at IS NOT OLD.created_at;
    SELECT RAISE(ABORT, 'systemd output stream evidence is immutable')
    WHERE OLD.stream_complete = 1 AND NEW.stream_complete != 1;
    SELECT RAISE(ABORT, 'systemd output cleanup transition is invalid')
    WHERE NOT (
        (OLD.cleanup_state = 'active'
            AND NEW.cleanup_state IN ('active','pending','complete'))
        OR (OLD.cleanup_state = 'pending'
            AND NEW.cleanup_state IN ('pending','complete'))
        OR (OLD.cleanup_state = 'complete' AND NEW.cleanup_state = 'complete')
    );
    SELECT RAISE(ABORT, 'systemd cleanup validation is immutable')
    WHERE OLD.cleanup_validated IS NOT NULL
      AND NEW.cleanup_validated IS NOT OLD.cleanup_validated;
    SELECT RAISE(ABORT, 'completed systemd cleanup timestamp is immutable')
    WHERE OLD.cleanup_at IS NOT NULL AND NEW.cleanup_at IS NOT OLD.cleanup_at;
    SELECT RAISE(ABORT, 'systemd cleanup timestamp requires completion')
    WHERE NEW.cleanup_state != 'complete' AND NEW.cleanup_at IS NOT NULL;
    SELECT RAISE(ABORT, 'systemd cleanup completion requires timestamp')
    WHERE NEW.cleanup_state = 'complete' AND NEW.cleanup_at IS NULL;
END"""

_EXECUTION_CONTAINMENT_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER execution_containment_immutable_delete
BEFORE DELETE ON execution_containment
BEGIN
    SELECT RAISE(ABORT, 'containment evidence is immutable');
END"""

_EXECUTION_CANCELLATIONS_TRANSITION_DDL = """CREATE TRIGGER execution_cancellations_transition
BEFORE UPDATE ON execution_cancellations
BEGIN
    SELECT RAISE(ABORT, 'cancellation identity is immutable')
    WHERE NEW.cancellation_id IS NOT OLD.cancellation_id
       OR NEW.job_id IS NOT OLD.job_id
       OR NEW.attempt_id IS NOT OLD.attempt_id
       OR NEW.claim_epoch IS NOT OLD.claim_epoch
       OR NEW.requested_at IS NOT OLD.requested_at;
    SELECT RAISE(ABORT, 'cancellation transition is invalid')
    WHERE NOT (OLD.state = 'requested' AND NEW.state = 'acknowledged'
        AND OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL
        AND NEW.too_late_at IS NULL);
END"""

_EXECUTION_CANCELLATIONS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER execution_cancellations_immutable_delete
BEFORE DELETE ON execution_cancellations
BEGIN
    SELECT RAISE(ABORT, 'cancellation evidence is immutable');
END"""

_BACKEND_EXECUTIONS_STAGE_INSERT_DDL = """CREATE TRIGGER backend_executions_stage_insert
BEFORE INSERT ON backend_executions
WHEN NEW.state != 'resolved' OR NEW.launch_json IS NOT NULL
    OR NEW.launch_at IS NOT NULL OR NEW.observed_json IS NOT NULL
    OR NEW.observed_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'backend execution must start in resolved state');
END"""

_BACKEND_EXECUTIONS_STAGE_TRANSITION_DDL = """CREATE TRIGGER backend_executions_stage_transition
BEFORE UPDATE ON backend_executions
BEGIN
    SELECT RAISE(ABORT, 'backend execution resolved evidence is immutable')
    WHERE NEW.attempt_id IS NOT OLD.attempt_id
       OR NEW.job_id IS NOT OLD.job_id
       OR NEW.backend_kind IS NOT OLD.backend_kind
       OR NEW.candidate_id IS NOT OLD.candidate_id
       OR NEW.resolved_json IS NOT OLD.resolved_json
       OR NEW.resolved_digest IS NOT OLD.resolved_digest
       OR NEW.resolved_at IS NOT OLD.resolved_at;
    SELECT RAISE(ABORT, 'backend execution stage transition is invalid')
    WHERE NOT ((OLD.state = 'resolved' AND NEW.state = 'launched'
            AND NEW.launch_json IS NOT NULL AND NEW.launch_at IS NOT NULL
            AND NEW.observed_json IS NULL AND NEW.observed_at IS NULL)
        OR (OLD.state = 'launched' AND NEW.state = 'observed'
            AND NEW.launch_json IS OLD.launch_json
            AND NEW.launch_at IS OLD.launch_at
            AND NEW.observed_json IS NOT NULL
            AND NEW.observed_at IS NOT NULL));
END"""

_BACKEND_EXECUTIONS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER backend_executions_immutable_delete
BEFORE DELETE ON backend_executions
BEGIN
    SELECT RAISE(ABORT, 'backend execution evidence is immutable');
END"""

_EXECUTION_RESOURCE_DDL = """CREATE TABLE execution_resource (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    state TEXT NOT NULL CHECK (state IN ('available','claimed','quarantined')),
    job_id TEXT,
    attempt_id TEXT,
    owner_id TEXT,
    reason TEXT,
    updated_at TEXT NOT NULL
)"""

_ARTIFACT_PUBLICATION_AUTHORITY_DDL = """CREATE TABLE artifact_publication_authority (
    publication_id TEXT PRIMARY KEY REFERENCES artifact_publications(publication_id),
    job_id TEXT NOT NULL REFERENCES execution_jobs(job_id),
    attempt_id TEXT NOT NULL REFERENCES execution_attempts(attempt_id),
    owner_id TEXT,
    claim_epoch INTEGER NOT NULL CHECK (claim_epoch >= 0),
    created_at TEXT NOT NULL
)"""

_EXECUTION_ADMISSIONS_DDL = """CREATE TABLE execution_admissions (
    job_id TEXT PRIMARY KEY REFERENCES execution_jobs(job_id),
    admission_profile_json TEXT NOT NULL,
    workload_demand_json TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN (
'queued','not_required','blocked','denied','reserved','released','quarantined','canceled'
    )),
    decision_reason TEXT NOT NULL,
    profile_fingerprint TEXT,
    required_bytes_json TEXT NOT NULL,
    unknown_reasons_json TEXT NOT NULL,
    reserved_bytes_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_EXECUTION_JOBS_QUEUED_INDEX_DDL = """CREATE INDEX execution_jobs_queued_idx
    ON execution_jobs(status, created_at, job_id)"""

_EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL = """CREATE INDEX execution_attempts_running_idx
    ON execution_attempts(job_id, status)"""

_EXECUTION_ADMISSIONS_DISPATCH_INDEX_DDL = """CREATE INDEX execution_admissions_dispatch_idx
    ON execution_admissions(decision, created_at, job_id)"""

_BACKEND_EXECUTIONS_JOB_INDEX_DDL = """CREATE INDEX backend_executions_job_idx
    ON backend_executions(job_id, resolved_at)"""

_GENERATION_REQUESTS_DDL = """CREATE TABLE generation_requests (
    request_id TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
)"""

_GENERATION_JOBS_DDL = """CREATE TABLE generation_jobs (
    job_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES generation_requests(request_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    adapter_id TEXT NOT NULL,
    adapter_configuration_json TEXT NOT NULL,
    resolved_prompt TEXT NOT NULL,
    resolved_seed INTEGER NOT NULL,
    validated_reference_ids_json TEXT NOT NULL,
    output_slot TEXT NOT NULL,
    output_slot_id TEXT NOT NULL UNIQUE,
    effective_parameters_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)"""

_GENERATION_ATTEMPTS_DDL = """CREATE TABLE generation_attempts (
    attempt_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES generation_jobs(job_id),
    attempt_number INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    adapter_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error_message TEXT,
    UNIQUE (job_id, attempt_number),
    UNIQUE (job_id, attempt_id)
)"""

_GENERATION_ARTIFACTS_DDL = """CREATE TABLE generation_artifacts (
    artifact_id TEXT PRIMARY KEY,
    job_id TEXT REFERENCES generation_jobs(job_id),
    attempt_id TEXT REFERENCES generation_attempts(attempt_id),
    output_slot_id TEXT,
    path TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    image_format TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('generated', 'imported')),
    import_provenance_json TEXT,
    CHECK ((origin = 'generated' AND job_id IS NOT NULL
        AND attempt_id IS NOT NULL AND output_slot_id IS NOT NULL
        AND import_provenance_json IS NULL)
        OR (origin = 'imported' AND job_id IS NULL
        AND attempt_id IS NULL AND output_slot_id IS NULL
        AND import_provenance_json IS NOT NULL)),
    UNIQUE (job_id, output_slot_id),
    FOREIGN KEY (job_id, attempt_id)
        REFERENCES generation_attempts(job_id, attempt_id)
)"""

_ARTIFACT_EDGES_DDL = """CREATE TABLE artifact_edges (
    source_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
    target_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
    role TEXT NOT NULL CHECK (
        role IN ('reference','source','derivation','inspiration')),
    position INTEGER NOT NULL CHECK (position >= 0),
    CHECK (source_id != target_id),
    PRIMARY KEY (target_id, position),
    UNIQUE (source_id, target_id, role)
)"""

_ARTIFACT_PUBLICATIONS_DDL = """CREATE TABLE artifact_publications (
    publication_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL UNIQUE,
    root TEXT NOT NULL,
    root_dev INTEGER NOT NULL,
    root_ino INTEGER NOT NULL,
    root_token TEXT NOT NULL,
    stage_name TEXT NOT NULL UNIQUE,
    stage_dev INTEGER,
    stage_ino INTEGER,
    final_name TEXT,
    state TEXT NOT NULL CHECK (
        state IN ('allocated','ready','committed','abandoned')),
    job_id TEXT,
    attempt_id TEXT,
    artifact_json TEXT,
    sources_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    error TEXT
)"""

_ARTIFACT_INTEGRITY_DDL = """CREATE TABLE artifact_integrity (
    artifact_id TEXT PRIMARY KEY REFERENCES generation_artifacts(artifact_id),
    status TEXT NOT NULL CHECK (status IN ('ok','missing','corrupt')),
    checked_at TEXT NOT NULL,
    detail TEXT
)"""

_GENERATION_BATCHES_DDL = """CREATE TABLE generation_batches (
    batch_id TEXT PRIMARY KEY,
    batch_key TEXT NOT NULL UNIQUE,
    manifest_json TEXT NOT NULL,
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64),
    execution_identity_json TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
    coordinator_state TEXT NOT NULL CHECK (coordinator_state IN (
        'planned','running','complete','partial','failed','attention_required')),
    claim_owner TEXT,
    claim_epoch INTEGER NOT NULL DEFAULT 0 CHECK (claim_epoch >= 0),
    claim_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK ((claim_owner IS NULL AND claim_expires_at IS NULL)
        OR (claim_owner IS NOT NULL AND claim_expires_at IS NOT NULL))
)"""

_GENERATION_BATCH_SLOTS_DDL = """CREATE TABLE generation_batch_slots (
    slot_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES generation_batches(batch_id),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    output_slot TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    idempotency_key TEXT NOT NULL UNIQUE,
    admission_profile_json TEXT,
    workload_demand_json TEXT,
    max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
    coordinator_state TEXT NOT NULL CHECK (coordinator_state IN (
        'planned','accepted','succeeded','failed','canceled','attention_required')),
    service_job_id TEXT UNIQUE REFERENCES generation_jobs(job_id),
    service_request_id TEXT REFERENCES generation_requests(request_id),
    output_slot_id TEXT REFERENCES generation_jobs(output_slot_id),
    artifact_id TEXT REFERENCES generation_artifacts(artifact_id),
    detail TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, ordinal),
    CHECK ((admission_profile_json IS NULL AND workload_demand_json IS NULL)
        OR (admission_profile_json IS NOT NULL AND workload_demand_json IS NOT NULL))
)"""

_GENERATION_ARTIFACTS_JOB_INDEX_DDL = """CREATE INDEX generation_artifacts_job_idx
    ON generation_artifacts(job_id)"""

_GENERATION_BATCH_SLOTS_ORDER_INDEX_DDL = """CREATE INDEX generation_batch_slots_order_idx
    ON generation_batch_slots(batch_id, ordinal)"""

_GENERATION_BATCHES_IDENTITY_IMMUTABLE_DDL = """CREATE TRIGGER generation_batches_identity_immutable
BEFORE UPDATE ON generation_batches
BEGIN
    SELECT RAISE(ABORT, 'generation batch identity is immutable')
    WHERE NEW.batch_id IS NOT OLD.batch_id
    OR NEW.batch_key IS NOT OLD.batch_key
    OR NEW.manifest_json IS NOT OLD.manifest_json
    OR NEW.manifest_digest IS NOT OLD.manifest_digest
    OR NEW.execution_identity_json IS NOT OLD.execution_identity_json
    OR NEW.max_attempts IS NOT OLD.max_attempts
    OR NEW.created_at IS NOT OLD.created_at;
END"""

_GENERATION_BATCHES_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_batches_immutable_delete
BEFORE DELETE ON generation_batches
BEGIN
    SELECT RAISE(ABORT, 'generation batches are immutable');
END"""

_GENERATION_BATCH_SLOTS_IDENTITY_IMMUTABLE_DDL = """CREATE TRIGGER generation_batch_slots_identity_immutable
BEFORE UPDATE ON generation_batch_slots
BEGIN
    SELECT RAISE(ABORT, 'generation batch slot identity is immutable')
    WHERE NEW.slot_id IS NOT OLD.slot_id
    OR NEW.batch_id IS NOT OLD.batch_id
    OR NEW.ordinal IS NOT OLD.ordinal
    OR NEW.output_slot IS NOT OLD.output_slot
    OR NEW.request_json IS NOT OLD.request_json
    OR NEW.request_digest IS NOT OLD.request_digest
    OR NEW.idempotency_key IS NOT OLD.idempotency_key
    OR NEW.admission_profile_json IS NOT OLD.admission_profile_json
    OR NEW.workload_demand_json IS NOT OLD.workload_demand_json
    OR NEW.max_attempts IS NOT OLD.max_attempts
    OR NEW.created_at IS NOT OLD.created_at;
END"""

_GENERATION_BATCH_SLOTS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_batch_slots_immutable_delete
BEFORE DELETE ON generation_batch_slots
BEGIN
    SELECT RAISE(ABORT, 'generation batch slots are immutable');
END"""

_GENERATION_REQUESTS_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER generation_requests_immutable_update
BEFORE UPDATE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END"""

_GENERATION_REQUESTS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_requests_immutable_delete
BEFORE DELETE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END"""

_GENERATION_ARTIFACTS_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER generation_artifacts_immutable_update
BEFORE UPDATE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END"""

_GENERATION_ARTIFACTS_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER generation_artifacts_immutable_delete
BEFORE DELETE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END"""

_ARTIFACT_EDGES_ACYCLIC_DDL = """CREATE TRIGGER artifact_edges_acyclic
BEFORE INSERT ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact lineage cycle') WHERE EXISTS (
        WITH RECURSIVE descendants(id) AS (
            SELECT target_id FROM artifact_edges
            WHERE source_id = NEW.target_id
            UNION
            SELECT e.target_id FROM artifact_edges e JOIN descendants d
                ON e.source_id = d.id
        )
        SELECT 1 FROM descendants WHERE id = NEW.source_id
    );
END"""

_ARTIFACT_EDGES_IMMUTABLE_UPDATE_DDL = """CREATE TRIGGER artifact_edges_immutable_update
BEFORE UPDATE ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact edges are immutable');
END"""

_ARTIFACT_EDGES_IMMUTABLE_DELETE_DDL = """CREATE TRIGGER artifact_edges_immutable_delete
BEFORE DELETE ON artifact_edges
BEGIN
    SELECT RAISE(ABORT, 'artifact edges are immutable');
END"""

_ARTIFACT_EDGES_SEALED_DDL = """CREATE TRIGGER artifact_edges_sealed
BEFORE INSERT ON artifact_edges
WHEN NOT EXISTS (
    SELECT 1 FROM artifact_publications
    WHERE artifact_id = NEW.target_id AND state = 'ready'
)
BEGIN
    SELECT RAISE(ABORT, 'artifact lineage is sealed');
END"""

_EXECUTION_TABLE_DDL: dict[str, str] = {
    "execution_jobs": _EXECUTION_JOBS_DDL,
    "execution_attempts": _EXECUTION_ATTEMPTS_DDL,
    "execution_resource": _EXECUTION_RESOURCE_DDL,
    "artifact_publication_authority": _ARTIFACT_PUBLICATION_AUTHORITY_DDL,
    "execution_admissions": _EXECUTION_ADMISSIONS_DDL,
    "backend_executions": _BACKEND_EXECUTIONS_DDL,
    "execution_containment": _EXECUTION_CONTAINMENT_DDL,
    "systemd_output_lifecycle": _SYSTEMD_OUTPUT_LIFECYCLE_DDL,
    "execution_cancellations": _EXECUTION_CANCELLATIONS_DDL,
}


_CURRENT_TABLE_DDL: dict[str, str] = {
    "generation_requests": _GENERATION_REQUESTS_DDL,
    "generation_jobs": _GENERATION_JOBS_DDL,
    "generation_attempts": _GENERATION_ATTEMPTS_DDL,
    "generation_artifacts": _GENERATION_ARTIFACTS_DDL,
    "artifact_edges": _ARTIFACT_EDGES_DDL,
    "artifact_publications": _ARTIFACT_PUBLICATIONS_DDL,
    "artifact_integrity": _ARTIFACT_INTEGRITY_DDL,
    "generation_batches": _GENERATION_BATCHES_DDL,
    "generation_batch_slots": _GENERATION_BATCH_SLOTS_DDL,
    **_EXECUTION_TABLE_DDL,
}

_CURRENT_TABLES = frozenset(_CURRENT_TABLE_DDL)

_CURRENT_INDEX_DDL: dict[str, str] = {
    "generation_artifacts_job_idx": _GENERATION_ARTIFACTS_JOB_INDEX_DDL,
    "generation_batch_slots_order_idx": _GENERATION_BATCH_SLOTS_ORDER_INDEX_DDL,
    "execution_jobs_queued_idx": _EXECUTION_JOBS_QUEUED_INDEX_DDL,
    "execution_attempts_running_idx": _EXECUTION_ATTEMPTS_RUNNING_INDEX_DDL,
    "execution_admissions_dispatch_idx": _EXECUTION_ADMISSIONS_DISPATCH_INDEX_DDL,
    "backend_executions_job_idx": _BACKEND_EXECUTIONS_JOB_INDEX_DDL,
    "systemd_output_lifecycle_pending_idx": (
        "CREATE INDEX systemd_output_lifecycle_pending_idx "
        "ON systemd_output_lifecycle(cleanup_state, created_at, attempt_id) "
        "WHERE cleanup_state = 'pending'"
    ),
}

_STATIC_TRIGGER_DDL: dict[str, str] = {
    "generation_requests_immutable_update": (
        _GENERATION_REQUESTS_IMMUTABLE_UPDATE_DDL
    ),
    "generation_requests_immutable_delete": (
        _GENERATION_REQUESTS_IMMUTABLE_DELETE_DDL
    ),
    "generation_artifacts_immutable_update": (
        _GENERATION_ARTIFACTS_IMMUTABLE_UPDATE_DDL
    ),
    "generation_artifacts_immutable_delete": (
        _GENERATION_ARTIFACTS_IMMUTABLE_DELETE_DDL
    ),
    "artifact_edges_acyclic": _ARTIFACT_EDGES_ACYCLIC_DDL,
    "artifact_edges_immutable_update": _ARTIFACT_EDGES_IMMUTABLE_UPDATE_DDL,
    "artifact_edges_immutable_delete": _ARTIFACT_EDGES_IMMUTABLE_DELETE_DDL,
    "artifact_edges_sealed": _ARTIFACT_EDGES_SEALED_DDL,
    "backend_executions_stage_insert": _BACKEND_EXECUTIONS_STAGE_INSERT_DDL,
    "backend_executions_stage_transition": _BACKEND_EXECUTIONS_STAGE_TRANSITION_DDL,
    "backend_executions_immutable_delete": _BACKEND_EXECUTIONS_IMMUTABLE_DELETE_DDL,
    "execution_containment_stage_transition": (
        _EXECUTION_CONTAINMENT_STAGE_TRANSITION_DDL
    ),
    "execution_containment_immutable_delete": (
        _EXECUTION_CONTAINMENT_IMMUTABLE_DELETE_DDL
    ),
    "systemd_output_lifecycle_transition": (
        _SYSTEMD_OUTPUT_LIFECYCLE_TRANSITION_DDL
    ),
    "systemd_output_lifecycle_immutable_delete": (
        "CREATE TRIGGER systemd_output_lifecycle_immutable_delete "
        "BEFORE DELETE ON systemd_output_lifecycle BEGIN "
        "SELECT RAISE(ABORT, 'systemd output lifecycle evidence is immutable'); "
        "END"
    ),
    "execution_cancellations_transition": (
        _EXECUTION_CANCELLATIONS_TRANSITION_DDL
    ),
    "execution_cancellations_immutable_delete": (
        _EXECUTION_CANCELLATIONS_IMMUTABLE_DELETE_DDL
    ),
    "generation_batches_identity_immutable": (
        _GENERATION_BATCHES_IDENTITY_IMMUTABLE_DDL
    ),
    "generation_batches_immutable_delete": (
        _GENERATION_BATCHES_IMMUTABLE_DELETE_DDL
    ),
    "generation_batch_slots_identity_immutable": (
        _GENERATION_BATCH_SLOTS_IDENTITY_IMMUTABLE_DDL
    ),
    "generation_batch_slots_immutable_delete": (
        _GENERATION_BATCH_SLOTS_IMMUTABLE_DELETE_DDL
    ),
}


@dataclass(frozen=True, slots=True)
class PendingExecution:
    """Identifiers and resolved references returned after a job is committed."""

    created: bool
    request_id: str
    job_id: str
    attempt_id: str
    output_slot_id: str
    references: tuple[ResolvedReference, ...]


@dataclass(frozen=True, slots=True)
class QueuedExecution:
    """One idempotent admission result before any attempt has been claimed."""

    created: bool
    request_id: str
    job_id: str
    status: str
    output_slot_id: str
    max_attempts: int
    references: tuple[ResolvedReference, ...]


@dataclass(frozen=True, slots=True)
class ExecutionClaim:
    """Private worker capability returned by one atomic queue claim."""

    job_id: str
    attempt_id: str
    attempt_number: int
    owner_id: str
    claim_epoch: int
    max_attempts: int
    resolved_prompt: str
    resolved_seed: int
    width: int
    height: int
    output_slot: str
    output_slot_id: str
    references: tuple[ResolvedReference, ...]
    adapter_id: str
    adapter_configuration_json: str
    resolved_output_directory: str
    process_contained: bool
    containment_contract: str | None
    lease_expires_at: str


@dataclass(frozen=True, slots=True)
class PendingSystemdOutputCleanup:
    """A terminal attempt whose broker scratch cleanup still needs retry."""

    identity: AttemptUnitIdentity
    validated: bool


class SQLiteStore:
    """Store generation records in a local SQLite database.

    New databases use the complete current schema. Existing databases are
    opened only after read-only structural validation confirms that exact
    schema; incompatible databases are rejected without mutation. Each
    operation owns a short-lived connection.
    """

    def __init__(self, database_path: Path, *, read_only: bool = False) -> None:
        """Open the current schema, with an optional mode that never initializes the file."""
        self.database_path = database_path.expanduser().resolve()
        self._systemd_evidence_ledger = SystemdEvidenceLedger(
            SystemdEvidenceLedger.path_for(self.database_path)
        )
        self.read_only = read_only
        if self.read_only:
            self._validate_existing_database()
        else:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            if self.database_path.exists() and self.database_path.stat().st_size:
                self._validate_existing_database()
            else:
                self._initialize()

    def initialize_systemd_evidence_ledger(self, *, worker_gid: int) -> None:
        """Create the root-owned ledger with read access for the worker group."""
        self._systemd_evidence_ledger.initialize(worker_gid=worker_gid)

    @contextmanager
    def _connection(
        self,
        transaction: bool = False,
        *,
        read_transaction: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        if transaction and read_transaction:
            raise ValueError(
                "a connection cannot be both a read and a write transaction"
            )
        if transaction and self.read_only:
            raise sqlite3.OperationalError("read-only store cannot open a write transaction")
        if self.read_only:
            connection = sqlite3.connect(
                f"{self.database_path.as_uri()}?mode=ro",
                timeout=30,
                isolation_level=None,
                uri=True,
            )
        else:
            connection = sqlite3.connect(
                str(self.database_path), timeout=30, isolation_level=None
            )
        connection.row_factory = sqlite3.Row
        connection.create_function(
            _WRITER_EPOCH_FUNCTION, 0, lambda: _WRITER_EPOCH, deterministic=True
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        if transaction:
            connection.execute("BEGIN IMMEDIATE")
        elif read_transaction:
            connection.execute("BEGIN DEFERRED")
        try:
            yield connection
            if transaction or read_transaction:
                connection.commit()
        except BaseException:
            if transaction or read_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        """Create the complete current schema in one SQLite transaction."""
        with self._connection(transaction=True) as connection:
            existing_objects = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
            ).fetchone()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if existing_objects is not None or version:
                self._validate_current_schema(connection)
                return

            for definition in _CURRENT_TABLE_DDL.values():
                connection.execute(definition)
            for definition in _CURRENT_INDEX_DDL.values():
                connection.execute(definition)
            connection.execute(
                "INSERT INTO execution_resource "
                "(id, state, job_id, attempt_id, owner_id, reason, updated_at) "
                "VALUES (1, 'available', NULL, NULL, NULL, NULL, ?)",
                ("1970-01-01T00:00:00+00:00",),
            )
            for definition in _STATIC_TRIGGER_DDL.values():
                connection.execute(definition)
            self._install_writer_guards(connection)
            connection.execute(f"PRAGMA user_version = {_CURRENT_SCHEMA_VERSION}")
            self._validate_current_schema(connection)

    def _validate_existing_database(self) -> None:
        """Validate an existing database through a read-only connection."""
        connection = sqlite3.connect(
            f"{self.database_path.as_uri()}?mode=ro",
            timeout=30,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.create_function(
            _WRITER_EPOCH_FUNCTION,
            0,
            lambda: _WRITER_EPOCH,
            deterministic=True,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            self._validate_current_schema(connection)
        except sqlite3.DatabaseError as error:
            raise RuntimeError(
                "database cannot be opened as a current media-generation "
                "schema; no changes were made"
            ) from error
        finally:
            connection.close()

    @staticmethod
    def _incomplete_schema(detail: str) -> RuntimeError:
        """Build an actionable error for a non-current database layout."""
        return RuntimeError(
            "database schema is incompatible with the current media-generation "
            f"schema: {detail}; no changes were made"
        )

    @staticmethod
    def _normalized_schema_sql(sql: str) -> str:
        """Normalize one complete DDL statement while preserving literals."""
        compact: list[str] = []
        index = 0
        closing_quote: str | None = None

        while index < len(sql):
            character = sql[index]
            if closing_quote is not None:
                compact.append(character)
                if character == closing_quote:
                    if (
                        closing_quote != "]"
                        and index + 1 < len(sql)
                        and sql[index + 1] == closing_quote
                    ):
                        compact.append(sql[index + 1])
                        index += 2
                        continue
                    closing_quote = None
                index += 1
                continue

            if sql.startswith("--", index):
                newline = sql.find("\n", index + 2)
                index = len(sql) if newline < 0 else newline + 1
                continue
            if sql.startswith("/*", index):
                comment_end = sql.find("*/", index + 2)
                if comment_end < 0:
                    raise ValueError("unterminated SQL comment")
                index = comment_end + 2
                continue
            if character in {"'", '"', "`", "["}:
                closing_quote = "]" if character == "[" else character
                compact.append(character)
                index += 1
                continue
            if character.isspace():
                index += 1
                continue
            compact.append(character.lower())
            index += 1

        if closing_quote is not None:
            raise ValueError("unterminated quoted SQL")
        return "".join(compact)

    @staticmethod
    def _validate_current_schema(connection: sqlite3.Connection) -> None:
        """Require the exact supported schema without changing the database."""
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != _CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"unsupported database schema version {version}; "
                f"expected {_CURRENT_SCHEMA_VERSION}; no changes were made"
            )

        objects = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
        by_type: dict[str, dict[str, str]] = {
            "table": {},
            "index": {},
            "trigger": {},
            "view": {},
        }
        for row in objects:
            object_type = str(row["type"])
            if object_type in by_type:
                by_type[object_type][str(row["name"])] = str(row["sql"] or "")

        if by_type["view"]:
            raise SQLiteStore._incomplete_schema(
                "unexpected views: " + ", ".join(sorted(by_type["view"]))
            )

        tables = frozenset(by_type["table"])
        missing_tables = sorted(_CURRENT_TABLES - tables)
        unexpected_tables = sorted(tables - _CURRENT_TABLES)
        if missing_tables or unexpected_tables:
            details: list[str] = []
            if missing_tables:
                details.append("missing tables: " + ", ".join(missing_tables))
            if unexpected_tables:
                details.append(
                    "unexpected tables: " + ", ".join(unexpected_tables)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))

        for table, expected_sql in _CURRENT_TABLE_DDL.items():
            try:
                actual_sql = SQLiteStore._normalized_schema_sql(
                    by_type["table"][table]
                )
                normalized_expected = SQLiteStore._normalized_schema_sql(
                    expected_sql
                )
            except ValueError as error:
                raise SQLiteStore._incomplete_schema(
                    f"{table} malformed table definition"
                ) from error
            if actual_sql != normalized_expected:
                raise SQLiteStore._incomplete_schema(
                    f"{table} divergent table definition"
                )

        named_indexes = frozenset(by_type["index"])
        missing_indexes = sorted(
            frozenset(_CURRENT_INDEX_DDL) - named_indexes
        )
        unexpected_indexes = sorted(
            named_indexes - frozenset(_CURRENT_INDEX_DDL)
        )
        if missing_indexes or unexpected_indexes:
            details = []
            if missing_indexes:
                details.append("missing indexes: " + ", ".join(missing_indexes))
            if unexpected_indexes:
                details.append(
                    "unexpected indexes: " + ", ".join(unexpected_indexes)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))
        for index_name, expected_sql in _CURRENT_INDEX_DDL.items():
            actual_sql = SQLiteStore._normalized_schema_sql(
                by_type["index"][index_name]
            )
            if actual_sql != SQLiteStore._normalized_schema_sql(expected_sql):
                raise SQLiteStore._incomplete_schema(
                    f"index {index_name} divergent definition"
                )

        expected_triggers = dict(_STATIC_TRIGGER_DDL)
        for table, operation in _WRITER_GUARDS:
            guard_name, guard_sql = SQLiteStore._writer_guard_sql(
                table, operation
            )
            expected_triggers[guard_name] = guard_sql
        actual_triggers = frozenset(by_type["trigger"])
        missing_triggers = sorted(frozenset(expected_triggers) - actual_triggers)
        unexpected_triggers = sorted(actual_triggers - frozenset(expected_triggers))
        if missing_triggers or unexpected_triggers:
            details = []
            if missing_triggers:
                details.append(
                    "missing triggers: " + ", ".join(missing_triggers)
                )
            if unexpected_triggers:
                details.append(
                    "unexpected triggers: " + ", ".join(unexpected_triggers)
                )
            raise SQLiteStore._incomplete_schema("; ".join(details))
        for trigger_name, expected_sql in expected_triggers.items():
            actual_sql = SQLiteStore._normalized_schema_sql(
                by_type["trigger"][trigger_name]
            )
            if actual_sql != SQLiteStore._normalized_schema_sql(expected_sql):
                raise SQLiteStore._incomplete_schema(
                    f"trigger {trigger_name} divergent definition"
                )

        resources = connection.execute(
            "SELECT id, state FROM execution_resource ORDER BY id"
        ).fetchall()
        if (
            len(resources) != 1
            or int(resources[0]["id"]) != 1
            or str(resources[0]["state"])
            not in {"available", "claimed", "quarantined"}
        ):
            raise SQLiteStore._incomplete_schema(
                "execution_resource singleton row missing or invalid"
            )

        missing_execution = connection.execute(
            """SELECT jobs.job_id
               FROM generation_jobs AS jobs
               LEFT JOIN execution_jobs AS execution
                 ON execution.job_id = jobs.job_id
               WHERE execution.job_id IS NULL
               LIMIT 1"""
        ).fetchone()
        if missing_execution is not None:
            raise SQLiteStore._incomplete_schema(
                "generation job lacks execution state: "
                f"{missing_execution['job_id']}"
            )

        missing_admission = connection.execute(
            """SELECT execution.job_id
               FROM execution_jobs AS execution
            LEFT JOIN execution_admissions AS admission
                 ON admission.job_id = execution.job_id
               WHERE admission.job_id IS NULL
               LIMIT 1"""
        ).fetchone()
        if missing_admission is not None:
            raise SQLiteStore._incomplete_schema(
                "execution job lacks admission evidence: "
                f"{missing_admission['job_id']}"
            )

        try:
            AdmissionPersistence.validate_persisted(connection)
        except ValueError as error:
            raise SQLiteStore._incomplete_schema(str(error)) from error

    @staticmethod
    def _writer_guard_sql(table: str, operation: str) -> tuple[str, str]:
        """Return the trigger name and definition for one guarded write."""
        name = f"t04_writer_guard_{table}_{operation.lower()}"
        sql = f"""CREATE TRIGGER {name}
BEFORE {operation} ON {table}
WHEN {_WRITER_EPOCH_FUNCTION}() != {_WRITER_EPOCH}
BEGIN
    SELECT RAISE(ABORT, 'stale media-generation writer');
END"""
        return name, sql

    @classmethod
    def _install_writer_guards(cls, connection: sqlite3.Connection) -> None:
        """Create current writer guards for a newly initialized database."""
        for table, operation in _WRITER_GUARDS:
            name, expected_sql = cls._writer_guard_sql(table, operation)
            existing = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'trigger' AND name = ?",
                (name,),
            ).fetchone()
            if existing is not None:
                raise cls._incomplete_schema(
                    f"writer guard already exists during initialization: {name}"
                )
            connection.execute(expected_sql)

    @staticmethod
    def _insert_sources(connection, artifact_id: str, sources: tuple[ArtifactSource, ...]) -> None:
        for position, source in enumerate(sources):
            connection.execute("INSERT INTO artifact_edges VALUES (?, ?, ?, ?)",
                (source.artifact_id, artifact_id, source.role, position))

    @staticmethod
    def _references_for_job(
        connection: sqlite3.Connection, job_id: str
    ) -> tuple[ResolvedReference, ...]:
        """Reconstruct the ordered reference identities frozen on a job."""
        row = connection.execute(
            """SELECT jobs.validated_reference_ids_json, execution.resolved_plan_json
               FROM generation_jobs AS jobs
               JOIN execution_jobs AS execution ON execution.job_id = jobs.job_id
               WHERE jobs.job_id = ?""",
            (job_id,),
        ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"job not found: {job_id}")
        plan = json.loads(str(row["resolved_plan_json"]))
        roles = [str(item.get("role", "reference")) for item in plan["references"]]
        references: list[ResolvedReference] = []
        for position, artifact_id in enumerate(
            json.loads(str(row["validated_reference_ids_json"]))
        ):
            artifact = connection.execute(
                "SELECT artifact_id, sha256, path FROM generation_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if artifact is None:
                raise UnknownReferenceError(f"unknown reference artifact ID: {artifact_id}")
            references.append(
                ResolvedReference(
                    artifact_id=str(artifact["artifact_id"]),
                    content_sha256=str(artifact["sha256"]),
                    path=Path(str(artifact["path"])),
                    role=roles[position] if position < len(roles) else "reference",
                )
            )
        return tuple(references)

    @staticmethod
    def _resolved_plan_json(
        row: sqlite3.Row,
        references: tuple[ResolvedReference, ...],
    ) -> str:
        """Serialize every run input that must remain frozen before claim."""
        parameters = json.loads(str(row["effective_parameters_json"]))
        return _json(
            {
                "resolved_prompt": str(row["resolved_prompt"]),
                "resolved_seed": int(row["resolved_seed"]),
                "width": int(parameters["width"]),
                "height": int(parameters["height"]),
                "output_slot": str(row["output_slot"]),
                "output_slot_id": str(row["output_slot_id"]),
                "references": [
                    {
                        "artifact_id": reference.artifact_id,
                        "content_sha256": reference.content_sha256,
                        "path": str(reference.path),
                        "role": reference.role,
                    }
                    for reference in references
                ],
                "resolved_output_directory": (
                    str(Path(parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY]).expanduser().resolve())
                    if isinstance(parameters.get(_RESOLVED_OUTPUT_DIRECTORY_KEY), str)
                    else ""
                ),
            }
        )

    def find_idempotency_key(self, idempotency_key: str) -> tuple[str, str] | None:
        """Return an idempotency match through a read-only database connection."""
        connection = sqlite3.connect(
            f"{self.database_path.as_uri()}?mode=ro",
            timeout=30,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT job_id, request_digest FROM generation_jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else (str(row["job_id"]), str(row["request_digest"]))

    @classmethod
    def find_idempotency_key_readonly(
        cls, database_path: Path, idempotency_key: str
    ) -> tuple[str, str] | None:
        """Look up an accepted job without initializing or mutating the database.

        This path is for reconciliation after a caller loses its acknowledgement.
        A missing database means no job has been accepted. An existing database
        must pass the same current-schema validation as normal service startup.
        """
        path = Path(database_path).expanduser().resolve()
        if not path.exists():
            return None
        if not path.is_file():
            raise RuntimeError("GenerationService database path is not a regular file")
        store = object.__new__(cls)
        store.database_path = path
        store._validate_existing_database()
        return store.find_idempotency_key(idempotency_key)

    def persist_generation_batch(
        self,
        *,
        batch_id: str,
        batch_key: str,
        manifest_json: str,
        manifest_digest: str,
        execution_identity_json: str,
        max_attempts: int,
        slots: list[dict[str, object]],
        timestamp: str,
    ) -> tuple[str, bool]:
        """Persist immutable batch intent before any T04 job is admitted."""
        with self._connection(transaction=True) as connection:
            existing = connection.execute(
                "SELECT batch_id, manifest_json, manifest_digest, "
                "execution_identity_json, max_attempts "
                "FROM generation_batches WHERE batch_key = ?",
                (batch_key,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["manifest_json"]) != manifest_json
                    or str(existing["manifest_digest"]) != manifest_digest
                    or str(existing["execution_identity_json"])
                    != execution_identity_json
                    or int(existing["max_attempts"]) != max_attempts
                ):
                    raise IdempotencyConflictError(
                        "batch key already bound to different immutable intent"
                    )
                persisted_count = int(
                    connection.execute(
                        "SELECT count(*) FROM generation_batch_slots WHERE batch_id = ?",
                        (str(existing["batch_id"]),),
                    ).fetchone()[0]
                )
                if persisted_count != len(slots):
                    raise RuntimeError("persisted batch slot manifest is inconsistent")
                return str(existing["batch_id"]), False

            connection.execute(
                """INSERT INTO generation_batches (
                    batch_id, batch_key, manifest_json, manifest_digest,
                    execution_identity_json, max_attempts, coordinator_state,
                    claim_owner, claim_epoch, claim_expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'planned', NULL, 0, NULL, ?, ?)""",
                (
                    batch_id,
                    batch_key,
                    manifest_json,
                    manifest_digest,
                    execution_identity_json,
                    max_attempts,
                    timestamp,
                    timestamp,
                ),
            )
            connection.executemany(
                """INSERT INTO generation_batch_slots (
                    slot_id, batch_id, ordinal, output_slot, request_json,
                    request_digest, idempotency_key, admission_profile_json,
                    workload_demand_json, max_attempts, coordinator_state,
                    service_job_id, service_request_id, output_slot_id, artifact_id,
                    detail, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', NULL, NULL,
                          NULL, NULL, NULL, ?, ?)""",
                [
                    (
                        str(slot["slot_id"]),
                        batch_id,
                        int(slot["ordinal"]),
                        str(slot["output_slot"]),
                        str(slot["request_json"]),
                        str(slot["request_digest"]),
                        str(slot["idempotency_key"]),
                        slot.get("admission_profile_json"),
                        slot.get("workload_demand_json"),
                        max_attempts,
                        timestamp,
                        timestamp,
                    )
                    for slot in slots
                ],
            )
        return batch_id, True

    def get_generation_batch(self, identifier: str) -> dict[str, object]:
        """Read one persisted batch by stable ID or idempotency key."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM generation_batches "
                "WHERE batch_id = ? OR batch_key = ?",
                (identifier, identifier),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"batch not found: {identifier}")
        return dict(row)

    def get_generation_batch_slots(self, batch_id: str) -> list[dict[str, object]]:
        """Read batch slots in their immutable manifest order."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM generation_batch_slots "
                "WHERE batch_id = ? ORDER BY ordinal",
                (batch_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_generation_batch(
        self, batch_id: str, owner: str, now: str, expires_at: str
    ) -> dict[str, object] | None:
        """Atomically take an available coordinator lease with a new epoch."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                "SELECT coordinator_state, claim_owner, claim_expires_at, claim_epoch "
                "FROM generation_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"batch not found: {batch_id}")
            if row["coordinator_state"] == "complete":
                return None
            if (
                row["claim_owner"] is not None
                and str(row["claim_owner"]) != owner
                and row["claim_expires_at"] is not None
                and str(row["claim_expires_at"]) > now
            ):
                return None
            connection.execute(
                """UPDATE generation_batches
                   SET claim_owner = ?, claim_epoch = claim_epoch + 1,
                       claim_expires_at = ?, coordinator_state = 'running',
                       updated_at = ? WHERE batch_id = ?""",
                (owner, expires_at, now, batch_id),
            )
            claimed = connection.execute(
                "SELECT * FROM generation_batches WHERE batch_id = ?", (batch_id,)
            ).fetchone()
        return dict(claimed)

    def renew_generation_batch_claim(
        self,
        batch_id: str,
        owner: str,
        epoch: int,
        now: str,
        expires_at: str,
    ) -> bool:
        """Extend only a live coordinator claim with its current fencing epoch."""
        with self._connection(transaction=True) as connection:
            cursor = connection.execute(
                """UPDATE generation_batches SET claim_expires_at = ?, updated_at = ?
                   WHERE batch_id = ? AND claim_owner = ? AND claim_epoch = ?
                   AND claim_expires_at > ?""",
                (expires_at, now, batch_id, owner, epoch, now),
            )
        return cursor.rowcount == 1

    def checkpoint_generation_batch_slot(
        self,
        *,
        batch_id: str,
        slot_id: str,
        owner: str,
        epoch: int,
        now: str,
        coordinator_state: str,
        service_job_id: str | None = None,
        service_request_id: str | None = None,
        output_slot_id: str | None = None,
        artifact_id: str | None = None,
        detail: str | None = None,
    ) -> bool:
        """Checkpoint observed T04 identities only under a live batch claim."""
        with self._connection(transaction=True) as connection:
            claim = connection.execute(
                """SELECT 1 FROM generation_batches
                   WHERE batch_id = ? AND claim_owner = ? AND claim_epoch = ?
                   AND claim_expires_at > ?""",
                (batch_id, owner, epoch, now),
            ).fetchone()
            if claim is None:
                return False
            cursor = connection.execute(
                """UPDATE generation_batch_slots
                   SET coordinator_state = ?,
                       service_job_id = COALESCE(?, service_job_id),
                       service_request_id = COALESCE(?, service_request_id),
                       output_slot_id = COALESCE(?, output_slot_id),
                       artifact_id = COALESCE(?, artifact_id),
                       detail = ?, updated_at = ?
                   WHERE batch_id = ? AND slot_id = ?""",
                (
                    coordinator_state,
                    service_job_id,
                    service_request_id,
                    output_slot_id,
                    artifact_id,
                    detail,
                    now,
                    batch_id,
                    slot_id,
                ),
            )
        return cursor.rowcount == 1

    def set_generation_batch_state(
        self,
        batch_id: str,
        owner: str,
        epoch: int,
        now: str,
        coordinator_state: str,
    ) -> bool:
        """Set the coordinator summary under its current live claim."""
        with self._connection(transaction=True) as connection:
            cursor = connection.execute(
                """UPDATE generation_batches SET coordinator_state = ?, updated_at = ?
                   WHERE batch_id = ? AND claim_owner = ? AND claim_epoch = ?
                   AND claim_expires_at > ?""",
                (coordinator_state, now, batch_id, owner, epoch, now),
            )
        return cursor.rowcount == 1

    def release_generation_batch_claim(
        self, batch_id: str, owner: str, epoch: int, now: str
    ) -> bool:
        """Release only the lease still owned by this coordinator epoch."""
        with self._connection(transaction=True) as connection:
            cursor = connection.execute(
                """UPDATE generation_batches
                   SET claim_owner = NULL, claim_expires_at = NULL, updated_at = ?
                   WHERE batch_id = ? AND claim_owner = ? AND claim_epoch = ?""",
                (now, batch_id, owner, epoch),
            )
        return cursor.rowcount == 1

    def create_queued_execution(
        self,
        *,
        request: GenerationRequest,
        request_digest: str,
        idempotency_key: str,
        request_id: str,
        job_id: str,
        output_slot_id: str,
        resolved_seed: int,
        adapter_id: str,
        adapter_configuration_json: str,
        privacy_compliance_json: str,
        effective_parameters_json: str,
        resolved_output_directory: str,
        max_attempts: int | None,
        containment_contract: str | None,
        timestamp: str,
        admission: PendingAdmission,
        allow_not_required: bool,
    ) -> QueuedExecution:
        """Atomically persist or reuse a queued job and its admission evidence.

        A new job requires validated ``PendingAdmission`` evidence. Only the
        exact bundled deterministic CPU adapter may receive ``not_required``;
        every other queued job must carry explicit capacity evidence. Reusing
        an existing job preserves the admission and attempt budget recorded
        when that job was created.
        """
        effective_max_attempts = 1 if max_attempts is None else max_attempts
        if (
            isinstance(effective_max_attempts, bool)
            or not isinstance(effective_max_attempts, int)
            or effective_max_attempts < 1
        ):
            raise ValueError("max_attempts must be a positive integer")
        requested_privacy = json.loads(privacy_compliance_json)
        if (
            not is_privacy_compliance_record(requested_privacy)
            or requested_privacy.get("adapter_id") != adapter_id
        ):
            raise ValueError("privacy compliance evidence is malformed")
        if not isinstance(admission, PendingAdmission):
            raise ValueError("admission evidence must be a PendingAdmission")
        AdmissionPersistence.validate_new(
            admission,
            adapter_id,
            allow_not_required=allow_not_required,
        )
        if (
            admission.decision in {"blocked", "denied"}
            and (admission.profile is None or admission.demand is None)
        ):
            raise ValueError(
                "blocked heavyweight admission requires explicit profile and demand evidence"
            )
        with self._connection(transaction=True) as connection:
            existing = connection.execute(
                """SELECT jobs.*, execution.status AS execution_status,
                          execution.max_attempts AS execution_max_attempts,
                          execution.containment_contract,
                          execution.privacy_compliance_json,
                          execution.retry_eligible AS execution_retry_eligible
                   FROM generation_jobs AS jobs
                   JOIN execution_jobs AS execution ON execution.job_id = jobs.job_id
                   WHERE jobs.idempotency_key = ?""",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest:
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different canonical request intent"
                    )
                if existing["adapter_id"] != adapter_id or json.loads(
                    str(existing["adapter_configuration_json"])
                ) != json.loads(adapter_configuration_json):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different adapter identity or configuration"
                    )
                stored_privacy = _decode_stored_privacy_compliance(
                    existing["privacy_compliance_json"], adapter_id
                )
                if stored_privacy != requested_privacy:
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different privacy-compliance evidence"
                    )
                if (
                    max_attempts is not None
                    and existing["execution_status"] != "succeeded"
                    and int(existing["execution_max_attempts"]) != max_attempts
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different attempt budget"
                    )
                if (
                    existing["containment_contract"] != containment_contract
                    and existing["execution_status"] != "succeeded"
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different containment contract"
                    )
                existing_directory = self._output_directory_for_job(
                    connection,
                    str(existing["job_id"]),
                    str(existing["effective_parameters_json"]),
                )
                if existing_directory != str(
                    Path(resolved_output_directory).expanduser().resolve()
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different or unknown output directory"
                    )
                pinned_admission = AdmissionPersistence.snapshot(
                    connection, str(existing["job_id"])
                )
                proposed_demand = (
                    None if admission.demand is None else admission.demand.to_dict()
                )
                if (
                    pinned_admission is None
                    or pinned_admission.profile_fingerprint
                    != admission.profile_fingerprint
                    or _json(pinned_admission.demand) != _json(proposed_demand)
                    or pinned_admission.required_bytes != admission.required_bytes
                    or pinned_admission.unknown_reasons != admission.unknown_reasons
                ):
                    raise IdempotencyConflictError(
                        "idempotency key already bound to different admission evidence"
                    )
                return QueuedExecution(
                    False,
                    str(existing["request_id"]),
                    str(existing["job_id"]),
                    str(existing["execution_status"]),
                    str(existing["output_slot_id"]),
                    int(existing["execution_max_attempts"]),
                    self._references_for_job(connection, str(existing["job_id"])),
                )

            references = self._resolve_references(
                connection, request.reference_ids, request.reference_roles
            )
            parameters = json.loads(effective_parameters_json)
            parameters[_RESOLVED_OUTPUT_DIRECTORY_KEY] = str(
                Path(resolved_output_directory).expanduser().resolve()
            )
            frozen_parameters_json = _json(parameters)
            connection.execute(
                "INSERT INTO generation_requests "
                "(request_id, canonical_json, request_digest, created_at) VALUES (?, ?, ?, ?)",
                (request_id, request.canonical_json(), request_digest, timestamp),
            )
            connection.execute(
                """INSERT INTO generation_jobs (
                    job_id, request_id, idempotency_key, request_digest, status,
                    adapter_id, adapter_configuration_json, resolved_prompt, resolved_seed,
                    validated_reference_ids_json, output_slot, output_slot_id,
                    effective_parameters_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    request_id,
                    idempotency_key,
                    request_digest,
                    adapter_id,
                    adapter_configuration_json,
                    request.prompt,
                    resolved_seed,
                    _json(request.reference_ids),
                    request.output_slot,
                    output_slot_id,
                    frozen_parameters_json,
                    timestamp,
                    timestamp,
                ),
            )
            job_row = connection.execute(
                "SELECT * FROM generation_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            assert job_row is not None
            connection.execute(
                """INSERT INTO execution_jobs
                    (job_id,status,max_attempts,containment_contract,privacy_compliance_json,
                    fence_epoch,current_attempt_id,
                    retry_eligible,failure_message,resolved_plan_json,created_at,updated_at)
                   VALUES (?,'queued',?,?,?,0,NULL,0,NULL,?,?,?)""",
                (
                    job_id,
                    effective_max_attempts,
                    containment_contract,
                    privacy_compliance_json,
                    self._resolved_plan_json(job_row, references),
                    timestamp,
                    timestamp,
                ),
            )
            AdmissionPersistence.insert(
                connection,
                job_id=job_id,
                admission=admission,
                timestamp=timestamp,
            )
            return QueuedExecution(
                True,
                request_id,
                job_id,
                "queued",
                output_slot_id,
                effective_max_attempts,
                references,
            )

    @staticmethod
    def _resolve_references(
        connection: sqlite3.Connection,
        artifact_ids: tuple[str, ...],
        roles: tuple[str, ...] = (),
    ) -> tuple[ResolvedReference, ...]:
        references: list[ResolvedReference] = []
        for position, artifact_id in enumerate(artifact_ids):
            row = connection.execute(
                "SELECT artifact_id, sha256, path FROM generation_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise UnknownReferenceError(f"unknown reference artifact ID: {artifact_id}")
            references.append(
                ResolvedReference(
                    artifact_id=str(row["artifact_id"]),
                    content_sha256=str(row["sha256"]),
                    path=Path(str(row["path"])),
                    role=roles[position] if position < len(roles) else "reference",
                )
            )
        return tuple(references)

    def create_pending_execution(
        self,
        *,
        request: GenerationRequest,
        request_digest: str,
        idempotency_key: str,
        request_id: str,
        job_id: str,
        attempt_id: str,
        output_slot_id: str,
        resolved_seed: int,
        adapter_id: str,
        adapter_configuration_json: str,
        effective_parameters_json: str,
        resolved_output_directory: str,
        timestamp: str,
    ) -> PendingExecution:
        """Reject the retired pre-queue admission path before it changes rows.

        Callers must use queued admission and a resource-owning claim so that
        every running attempt has durable sidecars and publication authority.
        """
        raise RuntimeError("use queued admission and claim_next_execution")

    def claim_next_execution(
        self,
        *,
        attempt_id: str,
        owner_id: str,
        adapter_id: str,
        resolved_output_directory: str,
        process_contained: bool,
        containment_contract: str | None,
        timestamp: str,
        lease_expires_at: str,
        privacy_compliance_json: str | None = None,
        job_id: str | None = None,
        adapter_configuration_json: str | None = None,
        allow_not_required: bool = False,
    ) -> ExecutionClaim | None:
        """Atomically create one attempt from explicitly admitted queued work.

        The selected row must have current privacy-compliance evidence and an
        admission decision of queued or not_required. Missing admission evidence
        is never treated as an implicit execution grant. Only callers that have
        verified the adapter's exact concrete type may enable ``not_required``.
        """
        requested_directory = str(Path(resolved_output_directory).expanduser().resolve())
        if not isinstance(privacy_compliance_json, str):
            suffix = "" if job_id is None else f": {job_id}"
            raise GenerationError(
                f"{_PRIVACY_CLAIM_EVIDENCE_REQUIRED}{suffix}"
            )
        requested_privacy = json.loads(privacy_compliance_json)
        if (
            not is_privacy_compliance_record(requested_privacy)
            or requested_privacy.get("adapter_id") != adapter_id
        ):
            raise ValueError("privacy compliance evidence malformed")
        with self._connection(transaction=True) as connection:
            resource = connection.execute(
                "SELECT state FROM execution_resource WHERE id = 1"
            ).fetchone()
            if resource is None or resource["state"] != "available":
                return None

            query = """SELECT jobs.*, execution.status AS execution_status,
                execution.max_attempts, execution.fence_epoch,
                execution.containment_contract,
                execution.resolved_plan_json,
                execution.privacy_compliance_json,
                admission.decision AS admission_decision,
                admission.decision_reason AS admission_reason,
        admission.admission_profile_json AS admission_profile_json,
        admission.workload_demand_json AS admission_demand_json,
               admission.profile_fingerprint AS admission_profile_fingerprint,
                admission.required_bytes_json AS admission_required_bytes_json
                FROM generation_jobs AS jobs
                JOIN execution_jobs AS execution
                  ON execution.job_id = jobs.job_id
                JOIN execution_admissions AS admission
                  ON admission.job_id = execution.job_id
                WHERE execution.status = 'queued'
                  AND jobs.adapter_id = ?
                  AND execution.containment_contract IS ?
        AND (
            admission.decision = 'queued'
            OR (? AND admission.decision = 'not_required')
        )
                  AND admission.decision_reason != 'resource_busy'"""
            parameters: list[object] = [
                adapter_id,
                containment_contract,
                int(allow_not_required),
            ]
            if job_id is not None:
                query += " AND jobs.job_id = ?"
                parameters.append(job_id)
            query += " ORDER BY execution.created_at, jobs.job_id"
            candidate = None
            privacy_rejection_job_id: str | None = None
            for row in connection.execute(query, tuple(parameters)).fetchall():
                if str(row["admission_decision"]) == "queued":
                    try:
                        AdmissionPersistence.validate_claim_evidence(
                            row["admission_profile_json"],
                            row["admission_demand_json"],
                    row["admission_profile_fingerprint"],
                row["admission_required_bytes_json"],
                            row["job_id"],
                        )
                    except ValueError as error:
                        raise RuntimeError(str(error)) from error
                if (
                    self._output_directory_for_job(
                        connection,
                        str(row["job_id"]),
                        str(row["effective_parameters_json"]),
                    )
                    != requested_directory
                ):
                    continue
                stored_privacy_json = row["privacy_compliance_json"]
                _decode_stored_privacy_compliance(stored_privacy_json, adapter_id)
                if (
                    adapter_configuration_json is None
                    or str(row["adapter_configuration_json"])
                    != adapter_configuration_json
                ):
                    raise GenerationError(
                        f"{_PRIVACY_CLAIM_CONFIGURATION_REQUIRED}: "
                        f"{row['job_id']}"
                    )
                if stored_privacy_json != privacy_compliance_json:
                    privacy_rejection_job_id = str(row["job_id"])
                    continue
                candidate = row
                break
            if candidate is None:
                if privacy_rejection_job_id is not None:
                    raise GenerationError(
                        f"{_PRIVACY_CLAIM_EVIDENCE_REQUIRED}: "
                        f"{privacy_rejection_job_id}"
                    )
                return None

            last_number = connection.execute(
                "SELECT max(attempt_number) FROM generation_attempts WHERE job_id = ?",
                (candidate["job_id"],),
            ).fetchone()[0] or 0
            attempt_number = int(last_number) + 1
            if attempt_number > int(candidate["max_attempts"]):
                connection.execute(
                    "UPDATE execution_jobs SET status = 'failed', retry_eligible = 0, "
                    "failure_message = 'attempt budget exhausted', updated_at = ? WHERE job_id = ?",
                    (timestamp, candidate["job_id"]),
                )
                return None
            claim_epoch = int(candidate["fence_epoch"]) + 1
            connection.execute(
                "UPDATE generation_jobs SET updated_at = ? WHERE job_id = ?",
                (timestamp, candidate["job_id"]),
            )
            connection.execute(
                """INSERT INTO generation_attempts
                   (attempt_id,job_id,attempt_number,status,adapter_id,
                    started_at,finished_at,error_message)
                   VALUES (?,?,?,'running',?,?,NULL,NULL)""",
                (
                    attempt_id,
                    candidate["job_id"],
                    attempt_number,
                    candidate["adapter_id"],
                    timestamp,
                ),
            )
            plan_json = str(candidate["resolved_plan_json"])
            connection.execute(
                """INSERT INTO execution_attempts
                   (attempt_id,job_id,attempt_number,status,owner_id,claim_epoch,
                    heartbeat_at,lease_expires_at,process_contained,containment_contract,failure_class,
                    termination_proven,plan_json,completed_at)
                   VALUES (?,?,?,'running',?,?,?,?,?,?,NULL,0,?,NULL)""",
                (
                    attempt_id,
                    candidate["job_id"],
                    attempt_number,
                    owner_id,
                    claim_epoch,
                    timestamp,
                    lease_expires_at,
                    int(process_contained),
                    containment_contract,
                    plan_json,
                ),
            )
            connection.execute(
                "UPDATE execution_jobs SET status = 'running', fence_epoch = ?, "
                "current_attempt_id = ?, retry_eligible = 0, failure_message = NULL, "
                "updated_at = ? WHERE job_id = ? AND status = 'queued'",
                (claim_epoch, attempt_id, timestamp, candidate["job_id"]),
            )
            connection.execute(
                """UPDATE execution_resource
                   SET state = 'claimed', job_id = ?, attempt_id = ?, owner_id = ?,
                       reason = NULL, updated_at = ? WHERE id = 1""",
                (candidate["job_id"], attempt_id, owner_id, timestamp),
            )
            if not AdmissionPersistence.reserve(
                connection,
                str(candidate["job_id"]),
                source_decision=str(candidate["admission_decision"]),
                timestamp=timestamp,
                required_bytes_json=str(candidate["admission_required_bytes_json"]),
            ):
                raise RuntimeError("admission reservation transition was rejected")
            plan = json.loads(plan_json)
            references = tuple(
                ResolvedReference(
                    artifact_id=str(item["artifact_id"]),
                    content_sha256=str(item["content_sha256"]),
                    path=Path(str(item["path"])),
                    role=str(item.get("role", "reference")),
                )
                for item in plan["references"]
            )
            return ExecutionClaim(
                job_id=str(candidate["job_id"]),
                attempt_id=attempt_id,
                attempt_number=attempt_number,
                owner_id=owner_id,
                claim_epoch=claim_epoch,
                max_attempts=int(candidate["max_attempts"]),
                resolved_prompt=str(plan["resolved_prompt"]),
                resolved_seed=int(plan["resolved_seed"]),
                width=int(plan["width"]),
                height=int(plan["height"]),
                output_slot=str(plan["output_slot"]),
                output_slot_id=str(plan["output_slot_id"]),
                references=references,
                adapter_id=str(candidate["adapter_id"]),
                adapter_configuration_json=str(candidate["adapter_configuration_json"]),
                resolved_output_directory=str(plan["resolved_output_directory"]),
                process_contained=process_contained,
                containment_contract=containment_contract,
                lease_expires_at=lease_expires_at,
            )

    def bind_attempt_containment(
        self, identity: AttemptUnitIdentity, *, timestamp: str
    ) -> None:
        """Pin one systemd invocation before the runner receives execute authority.

        The identity is written only while the attempt's claim and exact
        resolved invocation are current. A later cancellation fence does not
        erase it; that immutable identity is the only target accepted by the
        termination-only writer.
        """
        _require_systemd_broker_process()
        if not isinstance(identity, AttemptUnitIdentity):
            raise TypeError("identity must be an AttemptUnitIdentity")
        identity_json = backend_canonical_json(identity.to_mapping())
        identity_hash = identity_digest(identity)
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT attempts.owner_id, attempts.claim_epoch,
                          attempts.containment_contract, attempts.process_contained,
                          jobs.status AS job_status, jobs.fence_epoch,
                          jobs.current_attempt_id, backend.resolved_digest,
                          backend.state AS backend_state
                   FROM execution_attempts AS attempts
                   JOIN execution_jobs AS jobs ON jobs.job_id = attempts.job_id
                   JOIN backend_executions AS backend
                     ON backend.attempt_id = attempts.attempt_id
                   WHERE attempts.job_id = ? AND attempts.attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                row is None
                or row["job_status"] != "running"
                or row["current_attempt_id"] != identity.attempt_id
                or row["owner_id"] != identity.owner_id
                or row["claim_epoch"] != identity.claim_epoch
                or row["fence_epoch"] != identity.claim_epoch
                or row["containment_contract"] != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
                or row["process_contained"] != 1
                or row["resolved_digest"] != identity.resolved_digest
                or row["backend_state"] != "resolved"
            ):
                raise BackendEvidenceError(
                    "systemd containment identity does not match the active resolved attempt"
                )
            prior = connection.execute(
                "SELECT identity_json, identity_digest FROM execution_containment "
                "WHERE job_id = ? AND attempt_id = ?",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if prior is not None:
                if (
                    prior["identity_json"] != identity_json
                    or prior["identity_digest"] != identity_hash
                ):
                    raise BackendEvidenceError(
                        "attempt is already bound to another systemd invocation"
                    )
                lifecycle = connection.execute(
                    """SELECT identity_digest FROM systemd_output_lifecycle
                       WHERE job_id = ? AND attempt_id = ?""",
                    (identity.job_id, identity.attempt_id),
                ).fetchone()
                if lifecycle is None or lifecycle["identity_digest"] != identity_hash:
                    raise BackendEvidenceError(
                        "systemd output lifecycle is missing or identifies another invocation"
                    )
                self._systemd_evidence_ledger.bind_identity(identity)
                return
            self._systemd_evidence_ledger.bind_identity(identity)
            connection.execute(
                """INSERT INTO execution_containment
                   (attempt_id,job_id,identity_json,identity_digest,
                    termination_json,termination_at,created_at)
                   VALUES (?,?,?, ?,NULL,NULL,?)""",
                (
                    identity.attempt_id,
                    identity.job_id,
                    identity_json,
                    identity_hash,
                    timestamp,
                ),
            )
            connection.execute(
                """INSERT INTO systemd_output_lifecycle
                   (attempt_id,job_id,identity_digest,stream_complete,
                    cleanup_state,cleanup_validated,created_at,cleanup_at)
                   VALUES (?,?,?,0,'active',NULL,?,NULL)""",
                (identity.attempt_id, identity.job_id, identity_hash, timestamp),
            )

    def record_systemd_stream_complete(
        self,
        identity: AttemptUnitIdentity,
        *,
        owner_id: str,
        claim_epoch: int,
        timestamp: str,
    ) -> None:
        """Persist that this attempt's pinned scratch stream passed validation."""
        if not isinstance(identity, AttemptUnitIdentity):
            raise TypeError("identity must be an AttemptUnitIdentity")
        identity_hash = identity_digest(identity)
        with self._connection(transaction=True) as connection:
            self._require_backend_authority(
                connection, identity.job_id, identity.attempt_id,
                owner_id, claim_epoch,
            )
            row = connection.execute(
                """SELECT containment.identity_json, containment.identity_digest,
                          backend.resolved_digest, attempts.containment_contract
                   FROM execution_containment AS containment
                   JOIN backend_executions AS backend USING (attempt_id)
                   JOIN execution_attempts AS attempts USING (attempt_id)
                   WHERE containment.job_id = ? AND containment.attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                row is None
                or row["identity_json"] != backend_canonical_json(identity.to_mapping())
                or row["identity_digest"] != identity_hash
                or row["resolved_digest"] != identity.resolved_digest
                or row["containment_contract"] != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            ):
                raise BackendEvidenceError(
                    "validated stream does not match the current systemd attempt"
                )
            lifecycle = connection.execute(
                """SELECT identity_digest, stream_complete, cleanup_state
                   FROM systemd_output_lifecycle
                   WHERE job_id = ? AND attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                lifecycle is None
                or lifecycle["identity_digest"] != identity_hash
                or lifecycle["cleanup_state"] != "active"
            ):
                raise BackendEvidenceError(
                    "systemd output lifecycle is missing or no longer active"
                )
            if lifecycle["stream_complete"] == 1:
                return
            updated = connection.execute(
                """UPDATE systemd_output_lifecycle
                   SET stream_complete = 1
                   WHERE job_id = ? AND attempt_id = ?
                     AND identity_digest = ? AND stream_complete = 0
                     AND cleanup_state = 'active'""",
                (identity.job_id, identity.attempt_id, identity_hash),
            )
            if updated.rowcount != 1:
                raise BackendEvidenceError(
                    "systemd output stream completion could not be recorded"
                )

    def pending_systemd_output_cleanups(
        self, *, limit: int = 16, attempt_id: str | None = None
    ) -> tuple[PendingSystemdOutputCleanup, ...]:
        """Return a bounded batch of terminal attempts with resolved publications."""
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError("cleanup batch limit must be an integer from 1 through 64")
        if attempt_id is not None and (not isinstance(attempt_id, str) or not attempt_id):
            raise ValueError("attempt_id must be a nonempty string when provided")
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT lifecycle.job_id, lifecycle.attempt_id,
                          lifecycle.identity_digest AS lifecycle_identity_digest,
                          lifecycle.cleanup_validated,
                          containment.identity_json,
                          containment.identity_digest AS containment_identity_digest,
                          backend.resolved_digest, attempts.status AS attempt_status
                   FROM systemd_output_lifecycle AS lifecycle
                   JOIN execution_containment AS containment
                     ON containment.job_id = lifecycle.job_id
                    AND containment.attempt_id = lifecycle.attempt_id
                   JOIN backend_executions AS backend
                     ON backend.attempt_id = lifecycle.attempt_id
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = lifecycle.attempt_id
                   WHERE lifecycle.cleanup_state = 'pending'
                     AND ((lifecycle.cleanup_validated = 1
                           AND attempts.status = 'succeeded'
                           AND EXISTS (
                               SELECT 1 FROM artifact_publications AS publications
                               WHERE publications.attempt_id = lifecycle.attempt_id
                                 AND publications.state = 'committed'
                           ))
                       OR (lifecycle.cleanup_validated = 0
                           AND attempts.status IN ('failed','canceled')
                           AND NOT EXISTS (
                               SELECT 1 FROM artifact_publications AS publications
                               WHERE publications.attempt_id = lifecycle.attempt_id
                                 AND publications.state IN ('allocated','ready','committed')
                           )))
                     AND (? IS NULL OR lifecycle.attempt_id = ?)
                   ORDER BY lifecycle.created_at, lifecycle.attempt_id
                   LIMIT ?""",
                (attempt_id, attempt_id, limit),
            ).fetchall()
        pending: list[PendingSystemdOutputCleanup] = []
        for row in rows:
            try:
                identity = AttemptUnitIdentity.from_mapping(
                    json.loads(str(row["identity_json"]))
                )
                if (
                    identity.job_id != row["job_id"]
                    or identity.attempt_id != row["attempt_id"]
                    or identity.resolved_digest != row["resolved_digest"]
                    or identity_digest(identity) != row["containment_identity_digest"]
                    or row["containment_identity_digest"]
                    != row["lifecycle_identity_digest"]
                ):
                    raise ValueError("cleanup identity digest does not match")
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise BackendEvidenceError(
                    "pending systemd cleanup has a malformed attempt identity"
                ) from error
            with self._connection() as connection:
                termination_proven = self._attempt_cgroup_termination_evidence(
                    connection,
                    identity.job_id,
                    identity.attempt_id,
                    require_current_attempt=False,
                )
            if not termination_proven:
                continue
            ledger_identity = self._systemd_evidence_ledger.read_identity(
                identity.job_id, identity.attempt_id
            )
            if ledger_identity != identity:
                raise BackendEvidenceError(
                    "pending cleanup identity differs from the root evidence ledger"
                )
            pending.append(
                PendingSystemdOutputCleanup(
                    identity=identity,
                    validated=bool(row["cleanup_validated"]),
                )
            )
        return tuple(pending)

    def systemd_output_cleanup_authorized(
        self, identity: AttemptUnitIdentity, *, validated: bool
    ) -> bool:
        """Authorize cleanup for one terminal attempt and exact unit identity."""
        if not isinstance(identity, AttemptUnitIdentity) or type(validated) is not bool:
            return False
        identity_hash = identity_digest(identity)
        with self._connection() as connection:
            row = connection.execute(
                """SELECT lifecycle.cleanup_state, lifecycle.cleanup_validated,
                          lifecycle.identity_digest AS lifecycle_identity_digest,
                          containment.identity_digest AS containment_identity_digest,
                          containment.identity_json, attempts.status AS attempt_status,
                          EXISTS (SELECT 1 FROM artifact_publications
                                  WHERE attempt_id = lifecycle.attempt_id
                                    AND state = 'committed') AS has_committed_publication,
                          EXISTS (SELECT 1 FROM artifact_publications
                                  WHERE attempt_id = lifecycle.attempt_id
                                    AND state IN ('allocated','ready','committed')) AS has_unresolved_publication
                   FROM systemd_output_lifecycle AS lifecycle
                   JOIN execution_containment AS containment
                     ON containment.job_id = lifecycle.job_id
                    AND containment.attempt_id = lifecycle.attempt_id
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = lifecycle.attempt_id
                   WHERE lifecycle.job_id = ? AND lifecycle.attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                row is None
                or row["cleanup_state"] not in {"pending", "complete"}
                or row["cleanup_validated"] != int(validated)
                or row["lifecycle_identity_digest"] != identity_hash
                or row["containment_identity_digest"] != identity_hash
                or row["identity_json"]
                != backend_canonical_json(identity.to_mapping())
                or (validated and row["attempt_status"] != "succeeded")
                or (validated and not row["has_committed_publication"])
                or (not validated and row["attempt_status"] not in {"failed", "canceled"})
                or (not validated and row["has_unresolved_publication"])
            ):
                return False
            if not self._attempt_cgroup_termination_evidence(
                connection,
                identity.job_id,
                identity.attempt_id,
                require_current_attempt=False,
            ):
                return False
        return self._systemd_evidence_ledger.read_identity(
            identity.job_id, identity.attempt_id
        ) == identity

    def mark_systemd_output_cleanup_complete(
        self,
        identity: AttemptUnitIdentity,
        *,
        validated: bool,
        timestamp: str,
    ) -> None:
        """Record a broker-confirmed cleanup without changing execution authority."""
        if not isinstance(identity, AttemptUnitIdentity):
            raise TypeError("identity must be an AttemptUnitIdentity")
        if type(validated) is not bool:
            raise ValueError("validated must be a boolean")
        identity_hash = identity_digest(identity)
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT lifecycle.cleanup_state, lifecycle.cleanup_validated,
                          lifecycle.identity_digest AS lifecycle_identity_digest,
                          containment.identity_json,
                          containment.identity_digest AS containment_identity_digest,
                          attempts.status AS attempt_status,
                          EXISTS (SELECT 1 FROM artifact_publications
                                  WHERE attempt_id = lifecycle.attempt_id
                                    AND state = 'committed') AS has_committed_publication,
                          EXISTS (SELECT 1 FROM artifact_publications
                                  WHERE attempt_id = lifecycle.attempt_id
                                    AND state IN ('allocated','ready','committed')) AS has_unresolved_publication
                   FROM systemd_output_lifecycle AS lifecycle
                   JOIN execution_containment AS containment
                     ON containment.job_id = lifecycle.job_id
                    AND containment.attempt_id = lifecycle.attempt_id
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = lifecycle.attempt_id
                   WHERE lifecycle.job_id = ? AND lifecycle.attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                row is None
                or row["lifecycle_identity_digest"] != identity_hash
                or row["lifecycle_identity_digest"]
                != row["containment_identity_digest"]
                or row["identity_json"]
                != backend_canonical_json(identity.to_mapping())
                or (validated and row["attempt_status"] != "succeeded")
                or (validated and not row["has_committed_publication"])
                or (not validated and row["attempt_status"] not in {"failed", "canceled"})
                or (not validated and row["has_unresolved_publication"])
            ):
                raise BackendEvidenceError(
                    "cleanup acknowledgment identifies another systemd invocation"
                )
            current_state = str(row["cleanup_state"])
            current_validation = row["cleanup_validated"]
            if current_state == "complete":
                if current_validation != int(validated):
                    raise BackendEvidenceError(
                        "cleanup acknowledgment conflicts with completed lifecycle evidence"
                    )
                return
            if current_state == "pending" and current_validation != int(validated):
                raise BackendEvidenceError(
                    "cleanup acknowledgment conflicts with pending lifecycle evidence"
                )
            if not self._attempt_cgroup_termination_evidence(
                connection,
                identity.job_id,
                identity.attempt_id,
                require_current_attempt=False,
            ):
                raise BackendEvidenceError(
                    "cleanup acknowledgment requires verified whole-cgroup termination"
                )
            connection.execute(
                """UPDATE systemd_output_lifecycle
                   SET cleanup_state = 'complete',
                       cleanup_validated = ?, cleanup_at = ?
                   WHERE job_id = ? AND attempt_id = ?
                     AND cleanup_state IN ('active','pending')""",
                (
                    int(validated), timestamp,
                    identity.job_id, identity.attempt_id,
                ),
            )

    def attempt_containment_identity(
        self, job_id: str, attempt_id: str
    ) -> AttemptUnitIdentity | None:
        """Return the validated immutable service identity, if it was bound."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT identity_json, identity_digest, resolved_digest
                   FROM execution_containment
                   JOIN backend_executions USING (attempt_id)
                   WHERE execution_containment.job_id = ?
                     AND execution_containment.attempt_id = ?""",
                (job_id, attempt_id),
            ).fetchone()
        if row is None:
            return None
        try:
            identity = AttemptUnitIdentity.from_mapping(
                json.loads(str(row["identity_json"]))
            )
            if (
                identity_digest(identity) != row["identity_digest"]
                or identity.resolved_digest != row["resolved_digest"]
                or identity.job_id != job_id
                or identity.attempt_id != attempt_id
            ):
                raise ValueError("stored identity digest or attempt binding changed")
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError(
                "stored systemd attempt identity is malformed"
            ) from error
        ledger_identity = self._systemd_evidence_ledger.read_identity(
            job_id, attempt_id
        )
        if ledger_identity is None:
            return None
        if ledger_identity != identity:
            raise BackendEvidenceError(
                "stored systemd identity differs from the root evidence ledger"
            )
        return identity

    def attempt_recovery_cleanup_authorized(
        self, identity: AttemptUnitIdentity
    ) -> bool:
        """Require a durable publication fence before recovery removes scratch."""
        if not isinstance(identity, AttemptUnitIdentity):
            raise TypeError("identity must be an AttemptUnitIdentity")
        with self._connection() as connection:
            row = connection.execute(
                """SELECT jobs.status AS job_status, jobs.current_attempt_id,
                          jobs.fence_epoch, attempts.claim_epoch,
                          attempts.status AS attempt_status,
                          resource.state AS resource_state,
                          resource.job_id AS resource_job_id,
                          resource.attempt_id AS resource_attempt_id
                   FROM execution_jobs AS jobs
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = jobs.current_attempt_id
                   JOIN execution_resource AS resource ON resource.id = 1
                   JOIN execution_containment AS containment
                     ON containment.attempt_id = attempts.attempt_id
                   WHERE jobs.job_id = ? AND attempts.attempt_id = ?
                     AND containment.identity_digest = ?""",
                (
                    identity.job_id,
                    identity.attempt_id,
                    identity_digest(identity),
                ),
            ).fetchone()
            if row is None or row["current_attempt_id"] != identity.attempt_id:
                return False
            if row["resource_job_id"] != identity.job_id or row["resource_attempt_id"] != identity.attempt_id:
                return False
            if row["resource_state"] not in {"claimed", "quarantined"}:
                return False
            if connection.execute(
                """SELECT 1 FROM artifact_publications WHERE job_id = ?
                   AND state IN ('allocated','ready','committed')""",
                (identity.job_id,),
            ).fetchone() is not None:
                return False
            fenced_worker = (
                row["job_status"] in {"running", "canceled"}
                and row["attempt_status"] == "running"
                and row["fence_epoch"] == row["claim_epoch"] + 1
            )
            terminal_attempt = (
                row["attempt_status"] in {"failed", "canceled"}
                and row["resource_state"] == "quarantined"
            )
            return bool(fenced_worker or terminal_attempt)

    def record_attempt_termination_evidence(
        self,
        identity: AttemptUnitIdentity,
        evidence: CgroupTerminationEvidence,
        *,
        timestamp: str,
    ) -> None:
        """Persist exact cgroup-empty proof without restoring fenced authority.

        This writer validates only the immutable attempt and unit identity. It
        cannot record engine launch/exit, extend a lease, or create
        publication authority. Identical retries are idempotent.
        """
        _require_systemd_broker_process()
        if not isinstance(identity, AttemptUnitIdentity):
            raise TypeError("identity must be an AttemptUnitIdentity")
        if not isinstance(evidence, CgroupTerminationEvidence):
            raise TypeError("evidence must be CgroupTerminationEvidence")
        if evidence.identity != identity:
            raise BackendEvidenceError(
                "cgroup termination evidence names a different unit invocation"
            )
        identity_json = backend_canonical_json(identity.to_mapping())
        proof_json = backend_canonical_json(evidence.to_mapping())
        identity_hash = identity_digest(identity)
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT containment.identity_json, containment.identity_digest,
                          containment.termination_json, attempts.containment_contract,
                          jobs.current_attempt_id, backend.resolved_digest
                   FROM execution_containment AS containment
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = containment.attempt_id
                   JOIN execution_jobs AS jobs ON jobs.job_id = containment.job_id
                   JOIN backend_executions AS backend
                     ON backend.attempt_id = containment.attempt_id
                   WHERE containment.job_id = ? AND containment.attempt_id = ?""",
                (identity.job_id, identity.attempt_id),
            ).fetchone()
            if (
                row is None
                or row["current_attempt_id"] != identity.attempt_id
                or row["containment_contract"] != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
                or row["identity_json"] != identity_json
                or row["identity_digest"] != identity_hash
                or row["resolved_digest"] != identity.resolved_digest
            ):
                raise BackendEvidenceError(
                    "termination evidence does not match the current attempt containment identity"
                )
            if (
                row["termination_json"] is not None
                and row["termination_json"] != proof_json
            ):
                raise BackendEvidenceError(
                    "attempt already has different cgroup termination evidence"
                )
            self._systemd_evidence_ledger.record_termination(
                identity, evidence, timestamp=timestamp
            )
            if row["termination_json"] is not None:
                return
            connection.execute(
                """UPDATE execution_containment
                   SET termination_json = ?, termination_at = ?
                   WHERE job_id = ? AND attempt_id = ?
                     AND termination_json IS NULL""",
                (proof_json, timestamp, identity.job_id, identity.attempt_id),
            )
            cancellation = connection.execute(
                """SELECT state, attempt_id FROM execution_cancellations
                   WHERE job_id = ? AND claim_epoch = ?""",
                (identity.job_id, identity.claim_epoch),
            ).fetchone()
            if (
                cancellation is not None
                and cancellation["state"] == "requested"
                and cancellation["attempt_id"] == identity.attempt_id
            ):
                connection.execute(
                    """UPDATE execution_cancellations
                       SET state = 'acknowledged', acknowledged_at = ?
                       WHERE job_id = ? AND claim_epoch = ? AND state = 'requested'""",
                    (timestamp, identity.job_id, identity.claim_epoch),
                )

    def cancel_execution(self, job_id: str, timestamp: str) -> str:
        """Fence publication and durably record the cancellation lifecycle."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT execution.status AS execution_status,
                          execution.current_attempt_id,
                          execution.fence_epoch,
                          attempts.claim_epoch AS attempt_claim_epoch,
                          resource.state AS resource_state,
                          attempts.status AS attempt_status
                   FROM execution_jobs AS execution
                   JOIN execution_resource AS resource ON resource.id = 1
                   LEFT JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = execution.current_attempt_id
                   WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            if row["execution_status"] == "canceled":
                prior_cancellation = connection.execute(
                    """SELECT state FROM execution_cancellations
                       WHERE job_id = ? AND attempt_id IS ?
                       ORDER BY claim_epoch DESC LIMIT 1""",
                    (job_id, row["current_attempt_id"]),
                ).fetchone()
                if prior_cancellation is not None:
                    return str(prior_cancellation["state"])
            cancellation_epoch = (
                int(row["fence_epoch"]) + 1
                if row["execution_status"] == "queued"
                or (
                    row["execution_status"] == "canceled"
                    and not (
                        row["resource_state"] == "claimed"
                        and row["attempt_status"] == "running"
                    )
                )
                or row["attempt_claim_epoch"] is None
                else int(row["attempt_claim_epoch"])
            )
            prior = connection.execute(
                """SELECT state FROM execution_cancellations
                   WHERE job_id = ? AND claim_epoch = ?""",
                (job_id, cancellation_epoch),
            ).fetchone()
            if prior is not None:
                return str(prior["state"])
            if row["execution_status"] in {"succeeded"}:
                connection.execute(
                    """INSERT INTO execution_cancellations
                       (job_id,attempt_id,claim_epoch,state,requested_at,acknowledged_at,too_late_at)
                       VALUES (?,?,?,'too_late',NULL,NULL,?)""",
                    (job_id, row["current_attempt_id"], cancellation_epoch, timestamp),
                )
                return "too_late"
            if row["execution_status"] == "queued":
                connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'canceled', retry_eligible = 0,
                           failure_message = 'canceled before dispatch', updated_at = ?
                       WHERE job_id = ? AND status = 'queued'""",
                    (timestamp, job_id),
                )
                connection.execute(
                    "UPDATE generation_jobs SET status = 'failed', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                AdmissionPersistence.cancel_before_dispatch(connection, job_id, timestamp)
                connection.execute(
                    """INSERT INTO execution_cancellations
                       (job_id,attempt_id,claim_epoch,state,requested_at,acknowledged_at,too_late_at)
                       VALUES (?,NULL,?,'acknowledged',?,?,NULL)""",
                    (job_id, cancellation_epoch, timestamp, timestamp),
                )
                return "acknowledged"
            if row["execution_status"] == "running":
                connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'canceled', fence_epoch = fence_epoch + 1,
                           retry_eligible = 0,
                           failure_message = 'canceled during adapter invocation',
                           updated_at = ? WHERE job_id = ? AND status = 'running'""",
                    (timestamp, job_id),
                )
                connection.execute(
                    "UPDATE generation_jobs SET status = 'failed', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                connection.execute(
                    """INSERT INTO execution_cancellations
                       (job_id,attempt_id,claim_epoch,state,requested_at,acknowledged_at,too_late_at)
                       VALUES (?,?,?,'requested',?,NULL,NULL)""",
                    (job_id, row["current_attempt_id"], cancellation_epoch, timestamp),
                )
                return "requested"
            connection.execute(
                """INSERT INTO execution_cancellations
                   (job_id,attempt_id,claim_epoch,state,requested_at,acknowledged_at,too_late_at)
                   VALUES (?,?,?,'too_late',NULL,NULL,?)""",
                (job_id, row["current_attempt_id"], cancellation_epoch, timestamp),
            )
            return "too_late"

    def acknowledge_execution_cancellation(
        self, job_id: str, attempt_id: str, *, timestamp: str
    ) -> bool:
        """Acknowledge a fenced cancellation only after validated termination."""
        with self._connection(transaction=True) as connection:
            attempt = connection.execute(
                "SELECT claim_epoch FROM execution_attempts WHERE job_id = ? AND attempt_id = ?",
                (job_id, attempt_id),
            ).fetchone()
            if attempt is None:
                return False
            row = connection.execute(
                """SELECT cancellations.state, cancellations.attempt_id,
                          cancellations.claim_epoch,
                          jobs.status AS job_status, jobs.current_attempt_id,
                          attempts.claim_epoch AS attempt_claim_epoch
                   FROM execution_cancellations AS cancellations
                   JOIN execution_jobs AS jobs ON jobs.job_id = cancellations.job_id
                   LEFT JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = cancellations.attempt_id
                   WHERE cancellations.job_id = ? AND cancellations.attempt_id = ?
                     AND cancellations.claim_epoch = ?""",
                (job_id, attempt_id, attempt["claim_epoch"]),
            ).fetchone()
            if (
                row is None
                or row["state"] == "acknowledged"
                or row["state"] != "requested"
                or row["attempt_id"] != attempt_id
                or row["claim_epoch"] != row["attempt_claim_epoch"]
                or row["current_attempt_id"] != attempt_id
                or row["job_status"] != "canceled"
                or not self._attempt_termination_proven(connection, job_id, attempt_id)
            ):
                return bool(row is not None and row["state"] == "acknowledged")
            updated = connection.execute(
                """UPDATE execution_cancellations
                   SET state = 'acknowledged', acknowledged_at = ?
                   WHERE job_id = ? AND claim_epoch = ? AND state = 'requested'""",
                (timestamp, job_id, row["claim_epoch"]),
            )
            return updated.rowcount == 1

    def retry_execution(self, job_id: str, timestamp: str) -> bool:
        """Acknowledge an eligible bounded retry, requeueing it only if needed."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT execution.status, execution.retry_eligible,
                          execution.max_attempts, resource.state AS resource_state,
                          admission.decision AS admission_decision,
                          (SELECT count(*) FROM execution_attempts
                           WHERE job_id = ?) AS attempt_count
                   FROM execution_jobs AS execution
                   JOIN execution_resource AS resource ON resource.id = 1
                JOIN execution_admissions AS admission
                     ON admission.job_id = execution.job_id
                   WHERE execution.job_id = ?""",
                (job_id, job_id),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            if (
                row["status"] not in {"failed", "queued"}
                or not bool(row["retry_eligible"])
                or row["resource_state"] != "available"
                or int(row["attempt_count"]) >= int(row["max_attempts"])
                or row["admission_decision"] is None
            ):
                return False
            if row["status"] == "failed":
                updated = connection.execute(
                    """UPDATE execution_jobs
                       SET status = 'queued', retry_eligible = 0,
                           failure_message = NULL, updated_at = ?
                       WHERE job_id = ? AND status = 'failed'""",
                    (timestamp, job_id),
                )
                if updated.rowcount != 1:
                    return False
                connection.execute(
                    "UPDATE generation_jobs SET status = 'running', updated_at = ? WHERE job_id = ?",
                    (timestamp, job_id),
                )
                if row["admission_decision"] != "not_required" and not AdmissionPersistence.requeue_after_safe_retry(
                    connection, job_id, timestamp
                ):
                    raise RuntimeError("admission retry transition was rejected")
            else:
                admission = AdmissionPersistence.snapshot(connection, job_id)
                if admission is None or admission.decision not in {
                "queued",
                "not_required",
            }:
                    return False
            return True

    def resource_snapshot(self) -> dict[str, object]:
        """Return the persisted heavyweight-resource reservation."""
        with self._connection() as connection:
            row = AdmissionPersistence.resource_snapshot(connection)
            if row is None:
                raise RuntimeError("execution resource reservation row is missing")
            return row

    def inspect_admission(self, job_id: str) -> AdmissionInspection | None:
        """Read admission and its owned reservation from one transaction."""
        with self._connection(read_transaction=True) as connection:
            return AdmissionPersistence.inspect(connection, job_id)

    def current_attempt(self, job_id: str) -> dict[str, object] | None:
        """Return private recovery metadata for the current attempt."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT attempts.*, execution.status AS job_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.containment_contract AS job_containment_contract
                   FROM execution_jobs AS execution
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = execution.current_attempt_id
                   WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            return None if row is None else dict(row)

    def assert_attempt_authority(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
    ) -> bool:
        """Read whether a claim is still the job's current publication authority."""
        with self._connection() as connection:
            return self._attempt_authorized(connection, job_id, attempt_id, owner_id, claim_epoch)

    def fence_attempt_for_recovery(
        self, job_id: str, attempt_id: str, *, timestamp: str
    ) -> dict[str, object] | None:
        """Revoke a lost worker's publication authority without guessing termination."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT jobs.status, jobs.current_attempt_id, jobs.fence_epoch,
                          attempts.owner_id, attempts.claim_epoch, attempts.status AS attempt_status,
                          resource.state AS resource_state, resource.attempt_id AS resource_attempt
                   FROM execution_jobs AS jobs
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = jobs.current_attempt_id
                   JOIN execution_resource AS resource ON resource.id = 1
                   WHERE jobs.job_id = ? AND attempts.attempt_id = ?""",
                (job_id, attempt_id),
            ).fetchone()
            if row is None or row["resource_attempt"] != attempt_id:
                return None
            if row["status"] == "running" and row["attempt_status"] == "running":
                if row["fence_epoch"] == row["claim_epoch"]:
                    connection.execute(
                        """UPDATE execution_jobs
                           SET fence_epoch = fence_epoch + 1, retry_eligible = 0,
                               failure_message = 'worker loss fenced publication',
                               updated_at = ?
                           WHERE job_id = ? AND status = 'running'
                             AND current_attempt_id = ? AND fence_epoch = ?""",
                        (
                            timestamp,
                            job_id,
                            attempt_id,
                            row["claim_epoch"],
                        ),
                    )
            return dict(row)

    @staticmethod
    def _attempt_authorized(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
    ) -> bool:
        if owner_id is None or claim_epoch is None:
            return False
        return connection.execute(
            """SELECT 1 FROM execution_jobs AS jobs
               JOIN execution_attempts AS attempts
                 ON attempts.attempt_id = jobs.current_attempt_id
               WHERE jobs.job_id = ? AND jobs.current_attempt_id = ?
                 AND jobs.fence_epoch = ? AND attempts.owner_id = ?
                 AND attempts.claim_epoch = ? AND attempts.status = 'running'""",
            (job_id, attempt_id, claim_epoch, owner_id, claim_epoch),
        ).fetchone() is not None

    def renew_attempt(
        self,
        job_id: str,
        attempt_id: str,
        owner_id: str,
        claim_epoch: int,
        heartbeat_at: str,
        lease_expires_at: str,
    ) -> bool:
        """Extend one still-current lease and report whether authority remains."""
        with self._connection(transaction=True) as connection:
            if not self._attempt_authorized(
                connection, job_id, attempt_id, owner_id, claim_epoch
            ):
                return False
            updated = connection.execute(
                """UPDATE execution_attempts
                   SET heartbeat_at = ?, lease_expires_at = ?
                   WHERE attempt_id = ? AND job_id = ? AND owner_id = ?
                     AND claim_epoch = ? AND status = 'running'""",
                (heartbeat_at, lease_expires_at, attempt_id, job_id, owner_id, claim_epoch),
            )
            return updated.rowcount == 1

    @staticmethod
    def _attempt_requires_process_tree_resource_release(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
    ) -> bool:
        """Return whether the admitted adapter denies direct-child release.

        The immutable adapter identities on the admitted job and its attempt
        must agree before configuration is considered. A ComfyUI identity
        always requires process-tree evidence, even when an older configuration
        omitted the release declaration. Missing or malformed persisted
        configuration fails closed. The helper is consulted only after a
        launched child has a termination observation; pre-spawn failures have
        no descendant process to contain.
        """
        row = connection.execute(
            """SELECT jobs.adapter_id AS admitted_adapter_id,
                      admitted_attempt.adapter_id AS attempt_adapter_id,
                      jobs.adapter_configuration_json
            FROM generation_jobs AS jobs
            JOIN generation_attempts AS admitted_attempt
              ON admitted_attempt.job_id = jobs.job_id
            JOIN execution_attempts AS attempts
              ON attempts.attempt_id = admitted_attempt.attempt_id
            WHERE jobs.job_id = ? AND attempts.attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if row is None:
            return True
        admitted_adapter_id = row["admitted_adapter_id"]
        attempt_adapter_id = row["attempt_adapter_id"]
        if (
            not isinstance(admitted_adapter_id, str)
            or not isinstance(attempt_adapter_id, str)
            or not admitted_adapter_id
            or admitted_adapter_id != attempt_adapter_id
        ):
            return True
        try:
            configuration = json.loads(str(row["adapter_configuration_json"]))
        except (TypeError, ValueError):
            return True
        if not isinstance(configuration, Mapping):
            return True
        if (
            configuration.get("backend_kind") == COMFYUI_RESOLVED_BACKEND_KIND
            and admitted_adapter_id != COMFYUI_ADAPTER_ID
        ):
            return True
        return configuration_requires_process_tree_resource_release(
            configuration,
            adapter_id=admitted_adapter_id,
        )

    @classmethod
    def _resource_release_proven(
        cls,
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        *,
        containment_contract: str | None,
        effective_termination_proven: bool,
        direct_child_termination_proven: bool,
        prelaunch_refusal: bool = False,
    ) -> bool:
        """Return whether trusted evidence permits reuse of the T06 lease.

        A direct-child observation proves only that the application's child
        was reaped. Adapters that require process-tree evidence must remain
        quarantined because this supervisor does not observe descendants. A
        legacy containment declaration cannot override that adapter policy.
        A current process may assert that it never started a child; that
        assertion releases only while no durable launch evidence exists.
        """
        if prelaunch_refusal:
            return effective_termination_proven and not cls._attempt_has_launch_evidence(
                connection, job_id, attempt_id
            )
        if cls._attempt_requires_process_tree_resource_release(
            connection, job_id, attempt_id
        ):
            return False
        if not effective_termination_proven:
            return False
        if containment_contract is not None:
            return True
        return direct_child_termination_proven

    @staticmethod
    def _attempt_has_launch_evidence(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
    ) -> bool:
        """Return whether durable evidence records a process launch."""
        row = connection.execute(
            "SELECT state FROM backend_executions "
            "WHERE job_id = ? AND attempt_id = ?",
            (job_id, attempt_id),
        ).fetchone()
        if row is None:
            return False
        state = str(row["state"])
        if state not in EXECUTION_STATES:
            raise BackendEvidenceError("stored backend execution has unknown state")
        return state in {"launched", "observed"}

    @staticmethod
    def _attempt_termination_evidence(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
    ) -> bool:
        """Return whether a validated reaped-child observation is persisted.

        Missing or pre-observation rows are not proof. Malformed persisted
        evidence raises so finalization cannot convert it into a release.
        """
        row = connection.execute(
            """SELECT executions.*,
                      admitted.adapter_configuration_json AS adapter_configuration_json
               FROM backend_executions AS executions
               JOIN generation_jobs AS admitted
                 ON admitted.job_id = executions.job_id
               WHERE executions.job_id = ? AND executions.attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if row is None:
            return False
        record = SQLiteStore._decode_backend_execution(row)
        if record["state"] != "observed":
            return False
        observed = record["observed"]
        if not isinstance(observed, dict):
            raise BackendEvidenceError("observed backend execution evidence is missing")
        return observation_proves_reaped_child(observed)

    def _attempt_cgroup_termination_evidence(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        *,
        require_current_attempt: bool = True,
    ) -> bool:
        """Validate the persisted whole-cgroup proof independently of engine exit."""
        row = connection.execute(
            """SELECT containment.identity_json, containment.identity_digest,
                      containment.termination_json, attempts.containment_contract,
                      jobs.current_attempt_id, backend.resolved_digest
               FROM execution_containment AS containment
               JOIN execution_attempts AS attempts
                 ON attempts.attempt_id = containment.attempt_id
               JOIN execution_jobs AS jobs ON jobs.job_id = containment.job_id
               JOIN backend_executions AS backend
                 ON backend.attempt_id = containment.attempt_id
               WHERE containment.job_id = ? AND containment.attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if row is None:
            return False
        if (
            row["containment_contract"] != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            or (require_current_attempt and row["current_attempt_id"] != attempt_id)
        ):
            return False
        try:
            identity_mapping = json.loads(str(row["identity_json"]))
            identity = AttemptUnitIdentity.from_mapping(identity_mapping)
            if (
                identity.job_id != job_id
                or identity.attempt_id != attempt_id
                or identity.resolved_digest != row["resolved_digest"]
                or identity_digest(identity) != row["identity_digest"]
            ):
                raise ValueError("stored containment identity does not match its attempt")
            proof_json = row["termination_json"]
            ledger_identity = self._systemd_evidence_ledger.read_identity(
                job_id, attempt_id
            )
            if ledger_identity is None:
                return False
            if ledger_identity != identity:
                raise ValueError("root evidence ledger names another invocation")
            ledger_proof = self._systemd_evidence_ledger.read_termination(identity)
            if ledger_proof is None:
                return False
            if proof_json is not None:
                database_proof = CgroupTerminationEvidence.from_mapping(
                    json.loads(str(proof_json))
                )
                if database_proof != ledger_proof:
                    raise ValueError(
                        "job database cgroup proof differs from root ledger"
                    )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError(
                "stored systemd containment evidence is malformed"
            ) from error
        return True

    def termination_evidence_proven(self, job_id: str, attempt_id: str) -> bool:
        """Read whether the exact engine child has a durable exit observation."""
        with self._connection() as connection:
            return self._attempt_termination_evidence(connection, job_id, attempt_id)

    def attempt_termination_proven(self, job_id: str, attempt_id: str) -> bool:
        """Return termination proof under the attempt's persisted adapter policy.

        ComfyUI attempts accept only validated direct-child observation. A
        containment contract cannot substitute for process-tree evidence.
        Historical adapters retain their trusted contract-or-observation
        behavior.
        """
        with self._connection() as connection:
            return self._attempt_termination_proven(
                connection, job_id, attempt_id
            )

    def release_quarantined_attempt(
        self, job_id: str, attempt_id: str, *, timestamp: str
    ) -> bool:
        """Release a fenced terminal attempt after late verified cgroup proof."""
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                """SELECT resource.state AS resource_state,
                          resource.job_id AS resource_job_id,
                          resource.attempt_id AS resource_attempt_id,
                          jobs.current_attempt_id, attempts.status AS attempt_status,
                          attempts.claim_epoch,
                          attempts.containment_contract
                   FROM execution_resource AS resource
                   JOIN execution_jobs AS jobs ON jobs.job_id = resource.job_id
                   JOIN execution_attempts AS attempts
                     ON attempts.attempt_id = resource.attempt_id
                   WHERE resource.id = 1 AND resource.job_id = ?
                     AND resource.attempt_id = ?""",
                (job_id, attempt_id),
            ).fetchone()
            if (
                row is None
                or row["resource_state"] != "quarantined"
                or row["resource_job_id"] != job_id
                or row["resource_attempt_id"] != attempt_id
                or row["current_attempt_id"] != attempt_id
                or row["attempt_status"] not in {"failed", "canceled"}
                or row["containment_contract"] != SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
                or not self._attempt_termination_proven(connection, job_id, attempt_id)
            ):
                return False
            if connection.execute(
                """SELECT 1 FROM artifact_publications WHERE job_id = ?
                   AND state IN ('ready','committed')""",
                (job_id,),
            ).fetchone() is not None:
                return False
            admission = AdmissionPersistence.snapshot(connection, job_id)
            if admission is None:
                return False
            connection.execute(
                """UPDATE execution_attempts SET termination_proven = 1
                   WHERE attempt_id = ? AND job_id = ?""",
                (attempt_id, job_id),
            )
            connection.execute(
                """UPDATE execution_resource
                   SET state = 'available', job_id = NULL, attempt_id = NULL,
                       owner_id = NULL, reason = NULL, updated_at = ?
                   WHERE id = 1 AND state = 'quarantined'
                     AND job_id = ? AND attempt_id = ?""",
                (timestamp, job_id, attempt_id),
            )
            if not AdmissionPersistence.finish(
                connection,
                job_id,
                decision="released",
                reason="verified_cgroup_termination_and_reconciled_publication",
                timestamp=timestamp,
            ):
                raise RuntimeError("admission release transition was rejected")
            connection.execute(
                """UPDATE execution_cancellations
                   SET state = 'acknowledged', acknowledged_at = ?
                   WHERE job_id = ? AND attempt_id = ? AND claim_epoch = ?
                     AND state = 'requested'""",
                (timestamp, job_id, attempt_id, row["claim_epoch"]),
            )
            return True

    def _attempt_termination_proven(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
    ) -> bool:
        direct_child_termination_proven = self._attempt_termination_evidence(
            connection, job_id, attempt_id
        )
        if self._attempt_requires_process_tree_resource_release(
            connection, job_id, attempt_id
        ):
            return direct_child_termination_proven
        row = connection.execute(
            """SELECT containment_contract, process_contained
               FROM execution_attempts WHERE job_id = ? AND attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if row is None:
            return direct_child_termination_proven
        contract = row["containment_contract"]
        if contract == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT:
            return self._attempt_cgroup_termination_evidence(
                connection, job_id, attempt_id
            )
        return direct_child_termination_proven or (
            isinstance(contract, str)
            and bool(contract)
            and bool(row["process_contained"])
        )

    @staticmethod
    def _decode_backend_execution(row: sqlite3.Row) -> dict[str, object]:
        """Validate one persisted execution row and return its full records."""
        attempt_id = str(row["attempt_id"])
        try:
            resolved = json.loads(str(row["resolved_json"]))
            launch = (
                None if row["launch_json"] is None else json.loads(str(row["launch_json"]))
            )
            observed = (
                None
                if row["observed_json"] is None
                else json.loads(str(row["observed_json"]))
            )
        except (TypeError, ValueError) as error:
            raise BackendEvidenceError(
                "stored backend execution evidence is not valid JSON"
            ) from error
        if not isinstance(resolved, dict):
            raise BackendEvidenceError("stored resolved evidence must be an object")
        if (
            type(resolved.get("schema_version")) is int
            and resolved.get("schema_version") in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS
        ):
            try:
                persisted_approval = _persisted_workflow_approval(
                    row["adapter_configuration_json"]
                )
            except (IndexError, KeyError) as error:
                raise BackendEvidenceError(
                    "stored ComfyUI execution is missing its persisted workflow approval"
                ) from error
            validate_resolved_record(
                resolved,
                expected_workflow_approval=persisted_approval,
            )
        else:
            validate_resolved_record(resolved)
        if resolved.get("attempt_id") != attempt_id:
            raise BackendEvidenceError("resolved evidence identifies a different attempt")
        if resolved.get("candidate_id") != str(row["candidate_id"]):
            raise BackendEvidenceError("resolved evidence candidate identity diverged")
        if resolved.get("backend_kind") != str(row["backend_kind"]):
            raise BackendEvidenceError("resolved evidence backend kind diverged")
        if backend_digest(resolved) != str(row["resolved_digest"]):
            raise BackendEvidenceError("resolved evidence digest does not match its bytes")
        state = str(row["state"])
        if state not in EXECUTION_STATES:
            raise BackendEvidenceError("stored backend execution has an unknown state")
        if state in {"launched", "observed"}:
            if launch is None or row["launch_at"] is None:
                raise BackendEvidenceError("launched evidence is missing its launch record")
            if not isinstance(launch, dict):
                raise BackendEvidenceError("stored launch evidence must be an object")
            validate_launch_record(launch)
            if launch.get("attempt_id") != attempt_id:
                raise BackendEvidenceError("launch evidence identifies a different attempt")
            SQLiteStore._validate_launch_matches_resolved(resolved, launch)
        elif launch is not None or row["launch_at"] is not None:
            raise BackendEvidenceError("resolved evidence carries an unexpected launch record")
        if state == "observed":
            if observed is None or row["observed_at"] is None:
                raise BackendEvidenceError("observed evidence is missing its observation record")
            if not isinstance(observed, dict):
                raise BackendEvidenceError("stored observation evidence must be an object")
            validate_observed_record(observed)
            if observed.get("attempt_id") != attempt_id:
                raise BackendEvidenceError(
                    "observation evidence identifies a different attempt"
                )
        elif observed is not None or row["observed_at"] is not None:
            raise BackendEvidenceError(
                "pre-observation evidence carries an unexpected observation record"
            )
        return {
            "job_id": str(row["job_id"]),
            "attempt_id": attempt_id,
            "backend_kind": str(row["backend_kind"]),
            "candidate_id": str(row["candidate_id"]),
            "state": state,
            "resolved_digest": str(row["resolved_digest"]),
            "resolved_at": str(row["resolved_at"]),
            "launch_at": None if row["launch_at"] is None else str(row["launch_at"]),
            "observed_at": (
                None if row["observed_at"] is None else str(row["observed_at"])
            ),
            "resolved": resolved,
            "launch": launch,
            "observed": observed,
        }

    @staticmethod
    def _validate_launch_matches_resolved(
        resolved: Mapping[str, object], launch: Mapping[str, object]
    ) -> None:
        """Refuse launch evidence that names a different invocation.

        The launch record is written by the application-owned supervisor with
        the exact argv and environment it spawned. Comparing it with the
        immutable resolved plan ties a later observation to the process the
        pre-dispatch policy approved.
        """
        if launch.get("argv") != resolved.get("argv"):
            raise BackendEvidenceError(
                "launch argv does not match the resolved invocation"
            )
        environment = resolved.get("environment")
        if not isinstance(environment, Mapping):
            raise BackendEvidenceError("resolved environment evidence is malformed")
        names = environment.get("names")
        values = environment.get("values")
        if not isinstance(names, list) or not isinstance(values, Mapping):
            raise BackendEvidenceError("resolved environment evidence is malformed")
        launch_environment = launch.get("environment")
        if not isinstance(launch_environment, Mapping):
            raise BackendEvidenceError("launch environment evidence is malformed")
        if set(launch_environment) != set(names):
            raise BackendEvidenceError(
                "launch environment names do not match the resolved invocation"
            )
        for name, value in values.items():
            if launch_environment.get(name) != value:
                raise BackendEvidenceError(
                    "launch environment values do not match the resolved invocation"
                )

    def get_backend_execution(
        self,
        job_id: str,
        attempt_id: str | None = None,
    ) -> dict[str, object] | None:
        """Return full validated execution records for one attempt.

        With no explicit attempt, only the job's current attempt is considered.
        A missing evidence row returns ``None``; a malformed row raises.
        """
        with self._connection() as connection:
            if attempt_id is None:
                row = connection.execute(
                    """SELECT executions.*,
                              admitted.adapter_configuration_json AS adapter_configuration_json
                       FROM execution_jobs AS jobs
                       JOIN generation_jobs AS admitted
                         ON admitted.job_id = jobs.job_id
                       JOIN backend_executions AS executions
                         ON executions.attempt_id = jobs.current_attempt_id
                       WHERE jobs.job_id = ?""",
                    (job_id,),
                ).fetchone()
            else:
                attempt = connection.execute(
                    "SELECT 1 FROM execution_attempts WHERE job_id = ? AND attempt_id = ?",
                    (job_id, attempt_id),
                ).fetchone()
                if attempt is None:
                    raise RecordNotFoundError(
                        f"attempt {attempt_id} does not belong to job {job_id}"
                    )
                row = connection.execute(
                    """SELECT executions.*,
                              admitted.adapter_configuration_json AS adapter_configuration_json
                       FROM backend_executions AS executions
                       JOIN generation_jobs AS admitted
                         ON admitted.job_id = executions.job_id
                       WHERE executions.job_id = ? AND executions.attempt_id = ?""",
                    (job_id, attempt_id),
                ).fetchone()
        if row is None:
            return None
        return self._decode_backend_execution(row)

    @staticmethod
    def _require_backend_authority(
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
    ) -> None:
        """Refuse evidence writes from a stale owner, epoch, or attempt."""
        if not SQLiteStore._attempt_authorized(
            connection, job_id, attempt_id, owner_id, claim_epoch
        ):
            raise BackendEvidenceError(
                "attempt ownership, epoch, or current-job authority is stale; "
                "execution evidence was not written"
            )

    def insert_resolved_execution(
        self,
        *,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
        record: dict[str, object],
        timestamp: str,
    ) -> str:
        """Insert the immutable resolved plan for one current attempt.

        The record is validated before the transaction. The digest is computed
        from the same canonical bytes that a later read recomputes. Only one
        resolved insert is accepted per attempt.
        """
        validate_resolved_record(record)
        if record.get("attempt_id") != attempt_id:
            raise BackendEvidenceError("resolved evidence identifies a different attempt")
        resolved_json = serialize_resolved_record(record)
        resolved_digest = backend_digest(record)
        with self._connection(transaction=True) as connection:
            self._require_backend_authority(
                connection, job_id, attempt_id, owner_id, claim_epoch
            )
            if (
                type(record.get("schema_version")) is int
                and record.get("schema_version") in COMFYUI_RESOLVED_RECORD_SCHEMA_VERSIONS
            ):
                configuration_row = connection.execute(
                    "SELECT adapter_configuration_json FROM generation_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                if configuration_row is None:
                    raise BackendEvidenceError(
                        "resolved ComfyUI execution has no persisted adapter configuration"
                    )
                persisted_approval = _persisted_workflow_approval(
                    configuration_row["adapter_configuration_json"]
                )
                validate_resolved_record(
                    record,
                    expected_workflow_approval=persisted_approval,
                )
            try:
                connection.execute(
                    """INSERT INTO backend_executions
                       (attempt_id, job_id, backend_kind, candidate_id, resolved_json,
                        resolved_digest, resolved_at, launch_json, launch_at,
                        observed_json, observed_at, state)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, 'resolved')""",
                    (
                        attempt_id,
                        job_id,
                        str(record["backend_kind"]),
                        str(record["candidate_id"]),
                        resolved_json,
                        resolved_digest,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise BackendEvidenceError(
                    "resolved execution evidence already exists for this attempt"
                ) from error
        return resolved_digest

    def mark_execution_launched(
        self,
        *,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
        record: dict[str, object],
        timestamp: str,
    ) -> None:
        """Record exactly one resolved-to-launched transition."""
        validate_launch_record(record)
        if record.get("attempt_id") != attempt_id:
            raise BackendEvidenceError("launch evidence identifies a different attempt")
        with self._connection(transaction=True) as connection:
            self._require_backend_authority(
                connection, job_id, attempt_id, owner_id, claim_epoch
            )
            updated = connection.execute(
                """UPDATE backend_executions
                   SET launch_json = ?, launch_at = ?, state = 'launched'
                   WHERE job_id = ? AND attempt_id = ? AND state = 'resolved'""",
                (backend_canonical_json(record), timestamp, job_id, attempt_id),
            )
            if updated.rowcount != 1:
                raise BackendEvidenceError(
                    "backend execution is not resolved; launch evidence was not written"
                )

    def mark_execution_observed(
        self,
        *,
        job_id: str,
        attempt_id: str,
        owner_id: str | None,
        claim_epoch: int | None,
        record: dict[str, object],
        timestamp: str,
    ) -> None:
        """Record exactly one launched-to-observed transition."""
        validate_observed_record(record)
        if record.get("attempt_id") != attempt_id:
            raise BackendEvidenceError("observation evidence identifies a different attempt")
        with self._connection(transaction=True) as connection:
            self._require_backend_authority(
                connection, job_id, attempt_id, owner_id, claim_epoch
            )
            updated = connection.execute(
                """UPDATE backend_executions
                   SET observed_json = ?, observed_at = ?, state = 'observed'
                   WHERE job_id = ? AND attempt_id = ? AND state = 'launched'""",
                (backend_canonical_json(record), timestamp, job_id, attempt_id),
            )
            if updated.rowcount != 1:
                raise BackendEvidenceError(
                    "backend execution was not launched; observation evidence "
                    "was not written"
                )

    def _require_systemd_success_evidence(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        attempt_id: str,
    ) -> None:
        """Require engine, stream, and root-ledger proof before systemd success."""
        if not self._attempt_cgroup_termination_evidence(
            connection, job_id, attempt_id
        ):
            raise BackendEvidenceError(
                "systemd publication success requires verified whole-cgroup termination"
            )
        backend = connection.execute(
            """SELECT state, observed_json, observed_at
               FROM backend_executions WHERE job_id = ? AND attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if (
            backend is None
            or backend["state"] != "observed"
            or backend["observed_json"] is None
            or backend["observed_at"] is None
        ):
            raise BackendEvidenceError(
                "systemd publication success requires a durable engine observation"
            )
        try:
            observation = json.loads(str(backend["observed_json"]))
            if not isinstance(observation, dict):
                raise ValueError("engine observation is not an object")
            validate_observed_record(observation)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError(
                "systemd engine observation is malformed"
            ) from error
        if (
            observation.get("attempt_id") != attempt_id
            or not observation_proves_reaped_child(observation)
            or type(observation.get("exit_code")) is not int
            or observation.get("exit_code") != 0
            or observation.get("signal") is not None
        ):
            raise BackendEvidenceError(
                "systemd publication success requires a successful engine exit observation"
            )
        lifecycle = connection.execute(
            """SELECT lifecycle.identity_digest AS lifecycle_identity_digest,
                      lifecycle.stream_complete, lifecycle.cleanup_state,
                      containment.identity_digest AS containment_identity_digest,
                      containment.identity_json, backend.resolved_digest
               FROM systemd_output_lifecycle AS lifecycle
               JOIN execution_containment AS containment
                 ON containment.job_id = lifecycle.job_id
                AND containment.attempt_id = lifecycle.attempt_id
               JOIN backend_executions AS backend
                 ON backend.attempt_id = lifecycle.attempt_id
               WHERE lifecycle.job_id = ? AND lifecycle.attempt_id = ?""",
            (job_id, attempt_id),
        ).fetchone()
        if lifecycle is None:
            raise BackendEvidenceError(
                "systemd publication success lacks durable output lifecycle evidence"
            )
        try:
            identity = AttemptUnitIdentity.from_mapping(
                json.loads(str(lifecycle["identity_json"]))
            )
            if (
                identity.job_id != job_id
                or identity.attempt_id != attempt_id
                or identity.resolved_digest != lifecycle["resolved_digest"]
                or identity_digest(identity) != lifecycle["containment_identity_digest"]
                or lifecycle["lifecycle_identity_digest"]
                != lifecycle["containment_identity_digest"]
            ):
                raise ValueError("output lifecycle identity does not match containment")
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise BackendEvidenceError(
                "systemd output lifecycle identity is malformed"
            ) from error
        if lifecycle["stream_complete"] != 1 or lifecycle["cleanup_state"] != "active":
            raise BackendEvidenceError(
                "systemd publication success requires validated stream completion"
            )

    def complete_execution(
        self, artifact: GenerationArtifact, timestamp: str, *,
        publication_id: str | None = None, sources: tuple[ArtifactSource, ...] = (),
        attempt_owner_id: str | None = None, claim_epoch: int | None = None,
    ) -> None:
        """Commit an artifact and release work only with trusted termination proof.

        A rejected admission completion transition raises before the transaction
        commits, so execution, publication, and resource finalization are atomic.
        """
        with self._connection(transaction=True) as connection:
            row = connection.execute(
                "SELECT status, output_slot_id FROM generation_jobs WHERE job_id = ?", (artifact.job_id,)
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {artifact.job_id}")
            if row["status"] != "running":
                raise RuntimeError(f"job {artifact.job_id} is not running")
            if row["output_slot_id"] != artifact.output_slot_id:
                raise RuntimeError("artifact output slot does not belong to job")
            attempt = connection.execute(
                """SELECT status, process_contained, containment_contract, owner_id
                   FROM execution_attempts
                   WHERE job_id = ? AND attempt_id = ?""",
                (artifact.job_id, artifact.attempt_id),
            ).fetchone()
            if attempt is None:
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} does not belong to job {artifact.job_id}"
                )
            if attempt["status"] != "running":
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} for job {artifact.job_id} is not running"
                )
            if publication_id is None:
                raise RuntimeError(
                    "generated artifact completion requires a publication journal row"
                )
            if not self._attempt_authorized(
                connection, artifact.job_id, artifact.attempt_id,
                attempt_owner_id, claim_epoch,
            ):
                raise RuntimeError("attempt ownership, epoch, or current-job authority is stale")
            is_systemd_attempt = (
                attempt["containment_contract"]
                == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
            )
            if is_systemd_attempt:
                self._require_systemd_success_evidence(
                    connection, artifact.job_id, artifact.attempt_id
                )
            connection.execute(
                """INSERT INTO generation_artifacts (
                    artifact_id, job_id, attempt_id, output_slot_id, path, media_type,
                    image_format, width, height, file_size, sha256, created_at, origin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated')""",
                (
                    artifact.artifact_id,
                    artifact.job_id,
                    artifact.attempt_id,
                    artifact.output_slot_id,
                    artifact.path,
                    artifact.media_type,
                    artifact.image_format,
                    artifact.width,
                    artifact.height,
                    artifact.file_size,
                    artifact.sha256,
                    artifact.created_at,
                ),
            )
            updated_job = connection.execute(
                """UPDATE generation_jobs SET status = 'succeeded', updated_at = ?
                   WHERE job_id = ? AND status = 'running'""",
                (timestamp, artifact.job_id),
            )
            if updated_job.rowcount != 1:
                raise RuntimeError(f"job {artifact.job_id} could not be marked succeeded")
            updated_attempt = connection.execute(
                """UPDATE generation_attempts
                   SET status = 'succeeded', finished_at = ?, error_message = NULL
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (timestamp, artifact.attempt_id, artifact.job_id),
            )
            if updated_attempt.rowcount != 1:
                raise RuntimeError(
                    f"attempt {artifact.attempt_id} for job {artifact.job_id} "
                    "could not be marked succeeded"
                )

            self._insert_sources(connection, artifact.artifact_id, sources)
            if publication_id is not None:
                self._commit_publication_row(
                    connection,
                    publication_id,
                    artifact.artifact_id,
                    attempt_id=artifact.attempt_id,
                    attempt_owner_id=attempt_owner_id,
                    claim_epoch=claim_epoch,
                )
            if is_systemd_attempt:
                pending_cleanup = connection.execute(
                    """UPDATE systemd_output_lifecycle
                       SET cleanup_state = 'pending', cleanup_validated = 1
                       WHERE job_id = ? AND attempt_id = ?
                         AND cleanup_state = 'active' AND stream_complete = 1
                         AND identity_digest = (
                             SELECT identity_digest FROM execution_containment
                             WHERE job_id = ? AND attempt_id = ?
                         )""",
                    (
                        artifact.job_id, artifact.attempt_id,
                        artifact.job_id, artifact.attempt_id,
                    ),
                )
                if pending_cleanup.rowcount != 1:
                    raise BackendEvidenceError(
                        "systemd scratch cleanup could not be queued with publication"
                    )
            direct_child_termination_proven = self._attempt_termination_evidence(
                connection, artifact.job_id, artifact.attempt_id
            )
            process_tree_required = (
                self._attempt_requires_process_tree_resource_release(
                    connection, artifact.job_id, artifact.attempt_id
                )
            )
            termination_proven = self._attempt_termination_proven(
                connection, artifact.job_id, artifact.attempt_id
            )
            resource_release_proven = self._resource_release_proven(
                connection,
                artifact.job_id,
                artifact.attempt_id,
                containment_contract=attempt["containment_contract"],
                effective_termination_proven=termination_proven,
                direct_child_termination_proven=direct_child_termination_proven,
            )
            # This field records the adapter-scoped proof used to release T06.
            # The observation row retains the separate direct-child fact.
            connection.execute(
                """UPDATE execution_attempts
                   SET status = 'succeeded', completed_at = ?, failure_class = NULL,
                   termination_proven = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (
                    timestamp,
                    int(resource_release_proven),
                    artifact.attempt_id,
                    artifact.job_id,
                ),
            )
            connection.execute(
                """UPDATE execution_jobs
                   SET status = 'succeeded', retry_eligible = 0,
                   failure_message = NULL, updated_at = ?
                   WHERE job_id = ? AND status = 'running'""",
                (timestamp, artifact.job_id),
            )
            if resource_release_proven:
                connection.execute(
                    """UPDATE execution_resource
                       SET state = 'available', job_id = NULL, attempt_id = NULL,
                       owner_id = NULL, reason = NULL, updated_at = ? WHERE id = 1""",
                    (timestamp,),
                )
                admission_state = "released"
                admission_reason = "termination_and_publication_reconciled"
            else:
                quarantine_reason = (
                    "successful publication lacks required process-tree "
                    "termination evidence"
                    if process_tree_required
                    else "successful publication has no trusted "
                    "process-termination proof"
                )
                connection.execute(
                    """UPDATE execution_resource
                       SET state = 'quarantined', job_id = ?, attempt_id = ?,
                       owner_id = ?, reason = ?, updated_at = ? WHERE id = 1""",
                    (
                        artifact.job_id,
                        artifact.attempt_id,
                        attempt["owner_id"],
                        quarantine_reason,
                        timestamp,
                    ),
                )
                admission_state = "quarantined"
                admission_reason = quarantine_reason
            admission_finished = AdmissionPersistence.finish(
                connection,
                artifact.job_id,
                decision=admission_state,
                reason=admission_reason,
                timestamp=timestamp,
            )
            if not admission_finished:
                raise RuntimeError("admission completion transition was rejected")

    @staticmethod
    def _commit_publication_row(
        connection,
        publication_id: str,
        artifact_id: str,
        *,
        attempt_id: str | None = None,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
    ) -> None:
        if attempt_id is not None:
            authority = connection.execute(
                """SELECT job_id, attempt_id, owner_id, claim_epoch
                   FROM artifact_publication_authority WHERE publication_id = ?""",
                (publication_id,),
            ).fetchone()
            if authority is None or authority["attempt_id"] != attempt_id:
                raise RuntimeError("publication authority does not identify this attempt")
            if attempt_owner_id is not None or claim_epoch is not None:
                if (
                    authority["owner_id"] != attempt_owner_id
                    or int(authority["claim_epoch"]) != claim_epoch
                ):
                    raise RuntimeError("publication authority is stale")
        updated = connection.execute(
            "UPDATE artifact_publications SET state = 'committed', error = NULL "
            "WHERE publication_id = ? AND artifact_id = ? AND state = 'ready'",
            (publication_id, artifact_id),
        )
        if updated.rowcount != 1:
            raise RuntimeError("publication is not ready for this artifact")

    def complete_import(self, artifact: ImportedArtifact, publication_id: str,
                        sources: tuple[ArtifactSource, ...]) -> None:
        """Expose an import and all of its lineage in one durable transaction."""
        with self._connection(transaction=True) as connection:
            connection.execute("""INSERT INTO generation_artifacts
                (artifact_id, path, media_type, image_format, width, height, file_size,
                 sha256, created_at, origin, import_provenance_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'imported', ?)""",
                (artifact.artifact_id, artifact.path, artifact.media_type, artifact.image_format,
                 artifact.width, artifact.height, artifact.file_size, artifact.sha256,
                 artifact.created_at, _json(artifact.to_dict()["import_provenance"])))
            self._insert_sources(connection, artifact.artifact_id, sources)
            self._commit_publication_row(connection, publication_id, artifact.artifact_id)

    def create_publication(
        self,
        record: dict[str, object],
        *,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
    ) -> None:
        """Commit allocation intent before the publisher creates private content."""
        with self._connection(transaction=True) as connection:
            job_id = record.get("job_id")
            attempt_id = record.get("attempt_id")
            if job_id is not None and attempt_id is not None:
                if attempt_owner_id is None or claim_epoch is None:
                    raise RuntimeError("generated publication requires attempt authority")
                if not self._attempt_authorized(
                    connection,
                    str(job_id),
                    str(attempt_id),
                    attempt_owner_id,
                    claim_epoch,
                ):
                    raise RuntimeError("publication intent belongs to a stale attempt")
            fields = tuple(record)
            connection.execute(
                f"INSERT INTO artifact_publications ({','.join(fields)}) "
                f"VALUES ({','.join('?' for _ in fields)})", tuple(record.values()))
            if job_id is not None and attempt_id is not None:
                connection.execute(
                    """INSERT INTO artifact_publication_authority
                       (publication_id,job_id,attempt_id,owner_id,claim_epoch,created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        record["publication_id"],
                        job_id,
                        attempt_id,
                        attempt_owner_id,
                        claim_epoch,
                        record["created_at"],
                    ),
                )

    def update_publication(self, publication_id: str, **values: object) -> None:
        """Update journal metadata without changing its publication lifecycle state."""
        allowed = {"stage_dev", "stage_ino", "final_name", "artifact_json", "error"}
        if not values or not set(values) <= allowed:
            raise ValueError("unsupported publication update")
        with self._connection(transaction=True) as connection:
            self._require_publication_authority(connection, publication_id)
            connection.execute(
                f"UPDATE artifact_publications SET {','.join(key+' = ?' for key in values)} "
                "WHERE publication_id = ? AND state != 'committed'",
                (*values.values(), publication_id))

    def mark_publication_ready(self, publication_id: str, final_name: str,
                               artifact_json: str) -> None:
        """Record validated publication metadata through an allocated-to-ready transition."""
        with self._connection(transaction=True) as connection:
            self._require_publication_authority(connection, publication_id)
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'ready', final_name = ?, "
                "artifact_json = ? WHERE publication_id = ? AND state = 'allocated'",
                (final_name, artifact_json, publication_id),
            )
            if updated.rowcount != 1:
                raise RuntimeError("publication is not allocated for the ready transition")

    def abandon_publication(self, publication_id: str, error: str) -> None:
        """Terminally revoke an allocated publication idempotently."""
        with self._connection(transaction=True) as connection:
            updated = connection.execute(
                "UPDATE artifact_publications SET state = 'abandoned', error = ? "
                "WHERE publication_id = ? AND state = 'allocated'",
                (error, publication_id),
            )
            if updated.rowcount == 0:
                current = connection.execute(
                    "SELECT state FROM artifact_publications WHERE publication_id = ?",
                    (publication_id,),
                ).fetchone()
                if current is None or current["state"] != "abandoned":
                    raise RuntimeError("publication is not allocated for abandonment")

    def revoke_ready_publication(self, publication_id: str, error: str) -> None:
        """Revoke a ready journal only after its attempt authority has gone stale.

        Recovery uses this transition after cancellation or a fence change has
        made the journal unauthorized but before finalizing the attempt and
        releasing or quarantining the heavyweight resource. It changes only
        SQLite state. Final and staging files remain for the existing T03
        preservation and reconciliation path.
        """
        with self._connection(transaction=True) as connection:
            publication = connection.execute(
                "SELECT state, job_id, artifact_id FROM artifact_publications "
                "WHERE publication_id = ?",
                (publication_id,),
            ).fetchone()
            if publication is None:
                raise RecordNotFoundError(f"publication not found: {publication_id}")
            if publication["state"] == "abandoned":
                return
            if publication["state"] != "ready":
                raise RuntimeError(
                    "publication is not ready for authority-fenced revocation"
                )
            if connection.execute(
                "SELECT 1 FROM generation_artifacts WHERE artifact_id = ?",
                (publication["artifact_id"],),
            ).fetchone() is not None:
                raise RuntimeError("publication already has a committed artifact")

            authority = self._publication_authority(connection, publication_id)
            if authority is None:
                current = publication["job_id"] is None
            else:
                owner_id = (
                    None
                    if authority["owner_id"] is None
                    else str(authority["owner_id"])
                )
                current = self._attempt_authorized(
                    connection,
                    str(authority["job_id"]),
                    str(authority["attempt_id"]),
                    owner_id,
                    int(authority["claim_epoch"]),
                )
            if current:
                raise RuntimeError("publication authority is still current")

            connection.execute(
                "UPDATE artifact_publications SET state = 'abandoned', error = ? "
                "WHERE publication_id = ? AND state = 'ready'",
                (error, publication_id),
            )

    @staticmethod
    def _publication_authority(
        connection: sqlite3.Connection, publication_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM artifact_publication_authority WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()

    def _require_publication_authority(
        self, connection: sqlite3.Connection, publication_id: str
    ) -> None:
        authority = self._publication_authority(connection, publication_id)
        if authority is None:
            return
        owner_id = None if authority["owner_id"] is None else str(authority["owner_id"])
        if not self._attempt_authorized(
            connection,
            str(authority["job_id"]),
            str(authority["attempt_id"]),
            owner_id,
            int(authority["claim_epoch"]),
        ):
            raise RuntimeError("publication attempt authority is stale or canceled")

    def publication_authority_current(self, publication_id: str) -> bool:
        """Report whether a journal's stored attempt still has publication authority."""
        with self._connection() as connection:
            publication = connection.execute(
                "SELECT job_id FROM artifact_publications WHERE publication_id = ?",
                (publication_id,),
            ).fetchone()
            if publication is None:
                return False
            authority = self._publication_authority(connection, publication_id)
            if authority is None:
                # Imports have no generation attempt. A generated journal
                # without authority is historical or incomplete and must be
                # reconciled explicitly before it can publish.
                return publication["job_id"] is None
            owner_id = None if authority["owner_id"] is None else str(authority["owner_id"])
            return self._attempt_authorized(
                connection,
                str(authority["job_id"]),
                str(authority["attempt_id"]),
                owner_id,
                int(authority["claim_epoch"]),
            )

    def publications(self, root: str) -> list[dict[str, object]]:
        """List durable publication decisions for an exact authoritative root."""
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.root = ? ORDER BY publications.created_at""",
                (root,),
            )]

    def publication_for_artifact(self, artifact_id: str) -> dict[str, object] | None:
        """Read the publication journal that owns an artifact, if one exists."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.artifact_id = ?""",
                (artifact_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def publication(self, publication_id: str) -> dict[str, object]:
        """Read the durable decision, including after lost commit acknowledgement."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT publications.*, authority.owner_id AS attempt_owner_id,
                          authority.claim_epoch AS attempt_claim_epoch
                   FROM artifact_publications AS publications
                   LEFT JOIN artifact_publication_authority AS authority
                     ON authority.publication_id = publications.publication_id
                   WHERE publications.publication_id = ?""",
                (publication_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"publication not found: {publication_id}")
        return dict(row)

    def artifacts(self) -> list[GenerationArtifact | ImportedArtifact]:
        """List committed artifact metadata for integrity reconciliation."""
        with self._connection() as connection:
            return [self._artifact_from_row(row) for row in connection.execute(
                "SELECT * FROM generation_artifacts ORDER BY created_at, artifact_id")]

    def record_integrity(self, artifact_id: str, status: str, timestamp: str, detail: str | None) -> None:
        """Keep current observations separately from immutable provenance."""
        with self._connection(transaction=True) as connection:
            connection.execute("""INSERT INTO artifact_integrity VALUES (?, ?, ?, ?)
                ON CONFLICT(artifact_id) DO UPDATE SET status=excluded.status,
                checked_at=excluded.checked_at, detail=excluded.detail""",
                (artifact_id, status, timestamp, detail))

    def get_lineage(self, artifact_id: str) -> dict[str, object]:
        """Read directed relationships without changing their historical membership."""
        self.get_artifact(artifact_id)
        with self._connection() as connection:
            parents = [dict(row) for row in connection.execute(
                "SELECT * FROM artifact_edges WHERE target_id = ? ORDER BY position", (artifact_id,))]
            children = [dict(row) for row in connection.execute(
                "SELECT * FROM artifact_edges WHERE source_id = ? ORDER BY target_id, position", (artifact_id,))]
        return {"artifact_id": artifact_id, "parents": parents, "children": children}

    def fail_execution(
        self,
        job_id: str,
        attempt_id: str,
        message: str,
        timestamp: str,
        *,
        attempt_owner_id: str | None = None,
        claim_epoch: int | None = None,
        failure_class: str = "terminal",
        termination_proven: bool = False,
        prelaunch_refusal: bool = False,
        _recovery_fenced: bool = False,
        _revoked_publication_id: str | None = None,
    ) -> bool:
        """Finalize one current attempt and apply the durable outcome.

        Stale ownership is a no-op so an old adapter cannot fail a successor.
        A noncanceled attempt without trusted termination proof is reported as
        ambiguous at job level, retains its failure classification, quarantines
        the sole resource, and is never made retryable by this method.
        A rejected admission transition raises before the transaction commits,
        rolling back both execution and resource finalization.
        """
        if failure_class not in {
            "retryable",
            "terminal",
            "canceled",
            "ambiguous",
            "crash",
        }:
            raise ValueError(f"unsupported failure class: {failure_class}")
        with self._connection(transaction=True) as connection:
            current = self._attempt_authorized(
                connection, job_id, attempt_id, attempt_owner_id, claim_epoch
            )
            if not current:
                # Finalization of a canceled or durably revoked journal is a
                # narrower capability than publication. It still requires the
                # actual persisted claim and reservation, never ownerless data.
                if attempt_owner_id is None or claim_epoch is None:
                    return False
                canceled_claim = failure_class == "canceled" and connection.execute(
                    """SELECT 1 FROM execution_jobs AS jobs
                       JOIN execution_attempts AS attempts ON attempts.attempt_id = jobs.current_attempt_id
                       JOIN execution_resource AS resource ON resource.id = 1
                       WHERE jobs.job_id = ? AND jobs.status = 'canceled'
                         AND jobs.fence_epoch = ? + 1 AND attempts.attempt_id = ?
                         AND attempts.owner_id = ? AND attempts.claim_epoch = ?
                         AND resource.job_id = jobs.job_id AND resource.attempt_id = attempts.attempt_id
                         AND resource.owner_id = attempts.owner_id AND resource.state = 'claimed'""",
                    (job_id, claim_epoch, attempt_id, attempt_owner_id, claim_epoch),
                ).fetchone() is not None
                # A revoked journal can finalize only the immediately fenced,
                # still-running job. A newer cancellation must use the explicit
                # canceled capability above, never a stale crash classification.
                revoked_claim = failure_class != "canceled" and _revoked_publication_id is not None and connection.execute(
                    """SELECT 1 FROM artifact_publications AS publications
                       JOIN artifact_publication_authority AS authority USING (publication_id)
                       JOIN execution_jobs AS jobs ON jobs.job_id = authority.job_id
                       JOIN execution_attempts AS attempts ON attempts.attempt_id = jobs.current_attempt_id
                       JOIN execution_resource AS resource ON resource.id = 1
                       WHERE publications.publication_id = ? AND publications.state = 'abandoned'
                         AND authority.job_id = ? AND authority.attempt_id = ?
                         AND authority.owner_id = ? AND authority.claim_epoch = ?
                         AND jobs.status = 'running'
                         AND jobs.fence_epoch = authority.claim_epoch + 1
                         AND attempts.attempt_id = authority.attempt_id
                         AND attempts.owner_id = authority.owner_id AND attempts.claim_epoch = authority.claim_epoch
                         AND resource.job_id = jobs.job_id AND resource.attempt_id = attempts.attempt_id
                         AND resource.owner_id = attempts.owner_id AND resource.state = 'claimed'""",
                    (_revoked_publication_id, job_id, attempt_id, attempt_owner_id, claim_epoch),
                ).fetchone() is not None
                recovery_fenced_claim = (
                    _recovery_fenced
                    and failure_class != "canceled"
                    and connection.execute(
                        """SELECT 1 FROM execution_jobs AS jobs
                           JOIN execution_attempts AS attempts
                             ON attempts.attempt_id = jobs.current_attempt_id
                           JOIN execution_resource AS resource ON resource.id = 1
                           WHERE jobs.job_id = ? AND jobs.status = 'running'
                             AND jobs.current_attempt_id = ?
                             AND jobs.fence_epoch = ? + 1
                             AND attempts.attempt_id = ? AND attempts.status = 'running'
                             AND attempts.owner_id = ? AND attempts.claim_epoch = ?
                             AND resource.state = 'claimed' AND resource.job_id = jobs.job_id
                             AND resource.attempt_id = attempts.attempt_id
                             AND resource.owner_id = attempts.owner_id
                             AND NOT EXISTS (
                               SELECT 1 FROM artifact_publications
                               WHERE job_id = jobs.job_id
                                 AND state IN ('ready','committed')
                             )""",
                        (
                            job_id,
                            attempt_id,
                            claim_epoch,
                            attempt_id,
                            attempt_owner_id,
                            claim_epoch,
                        ),
                    ).fetchone()
                    is not None
                )
                if not canceled_claim and not revoked_claim and not recovery_fenced_claim:
                    return False
            if connection.execute(
                "SELECT 1 FROM artifact_publications WHERE job_id = ? "
                "AND state IN ('ready', 'committed')",
                (job_id,),
            ).fetchone() is not None:
                return False
            attempt = connection.execute(
                """SELECT status, process_contained, containment_contract
                   FROM execution_attempts
                WHERE attempt_id = ? AND job_id = ?""",
                (attempt_id, job_id),
            ).fetchone()
            if attempt is None or attempt["status"] != "running":
                return False
            job = connection.execute(
                """SELECT execution.max_attempts, execution.current_attempt_id,
                execution.fence_epoch, jobs.adapter_id
                FROM execution_jobs AS execution
                JOIN generation_jobs AS jobs
                ON jobs.job_id = execution.job_id
                WHERE execution.job_id = ?""",
                (job_id,),
            ).fetchone()
            if job is None or job["current_attempt_id"] != attempt_id:
                return False
            number = connection.execute(
                "SELECT attempt_number FROM execution_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()[0]
            direct_child_termination_proven = self._attempt_termination_evidence(
                connection, job_id, attempt_id
            )
            process_tree_required = (
                self._attempt_requires_process_tree_resource_release(
                    connection, job_id, attempt_id
                )
            )
            prelaunch_proven = (
                prelaunch_refusal
                and termination_proven
                and not self._attempt_has_launch_evidence(
                    connection, job_id, attempt_id
                )
            )
            validated_termination_proven = self._attempt_termination_proven(
                connection, job_id, attempt_id
            )
            if prelaunch_proven:
                effective_termination_proven = True
            elif not termination_proven:
                # An explicit uncertainty result outranks inferred contract proof.
                effective_termination_proven = False
            elif process_tree_required:
                effective_termination_proven = direct_child_termination_proven
            else:
                effective_termination_proven = validated_termination_proven
            resource_release_proven = self._resource_release_proven(
                connection,
                job_id,
                attempt_id,
                containment_contract=attempt["containment_contract"],
                effective_termination_proven=effective_termination_proven,
                direct_child_termination_proven=direct_child_termination_proven,
                prelaunch_refusal=prelaunch_refusal,
            )
            retry = (
            resource_release_proven
                and failure_class in {"retryable", "crash"}
                and int(number) < int(job["max_attempts"])
            )
            execution_status = (
                "canceled"
                if failure_class == "canceled"
                else "ambiguous"
            if failure_class == "ambiguous" or not effective_termination_proven
                else "queued"
                if retry
                else "failed"
            )
            attempt_status = "canceled" if failure_class == "canceled" else "failed"
            connection.execute(
                """UPDATE generation_attempts
                   SET status = 'failed', finished_at = ?, error_message = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (timestamp, message, attempt_id, job_id),
            )
            connection.execute(
                """UPDATE execution_attempts
                   SET status = ?, failure_class = ?, termination_proven = ?,
                       completed_at = ?
                   WHERE attempt_id = ? AND job_id = ? AND status = 'running'""",
                (
                    attempt_status,
                    failure_class,
                    int(resource_release_proven),
                    timestamp,
                    attempt_id,
                    job_id,
                ),
            )
            connection.execute(
                "UPDATE generation_jobs SET status = ?, updated_at = ? WHERE job_id = ?",
                ("running" if retry else "failed", timestamp, job_id),
            )
            connection.execute(
                """UPDATE execution_jobs
                   SET status = ?, retry_eligible = ?, failure_message = ?,
                       current_attempt_id = ?, updated_at = ?
                   WHERE job_id = ?""",
                (
                    execution_status,
                    int(retry),
                    message,
                    attempt_id,
                    timestamp,
                    job_id,
                ),
            )
            if (
                attempt["containment_contract"]
                == SYSTEMD_CGROUP_CONTAINMENT_CONTRACT
                and resource_release_proven
            ):
                bound_containment = connection.execute(
                    """SELECT identity_digest FROM execution_containment
                       WHERE job_id = ? AND attempt_id = ?""",
                    (job_id, attempt_id),
                ).fetchone()
                if bound_containment is not None:
                    cleanup = connection.execute(
                        """UPDATE systemd_output_lifecycle
                           SET cleanup_state = 'pending', cleanup_validated = 0
                           WHERE job_id = ? AND attempt_id = ?
                             AND cleanup_state = 'active'
                             AND identity_digest = ?""",
                        (job_id, attempt_id, bound_containment["identity_digest"]),
                    )
                    if cleanup.rowcount != 1:
                        raise RuntimeError(
                            "systemd failed-attempt cleanup could not be queued"
                        )
            resource_state = (
                "quarantined"
                if failure_class == "ambiguous" or not resource_release_proven
                else "available"
            )
            resource_quarantine_reason = (
                "attempt lacks required process-tree termination evidence"
                if process_tree_required and not resource_release_proven
                else (
                    "attempt has direct-child evidence but no required "
                    "process-tree termination evidence"
                    if effective_termination_proven and not resource_release_proven
                    else message
                )
            )
            connection.execute(
                """UPDATE execution_resource
                   SET state = ?, job_id = ?, attempt_id = ?, owner_id = ?,
                       reason = ?, updated_at = ? WHERE id = 1
                     AND job_id = ? AND attempt_id = ?""",
                (
                    resource_state,
                    job_id if resource_state == "quarantined" else None,
                    attempt_id if resource_state == "quarantined" else None,
                    attempt_owner_id if resource_state == "quarantined" else None,
                resource_quarantine_reason if resource_state == "quarantined" else None,
                    timestamp,
                    job_id,
                    attempt_id,
                ),
            )
            admission_before_finalize = AdmissionPersistence.snapshot(connection, job_id)
            if admission_before_finalize is None:
                raise RuntimeError("admission failure transition lacks current evidence")
            if resource_state == "quarantined":
                admission_state = "quarantined"
            elif retry:
                admission_state = (
                    "not_required"
                    if is_lightweight_cpu_adapter_id(job["adapter_id"])
                    and not admission_before_finalize.has_capacity_evidence
                    else "queued"
                )
            else:
                admission_state = "released"
            admission_finished = AdmissionPersistence.finish(
                connection,
                job_id,
                decision=admission_state,
            reason=resource_quarantine_reason,
                timestamp=timestamp,
            )
            if not admission_finished:
                raise RuntimeError("admission failure transition was rejected")
            if failure_class == "canceled" and effective_termination_proven:
                connection.execute(
                    """UPDATE execution_cancellations
                       SET state = 'acknowledged', acknowledged_at = ?
                       WHERE job_id = ? AND attempt_id = ? AND claim_epoch = ?
                         AND state = 'requested'""",
                    (timestamp, job_id, attempt_id, claim_epoch),
                )
            return True

    def get_request(self, request_id: str) -> GenerationRequestRecord:
        """Load an immutable request snapshot by its persisted identity."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM generation_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"request not found: {request_id}")
        payload = json.loads(str(row["canonical_json"]))
        return GenerationRequestRecord(
            request_id=str(row["request_id"]),
            request=GenerationRequest(**payload),
            request_digest=str(row["request_digest"]),
            created_at=str(row["created_at"]),
        )

    def get_job(self, job_id: str) -> GenerationJob:
        """Load job state and its associated artifact identity, if successful."""
        with self._connection() as connection:
            row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id,
                          execution.status AS execution_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.retry_eligible, execution.failure_message
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts
                     ON artifacts.job_id = jobs.job_id
                   LEFT JOIN execution_jobs AS execution
                     ON execution.job_id = jobs.job_id
                   WHERE jobs.job_id = ?""",
                (job_id,),
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"job not found: {job_id}")
        return self._job_from_row(row)

    def get_resolved_output_directory(self, job_id: str) -> str | None:
        """Return the output directory captured by current job intent."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT effective_parameters_json FROM generation_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            return self._output_directory_for_job(
                connection,
                job_id,
                str(row["effective_parameters_json"]),
            )

    def get_artifact(self, artifact_id: str) -> GenerationArtifact | ImportedArtifact:
        """Load one logical artifact and its persisted file metadata."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM generation_artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"artifact not found: {artifact_id}")
        return self._artifact_from_row(row)

    def get_provenance(self, job_id: str) -> dict[str, object]:
        """Return request, job, attempt history, artifact, and execution state."""
        with self._connection() as connection:
            job_row = connection.execute(
                """SELECT jobs.*, artifacts.artifact_id,
                          execution.status AS execution_status,
                          execution.max_attempts, execution.fence_epoch,
                          execution.retry_eligible, execution.failure_message,
                          execution.containment_contract,
                          execution.privacy_compliance_json,
                          execution.current_attempt_id,
                          resource.state AS resource_state,
                          resource.job_id AS resource_job_id,
                          resource.attempt_id AS resource_attempt_id,
resource.owner_id AS resource_owner_id,
resource.reason AS resource_reason
                   FROM generation_jobs AS jobs
                   LEFT JOIN generation_artifacts AS artifacts
                     ON artifacts.job_id = jobs.job_id
                   LEFT JOIN execution_jobs AS execution
                     ON execution.job_id = jobs.job_id
                   LEFT JOIN execution_resource AS resource ON resource.id = 1
                   WHERE jobs.job_id = ?""",
                (job_id,),
            ).fetchone()
            if job_row is None:
                raise RecordNotFoundError(f"job not found: {job_id}")
            request_row = connection.execute(
                "SELECT * FROM generation_requests WHERE request_id = ?",
                (job_row["request_id"],),
            ).fetchone()
            assert request_row is not None
            attempt_rows = connection.execute(
                """SELECT attempts.*, execution.status AS execution_status,
                          execution.owner_id, execution.claim_epoch,
                          execution.heartbeat_at, execution.lease_expires_at,
                          execution.process_contained,
                          execution.containment_contract,
                          execution.failure_class, execution.termination_proven
                   FROM generation_attempts AS attempts
                   LEFT JOIN execution_attempts AS execution
                     ON execution.attempt_id = attempts.attempt_id
                   WHERE attempts.job_id = ? ORDER BY attempts.attempt_number""",
                (job_id,),
            ).fetchall()
            artifact_row = connection.execute(
                "SELECT * FROM generation_artifacts WHERE job_id = ?", (job_id,)
            ).fetchone()
            request_payload = json.loads(str(request_row["canonical_json"]))
            request = GenerationRequestRecord(
                request_id=str(request_row["request_id"]),
                request=GenerationRequest(**request_payload),
                request_digest=str(request_row["request_digest"]),
                created_at=str(request_row["created_at"]),
            )
            job = self._job_from_row(job_row)
            job_payload = job.to_dict()
            attempts = tuple(self._attempt_from_row(row) for row in attempt_rows)
            artifact = None if artifact_row is None else self._artifact_from_row(artifact_row)
            execution_status = (
                str(job_row["execution_status"])
                if "execution_status" in job_row.keys() and job_row["execution_status"] is not None
                else job.status
            )
            privacy_compliance = _stored_privacy_compliance(job_row, job.adapter_id)
            admission_record = AdmissionPersistence.snapshot(connection, job_id)
            backend_execution = None
            current_attempt_id = job_row["current_attempt_id"]
            if current_attempt_id is not None:
                execution_row = connection.execute(
                    """SELECT executions.*,
                              admitted.adapter_configuration_json AS adapter_configuration_json
                       FROM backend_executions AS executions
                       JOIN generation_jobs AS admitted
                         ON admitted.job_id = executions.job_id
                       WHERE executions.job_id = ? AND executions.attempt_id = ?""",
                    (job_id, str(current_attempt_id)),
                ).fetchone()
                if execution_row is not None:
                    full_execution = self._decode_backend_execution(execution_row)
                    backend_execution = {
                        "attempt_id": full_execution["attempt_id"],
                        "state": full_execution["state"],
                        "resolved_digest": full_execution["resolved_digest"],
                        "observed_at": full_execution["observed_at"],
                    }
            return {
                "job_id": job.job_id,
                "request": request.to_dict(),
                "status": execution_status,
                "adapter_id": job.adapter_id,
                "adapter_configuration": job_payload["adapter_configuration"],
                "privacy_compliance": privacy_compliance,
                "resolved_prompt": job.resolved_prompt,
                "resolved_seed": job.resolved_seed,
                "validated_reference_ids": list(job.validated_reference_ids),
                "output_slot": job.output_slot,
                "output_slot_id": job.output_slot_id,
                "effective_parameters": job_payload["effective_parameters"],
                "attempt": None if not attempts else attempts[-1].to_dict(),
                "attempts": [attempt.to_dict() for attempt in attempts],
                "artifact": None if artifact is None else artifact.to_dict(),
                "admission": (
                    None if admission_record is None else admission_record.to_dict()
                ),
                "backend_execution": backend_execution,
                "execution": {
                    "status": execution_status,
                    "max_attempts": int(job_row["max_attempts"] or 1),
                    "fence_epoch": int(job_row["fence_epoch"] or 0),
                    "retry_eligible": bool(job_row["retry_eligible"] or 0),
                    "failure_message": job_row["failure_message"],
                    "containment_contract": job_row["containment_contract"],
                    "resource_state": str(job_row["resource_state"] or "available"),
                    "resource_job_id": job_row["resource_job_id"],
                    "resource_attempt_id": job_row["resource_attempt_id"],
                    "resource_owner_id": job_row["resource_owner_id"],
 "resource_reason": job_row["resource_reason"],
                },
            }

    @staticmethod
    def _output_directory_for_job(
        connection: sqlite3.Connection,
        job_id: str,
        effective_parameters_json: str,
    ) -> str | None:
        """Return the output directory captured in current job intent."""
        del connection, job_id
        effective_parameters = json.loads(effective_parameters_json)
        output_directory = effective_parameters.get(_RESOLVED_OUTPUT_DIRECTORY_KEY)
        if not isinstance(output_directory, str) or not output_directory:
            return None
        return str(Path(output_directory).expanduser().resolve())

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> GenerationJob:
        effective_parameters = json.loads(str(row["effective_parameters_json"]))
        effective_parameters.pop(_RESOLVED_OUTPUT_DIRECTORY_KEY, None)
        columns = row.keys()
        execution_status = (
            str(row["execution_status"])
            if "execution_status" in columns and row["execution_status"] is not None
            else str(row["status"])
        )
        return GenerationJob(
            job_id=str(row["job_id"]),
            request_id=str(row["request_id"]),
            status=str(row["status"]),
            adapter_id=str(row["adapter_id"]),
            adapter_configuration=json.loads(str(row["adapter_configuration_json"])),
            resolved_prompt=str(row["resolved_prompt"]),
            resolved_seed=int(row["resolved_seed"]),
            validated_reference_ids=tuple(json.loads(str(row["validated_reference_ids_json"]))),
            output_slot=str(row["output_slot"]),
            output_slot_id=str(row["output_slot_id"]),
            effective_parameters=effective_parameters,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            artifact_id=None if row["artifact_id"] is None else str(row["artifact_id"]),
            max_attempts=int(row["max_attempts"] or 1) if "max_attempts" in columns else 1,
            fence_epoch=int(row["fence_epoch"] or 0) if "fence_epoch" in columns else 0,
            execution_status=execution_status,
            retry_eligible=(
                bool(row["retry_eligible"])
                if "retry_eligible" in columns and row["retry_eligible"] is not None
                else False
            ),
            failure_message=(
                str(row["failure_message"])
                if "failure_message" in columns and row["failure_message"] is not None
                else None
            ),
        )

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> GenerationAttempt:
        columns = row.keys()
        return GenerationAttempt(
            attempt_id=str(row["attempt_id"]),
            job_id=str(row["job_id"]),
            attempt_number=int(row["attempt_number"]),
            status=(
                str(row["execution_status"])
                if "execution_status" in columns and row["execution_status"] is not None
                else str(row["status"])
            ),
            adapter_id=str(row["adapter_id"]),
            started_at=str(row["started_at"]),
            finished_at=None if row["finished_at"] is None else str(row["finished_at"]),
            error_message=None if row["error_message"] is None else str(row["error_message"]),
            owner_id=(
                str(row["owner_id"])
                if "owner_id" in columns and row["owner_id"] is not None
                else None
            ),
            claim_epoch=(
                int(row["claim_epoch"])
                if "claim_epoch" in columns and row["claim_epoch"] is not None
                else 0
            ),
            heartbeat_at=(
                str(row["heartbeat_at"])
                if "heartbeat_at" in columns and row["heartbeat_at"] is not None
                else None
            ),
            lease_expires_at=(
                str(row["lease_expires_at"])
                if "lease_expires_at" in columns and row["lease_expires_at"] is not None
                else None
            ),
            process_contained=(
                bool(row["process_contained"])
                if "process_contained" in columns and row["process_contained"] is not None
                else None
            ),
            containment_contract=(
                str(row["containment_contract"])
                if "containment_contract" in columns and row["containment_contract"] is not None
                else None
            ),
            failure_class=(
                str(row["failure_class"])
                if "failure_class" in columns and row["failure_class"] is not None
                else None
            ),
            termination_proven=(
                bool(row["termination_proven"])
                if "termination_proven" in columns and row["termination_proven"] is not None
                else False
            ),
        )

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> GenerationArtifact | ImportedArtifact:
        if row["origin"] == "imported":
            return ImportedArtifact(
                artifact_id=row["artifact_id"], path=row["path"], media_type=row["media_type"],
                image_format=row["image_format"], width=row["width"], height=row["height"],
                file_size=row["file_size"], sha256=row["sha256"], created_at=row["created_at"],
                import_provenance=json.loads(row["import_provenance_json"]))
        return GenerationArtifact(
            artifact_id=str(row["artifact_id"]),
            job_id=str(row["job_id"]),
            attempt_id=str(row["attempt_id"]),
            output_slot_id=str(row["output_slot_id"]),
            path=str(row["path"]),
            media_type=str(row["media_type"]),
            image_format=str(row["image_format"]),
            width=int(row["width"]),
            height=int(row["height"]),
            file_size=int(row["file_size"]),
            sha256=str(row["sha256"]),
            created_at=str(row["created_at"]),
        )


def _decode_stored_privacy_compliance(
    raw: object,
    adapter_id: str,
) -> dict[str, object]:
    """Decode non-NULL durable evidence or reject it as malformed."""
    try:
        payload = json.loads(str(raw))
    except (TypeError, ValueError) as error:
        raise GenerationError(_MALFORMED_STORED_PRIVACY_EVIDENCE) from error
    if not is_privacy_compliance_record(payload) or payload.get("adapter_id") != adapter_id:
            raise GenerationError(_MALFORMED_STORED_PRIVACY_EVIDENCE)
    return payload


def _stored_privacy_compliance(
    row: sqlite3.Row,
    adapter_id: str,
) -> dict[str, object]:
    """Decode the required durable privacy evidence for a current job."""
    return _decode_stored_privacy_compliance(
        row["privacy_compliance_json"], adapter_id
    )


def _json(value: object) -> str:
    """Serialize a stored value using the canonical JSON conventions."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
