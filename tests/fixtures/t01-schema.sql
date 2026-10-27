-- Frozen T01 schema from origin/main 92b6429118c8335d4fb00ca42b4a1a300cfac0e1.
-- Tests create a real SQLite database from this schema at runtime.

CREATE TABLE IF NOT EXISTS generation_requests (
    request_id TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS generation_jobs (
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
);

CREATE TABLE IF NOT EXISTS generation_attempts (
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
);

CREATE TABLE IF NOT EXISTS generation_artifacts (
    artifact_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES generation_jobs(job_id),
    attempt_id TEXT NOT NULL REFERENCES generation_attempts(attempt_id),
    output_slot_id TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    image_format TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (job_id, output_slot_id),
    FOREIGN KEY (job_id, attempt_id)
        REFERENCES generation_attempts(job_id, attempt_id)
);

CREATE INDEX IF NOT EXISTS generation_artifacts_job_idx
    ON generation_artifacts(job_id);

CREATE TRIGGER IF NOT EXISTS generation_requests_immutable_update
BEFORE UPDATE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END;

CREATE TRIGGER IF NOT EXISTS generation_requests_immutable_delete
BEFORE DELETE ON generation_requests
BEGIN
    SELECT RAISE(ABORT, 'generation requests are immutable');
END;

CREATE TRIGGER IF NOT EXISTS generation_artifacts_immutable_update
BEFORE UPDATE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS generation_artifacts_immutable_delete
BEFORE DELETE ON generation_artifacts
BEGIN
    SELECT RAISE(ABORT, 'generation artifacts are immutable');
END;
