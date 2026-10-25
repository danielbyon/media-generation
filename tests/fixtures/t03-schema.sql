-- Frozen final T03 DDL from 3285dc0382ebcbb54aecfe0c8d25331c0da77257.
-- Extracted from historical initialization and artifact migration, without running T04.

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

CREATE TABLE generation_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES generation_jobs(job_id),
                    attempt_id TEXT REFERENCES generation_attempts(attempt_id),
                    output_slot_id TEXT,
                    path TEXT NOT NULL UNIQUE,
                    media_type TEXT NOT NULL, image_format TEXT NOT NULL,
                    width INTEGER NOT NULL, height INTEGER NOT NULL,
                    file_size INTEGER NOT NULL, sha256 TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS generation_artifacts_job_idx
                ON generation_artifacts(job_id);

CREATE TABLE IF NOT EXISTS artifact_edges (
                source_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
                target_id TEXT NOT NULL REFERENCES generation_artifacts(artifact_id),
                role TEXT NOT NULL CHECK (role IN ('reference','source','derivation','inspiration')),
                position INTEGER NOT NULL CHECK (position >= 0),
                CHECK (source_id != target_id),
                PRIMARY KEY (target_id, position),
                UNIQUE (source_id, target_id, role)
            );

CREATE TRIGGER IF NOT EXISTS artifact_edges_acyclic
                BEFORE INSERT ON artifact_edges BEGIN
                SELECT RAISE(ABORT, 'artifact lineage cycle') WHERE EXISTS (
                    WITH RECURSIVE descendants(id) AS (
                        SELECT target_id FROM artifact_edges WHERE source_id = NEW.target_id
                        UNION SELECT e.target_id FROM artifact_edges e JOIN descendants d
                        ON e.source_id = d.id
                    ) SELECT 1 FROM descendants WHERE id = NEW.source_id
                ); END;

CREATE TABLE IF NOT EXISTS artifact_publications (
                publication_id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL UNIQUE,
                root TEXT NOT NULL, root_dev INTEGER NOT NULL, root_ino INTEGER NOT NULL,
                root_token TEXT NOT NULL,
                stage_name TEXT NOT NULL UNIQUE, stage_dev INTEGER, stage_ino INTEGER,
                final_name TEXT, state TEXT NOT NULL
                    CHECK (state IN ('allocated','ready','committed','abandoned')),
                job_id TEXT, attempt_id TEXT, artifact_json TEXT, sources_json TEXT NOT NULL,
                created_at TEXT NOT NULL, error TEXT
            );

CREATE TABLE IF NOT EXISTS artifact_integrity (
                artifact_id TEXT PRIMARY KEY REFERENCES generation_artifacts(artifact_id),
                status TEXT NOT NULL CHECK (status IN ('ok','missing','corrupt')),
                checked_at TEXT NOT NULL, detail TEXT
            );

CREATE TRIGGER IF NOT EXISTS artifact_edges_sealed
                BEFORE INSERT ON artifact_edges
                WHEN NOT EXISTS (SELECT 1 FROM artifact_publications
                    WHERE artifact_id = NEW.target_id AND state = 'ready')
                BEGIN SELECT RAISE(ABORT, 'artifact lineage is sealed'); END;

CREATE TRIGGER IF NOT EXISTS artifact_edges_immutable_update BEFORE UPDATE ON artifact_edges BEGIN SELECT RAISE(ABORT, 'artifact edges are immutable'); END;

CREATE TRIGGER IF NOT EXISTS artifact_edges_immutable_delete BEFORE DELETE ON artifact_edges BEGIN SELECT RAISE(ABORT, 'artifact edges are immutable'); END;

PRAGMA user_version = 2;
