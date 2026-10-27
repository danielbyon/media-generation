# media-generation

`media-generation` is a small, local image-generation service with synchronous
submission, an opt-in durable worker CLI, and SQLite persistence. It provides an
engine-neutral request contract and a deterministic CPU adapter so application
and adapter work can be exercised without a GPU, model download, or network
service.

## Setup

### Development commands

The root `Makefile` is the canonical development interface. Run `make help` to
see the complete target list. The first and default target only prints help, so
an accidental `make` cannot install packages or remove files.

1. `make setup` creates or refreshes the local `.venv` with `PYTHON`.
2. `make install` installs the package and test dependencies into the selected
   interpreter. Activate `.venv` first, or pass an explicit interpreter such as
   `make install PYTHON=.venv/bin/python`.
3. `make test` runs the full pytest suite under the shared worktree lock.
4. `make smoke` runs the `media-generation --help` entry point installed beside
   the selected `PYTHON`; set `CLI` only to override that location explicitly.
5. `make check` runs the test and smoke gates together.
6. `make clean-dry-run` validates and prints the exact cleanup plan without
   changing any file.
7. `make clean` runs that same cleanup engine and removes only the verified
   regenerable outputs described below.
8. `make clean-deep` is a separate, interactive action. It requires an explicit
   confirmation before removing a validated local `.venv`.

See [development cleanup](docs/architecture/development-cleanup.md) for the
ownership checks, protected paths, lock limitations, and report fields.

Use Python 3.14.4 or later in the 3.14 series. Python 3.11-3.13 and 3.15
are not supported. Create an isolated environment and install the package
with its test dependency:

```sh
python3.14 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[test]'
```

Pillow provides bounded PNG/JPEG verification and decoding. The optional `test`
extra supplies pytest for the black-box CLI and focused invariant tests.

## Submit and inspect a generation

Submit a canonical request using a stable idempotency key:

```sh
media-generation submit \
  --db ./studio.sqlite3 \
  --output-dir ./artifacts \
  --idempotency-key portrait-study-001 \
  --request-json '{"prompt":"A copper fox beneath a violet moon","seed":731,"width":64,"height":64,"reference_ids":[],"output_slot":"hero"}'
```

The command returns JSON containing the request ID, job ID, output-slot ID,
status, and logical artifact ID. Use those IDs to retrieve snapshots in later,
independent processes:

```sh
media-generation request --db ./studio.sqlite3 --id <request-id-from-submit>
media-generation job --db ./studio.sqlite3 --id <job-id-from-submit>
media-generation artifact --db ./studio.sqlite3 --id <artifact-id-from-submit>
media-generation provenance --db ./studio.sqlite3 --job-id <job-id-from-submit>
```

`--request-json -` reads the JSON object from standard input. Requests accept a
prompt, optional seed, width, height, a list of persisted artifact IDs, and a
semantic output-slot name. They do not accept adapter workflow syntax or input
file paths and URLs. A reference must be an existing logical artifact ID; an
unknown ID, malformed path-like value, unsupported dimension, or unsupported
adapter capability produces a structured error and a nonzero exit status. Before
execution, the service verifies that every referenced file still exists and
matches the SHA-256 value stored with its artifact record.

Repeating a submission reuses the existing job when the canonical request
intent, adapter identity, adapter configuration, and resolved output directory
all match the values stored for that idempotency key. A supplied attempt budget
must also match for a non-succeeded job. If a non-succeeded job recorded a
containment contract, the contract must match as well. A changed value produces
an explicit `idempotency_conflict`. A migrated terminal failed T01/T03 job whose
persisted containment contract is NULL keeps the legacy reuse behavior after
the other checks pass; that exception never applies to a queued or running job,
or to two different non-NULL contracts. A matching queued job retains its
persisted attempt budget; a matching succeeded job returns its existing artifact
identity; and a matching failed or ambiguous job remains inspectable. An omitted
`max_attempts` does not rewrite the budget chosen by the first admission, while an
explicitly different budget conflicts for non-succeeded work. If no seed is supplied,
the service resolves one
from the canonical request digest and persists it before adapter execution.

`submit` atomically admits a job and then attempts one synchronous execution.
It omits admission policy, so it reuses an existing job's persisted budget
without changing it. If another attempt owns the database's single heavyweight
resource, the command returns a structured `resource_busy` error containing
the durable `job_id`; it does not report a queue entry as a completed image.
Repeating `submit` after the resource is free executes the same queued job
without creating a second job, output slot, or attempt budget.

Job JSON reports two status dimensions without removing either compatibility
field: `status` is the legacy `generation_jobs.status` lifecycle
(`running`, `succeeded`, or `failed`), while `execution_status` is the durable
queue state (`queued`, `running`, `succeeded`, `failed`, `canceled`, or
`ambiguous`). `SubmissionResult.status` and provenance's top-level `status`
report the durable execution state. A queued job can show legacy `status`
`running` while `execution_status` is `queued`.

The SQLite database has one heavyweight execution resource shared by every job.
Resource occupancy is therefore provenance-wide context, not a property of an
individual job snapshot. `provenance.execution.resource_state` reports that
global state, and `resource_job_id`, `resource_attempt_id`, and
`resource_owner_id` identify its owner when one applies. A queued job must not
be interpreted as claiming the resource merely because a different job holds
it.

## Persistence and adapter boundary

SQLite stores immutable request content separately from each durable job and
its execution attempt. Before invoking an adapter, the service commits the
resolved prompt, seed, adapter identity and configuration, validated reference
IDs, output-slot identity, and effective dimensions. The artifact record keeps
a unique logical ID separate from the SHA-256 hash of its file contents.

The synchronous adapter interface receives a resolved `GenerationPlan` and an
open staging stream owned by the service. Adapters write that stream without
reopening a pathname or closing the stream. The bundled
`deterministic-cpu-png-v1` adapter writes an ordinary RGB PNG using only the
Python standard library. Its output is reproducible for the same prompt, seed,
dimensions, and reference contents. Artifact retrieval reports the file path,
PNG dimensions, media type, byte count, and content hash.

## Local inference privacy configuration

Each inference adapter has a versioned effective configuration. An
application-owned privacy profile binds the exact adapter identity,
configuration version, tool identity and version to required local-only setting
values. The evaluator checks external APIs, hosted/cloud inference, telemetry,
content upload, automatic network fetch or update, remote endpoints or proxies,
and cloud fallback. Missing settings or unrecognized values produce
`unverified`; a known
prohibited value produces `fail`; only a complete match produces `pass`.

The machine-readable result records the profile and configuration fingerprints,
control evidence, stable reason codes, and fixed assurance limitations. It never
contains raw adapter configuration and never claims network isolation or APEX
qualification. Credential-like and model-acquisition settings are rejected from
runtime configuration because credentials and acquisition concerns must remain
separate from inference settings.

The service rejects `fail` configuration. A matching compliance-capable profile
also rejects `unverified` values automatically. Callers can set
`require_privacy_pass=True` to reject an adapter that has no trusted profile at
all. The bundled deterministic CPU adapter retains its legacy execution behavior
under the default admission mode, but its provenance is explicitly `unverified`
for real-tool privacy. A job's
stored privacy evidence and exact configuration are required to match before an
idempotent submission is reused or a worker claims the job.

See [privacy compliance architecture](docs/architecture/privacy-compliance.md)
for the profile contract,
redaction rules, migration behavior, and real-tool integration responsibilities.

Before opening an existing T01 or T03 database with this release, stop every
older CLI worker, adapter process, and inference child that can write the
database or image tree; wait for them to exit. Back up the database with the
SQLite backup API or while it is offline, and preserve the image tree and
publication roots with it. The version 4 migration adds nullable privacy
evidence to execution jobs and preserves earlier rows as explicitly unverified.
The migration also installs database guards
that reject later writes from binaries that do not identify themselves as
current, but a trigger cannot prove that an already-running process stopped or
prevent it from changing files before its database commit fails. Restore the
pre-migration database before intentionally running an older binary again; a
version 4 database is not safely downgradeable in place.

## Durable execution

Use `enqueue` when admission and execution occur in separate processes:

```sh
media-generation enqueue --db ./studio.sqlite3 --output-dir ./artifacts \
  --idempotency-key portrait-study-002 --max-attempts 2 \
  --request-json '{"prompt":"A copper fox beneath a violet moon","seed":731,"width":64,"height":64,"reference_ids":[],"output_slot":"hero"}'

media-generation worker --db ./studio.sqlite3 --output-dir ./artifacts --limit 1
media-generation provenance --db ./studio.sqlite3 --job-id <job-id>
```

Admission stores the immutable request intent, the complete resolved execution
plan, adapter identity and configuration, reference IDs and hashes, output-slot
identity, and resolved destination before any attempt exists. A queued job has no
attempt until a worker claims it atomically. Workers sharing a database use one
heavyweight reservation, an owner and fence epoch, and a 30-second lease with a
five-second heartbeat while the adapter runs. `--limit` bounds how many queued
jobs one worker invocation considers; it does not permit concurrent heavyweight
attempts in the same database.

Worker JSON keeps invocation-level status and processed count. A complete loop
also returns outcomes for each claimed job and attempt, including attempt
status, job execution_status, failure_class, and termination_proven. Each
outcome is captured before another claim, so a failed retry followed by success
remains visible as two outcomes. The worker CLI exits 0 only for an idle loop
or when every processed attempt succeeded with termination proof. It exits 1
for contention or any failed, canceled, ambiguous, retry-queued, unresolved, or
unproven attempt, while preserving the JSON outcomes. A retry queued within its
saved budget remains available to a later worker despite that nonzero exit.

`--max-attempts` applies when a new job is admitted and defaults to one total
attempt. Reusing a matching job never resets its persisted budget; supplying
an explicitly different value conflicts for non-succeeded work. Reusing a
succeeded job ignores the incoming budget and leaves its persisted policy and
artifact unchanged. An automatic retry requires an
eligible failure classification, proof that the previous execution terminated,
successful publication recovery, an available resource, and remaining
persisted budget. An unknown outcome is quarantined and is never replayed
automatically. Restarting a worker does not reset the budget.

Termination proof comes only from a containment contract declared directly by
the adapter. Adapter identity, configuration, or a subclassed adapter's
inherited behavior is not proof. A valid artifact produced without that proof
remains committed and inspectable, while its attempt records
`termination_proven=false` and the heavyweight resource remains quarantined.
A noncanceled failure without proof is reported as `ambiguous`, retains its
failure classification, and cannot authorize replay.

Inspect or control durable work with:

```sh
media-generation cancel --db ./studio.sqlite3 --job-id <job-id>
media-generation retry --db ./studio.sqlite3 --job-id <job-id>
media-generation recover --db ./studio.sqlite3 --output-dir ./artifacts
```

`retry` acknowledges an eligible bounded retry that is already queued. Repeated
retry requests are idempotent and preserve the job, request, output slot, attempt
history, and immutable budget while the job remains queued, eligible, within
budget, and the heavyweight resource is available. A later worker claim, failed
recovery, or another job's resource claim can make a later request fail instead
of acknowledging stale eligibility. A later worker claim creates the next
attempt only when the persisted retry policy permits it.

Migration preserves historical failed work as terminal. The job keeps one
historical attempt, a one-attempt budget, retry eligibility set to false, and a
terminal attempt classification. Neither `work` nor `retry` replays that work.
Reusing its idempotency key returns the existing failed job under the NULL
containment compatibility rule above; it does not admit or execute new work.

Cancellation of a never-claimed job is terminal and creates no attempt. An
active attempt is fenced immediately, but cancel returns `accepted` while the
adapter may still be running. Releasing the heavyweight resource requires
evidence that execution stopped. A cancel after the artifact transaction commits
returns `too_late`; the successful artifact remains authoritative. Run `recover`
after an interrupted worker stops. It reconciles interrupted publication state
and reports `attention_required` when a process outcome or retained file cannot
be proven safe for further execution.

## Import, lineage, and recovery

Explicitly approve a local source directory and import a relative filename:

```sh
media-generation import --db ./studio.sqlite3 --output-dir ./artifacts \
  --approved-root /absolute/path/to/approved-images --source portrait.jpg
media-generation integrity --db ./studio.sqlite3 --output-dir ./artifacts --id <artifact-id>
media-generation lineage --db ./studio.sqlite3 --id <artifact-id>
media-generation reconcile --db ./studio.sqlite3 --output-dir ./artifacts
```

The approved root is an operator permission for this invocation. The source must
stay beneath it without traversing symlinks. Use the returned Artifact ID in
`reference_ids` to generate from an imported image. Each import has independent
identity and import provenance; it does not create a generation job. PNG and JPEG
are validated by full decoded content. Limits are 32 MiB encoded bytes, 8192 per
dimension, and 16,777,216 pixels; animated images and other formats are rejected.
Bytes are preserved, including image metadata. Import optional ordered lineage
with `--sources-json '[{"artifact_id":"<existing-id>","role":"inspiration"}]'`.

Publication requires a local macOS/Linux filesystem supporting durable extended
attributes, hard links, advisory locks, and file/directory sync. It stages and
syncs a file before a no-overwrite final link, directory
sync, and atomic metadata/lineage transaction. If interrupted, run `reconcile`
with the same database and output directory. It finishes validated owned
publications, cleans only proven private staging, and reports unknown files or
missing/corrupt media. It never deletes a published image. `artifact` remains a
historical metadata view; use `integrity` for a current content check. Published
content is verified before new reference use.

See [publication and recovery](docs/architecture/artifact-publication.md) for
ordering, migration, source authority, graph roles, and filesystem limitations.

## Current limits

This slice proves the local request-to-image and provenance path. The bundled
adapter creates a deterministic test image, not a production model result.
There is no HTTP API, graphical interface, distributed worker pool, or benchmark
orchestration. All cooperating workers must use the same SQLite database and
local output directory; the database enforces one heavyweight attempt at a time.
The bundled deterministic CPU adapter is the only real adapter in this context.
Its privacy evidence is configuration-unverified and does not qualify a real
inference tool. APEX hardware, real GPU inference, model quality, network
confinement, and hardware reliability are unverified.

## Read-only host inventory

Collect a bounded local snapshot without a GPU, model inference, installs, or
network access:

```sh
PYTHONPATH=src python3 -m media_generation inventory \
  --output /path/outside-the-repository/inventory-run
```

Collection is read-only unless version or device probes are explicitly enabled.
Before staging, the command snapshots existing destinations without following
final links. Missing paths, regular files up to 32 MiB, and symlink entries are
supported. Unreadable, non-regular, oversized, or changing destinations abort
before either file is replaced. The command stages `inventory.json` and
`transcript.txt` through exclusive temporary files in the output directory,
publishes the transcript first and the inventory second, and attempts a
best-effort rollback if the second replacement fails. The two replacements are
not crash-atomic; concurrent writers or a failed rollback can leave a mixed
pair. Both files carry the same run identifier.
Add `--manifest PATH`
to declare model roots, runtime paths, bundles, recipes, capabilities, and probe
policy. Version probes and device queries are opt-in. Full component hashing is
opt-in with `--hash-components`.

Exit status `0` means a complete host inventory, `4` means `partial`, and `5`
means `blocked`; all three write a report. Validation failures exit `2` and
output failures exit `3`. A written report is not APEX verification or
capability qualification. Generated inventories and transcripts must stay
outside Git.

See [the inventory architecture guide](docs/architecture/inventory.md) for the
manifest format, memory semantics, bounded header limits, fingerprint inputs,
and the operator workflow for running on a target host.

## Validation and generated outputs

Run the full test suite with `make test`. The tests generate real PNG
images, SQLite job/artifact records, and provenance snapshots in temporary
directories, and exercise retrieval through independent installed CLI processes.
Temporary test outputs are not committed to the repository.

Before reclaiming local build and test output, run `make clean-dry-run`. Its
human report contains the same candidate decisions and byte estimates as
`make clean`; the actual cleanup report adds filesystem free-space observations.
The cleanup command never replaces `media-generation recover` or `reconcile`,
which own application recovery and publication state.

GitHub Actions runs the same suite on Ubuntu and macOS with supported Python
versions for pull requests and pushes to `main`. The run logs provide validation
results. For a persistent local image and inspectable database, run the
`media-generation submit` and retrieval commands shown above; their outputs
remain in your chosen local directory.

Generated evidence bundles, screenshots, validation transcripts, and database
snapshots are not version-controlled. Retain specific outputs outside the
repository only when they are needed for a review or investigation.

### Idle-checkout cleanup

Run cleanup manually only while no build, test, install, generation or other
cleanup process writes the checkout. Hostile/concurrent writers are outside
this utility's contract. `make clean-dry-run` is read-only; `make clean` preserves
protected application data and `.venv`. Separately confirmed `make clean-deep`
deletes **all** verified local `.venv` contents, including custom files. See
[development cleanup](docs/architecture/development-cleanup.md) for boundaries,
reports, exclusions, and the standalone `python3 scripts/clean.py` fallback.
