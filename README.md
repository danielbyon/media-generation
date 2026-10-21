# media-generation

`media-generation` is a small, local image-generation service with a synchronous
CLI and SQLite persistence. It provides an engine-neutral request contract and
a deterministic CPU adapter so application and adapter work can be exercised
without a GPU, model download, or network service.

## Setup

Use Python 3.11 or later. Create an isolated environment and install the package
with its test dependency:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[test]'
```

The runtime has no third-party dependencies. The optional `test` extra supplies
pytest for the black-box CLI and focused invariant tests.

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

Repeating a submission reuses its existing job only when the canonical request
intent, adapter identity, adapter configuration, and resolved output directory
all match the values stored for that idempotency key. A changed request intent,
adapter identity or configuration, or output directory produces an explicit
`idempotency_conflict`. A matching succeeded job returns its existing artifact
identity; a matching failed job remains inspectable as failed. If no seed is
supplied, the service resolves one from the canonical request digest and
persists it before adapter execution.

## Persistence and adapter boundary

SQLite stores immutable request content separately from each durable job and
its execution attempt. Before invoking an adapter, the service commits the
resolved prompt, seed, adapter identity and configuration, validated reference
IDs, output-slot identity, and effective dimensions. The artifact record keeps
a unique logical ID separate from the SHA-256 hash of its file contents.

The synchronous adapter interface receives a resolved `GenerationPlan` and a
destination path selected by the service. The bundled
`deterministic-cpu-png-v1` adapter writes an ordinary RGB PNG using only the
Python standard library. Its output is reproducible for the same prompt, seed,
dimensions, and reference contents. Artifact retrieval reports the file path,
PNG dimensions, media type, byte count, and content hash.

## T01 limits

This slice proves the local request-to-image and provenance path. The bundled
adapter creates a deterministic test image, not a production model result.
There is no HTTP API, background worker, retry or lease system, crash-window
artifact reconciliation, production publication workflow, or benchmark
orchestration. T03/T04 publication and orchestration work remains out of scope.
APEX hardware, real GPU inference, engine behavior, model quality, and hardware
reliability are unverified.

## Evidence and validation

The JSON snapshots under `evidence/t01/` store artifact paths relative to the
repository so they can be reviewed from any checkout. The SQLite database keeps
resolved absolute paths for runtime access. After moving the evidence to a new
checkout path, reinstall the package and rebuild those runtime paths from the
verified artifact files:

```sh
python3 -m pip install -e '.[test]'
python3 evidence/t01/relocate.py
```

The relocation regression test copies the evidence into a separate checkout
path, runs the same reconstruction utility there, verifies artifact hashes and
portable snapshots, and reads the relocated artifact through the installed CLI.
Run it with the full test suite using `python3 -m pytest`.

`evidence/t01/validator-result.json` is the historical approved validation
record and retains the commit SHA and worktree fingerprint captured at that
time. A later local validation is recorded separately; its branch and commit
SHA identify the checked-out base, while its validation output and worktree
fingerprint describe the uncommitted implementation under review. It is
pre-push evidence and does not claim that a later commit or hosted CI run was
validated.
