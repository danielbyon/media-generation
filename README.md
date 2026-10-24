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

The synchronous adapter interface receives a resolved `GenerationPlan` and an
open staging stream owned by the service. Adapters write that stream without
reopening a pathname or closing the stream. The bundled
`deterministic-cpu-png-v1` adapter writes an ordinary RGB PNG using only the
Python standard library. Its output is reproducible for the same prompt, seed,
dimensions, and reference contents. Artifact retrieval reports the file path,
PNG dimensions, media type, byte count, and content hash.

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
There is no HTTP API, background worker, retry or lease system, attempt fencing,
or benchmark orchestration. T04 orchestration remains a separate slice.
APEX hardware, real GPU inference, engine behavior, model quality, and hardware
reliability are unverified.

## Validation and generated outputs

Run the full test suite with `python3 -m pytest`. The tests generate real PNG
images, SQLite job/artifact records, and provenance snapshots in temporary
directories, and exercise retrieval through independent installed CLI processes.
Temporary test outputs are not committed to the repository.

GitHub Actions runs the same suite on Ubuntu and macOS with supported Python
versions for pull requests and pushes to `main`. The run logs provide validation
results. For a persistent local image and inspectable database, run the
`media-generation submit` and retrieval commands shown above; their outputs
remain in your chosen local directory.

Generated evidence bundles, screenshots, validation transcripts, and database
snapshots are not version-controlled. Retain specific outputs outside the
repository only when they are needed for a review or investigation.
