# Resource admission and capacity profiles

## 1. Purpose and authority

Resource admission prevents image, text, vision, scoring, and model-loading
workloads from being dispatched when their declared memory need cannot fit a
conservative description of the host. It extends the durable execution tables
already owned by one SQLite database. The existing singleton
`execution_resource` row remains the only heavyweight execution authority; the
admission row records why a job was allowed, blocked, or denied, but it does not
create a second scheduler.

The capacity decision is captured when a job is queued. A worker reads that
pinned decision and profile from SQLite, so restarting the worker does not
require, and cannot silently substitute, a new host inventory snapshot.

## 2. Operator inputs

Admission uses three strict version-1 JSON documents:

1. A T02 inventory report, normally the `inventory.json` written by
   `media-generation inventory`.
2. An admission policy containing an explicit byte headroom for every observed
   allocatable pool.
3. A workload demand describing the memory, context, offload, and residency
   requirements of the queued work.

The policy shape is:

```json
{
  "schema": "media-generation.admission-policy",
  "schema_version": 1,
  "pool_headroom_bytes": {
    "system_ram": 8589934592,
    "nvidia:0:vram": 4294967296
  }
}
```

Headroom is a byte count reserved from the observed total of each named pool.
The policy must name every usable pool. A missing pool, an extra pool name, a
missing headroom value, an unsupported topology, or malformed inventory evidence
produces a blocked profile rather than an inferred limit.

An image workload example is:

```json
{
  "schema": "media-generation.workload-demand",
  "schema_version": 1,
  "kind": "image",
  "memory": {
    "status": "known",
    "system_ram_bytes": 21474836480,
    "accelerator_memory_bytes": 21474836480,
    "accelerator_pool_id": "nvidia:0:vram"
  },
  "context": {"status": "known", "tokens": 4096},
  "offload": {"status": "known", "mode": "none"},
  "residency": {"status": "known", "mode": "transient"}
}
```

`kind` may be `image`, `text`, `vision`, `scoring`, or `model_loading`.
Each demand dimension may instead be explicitly `unknown` with a reason. Unknown
memory, context, offload, or residency prevents dispatch. `not_applicable` is
accepted where a dimension genuinely does not exist, but it must not be used to
represent missing evidence.

For `unified_shared` inventory, omit `accelerator_pool_id`: accelerator demand is
charged to `system_ram`. A named accelerator pool is rejected because unified
sharing aliases do not establish a second allocatable capacity pool.

## 3. Conservative memory accounting

The profile consumes the validated T02 report's
`host.memory.topology.allocatable_pools` and `sharing_relationships`. The
topology's `reported_total_bytes` is descriptive evidence and is never used as a
separate allocatable pool. The report's stability fingerprint is recomputed from
the host, runtime, and Python content before the profile is derived.

1. For a unified-memory topology, system memory and accelerator demand are added
   once against `system_ram`. Shared apertures and visible-VRAM aliases are not
   added as independent capacity.
2. For a discrete topology, system demand is charged to `system_ram`, and
   accelerator demand is charged to one explicitly named dedicated VRAM pool.
3. Repeated sharing relationships are observations, not extra pools. Duplicate
   aliases therefore cannot increase capacity.
4. A known demand that exceeds any required pool receives `over_budget` and a
   concrete pool name. A topology or demand with insufficient evidence receives
   `blocked`. Neither state is claimable by a worker.

The profile origin and environment fingerprint are persisted with the decision.
A T02 report collected from a synthetic replay remains marked as
`synthetic_replay`; it does not establish APEX hardware qualification.

## 4. CLI workflow

Pass all three admission documents together when enqueuing or submitting work:

```sh
media-generation enqueue \
  --db ./studio.sqlite3 \
  --output-dir ./artifacts \
  --idempotency-key portrait-003 \
  --request-json - < request.json \
  --inventory-report ./inventory/inventory.json \
  --admission-policy ./admission-policy.json \
  --workload-demand ./image-demand.json

media-generation worker --db ./studio.sqlite3 --output-dir ./artifacts --limit 1
media-generation admission --db ./studio.sqlite3 --job-id <job-id>
```

When the three admission options are omitted, existing deterministic CPU
workflows retain the historical `legacy` admission path. Supplying only part of
the group is a validation error. Malformed documents return the structured
`admission_validation_error` CLI response before a job is written.

The `admission` command reports the pinned profile and demand, required bytes,
unknown reasons, timestamps, and current decision. If this job owns the singleton
heavyweight resource, the response also includes the reservation state, owner,
attempt, lease, and reserved bytes. It never includes prompts, credentials, or
media bytes.

The service exposes those fields through one typed admission inspection. The
store reads the decision and its owned reservation in one deferred SQLite read
transaction, so an operator inspection sees a consistent snapshot without
reserving the database write lock.

## 5. Decisions and reservation lifecycle

1. `queued` means the capacity fit and the job is waiting for the singleton
   resource. `resource_busy` is a queued reason, not a capacity denial.
2. `blocked` means required profile or demand evidence is unknown.
3. `denied` means known demand exceeds a required pool.
4. `reserved` means the existing claim transaction created an attempt, claimed
   the singleton resource, and copied required bytes into the reservation in the
   same commit.
5. `released` means confirmed termination and publication reconciliation permit
   reuse.
6. `quarantined` means execution termination or publication reconciliation is
   not proven. Lease expiry or a missing heartbeat alone cannot produce release.
7. `canceled` means the job was canceled before heavyweight dispatch.
8. `legacy` identifies a historical or intentionally CPU-only job admitted
   without capacity documents.
9. `unrecorded` means the job predates the admission schema and therefore has no
   trustworthy profile, demand, or decision evidence to report.

Automatic retry moves a reconciled admission back to `queued`; final success or
confirmed failure without retry moves it to `released`. A repeated idempotency
key reuses the original pinned evidence and never overwrites it with a later
profile or demand document.

An admission row can enter `queued` only when its execution row is already
`queued` in the same SQLite transaction. This keeps automatic retry and manual
requeue from exposing admission evidence as claimable before the execution
lifecycle permits a claim.

Jobs migrated from the pre-admission version 4 schema have no admission row and
remain inspectable as `unrecorded`; no profile, demand, fingerprint, or
reservation is fabricated. A queued migrated job cannot be claimed or retried
until an idempotent re-submission supplies valid profile and demand evidence and
atomically attaches a pending admission row. Missing or conflicting evidence is
refused. An attempt that was already running at migration may complete or fail
through its existing fenced owner; if it becomes retry-eligible, the durable
queued state remains non-claimable until re-admitted. Once an admission row
exists, only its explicit `queued` or `legacy` decisions are claimable.

## 6. Evidence boundaries

Synthetic replay and unit tests demonstrate software behavior only. They do not
prove that a particular APEX machine has a reported topology, that an inference
engine uses only the admitted memory, or that a production workload fits.
APEX-specific qualification remains **UNVERIFIED** until independently collected
host evidence and real-tool execution evidence demonstrate it.
