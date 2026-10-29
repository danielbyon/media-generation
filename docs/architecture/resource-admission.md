# Resource admission and capacity profiles

## 1. Purpose and authority

Resource admission prevents image, text, vision, scoring, and model-loading
workloads from being dispatched when their declared memory needs cannot fit a
conservative description of the host. Admission is persisted in the same SQLite
database as durable execution.

The singleton `execution_resource` row remains the only heavyweight execution
authority. An admission row explains why a job may claim that resource, but it
does not create a second scheduler.

The capacity decision is captured when a job is queued. A worker reads the
pinned decision from SQLite, so restarting a worker cannot silently substitute
new host inventory or different workload demand.

There are two current admission modes:

1. Heavyweight work must supply complete capacity evidence and receive a
   `queued` decision.
2. The exact bundled `DeterministicCpuAdapter` may receive `not_required` when
   no capacity documents are supplied. This exemption is selected by the
   service after an exact concrete-type check; callers cannot request it.

An adapter subclass, an arbitrary adapter configured to behave like the CPU
adapter, and a command-line flag cannot inherit the exemption. Omitting
capacity documents for any other adapter records a blocked decision that is not
claimable.

## 2. Operator inputs

Capacity admission uses three strict version-1 JSON documents:

1. A T02 inventory report, normally the `inventory.json` written by
   `media-generation inventory`.
2. An admission policy containing explicit byte headroom for every observed
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

Headroom is reserved from the observed total of each named pool. The policy
must name every usable pool. A missing pool, an extra pool name, a missing
headroom value, an unsupported topology, or malformed inventory evidence
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

Each demand dimension may explicitly report `unknown` and a reason. Unknown
memory, context, offload, or residency prevents dispatch. `not_applicable` is
accepted only where the dimension genuinely does not exist; it is not a
substitute for missing evidence.

For `unified_shared` inventory, omit `accelerator_pool_id`: accelerator demand
is charged to `system_ram`. A named accelerator pool is rejected because a
shared aperture does not establish a second allocatable pool.

## 3. Conservative memory accounting

A profile consumes the validated T02 report's
`host.memory.topology.allocatable_pools` and `sharing_relationships`. The
topology's `reported_total_bytes` is descriptive evidence and is never treated
as a separate allocatable pool. The report's stability fingerprint is recomputed
from host, runtime, and Python content before a profile is derived.

1. In unified-memory topology, system and accelerator demand are added once
   against `system_ram`. Shared apertures and visible-VRAM aliases do not add
   independent capacity.
2. In discrete topology, system demand is charged to `system_ram`, and
   accelerator demand is charged to one explicitly named dedicated VRAM pool.
3. Repeated sharing relationships are observations, not extra pools. Duplicate
   aliases therefore cannot increase capacity.
4. A known demand that exceeds any required pool receives `over_budget` and a
   concrete pool name. Insufficient evidence receives `blocked`. Neither state
   is claimable by a worker.

The profile origin and environment fingerprint are persisted with the decision.
A report collected from synthetic replay remains marked `synthetic_replay`; it
does not establish APEX hardware qualification.

## 4. CLI workflow

Pass all three admission documents together when enqueuing or submitting
heavyweight work:

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

All three options may be omitted only for the exact bundled deterministic CPU
adapter. That path stores `not_required` with reason
`lightweight_deterministic_cpu`. For every other adapter, omission stores
`blocked` with reason `resource_admission_required`; the job is durable and
inspectable but cannot be claimed. Supplying only part of the option group is a
validation error. Malformed documents return a structured
`admission_validation_error` before a job is written.

The `admission` command reports the pinned profile and demand, required bytes,
unknown reasons, timestamps, and current decision. If the job owns the singleton
heavyweight resource, the response also includes the reservation state, owner,
attempt, lease, and reserved bytes. It never includes prompts, credentials, or
media bytes.

The service exposes this evidence through one typed inspection. The store reads
the decision and owned reservation in one deferred SQLite read transaction, so
an operator sees a consistent snapshot without taking the database write lock.

## 5. Decisions and reservation lifecycle

1. `queued` means capacity fits and the job is waiting for the singleton
   resource. A `resource_busy` reason means another claim owns that resource;
   it is not a new capacity denial.
2. `not_required` is reserved for the exact lightweight deterministic CPU
   adapter when no capacity evidence was supplied.
3. `blocked` means required profile or demand evidence is unknown or omitted
   for heavyweight work.
4. `denied` means known demand exceeds a required pool.
5. `reserved` means the claim transaction created an attempt, acquired the
   singleton resource, and copied the admitted bytes into the reservation.
6. `released` means confirmed termination and publication reconciliation permit
   reuse.
7. `quarantined` means execution termination or publication reconciliation is
   not proven. Lease expiry or missing heartbeat alone cannot release it.
8. `canceled` means the job was canceled before heavyweight dispatch.

There is no current `legacy` or `unrecorded` decision. A current
`execution_jobs` row without an admission row is structurally invalid. Opening
such a database fails without mutation; the service never fabricates a profile,
demand, fingerprint, reservation, or historical decision. A `queued` decision
must contain both a complete pinned profile and workload demand. Creation,
schema reopening, and claim all reject an empty or malformed queued evidence
pair before an attempt can be created.

Automatic retry moves a reconciled heavyweight admission back to `queued`. A
lightweight CPU retry returns to `not_required` while no capacity documents
exist. Final success or confirmed failure without retry moves the admission to
`released`. Reusing an idempotency key preserves the capacity evidence pinned
when the job was first queued; a later profile or demand document cannot
replace it.

For current work, the explicit-admission requirement applies at the `queued`
boundary. Creation, schema reopening, and claim require a complete,
dispatchable profile and demand for a capacity-backed queued job. The exact
lightweight deterministic CPU adapter is the only adapter that may use
`not_required` without capacity documents. Once an admission has advanced
beyond `queued`, schema reopening does not perform a general revalidation of
its profile, demand, fingerprint, byte counts, or unknown reasons. It does
preserve the CPU exemption lineage: an evidence-free admission in `reserved`,
`released`, or `quarantined` must still belong to the exact lightweight CPU
adapter. A capacity-backed heavyweight reservation remains valid with its
persisted profile and demand evidence.

An admission transition can make a row claimable only when the execution row is
already queued in the same SQLite transaction. This ordering preserves retries
without exposing a capacity reservation before execution is permitted. A worker
may claim `queued` rows or, only when its adapter has the exact bundled
`DeterministicCpuAdapter` concrete type, `not_required` rows. Matching adapter
identity or configuration alone cannot claim the lightweight exemption, and
every claim still requires current privacy and adapter-configuration evidence.

## 6. Evidence boundaries

Synthetic replay and unit tests demonstrate software behavior only. They do not
prove that a particular APEX machine reports the topology described above, that
an inference engine uses only admitted memory, or that a production workload
fits.

APEX-specific qualification remains **UNVERIFIED** until independently collected
host evidence and real-tool execution evidence demonstrate it.
