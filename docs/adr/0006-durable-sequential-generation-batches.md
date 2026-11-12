# ADR 0006: Durable sequential generation batches

Status: Accepted

## Context

`GenerationService` owns admission, single-output execution, resource
reservations, attempt termination evidence, and publication. A batch needs a
durable request order and restart coordination while keeping those T04
decisions authoritative.

Batch recovery also needs to distinguish a newly admitted queued job from a
queued job whose bounded retry was already authorized. A coordinator lease
records ownership of batch updates. It cannot establish that an adapter or
service attempt has stopped.

## Decision

Add `GenerationBatchService` as a sequential coordinator over the existing
`GenerationService`. Persist an immutable batch manifest and one durable slot
per request in the same SQLite database. Schema version 7 includes batch and
slot tables, identity constraints, and writer-epoch guards. Existing version-6
databases fail read-only validation without migration.

Each slot pins its request, ordinal, stable service idempotency key, attempt
budget, and applicable admission profile and workload demand. The coordinator
commits all batch intent before it calls T04. It resolves an accepted T04 job
through its idempotency key before admission and reuses that job when present.
Every new or reused job still passes through T04 `enqueue`, which enforces the
existing admission and frozen service-job identity.

The batch manifest pins adapter configuration, privacy evidence, and resolved
output destination. Resumption requires exact matching profile and per-slot
demand inputs. T04 retains the execution configuration and admission record
already stored on each accepted job.

Execution stays sequential. A queued job with no attempts uses T04 `submit`.
A retry requires verified attempt history, termination proof, and remaining
budget. When T04 reports retry eligibility, the coordinator calls T04 `retry`
before `submit`. When T04 has already changed a failed job to `queued`, cleared
its retry flag, and restored admission to `queued`, that persisted transition
records the authorization; after a crash at this handoff, the coordinator
calls `submit` on the same job. A queued retry without this authorization is
held for attention. Failed jobs with exhausted or denied eligibility remain
inspectable. Running, canceled, ambiguous, quarantined, and unknown states are
observed or passed to T04 `recover` when that job owns the service resource.
Unresolved states require attention or refusal.

Coordinator claim expiry permits a new coordinator owner and fencing epoch. It
does not change the T04 attempt state or resource ownership. T04 recovery and
publication fencing determine whether the job can continue. The coordinator
calls recovery only after the persisted reservation matches both the job and
its current attempt. A failed slot with verified retry authority and remaining
budget keeps the batch in its running state, even if later slots have finished.

Batch reports read the current schema through a read-only connection and use
non-persisting integrity inspection. They report coordinator state, execution
status, publication state, artifact integrity, and lineage separately. A T04
success with missing or inconsistent publication, artifact, lineage, or file
evidence remains historically successful and is marked as requiring attention.

## Consequences

The batch layer adds durable order and recovery without creating a second
execution, admission, resource-ownership, or publication protocol. Lost
acknowledgements resolve through the stable idempotency key. A batch can report
partial success while preserving every T04 job and artifact identity.

The database supports only its exact current schema. Version-6 databases need
a new database path or an explicit owner-managed replacement. The coordinator
is local to the shared SQLite database; this decision adds no distributed
scheduler, schema migration, or broader execution refactor.

## Policy provenance

The applicable development-process policy is the immutable document at commit
`aa8dc7784641dd5416befdebc246ed081bfd7ade`. `skills/distribution.json` is absent
at that historical commit. It exists on current `development-process` main and
identifies the same policy revision. The difference is historical manifest
availability; both references identify one policy revision.
