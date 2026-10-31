# ADR 0003: Supervised backend execution evidence

Status: Accepted

## Context

The existing execution model can prove termination for the deterministic CPU
adapter because it runs in-process under a declared containment contract. A
real inference engine is a separate process. Its pre-dispatch intent, actual
spawn, and post-reap facts have different failure modes and must not be shared
in one mutable status field.

The service also needs to distinguish a safe preparation refusal from an
uncertain inference execution. Treating every failure after candidate loading
as an ambiguous GPU failure would quarantine the heavyweight resource even when
no process started. Conversely, treating a successful publication or an
adapter-reported exit as proof of termination would release the resource
without application-owned evidence.

The selected stable-diffusion.cpp command line has version-dependent syntax for
Qwen zero-conditioning and different meanings for reference and img2img inputs.
The application cannot safely infer a build's syntax from its version string or
probe flags during dispatch.

## Decision

Add a schema-versioned `backend_executions` table keyed by attempt. A row starts
with an immutable resolved plan, may transition once to a launch fact, and may
transition once from launched to an observed fact. SQL constraints and triggers
enforce the shape and one-way transitions; store methods add current-owner and
claim-epoch fencing plus exact row-count checks.

The application owns process supervision. It starts one direct child without a
shell, records launch after a successful spawn, drains pipes in bounded memory
while hashing every byte, reaps the child, and only then writes observation.
The observation records byte counts, complete digests, and a bounded text-free
classification of each stream. Captured output is never persisted, because
subprocess text can repeat a prompt or a credential. The observation also
records process-tree containment as false.

Termination proof comes from either an existing trusted static containment
contract or a validated observed record for the direct child. Reaping alone is
not enough: if an inherited pipe still has a live writer after the bounded
post-reap drain, the record marks the inherited streams as retained, termination
stays unproven, and the resource stays quarantined. Only an empty read
establishes a genuine end of stream. `EOFError`, `ValueError`, `EBADF`, and
every other unexpected read failure set an explicit stream-state uncertainty
flag with the same effect, because an unsuccessful read is not evidence that
the pipe closed. Missing or invalid evidence fails closed.

Preparation failures are classified before dispatch with stable codes. A failure
before resolution completes creates no backend execution row. If preparation
fails after the resolved row is written and before a child starts, the service
retains that row in the resolved state with no launch or observation and
finalizes the attempt as a terminal preparation failure. A real-engine attempt
is not marked dispatched until its resolved plan has been durably inserted.

Static worker configuration uses the stable T07 candidate identity plus engine,
recipe, component, profile, and privacy settings. It excludes observation
identity, the fresh `verification_id`, timestamps, absolute candidate paths, and
a configuration hash, so submission and worker selections remain comparable
after restarts.

The stable-diffusion.cpp adapter requires an operator-declared,
version-specific `sd_cpp_cli_contract` on both engine and recipe. Supported
forms are `bare-flag/v1` and `model-args/v1`. Reference images use ordered `-r`
arguments, and every conditioning image, including one declared with role
`source`, is passed that way in request order. The `-i`/`--init-img` and
`--strength` pair is refused for the Qwen edit operation. A declared component
role that cannot be mapped blocks execution, and each model family declares the
component roles its operations require.

Engine output is written to a private 0700 scratch directory outside output
storage and Git. The adapter validates it and copies it into the publisher's
open staging descriptor; the adapter owns scratch cleanup in its `finally` path.
The service also covers failures between resolution and execution.

## Consequences

The application can inspect the exact pre-dispatch plan, independently observe
that a spawn occurred, and persist post-reap process facts without trusting the
adapter to report them. Successful and failed real-engine attempts can release
the singleton resource when the direct child is proven reaped and publication
is reconciled under the existing authority rules.

A worker killed before durable observation remains ambiguous even if it had
written a resolved or launched record. A malformed row raises rather than
silently degrading. A grandchild survives the direct child and is not claimed
contained or terminated. The evidence describes one direct child and the
streams it inherited: a descendant that closes or redirects those streams, or
that starts its own session, is invisible, so a successful execution can leave
an unrelated process running and holding the resource. This decision adds no
descendant termination, monitoring, or recovery.

The schema has no migration. Existing version-5 databases are rejected without
mutation. Operators must preserve incompatible data and choose a new database
path.

The privacy profile proves application configuration only. It does not provide
OS network isolation. APEX model loading, ROCm execution, output quality, and
survivor-process behavior still require later runtime and qualification work.
The service recomputes the settings from the argv and environment it will
spawn and rejects any record that differs, so a stored map cannot authorize a
different invocation. The
privacy profile is pinned by application code rather than by the adapter: an
application-owned registry maps the exact adapter identity to the engine
identity, engine version, and configuration version it covers, and a policy
object exposed by an adapter is ignored.

## Rejected alternatives

- **Use one adapter-reported success flag.** It cannot distinguish spawn from
  termination and lets an adapter fabricate evidence.
- **Treat resolved as proof of launch.** A crash can occur before or after
  spawn, so this can release a resource while a child is alive.
- **Kill and wait with a short timeout, then release.** A timeout does not prove
  that a process or descendant stopped.
- **Guess the zero-conditioning syntax from a version string.** Upstream syntax
  changed within nearby builds, and the pinned executable cannot be substituted
  or probed speculatively.
- **Support adapters by inventing a generic flag.** The documented argument
  contract does not carry the required ordered per-adapter strength semantics.
- **Migrate older development databases.** The project supports only the current
  pre-1.0 schema, and silent migration would weaken the evidence boundary.
