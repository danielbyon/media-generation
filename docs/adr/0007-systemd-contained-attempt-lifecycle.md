# ADR 0007: Systemd-contained GPU attempt lifecycle

Status: Accepted software design; APEX deployment authorization is pending

## Context

`systemd-run` is the worker's direct child when it starts a transient system
service. Its exit status does not prove that the engine process exited or that
the service cgroup is empty. Cancellation and worker loss therefore need
attempt-bound unit identity and termination evidence that remain verifiable
after the worker stops owning publication authority.

The worker must keep ownership of image validation and publication. A runner
that can publish artifacts or finalize jobs would create a second authority
path and make cancellation races harder to fence.

## Decision

Use a root-owned broker for narrowly scoped systemd operations. State-changing
system-manager calls pass through its D-Bus/polkit authorization for
`org.freedesktop.systemd1.manage-units`. The broker is the only component that
invokes the system manager. It accepts authenticated local requests, verifies
the immutable resolved invocation and claim identity, and constructs one
transient system service per attempt with fixed properties and a configured
non-root runner identity. The worker receives no broad systemd privilege and
cannot submit arbitrary unit properties, commands, users, or groups. See the
[systemd manager documentation](https://freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).

Containment identity and cgroup-empty proof are stored in a separate
root-owned SQLite ledger beside the job database, with read access for the
worker group and no worker write access. The broker writes the ledger first and
mirrors those records into the job database. Because the worker can update the
job database, resource-release checks accept containment and termination
facts only when they match the root-owned ledger. A missing ledger record or a
mismatch is not termination proof.

An existing user manager was not selected because APEX has not been qualified
to provide the required system-service identity, GPU device allowlist, cgroup
policy, and durable unit lifecycle. The root broker keeps those controls in
one narrowly constrained component; installing it remains a separate owner
decision.

The attempt runner owns `ProcessSupervisor` and launches the engine as its
direct child. It records the existing launch and engine observation facts
through the broker. The broker separately records the unit invocation and
cgroup identity, then records whole-cgroup termination only from a pinned
`cgroup.events` descriptor whose identity was checked against systemd. The
launcher status, runner status, engine observation, unit result, cgroup
termination, and stream completion remain separate facts.

The broker waits for the matching unit's main process exit status before it
stops the unit and records the pinned cgroup-empty event. During cancellation
or worker loss, it stops the unit first, then verifies the runner exit before
recording cgroup emptiness. It saves the unit result before `StopUnit` can
garbage-collect the completed unit.

For success, the worker requires a valid successful engine observation, a
validated image, complete runner and unit results, empty-cgroup proof, current
publication authority, and the existing atomic publication transaction. It
streams the broker-pinned output descriptor into the publisher's existing
staging descriptor. The runner and broker do not publish artifacts or finalize
jobs.

Cancellation and worker-loss recovery fence publication first, stop the exact
attempt unit, reconcile or revoke incomplete publication state, and verify
whole-cgroup termination. They may release capacity without an engine
observation when the immutable containment identity, termination proof,
publication state, and existing resource authority checks are valid. Missing
or uncertain containment evidence leaves the resource quarantined.

The broker's software design is approved. Installing the privileged component,
creating its service account, granting device or filesystem access, and
provisioning the root-owned evidence ledger, or changing systemd configuration
on APEX require separate owner authorization. That action includes granting
the worker group read access to the ledger and verifying its protected parent
directory. APEX remains unqualified until the owner authorizes installation
and host-specific checks are complete.

## Consequences

- A unit name or `systemd-run` return code alone never proves engine or cgroup
  termination.
- A normal success needs both engine success evidence and whole-cgroup
  termination evidence.
- A canceled or recovered attempt can release capacity without an engine
  observation when cgroup termination and publication reconciliation are
  verified.
- The root broker is part of the trusted computing base and needs its own
  deployment review and host qualification.
- APEX qualification remains blocked until its owner authorizes installation
  and verifies the configured identities, ROCm and GPU device groups, model and
  input roots, root-owned broker path ancestors, scratch access, broker database
  access, and systemd cgroup behavior.

## Rejected alternatives

Giving the worker broad systemd permissions would allow it to submit arbitrary
commands, identities, or unit properties. A unit-name-prefix check does not
constrain those operations. Process-group signalling also cannot prove that all
processes in a GPU attempt have terminated. A separate publisher in the runner
would duplicate artifact authority and weaken the existing cancellation and
publication fence.
