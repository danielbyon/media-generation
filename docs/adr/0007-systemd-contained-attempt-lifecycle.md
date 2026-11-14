# ADR 0007: Systemd-contained GPU attempt lifecycle

Status: Accepted software design; trusted-workstation threat model approved by owner

## Context

`systemd-run` is the worker's direct child when it starts a transient system
service. Its exit status does not prove that the engine process exited or that
the service cgroup is empty. Cancellation and worker loss therefore need
attempt-bound unit identity and termination evidence that remain verifiable
after the worker stops owning publication authority.

The worker must keep ownership of image validation and publication. A runner
that can publish artifacts or finalize jobs would create a second authority
path and make cancellation races harder to fence.

## APEX workstation threat model

APEX is a trusted, single-owner workstation. Its owner, administrators, and OS
account configuration are trusted. Hostile local accounts and arbitrary
third-party code execution are outside the supported threat model.

The worker and inference engine may be faulty or compromised. The worker stays
in its dedicated non-root account and reaches systemd only through the
kernel-authenticated broker socket. The engine runs under the separate
non-root runner account inside one systemd cgroup with fixed device, filesystem,
capability, and namespace restrictions. The worker remains the only publisher;
the runner cannot access the worker database or artifact directory.

The broker checks keyed account and group records for the configured service
identities. It checks each account's NSS group lookup against its exact policy,
then verifies the runner's live UID, GID, supplementary groups, and cgroup from
the kernel before binding containment. For each worker request, it checks
SO_PEERCRED and the peer's live UID, GID, and supplementary groups. It does not
enumerate every host account or require protected groups to have no other
members.

Exhaustive NSS enumeration was rejected because the approved threat model
trusts the owner-administered account database, while enumeration across
multiple NSS providers is incomplete on this host and can change as providers
start or refresh. Global group exclusivity would add that same host-wide
dependency without restricting the worker or engine more than checking their
actual credentials. The broker instead rejects unexpected groups on the two
service identities and verifies the credentials systemd and the kernel gave
each process.

The accepted residual risk is that a trusted administrator can change NSS,
service groups, device ownership, or protected paths. Another trusted local
account can receive access through a shared group such as `render`, scratch,
or model-read. The worker must write its job database and publication output;
a compromised worker can misuse those role-level rights. It has no direct GPU
device or runner-scratch access, and the broker accepts only authenticated,
attempt-bound operations. The engine runs under the separate runner identity,
which can use the allowlisted GPU devices and read-only model/runtime paths
and can damage its own attempt scratch. The runner has no database or artifact
write access and cannot choose arbitrary systemd operations or escape
whole-cgroup cancellation.

Reassess this decision before supporting hostile local users, multi-owner
operation, untrusted third-party execution, or an administrator outside the
trusted boundary. Reassessment must also cover any change that gives another
account access to the private scratch or model-read groups.

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
one narrowly constrained component. The owner has authorized the isolated
installation, but provisioning remains gated on independent source review and
the final security review of the candidate.

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

The worker records validated stream completion against the immutable attempt
identity. `complete_execution` checks that record, the successful engine
observation, current publication authority, and matching root-ledger cgroup
proof in the same transaction that commits the artifact. That transaction also
queues validated scratch cleanup. The worker asks the broker to remove scratch
only after the publisher returns from its durable commit. If cleanup fails or
the worker exits before sending the acknowledgment, recovery retries a bounded
set of durable cleanup records. Recovery skips cleanup while a publication is
allocated or ready, leaving scratch available until reconciliation resolves it.

Cancellation and worker-loss recovery fence publication first, stop the exact
attempt unit, reconcile or revoke incomplete publication state, and verify
whole-cgroup termination. They may release capacity without an engine
observation when the immutable containment identity, termination proof,
publication state, and existing resource authority checks are valid. Missing
or uncertain containment evidence leaves the resource quarantined.

Failed or canceled attempts queue unvalidated cleanup only after their terminal
state, publication outcome, and whole-cgroup proof are durable. Recovery uses
the immutable attempt identity and root-ledger proof, so a later attempt cannot
redirect cleanup to a reused unit or cgroup.

The job database schema is version 9 and records stream completion and pending
scratch cleanup in `systemd_output_lifecycle`. The project has no migration
path. Existing version-8 databases remain unchanged and cannot open under the
new schema; their owner must select a new database path before deployment.

The owner has approved the isolated APEX installation under this threat model.
The source and security review gate must pass before provisioning. Installation
uses a manual broker start; the service is not enabled at boot. Host-specific
identity, permission, systemd, and real-engine checks remain required.

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
- NSS account and group enumeration is not a startup requirement. Keyed service
  identity checks and live kernel credential checks remain mandatory.
- APEX qualification remains incomplete until the approved source is installed
  and the configured identities, ROCm and GPU device groups, model and input
  roots, broker paths, scratch access, database access, and systemd cgroup
  behavior are verified.

## Rejected alternatives

Giving the worker broad systemd permissions would allow it to submit arbitrary
commands, identities, or unit properties. A unit-name-prefix check does not
constrain those operations. Process-group signalling also cannot prove that all
processes in a GPU attempt have terminated. A separate publisher in the runner
would duplicate artifact authority and weaken the existing cancellation and
publication fence. Exhaustive host NSS enumeration and protected-group
exclusivity were also rejected under the trusted-workstation assumption; exact
keyed identity checks and actual process credentials remain required.
