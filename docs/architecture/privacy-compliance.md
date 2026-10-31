# Local inference privacy configuration and compliance

## Scope

The privacy gate evaluates an inference adapter's effective JSON configuration
against an application-owned profile. A passing result means that the observed
settings matched the declared requirements for one exact adapter, tool version,
and configuration version.

A passing result does not prove network isolation, process confinement, or APEX
hardware qualification. It is configuration evidence only. Network controls,
process containment, publication integrity, and capacity admission are separate
contracts.

The bundled `deterministic-cpu-png-v1` adapter remains usable for deterministic
local generation and tests. Its application-owned profile declares that it
cannot establish real inference-tool privacy, so its result is `unverified`.

## Profile model

`src/media_generation/privacy.py` defines the current profile and result
schemas. A `PrivacyProfile` binds:

1. the privacy profile schema, identifier, and version;
2. the exact adapter identifier;
3. the tool identifier and tool version;
4. the exact scalar `configuration_version` required by the adapter; and
5. one rule for every supported privacy control.

A `PrivacySettingRule` names a JSON path, its expected value, and values known
to violate the local-only requirement. Policy construction rejects duplicate,
missing, unsupported, overlapping, credential-bearing, and self-attesting
rules.

A compliance-capable profile defines one rule for each supported control:

1. external API use;
2. hosted or cloud inference;
3. telemetry;
4. prompt, reference, artifact, or log upload;
5. automatic network fetch or update during inference;
6. remote endpoints or proxies; and
7. cloud or remote fallback.

The profile model is backend neutral. A downstream adapter must expose real,
version-specific setting paths for its tool. It must not invent flags or claim
support for an unverified integration.

## Evaluation

The policy selects only the profile whose adapter identifier and required
configuration version match the adapter's effective configuration. It then:

1. verifies that every declared setting is present;
2. passes an observed value only when it equals the expected value;
3. records a declared prohibited value as a failure;
4. treats missing, unrecognized, or wrongly typed values as unverified; and
5. combines results with `fail` taking precedence over `unverified`, and
   `unverified` taking precedence over `pass`.

An unknown adapter or unknown configuration version is `unverified`. An enabled
prohibited value is `fail`. A complete match is `pass`.

Adapter-provided compliance claims are untrusted. They are ignored and cause
the result to be `unverified`. Credential-like keys and nested model-acquisition
configuration cause `fail`. The service owns the expectation; an adapter
cannot choose its profile or submit a pass status.

For a supervised backend-execution adapter, the service selects the profile from
an application-owned registry keyed by the exact adapter identity, engine
identity, engine version, and configuration version. A policy object exposed by
the adapter is ignored, so an adapter cannot widen the controls that apply to it
and an unregistered identity is refused instead of evaluated permissively.

The real-engine registration pins the engine version to
`master-975-95b3090-2-gb13a482`. That value is the revision identity reported
by the pinned stable-diffusion.cpp source tree through `git describe --tags`, and it
denotes commit `b13a48219d5cdf408edcb93da6cd69b612ed03d3`. It is an opaque
source-revision identity rather than a semantic release number. Registration
and dispatch compare the value literally with the candidate declaration's
`engine.version`; a different describe string, branch, or commit is a different
engine identity and is refused. The application does not normalize versions or
accept a prefix, range, or approximate match.

The result contains its schema and status, exact adapter/profile/tool/version
identifiers, stable fingerprints, per-control redacted evidence, stable reason
codes, and fixed limitations. Fingerprints use canonical compact JSON with
sorted keys. Raw configuration and credentials are never copied into the
evidence.

An unprofiled adapter, or a configuration whose version does not match an
application-owned profile, keeps the observed scalar `configuration_version`
in the redacted result. This preserves attribution without trusting an adapter
claim.

## Database contract

The current persistent schema is version 6. Opening an empty database creates
that schema atomically. Opening an existing database uses a read-only connection
and validates the exact version, tables, indexes, triggers, singleton resource
row, execution/admission relationships, and current privacy records.

Only the exact current schema is accepted. Older databases, newer databases,
malformed current schemas, and non-empty databases without a version are
rejected without migration, normalization, deletion, or other mutation. There
is no compatibility reader for an older privacy column layout. An operator who
wants to remove an incompatible development database must make that decision
explicitly outside the application.

`execution_jobs.privacy_compliance_json` is `TEXT NOT NULL`. Every current
queued execution therefore has redacted privacy evidence from admission. The
service does not store `NULL`, does not infer evidence from an adapter at read
time, and does not migrate older rows into the current schema.

Stored evidence must be a complete record with the expected field types and
shape, one complete profile identity, valid controls and reasons, fixed
limitations, and a matching content fingerprint. A recomputed digest alone
does not make malformed evidence valid. An absent, null, malformed, or
wrong-adapter stored record fails closed.

## Service admission and worker claims

`GenerationService` evaluates current adapter configuration before admission
and again before every worker claim. In a batch, each job is checked
immediately before its claim so a configuration change after an earlier job
cannot authorize a later stale record.

The service always rejects `fail`. A matching compliance-capable profile that
requires `pass` also rejects `unverified`. Strict mode, selected with
`require_privacy_pass=True`, permits only `pass` when creating or reusing work.
In default mode, valid, exact `unverified` evidence is permitted only when no
matching compliance-capable profile requires `pass`. This keeps the
deterministic CPU adapter and unfinished development adapters usable when no
applicable pass requirement is configured.

The redacted evidence is stored with the queued execution and is exposed through
`provenance` as `privacy_compliance`. Idempotent reuse compares the exact
privacy evidence in addition to request intent, adapter identity, adapter
configuration, resolved output destination, and containment contract.

A worker claim must supply all of the following:

1. the current non-null privacy-compliance evidence;
2. the exact persisted adapter-configuration JSON;
3. the matching adapter identifier and output directory; and
4. process-containment evidence consistent with the persisted job.

Omitting the evidence argument, passing `None`, or passing malformed,
unverified-as-unsupported, stale, or wrong-adapter caller evidence fails closed.
The store also validates the stored record before comparing it with the caller
evidence. A mismatch creates no attempt, fence transition, resource
reservation, or publication authority.

A changed setting, profile version, configuration version, or policy cannot
reuse an older pass. The claim path compares canonical stored and caller
evidence exactly; there is no unrecorded fallback for a historical row.

Capacity admission is separate from privacy. Every new queued execution must
carry explicit current capacity evidence and a valid workload demand. Only the
exact bundled deterministic CPU adapter receives `not_required`. A subclass
does not inherit that exemption.

Process-termination proof also remains independent. A containment contract, or
a validated supervisor observation of a reaped direct child, states whether the
backend process is known to have terminated; neither says anything about
privacy. Publication, fencing, retry, cancellation, recovery, quarantine, and
artifact lineage continue to use their own authorities.

## Integration responsibilities

The following work belongs to later real-tool integrations:

1. Determine and test each tool's actual privacy settings.
2. Add exact profiles after those settings are documented and implemented in
   the application. A supervised backend-execution adapter does not supply its
   own control values; the application derives them from the resolved argument
   vector and the environment it passes to the child process.
3. Exercise representative local execution and fallback paths for each exact
   tool and version.
4. Qualify exact APEX runtime configurations separately; the privacy contract
   supplies no hardware result.
5. Retain the separate browser, LAN, authentication, and network-security
   responsibilities owned by those integrations.

An integration is ready for review only when the adapter publishes effective
privacy settings, the application-owned profile covers every control, strict
admission is enabled where local-only behavior is required, and the
configuration and policy versions are stable. A profile applies only to the
exact tool and configuration version it names.

For the real stable-diffusion.cpp engine the application owns the settings
record. It scans the resolved argument vector for URL schemes and for remote,
host, listen, server, API, proxy, download, update, telemetry, and fallback
tokens, and it records whether proxy variables or other network-enabling keys
appear in the child environment. A prohibited token produces `fail`; an
unrecognized flag or environment name stays `unverified` and blocks execution.
An explicit caller-supplied policy cannot replace the application-owned profile
that the service selects by adapter identity, engine identity, engine version,
and configuration version. The profile evaluates the resolved argv and child
environment.

The service repeats the derivation at dispatch instead of trusting the stored
map. It recomputes the settings from the argv and child environment it is about
to spawn, requires an exact match with the resolved record, and requires
`pass` before it inserts evidence or starts a process. The resolved record's
argv and environment must also match that prepared invocation.

The gate also binds the resolved record to the restart-stable configuration
persisted with the claim. Candidate identity, declaration digest, engine
identity and executable digest, recipe identity and document digest, required
component rows, adapters, and the CLI and invocation contracts must match that
admission selection. The `argv[0]` path must end with the selected executable
pin, and that one file is read again to confirm the pinned SHA-256; model and
component files are not hashed a second time. The gate compares the reported
component rows but does not bind the model-path values in the remaining `argv`
entries to the corresponding component artifact pins; that path mapping remains
inside the in-process adapter boundary. Substitutions of the candidate,
declaration, executable build or bytes, recipe, required component rows,
adapters, or contracts fail closed as `resolved_execution_mismatch` before
evidence is written or a process starts. An engine identity or version
mismatch against the application-owned registration fails earlier with the
privacy reason `resolved_engine_mismatch`.
The binding still consumes the configuration the adapter exposes at admission,
so an adapter that fabricates both its configuration and its resolution remains
an in-process trust boundary. The launch record captures the argv and child
environment that the supervisor passed without proving that the process opened
the same bytes the application verified after launch.
