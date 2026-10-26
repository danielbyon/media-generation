# Local inference privacy configuration and compliance

## Assurance boundary

The V1 privacy gate evaluates a supported inference adapter's effective
configuration against an application-owned profile. A passing result means that
the declared settings matched the profile for the exact adapter, tool version,
and configuration version. It does not prove that a process cannot make an
outbound connection, that a network is isolated, or that an APEX hardware
configuration has been qualified. The service never reports configuration
compliance as network confinement.

The current `deterministic-cpu-png-v1` adapter remains available for local image
and provenance tests. Its profile explicitly has no real inference-tool privacy
controls, so its result is `unverified`. A deterministic image still exercises
the ordinary queue and artifact path; it is not evidence about a production
model runtime.

## Profile model

`src/media_generation/privacy.py` defines the profile and result schemas.
`PrivacyProfile` binds these values:

1. the privacy profile schema, identifier, and profile version;
2. the exact adapter identity;
3. the tool identifier and tool version;
4. the exact `configuration_version` required in the adapter configuration; and
5. one rule for every supported privacy control.

`PrivacySettingRule` names a JSON setting path, the expected value, and values
that are known to violate the local-only requirement. Profiles with duplicate,
missing, unsupported, overlapping, credential-bearing, or self-attesting rules
are rejected while the policy is constructed.

Every compliance-capable profile covers these controls:

1. external APIs;
2. hosted or cloud inference;
3. telemetry;
4. prompt, reference, artifact, or log upload;
5. automatic network fetch or update during inference;
6. remote endpoints or proxies; and
7. cloud or remote fallback.

The contract is backend-neutral. A downstream adapter must populate the setting
paths with real, version-specific values documented by that tool. It must not
invent flags or label an unverified integration as supported. The synthetic
engine used in tests demonstrates the evaluator only and is not a backend
integration.

## Evaluation and status

The policy looks for exactly one profile whose adapter identity and required
configuration version match the adapter's effective configuration. It then:

1. verifies that every declared setting is present;
2. marks an expected value as passing;
3. marks a declared prohibited value as a known violation;
4. marks a missing, unrecognized, or wrongly typed value as unverified; and
5. combines the evidence using FAIL, then UNVERIFIED, then PASS precedence.

An unknown adapter or unknown configuration version is `unverified`. An enabled
value declared by a matching profile as prohibited is `fail`. A complete match
is `pass`. Adapter-provided keys that claim privacy compliance are ignored as
untrusted claims and make the result `unverified`.

Credential-like setting names and nested model-acquisition configuration make
the result `fail`. Names are matched in delimited or camelCase form across
mappings, lists, and tuples. Runtime inference settings must not carry
acquisition or cloud credentials. A profile gives the service a fixed
expectation; an adapter cannot select a profile or submit its own pass status.

The result includes:

1. the result schema version and status;
2. exact adapter, profile, tool, and configuration versions;
3. stable SHA-256 fingerprints for the profile, configuration, and complete
   result;
4. per-control redacted evidence and stable reason codes; and
5. fixed assurance limitations.

Fingerprints use canonical compact JSON with sorted keys. Unrecognized string
values and non-scalar values are replaced with redacted descriptions before a
result is serialized. Raw adapter configuration and credentials are never added
to compliance evidence.

An unprofiled adapter, or a configuration whose version does not match an
application-owned profile, retains the observed scalar
`configuration_version` in the redacted result. This keeps the failed or
unverified assessment attributable to the exact configuration version without
trusting an adapter-provided compliance claim.

## Service admission

`GenerationService` captures the adapter configuration once before each
admission and once before each worker claim. The captured values are used for
that admission or claim's store transaction. In a multi-job worker batch, the
service re-evaluates the current policy and configuration before every claim,
so configuration changed after an earlier job cannot authorize a later job
with stale evidence. The service always rejects a `fail` result, and a matching
compliance-capable profile automatically requires `pass`. The default mode
admits `unverified` only when no compliance-capable profile applies, so the
deterministic adapter remains usable and existing development adapters remain
inspectable.

Production integrations set `require_privacy_pass=True` so an unprofiled adapter
cannot be admitted. In that mode, the service refuses to construct or admit work
unless the result is `pass`. Tests that use a real-tool profile must prove the
positive, negative, missing, and unsupported cases with fixtures.

The redacted result is stored separately from the adapter configuration in an
execution-job column. `provenance` exposes it as `privacy_compliance`. SQLite
schema version 4 adds this nullable column. Existing version 3 rows remain NULL
and are read as `unverified` with the reason
`historical_record_unverified`; migration does not assign a retrospective pass.
Stored evidence is accepted only when every required field has the expected
type and shape, profile identity fields form a complete record, controls and
reasons contain valid entries, fixed limitations are present, and the content
fingerprint matches. A recomputed digest alone does not make malformed evidence
valid.

Idempotent reuse compares the exact privacy evidence in addition to the request,
adapter identity, configuration, output destination, and containment contract.
A worker claims only a job whose stored evidence matches the current service's
profile and configuration. A changed setting, profile version, or policy
therefore cannot reuse an older pass. A historical NULL record may continue
through the legacy, non-strict path for unverified execution, but it cannot be
reinterpreted as a pass.

Process-termination proof remains independent. The containment contract says
whether a dead adapter process is known to have terminated; it says nothing
about privacy. Publication, fencing, retry, cancellation, recovery, and
quarantine continue to use their existing authorities.

## Integration responsibilities

The following work belongs to later real-tool integrations:

1. T08, T09, and T14 determine and test each tool's actual settings.
2. Those tickets add exact profiles after the settings are documented and the
   corresponding adapter configuration is implemented.
3. Downstream integration tests exercise representative local execution and
   fallback paths for each exact tool and version.
4. T19 qualifies exact APEX runtime configurations; this contract supplies no
   hardware result.
5. T22 and T38 retain their separate browser, LAN, authentication, and network
   security responsibilities.

An integration is ready for review of this gate only when its adapter publishes
the effective privacy settings, its application-owned profile covers every
control, strict admission is enabled where local-only behavior is required, and
the configuration and policy versions are stable. The profile applies only to
the tested exact tool and configuration version.
