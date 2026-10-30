# ADR 0002: Prepare exact, evidence-bound candidate declarations

## Status

Accepted on 2026-10-28.

## Context

The host inventory introduced by ADR 0001 describes local facts without proving
that model files are complete, mutually compatible, or suitable for execution.
A later inference worker needs a durable object that identifies one exact engine
build, recipe, component bundle, adapter order, architecture configuration, and
set of license and compatibility documents.

Engine and model family names are not sufficient identities. A filename,
metadata header, self-computed digest, or operator assertion that two components
work together does not establish that the complete local bytes match an
independently chosen artifact or that the declared recipe is compatible with the
engine build.

Model acquisition also has a different credential and transport risk profile
from inference. A read-only inventory provenance URL must not cause a transfer.
Acquisition credentials must not become runtime configuration, and a redirect
must not receive credentials intended for another origin.

## Decision

T07 adds a strict, versioned candidate declaration. Every engine executable,
recipe document, component, license evidence document, provenance evidence
document, conversion evidence document, and optional T02 inventory report
carries an expected size and SHA-256 value. Verification streams each complete
regular file through a descriptor-relative no-follow open and compares the
observed size and full digest with those pins.

One evaluator produces the status consumed by `inspect`, `verify`, and
`prepare`. Per-file and compatibility findings use `ready`, `missing`,
`corrupt`, `incompatible`, or `unverified`. The overall status is the most
restrictive finding. Only `ready` means the declared candidate passed T07's
offline static preparation checks.

A declaration is not independent trust authority. Each provenance, license,
conversion, and compatibility evidence document becomes a ready evidence item
only when an operator-supplied `TrustedEvidence` record also matches its exact
size, SHA-256 value, and normalized contract. Candidate-authored evidence that
is internally consistent but has no matching host authority remains
`unverified`. The implementation contains no built-in model or license trust
store.

The authority records are consumed through the same public facade and CLI as
the declaration. The CLI reads them only from an explicitly named, separate
`--trusted-evidence` file. It has no default location, does not accept records
from the candidate declaration, and requires exact pin and contract matches.

A recipe declares its required component roles and every architecture flag that
must match the engine. Pinned compatibility documents must explicitly cover the
engine identity, engine version, recipe identity, each required role, and each
required flag. Missing coverage is `unverified`. A value mismatch is
`incompatible`.
The trusted compatibility contract also binds every component's explicit
`precision` and `quantization`. A changed format value without matching
independently pinned compatibility evidence cannot produce `ready`.

The Qwen Image Edit 2511 rule is version-specific. The evaluator reads declared
engine, recipe, and component identifiers; engine and recipe version fields; and
provenance publisher, revision, and canonical URL values, looking for a Qwen
Image Edit match and a separate `2511` match in that set.
Both the engine and recipe must explicitly enable
`qwen_image_zero_cond_t=true`. Pinned compatibility evidence must
cover that flag and bind the exact engine identity and version, recipe
identity, component roles and bytes, adapter configuration, and architecture
flags. The rule is not inferred from a model filename or a broad family claim.

Engine software terms and model component terms are separate records. Each
record names a license, SPDX identifier or license reference, terms URL, and an
independently pinned evidence file. Provenance URLs are attribution only.

Preparation remains offline unless the caller both passes an explicit acquire
flag and supplies a separate transport configuration with `"authorized":
true`. That configuration contains allowed HTTPS origins, credentials scoped to
exact origins, timeout, retry, redirect, and total-byte limits. The declaration's
acquisition section contains the exact remote URL for each acquirable engine,
recipe, or component. Evidence documents remain operator-provisioned.

Transfers use GET requests without a body, exact-origin credentials, no
environment proxy, manual HTTPS redirects, and bounded streaming. On Linux,
missing artifacts are written to an unnamed `O_TMPFILE` inode on the
destination filesystem. Its descriptor is retained, fully hashed, and
rechecked before publication.
`Content-Length` is checked when present; streamed size, streamed SHA-256, and
configured byte limits remain authoritative when it is absent. Publication and
recovery hash and synchronize the same nonblocking, no-follow published
descriptor. Its identity must match the observation made before synchronization,
and the directory entry is rechecked before recording success. A same-size
replacement, including identical bytes in a different inode, fails the operation.

Acquisition requires Linux, `O_TMPFILE`, and descriptor-bound `linkat`
publication. It fails before network access or output mutation on macOS and
when its capability preflight detects an unsupported filesystem or primitive;
offline inspection, verification, and preparation remain available. The
preflight opens an unnamed inode and probes `linkat` against the existing `.`
entry. That nonmutating probe cannot establish that a later link to a new name
will be permitted by the filesystem or its security policy. A final-name link
that returns `EOPNOTSUPP` or `ENOTSUP` aborts with a structured acquisition
failure, no final artifact or ready manifest, and an unverified journal with a
failed attempt. Acquisition never falls back to named staging or creates a
named temporary publication probe.

Publication synchronizes the verified inode and creates the final entry with
`linkat(AT_EMPTY_PATH)`, falling back to the descriptor under `/proc/self/fd`
with `AT_SYMLINK_FOLLOW` when required. Neither path replaces an existing
entry. The published file and its containing directory are synchronized, and
the final name is checked against the synchronized inode and metadata before
the journal records success. An unsupported or rejected publication is an
acquisition error; failure after linking leaves recovery pending. Closing the
descriptor is the only staging cleanup operation, so an acquisition never
adopts or removes a replacement staging path.

The acquisition journal records each artifact attempt as `attempted`,
`succeeded`, `failed`, or `skipped`. It contains artifact identifiers, attempt
numbers, byte counts, hashes, and safe reason codes. It does not contain URLs,
headers, origin allowlists, timeout values, credentials, or project content. A
journal tied to a different declaration is rejected. Its persisted transfer
total must also equal the sum of reservations recorded by attempted events;
mismatches fail closed before acquisition or publication.

The journal is not cryptographically authenticated. A transfer counter edited in
isolation is rejected by reconciliation with attempted reservations, but an
actor able to rewrite both consistently can forge the recorded history.
Protection against that actor depends on host filesystem access controls or a
separate authenticated evidence mechanism.

Journal history has a fixed 10,000-event limit and the declared transfer-byte
ceiling. Deleting or replacing the journal can discard prior attempt history
and reset transfer-budget accounting. Journal rewriting cannot make current
bytes pass declaration pins or leave an old ready manifest beside a new
journal transition, but the filesystem journal is not tamper-proof. Historical
transfer usage is not independently authenticated: an actor able to delete or
coherently rewrite both the journal status and its `attempted` reservations can
reset the recorded budget. Current artifact pins and final full-file
observations remain authoritative within the documented filesystem boundary.

A prepared manifest has two distinct identifiers:

* `candidate_id` is a stable SHA-256 identity of the normalized declared
  expectations, including engine, recipe, component, adapter, evidence pins,
  and inventory-evidence declarations. It excludes observations. Changing a
  declared pin or setting changes the candidate identity.
* `verification_id` is a stable SHA-256 identity of the candidate identity,
  overall status, item-level findings, and observed file identities. Changing
  bytes on disk or any verification result changes the verification identity
  while leaving `candidate_id` unchanged.

`verify` and `prepare` always evaluate the current declaration and files
again. Before changing a journal or beginning acquisition, `prepare` replaces
an existing manifest with a non-ready manifest that clears `verification_id`,
item findings, and observations. It publishes a ready manifest only after the
matching journal is durably ready. Offline and acquisition preparation use the
same bounded advisory journal lock; lock acquisition failure is a structured
output error with exit `7`.

After writing the journal status, `prepare` reloads and validates that journal
under the same lock and evaluates the complete current files again. If the
fresh status or candidate identity differs, it rewrites the journal before
producing the manifest and report. A journal that changes again before this
reconciliation completes fails as a structured output error and the manifest
remains non-ready.

The candidate commands use distinct process exit codes so automation does not
need to infer an outcome from prose:

| Exit | Meaning |
| ---: | --- |
| `0` | Static preparation is `ready`. |
| `5` | A required file is `missing`. |
| `6` | A declared file is `corrupt` or mismatched. |
| `3` | Candidate inputs are `incompatible`. |
| `4` | Static preparation remains `unverified`. |
| `2` | The declaration or acquisition configuration is invalid. |
| `7` | A requested manifest or journal could not be published safely. |
| `8` | An attempted, explicitly authorized acquisition failed. |

Exit `5` applies to an ordinary missing file when acquisition was not
requested. After an acquisition attempt starts, retry exhaustion, budget or
transport failure, digest mismatch, or staged artifact publication failure is
an operational `candidate_acquisition_error` with exit `8`. Failure to publish
the requested manifest or journal remains exit `7`.

Normal candidate status JSON is written to standard output. Operational error
JSON is written to standard error.

## Consequences

Downstream execution can consume a manifest only when its status is `ready`.
The manifest identifies the exact inputs and records the evidence limitations.
It does not prove that the engine loads the bundle, that the APEX host has enough
memory, that inference succeeds, that privacy configuration is effective, or
that output quality meets T19 qualification.

No independent real license, compatibility, provenance, or APEX evidence for a
production Qwen candidate is supplied by this repository or its synthetic test
fixtures. The synthetic Qwen mechanism is test evidence only. A real Qwen or
APEX candidate without separately reviewed host authority remains blocked from
static readiness and is reported `unverified`; it must not be presented as
ready merely because its declaration and files are internally consistent.

Operators must create declaration, trusted-evidence, and acquisition files
outside generated data directories and protect them using host filesystem
permissions. Manifest and journal outputs must also be outside Git worktrees so
host-specific preparation artifacts do not enter version control. The
acquisition destination check validates ancestors between its declared root and
the destination for nested Git metadata, preventing an otherwise safe root from
publishing into a repository created inside it. The implementation verifies a
retained unnamed descriptor and publishes through a descriptor-bound primitive.
It cannot prevent another process from modifying the final file after successful
publication. T08 must recheck the prepared identity or consume an immutably
retained bundle before model loading.

A process crash before publication closes the unnamed staging descriptor; the
kernel discards the unlinked inode. A crash after the atomic publication call
but before the success journal event leaves the final name either absent or
containing the verified bytes. Offline preparation refuses to emit ready while
an `attempted` or `publication_sync_failed` journal event requires recovery. Explicit
acquisition synchronizes and verifies that exact destination before recording
recovered success instead of downloading it again. A reported synchronization
failure remains unverified until a later explicit recovery passes those same
steps.

## Rejected alternatives

* Infer required roles, precision, quantization, or compatibility from model
  filenames or family names. Those claims are not exact evidence.
* Treat a digest computed during the same run without an independent expected
  value as integrity or provenance.
* Treat a candidate-authored evidence document as trusted without an independent
  host-owned expectation.
* Reuse T02 attribution URLs as download instructions.
* Put acquisition headers or credentials into the candidate declaration,
  manifest, journal, or inference configuration.
* Overwrite an existing corrupt destination during retry.
* Follow redirects automatically with the source origin's credentials.
* Label a static result as APEX execution evidence or T19 qualification.
