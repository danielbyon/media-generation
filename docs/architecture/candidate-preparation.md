# Declared candidate preparation

## Purpose and evidence boundary

T07 prepares one explicitly declared inference candidate for later execution.
The input names the exact engine build, recipe, component files, adapter order,
precision and conversion lineage, required component roles, architecture flags,
licenses, and compatibility evidence. Preparation reads complete files and
produces static evidence. It does not install software, load a model, import an
engine adapter, run inference, choose a model, or execute an APEX qualification.

The result `ready` means only that the declared files and evidence passed the
offline checks described here. It does not mean that T08 was run or that T19
qualified the configuration. Every report and prepared manifest therefore keeps
the following evidence fields separate:

```json
{
  "static_preparation": "ready",
  "independent_evidence_authority": "ready",
  "apex_execution": "unverified",
  "apex_execution_reason": "model_loading_and_inference_not_performed",
  "t08_execution": "required",
  "t19_qualification": "unverified"
}
```

## Workflow

Inspect a declaration and show its item-level status without writing files:

```sh
PYTHONPATH=src python3.14 -m media_generation candidate inspect \
  --declaration /path/outside-the-repository/candidate.json \
  --trusted-evidence /path/outside-the-repository/trusted-evidence.json
```

Repeat the same offline evaluation without writing files:

```sh
PYTHONPATH=src python3.14 -m media_generation candidate verify \
  --declaration /path/outside-the-repository/candidate.json \
  --trusted-evidence /path/outside-the-repository/trusted-evidence.json
```

Write a prepared manifest and a durable acquisition journal:

```sh
PYTHONPATH=src python3.14 -m media_generation candidate prepare \
  --declaration /path/outside-the-repository/candidate.json \
  --trusted-evidence /path/outside-the-repository/trusted-evidence.json \
  --manifest-output /path/outside-the-repository/prepared.json \
  --journal-output /path/outside-the-repository/acquisition-journal.json
```

The offline commands never contact a remote source, even when the declaration
contains an acquisition source URL. `verify` hashes the declared files and does
not alter them or create a journal.

`--trusted-evidence` is optional at argument parsing time, but static readiness
requires every evidence document to have a matching authority record. The file
is a separate host-owned input with schema
`media-generation.candidate-trusted-evidence`, schema version `1`, and bounded
`records` entries using the fields `authority_id`, `document_size_bytes`,
`document_sha256`, and `expected`. It has no default path and is never accepted
from the candidate declaration. The operator must review its contents and
protect it with host filesystem permissions. Omitting it or supplying a record
with a different size, digest, or normalized contract leaves the affected
evidence `unverified`. Duplicate authority identifiers are rejected with
`CandidateValidationError`, which the CLI reports as `candidate_validation_error`
with exit status `2`.

Acquire only missing artifacts from the declaration after reviewing both files:

```sh
PYTHONPATH=src python3.14 -m media_generation candidate prepare \
  --declaration /path/outside-the-repository/candidate.json \
  --trusted-evidence /path/outside-the-repository/trusted-evidence.json \
  --manifest-output /path/outside-the-repository/prepared.json \
  --journal-output /path/outside-the-repository/acquisition-journal.json \
  --acquire \
  --acquisition-config /path/outside-the-repository/acquisition-config.json
```

The acquisition configuration is transport authority and must remain separate
from inference configuration. The declaration and config must be retained with
the evidence needed to reproduce the candidate.

Manifest and journal destinations must be outside every Git worktree. The
command rejects a destination whose parent chain contains Git metadata, even
when the destination itself is ignored by the repository.
Acquired artifact destinations are checked separately from their declared
roots. Git metadata anywhere between the approved root and the destination
causes validation to fail before any remote transfer, including Git metadata
for a nested repository under an acceptable root. The destination check does
not walk above that root.

## Declaration schema

The root object requires `schema` equal to
`media-generation.candidate-declaration` and a JSON integer `schema_version`
equal to `1`; booleans and floating-point representations are rejected. JSON
duplicate keys, unknown fields, duplicate identifiers, duplicate paths, and
non-finite numbers are rejected. Every versioned control document and
acquisition journal uses the same exact-integer rule.

The declaration, trusted-evidence, and acquisition-configuration JSON control
files are read from one opened regular-file descriptor under a byte limit. The
parser records device, inode, mode, link count, owner, size, modification time,
and change time before and after the read, then confirms the path still resolves
to the same object. A symlink is accepted when its target remains stable. If the
opened file or path metadata changes during the read, validation fails closed.

The following excerpts are intentionally incomplete and are not a copyable
ready candidate. They show the required evidence shapes and relationships;
every omitted component and pinned document must be supplied and reviewed
before validation. The example does not identify an APEX-qualified model or
engine.

```json
{
  "schema": "media-generation.candidate-declaration",
  "schema_version": 1,
  "id": "synthetic-example",
  "roots": [
    {"id": "bundle", "path": "/path/outside-the-repository/bundle"}
  ],
  "engine": {
    "id": "example-engine",
    "version": "1.2.3",
    "build": "operator-recorded-build-id",
    "executable": {
      "root": "bundle",
      "path": "bin/engine",
      "size_bytes": 1234,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
    },
    "provenance": {
      "publisher": "Example publisher",
      "revision": "immutable-upstream-revision",
      "canonical_url": "https://example.invalid/engine-source",
      "evidence": {
        "root": "bundle",
        "path": "evidence/engine-provenance.json",
        "size_bytes": 100,
        "sha256": "0000000000000000000000000000000000000000000000000000000000000008"
      }
    },
    "license": {
      "name": "Example engine terms",
      "spdx": "LicenseRef-Example",
      "terms_url": "https://example.invalid/engine-license",
      "evidence": {
        "root": "bundle",
        "path": "licenses/engine.json",
        "size_bytes": 100,
        "sha256": "0000000000000000000000000000000000000000000000000000000000000002"
      }
    },
    "architecture_flags": {
      "example_edit_zero_conditioning": true,
      "target_backend": "backend-a"
    }
  },
  "recipe": {
    "id": "example-recipe",
    "document": {
      "root": "bundle",
      "path": "recipes/edit.json",
      "size_bytes": 200,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000003"
    },
    "required_component_roles": ["diffusion_model", "vae", "tokenizer"],
    "engine_id": "example-engine",
    "engine_version": "1.2.3",
    "pipeline_version": "example-pipeline-v1",
    "template_version": "example-template-v1",
    "architecture_flags": {
      "example_edit_zero_conditioning": true,
      "target_backend": "backend-a"
    },
    "compatibility_evidence": [
      {
        "claims": [
          "engine",
          "version",
          "recipe",
          "role:diffusion_model",
          "role:vae",
          "role:tokenizer",
          "flag:example_edit_zero_conditioning",
          "flag:target_backend"
        ],
        "document": {
          "root": "bundle",
          "path": "evidence/compatibility.json",
          "size_bytes": 300,
          "sha256": "0000000000000000000000000000000000000000000000000000000000000004"
        }
      }
    ]
  },
  "components": [
    {
      "id": "diffusion",
      "role": "diffusion_model",
      "artifact": {
        "root": "bundle",
        "path": "models/diffusion.safetensors",
        "size_bytes": 5000,
        "sha256": "0000000000000000000000000000000000000000000000000000000000000005"
      },
      "provenance": {
        "publisher": "Example publisher",
        "revision": "model-revision",
        "canonical_url": "https://example.invalid/model-source",
        "evidence": {
          "root": "bundle",
          "path": "evidence/diffusion-provenance.json",
          "size_bytes": 100,
          "sha256": "0000000000000000000000000000000000000000000000000000000000000009"
        }
      },
      "license": {
        "name": "Example model terms",
        "spdx": "LicenseRef-Example-Model",
        "terms_url": "https://example.invalid/model-license",
        "evidence": {
          "root": "bundle",
          "path": "licenses/model.json",
          "size_bytes": 110,
          "sha256": "0000000000000000000000000000000000000000000000000000000000000006"
        }
      },
      "precision": "bf16",
      "quantization": "none",
      "conversion": {
        "lineage": "original",
        "tool": null,
        "evidence": {
          "root": "bundle",
          "path": "evidence/conversion.json",
          "size_bytes": 90,
          "sha256": "0000000000000000000000000000000000000000000000000000000000000007"
        }
      }
    }
  ],
  "adapters": [],
  "acquisition": {
    "sources": [
      {
        "artifact": "component:diffusion",
        "url": "https://download.example.invalid/exact/diffusion.safetensors"
      }
    ]
  }
}
```

The declaration excerpt omits the required `vae` and `tokenizer` component
objects and would consequently report `incompatible`. A complete component
object uses the same structure as `diffusion`.

The pinned compatibility document is strict JSON. It is not Markdown and must
match the declaration values exactly. Its required top-level shape is:

```json
{
  "schema": "media-generation.candidate-compatibility-evidence",
  "schema_version": 1,
  "claims": [
    "engine",
    "flag:example_edit_zero_conditioning",
    "flag:target_backend",
    "recipe",
    "role:diffusion_model",
    "role:tokenizer",
    "role:vae",
    "version"
  ],
  "engine": {
    "id": "example-engine",
    "version": "1.2.3",
    "build": "operator-recorded-build-id",
    "executable": {
      "size_bytes": 1234,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000001"
    },
    "architecture_flags": {
      "example_edit_zero_conditioning": true,
      "target_backend": "backend-a"
    }
  },
  "recipe": {
    "id": "example-recipe",
    "document": {
      "size_bytes": 200,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000003"
    },
    "pipeline_version": "example-pipeline-v1",
    "template_version": "example-template-v1"
  },
  "required_roles": [
    {
      "role": "diffusion_model",
      "components": [
        {
          "id": "diffusion",
          "size_bytes": 5000,
          "sha256": "0000000000000000000000000000000000000000000000000000000000000005",
          "precision": "bf16",
          "quantization": "none"
        }
      ]
    }
  ],
  "components": [
    {
      "id": "diffusion",
      "role": "diffusion_model",
      "size_bytes": 5000,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000005",
      "precision": "bf16",
      "quantization": "none"
    }
  ],
  "architecture_flags": {
    "example_edit_zero_conditioning": true,
    "target_backend": "backend-a"
  },
  "adapters": []
}
```

The compatibility excerpt is also incomplete: expand `required_roles` and
`components` to match every declaration entry before pinning its exact bytes.

Each root is a trusted directory boundary. Artifact paths are POSIX relative
paths beneath that root. Absolute paths, backslashes, `.` components, and `..`
components are rejected. File opens walk each path component relative to an open
directory descriptor with no-follow flags. A file reached through a symlink is
`corrupt`; a host without descriptor-relative containment reports
`unverified` rather than falling back to a less safe path check.

The engine executable must also have at least one execute-permission bit. An
acquired executable is staged with mode `0700`; no downloaded file is executed
as part of preparation.

`precision` and `quantization` must be explicit known values. `unknown`,
`auto`, `default`, and empty values are rejected. A conversion record names its
lineage, optional conversion tool and version, and a pinned evidence document.
The trusted compatibility contract binds both values for every component,
including each entry under `required_roles`. Changing either value without a
matching independently pinned compatibility document leaves the candidate
`unverified`.

Every adapter-role or lora-role component must have exactly one adapter entry.
Entries may name only those roles and must use each component once. Adapter
order values are unique and contiguous from `1`, and strength is a finite value
from `-10` through `10`. Order and strength are part of candidate identity and
the independently pinned compatibility contract. No configuration is inferred.

## Readiness rules

The evaluator compares each expected size and SHA-256 value with the complete
regular file it reads. A missing file is `missing`. A changed size or digest, a
non-regular file, or a symlink is `corrupt`. A required role or engine flag that
does not match is `incompatible`. Missing or incomplete evidence is `unverified`
or `missing` according to the failed observation. Any non-ready item makes the
candidate blocked.

Evaluation also compares the device and inode recorded for every declared
engine, recipe, and component file. Two paths that resolve to one physical file
are `corrupt`, even when their bytes and declared pins match. Repeating this
check during evaluation prevents a hard-link alias created after declaration
parsing from becoming ready.

A declaration is not independent evidence authority. The CLI and public Python
facade accept explicitly supplied `TrustedEvidence` records. The CLI loads them
only through the separate `--trusted-evidence` file described above.
Provenance, license, conversion, and compatibility documents become ready items
only when one of those operator-supplied records matches the exact file size,
SHA-256 value, and normalized evidence contract. A candidate-authored document
with no matching host authority remains `unverified`, even when its bytes match
the declaration pin. No built-in model, license, or upstream-evidence trust
store is provided.

Compatibility evidence must cover every required claim. A claim identifier is
one of `engine`, `version`, `recipe`, `role:<role>`, or `flag:<flag>`. A cited
document is itself pinned by size and SHA-256. Unknown claims and duplicate
claims are rejected during declaration parsing.

The Qwen Image Edit 2511 rule is version-specific. The evaluator reads declared
engine, recipe, and component identifiers; engine and recipe version fields; and
provenance publisher, revision, and canonical URL values. It looks for a Qwen
Image Edit match and a separate `2511` match in that set.
The two matches may occur in different strings. Both the engine and recipe
must explicitly enable `qwen_image_zero_cond_t=true`. Pinned
compatibility evidence must cover that flag and bind the exact engine identity
and version, recipe identity, component roles and bytes, adapter
configuration, and architecture flags. An absent flag is `incompatible`; an
unverifiable compatibility document is `unverified`. Artifact pins, filenames,
license or conversion evidence paths, and broad family labels do not trigger or
satisfy the rule.

The recipe document is a separately pinned file. Its expected digest and size
are checked in addition to compatibility claims. A changed recipe therefore
changes or blocks the candidate rather than inheriting an earlier readiness
result.

## Stable identities

`candidate_id` is the SHA-256 identity of the normalized declared expectations.
It includes engine, recipe, component, adapter, evidence-pin, and optional T02
evidence declarations, and excludes observations. Changing a declared setting
or pin creates a different candidate identity.

`verification_id` is the SHA-256 identity of the candidate identity, the overall
status, item-level findings, and observed file identities. Changing bytes on
disk or any verification result changes `verification_id` while preserving
`candidate_id`. T08 must require both the expected `candidate_id` and a fresh
ready `verification_id` before execution.

## Acquisition configuration

The acquisition config is a second strict JSON document:

```json
{
  "schema": "media-generation.candidate-acquisition-config",
  "schema_version": 1,
  "authorized": true,
  "allowed_origins": ["https://download.example.invalid"],
  "credentials": [
    {
      "origin": "https://download.example.invalid",
      "headers": {"Authorization": "operator-supplied-secret"}
    }
  ],
  "timeout_seconds": 30,
  "max_redirects": 2,
  "max_attempts": 3,
  "max_total_bytes": 2000000000
}
```

Use a real credential value only in a protected file outside the repository.
The application does not read credentials from environment variables, project
prompts, the database, or inference configuration. Each credential set is sent
only to its exact normalized origin. Redirects are handled manually, must remain
HTTPS, and must name another allowed origin. The target origin's credentials may
be used; the source origin's credentials are not forwarded.
Malformed redirect URLs fail as bounded acquisition errors with exit `8`
without echoing the `Location` value or transport credentials.

Requests are GET requests with no project body. Proxies from environment
variables are disabled. Redirect count, attempts, timeout, expected artifact
size, and configured total actual bytes across all sources and retries bound the
acquisition run. The acquisition config is never serialized into the manifest,
journal, report, or inference configuration.

Each missing artifact starts one monotonic deadline before its first network
operation. The same absolute expiry is retained across DNS resolution, TCP
connection, TLS negotiation, request sending, HTTP status and header parsing,
interim responses, redirects, retries, and every body/framing read, including
chunk extensions and trailers. It is not restarted at a response or attempt.
Once that deadline expires, the transfer fails as `transfer_timeout` without
reserving another retry or replacing the timeout with a byte-budget error.

The private acquisition transport runs each HTTPS response in a disposable
standard-library worker process. The parent supervises anonymous-pipe reads and
writes with the artifact's remaining time. If the deadline expires, it kills
and synchronously reaps the worker before returning `transfer_timeout`. This
terminates blocked name resolution and HTTP parsing as well as socket I/O;
there is no abandoned resolver thread. Cancellation latency includes process
termination, reaping, and normal operating-system scheduling. Deadline tests
measure from the transfer deadline rather than from declaration evaluation.

The worker uses the selected Python interpreter with isolated startup, no
inherited environment, and closed inherited descriptors. URLs and credential
headers cross anonymous pipes only; they are absent from process arguments and
temporary files. Certificate trust, hostname verification, and SNI use Python's
default TLS context. The worker performs one GET and never follows redirects;
the acquisition caller continues to validate each origin and select that
origin's credentials. It sends body bytes only on bounded read requests from
the parent, retaining the pinned-size and total-transfer checks. Internal caps
limit protocol control frames and serialized response headers to 64 KiB, HTTP
lines to 16 KiB, and header count to 100. Raw final and interim header fields
must have valid token names, CRLF line endings, and values without forbidden
controls or folded lines. Validation runs before the standard library's email
parser can discard malformed fields and hide later framing headers. Reported
parser defects also reject the response before metadata or body bytes reach the
parent. A malformed or oversized response fails closed with a redacted transport
error. Timeout cleanup closes the unnamed staging descriptor
and releases the journal lock; independently pinned verification and publication
remain required for readiness.

## Staging, publication, and retry

Only a missing acquisition target is transferred. Existing files, including
corrupt files, are left untouched. Acquisition requires Linux and a destination
filesystem supporting `O_TMPFILE` and descriptor-based hard-link publication.
Offline `inspect`, `verify`, and `prepare` remain available on macOS and on
filesystems without these acquisition capabilities.

Before creating a journal lock, invalidating a manifest, writing a journal, or
contacting a remote source, acquisition preflights every declared source's
existing destination parent. It opens an empty mode-0600 inode with
`O_RDWR | O_TMPFILE | O_NOFOLLOW | O_CLOEXEC`, confirms through `fstat` that it is
an unlinked regular file on the destination filesystem, and attempts a
descriptor link to the existing `.` directory entry. That attempt must return
`EEXIST`; it creates no probe name. The empty inode is then closed. A platform,
filesystem, or descriptor-link rejection detected during preflight produces a
structured acquisition error (CLI exit `8`) before network access or named-file
mutation.

The nonmutating publication probe detects unavailable system calls, rejected
flags, missing procfs fallback, and permission failures reached before the
existing-destination check. `EEXIST` cannot prove checks the kernel performs only
for a successful new link, even when directory permissions and security policy
remain unchanged. If publication to the final name returns `EOPNOTSUPP` or
`ENOTSUP`, acquisition aborts with a structured error, closes its descriptors,
and leaves the journal unverified with a failed attempt. It creates no final
artifact or ready manifest and does not fall back to named staging. No named
temporary probe is needed to establish this failure boundary. Native Linux
qualification must exercise a successful publication on the actual destination
filesystem.

For each transfer, the implementation:

1. Opens the existing destination parent descriptor-relative without following
   links, then creates and preflights a fresh unnamed `O_TMPFILE` inode there
   before opening the network response. It never creates an artifact staging
   directory or staging pathname. `O_EXCL` is omitted because it would prohibit
   later publication of an `O_TMPFILE` inode.
2. Checks `Content-Length` when present. Streamed size, streamed SHA-256, and
   the configured total-byte limit remain authoritative when the header is absent.
3. Rejects a size or digest mismatch, fully hashes the retained descriptor, and
   compares inode, size, modification time, and change time before and after
   verification. It synchronizes that descriptor before publication.
4. Atomically creates the absent final name with `linkat(AT_EMPTY_PATH)`. When
   the direct descriptor form is unavailable to the process, it uses Linux's
   documented `/proc/self/fd/<descriptor>` with `AT_SYMLINK_FOLLOW` alternative.
   The fallback requires an accessible procfs descriptor reference; it does not
   require `CAP_DAC_READ_SEARCH`. Neither form replaces an existing file,
   directory, or symlink. The final entry must identify the retained inode,
   including when a replacement contains identical pinned bytes.
5. Reopens the published entry nonblocking and without following links, checks
   its identity against the retained inode, verifies its full-file pins, and
   synchronizes both file and parent directory. Device, inode, size, and
   nanosecond mtime/ctime must remain unchanged through directory synchronization
   and the final full-file observation before journal success. Post-publication
   failures are recorded as `publication_sync_failed`, leaving recovery pending.

Staging cleanup only closes owned descriptors. A failure while closing one
resource cannot skip another descriptor or replace an existing primary error.
Descriptor numbers are never retried after a failed close. Closing the last
reference to an unpublished inode lets the kernel reclaim it, including after
process exit. There is no named stage to replace after creation, and no
identity-check/unlink or identity-check/rmdir sequence. No artifact cleanup
renames, unlinks, or removes a directory entry, including a raced replacement
or an already published final name. Existing manifest/journal atomic output
handling is separate from artifact staging.

Publication recovery also retains the original verification or synchronization
error if closing its reader or parent descriptor fails. A parent close failure
after successful synchronization is recorded as `publication_sync_failed`;
offline preparation continues to reject readiness until explicit acquisition
repeats synchronization and verification successfully.

Local tests on Darwin inject the Linux inode syscalls and exercise real I/O,
hashing, synchronization, and hard links against synthetic fixtures. They are
not native Linux qualification. Native `O_TMPFILE` and descriptor-publication
checks remain required on APEX, under its actual filesystem and process policy.

A crash after atomic publication but before the success event leaves either no
final entry or the exact verified bytes. Offline preparation fails closed
without changing the destination or journal when the journal has an
`attempted` event or a `publication_sync_failed` event that still requires
recovery. It first invalidates any existing ready manifest, as required to keep
an old ready result from surviving a journal transition. If no manifest exists,
offline refusal does not create one. The separate offline `verify` command
remains read-only and does not mutate candidate files. Explicit acquisition may recover a verified destination by
synchronizing it and verifying it again before recording a recovered success;
the artifact is not downloaded again. A synchronization failure remains
`unverified` until an explicit recovery attempts synchronization and
reverification again. An unavailable or corrupt initial observation also leaves
recovery pending and fails preparation. A missing observation permits a bounded
replacement attempt, but does not discharge the existing recovery obligation.
An interrupted attempt recorded as `interrupted_attempt`, a later failed
transfer or publication conflict, and an exhausted transfer budget all retain
that obligation. The journal tracks unresolved transfers separately from
publication durability across its event history; only a synchronized, verified
publication or explicit recovery clears it. Offline preparation cannot report
ready merely because exact bytes reappear after a transient observation failure.

Each journal transition is published as one atomic JSON file write and synced
to the containing directory. Explicit acquisition synchronizes and verifies a
destination found after an `attempted` event or a failed
`publication_sync_failed` event before recording a recovered success; it is not
downloaded again. A journal associated with a different declaration digest is
rejected.

The persisted transfer total is accepted only when it equals the sum of byte
reservations recorded by `attempted` events. A mismatch rejects the journal
before acquisition, budget reconstruction, journal rewrite, or publication.

The journal is not cryptographically authenticated. Event reconciliation rejects
a counter-only edit because changing `transfer_bytes` without changing the
`attempted` reservations is detected, but an actor able to rewrite both values
consistently can forge the history. Integrity against such an actor depends on
host filesystem access controls or a separate authenticated evidence mechanism.

Offline and acquisition preparation both hold the same bounded advisory
journal lock across journal read, validation, mutation, and publication.
The manifest destination is rejected if its normalized path or existing file
identity aliases the lock file, so manifest invalidation cannot replace the
active lock inode.
Failing to acquire the lock, including a timeout while another process owns
it, is reported as a structured `candidate_output_error` with exit `7`.
Before any journal transition or acquisition mutation, an existing manifest is
replaced with a non-ready manifest that clears `verification_id`, item
findings, and observations. A ready manifest is published only after the
matching journal has been durably published as ready. These file replacements
and directory synchronizations can leave the previous non-ready manifest or no
manifest after a crash, but cannot leave an old ready manifest beside a
mutated journal.

After writing the journal status, preparation reloads and validates that
journal under the same lock and evaluates the complete current files again.
If the fresh status or candidate identity differs, preparation rewrites the
journal before publishing the manifest. The manifest and returned report are
then produced from that reconciled evaluation. A journal that changes again
before reconciliation completes fails as a structured output error and the
manifest remains non-ready.

The journal history is deliberately capped at 10,000 events and the declared
transfer-byte ceiling. Each transfer attempt requires room for both its
reservation and outcome before contacting a source or publishing an artifact.
Publication recovery requires one free event slot before synchronization.
Every append also checks capacity before changing the in-memory or persisted
history. Exhausted event capacity fails with a structured `candidate_output_error`
(exit `7`), leaving the journal valid for later inspection.
Deleting or replacing the journal can discard prior
attempt history and reset transfer-budget accounting. Rewriting or deleting
journal state cannot make current bytes pass their declaration pins, and an
old ready manifest is invalidated before the next journal transition, but the
filesystem journal is not tamper-proof. Operators must protect it with host
permissions and retain it for the intended transfer-budget history. Historical
transfer usage is not independently authenticated: an actor able to delete or
coherently rewrite both the journal status and its `attempted` reservations can
reset the recorded budget. Current artifact pins and final full-file
observations remain authoritative within the documented filesystem boundary.

## T02 relationship

T02 inventory manifests remain read-only. Their URLs are attribution only and
are never acquisition instructions. T07 uses its own acquisition declaration
and transport configuration.

A T07 declaration may optionally name a pinned T02 inventory report as
supplementary evidence. T07 verifies that report's complete size and SHA-256 but
does not reinterpret its host observations as APEX qualification. Omitting the
optional report is recorded explicitly and does not create a host claim.

## Exit status and outputs

`candidate inspect` and `candidate verify` write one JSON report to standard
output. `candidate prepare` additionally writes the requested manifest and
journal. Output paths must not replace the declaration, any declared artifact
or evidence file, the acquisition configuration, or the trusted-evidence input.
Direct paths and hard-link or symbolic-link aliases are rejected for both the
manifest and journal. When a control path is a symlink, both the symlink inode
and its referent inode are protected, so a direct, hard-link, or symbolic-link
alias of the referent is also rejected.

| Exit | Static status or condition |
| ---: | --- |
| `0` | `ready` |
| `5` | `missing` |
| `6` | `corrupt` or mismatched |
| `3` | `incompatible` |
| `4` | `unverified` |
| `2` | invalid declaration or transport configuration |
| `7` | requested output could not be published safely |
| `8` | an attempted, explicitly authorized acquisition failed |

Exit `5` describes an ordinary missing artifact when acquisition was not
requested. Once an acquisition attempt starts, retry exhaustion, budget or
transport failure, digest mismatch, or staged artifact publication failure is
reported as `candidate_acquisition_error` on standard error with exit `8`.
Failure to publish a requested manifest or journal remains exit `7`.

The exit code and manifest status refer only to offline static preparation.
Follow-up T08 execution must use the prepared candidate identifier and enforce
the T06 admission boundary. T19 remains responsible for exact real-engine
qualification.

The repository and synthetic fixtures do not contain independent real license,
compatibility, provenance, or APEX evidence for a production Qwen candidate.
Synthetic tests prove the evaluator mechanism only. A real Qwen or APEX
candidate without separately reviewed host authority and exact local pins
remains blocked from static readiness and reports `unverified`. No static T07
result demonstrates APEX model loading, inference, hardware sufficiency,
privacy enforcement, or image quality.
