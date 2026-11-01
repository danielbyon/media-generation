# Supervised local backend execution

This document describes how the service executes an opt-in local inference
backend, records the execution plan and process facts, and decides whether a
heavyweight resource may be released. It applies to adapters that implement the
declared preparation and process boundary described here. The bundled
deterministic CPU adapter continues to use the simpler in-process adapter
interface and does not create backend execution records.

The design separates four questions that must not be conflated:

1. Is the selected engine, recipe, and component bundle statically ready?
2. What exact operation was resolved before dispatch?
3. Did a direct child process actually start?
4. Was that direct child reaped, and how did it terminate?

Static readiness proves only that declared files match independently supplied
expectations. A resolved plan is not launch evidence. A launch record is not
termination evidence. Only a validated observation written after the direct
child was reaped can establish direct-child termination.

## Candidate and recipe gate

The opt-in stable-diffusion.cpp adapter accepts a T07 candidate declaration and
an optional separate file of host-owned trusted evidence. Loading the adapter
parses both documents, validates the engine identifier, ROCm backend declaration,
CLI contract, recipe identity and schema, and executable access, then derives the
restart-stable candidate identity and declared capabilities. Construction does
not load a model, hash model component files, start a process, inspect Git, or
capture host runtime facts.

Before every dispatch `resolve_execution` performs the authoritative offline T07
evaluation. Static preparation and independent evidence authority must both be
`ready`, and every pinned declaration, recipe, component, executable, and trusted
evidence file is read and re-hashed. The selected candidate's stable
`candidate_id` must still match the identity captured in the adapter
configuration. A failure is refused before any process starts; the service never
substitutes another bundle. The fresh `verification_id` belongs to that resolved
attempt only and is excluded from the restart-stable static configuration.

T07 declaration schema version 1 has no field that references a prepared
manifest or an acquisition journal. The adapter therefore re-evaluates the
exact declaration and files instead of trusting prior preparation output. A
declaration carrying an unknown preparation-reference field is rejected by the
strict schema, and a prepared manifest cannot be substituted for the candidate
declaration; both cases fail closed as `bundle_corrupt`. A future declaration
version that references preparation evidence must validate that evidence before
this adapter accepts it.

The invocation recipe is a separate pinned JSON document. It must match the
declared recipe identifier and use this exact top-level shape:

```json
{
  "schema": "media-generation.sd-cpp-recipe",
  "schema_version": 1,
  "id": "recipe-id",
  "engine_id": "stable-diffusion.cpp",
  "operations": {
    "generate": {
      "required_component_roles": ["diffusion_model", "vae", "text_encoder"],
      "model_args": [],
      "sampling": {
        "sampling_method": "euler",
        "steps": 20,
        "cfg_scale": 7.0,
        "flow_shift": 3.0,
        "strength": null
      }
    }
  },
  "limits": {
    "max_width": 1024,
    "max_height": 1024,
    "max_references": 3,
    "max_source_images": 1
  }
}
```

The `edit` operation uses the same fields. Every conditioning image, whether
declared with role `reference` or role `source`, is passed through the
repeatable `-r`/`--ref-image` argument in request order; the `-i`/
`--init-img` and `--strength` pair is refused for the Qwen edit operation.
Unknown keys, duplicate JSON fields,
unsupported sampling methods, out-of-range values, undeclared component roles,
and more than eight model arguments are rejected as `recipe_invalid`. Sampling
steps are bounded to 1 through 50, CFG scale to 0 through 15, flow shift to 0
through 10, and optional strength to 0.05 through 1.0. The recipe's `engine_id`
must match the declared engine.

Independent application ceilings apply even when recipe limits are larger:
width and height must be 64 through 2048 and multiples of 8, with no dimension
above 2048 pixels; at most three conditioning images total and at most one
`source` image are accepted. A recipe may declare only `generate`, only `edit`,
or both. The operation is selected from the persisted reference roles, never
submitted as an independent request parameter.

Component roles map to stable-diffusion.cpp arguments as follows:

| T07 role | Argument |
| --- | --- |
| `diffusion_model` | `--diffusion-model` |
| `vae` | `--vae` |
| `text_encoder` | `--llm` |
| `vision_encoder` | `--llm_vision` |

An operation profile must explicitly list every role it requires. A role that
is not mapped by the invocation contract, or a required role absent from the
candidate, blocks the bundle. The adapter does not infer a vision encoder or
any other component from a filename.

Each model family also declares a version-specific required-role profile. The
Qwen image edit profile requires `diffusion_model`, `vae`, and
`text_encoder`, and it maps `vision_encoder` to `--llm_vision` when the
candidate declares one. A candidate that declares a component role the profile
does not map is refused rather than silently ignored, and a declared
`vision_encoder` that the selected operation cannot pass is likewise refused.

## Versioned command-line contract

The Qwen zero-conditioning spelling changed between stable-diffusion.cpp
versions. The declaration and recipe must both explicitly set
`architecture_flags.sd_cpp_cli_contract` to one of these values:

| Contract | Emitted argument |
| --- | --- |
| `bare-flag/v1` | `--qwen-image-zero-cond-t` |
| `model-args/v1` | `--model-args qwen_image_zero_cond_t=true` |

The values must match. The adapter never probes a binary to guess which syntax
it supports. For a Qwen Image Edit 2511 declaration, an `edit` profile must
request `qwen_image_zero_cond_t=true`.

References are passed through repeated `-r`/`--ref-image` arguments in the
persisted conditioning order. A source image in the `ref-image` edit profile is
part of that order. An explicitly selected `init-img` profile instead passes
the single source through `-i`/`--init-img` and passes any other conditioning
through `-r`; `--strength` is emitted only for that mode. A generate profile
cannot carry strength. These distinctions are not inferred from the model name.

## Execution record state machine

Schema version 6 adds one `backend_executions` row per attempt with a resolved execution plan. The primary key is `attempt_id`; `job_id` must identify an execution job. The row
has a `resolved` stage, a one-way transition to `launched`, and a one-way
transition to `observed`. SQLite table constraints tie each optional JSON and
timestamp column to the corresponding state. Triggers enforce these rules in
addition to application row-count checks:

1. Insert must be in `resolved` state with every later-stage column null.
2. The resolved identity, digest, JSON, and timestamp cannot be updated.
3. The only permitted updates are `resolved` to `launched` and `launched` to
   `observed`.
4. Launch fields cannot change when the row becomes observed.
5. Backend evidence cannot be deleted.
6. Writer-epoch guards cover insert and update.

There is no migration path. A database created for an older schema is rejected
without mutation, exactly like every other unsupported current-schema version.

Every evidence write first proves that the supplied owner, claim epoch, and
attempt still match the job's current running attempt. A stale worker cannot
append evidence. The two transitions use conditional updates and require a
row count of exactly one, so a stage cannot be skipped or repeated.

## Resolved execution plan

The resolved record is inserted after resolution succeeds and before dispatch. It
contains:

- the T07 candidate identity, fresh `verification_id`, and declaration digest;
- engine identifier, version, build, and executable SHA-256;
- recipe identifier and document SHA-256;
- the ordered component roles with identifier, SHA-256, precision, and
  quantization;
- ordered adapter identifiers, positions, and strengths;
- the normalized model-facing prompt, resolved seed, width, and height;
- effective sampling method, steps, CFG scale, flow shift, and optional
  strength;
- ordered conditioning artifact IDs, roles, and content SHA-256 values;
- the exact argument vector, executed without a shell;
- sorted environment allowlist names and only the selected non-sensitive
  values;
- the scratch output basename, invocation contract version, and declared CLI
  contract version;
- a runtime fingerprint from read-only sources: platform, machine,
  `ROCM_PATH`, ROCm version, amdgpu module version or its opaque
  `srcversion` fallback, `HSA_OVERRIDE_GFX_VERSION`, and
  `HIP_VISIBLE_DEVICES`.

The record never contains credentials, acquisition settings, or raw image
bytes. The adapter currently refuses declared LoRA or other adapters because
the documented invocation contract cannot bind their required order and
strength without guessing. Such a request finishes with
`operation_unsupported`.

The engine version stored in the resolved record is copied from the candidate
declaration. The application-owned registration pins the real
stable-diffusion.cpp identity to `master-975-95b3090-2-gb13a482`, the exact
`git describe --tags` identity of commit
`b13a48219d5cdf408edcb93da6cd69b612ed03d3`. Exact string matching remains
mandatory at configuration evaluation and dispatch; a different describe
string, branch, or commit identifies different engine source and is refused.

Runtime markers are read without mutation. `rocm_version` is read from
`$ROCM_PATH/.info/version` when `ROCM_PATH` names a readable installation
marker, then from `/opt/rocm/.info/version`. `amdgpu_version` is read from
`/sys/module/amdgpu/version` when readable, then from
`/sys/module/amdgpu/srcversion`. The srcversion file is an opaque loaded-module
build identifier, not a semantic driver version; the application records it
under the existing field name and does not parse or order it. If neither
amdgpu marker is readable, or neither ROCm marker is readable, the
corresponding value is `null` and dispatch validation refuses the execution.

Verification happens before launch. The resolved record states that the pinned
bytes were verified before the process started and that the engine may open
different bytes afterwards, because no retained file handle is kept across the
launch. That fact is stored as the `verification_window` object with its
`verified_before_launch` and `engine_may_open_different_bytes_after_launch`
flags. The application does not claim that the engine loaded the hashed bytes.

## Launch fact

The application-owned `ProcessSupervisor` writes the launch record immediately
after `subprocess.Popen` succeeds and before it waits for the child. The record
contains the supervising process PID, a monotonic start value, and an explicit
`launched: true` fact.

If launch persistence fails, the supervisor kills and reaps the direct child
and preserves the persistence error. Because durable launch evidence was not
written, finalization remains conservative even though the code attempted
cleanup. A resolved row by itself is never presented as a launch.

A failure while draining the output pipes is handled the same way: the
supervisor kills the direct child, waits for it, closes both pipe handles, and
re-raises the original error. The service then quarantines the attempt because
no validated observation exists.

The launch record also stores the exact argument vector and the environment
mapping that the supervisor passed to the child. The service compares that
recorded invocation with the resolved plan before it accepts any observation,
and a mismatch fails closed. Because the launch record names what was actually
spawned, an adapter that never spawns cannot produce termination proof.

## Observation and reaping

The supervisor reads both output pipes through a non-blocking selector. It
hashes every byte read, counts stdout and stderr bytes, and keeps at most the
first 2 KiB of each stream in memory. After the direct child is reaped it
performs a bounded final drain so an inherited pipe cannot make supervision wait
forever. Descendant processes are not killed or tracked. Every byte read during
the bounded drain and during the follow-up open-stream probe is fed into the
same counters and digests, so a residual-writer decision never drops bytes from
the recorded evidence.

Captured output is never persisted. Subprocess stdout and stderr can repeat the
request prompt or a credential, so the observation stores a bounded, text-free
description instead of an excerpt. That description has three parts:

- a byte count and a complete SHA-256 digest for each stream;
- one encoding classification per stream: `empty`, `truncated` (the
  retained prefix is shorter than the stream), `non_utf8`, or `utf8`;
- a closed set of taxonomy codes derived in memory: `blank`,
  `lines_bounded`, `many_lines`, `contains_url`,
  `contains_absolute_path`, `secret_like_material_detected`,
  `prompt_echo_detected`, `truncated`, and `non_utf8`.

A code states that a class of value appeared; it never carries the matched text.
Prompt-echo detection compares the retained prefix with request text the
application already placed in the argument vector, and only the comparison
result survives.

The observation record contains:

- exactly one direct child's exit code or terminating signal;
- `direct_child_reaped: true`, written only after `wait()` returned;
- elapsed supervision duration;
- stdout and stderr byte counts and complete captured-stream SHA-256 values;
- `stdout_classification`, `stderr_classification`,
  `stdout_codes`, and `stderr_codes` as described above;
- `inherited_streams_retained_after_reap`, true when an inherited pipe
  still had a live writer after the bounded post-reap drain;
- `stream_state_unknown`, true when a pipe read failed in a way that is
  not a genuine end of stream;
- `process_tree_containment: false`.

The last field is deliberate. Starting a new session is not a containment
guarantee, and a surviving grandchild may continue running after the direct
child is reaped. The application makes no process-tree, filesystem, or network
isolation claim.

A failing read is never treated as end of stream. Only an empty read from
`os.read()` establishes EOF. `EOFError`, `ValueError`, `EBADF`, and every
other unexpected read failure mean the stream state is unknown; that pipe
stops being read and the observation sets `stream_state_unknown`, so the
attempt cannot serve as termination proof. In that state,
`inherited_streams_retained_after_reap: false` means only that no surviving
writer was successfully observed; it does not prove that no descendant still
holds the inherited pipes.

### Descendant visibility limit

`inherited_streams_retained_after_reap: false` means no descendant kept
the child's stdout or stderr open. It is not evidence that no descendant
process exists. A descendant that closes or redirects its inherited streams, or
that starts in its own session, leaves nothing the supervisor can observe. The
direct child is then reaped, the resource is released, and an unrelated process
may still be running and holding the same accelerator memory.

This slice tracks, terminates, and recovers no descendant processes.
Process-tree containment stays `false` for every observation, and a
successful execution is a statement about one direct child and the streams it
inherited.

## Termination proof and resource release

Termination is proven either by an existing trusted static containment contract
or by a validated observed row for the current attempt with
`direct_child_reaped: true`,
`inherited_streams_retained_after_reap: false`, and
`stream_state_unknown: false`. A reaped direct child whose inherited pipes
stayed open after the bounded drain shows that another process still held the
child's streams, so the attempt keeps the resource quarantined even when the
artifact publishes successfully. The same check is used for successful
publication, failed execution, cancellation recovery, and abandoned-attempt
reconciliation.

The proof is bounded by the descendant visibility limit described above. It
establishes that the direct child ended and that no descendant kept its
inherited pipes; it does not establish that the process tree is empty.

A resolved or launched row alone is not termination proof. A missing row, a
malformed row, an unknown state, or an observation write failure leaves the
attempt uncertain. Failure finalization records `ambiguous`, quarantines the
singleton resource, and causes recovery to report `attention_required`.

A successful artifact may already be committed when no termination proof is
available. In that case the artifact and job remain inspectable, but the
resource is quarantined. The service releases the singleton resource only when
all three conditions hold:

1. the current attempt has trusted termination evidence;
2. publication is reconciled and committed under the existing fencing rules;
3. the owner, claim epoch, attempt, and current-job authority still match.

The process evidence changes only the termination input. It does not change
attempt numbering, publisher ownership, fence epochs, retry eligibility, or
no-clobber artifact publication.

## Pre-dispatch refusals

An adapter prepares and resolves the execution before it marks the attempt as
dispatched. If preparation raises a `BackendPreparationError` before resolution
completes, the service finalizes a terminal preparation failure without creating
backend evidence and without classifying an inference process as ambiguous. If
preparation fails after the resolved row is written but before a child starts,
the service retains that row in the resolved state with no launch or observation
and finalizes a terminal preparation failure. The persisted message includes one
stable code:

Request validation rejects NUL bytes in the submitted prompt before
admission, so an invalid argv cannot reach the supervisor. As defense
in depth, an invalid resolved invocation that raises `ValueError` during
spawn is also classified as `engine_launch_failed`: no child started, no
launch evidence exists, and the attempt is a terminal preparation failure.

| Code | Meaning |
| --- | --- |
| `bundle_missing` | A declared required file is absent. |
| `bundle_corrupt` | A file, control document, or identity no longer matches. |
| `bundle_incompatible` | The declared engine, roles, or compatibility contract cannot execute the operation. |
| `bundle_unverified` | Independent trusted evidence is absent or does not verify. |
| `runtime_platform_mismatch` | The selected runtime is not the required platform. |
| `runtime_evidence_incomplete` | Required runtime markers cannot be read. |
| `engine_launch_failed` | The verified executable could not be started, or the resolved invocation was rejected before spawn. |
| `recipe_invalid` | The invocation recipe is malformed or violates its strict schema. |
| `operation_unsupported` | The selected profile cannot represent the requested operation. |
| `resolved_execution_mismatch` | The resolved record does not match the candidate and executable selected at admission. |

## Scratch output and publication

The engine writes to `output.png` in a private directory created with
`tempfile.mkdtemp` mode 0700. The directory is outside the configured output
directory and outside a detected Git worktree. The adapter validates the image
format and dimensions through a no-follow file handle before copying bytes into
the publisher's already-open staging descriptor. The existing publisher then
performs its normal full-image validation, filesystem synchronization, lineage
insertion, and no-clobber publication.

The adapter removes the scratch directory in `finally` after success or failure.
The service also removes it if publication fails after resolution but before
`execute` opens the publisher's staging descriptor. A process crash can leave the
system temporary directory for external cleanup; it does not create a named
staging file in the artifact directory.

## Privacy and admission

The real-engine privacy profile is application-owned. Its required controls
assert that the application does not configure an external API, cloud or
fallback inference path, telemetry, content upload, automatic network fetch or
update, remote endpoint, or proxy. The child environment is rebuilt from a
fixed allowlist and contains no proxy or credential variables.

The adapter does not supply these control values. The application derives them
from the resolved argument vector and the environment it will pass to the
child. A URL scheme, a remote, host, listen, server, API, proxy, download,
update, telemetry, or fallback token in the invocation marks the matching
control prohibited, and any proxy variable in the environment does the same.
The privacy profile is selected by the application, not by the adapter. An
application-owned registry maps the exact adapter identifier to the engine
identity, engine version, and configuration version it covers, and the service
reads the profile from that registry. A policy object exposed by an adapter is
ignored, so an adapter cannot widen the controls that apply to it. Adding an
adapter identity to the registry is an application change.

Invocation or environment settings the application cannot classify remain
`unverified` and block execution.

The service evaluates the record at the dispatch boundary before it inserts the
resolved row and before it spawns a child. It requires the record's argv and
environment to match the prepared invocation, recomputes the privacy settings
from that argv and environment, requires the recorded map to match the
recomputation, requires the adapter to declare an identity present in the
application-owned privacy registry, requires the record's declared engine
identity and version to match that registration, and requires the
application-owned policy to return `pass`. A prohibited token in the argv or a
proxy variable in the environment fails this gate.

The gate also binds the record to the restart-stable adapter configuration
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
adapters, or contracts fail closed as `resolved_execution_mismatch` before the
resolved row is inserted or a child starts. An engine identity or version
mismatch against the application-owned registration fails earlier with the
privacy reason `resolved_engine_mismatch`.
The binding still consumes the configuration the adapter exposes at admission,
so an adapter that fabricates both its configuration and its resolution remains
an in-process trust boundary. The launch record captures the argv and
environment the supervisor passed; it does not prove that the process opened
the same bytes the application verified, because the engine opens those paths
itself after launch.

These controls describe application configuration only. They do not prove that
the executable contains no network code and do not provide operating-system
network confinement. Missing or unrecognized control values remain
`unverified` and block the configuration-compliant execution profile.
Prohibited values fail admission.

Heavyweight execution still requires a current T06 admission decision and the
single heavyweight reservation. Workers use the admission evidence persisted at
submission; they do not accept capacity documents. A worker configures the same
candidate and privacy configuration that it will claim, and an exact
configuration mismatch is an error rather than a fallback selection.

## Command-line use and inspection

`submit`, `enqueue`, and `worker` accept `--engine-candidate` and optional
`--engine-trusted-evidence`. Supplying no engine flags keeps the deterministic
CPU adapter. Supplying trusted evidence without a candidate is invalid.

`submit` and `enqueue` also accept the T06 inventory, policy, and workload
demand files. `worker` has no capacity-file arguments because claim validation
uses the evidence stored with the queued job.

The full validated records for the current attempt are available through:

```sh
media-generation execution --db ./studio.sqlite3 --job-id <job-id>
media-generation execution --db ./studio.sqlite3 --job-id <job-id> \
  --attempt-id <attempt-id>
```

The provenance snapshot contains a compact `backend_execution` value with the
attempt ID, state, resolved digest, and observation timestamp, or `null` when
the current attempt has no backend record.

## Reopen validation

Reading an execution row parses and validates every present stage, checks that
its attempt identity agrees with the row, checks the engine and recipe
identities stored in columns, and recomputes the resolved digest from canonical
JSON. A malformed or digest-mismatched row raises `BackendEvidenceError`; it is
never treated as a missing row or downgraded to an unproven state.

## Unverified boundaries

The software path and synthetic conformance executable establish argument
mapping, process supervision, evidence persistence, failure handling, and
publication behavior. They do not establish that a particular Qwen checkpoint
loads on APEX, that ROCm execution succeeds, that image quality is acceptable,
that a survivor process is contained, or that the engine cannot access a
network. Those remain runtime and qualification concerns outside this evidence
layer.

Component and executable hashes are verified before launch. Because no retained
descriptor spans the launch, the bytes the engine opens afterwards may differ
from the bytes that were hashed; the resolved record states this window
explicitly.
