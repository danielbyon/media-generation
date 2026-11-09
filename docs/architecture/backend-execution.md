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

## ComfyUI graph execution and resolved record v3

ComfyUI has a distinct opt-in adapter and invocation contract. It does not
rewrite an SD.cpp command and does not inherit the SD.cpp zero-conditioning
rule. The adapter accepts only the pinned `comfyui-api/v1` graph contract and
re-evaluates the candidate, executable, recipe, node bundle, and required
component pins before launch. A missing or modified pin, an unsupported node,
an unsupported reference role or count, or a graph placeholder mismatch is
refused before the server process starts.

T07 ComfyUI readiness requires trusted compatibility evidence for the fixed
claim `backend-policy:comfyui/qwen-image-edit-2511-reference-latent-timestep-zero/v1`
bound to the exact recipe document digest. An engine label does not replace
that evidence. Profile version 2 execution and resolved-record revalidation
both require the validated graph described below. See ADR 0005.
Candidate recipes use one of two versioned graph contracts. Version 1 remains
loadable for historical synthetic tests, where `generate` may have no image and
`edit` has one `source`. A non-synthetic candidate must use version 2 and fails
closed if it selects the older profile.

Version 2 separates the two supported operations:

| Operation | Required image role | Sampling latent | Output path |
| --- | --- | --- | --- |
| `generate` | exactly one `reference` | `EmptyLatentImage` at the requested dimensions | decoder output directly to `SaveImage` |
| `edit` | exactly one `source` | `VAEEncode` of the scaled source | decoder output through a bounded `ImageScale` to `SaveImage` |

Text-only generation, multiple references, and either image role on the wrong
operation are unsupported. These rules apply to candidate admission and to
execution, so a normalized request must match the selected operation profile.

The version 2 topology is fixed. `LoadImage` feeds
`FluxKontextImageScale`. The scaled image feeds both positive and negative
`TextEncodeQwenImageEditPlus` nodes. The positive prompt is the resolved prompt
and the negative prompt is empty. Each encoder feeds its own
`FluxKontextMultiReferenceLatentMethod` with
`reference_latents_method=index_timestep_zero`, and the sampler consumes only
those two branches. The model branch is `UNETLoader`, then
`ModelSamplingAuraFlow`, then `CFGNorm`, then `KSampler`. The profile uses 40
steps, CFG 4, flow shift 3.1, Euler sampling, the simple scheduler, denoise 1,
and no Lightning LoRA. Validation rejects additional, missing, disconnected,
or substituted nodes and unapproved inputs.

SQLite database schema 6 remains unchanged. Current ComfyUI executions use a
v4 resolved record in the existing immutable
`backend_executions.resolved_json` column, bound by `resolved_digest`.
Historical v2 and v3 resolved rows remain readable and are never rewritten.
Launch and observed records retain their v2 schemas.

Resolved record v3 fixes the top-level identity to
`backend_kind=comfyui-local-http`, `invocation_contract=comfyui-http/v1`, and
`cli_contract=comfyui-api/v1`. It adds one `effective_execution` object that
contains the complete expanded API graph, the exact resolved node inputs, the
model-facing configuration, the effective server and API configuration, the
attempt-bound `prompt_id`, `client_id=attempt_id`, and the exact canonical HTTP
request body. SHA-256 digests bind the graph, configuration, and request body.
The adapter persists these bytes before dispatch and sends those same bytes in
the single `POST /prompt` request. Raw image bytes and credentials are excluded.

V3 validation is bounded and strict. Missing fields, malformed or oversized
values, unsupported record versions, graph or digest mismatches, unknown nodes,
prohibited input names, inconsistent request identity, or a backend identity
that does not match the v3 contract fail closed before dispatch. Historical v2
records retain their original validation and serialized bytes.

Resolved record v4 adds `privacy_evidence` to the v3 execution evidence. The
new object records its own schema version, status, evidence source, adapter ID,
engine ID and version, adapter configuration version, profile ID, profile
version and fingerprint, effective configuration SHA-256, and sorted reason
codes. It contains no credentials or raw environment values. The profile and
configuration values are checked against the application-owned local profile
and the exact effective configuration. Store insertion, restart decoding, and
pre-dispatch verification reject altered values, unsupported evidence versions,
unknown reason codes, or a mismatched evidence fingerprint. V3 records remain
readable without `privacy_evidence`; v4 records require it.

For profile version 2, the v3 configuration's `workflow` object also records
`profile_version`, `sampling_resolution`, and `output_dimensions`. Generation
records the requested empty-latent dimensions as its sampling resolution and a
decoder-native output. Editing records
`mode=flux-kontext-image-scale` with an unknown sampling width and height,
because `FluxKontextImageScale` determines those model-side dimensions. It also
records the requested post-decode output dimensions. These fields remain inside
the existing v3 resolved record and therefore do not change database schema 6
or either historical launch or observed record version.

`ProcessSupervisor.run_managed` is the additive path for a service-owned
ComfyUI server. It starts one direct child on `127.0.0.1`, drains both output
streams concurrently, exposes bounded liveness and authority checks to the HTTP
session, terminates and reaps the direct child, and records the existing launch
and observed evidence. It does not claim descendant containment. Readiness and
server identity are checked before uploads or graph submission. Completion and
output retrieval are bounded, and only a validated image is copied into private
run-scoped storage for the existing publication boundary.

The canonical attempt-bound `prompt_id` is sent in the persisted request body;
`client_id` is the attempt identifier and is routing metadata rather than an
idempotency token. ComfyUI does not make duplicate POSTs idempotent. After a
lost or malformed response, the adapter observes the pinned jobs listing,
queue, and history routes for positive evidence tied to that ID. An absent row,
empty queue, 404, or malformed observation does not prove rejection. The
adapter never resubmits an ambiguous `POST /prompt`. If acceptance or
completion cannot be established, it terminates the owned child and reports an
ambiguous outcome. Publication is refused. The supervisor records the
reaped direct child as direct-child termination evidence. The ComfyUI adapter
also declares that T06 release requires process-tree evidence, which this
supervisor does not collect. An attempt that started the server therefore
keeps its T06 resource quarantined, including after an artifact publishes.

For profile version 2, a CLI request with `operation: "edit"` requires exactly
one image whose role is `source`. A request that selects `generate` requires
exactly one image whose role is `reference`. Candidate admission validates the
image path through `FluxKontextImageScale`, both Qwen conditioning branches, the
sampler, and the declared output node. Execution validates the substituted
graph again. The adapter reports editing support only when the approved profile
contains that capability. The operation assertion is excluded from canonical
request hashing; persisted reference IDs and roles continue to define the
stable request.

Runtime approval is read from the host-configured
`MEDIA_GENERATION_COMFYUI_RUNTIME_APPROVAL_PATH`. The verification key comes
from a fixed host path: `/private/etc/media-generation/comfyui-runtime-public-key`
on macOS and `/etc/media-generation/comfyui-runtime-public-key` elsewhere. The
key file and every parent directory must be root-owned and not group- or
world-writable. Symlink components are rejected. The verifier ignores
environment-selected public-key paths. The manifest path may be selected by the
host environment, but it must be absolute and normalized, stay outside the
repository, and contain no symlink components.

The approval envelope and payload use canonical strict JSON. An Ed25519
signature authenticates the exact ComfyUI version, candidate identity,
interpreter, workflow, component files, and six runtime roots: Python home,
ComfyUI source, Python imports, native dependencies, frontend, and node
implementations. Runtime pin schema version 5 also signs each path in
`python_stdlib_paths` with a matching `python_stdlib_pins` record containing
the tree SHA-256, total file bytes, and entry count.

Tree verification uses descriptor-relative no-follow opens, identity checks,
and streamed 1 MiB reads. It allows at most 100,000 entries and 64 directory
levels per root, 32 GiB per pinned file, 8 GiB per root, 16 GiB across runtime
and standard-library roots, and 64 GiB across explicitly pinned files. Unsafe
paths, symlinks, changed bytes, malformed input, and exceeded limits fail
closed. The approval file is limited to 2 MiB, the public-key file to 256
bytes, and JSON nesting to 48 levels. The separate frontend-tree check is
limited to 4,096 entries, 64 directory levels, and 128 MiB. The larger bound
admits the complete upstream ComfyUI 1.55.17 frontend, including JavaScript
source maps, without creating a custom asset distribution. Recipe documents
and ComfyUI JSON responses are each capped at 1 MiB, and each reference upload
is capped at 32 MiB. Exceeding a limit refuses the operation; the adapter does
not truncate and continue.

The signed interpreter pin includes its exact path, size, and SHA-256. The
child command uses that path as `argv[0]` and starts Python with `-P -s -S`.
It leaves `PYTHONHOME` unset so Python can establish the venv and base
interpreter prefixes from its own configuration. The signed approval records
the expected `sys.prefix`, `sys.base_prefix`, and standard-library paths. The
bootstrap checks both prefixes and each initial `sys.path` entry against the
signed roots. It then replaces `sys.path` with the signed standard-library,
Python import, and ComfyUI source roots before importing `runpy` or ComfyUI.

The child environment is built from an empty mapping. It copies only present
values for recipe-listed safe environment names. `PATH` is replaced with the
fixed `/usr/bin`, `/bin`, `/usr/sbin`, and `/sbin` search path, and
`LD_LIBRARY_PATH` is replaced with the
signed native-dependency root. A recipe-listed `PYTHONHASHSEED` is admitted
only as `random` or an ASCII decimal integer from 0 through 4294967295; other
`PYTHON*` variables are not passed to the child. Python does not receive
`PYTHONPATH`; `-P` prevents implicit script or working-directory imports, `-s`
disables the user site, and `-S` skips site initialization, including `.pth`,
`sitecustomize`, and `usercustomize` hooks. Unrelated inherited environment
variables are not passed to the child.

The application reloads and verifies the signed approval during construction,
resolution, before process launch, and immediately before `POST /prompt`. The
last check runs after readiness and reference uploads. It rechecks the signed
manifest and runtime closure, including each signed standard-library tree. It
confirms the manifest and trust-key fingerprints still match the adapter's
initial approval and rebinds the candidate and child launch paths. This catches
changes made after startup and before prompt submission. The check cannot lock
files against later replacement or prove which bytes the operating system
loads after verification; that load-time TOCTOU window remains.

The production ComfyUI privacy registration is derived dynamically from an
authenticated signed runtime manifest and uses configuration version
`comfyui-local/v2`. Without a valid independently signed manifest,
`_require_independent_runtime_pin_binding()` fails closed and no production
ComfyUI candidate is active. The repository contains no approved ComfyUI
manifest, T07 candidate, or APEX inference evidence. The synthetic test
fixtures override approval only inside tests and do not change the production
gate. A local frontend digest supplements the
signed frontend path and launch argument; it does not establish APEX
qualification or prove which frontend bytes the process later loads.

A host Python standard library with symlinked roots or members fails the
no-follow tree check and remains unqualified. Production stays blocked until
the selected runtime passes the signed standard-library checks; the verifier
does not follow those links.

### Node authority v3

`media-generation.comfyui-node-implementations` schema version 3 binds the
registered inputs of every ComfyUI graph class to a deterministic source
archive. Schema version 2 documents remain readable through their existing
validation path. Node authority v3 does not change the database, candidate,
recipe, runtime-pin, generic evidence, launch, or observed record versions.

The authority document has exact top-level keys `schema`, `schema_version`,
`tool_id`, `tool_version`, `source_root_sha256`, `component`, `sources`, and
`nodes`. The single component records `id`, `size_bytes`, and `sha256`. Source
pins are sorted by `path` and record `path`, `size_bytes`, and `sha256`. Each
graph class names one `source_path`, `registration_api`, `component_id`, and
`component_sha256`; its `inputs` object records exact `required`, `optional`,
and `hidden` registration names. Existing tool identity fields retain their
prior values.

The component is a canonical `ZIP_STORED` archive. It contains one
`manifest.json` and `sources/<relative-source-path>` members in sorted order,
with a fixed 1980 timestamp, fixed Unix regular-file mode, and no extras or
comments. The archive is at most 32 MiB, its canonical manifest at most 256
KiB, and it holds at most 64 sources. Each source is at most 8 MiB, each path
at most 1024 UTF-8 bytes and eight components deep. Verification rejects
absolute, parent-traversing, backslash, control-character, NUL, duplicate, and
case-fold-colliding paths; encrypted, compressed, directory, symlink, special,
malformed, or length-inconsistent members; and any CRC mismatch. A successful
check rebuilds the archive, compares the result with expected T07 `other`
component identity, and compares every source byte and hash with the signed
`comfyui_source` root. `source_root_sha256` must equal the signed runtime-pin
root digest. The Git tree digest is provenance only and cannot replace it.

Offline AST verification reads the five measured ComfyUI source files without
importing or executing them. Legacy classes use literal `INPUT_TYPES` and
`NODE_CLASS_MAPPINGS` entries. Modern classes use `io.ComfyNode`, literal
`io.Schema.node_id` and `io.*.Input` registration, and extension
`get_node_list` membership. Each class must appear once with an unambiguous
registration and extension mapping. Profile-v2 admission for v3 requires the
exact 15-class generate and edit coverage, every required input in the graph,
registered optional inputs only where supplied, and no graph-supplied hidden
input. This parsing proves source registration structure; it does not prove
that imports or runtime node resolution will succeed.

The node-source component is distinct from the signed runtime-pin
`node_implementations` root. Current commit `9fa63b0acc1fe3503db536109e104bba3bb1614f`
and Git tree `56003da4ea4f6c12770150d53b8f100a172ab65c` have no signed source
root digest. Production v3 bundle generation and independent T07 component
approval therefore remain unavailable. Unit tests use explicitly synthetic
root and component pins and cannot activate a production authority record.

Admission privacy facts are computed from the validated durable launch
template, environment allowlist, both operation graphs, local frontend tree,
endpoint contract, and trusted node pins. The persisted adapter configuration
labels this as `validated-durable-template`; its placeholder port and paths
are not presented as the effective invocation. It also records that the same
policy rechecks `argv`, environment, loopback endpoint, run-scoped directories,
frontend root and digest, graph, and request body against the exact effective
invocation immediately before dispatch. The frontend tree is rehashed before
startup and before graph submission. Readiness requires the pinned ComfyUI
version. Upstream `system_stats` may omit `system.web_root`; when it does, the
adapter relies on the signed frontend path, the exact `--front-end-root` launch
argument, and the local tree digest. If `web_root` is present, it must equal
the signed frontend path or readiness fails closed.

Before uploading references or sending the prompt, the adapter requires the
server's node-replacement map to be empty. This prevents ComfyUI's prompt
replacement hook from changing the submitted graph without corresponding
durable evidence. A nonempty, missing, or malformed replacement observation
fails closed.

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
direct child is then reaped. Direct-child termination evidence can authorize
resource release only when the persisted adapter policy explicitly selects the
direct-child scope. It never establishes process-tree containment. ComfyUI
requires process-tree evidence, so its resource remains quarantined while an
unrelated process may still be running and holding the same accelerator memory.

This slice tracks, terminates, and recovers no descendant processes.
Process-tree containment stays `false` for every observation, and a
successful execution is a statement about one direct child and the streams it
inherited.

## Termination proof and resource release

Direct-child termination evidence comes from a trusted static containment
contract or from a validated observation of the current attempt. The
observation must contain `direct_child_reaped: true`,
`inherited_streams_retained_after_reap: false`, and
`stream_state_unknown: false`. A reaped child that left an inherited pipe open
shows that another process still held that pipe, so the attempt keeps the
resource quarantined.

This evidence establishes that the direct child ended and that no descendant
kept its inherited pipes open. It does not establish that no descendant
process exists.

The immutable adapter identity recorded at admission and repeated on the
attempt selects the resource-release policy before configuration is read. The
two identities must agree. A configuration can declare the
`media-generation.resource-release` schema version 1 with either
`direct-child` or `process-tree` required scope. The known ComfyUI identity
always requires `process-tree`, so a missing, historical, malformed, or
unsupported declaration cannot activate direct-child release. Other
historical adapters without a declaration keep their existing direct-child
contract; a malformed or unsupported declaration fails closed for them too.
Until a reviewed implementation collects process-tree evidence, ComfyUI
attempts remain quarantined after the direct child is reaped. A pre-spawn
failure can still release the resource because no child was launched.

A resolved or launched row alone is not termination proof. A missing row,
malformed row, unknown state, or failed observation write leaves the attempt
uncertain. Failure finalization records `ambiguous`, quarantines the singleton
resource, and causes the recovery report to return `attention_required`.

A successful artifact may already be committed when required termination
evidence is unavailable. The artifact and job remain inspectable, and the
resource stays quarantined. The service releases the singleton resource only
when all of these conditions hold:

1. The current attempt has trusted termination evidence for its adapter's
   declared release scope.
2. Publication is reconciled and committed under the existing fencing rules.
3. The owner, claim epoch, attempt, and current-job authority still match.

Process evidence changes the release input. It does not change attempt
numbering, publisher ownership, fence epochs, retry eligibility, or
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
