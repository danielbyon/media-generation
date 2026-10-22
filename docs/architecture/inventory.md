# Read-only inventory

The inventory command collects a bounded snapshot of a local machine and the
runtimes and model components that an operator has explicitly declared. It is
designed to run without a GPU, without model inference, and without network
access. The command writes only its requested output files; every host, runtime,
and model observation is read-only.

The report is evidence about what was observed in a particular run. It does not
prove that a model works, that an engine supports an operation, that a host has
been validated for production, or that the run happened on a particular
physical machine. Those are separate qualification stages.

## 1. Command and outputs

Run the command from a checkout without installing the package:

```sh
PYTHONPATH=src python3 -m media_generation inventory \
  --output /path/outside-the-repository/inventory-run
```

The package's `__main__` module forwards to the same `media_generation.cli`
entry point as the installed `media-generation` console script.

The command writes two files in the output directory:

- `inventory.json` is the versioned machine-readable report.
- `transcript.txt` is a bounded, human-readable probe and finding log.

The writer creates each file through an exclusive temporary file in the same
output directory and replaces the destination atomically. A pre-existing
symbolic link named `inventory.json` or `transcript.txt` is replaced rather
than followed, so output cannot be redirected outside the selected directory.
Temporary files are removed when a write fails.

Both paths are also returned in the command summary on standard output. Use an
output directory outside the repository. Generated inventories, transcripts,
host fingerprints, and evidence bundles must not be committed. The repository
ignore list reserves `/inventory-runs/` as a safety net for local runs inside a
checkout.

Optional arguments:

- `--manifest PATH` supplies a strict declaration of model roots, runtime
  paths, bundles, recipes, capabilities, and probe policy.
- `--hash-components` enables full SHA-256 hashing of declared model
  components.
- `--hash-limit-bytes BYTES` sets the per-component hash cap. The default is
  16 GiB and the value must be positive.
- `--replay PATH` reads deterministic synthetic observations for tests. A
  replay file must declare `synthetic: true`.

### Exit status

| Exit | Meaning |
| ---: | --- |
| `0` | The host inventory is `ok`; the report was written. |
| `4` | The host inventory is `partial`; the report was written. |
| `5` | The host inventory is `blocked`; the report was written when possible. |
| `2` | A manifest, replay file, or command option failed validation. No inventory is written. |
| `3` | The requested output could not be written. |
| `1` | An unexpected failure escaped structured handling. |

Exit codes `0`, `4`, and `5` all mean that a valid summary was produced. They
do not all mean that collection succeeded. Automation must inspect
`host_inventory_status` or the process exit code rather than treating a written
file as a passing evidence gate.

## 2. Status and evidence gates

The command summary and `evidence_gate.host_inventory_status` use one of these
values:

- `ok`: required host probes completed and no configured runtime or bundle was
  known to be incomplete.
- `partial`: the report is usable, but at least one required or configured
  observation was unavailable, skipped, timed out, malformed, or in error.
- `blocked`: a required host identity or memory observation could not be made.
  Other sections may still contain useful observations.

Individual probes use `ok`, `unavailable`, `skipped`, `timeout`, `error`, or
`malformed` with a reason and bounded detail. A missing executable, an empty
manifest, a permission failure, and an unknown memory relationship are different
outcomes and must not be collapsed into `absent`.

`evidence_gate` separates the report from later evidence stages:

```json
{
  "report_written": true,
  "host_inventory_status": "partial",
  "configuration_inspection": "configured",
  "evidence_origin": "local_host",
  "apex_verification": "unverified",
  "apex_verification_reason": "live_apex_inventory_not_performed",
  "capability_qualification": "unverified",
  "capability_qualification_reason": "no_execution_or_qualification"
}
```

`report_written` means only that the requested JSON and transcript were written.
It is not a hardware, engine, model, or product qualification result. A report
generated on another machine is not APEX evidence. Replay output sets
`evidence_origin` to `synthetic_replay` and must never be treated as host
evidence.

## 3. Collection scope and read-only behavior

The collector performs these operations:

- Reads standard platform, kernel, CPU, memory, Python, and Linux DRM/sysfs
  metadata. A DRM card device link is accepted only when it resolves beneath
  /sys/devices; unrelated links are rejected.
- Reads bounded, fixed-location runtime markers, version files, and Git HEAD and
  ref files.
- Resolves cataloged executable names through `PATH` and a short list of known
  installation locations.
- Reads active Python environment distribution metadata without importing the
  distributions.
- Inspects explicitly declared model components and small approved sidecars.

It does not:

- Install, update, download, or remove software.
- Load model weights or run inference.
- Scan arbitrary directories recursively.
- Follow symlinks below a declared model root, including intermediate links.
  A declared root itself may be a symlink and is treated as trusted.
- Fetch a manifest URL.
- Read environment variables, credentials, or arbitrary file contents.
- Change firewall, network, service, or device state.

Model-root containment is enforced when each file is opened, not only when
paths are validated. On POSIX hosts where `os.open` supports directory
descriptors, the collector walks from the trusted root through
`O_NOFOLLOW | O_DIRECTORY` descriptors and opens the final entry without
following links, so an intermediate directory swapped for a link after
validation is refused. Platforms without descriptor-relative opens allow only
a direct child of the declared root and report
`descriptor_containment_unavailable` for nested paths instead of reading them.

The only writes are the inventory and transcript files in the requested output
directory. An operator may choose to run the collector through an existing remote
session, but the collector does not create one, copy source trees, or orchestrate
remote hosts.

## 4. Empty and configured manifests

Without `--manifest`, the report says `configuration_inspection:
not_configured` and records `model_inventory.reason: manifest_not_supplied`.
This means that no model roots, bundles, recipes, or declared capabilities were
inspected. It does not mean that models are absent from the machine.

A supplied manifest with no model roots or bundles records
`model_inventory.inspection: not_configured` and `reason:
no_bundles_declared`. The manifest itself is still `configured`; only the model
declarations are empty. A model root is a containment boundary for declared
components. The collector does not enumerate the root looking for models.

## 5. Manifest format

Manifests are strict JSON, no larger than 1 MiB. The limit is applied while
reading as well as by the initial size check, so a file that grows after
validation is rejected without reading past the limit. Unknown fields and
duplicate keys are rejected so a typo cannot silently change the evidence.
Relative paths are resolved against the manifest file, not the current
directory.

```json
{
  "schema": "media-generation.inventory-manifest",
  "schema_version": 1,
  "description": "Operator-declared inventory scope",
  "model_roots": [
    {"id": "models", "path": "/data/models"}
  ],
  "runtimes": [
    {
      "id": "comfyui",
      "path": "/opt/ComfyUI",
      "probe_version": false,
      "declared_capabilities": [
        {
          "task": "text_to_image",
          "support": "advertised",
          "source": {"kind": "url", "value": "https://example.invalid/docs"},
          "notes": "Vendor or project documentation claim"
        }
      ]
    }
  ],
  "bundles": [
    {
      "id": "candidate-a",
      "engine": "comfyui",
      "recipe": {
        "id": "recipe-a",
        "source": {"kind": "operator", "value": "local workflow"},
        "parameters": {"steps": 20, "sampler": "euler"}
      },
      "components": [
        {
          "id": "diffusion-model",
          "role": "diffusion_model",
          "path": "/data/models/example.safetensors"
        }
      ],
      "declared_capabilities": []
    }
  ],
  "probe_policy": {
    "device_queries": false,
    "timeout_seconds": 5
  }
}
```

Runtime IDs and bundle engines must come from the fixed catalog: `stable-diffusion.cpp`,
`comfyui`, `invokeai`, `ollama`, `llama.cpp`, `diffusers`, `torch`,
`transformers`, or `rocm`. A manifest can select catalog entries and declare
paths and component roles. It cannot inject executable names, argv vectors,
shell snippets, or search roots.

Component roles are `checkpoint`, `diffusion_model`, `text_encoder`,
`vision_encoder`, `tokenizer`, `vae`, `adapter`, `upscaler`, `controlnet`,
`projector`, or `other`. A component must be inside a declared model root.

Capability support is limited to `advertised` and `declared`. Every capability
item remains `local_execution: not_performed` and `qualification: unqualified`.
An engine name, model filename, or manifest claim is not test evidence.

Recipe sources with `kind: url` are attribution strings. They are never
retrieved. On-disk recipes are read only through an explicitly declared bounded
path, with a 256 KiB limit.

## 6. Passive runtime discovery

Runtime discovery is bounded to:

- Explicit runtime paths from the manifest.
- Cataloged executable names resolved through `PATH`.
- A short catalog of conventional installation locations.
- ComfyUI-style directories with a `main.py` marker.
- Active Python environment distribution metadata for `diffusers`, `torch`,
  `transformers`, and `rocm`.
- Bounded version files and Git HEAD/ref metadata for directory runtimes.

Python distributions are identified through distribution metadata; modules
are not imported. The metadata read is an observation on the collection
source, so replay uses recorded distribution records and never consults
packages installed on the machine running the test. This catches packages
that are installed in a virtual environment but whose console scripts are
not on `PATH`.

For a binary runtime, the report records its resolved path, file kind, size,
mtime, executable bit, and a SHA-256 digest when the file is within the 512 MiB
runtime digest cap. If the digest cannot be computed, the digest object records
`skipped` or `unavailable` with a reason. A directory runtime records its path,
marker set, version file, and bounded Git source revision. A Python distribution
records its package name, observed version, and distribution location.

The environment fingerprint includes the observed runtime path, size, digest
state and value, version state and value, source revision, and version-file
value. This keeps the executable identity in the fingerprint even when the
version probe is disabled.

## 7. Runtime execution policy

Passive discovery does not execute a runtime. A manifest entry with
`"probe_version": true` opts in to one fixed version or help command from the
catalog. The command has a timeout from `probe_policy.timeout_seconds` (1 to 30
seconds) and a 32 KiB output cap. The stdout excerpt is retained in the bounded
transcript; the JSON report records the command, status, exit code, output size,
truncation flag, reason, and parsed version when available.

Device-inventory commands are also opt-in. With
`probe_policy.device_queries: false`, the collector records a single skipped
`gpu:device-queries` probe and does not resolve or run `lspci`, `rocm-smi`,
`nvidia-smi`, or `hipconfig`. Setting the policy to `true` enables the fixed
catalog commands with the same timeout and output bounds. These commands are
treated as potentially stateful device queries and are never enabled by default.

The fixed `/opt/rocm/.info/version` file read is a passive toolchain identity
read, not a device query.

## 8. Memory semantics

The report keeps these values distinct. PCI class `0x0300` identifies a display
device; it does not prove that a memory pool is dedicated or shared.
Dedicated VRAM is marked only when a device query reports it explicitly, such
as `nvidia-smi`. A card without reliable memory-kind evidence remains `unknown`:
its pools are reported but are not allocatable and are not added to a total.

- `host.memory.system.total_bytes` is system RAM.
- Each accelerator's `pools` contains the reported GPU pools, including
  dedicated VRAM, shared carve-out, GTT, and visible-VRAM aliases as observed.
- `host.memory.topology.allocatable_pools` lists only pools that can be treated
  as independently allocatable. System RAM and each dedicated VRAM pool appear
  as separate entries.
- `host.memory.topology.sharing_relationships` records whether a pool is inside
  system RAM, a shared system aperture, a duplicate alias, or an unknown
  relationship.

`reported_total_bytes` is only a convenience aggregate. It is never one pool:
`reported_total_is_allocatable_pool` is always `false`. For a discrete topology
the aggregate may include system RAM and dedicated VRAM. GTT, carve-outs, and
visible-VRAM aliases are not added to that aggregate because they are views or
aliases of memory already represented.

A dedicated VRAM total larger than system RAM is valid. A shared pool larger
than system RAM is treated as a conflict and leaves the topology ambiguous. If
the sharing relationship cannot be established, the topology remains `unknown`
or `ambiguous`; no total is invented. Unified memory is never counted by adding
system RAM and a shared GPU aperture. A GTT aperture on a device with
dedicated VRAM does not by itself make the topology ambiguous.

## 9. Model component inspection

Every declared component is inspected with a non-following `lstat`. Paths are
rechecked at inspection time against the declared model roots. The root may
be a symlink, but every entry below it must be a real directory and the
final entry must not be a symlink. The same rule applies to sidecars and
recipe files. Each open walks below the declared root using directory
descriptors and `O_NOFOLLOW`, including the final entry, so a path component
replaced by a link after validation is refused. The initial `lstat` checks
identify unsafe declarations; the descriptor-relative open revalidates
containment at the OS layer.

Directories receive a bounded one-level listing. The collector stops after a
bounded scan window, sorts only the retained entries for stable output, and
sets `truncated` when more entries exist. Enumeration opens the directory
relative to the trusted root with `O_NOFOLLOW | O_DIRECTORY`, so an
intermediate or final link replacement is refused before entries are read.
Regular files are identified by suffix and receive a bounded header read:

- Safetensors: at most a 1 MiB header, at most 100,000 tensor entries, dtype
  counts, and a small descriptive metadata allowlist.
- GGUF: at most a 1 MiB header, at most 100,000 tensor entries, strings of at
  most 1 MiB, arrays of at most 4,096 items, and nesting depth of at most 3.
  ``general.file_type`` is translated with the current llama.cpp
  ``llama_ftype`` enum. Unknown or sentinel values stay unclassified while the
  raw integer is retained in ``quantization_enum``; quantization is never
  inferred from a filename.
- Approved sidecars: `config.json` and `model_index.json`, each at most 256 KiB,
  with only `_class_name`, `architectures`, `model_type`, `torch_dtype`, and
  `quantization_config` retained.

Tensor data is not loaded. Legacy pickle-like formats such as `.ckpt`, `.pt`,
`.pth`, and `.bin` are refused rather than parsed. A malformed, truncated, or
inaccessible header produces an explicit status and reason; it does not produce
guessed architecture or quantization values.

Full component hashing is off by default. With `--hash-components`, each
declared component is streamed to SHA-256 up to the configured per-component
limit. Read-time byte accounting, opened-file size checks, and descriptor
identity checks stop a hash when the file grows beyond the limit or is replaced
before or during reading; no partial digest is published. Only regular files
are hashed; FIFOs, sockets, devices, and directories are rejected with
`not_regular_file` without being opened for reading. A component beyond the
limit remains present with an explicit `skipped` digest state. A bundle
identity becomes `complete` only when its recipe and all component digests
were actually computed.

## 10. Environment fingerprint

`environment-fingerprint/v1` is a SHA-256 digest over a canonical JSON document.
Its inputs are:

- OS ID and version ID.
- Kernel release and machine architecture.
- CPU model, architecture, and logical core count.
- Accelerator IDs, vendor and device IDs, PCI class and address, driver and
  driver version, name, and reported pool identity and size.
- System memory total, topology class, and reported aggregate.
- Runtime ID, presence, path, size, digest state and value, version state and
  value, source revision, and version-file value.
- Python implementation and version.

The fingerprint excludes run IDs, timestamps, probe durations and order, hostname,
output and manifest paths, environment variables, locale, and free or available
memory. Missing stable attributes remain explicit unknown entries, so enabling a
previously unavailable probe changes the digest instead of silently disappearing
from the input document.

## 11. Replay mode

Replay exists for deterministic tests. A replay document must use schema
`media-generation.inventory-replay`, schema version 1, and `synthetic: true`. The
report is marked `collection_mode: replay`, `evidence_origin: synthetic_replay`,
and the transcript begins with a synthetic-evidence banner. Replay does not
fabricate model bytes, header contents, or content hashes. Replay documents
are capped at 4 MiB and must be valid UTF-8 JSON; oversized or malformed input
produces a structured validation error before the full document is parsed.

Replay is not a live APEX inventory, a substitute for a host run, or permission
to treat fixture values as hardware observations.

## 12. APEX operator workflow

The collector does not connect to APEX, copy source, install packages, or delete
remote files. A person with explicit access to the target host performs these
steps locally on that host or through a session they are authorized to use.

1. Confirm the target host identity and the checkout commit. Do not use a report
   from a development machine as APEX evidence.
2. Use the existing source checkout and Python 3.11 or later. Do not install a
   new package unless the host owner has approved that change.
3. Create one output directory outside the repository. Do not create a second
   copy elsewhere.
4. Write a manifest outside the repository containing only the model roots,
   runtime paths, bundles, and capabilities the operator wants inspected.
5. Run the collector with no version or device probes first:

```sh
cd /path/to/media-generation
output=/path/outside-the-repository/apex-inventory-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$output"
PYTHONPATH=src python3 -m media_generation inventory \
  --manifest /path/outside-the-repository/apex-manifest.json \
  --output "$output" > "$output/summary.json"
status=$?
printf 'inventory exit status: %s\n' "$status"
```

6. Inspect `inventory.json`, `transcript.txt`, and `summary.json`. Confirm the
   host identity, the `host_inventory_status`, the environment fingerprint, and
   the explicit unavailable or unknown observations.
7. Only after reviewing the passive result should the operator consider adding
   `"probe_version": true` for a fixed runtime probe or
   `"probe_policy": {"device_queries": true}` for device tooling. Both are
   opt-in and may load drivers or query device state.

Do not stage or commit the output directory, manifest, host fingerprint,
transcript, or any evidence bundle. Those artifacts belong in the single chosen
external output directory.

## 13. Evidence boundary

A successful local inventory can establish that the collector ran and what it
observed within its bounded scope. It cannot establish that APEX hardware,
drivers, runtimes, model execution, image quality, or a particular capability
were validated. Those require a separately authorized run on the target host
and later qualification tests. Until that happens, APEX verification and
capability qualification remain `unverified`.
