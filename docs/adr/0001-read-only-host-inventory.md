# ADR 0001: Use a bounded, read-only host inventory

## Status

Accepted.

## Context

The project needs repeatable facts about a host before it can prepare
capability-aware model candidates or run qualification benchmarks. Earlier
descriptions of the target host mixed installed tools, model availability, and
memory totals with assumptions. Those assumptions can cause a workflow to select
an engine or model that was never installed, to treat shared GPU memory as extra
RAM, or to present a written report as hardware validation.

The inventory must be safe to run on a working host. It must not install
software, load model weights, run inference, contact external services, scan the
whole filesystem, or change device state. It also must be useful when access is
incomplete: a missing observation has to remain visible instead of becoming an
invented value or a silent absence.

## Decision

1. The inventory is a Python standard-library command with schema-versioned JSON
   and a bounded transcript. It writes only to one explicitly requested output
   directory, through exclusive same-directory temporary files that are
   atomically replaced, so a pre-existing link cannot redirect the write.
2. Discovery is bounded to explicit declarations, `PATH`, fixed cataloged
   locations, active Python distribution metadata, fixed runtime markers and
   version files, fixed Git metadata, Linux DRM/sysfs, and approved model paths.
   It does not recursively search arbitrary directories.
3. Every attempted, skipped, blocked, timed-out, malformed, or inaccessible
   observation has a structured status and reason. An empty declaration is
   `not_configured` or `not_inspected`, never `absent`.
4. Runtime and device execution is opt-in. Version and help commands come from
   the built-in catalog with timeouts and output caps. Device commands require
   `probe_policy.device_queries: true`.
5. Model headers are parsed by default within fixed byte, entry, and nesting
   limits. Approved sidecar JSON is byte-capped but parsed with the standard
   library, so it has no separate nesting or allocation bound. Tensor data is
   not loaded. Model-root
   reads and directory listings re-check containment at open time. Full content
   hashing is opt-in, streaming, and bounded at read time: a file that grows,
   changes metadata, or is replaced aborts without publishing a digest, and only
   regular files are accepted. Mutation detection is best-effort rather than an
   immutable snapshot. GGUF quantization labels come from the header's llama.cpp file-type
   enum; unknown values remain unclassified with the raw enum retained, and
   filenames are never used to infer quantization.
6. Memory is reported as separate observed pools with explicit sharing
   relationships. System RAM, dedicated VRAM, GTT, carve-outs, and aliases are
   not added into one allocatable pool. Unknown topology stays unknown.
7. Environment fingerprints cover stable host, accelerator, runtime, and Python
   identities. They exclude timestamps, run duration, probe order, hostnames,
   output and manifest paths, environment variables, and transient memory use.
   Runtime executable paths are included as part of executable identity.
8. Report writing, host-inventory completeness, APEX verification, and
   capability qualification are separate outcomes. A `blocked` or `partial`
   inventory can still have a written report and a nonzero automation status.

## Consequences

- Operators get an inspectable record of what was actually observed, including
  what could not be learned.
- A report from a development host is not APEX evidence. Live APEX verification
  remains unverified until a separately authorized run happens on the target.
- Some installed software will be missed if it is outside the catalog, outside
  the bounded search locations, or not represented in active Python metadata.
  The report exposes that search scope rather than claiming a global absence.
- Model header inspection gives useful metadata without reading the full file,
  but it can only report what the format and bounded parser expose. Malformed or
  truncated inputs remain unknown.
- A version probe or device query can have side effects even though the
  collector itself does not install or generate. Keeping both opt-in makes the
  default run conservative.

## Rejected alternatives

- **PATH-only discovery.** It misses Python-environment installations and
  directory-based engines such as ComfyUI. The catalog and bounded known-location
  search cover those cases without a general filesystem walk.
- **Automatic recursive scanning of model roots.** It is unbounded, can expose
  unrelated private files, and makes the cost of a run unpredictable. Components
  are inspected only when declared.
- **Automatic `rocm-smi`, `nvidia-smi`, or `hipconfig`.** Those commands can
  query or initialize device state. They require explicit opt-in.
- **Treating empty manifests as evidence of absence.** No roots or bundles were
  inspected. The report records `not_configured` and leaves model absence
  unknown.
- **Adding all reported GPU memory to system memory.** Shared apertures and
  carve-outs are views of memory already represented. Summing them double-counts
  unified memory and misstates allocatable capacity. PCI display class is not
  treated as evidence that a pool is dedicated.
- **Following symlinks below a declared model root.** An intermediate link can
  redirect a read outside the declared tree. The root itself may be a symlink,
  but entries below it must be real directories and files must be opened with
  O_NOFOLLOW.
- **Hashing every weight file by default.** Full hashing is expensive and can
  read terabytes. It is opt-in, per component, bounded, and streamed.
- **Fetching manifest source URLs.** URLs are provenance and attribution only.
  A declaration must never cause network traffic.
- **Putting APEX verification in the report-writing success field.** A written
  JSON file is not a passed hardware gate. The evidence gate states that APEX
  verification and capability qualification remain unverified.
