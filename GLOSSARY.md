# Local AI Creative Studio

Language for character-centered image creation, structured scenes, generation, and evaluation. Product decisions live in GitHub issue #1 and its review addenda; the rationale for the resolved scene and acceptance terms is in `docs/research/2026-10-20-spec-research-review.md`, section 3.

## Language

**Scene**:
A persistent unit of structured creative intent, including character, activity, location, camera, lighting, and mood. A scene can inherit defaults from a parent scene and supply explicit overrides.
_Avoid_: prompt, artifact, video shot as substitutes for a scene.

**Scene hierarchy**:
The parent-child relationship through which scenes inherit structured defaults. It is distinct from the artifact derivation DAG and from future video timelines.
_Avoid_: folder tree, artifact lineage as substitutes for scene inheritance.

**SceneRevision**:
An immutable version of a scene's structured intent with explicit revision provenance. Later edits create new intent rather than changing a recorded revision.
_Avoid_: latest scene as the identity of a historical revision.

**Scene override**:
An explicit child-scene value that replaces an inherited structured default for that scene. It is distinct from a free-text prompt override.
_Avoid_: prompt override as a synonym.

**Effective scene**:
The complete structured intent resolved from inherited defaults and explicit child overrides for a particular generation. Its recorded snapshot preserves the values and contributing revision identities used by that generation.
_Avoid_: current parent values as a substitute for a historical effective scene.

**ModelVariant**:
An explicitly selected identity for an exact model/component bundle and its provenance, distinct from its model family or stock release. Different weight hashes can be valid variants of the same family; a variant's own approved pins determine its integrity.
_Avoid_: stock model, model family, publisher release hash as substitutes for selected variant identity.

**Benchmark profile**:
Explicit, versioned test conditions used to collect comparable execution and quality evidence. A benchmark profile is not an owner-approved product target.
_Avoid_: accepted preset, product SLO as synonyms.

**Preview/final acceptance envelope**:
The owner's selected useful dimensions/aspects, acceptable end-to-end latency, and visual quality trade-offs for preview and final output. Under the approved measurement-first process, its values are selected after measured finalist review.
_Avoid_: weighted score, fastest configuration as substitutes for acceptance.

**Generation batch**:
An immutable ordered collection of generation requests coordinated in one SQLite database. Each request runs through the existing single-output `GenerationService` and keeps that service's admission, execution, resource, and publication records.
_Avoid_: job queue, distributed scheduler, or multi-output GenerationJob as substitutes.

**Batch slot**:
A durable identity for one request in a generation batch. It pins the request, ordinal, idempotency key, attempt budget, and applicable admission evidence to the matching T04 GenerationJob.
_Avoid_: output filename as a substitute for slot identity.

**Batch coordinator claim**:
An owner and fencing epoch that permit one coordinator to update a batch at a time. Claim expiry permits another coordinator to take over; the GenerationJob's resource and attempt evidence still determine whether execution can continue.
_Avoid_: proof of process termination or service-attempt completion.

**Publication state**:
The T04 journal's recorded progress toward committing an artifact and its lineage in SQLite.
_Avoid_: adapter success or the presence of a file as proof of committed publication.

**Artifact integrity**:
A read-time check that current artifact bytes and their publication location match immutable metadata. Batch reports run this check without storing an integrity observation.
_Avoid_: execution status or historical success as a current file check.
