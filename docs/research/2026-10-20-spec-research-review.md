# Local AI Creative Studio: specification and research review

Date: 2026-10-20 (America/Los_Angeles)
Status: Specification-level review and resolution record. Owner follow-up on 2026-10-21 approved O1-B and O2-B; no owner decision remains outstanding from this review. Preview/final acceptance values are intentionally deferred until measured finalist review. No APEX runtime qualification, engine selection, or implementation approval is implied.

## 1. Sources and authority

1. **Product specification:** [GitHub issue #1](https://github.com/danielbyon/media-generation/issues/1), title "Spec: Local AI Creative Studio V1 - Unified Image Workflow and Automated Evaluation". Reviewed body updated at `2026-10-21T06:45:12Z` (October 20 in the project timezone); there were no comments when reviewed.
2. **Attached research:** `local_ai_creative_studio_custom_first_research_2026-10-20.md`, SHA-256 `80505922a4c33ba03668be64e503d8e85946e53a146257ba4ab6b3967c16c82a`. Section/line references below refer to the uploaded document, not a repository copy. The attachment is retained unchanged; this document explicitly amends its recommendations rather than silently replacing its contents.
3. **Repository provenance:** clean `main` at `846e1ab37d9c6f22fd9157526defc8f2fdae3db9`; scaffold, agent configuration, and tracker conventions only. No application implementation, project glossary, or architectural decision records were present. Repository instructions require the `danielbyon` GitHub identity.
4. **Decision precedence:** explicit owner decisions govern scope; issue #1 is the normative product specification; research recommendations are hypotheses. An omitted research-baseline requirement is not silently deleted, and an architectural hypothesis is not silently promoted to an approved choice.
5. **Evidence labels:** the resolutions below are review decisions inferred from those constraints. Statements attributed to upstream are separately cited as [V1]-[V17]. Upstream documentation establishes a documented capability, not success on APEX or arbitrary checkpoint derivatives.
6. **Owner follow-up (2026-10-21):** the owner answered `1. b` and `2. b` to O1 and O2. This explicitly approves inherited scene defaults and choosing preview/final acceptance targets after the first measured finalist comparison. Section 3 records the decisions, their rationale, rejected alternatives, and remaining empirical gates.

## 2. Resolved findings

### R01. Separate the product specification from the first executable slice

**Basis:** issue Solution, 52 User Stories, Implementation Decisions 16 and 21; research sections 4-5.

**Resolution:** issue #1 describes the complete v1 product and its future seams, not a single implementation-sized task. The immediate slice is inventory, a narrow application-owned generation contract, two independently implemented eligible engine adapters, immutable fixtures, execution evidence, recovery tests, and reports. Do not interpret its readiness label as authorization to implement all v1 stories at once. Full v1 acceptance remains separate from harness acceptance.

**Rationale/rejected alternative:** building the UI, autonomous explorer, production distributed queue, and all candidate integrations before proving the contract would turn an evidence-gathering slice into a platform project. The opposite error is calling a successful 48-image experiment a finished v1.

**Check:** acceptance reports name their milestone and explicitly list product stories not yet exercised. A run with fewer than two eligible engine implementations may be useful evidence but does not pass the two-engine comparison deliverable.

### R02. Infrastructure remains provisional; modules are not mandatory microservices

**Basis:** research section 3 proposes FastAPI/PostgreSQL/a central storage host; issue Out of Scope rejects premature product/framework selection.

**Resolution:** these are candidates, not commitments. Start with a modular application/control process and separately supervised inference processes; a logical planning or storage module does not require another deployed service or machine. Central storage means one authoritative owner and may initially be a directory on APEX. Additional workers communicate through the application rather than opening its database or sharing writable source folders.

**Rationale/rejected alternative:** future workers do not by themselves require PostgreSQL, Celery, NFS, or a separate storage appliance. Persistence selection can use transactional, writer-concurrency, recovery, and export requirements; it does not need a GPU performance contest. Avoid speculative interchangeable database/UI/framework adapters. Only inference already has two real implementations demanding an adapter seam.

**Check:** before selecting persistence/queue products, record the chosen requirements, alternatives, and failure-test evidence. A queue library must not become the public generation contract.

### R03. Preserve accepted environment risk without weakening privacy

**Basis:** issue Implementation Decision 20 and Out of Scope; research sections 3, 4, and R2.

**Resolution:** using shared experimental dependencies remains allowed. Mandatory environment snapshots, rollback gates, and dependency containers are not reintroduced. Runtime egress confinement remains mandatory and can be enforced independently of dependency isolation. Inventory is read-only; installation, firewall changes, model loading, and destructive failure injection are later explicit stages, not disguised inventory probes.

**Check:** capture environment fingerprints before and after changes. If no enforcement is already present, inventory reports privacy as unverified rather than claiming to have tested it. Do not modify the owner's machine-wide network policy or terminate unrelated workloads merely to run an experiment.

### R04. Normalize terminology and immutable identity snapshots

**Basis:** research Core entities differs from issue Implementation Decision 5 and omits stable Scene identity and reference membership.

**Resolution:** use issue terminology. `GenerationRequest` is immutable intent; `GenerationJob` is durable orchestration; `GenerationAttempt` is one execution attempt (research `GenerationRun`). `ReferenceArtifact` is an artifact role, not a competing content identity. `ModelVariant` identifies model lineage; immutable model artifacts identify exact bytes; a versioned `ModelPreset`/resolved recipe identifies execution choices. No particular table layout is mandated.

A `CharacterRevision` freezes ordered reference membership, each reference's role/crop/preprocessing, canonical attributes, and lock policy. `Scene` has stable identity and `SceneRevision` contains a snapshot. Requests reference explicit revisions, never a moving "latest" pointer. Concurrent edits create revisions or conflicts, not lost updates.

**Check:** changing a character's references, a preset, or a scene while a job is queued cannot change that job. Scene hierarchy uses inherited structured defaults with explicit child overrides, as approved in O1 below; artifact derivation is not a substitute for scene hierarchy.

### R05. Exact prompts, identity locks, and human authority have distinct meanings

**Basis:** issue stories 6-7, 12-14, 33; research invariants 1 and evaluation guidance.

**Resolution:** identity locks constrain intended attributes; they are not a promise that a generative model will preserve pixels or every feature. An exact prompt override replaces the model-facing prompt field without silent AI polishing and without changing the scene/profile. Preserve required backend templates and all other submitted prompt fields separately so "exact" is inspectable. Structured edits or lock relaxation require explicit versioned intent.

Detectable structured conflicts require correction or explicit relaxation; uncertain semantic conflicts may be flagged, not falsely declared impossible by a VLM. Generated identity failures are advisory assessments and must remain inspectable and overridable, not silently deleted. The outfit-change fixture explicitly unlocks outfit while preserving its declared identity traits.

**Check:** overriding prompt text cannot mutate a profile; editing a structured field cannot silently alter an old job; a judge disagreement cannot destroy an output.

### R06. Preserve operation semantics and reference roles

**Basis:** issue Implementation Decisions 8 and 10; research GenerationRequest/source_artifacts.

**Resolution:** distinguish generation from canonical references, editing an existing result, and preview-to-final derivation. Preserve ordered inputs and roles such as identity reference, edit source, composition reference, or optional mask. Persist both actual conditioning edges and a branch's creative origin; a regeneration can originate from a selected image without conditioning on its pixels. Preview/final are separate requests/artifacts; cross-model final generation does not promise preservation of preview composition.

**Check:** the gallery can explain what influenced the pixels versus what merely inspired the branch. Masked editing, independent multi-character identity binding, and timelines are not silently added as acceptance requirements beyond the approved scope.

### R07. Capability discovery is exact and fail-closed

**Basis:** issue stories 18-22, 39 and testing 2; research sections 2-3.

**Resolution:** capability belongs to `(engine build, pipeline/recipe, exact model bundle, worker environment)`, not merely a model filename or family. Record advertised versus smoke-tested support, maximum reference count/order, dimensions/aspect constraints, conditioning modes, supported parameters, quantization/offload requirements, cancellation behavior, and available telemetry. Unsupported required inputs yield explicit errors. Optional degradation requires prior user/manifest permission and a recorded resolution.

**Check:** never discard an extra reference, ignore a negative prompt, downgrade an edit into text-to-image, or silently substitute a model. One-reference support does not qualify multi-reference workflows.

### R08. Pin complete model bundles and architecture-specific recipes

**Basis:** research candidate table, Suggested first model families, provenance invariant; issue decisions 16-17.

**Verified correction:** stable-diffusion.cpp documents that Qwen Image Edit 2511 requires `--model-args qwen_image_zero_cond_t=true`; omission can materially degrade editing [V1]. Its Klein documentation separates distilled and base variants and uses different step/guidance recipes [V2]. The Qwen and FLUX model cards identify their distinct Diffusers pipelines [V3,V4].

**Resolution:** a manifest includes transformer, VAE, tokenizer/processor, text/vision encoders, projectors, adapters with order/strength, conversion provenance, quantization per component, source revisions, and required architecture switches. Do not confuse the separate Qwen3-VL planning candidate with Qwen Image Edit's required encoder. Pin preprocessing, templates, graph/node versions, and actual backend defaults as well.

**Check:** reference conditioning is verified, not just model loading. Research S3 is the Qwen-specific recipe, not a FLUX citation. Verify recipes against the pinned executable; do not force a current flag onto an incompatible older build.

### R09. Freeze execution intent before expensive work

**Basis:** issue generation contract/provenance; research invariant 5.

**Resolution:** persist validated intent and resolve a versioned execution plan before dispatch. The plan contains output slots, per-slot seeds, selected model/preset versions, effective parameters, exact prompts, input transformations, and expected capabilities. Capture the actual executable payload and runtime fingerprint at execution; reject unexplained drift. A stochastic rerun creates a new logical request. Explicitly permitted compatible worker failover is another attempt, not an unrecorded recipe change.

**Check:** a server restart or a changed default sampler cannot silently change a queued request. A "reproduce" operation reports missing weights/incompatible environments rather than substituting them or promising cross-device pixel equality.

### R10. Idempotency means one publication per logical output, not exactly-once GPU execution

**Basis:** issue decision 9; research invariants 3-4.

**Resolution:** bind an idempotency key to a canonical request digest. Same key/same request returns the existing job; same key/different request is a conflict. Track attempts independently and enforce one published artifact per logical output slot with transactional uniqueness/fencing. A batch can succeed partially; successful slots are not regenerated when only failed slots are retried.

**Rationale/rejected alternative:** transport retries, process crashes, and uncertain remote submission may cause duplicate computation. Neither "exactly once" execution nor a queue task ID alone prevents duplicate published artifacts. Celery's acknowledgement/worker-loss behavior requires explicit configuration and testing [V5].

**Check:** inject duplicate delivery, lost acknowledgements, restart after publication, and two attempts racing to publish one slot.

### R11. Make crash recovery, dispatch uncertainty, and cancellation explicit

**Basis:** research Durable scheduler; issue failures/cancellation/retry stories.

**Resolution:** use durable job transitions, attempt identities, heartbeats/leases, and fencing of stale result commits. If database and queue writes are separate, provide an outbox or equivalent reconciled dispatch protocol. Unknown submission status is reconciled before blind resubmission. Cancellation distinguishes requested, acknowledged, and too-late/already-completed; acceptance of cancellation and publication must be serialized.

A lost heartbeat does not prove GPU work stopped. Do not release a physical device for another local job until termination is confirmed or the worker is quarantined. An adapter that can only globally interrupt its server must use a dedicated supervised instance or report that limitation; it must not cancel unrelated owner jobs.

**Check:** network partition, stale worker result, queued cancellation, running cancellation, cancellation/finalization races, and application/engine restart. Procrastinate documents stalled-job recovery separately and currently asks for additional maintainers; evaluate it rather than assuming an operational winner [V6,V7].

### R12. Schedule all competing inference, not only diffusion

**Basis:** research local LLM/VLM, scoring, worker reservations; issue multiple-worker requirements.

**Resolution:** admission control covers planning, reference analysis, generation, scoring, model loading, and eventual training. Begin with one heavyweight inference lease per measured resource domain. Record CPU RAM, shared/discrete GPU memory topology, model residency, scratch space, context/reference sizes, and offload buffers; do not count shared APU memory twice. Cache residency and switching cost belong in the plan.

**Check:** profile generation plus resident planner/scorer, large references, model switches, and memory-pressure failure. Observed APEX inventory, not a retail device name or generic ROCm support statement, determines the qualified path. AMD's documentation is version-scoped [V8]. Future worker routing must not assume identical acceleration. Resource preemption/resuming a diffusion step is not promised by a cancel API.

### R13. Define the file/database commit protocol

**Basis:** research invariant 3; issue Storage.

**Resolution:** worker scratch is not authoritative storage. Ingest into a unique temporary file on the destination filesystem; validate byte count, digest, format, and dimensions; flush file contents; publish without overwriting another artifact; sync affected directory entries; then commit published metadata, output-slot ownership, lineage, and job transition under fencing. Handle each crash window through reconciliation. Do not claim filesystem rename and database commit are one atomic transaction.

**Evidence:** file `fsync` does not by itself persist directory entries, and rename has filesystem constraints [V9,V10].

**Check:** crashes before/after rename and database commit, truncated transfer, ENOSPC, duplicate ingest, and hash mismatch. Readers must not see staged or incomplete artifacts as published.

### R14. Separate artifact identity from blob identity

**Basis:** research hash/path invariant and DAG; issue Artifact/Derivation.

**Resolution:** an artifact is a logical result with its own provenance; a blob is immutable file content identified by digest. Different generations may legitimately produce identical bytes and share a blob without sharing artifact identity. Edges connect logical artifacts and preserve roles; they are added with publication and cannot create cycles.

**Rationale/rejected alternative:** using the content hash as the artifact/node ID can collapse two generations, lose lineage, or create a self-edge when an edit returns unchanged pixels.

**Check:** import the same file twice, return an unchanged image from an edit, and publish identical bytes from independent jobs. Provenance remains distinct and the DAG remains valid.

### R15. Bound filesystem and executable input authority

**Basis:** research local-filesystem/private-LAN-only API; issue immutable references/privacy.

**Resolution:** public requests use artifact IDs and approved upload/import paths, not arbitrary worker paths or URLs. Validate content rather than trusting MIME/extension; limit decoded dimensions and file size; normalize orientation/color for model input while preserving original bytes and recording derived transforms. Reject path traversal, symlink escape, archive escape, unexpected active content, and remote image URLs. Adapters may not introduce unchecked shell interpolation or arbitrary graph/plugin code from prompts.

**Check:** malformed images, huge decode dimensions, traversal names, executable metadata/HTML report injection, and reference URL attempts. Models and custom nodes are supply-chain inputs; a hash records identity, not trust. Remote-code requirements require explicit review in the update workflow, not automatic runtime execution.

### R16. Make the privacy gate stronger and actually testable

**Basis:** research privacy metric counts all outbound attempts; issue testing 6 only mentions content-bearing attempts.

**Resolution:** app-controlled inference processes deny all non-allowlisted network destinations, not only recognizable content transfers. Allow exact required private endpoints, not all private IP space or a LAN proxy that can relay to the internet. Include IPv4/IPv6, DNS, redirects, proxy settings, browser assets, telemetry, model APIs, extensions, logs, and crash reporters. The updater has external access but no access to project content or runtime credentials; runtime has no updater/cloud tokens. No cloud fallback.

Use attributable socket-attempt/firewall evidence and application/browser tests. Deliberate negative-test probes must be observed and denied; unexpected runtime attempts fail qualification even when blocked. Packet payload scanning cannot prove that encrypted/encoded content was never transmitted. Missing observability means unverified, not pass.

Ollama has explicit cloud-disable configuration [V11]; Hugging Face offline and telemetry controls are distinct [V12]. Configure them as defense in depth, not as a substitute for enforcement. Cold process/model loading after an explicit prefetch must also pass offline.

### R17. LAN access still needs application security

**Basis:** research Security; issue MacBook access and v3 multi-user exclusions.

**Resolution:** single-owner authentication is compatible with accounts/teams being out of scope. Protect artifact reads, job mutation, exports, backend administration, and worker ingest. Use restricted origins/CSRF controls and protected LAN transport; keep model backends behind the application. A prompt/reference is untrusted data, not permission to run tools or contact endpoints. Do not enable generic LLM shell, file, web-search, tunnel, or MCP tools as part of scene planning.

**Check:** unauthenticated LAN requests, hostile browser origins, worker spoofing, prompt-supplied URLs/tools, and unauthorized artifact lookup. This is an application threat model, not a promise to defend against a malicious local administrator or compromised user browser.

### R18. Ordinary files require lifecycle and export rules

**Basis:** issue stories 30-35 and testing 11; research immutable files.

**Resolution:** published originals are append-only from the application's perspective. Unexpected external deletion/modification is recorded as missing/corrupt, never silently accepted as a new input. Export uses versioned manifests, stable IDs, relative content paths, hashes, revisions, lineage, and provenance; absolute host paths and secrets are not portable identifiers. Check restore consistency across database and files.

Curation rejection is not deletion. Do not introduce automatic destructive retention. Reconcile and garbage-collect abandoned staging data only after checking active attempts; preserve published content unless the owner explicitly deletes it. Stop cleanly when storage admission fails. For large benchmarks, cache keys include fixtures, recipes, environment, evaluators, and protocol versions, not just prompt/seed.

**Check:** offline export/reimport, moved storage root, cross-project shared character, shared blob references, corrupt/missing files, and interrupted backup.

### R19. Bound autonomous work in durable state

**Basis:** issue bounded autonomous modes; research run-stage caching.

**Resolution:** selective execution remains default. Autonomous launches require an explicit run budget: total submissions including retries, branch depth/breadth, deadline, concurrent inference, storage allowance, and stopping conditions. Schema-repair loops, model fallbacks, evaluations, and repeated low-quality retries consume that budget. Resume preserves spent budget and cancellation. No implicit fresh budget on restart.

**Check:** an uncooperative planner, repeated invalid JSON, repeated refusal/technical failure, low-score loops, and process restarts cannot run forever. Scoring may propose the next branch but cannot expand scope or destroy history. These launch parameters need not be arbitrarily hard-coded as the owner's permanent preferences.

### R20. Treat the 24 cases as a screening matrix, not full qualification

**Basis:** research sections 4-5; issue first executable deliverable.

**Resolution:** retain 3 styles x 4 scene changes x 2 seeds = 24 cases per exact configuration. Two configurations yield 48 scheduled cases only when each case produces one output; smoke tests, calibration, repetitions, retries, and additional configurations are separate counts. Record failures and unsupported cases rather than shrinking the denominator.

Add separately identified capability/conformance tests for one versus multiple references, canonical-reference regeneration versus source-image editing, reference-order preservation, chained-edit identity drift, and a large composition change. Full v1 later exercises analysis/planning, selective queueing, preview/final, branch/gallery, provenance, export, and restart. A non-refusing model that ignores the task is not behaviorally qualified.

**Check:** the report distinguishes API support, completed execution, useful output, recovery/privacy gates, and overall product qualification. Do not force an unsupported candidate into a fake comparable test.

### R21. Avoid model/engine confounding and unbounded candidate search

**Basis:** issue engine neutrality and comparisons; research first model shortlist.

**Resolution:** an engine comparison holds the model lineage and comparable recipe fixed. If weights, quantization, encoders, precision, or preprocessing differ, label it a configuration comparison and disclose the confound. Match high-level task intent where numeric settings have different meanings. Tuned finalist results form a separate track and cannot be mixed into the controlled track.

Screen all shortlisted engines through bounded capability inspection, then implement/execute two eligible independent engine paths. Existing installation affects discovery effort, not quality ranking. Refresh candidate availability during the explicit acquisition stage, but freeze the run manifest; no endless search for the newest family. A base model is an integration baseline, not evidence that a desired tuned derivative qualifies.

**Check:** publish all configuration identities and exclusions. Never conclude that engine A is superior from A/model-X versus B/model-Y without qualification.

### R22. Fix benchmark measurement design

**Basis:** research efficiency/p50/p95 metrics; issue testing 7-8.

**Resolution:** separate process cold start, model cold load, warm inference, queue wait, planning, preprocessing, transfer, decoding, ingest, scoring, and end-to-end wall time. Record cache state, reference count/resolution, output size, acceleration, power policy, thermals, background load, and telemetry overhead. Randomize/block configuration order where feasible; do not warm one candidate and cold-start another.

Two seeds per heterogeneous case do not establish stable tail latency or a statistical quality winner. Use a separately budgeted repeated fixed-workload performance protocol. Report sample counts, raw distributions, variability, and uncertainty; any observed p95 is descriptive of that run, not a production guarantee. Missing energy/GPU counters are `unavailable`, not zero. Instrumentation-heavy traces are a separately labeled run when they materially affect timing.

### R23. Prevent evaluator circularity and false confidence

**Basis:** research DINOv2/VLM measures; issue human authority.

**Resolution:** freeze reference fixtures independently of the candidate being scored. Distinguish manual character truth from VLM-suggested traits; deliberately vary unlocked outfit/background/pose while retaining locked identity. Include identity-negative controls, face-occluded/full-body examples, and per-style reporting so a face-only metric cannot conceal failures. DINOv2 provides general visual features, not a validated character-identity oracle [V13].

Calibrate on a small blinded stratified sample with disagreements and representative/random cases, not only hand-picked finalists. A VLM's self-reported confidence is not a calibrated probability. Preserve missing/refused/truncated judgments; enforce schema AND semantic/domain validation. Structured-output APIs help parse results but do not establish correctness [V14,V15]. If the planner is also the judge, disclose correlated error and use independent checks/human calibration. Keep a held-out set when adaptive search optimizes judge scores.

**Check:** evaluator refusal is not automatically generator failure, and a successful similarity score is not sufficient evidence of identity preservation.

### R24. Operationalize the scorecard without fabricating thresholds

**Basis:** research agreed weights and gates; issue decisions 18-19.

**Resolution:** preserve 40% fidelity, 25% flexibility, 20% efficiency, 15% creative intelligence for end-to-end configurations only. Freeze named rubrics and normalization before ranked runs; keep task coverage/failure rates visible; report style-specific results and uncertainty. Score components separately until an end-to-end workflow exists. Do not min-max normalize against whichever candidates happened to run or add hidden weights for adherence/quality; publish how those observations inform the agreed dimensions and acceptance gates.

Use a Pareto view when quality/latency trade-offs are not distinguishable or acceptance preferences remain unset. Weighted ranking is not an acceptance criterion. Do not automatically waive failed privacy/durability/required-capability gates because a total score is high. Under approved O2-B, the owner chooses the preview/final acceptance envelope after the first measured finalist comparison; benchmark settings remain labeled test conditions until that selection.

### R25. Preserve scope and licensing decisions

**Basis:** issue Content suitability, Licensing, Version boundaries; research baseline.

**Resolution:** private image-first use, approved reference types, optional later training, v2 video/audio, and potential v3 commercialization remain unchanged. No mandatory character-rights database, commercialization gate in technical scores, or new public SaaS/multi-tenant work is introduced. Record licenses/usage notes per software component AND exact checkpoint/adapter/evaluator artifact, including unknown provenance; documenting an unknown does not establish permission. Preserve lawful-use and consent constraints without claiming private use overrides terms.

Video extensibility is a constraint on identifiers/provenance and job kinds, not a claim that video is merely an image with another MIME type. Future clips may need timed inputs, multiple outputs, audio, and frame provenance. Do not implement those structures or training UI in the first slice.

### R26. Separate documented upstream facts from qualified local evidence

**Basis:** research source assertions, verdict, and unresolved factual questions.

**Resolution:** preserve the candidate status of stable-diffusion.cpp, Diffusers, InvokeAI, ComfyUI, llama.cpp, Ollama, Procrastinate, Celery, and local evaluators. InvokeAI's saved workflow versus executable graph distinction is supported upstream [V16]. llama.cpp documents schema-constrained output and experimental multimodal support [V15,V17]. None of these facts chooses a winner or proves the exact desired derivative is supported.

Qualification captures source commit/release, retrieval date, installed build, full weight hashes, and actual result. Moving `main`/`master` documentation is discovery evidence only. Record changing documentation or stale example paths as such; do not silently substitute a newer model and imply continuity with an older benchmark. Source-backed desk research is sufficient to start controlled validation, not sufficient to close all architectural risks.

## 3. Owner decisions resolved on 2026-10-21

The owner selected B for both questions. These approvals supersede the pending O1/O2 wording in the original review addendum on issue #1. No further owner clarification is required by this review; empirical qualification remains outstanding as listed in section 4.

### O1. Inherited scene defaults - approved B

**Source and previous ambiguity:** research section 1 explicitly includes "hierarchical scenes" (line 12). The original issue body included scenes/themes and artifact branches without deciding whether nested scenes were organizational only or inherited structured defaults.

**Decision:** child scenes inherit structured defaults from their parent and apply explicit child overrides. Before generation is queued, resolve the effective scene and capture its complete structured intent and contributing revision identities in an immutable snapshot. Preserve the distinction between authored overrides, inherited values, and the effective scene. Existing exact prompt overrides remain separate from structured scene revisions.

**Rationale:** shared scene settings can be defined once while child scenes explore targeted differences, such as activity or camera, without duplicating the location and lighting. This supports the approved exploration workflow.

**Rejected alternative:** A, organizational grouping only with independent complete child specifications. It does not provide the selected inheritance behavior and requires repeated shared settings.

**Invariants and failure modes:** changing a parent cannot rewrite a recorded scene revision, queued request, retry, or historical result. A later generation using updated defaults records new effective intent rather than rewriting old intent. Child overrides do not bypass character locks or explicit revision requirements. Scene hierarchy remains distinct from the artifact derivation DAG and future video timelines. Cyclic hierarchy or an unresolved contributing revision must produce an explicit validation error rather than partial intent.

**Acceptance checks:** a child inherits parent location/lighting while overriding camera; the effective values and their revision provenance are inspectable. A subsequent parent change leaves the already queued request unchanged. A new generation from updated scene intent records its new snapshot. Prompt overrides do not mutate the hierarchy or scene revisions.

**Impact:** the scene-hierarchy product decision is resolved. It does not add scene UI to the first inventory/two-engine harness slice or select a storage implementation.

### O2. Measure first, then choose preview/final targets - approved B

**Source and previous ambiguity:** the issue requests quick previews/final quality and weighted efficiency; research proposes latency metrics. Neither supplied approved dimensions/aspects, wait limits, or a minimum visual acceptance level.

**Decision:** run explicit, labeled benchmark profiles first. After the first measured finalist comparison, the owner selects the useful preview/final dimensions, aspect ratios, acceptable end-to-end latency, and visual quality trade-offs from the timings and contact sheets. Record the selected envelope and the evidence supporting it when that later decision is made.

**Rationale:** measured quality-versus-latency trade-offs on APEX provide the basis for useful targets, while limiting manual participation to the consequential finalist decision. There is no APEX benchmark evidence in this review from which to infer realistic targets.

**Rejected alternative:** A, fixing product limits before measurements. No arbitrary seconds, resolution, aspect ratio, or fidelity cutoff is approved by this choice.

**Invariants and failure modes:** benchmark resolutions and budgets are test conditions, not approved product targets. Weighted ranking or a VLM score cannot supply the owner's visual acceptance decision. Privacy, durability, and required-capability gates remain mandatory; choosing quality/performance targets later does not waive them. Do not claim final backend/preset qualification or a production latency SLO before the measured evidence and the owner's envelope selection exist.

**Acceptance checks:** reports separate test profiles from accepted product presets, show measured quality/latency and uncertainty, and retain failed gates. The eventual acceptance record identifies the selected preview/final targets and supporting evaluation run(s), rather than silently relabeling the fastest configuration as qualified.

**Impact:** the timing/process decision is resolved and evidence collection is unblocked. The actual envelope values remain an intentional post-benchmark acceptance step, not an unanswered design-interview question.

## 4. Empirical work still required, not questions for the owner to debug

| Evidence gap | Required automated evidence | Consequence until available |
|---|---|---|
| APEX environment and exact artifact availability | Read-only inventory of OS/kernel/driver, acceleration, memory topology, binaries, model bundles and hashes | No assertion that an advertised upstream feature works locally |
| Exact derivative and pipeline compatibility | Load, conditioned one/multi-reference smoke tests, explicit effective recipe | Candidate, not supported/qualified |
| Quality versus quantization and speed | Controlled configuration track, separately tuned finalists, chained-edit tests and fixed-workload timing | No engine winner or performance guarantee |
| Local planning and judging | Schema/semantic validation, bounded failures, blinded calibration, per-style error analysis | Advisory judgments with uncalibrated confidence |
| Queue/cancel/durability | Duplicate delivery, lost response, partition, stale result, crash-window, batch partial failure, disk-full tests | No exactly-once publication or recoverability claim |
| Privacy | Full cold-to-warm local workflow under enforced allowlists, attributable attempts, browser checks, negative controls | Gate unverified, never inferred from localhost configuration |

These are bounded validation tasks to automate. They are not requests for the owner to hand-write fixtures, gather logs, tune candidates repeatedly, or debug environments manually.

## 5. Verification limits

This review read the live issue, issue comments, attached research, repository scaffold/instructions, and the primary sources below. It did not SSH into APEX, install models, run inference, mutate firewall policy, test GPU recovery, or measure quality/performance. There are no fabricated scores. The original research attachment remains unchanged. This review is an explicit amendment and rationale record; runtime changes and benchmark execution are outside this review task.

## 6. Primary-source verification references

All checked during this review. Mutable documentation must be pinned again when creating an executable run manifest.

- [V1] stable-diffusion.cpp Qwen Image Edit recipe: https://raw.githubusercontent.com/leejet/stable-diffusion.cpp/master/docs/qwen_image_edit.md
- [V2] stable-diffusion.cpp FLUX.2/Klein recipes: https://raw.githubusercontent.com/leejet/stable-diffusion.cpp/master/docs/flux2.md
- [V3] Qwen Image Edit 2511 model card: https://huggingface.co/Qwen/Qwen-Image-Edit-2511
- [V4] FLUX.2 Klein 4B model card: https://huggingface.co/black-forest-labs/FLUX.2-klein-4B
- [V5] Celery task acknowledgement, idempotency, and worker-loss semantics: https://docs.celeryq.dev/en/stable/userguide/tasks.html
- [V6] Procrastinate overview and maintenance notice: https://procrastinate.readthedocs.io/en/stable/
- [V7] Procrastinate stalled-job recovery: https://procrastinate.readthedocs.io/en/stable/howto/production/retry_stalled_jobs.html
- [V8] AMD version-scoped Radeon/Ryzen ROCm documentation: https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/
- [V9] Linux fsync manual: https://man7.org/linux/man-pages/man2/fsync.2.html
- [V10] Linux rename manual: https://man7.org/linux/man-pages/man2/rename.2.html
- [V11] Ollama local-only/cloud-disable and proxy configuration: https://docs.ollama.com/faq
- [V12] Hugging Face offline/telemetry environment variables: https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables
- [V13] DINOv2 upstream features and models: https://github.com/facebookresearch/dinov2
- [V14] Ollama structured output: https://docs.ollama.com/capabilities/structured-outputs
- [V15] llama.cpp server capabilities: https://raw.githubusercontent.com/ggml-org/llama.cpp/master/tools/server/README.md
- [V16] InvokeAI executable graph/workflow API: https://invoke-ai.github.io/InvokeAI-7/development/guides/workflow-api/
- [V17] llama.cpp multimodal input and projector configuration: https://github.com/ggml-org/llama.cpp/blob/master/docs/multimodal.md
