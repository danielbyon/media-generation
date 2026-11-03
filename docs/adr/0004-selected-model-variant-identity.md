# ADR 0004: Qualify explicitly selected model variants, not stock-release hashes

## Status

Accepted on 2026-11-03 (owner decision).

## Context

The APEX contains specific Hugging Face downloads of uncensored/unlocked open-source model variants, not necessarily the original stock releases. Variants can share a model family, architecture, or familiar filename while containing different weights. The earlier T09 Qwen candidate checks used hashes that matched Comfy-Org's published artifacts. Those matches establish the identity of **those three files**; they are not evidence that every installed or intended APEX variant must match the stock artifact.

A stock-release hash allowlist would wrongly reject a deliberately selected third-party variant. Conversely, accepting an arbitrary changed hash would defeat T07's independently pinned candidate integrity, reproducibility, and provenance guarantees. We need to distinguish **eligibility of a variant** from **integrity of an approved candidate**.

## Decision

1. **The explicitly selected ModelVariant is authoritative for model choice.** A candidate identifies the exact selected engine/build, recipe, model-component bytes, precision/quantization, architecture flags, component roles, and host/worker context. The operator may select an unlocked/uncensored Hugging Face variant where technically compatible and lawful. No preference or eligibility rule requires its hash to equal an official/base/stock checkpoint.
2. **Pin the selected bytes, not a stock baseline.** Record the selected variant's local canonical path, full size and SHA-256, and, where supported by evidence, the Hugging Face repository, immutable revision, file path, publisher, license, and conversion lineage. A publisher's official hash may be retained for comparison but is not the candidate's expected hash unless those exact official bytes were selected.
3. **Keep T07 fail-closed integrity and independent trust.** The expected hash in an approved T07 declaration is binding. If the selected local bytes differ from that declared/approved hash, the *current candidate* is corrupt or mismatched and cannot proceed. An intentional variant switch requires a new or amended declaration, new candidate identity, independently reviewed expected pins/evidence, and renewed applicable qualification; never silently rewrite a pin, accept arbitrary bytes, or self-approve. Missing provenance, license, conversion, or independently trusted authority remains unverified under ADR 0002; technical incompatibility remains incompatible.
4. **Never substitute silently.** An unavailable, failed, or unapproved selected variant does not permit automatic fallback to a stock release, another quantization, a different checkpoint, or another engine. Report the specific blocked, unverified, or unsupported condition. Preserve installed variants; do not overwrite, rename, delete, duplicate, or redownload them without explicit owner authorization.
5. **Separate names from observed capabilities.** An "uncensored"/"unlocked" label or a different hash does not itself prove behavior, safety, compatibility, licensing, or provenance. T17 must test the exact selected variant with lawful fictional-adult scenarios and authorized references; record refusal, unsupported operation, runtime failure, and output quality separately. Preserve applicable legal, consent, license, privacy, and resource-admission constraints.
6. **Preserve identity across the lifecycle.** Inventory (T02), candidate preparation (T07), real inference adapters (T08/T09), behavior screening (T17), model selection and preset versions (T34), and later evaluation/reproduction must distinguish model family, selected variant, candidate identity, and observed worker configuration. Capture exact resolved weights and settings in job provenance. Changing a variant cannot retroactively inherit earlier execution evidence, qualification, or owner acceptance.
7. **Applies beyond Qwen.** This is an engine- and modality-neutral decision for image and local text/vision models and future video/audio adapters. It does not relax T05 local-only configuration, T06 resource/containment requirements, T07 trusted-evidence checks, or any authorization gate.

## Consequences and failure modes

- The existing T09 Qwen graph templates and hashes matching Comfy-Org remain valid observations for those exact files, not a global allowlist. Before choosing the final T09 configuration, inventory the intended unlocked downloads and obtain an explicit variant selection. Do not relabel the already pinned official-byte candidate as an unlocked model without evidence.
- **Stock hash differs, selected variant hash matches its independently approved pin:** permitted to continue subject to all other gates.
- **Selected variant bytes differ from its declared/approved pin:** fail closed, even if they resemble another known release. Re-declare and reapprove any intentional change.
- **Byte identity is known but attribution, license, conversion history, or authority is missing:** record unverified rather than inventing evidence or claiming T07 ready.
- **Model family matches but recipe/node/runtime support is absent:** report incompatible or unsupported, not a successful substitution.
- Model selection must not introduce application-level blanket disqualification merely for the variant being uncensored/unlocked. Behavioral assessment stays specific to the lawful scenarios and actual configuration tested.

## Rejected alternatives

- **Require official publisher/stock hashes.** Rejects intentional unlocked variants even when they are the desired inputs.
- **Skip SHA-256 or accept any digest when a model is labeled unlocked.** Removes the independent artifact-integrity invariant and makes runs irreproducible.
- **Auto-substitute the nearest stock model.** Violates owner selection, changes behavior, and corrupts provenance.
- **Infer suitability from names or downloaded-source claims alone.** Neither a label nor a checksum establishes runtime support or observed behavior.
- **Treat private local deployment as a license or consent waiver.** T07 and T17 requirements continue to apply.

## Related decisions and tickets

ADR 0001 governs read-only inventory; ADR 0002 governs exact declarations and independent evidence; ADR 0003 governs backend execution provenance. This ADR clarifies variant eligibility without superseding those fail-closed requirements.

See specification #1 and T02 #3, T07 #8, T08 #9, T09 #10, T17 #18, and T34 #35.
