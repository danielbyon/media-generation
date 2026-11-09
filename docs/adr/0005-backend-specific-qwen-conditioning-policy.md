# ADR 0005: Backend-specific Qwen 2511 conditioning policy

## Status

Accepted on 2026-11-03 (owner decision).

## Context

The Qwen Image Edit 2511 zero-conditioning rule was written for
stable-diffusion.cpp. That backend accepts the literal
`qwen_image_zero_cond_t=true` flag or model argument. ComfyUI does not expose
this command-line option. Its recipe-v2 graph selects the corresponding
reference behavior through two `FluxKontextMultiReferenceLatentMethod` nodes,
each with `reference_latents_method=index_timestep_zero`.

Using an engine label to exempt a candidate from the stable-diffusion.cpp flag
would make T07 readiness depend on naming instead of evidence. Treating the
ComfyUI graph setting as the stable-diffusion.cpp flag would also misdescribe
the invocation contract and weaken the graph checks required before dispatch.

## Decision

1. The stable-diffusion.cpp Qwen Image Edit 2511 rule remains unchanged. An
   engine and recipe that use that backend must both declare the literal
   `qwen_image_zero_cond_t=true` value, and the declared command-line contract
   must emit the matching argument. Missing or false values remain
   `incompatible`.
2. ComfyUI has one fixed policy claim for this model:
   `backend-policy:comfyui/qwen-image-edit-2511-reference-latent-timestep-zero/v1`.
   The claim is valid only for a recipe whose engine identifier is `comfyui`.
3. T07 readiness for a ComfyUI selection requires that fixed claim in trusted
   compatibility evidence. The trusted record must match the complete evidence
   document, and that document must bind the exact recipe document SHA-256. A
   ComfyUI engine identifier by itself cannot satisfy, alter, or replace this
   requirement. Missing, mismatched, or untrusted policy evidence leaves the
   candidate non-ready.
4. A ComfyUI `media-generation.comfyui-recipe` version 2 candidate must contain
   the exact validated Qwen edit graph. Both positive and negative
   `FluxKontextMultiReferenceLatentMethod` nodes must use
   `index_timestep_zero`, and the sampler must consume both branches. ComfyUI
   candidate loading validates the graph before engine startup, and the adapter
   revalidates the effective graph before dispatch. T07 candidate evaluation
   verifies the pinned recipe and trusted policy evidence but does not parse the
   graph.
5. The selected backend kind is an application-owned input. Unknown values
   fail closed. Selecting ComfyUI removes the stable-diffusion.cpp flag
   requirement and adds the fixed ComfyUI policy-evidence requirement.

## Consequences

T07 can distinguish the two backend policies without weakening either one.
ComfyUI readiness now depends on independently supplied evidence tied to the
exact recipe, while stable-diffusion.cpp keeps its literal flag and CLI syntax
checks. A change to the recipe bytes changes the trusted evidence binding. A
graph that differs from the validated recipe-v2 method graph fails during
ComfyUI candidate loading and is checked again before dispatch.

This decision does not authorize a ComfyUI runtime, demonstrate model loading,
or establish APEX inference or T19 qualification. Synthetic test authorities
remain test fixtures and do not create production trust.

## Rejected alternatives

- **Exempt ComfyUI using its engine identifier alone.** A declaration can name
  the engine while carrying no trusted policy evidence.
- **Describe the ComfyUI graph method as a CLI flag.** The adapter sends a JSON
  graph and has no equivalent stable-diffusion.cpp argument.
- **Accept a policy claim without binding the recipe digest.** The approval
  could survive a changed graph or recipe.
- **Infer the policy from filenames or family labels.** Those labels do not
  establish the executable contract or graph behavior.

## Related decisions

ADR 0002 defines T07 declarations and independent evidence. ADR 0003 defines
supervised backend execution evidence. ADR 0005 adds this backend-specific
policy scope while preserving the accepted requirements in both records.
