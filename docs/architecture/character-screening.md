# Headless character screening

The screening command runs the T10 protocol through `GenerationService`. Each exact engine and model configuration gets 24 separately recorded, single-output requests: three reference styles, four labeled scenario changes, and two seeds. Unsupported, blocked, failed, queued, and interrupted cases remain in the denominator. Supplementary capability, editing, chain, composition, outfit, and preview/final cases are reported separately.

## Prepare the local references

Import each operator-approved image through the existing import command. Keep the source files and the screening data outside Git.

```sh
media-generation import \
  --db /private/screening-data/generation.sqlite3 \
  --output-dir /private/screening-data/artifacts \
  --approved-root /private/approved-images \
  --source front-reference.png
```

Record the returned artifact ID and SHA-256 in the version 1 screening manifest. A reference style lists ordered artifact IDs, their matching hashes, and a role for each input. The runner checks these fingerprints against the existing service database before it admits work. `GenerationService` verifies the referenced media bytes again during admission.

The manifest also freezes the selected `ModelVariant`, its component paths and hashes, the request dimensions, the three reference styles, the four scenario prompts, and the two distinct seeds. Candidate component pins must match the variant's component hashes. Keep trusted T07 evidence with the candidate declaration; the manifest does not replace it.

## Manifest version 1

The root object uses `schema: "media-generation.character-screening"` and integer `schema_version: 1`. It contains `protocol_id`, `selected_model_variant`, `request_profile`, `reference_styles`, `scenario_changes`, `seeds`, and optional `supplementary_cases`.

- `selected_model_variant` contains `id`, `family`, `repository`, `revision`, and `components`. Each component records `id`, `role`, absolute local `path`, `size_bytes`, `sha256`, `precision`, and `quantization`. Optional `architecture_flags` and `worker_context` preserve additional selected-variant details.
- `request_profile` contains `width`, `height`, and `output_slot_prefix`.
- `reference_styles` has exactly three entries. Each has a unique `id`, `label`, ordered `artifact_ids`, matching `sha256` values, and matching `roles` (`reference` or `source`).
- `scenario_changes` has exactly four entries. Each has a unique `id`, `label`, complete `prompt`, and `operation_intent` (`generate` or `edit`).
- `seeds` contains exactly two distinct integers from 0 through 4,294,967,295.
- `supplementary_cases` may contain `capability`, `edit`, `regeneration`, `chain`, `large_composition`, `outfit_unlocked`, and `preview_final` cases. Each case has a unique `id`, `label`, request, and `operation_intent`. A request may set its own dimensions and reference list. Every reference needs a matching `conditioning_sha256` entry. Chain steps use one `chain_id` and consecutive `chain_step` values. Preview/final pairing uses one pair ID with one case for each role.

The runner checks duplicate object keys, unknown fields, artifact IDs, roles, component hashes, case counts, seeds, and operation/role combinations before it creates a run. It stores `GenerationRequest.to_dict()` and its unchanged digest contract. The `operation_intent` is stored as a separate ledger field because it is not part of that canonical serialization.

Supplementary requests use the same pinned-input format. A `capability` case can cover one or several references and their order and roles. An `edit` case uses a source role; a `regeneration` case uses canonical reference roles. A `chain` groups two or more steps with consecutive step numbers. Its conditioning artifacts must already exist and be pinned when the run is created. To use an output from another run in a chain, create the follow-up run after that artifact exists.

Preview and final cases are separate requests under `preview_final`. Their profile is labeled experimental and carries no product acceptance target. The pairing relation and creative origin are stored separately from the request's actual conditioning inputs. A preview is a conditioning input only when its artifact ID appears in the final request.

## Run and resume

Prepare an independently reviewed T07 candidate and select the intended engine backend. Heavyweight execution also needs current T02 admission, policy, and workload-demand inputs. The existing T05 privacy checks, T06 admission, adapter capability rules, and service attempt budget remain in force.

After the ledger commits a new run, the CLI writes `screening_run_id=<run-id>` to stderr before it starts the first case. Keep that ID so the run can be resumed if execution stops before the report is written.

```sh
media-generation screen run \
  --manifest /private/screening-data/character-screening.json \
  --data-dir /private/screening-data \
  --engine-candidate /private/candidate/candidate.json \
  --engine-trusted-evidence /private/candidate/trusted-evidence.json \
  --engine-backend stable-diffusion-cpp \
  --inventory-report /private/screening-data/inventory.json \
  --admission-policy /private/screening-data/admission-policy.json \
  --workload-demand /private/screening-data/workload-demand.json
```

The data directory contains a separate `screening.sqlite3` ledger. The GenerationService database defaults to `generation.sqlite3` in that directory, and output files default to its `artifacts` subdirectory. Use `--service-db` or `--output-dir` to select different external paths. The runner rejects data, service, output, or manifest paths inside a Git worktree.

The ledger creates the run ID, case IDs, frozen definitions, request snapshots, canonical request digests, and case-specific idempotency keys. It commits all cases before the first service admission. `GenerationService` creates request, job, attempt, artifact, and output-slot identities. A new run gets a new run ID and fresh idempotency keys; resume retains the original identities.

Resume with the same candidate and admission inputs:

```sh
media-generation screen resume \
  --run-id <run-id> \
  --data-dir /private/screening-data \
  --engine-candidate /private/candidate/candidate.json \
  --engine-trusted-evidence /private/candidate/trusted-evidence.json \
  --engine-backend stable-diffusion-cpp \
  --inventory-report /private/screening-data/inventory.json \
  --admission-policy /private/screening-data/admission-policy.json \
  --workload-demand /private/screening-data/workload-demand.json
```

For each case, the runner first looks up the persisted service idempotency key through a read-only GenerationService interface and compares its stored digest with the frozen request digest. It can recover the original job even when current admission or adapter checks would reject a new submission. New execution and continuation of queued work still go through the current service gates. A changed manifest or execution identity requires a new run.

Two runner processes coordinate each case through SQLite leases and claim epochs. Lease transactions end before inference begins. A heartbeat renews long-running claims; after a process exits, a later runner can take over an expired claim and reconcile the service key. GenerationService retains its own attempt fencing and retry budget.

## Reports and evidence

Print JSON or a readable case summary:

```sh
media-generation screen report --run-id <run-id> \
  --data-dir /private/screening-data --format json

media-generation screen report --run-id <run-id> \
  --data-dir /private/screening-data --format summary
```

Reports include all 24 matrix slots, supplementary cases, exact request/job/attempt/artifact identities, the frozen variant and configuration fingerprints, service status, and artifact integrity. Each case keeps its benchmark outcome and error alongside the underlying GenerationService status. Execution success and artifact integrity are separate fields. A missing or corrupt published file remains visible; report inspection never regenerates or replaces it. Report and resume inspections verify artifact bytes without writing an integrity observation or initializing a missing GenerationService database.

Successful report retrieval returns `status: "available"`, including when matrix execution is incomplete. `summary.matrix_status_counts` counts benchmark case outcomes; `matrix_execution` reports completion and success from persisted service execution. `matrix_execution.status` is complete only after all 24 cases have recorded execution outcomes; `execution_success` is true only when all 24 succeeded. The `report` command returns success when it retrieves the report. `run` and `resume` return failure when the matrix is incomplete or any case did not succeed.

The report keeps both `apex_execution` and `qualification` unverified. Software tests, local job records, and candidate readiness do not establish that the 24 cases ran on the owner-selected APEX configuration or passed qualification. Live APEX outputs and their host and configuration evidence are required before issue #11 can be treated as hardware screening evidence.

T10 records repeatable screening inputs and outputs. T11 measures timing distributions, T15 evaluates outputs, and T20/T21 handle configuration qualification and owner selection. The screening report assigns no quality score or product acceptance threshold.
