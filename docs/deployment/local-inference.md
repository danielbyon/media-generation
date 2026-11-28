# Deploy local inference

Install a reviewed application release and its pinned dependencies in a
versioned environment. Run the worker under an account that can read the
selected runtime and model files and access the intended GPU. Keep its SQLite
database and private staging directory on local, access-controlled storage.
The T05 privacy check verifies the application's effective runtime settings;
the worker account still has the operating system permissions granted to it.

Schema 11 has no migration from earlier releases. Keep each database,
artifact directory, and unresolved attempt record with the release that wrote
it. Restore those pieces together during rollback. The owner must separately
authorize retiring an earlier installation or archiving its state.

## Image generation

Use the reviewed SD-C++ candidate and its trusted evidence for image
generation. Preserve the configured ROCm library paths and GNU OpenMP
resolution when the installed runtime requires them.

Stop admission and dispatch before switching releases. Check for surviving
inference processes before allowing the new database to accept work. A
quarantined resource requires operator attention. Recovery can use durable
launch and termination evidence; a stale PID or expired lease does not prove
that a process group has ended.

T13 completed all three real-engine acceptance scenarios on the reviewed
release. A verified generation and resource release. B verified cancellation
after engine start, release after confirmed termination, and no publication. C
intentionally stopped the owner-identified worker after engine start; because
termination proof was not durable, recovery abandoned publication, required
attention, quarantined the resource, and blocked the next dispatch. An earlier
SIGABRT attempt remains unexplained and did not count as C. Keep the quarantine
until the owner separately authorizes its disposition. See the
[T13 completion record](https://github.com/danielbyon/media-generation/issues/14).

For a release that changes image generation, pause unrelated inference during
acceptance. Verify the installed release and candidate, then complete one real
generation and check its artifact and resource release. Cancel a different job
after engine start and confirm that cancellation settles without publication.
In a third run, stop only the owner-identified worker after engine start and
use `recover`. Confirm that stale publication is fenced and uncertain process
termination keeps the resource quarantined. Record job and attempt IDs,
publication outcomes, and resource states.

## Text and vision inference

The provisional multimodal candidate is SmolVLM2-2.2B-Instruct Q4_K_M with
`mmproj-SmolVLM2-2.2B-Instruct-f16.gguf`, published by ggml-org at revision
[`dee053fcacd753963eb4997eef2c176ee8bb2bf7`](https://huggingface.co/ggml-org/SmolVLM2-2.2B-Instruct-GGUF/tree/dee053fcacd753963eb4997eef2c176ee8bb2bf7).
The model file is the T07 `checkpoint`; the projector file is a T07
`projector` component. The original model lineage and both component hashes
still need independent verification. Prepare the published files through T07.
Do not convert the model as part of application setup.

The llama.cpp MTMD CLI build is experimental. Its supported build applies the
one-line single-turn change at the pinned source revision
[`1a03cf47f67be591699d1f0f7ca28e1ed6eb8c7e`](https://github.com/ggml-org/llama.cpp/blob/1a03cf47f67be591699d1f0f7ca28e1ed6eb8c7e/tools/mtmd/mtmd-cli.cpp#L301).
The worker passes `--offline` and `--ctx-size 4096`, and caps output at 512
tokens. A lower output limit is allowed. Each request uses one absolute
deadline of at most 300 seconds from enqueue; a shorter deadline is allowed.
Vision inference accepts images up to 8,388,608 pixels. Image generation keeps
its 16,777,216-pixel limit. Response capture remains capped at 1 MiB.
Do not dispatch real requests until the exact binary, model and projector
hashes, hardware compatibility, resource demand, and response stream have
been verified. Stream evidence must show one JSON document on stdout and
diagnostics on stderr for each supported request kind.

The worker checks the candidate against independently trusted T07 evidence.
Its T05 profile must match the effective llama.cpp settings. Admission also
requires a ready APEX capacity profile and a separate T06 demand for each
request kind. The demand must declare a known 4,096-token context. Resource
qualification must bind that context, the configured output limit, and the
request kind's image limit. The runtime hardware fingerprint and measured
memory demand must match those records. These checks record evidence; they do
not impose operating-system network isolation.

Write each request to a JSON file so prompt text does not appear in the
command line. Vision requests also name a local image path; a relative image
path is resolved from the request file's directory. Enqueue requests before
starting the qualified worker. The runtime configuration names the executable,
model and projector components, token limit, and hardware fingerprint. Paths
in it are relative to that file. The effective invocation record also includes
the context and image bounds. The qualification file has one record per
request kind, with build, response-stream, hardware, and resource evidence.
The workload-demand file maps each kind to its T06 demand, including the known
context size.

```sh
media-generation inference enqueue \
  --db /var/lib/media-generation/jobs.sqlite3 \
  --idempotency-key request-001 \
  --request-file /var/lib/media-generation/requests/request-001.json \
  --runtime-config /etc/media-generation/llama-runtime.json \
  --inventory-report /var/lib/media-generation/apex-inventory.json \
  --admission-policy /etc/media-generation/admission-policy.json \
  --workload-demands /etc/media-generation/inference-demands.json

media-generation inference worker \
  --db /var/lib/media-generation/jobs.sqlite3 \
  --output-dir /var/lib/media-generation/private-stage \
  --runtime-config /etc/media-generation/llama-runtime.json \
  --runtime-qualification /etc/media-generation/llama-qualification.json \
  --candidate /etc/media-generation/smolvlm2-candidate.json \
  --trusted-evidence /etc/media-generation/trusted-evidence.json \
  --inventory-report /var/lib/media-generation/apex-inventory.json \
  --admission-policy /etc/media-generation/admission-policy.json \
  --workload-demands /etc/media-generation/inference-demands.json
```

The qualification and workload-demand files have separate `text` and `vision`
entries. Queue records retain the original deadline across a repair attempt.
Only an invalid response eligible under the response contract can use the
single repair attempt. If that response is still invalid, the attempt is
recorded as `repair_exhausted`; no third invocation is launched. A process
crash does not grant another invocation.
Use `inference cancel` to fence a request and `inference recover` to reconcile
an interrupted worker. Inspect `inference provenance` for redacted request,
attempt, qualification, and termination evidence. Raw prompts, image paths,
and response text do not belong in public provenance.
