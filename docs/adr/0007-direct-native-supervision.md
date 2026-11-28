# ADR 0007: Direct supervision of native inference

Status: Accepted for the single-owner V1 application.

## Decision

Trust the workstation owner, operating system, installed application, and
selected inference software. The engine runs under the worker account. Both can
access that account’s files and GPU devices. A compromised process could alter
job or artifact state, bypass admission, or leave its process group. Review
this decision before supporting untrusted components, multiple owners, or
stronger OS isolation requirements.

The installed SD-C++ backend must implement the local, synchronous
`sd-cpp-exec-v1` image CLI contract. The reviewed upstream image path calls
the inference library in the CLI process and writes its result locally.
Supported builds and their dependencies must keep any helpers in the original
process group and must complete their GPU work before that group exits.
Delegating inference to a server or detaching helpers is outside this contract.
Dispatch checks the reviewed candidate’s executable digest. Review and pin
a replacement build before dispatching it, and check its linked runtime. Upstream
source inspection does not qualify a locally built binary or GPU workload.
[SD-C++ image CLI at b13a482](https://github.com/leejet/stable-diffusion.cpp/blob/b13a482/examples/cli/main.cpp#L815-L868)

Text and vision requests use the llama.cpp MTMD CLI at source revision
`1a03cf47f67be591699d1f0f7ca28e1ed6eb8c7e`. Its experimental build includes
the one-line single-turn change in
[`mtmd-cli.cpp`](https://github.com/ggml-org/llama.cpp/blob/1a03cf47f67be591699d1f0f7ca28e1ed6eb8c7e/tools/mtmd/mtmd-cli.cpp#L301).
The worker passes `--offline` and `--ctx-size 4096`, caps generated output at
512 tokens, and captures at most 1 MiB of stdout. Each request has an absolute
deadline of at most 300 seconds from enqueue. Vision input is limited to
8,388,608 pixels. Smaller output and deadline limits are allowed. Dispatch
requires separate evidence for the exact build, one-JSON-document stdout
behavior, compatible hardware, matching execution bounds, and measured resource
demand. The upstream CLI does not expose its response termination reason, so
the application records it as unknown.

The worker owns process supervision and publication. After reaping the child,
the supervisor checks the original process group and records the result on
the exact SQLite attempt. An absent group and settled output streams permit
release after publication settlement. A surviving group, a lost worker before
proof is durable, or an uncertain result keeps capacity quarantined.
Recovery can reconcile a persisted result. It cannot safely reconstruct the
original process identity.

The local-only privacy gate and private application storage remain required.
The configuration and evidence checks make no claim of OS-enforced network
or filesystem isolation.

## Alternatives

The prior root broker, isolated runner account, and separate evidence ledger
protected against compromised worker or engine processes. They imposed
privileged deployment and a second persistence authority. The owner accepted
the narrower trust model to remove those costs. A global interruption
operation would affect unrelated work. Reusing a PID after worker loss
could signal a different process. Neither belongs in the supported lifecycle.

The shared lifecycle uses schema 11 with no migration from earlier state.
Inference attempts use the common launch and termination records while
keeping their response data separate from image-generation result records.
Keep earlier state with its matching release for rollback.
