# Deploy local inference

Install the reviewed application release and dependencies in a versioned
environment. Use the worker account with access to the intended GPU, local
runtime and models. Keep its database, artifact directory, and staging files
private. Use the verified native SD-C++ candidate and its trusted evidence.
Preserve the configured ROCm library paths and GNU OpenMP resolution when
required by the installed runtime.

Stop admission and dispatch before switching releases. Check for surviving
inference processes before allowing the new database to accept work. Preserve
the previous software and state together for rollback. Schema 10 requires a
fresh database. The owner must separately authorize retiring an earlier
installation and archiving its database, artifacts, and any unresolved
attempt evidence.

Use the existing `enqueue`, `worker`, `cancel`, and `recover` commands.
A quarantined resource requires operator attention. A restarted worker can
reconcile durable state and cannot infer termination from a stale PID or a
lease timeout.

## Product acceptance

Pause unrelated inference during the checks. Verify the installed release and
candidate, then complete one real generation and verify its artifact and
resource release. Cancel a different job after engine start and check that
the cancellation settles without a publication. In a third run, stop only
the owner-identified worker after engine start and use `recover`. Confirm
stale publication is fenced and that uncertain termination prevents another
dispatch. Keep the job and attempt IDs, publication outcomes, and resource
states. This sequence also applies when qualifying another backend under
its own documented lifecycle contract.
