# Artifact publication and recovery

## 1. Identity and compatibility

An Artifact ID identifies one immutable logical image and its provenance. The
SHA-256 value identifies the encoded bytes. Two jobs or two import commands can
produce the same bytes and still create distinct Artifact IDs. This
implementation does not share blobs; images remain ordinary files outside
SQLite.

The current generated-artifact record retains its job, attempt, output slot,
metadata, identity, and public JSON shape. An imported record has no generation
job, attempt, or output slot; it retains the explicitly approved source root,
relative filename, observed source identity and timestamps, and import time.
The source bytes are copied unchanged, including metadata and orientation.
Later edits to the source file cannot change the stored artifact.

The current schema is `user_version = 5`. A new database creates artifact,
lineage, publication, execution, privacy, and admission structures directly in
one transaction. An existing database reopens through a read-only connection
and must match the complete current schema exactly. Older, newer, partial,
malformed-current, and nonempty unversioned databases are rejected without
mutation. There is no migration, backfill, historical publication repair, or
old-job compatibility path.

Every current generation job has an `execution_jobs` sidecar with non-null
privacy-compliance evidence and exactly one `execution_admissions` row. The
`execution_resource` singleton must contain one valid row. A job without its
execution sidecar or admission evidence makes the database structurally
incompatible. A `not_required` admission is accepted only for the exact bundled
`deterministic-cpu-png-v1` adapter.

The store also creates immutable-artifact and writer-epoch triggers. Every
connection registers the connection-local
`media_generation_writer_epoch()` function. `BEFORE INSERT/UPDATE` guards on
current mutation tables require epoch 5. A client that lacks the function, or
that reports a different epoch, aborts on its first guarded mutation.
Validation compares every table, index, trigger definition, singleton resource
row, execution sidecar, admission row, and exemption. Unknown objects and
divergent same-name definitions fail closed.

The writer guard protects SQLite writes after a compatible database has been
opened. It is not a process supervisor or authentication boundary. Operators
must stop every worker, adapter, and inference process before replacing a
database or image tree. An already-running process can still change files, and
a deliberately modified client can register a matching function or remove
triggers. Preserve the incompatible database and choose a new path; delete a
disposable development database only after explicit operator acceptance.

## 2. Approved import boundary

The local CLI is an operator interface. `import --approved-root DIR --source NAME`
explicitly grants read authority beneath DIR for that invocation. This is not a
network authentication mechanism. A future remote interface must supply its own
trusted root policy; it must not relay an untrusted user's chosen approved root.
The Python `import_image` method has the same administrative responsibility.
Generation requests continue to accept only Artifact IDs.

Every source directory component, including ancestors of the approved root, is
opened relative to a pinned descriptor with `O_NOFOLLOW`; directories also use
`O_DIRECTORY`. The leaf must be a regular file. Absolute source names, URLs,
parent traversal, empty/dot components, backslashes, symlinks, and nonregular
inputs are rejected. Reads use the opened descriptor and compare identity,
size, modification time, and change time before and after copying. A changing
input is rejected. The original input is never modified.

Only static, single-frame PNG and JPEG content is accepted. Extensions have no
authority. Pillow verifies structure and fully decodes pixels; header inspection
alone is insufficient. The inclusive limits are 32 MiB encoded bytes, 8192 pixels
per dimension, and 16,777,216 decoded pixels. APNG, MPO, other image formats,
truncated images, decompression-bomb warnings, and malformed content are rejected.
The same limits validate generated images and subsequent integrity checks.
Decoding uses a bounded in-memory snapshot; these limits are admission ceilings,
not a promise of a particular peak resident-memory footprint.

## 3. Ordering, execution authority, and durable decisions

The authoritative destination must be on a local POSIX filesystem that supports
hard links, durable extended attributes, advisory `flock`, and file and directory
`fsync`. Destination components must be real directories. The permanent
`.artifact-publication.lock` serializes all publishers and reconciliation for
the destination, including separate processes. External writers, operators, and
unrelated processes must never unlink the lock file or edit the private
`.artifact-cleanup` directory while the store is in use. The store's publication
and reconciliation operations may create, inspect, and remove entries while
holding the publication lock and after verifying directory and captured inode
ownership tokens. A stable random directory ownership token is synced and bound
into each publication record; a reused inode number alone is insufficient proof
of ownership.

The publication lock serializes final names, staging cleanup, and reconciliation.
Execution scheduling uses separate SQLite rows and transaction guards in the
same database. All cooperating workers must use the database and output
directory. Admission atomically stores one immutable request, job, output slot,
fully resolved plan, adapter identity and configuration, ordered reference IDs
and content hashes, resolved destination, and persisted attempt budget before
any attempt exists.

An omitted budget defaults to one only for a new job; reuse preserves the first
admission's budget, and an explicitly different value conflicts for non-
succeeded jobs. Succeeded reuse returns the existing artifact without changing
its saved budget. Reuse also requires a matching resolved destination and any
containment contract recorded by a non-succeeded job. The pinned admission
profile fingerprint, workload demand, required bytes, and unknown reasons must
also match. A queued job has no attempt until a worker claim succeeds. Each database
contains one heavyweight resource row for its local execution domain.

A claim atomically reserves that resource and creates the current attempt with a
random owner, monotonically changing fence epoch, heartbeat, and lease. The
default lease is 30 seconds and the worker heartbeats every five seconds. Lease
expiry is evidence to inspect, not proof that an external process stopped, and
does not by itself release the resource. Every completion, failure, heartbeat,
publication commit, and recovery mutation checks current owner and epoch where
applicable. Stale actors cannot complete work, fail a successor, or publish an
artifact.

Automatic retry is permitted only when all conditions hold together: the
failure classification is explicitly retryable or a process-contained crash,
termination has been proven, publication reconciliation found no unresolved or
committed journal for the attempt, the heavyweight resource is available, and
persisted attempt budget remains. The default budget is one total attempt. A
worker restart does not reset it. Unknown outcomes are quarantined and never
replayed automatically; retry keeps the request, job, output slot, and budget.

Termination proof is accepted only from a containment contract declared
directly by the adapter. An adapter identity, inherited class behavior, or
successful return does not establish that an external process stopped. A valid
artifact produced without trusted proof remains committed and inspectable, but
its attempt records `termination_proven=false` and the resource stays
quarantined. A noncanceled failure without proof reports the durable job as
`ambiguous`, retains its underlying failure classification, and cannot
authorize replay.

The public retry operation may acknowledge an eligible bounded retry while it is already queued. Repeated requests are idempotent and preserve the job, request, output slot, attempt history, and budget while the job remains queued, within budget, and the resource is available. A later worker claim, recovery failure, or another job's resource claim can invalidate a subsequent retry acknowledgement; only a worker claim starts the next attempt. The singleton resource state appears in provenance's execution context with owner IDs where applicable. Individual job snapshots do not imply resource ownership.

Cancellation of a queued job makes it terminal before any attempt exists. For a
claimed attempt, cancellation fences the current owner and epoch immediately and
returns `accepted` while that execution may still be stopping. The heavyweight
resource is released only after recovery proves termination and publication
state is safe. An active attempt may accept cancellation through every precommit
publication checkpoint because the database artifact/lineage transaction remains
the logical linearization point. After that transaction commits, cancellation
returns `too_late` and reports success if the job already succeeded.

A physical final filename can exist before the artifact transaction commits. It
is not a logical Artifact until artifact, lineage, output-slot, attempt, and
publication rows commit atomically. Removing or adopting that physical name does
not decide publication order. Recovery preserves it when its attempt was
canceled or fenced, reports it as unregistered physical content, and never
adopts it as a successful artifact. This requires no separate durable decision
before `os.link`.

The publication sequence is:

1. Commit a unique publication intent in SQLite, including destination identity,
   logical artifact identity, stage name, and real generation attribution when
   applicable. SQLite connections use `synchronous=FULL`.
2. Exclusively create the private stage on the destination filesystem. Attach
   its unique publication token as an extended attribute and sync it before
   recording device and inode and syncing the directory. Both adapters and import
   write directly to the pinned stream; they never reopen its pathname.
3. Validate the complete image and digest, flush and sync the file, and commit
   validated artifact and ordered source descriptions as a `ready` journal.
4. Hard-link the owned inode into its final name without overwriting an existing
   entry. Retain the private name until metadata commit. Verify the final inode
   and complete content, sync the file and containing directory, and recheck the
   destination identity.
5. In one SQLite transaction, insert the artifact and edges, claim its output
   slot, mark its real job and attempt successful if generated, and mark the
   journal committed. Only this transaction makes the artifact retrievable.
6. Atomically capture the private link into the owner-only
   `.artifact-cleanup` directory, sync both directories, then validate the
   captured inode and token before unlinking it there. A replacement captured in
   this window is retained and its location is reported. The private cleanup
   directory remains for reuse. Failure or loss of acknowledgement after commit
   never deletes final media or changes a successful job to failed. Cleanup can be
   repeated by reconciliation.

Filesystem publication and SQLite commit are separate durable operations. No
atomic transaction spans them. A lost commit acknowledgement is resolved by
reading the durable journal, not by deleting content. Generated idempotency keys
continue to resolve the original job. Reconciliation never invokes an adapter.

## 4. Reconciliation and integrity

`reconcile` takes the same destination lock as publishers. It waits for an active
publication to finish before inspecting entries. Recovery is idempotent:

1. An allocated, incomplete publication is abandoned. Its real running job may
   be failed, and the stage is removed only when its regular-file device/inode
   and random ownership token match the durable record. Capture precedes the
   final ownership check so a replacement public stage name cannot cause an
   unrelated file to be deleted.
2. A ready publication with current attempt authority is revalidated. Owned
   staged content may be linked and synced, or an already linked owned final file
   may be adopted, before the same artifact/lineage transaction completes.
3. A ready publication whose attempt is canceled or whose owner, epoch, or job
   authority is stale uses the exceptional revoked-ready transition. In one
   SQLite transaction, recovery rechecks authority and committed artifact
   existence, then changes only `ready` to `abandoned` with an explicit reason.
   It refuses the transition if the artifact transaction won or the publication
   is committed. The ordinary allocated-only abandonment guard remains in place
   for every other state. Repeated recovery is idempotent. No final or staging
   file is unlinked by this transition.
4. A committed publication keeps its media and successful result. Any owned
   remaining private link can be cleaned up.
5. An unknown file, mismatched inode, final-name collision, or ambiguous
   ownership is preserved and reported. In the unavoidable window between
   exclusive create and recording its inode, recovery cannot prove ownership of
   an existing entry and reports `ownership_uncertain`. It does not delete it.
   Recovery also refuses missing or mismatched directory or file ownership
   tokens; it never manufactures them. Interrupted cleanup resumes from the
   captured entry in the private cleanup directory.
6. A missing or changed published image is reported as `missing` or `corrupt`.
   Observations are stored separately from immutable historical metadata. Such
   content cannot be used as a new trusted reference. Matching restored original
   bytes can become healthy on a subsequent check; history is never rewritten.

The report includes publications, cleanup outcomes, integrity observations, and
orphan filenames. A final filename retained by an abandoned ready publication is
included in `orphan_files` so operators can inspect the physical content without
re-adopting it. An orphan name alone is never deletion authority. Errors such as
disk exhaustion, denied `fsync`, missing ready content, and concurrent foreign
entries are reported rather than converted into successful publication. An
operator must investigate unresolved entries; no general retention or deletion
policy is implemented.

Reconciliation returns `status: complete` only when every journal entry is
resolved, cleanup is finished, and inspected content is healthy. Otherwise it
returns `attention_required`; the CLI still prints the report to standard output
and exits 1. The `integrity` command is an observation query and returns its
explicit `ok`, `missing`, or `corrupt` status in JSON without changing
historical success.

For an artifact with a publication journal, the recorded publication owner
and final filename determine the verification path. A path or name mismatch is
corrupt evidence, not a reason to infer another location.

For a current record without a publication row, integrity first requires that
the stored parent is the authorized output root. A cross-root record is trusted
only when a direct durable lineage neighbor resolves through a pinned no-follow
directory alias to the configured root and its bytes still match immutable
metadata. The neighbor is opened relative to the pinned directory, with no-follow
checks on every path component. Alias evidence does not infer a path, migrate a
row, authorize a new import, or grant ownership to an unrelated artifact.
Missing or corrupt neighbor content and aliases that resolve elsewhere remain
untrusted.

Verification pins and compares the alias directory identity with the configured
root, reads the neighbor through the pinned descriptor, and reconfirms the alias
binding before accepting evidence.

## 5. Lineage

Edges point from a source artifact to a derived artifact. Their explicit roles
are `reference` (actual conditioning), `source` (image being edited), `derivation`
(related rendition), and `inspiration` (creative origin without conditioning).
The deterministic adapter uses ordered reference content hashes in its output.
The list position is persisted. Duplicate artifact/role pairs are rejected
before allocating publication content. Imported images may declare ordered parents via
`--sources-json`; ordinary generation automatically records its reference IDs.

Foreign keys forbid missing endpoints. Constraints and a recursive SQLite trigger
forbid self-edges and cycles. Artifact and edge updates/deletes are rejected.
Artifact creation and all its edges commit together. A sealing trigger prevents
appending parents to an artifact after that transaction. Lineage is inspectable in
both directions across restarts; it is unrelated to scene hierarchy.

## 6. Validation and limits

Tests create fresh current-schema databases directly. They verify atomic
initialization, exact object definitions, same-schema reopen, missing execution
or admission evidence, incompatible-writer guards, and byte-for-byte
non-mutation when older, newer, malformed-current, or nonempty unversioned
databases are rejected. Runtime images exercise the import boundary and full
decoding. The
field-by-field publication fault matrix covers allocation through reply loss.
Focused cancellation tests exercise all 14 precommit checkpoints as accepted and
all six postcommit checkpoints as `too_late`. Recovery tests cover canceled ready
journals before and after physical link, repeated convergence, committed-wins
refusal, retained-final orphan reporting, owner and epoch fences, stale
completion, immutable retry budgets, omitted cross-surface budget reuse,
unqualified success and failure containment, malformed current schemas, and
successful bounded retry through the CLI.

These tests establish process-crash behavior on the tested filesystem. They do
not simulate a power-cutting device or certify storage firmware, controller
caches, network filesystems, or hardware reliability. On platforms where
`os.fsync` does not request a device-cache flush, notably Darwin without
`F_FULLFSYNC`, success acknowledges the host filesystem's writeback state only;
the project does not claim power-loss durability there. Cooperative writers must
use the protocol and leave the private cleanup namespace untouched. A privileged
or same-account process can still modify files or the database outside the
protocol. Descriptor checks and later integrity verification detect observable
changes, but do not protect against an adversary controlling the storage host.

Workers coordinate through one SQLite database and one local filesystem. This
implementation has no distributed scheduling, HTTP service, model download,
network inference, or model installation. The bundled deterministic adapter is
CPU-only test infrastructure, not a production model result.
