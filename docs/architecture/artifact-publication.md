# Artifact publication and recovery

## 1. Identity and compatibility

An Artifact ID identifies an immutable logical image and its provenance. SHA-256
identifies the encoded bytes. Two jobs or two import commands can produce the
same bytes and still create distinct Artifact IDs. This implementation does not
share blobs. Images remain ordinary files outside SQLite.

On opening a T01 database, an atomic SQLite migration extends the artifact table
to distinguish generated and imported records. Generated records retain their
job, attempt, output slot, metadata, IDs, and public JSON shape. Imports have no
job, attempt, or output slot; they retain the explicitly approved source root,
relative filename, observed source identity and timestamps, and import time. The
source is copied unchanged, including metadata and orientation. Subsequent edits
to the source file cannot change the stored artifact. Migration backfills ordered
reference edges from historical jobs and leaves their rows and image bytes intact.

The current schema uses `user_version = 3`. Version 3 adds execution and
publication-authority sidecar tables while leaving the T01 and T03 record tables,
JSON, identities, image bytes, and lineage unchanged. Publication authority is
backfilled only for historical publications whose journal state is `committed`.
An unfinished historical journal has no trustworthy owner, epoch, lease, or
containment evidence, so it remains quarantined. Opening a version-3 database
requires all four sidecar tables and the valid singleton `execution_resource`
row; an incomplete schema fails closed before admission. Migration and backfill
execute in one transaction; failure rolls back the entire upgrade. Older
application versions must not write an upgraded database; migration remains
compatibility-forward for database readers.

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
and digests, destination, and persisted attempt budget. An omitted budget
defaults to one only for a new job; reuse preserves the first admission's
budget and an explicitly different value conflicts. A queued job has no attempt
until a worker claim succeeds. The database contains one heavyweight resource
row for the local execution domain.

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

The public retry operation may acknowledge an eligible bounded retry while it
is already queued. Repeated requests are idempotent and preserve the job,
request, output slot, attempt history, and budget; only a worker claim starts
the next attempt.

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

For a journal-backed artifact, the recorded publication owner determines the
verification path. The `integrity --output-dir` argument supplies inspection
context for legacy artifacts that have no publication record. Migration keeps
historical T01 artifact paths unchanged. A legacy artifact in a different
directory is trusted only as direct durable-edge compatibility evidence when a
neighbor without a publication record has a parent resolving under the configured
output root and its bytes still match immutable metadata. The neighbor is opened
relative to a pinned directory with no-follow checks under the configured root.
An alias is compatibility evidence for legacy lineage, not authority for a new
import or for an artifact owned by a publication journal. Missing or corrupt
neighbor content and aliases that resolve elsewhere remain untrusted.
Verification also pins and compares the alias directory identity with the
configured root, reads the neighbor through the pinned descriptor, and reconfirms
the alias binding before accepting evidence.

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

Tests construct real T01 and historical T03 databases from frozen SQL fixtures.
They verify transactional migration, old artifact JSON, identities, lineage,
idempotency, unfinished-journal quarantine, and version-3 singleton-resource
completeness. Runtime images exercise the import boundary and full decoding. The
field-by-field publication fault matrix covers allocation through reply loss.
Focused cancellation tests exercise all 14 precommit checkpoints as accepted and
all six postcommit checkpoints as `too_late`. Recovery tests cover canceled ready
journals before and after physical link, repeated convergence, committed-wins
refusal, retained-final orphan reporting, owner and epoch fences, stale
completion, immutable retry budgets, omitted cross-surface budget reuse,
unqualified success and failure containment, malformed version-3 schemas, and
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
