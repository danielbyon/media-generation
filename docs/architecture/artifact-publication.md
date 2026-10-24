# Artifact publication and recovery

## 1. Identity and compatibility

An Artifact ID identifies an immutable logical image and its provenance. SHA-256
identifies encoded bytes. Two jobs or two import commands can produce the same
bytes and still create distinct Artifact IDs. This implementation does not share
blobs. Images remain ordinary files outside SQLite.

On opening a T01 database, an atomic SQLite migration extends the artifact table
to distinguish generated and imported records. Generated records retain their
job, attempt, output slot, metadata, IDs, and public JSON shape. Imports have no
job, attempt, or output slot; they retain the explicitly approved source root,
relative filename, observed source identity/timestamps, and import time. The
source is copied unchanged, including metadata and orientation. Subsequent edits
to the source file cannot change the stored artifact. Migration backfills ordered
reference edges from historical jobs and leaves their rows and image bytes intact.
The schema uses `user_version = 2`. Older application versions must not write to
an upgraded database; migration compatibility is forward reading by this version.

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

## 3. Ordering and durable decisions

The authoritative destination must be on a local POSIX filesystem that supports
hard links, durable extended attributes, advisory `flock`, and file and directory
`fsync`. Its components must
be real directories. A permanent `.artifact-publication.lock` serializes all
publishers and reconciliation for that destination, including separate processes.
Never unlink that file or edit the private `.artifact-cleanup` directory while
the store is in use. A stable random directory ownership token is synced and
bound into each publication record; a reused inode number alone is insufficient
proof of ownership. This is a filesystem publication
mutex; execution scheduling, attempt authorization, leases, and fencing are not
part of it.

The publication sequence is:

1. Commit a unique publication intent in SQLite, including destination identity,
   logical artifact identity, stage name, and real generation attribution when
   applicable. SQLite connections use `synchronous=FULL`.
2. Exclusively create a private stage on the destination filesystem. Attach its
   unique publication token as an extended attribute and sync it before recording
   the device/inode and syncing the directory. Both adapters and import write
   directly to its pinned stream; they never reopen its pathname.
3. Validate the complete image and digest, flush and sync the file, and commit
   the validated artifact and ordered source descriptions as a `ready` journal.
4. Hard-link the owned inode into its final name without overwriting an existing
   entry. Retain the private name until metadata commit. Verify the final inode
   and complete content, sync the file and containing directory, and recheck
   destination identity.
5. In one SQLite transaction, insert the artifact and edges, claim its output
   slot, mark its real job/attempt successful if generated, and mark the journal
   committed. Only this transaction makes an artifact retrievable.
6. Atomically capture the private link into the owner-only `.artifact-cleanup`
   directory, sync both directories, then validate the captured inode and token
   before unlinking it there. A replacement captured in this window is retained
   and its location reported. The private cleanup directory remains for reuse. Failure or
   loss of acknowledgement after commit never deletes the final media or changes
   a successful job to failed. Cleanup can be repeated by reconciliation.

Filesystem publication and the SQLite commit are separate durable operations.
No atomic transaction spans them. A lost commit acknowledgement is resolved by
reading the durable journal, not by deleting content. Generated idempotency keys
continue to resolve to the original job; a ready interrupted publication remains
running until reconciliation completes. Reconciliation never invokes the adapter.

## 4. Reconciliation and integrity

`reconcile` takes the same destination lock as publishers. It waits for active
publication to finish before inspecting entries. Recovery is idempotent:

1. An allocated, incomplete publication is abandoned. Its real running job may
   be failed, and a stage is removed only when its regular-file device/inode
   and random ownership token match the durable record. Capture precedes the
   final ownership check so replacement of the public stage name cannot cause
   an unrelated file to be deleted.
2. A ready publication is revalidated. Owned staged content may be linked and
   synced, or an already linked owned final file may be adopted, before the same
   artifact/lineage transaction is completed.
3. A committed publication keeps its media and successful result. Any owned
   remaining private link can be cleaned up.
4. An unknown file, a mismatched inode, a final-name collision, or ambiguous
   ownership is preserved and reported. In the unavoidable window between an
   exclusive create and recording its inode, recovery cannot prove ownership of
   an existing entry and reports `ownership_uncertain`. It does not delete it.
   Recovery also refuses missing or mismatched directory/file ownership tokens;
   it never manufactures them. Interrupted cleanup resumes from the captured
   entry in the private cleanup directory.
5. A missing or changed published image is reported as `missing` or `corrupt`.
   Observations are stored separately from immutable historical metadata. Such
   content cannot be used as a new trusted reference. Matching restored original
   bytes can become healthy on a subsequent check; history is never rewritten.

The report includes publications, cleanup outcomes, integrity observations, and
orphan filenames. An orphan name alone is never deletion authority. Errors such
as disk exhaustion, denied fsync, missing ready content, and concurrent foreign
entries are reported rather than converted into successful publication. An
operator must investigate unresolved entries; no retention/deletion policy is
implemented.

Reconciliation returns `status: complete` only when every journal entry is
resolved, cleanup is finished, and inspected content is healthy. Otherwise it
returns `attention_required`; the CLI still prints the report to stdout and
exits 1. The `integrity` command is an observation query and returns its explicit
`ok`, `missing`, or `corrupt` status in JSON without changing historical success.
For a journal-backed artifact, the recorded publication owner determines the
verification path. The `integrity --output-dir` argument supplies inspection
context for legacy artifacts that have no publication record.

Migration keeps historical T01 artifact paths unchanged. A legacy artifact in a
different directory is trusted only when it has a direct durable edge to an
neighbor without a publication record whose parent resolves to the configured
output root and whose bytes still match its immutable metadata. The neighbor is
reopened with descriptor-relative, no-follow checks under the configured root.
An alias is
compatibility evidence for legacy lineage, not authority for a new import or
for an artifact owned by a publication journal. Missing or corrupt neighbor
content and aliases that resolve elsewhere remain untrusted. Verification also
pins and compares the alias directory's identity with the configured root,
reads the neighbor through that pinned descriptor, and reconfirms the alias
binding before accepting the evidence.

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

Tests construct a real T01 database from the frozen SQL schema in
`tests/fixtures/t01-schema.sql`, then verify migration, old artifact JSON,
idempotency, and reference resolution. Runtime-created images exercise the import
boundary and full decoding. Exception injection and subprocess `os._exit` cover
stage allocation/write, validation, file sync, linking, directory sync, commit,
and reply loss. Additional tests cover concurrent reconciliation, collisions,
repeated recovery, duplicate bytes, and external corruption.

These tests establish process-crash behavior on the tested filesystem. They do
not simulate a power-cutting device or certify storage firmware, controller
caches, network filesystems, or hardware reliability. POSIX fsync success is the
host's durability acknowledgement. Cooperative writers must use this protocol and leave the private cleanup
namespace untouched;
a privileged or same-account process can still modify files or the database
outside it. Descriptor checks and later integrity verification detect observable
changes, but are not protection from an adversary controlling the storage host.
The bundled adapter remains CPU-only test infrastructure.

Pillow's [image documentation](https://pillow.readthedocs.io/en/stable/reference/Image.html)
describes the distinction between opening, verifying, and loading images.
