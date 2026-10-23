"""Destination-owned image publication and restart reconciliation.

A permanent advisory lock serializes publishers and reconciliation for one
output directory. SQLite journals ownership before file creation and records
validated metadata before linking the file into its final name. The final link
and directory are synced before a transaction exposes the artifact and edges.
No path is deleted merely because artifact metadata is absent.
"""
from __future__ import annotations

import fcntl
import errno
import json
import os
import stat
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Callable, Iterator

from .domain import ArtifactSource, GenerationArtifact, ImportedArtifact
from .errors import PublicationError
from .images import ImageInfo, open_regular, validate_image
from .store import SQLiteStore
from .ownership import read_token, create_token

Artifact = GenerationArtifact | ImportedArtifact
Checkpoint = Callable[[str], None]
_ROOT_TOKEN = 'user.media_generation.root'
_STAGE_TOKEN = 'user.media_generation.publication'
_CLEANUP_TOKEN = 'user.media_generation.cleanup'
_CLEANUP_DIRECTORY = '.artifact-cleanup'


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def destination_directory(path: Path, *, create: bool = True) -> Iterator[int]:
    """Create/open a directory by descriptors without following symlink components."""
    absolute = Path(os.path.abspath(path.expanduser()))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                os.fsync(fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


class PublicationManager:
    """Publish ordinary files with a durable journal, separate from worker authority.

    The lock is a storage mutex, not an attempt lease or fencing protocol. Each
    destination has one permanent lock file that must never be removed while
    this storage directory is in use. Local POSIX filesystems with hard links,
    advisory locks, and file/directory fsync are required.
    """

    def __init__(self, store: SQLiteStore, root: Path, checkpoint: Checkpoint | None = None):
        self.store = store
        self.root = Path(os.path.abspath(root.expanduser()))
        self.checkpoint = checkpoint or (lambda name: None)

    @contextmanager
    def _locked(self, *, publishing: bool = False) -> Iterator[int]:
        with destination_directory(self.root, create=publishing) as directory:
            lock = os.open('.artifact-publication.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
            try:
                if not stat.S_ISREG(os.fstat(lock).st_mode):
                    raise PublicationError('publication lock is not a regular file')
                fcntl.flock(lock, fcntl.LOCK_EX)
                if self._identity(os.fstat(lock)) != self._identity(os.stat(
                    '.artifact-publication.lock', dir_fd=directory, follow_symlinks=False
                )):
                    raise PublicationError('publication lock was replaced')
                self._check_root_token(directory, create=publishing)
                os.fsync(directory)
                yield directory
            finally:
                os.close(lock)

    @staticmethod
    def _identity(value: os.stat_result) -> tuple[int, int]:
        return value.st_dev, value.st_ino

    def _assert_root(self, directory: int) -> None:
        with destination_directory(self.root, create=False) as current:
            if self._identity(os.fstat(current)) != self._identity(os.fstat(directory)):
                raise PublicationError('authoritative destination directory changed')
            self._check_root_token(current, create=False)

    def _check_root_token(self, directory: int, *, create: bool) -> bytes | None:
        """Bind a directory lifetime independently of reusable inode numbers.

        A missing token may be initialized only by a new publication on a root
        with no existing journal. Recovery never manufactures ownership proof.
        """
        records = self.store.publications(str(self.root))
        try:
            token = read_token(directory, _ROOT_TOKEN)
        except OSError as error:
            absent = error.errno in {getattr(errno, 'ENODATA', -1), getattr(errno, 'ENOATTR', -2)}
            if not absent:
                raise PublicationError('destination ownership xattrs are unavailable') from error
            if records:
                raise PublicationError('destination ownership token is missing') from error
            if not create:
                return None
            token = uuid.uuid4().hex.encode('ascii')
            create_token(directory, _ROOT_TOKEN, token)
            os.fsync(directory)
        if len(token) != 32 or any(byte not in b'0123456789abcdef' for byte in token):
            raise PublicationError('destination ownership token is invalid')
        for record in records:
            if (token.decode('ascii') != record['root_token'] or
                self._identity(os.fstat(directory)) != (record['root_dev'], record['root_ino'])):
                raise PublicationError('destination ownership token or inode changed')
        return token

    @staticmethod
    def _owned(directory: int, name: str, record: dict[str, object]) -> bool:
        """Require a pinned regular inode and its durable per-publication token."""
        if not name or Path(name).name != name:
            return False
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
        except OSError:
            return False
        try:
            observed = os.fstat(descriptor)
            return (stat.S_ISREG(observed.st_mode)
                and (observed.st_dev, observed.st_ino) == (record['stage_dev'], record['stage_ino'])
                and read_token(descriptor, _STAGE_TOKEN) == str(record['publication_id']).encode('ascii'))
        except OSError:
            return False
        finally:
            os.close(descriptor)

    @contextmanager
    def _cleanup_directory(self, directory: int, root_token: str, *, create: bool) -> Iterator[int]:
        """Pin the private cleanup namespace; existing directories need their token.

        Only protocol code may modify this mode-0700 namespace. All cooperating
        processes hold the destination lock. It remains present after cleanup,
        avoiding a second check-then-rmdir race at the public root.
        """
        created = False
        if create:
            try:
                os.mkdir(_CLEANUP_DIRECTORY, mode=0o700, dir_fd=directory)
                created = True
            except FileExistsError:
                pass
        descriptor = os.open(_CLEANUP_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=directory)
        try:
            observed = os.fstat(descriptor)
            if observed.st_uid != os.geteuid() or observed.st_mode & 0o077:
                raise PublicationError('cleanup directory is not private to the storage owner')
            expected = root_token.encode('ascii')
            if created:
                create_token(descriptor, _CLEANUP_TOKEN, expected)
                os.fsync(descriptor)
                os.fsync(directory)
            if read_token(descriptor, _CLEANUP_TOKEN) != expected:
                raise PublicationError('cleanup directory ownership is uncertain')
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _exists(directory: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def _clean_stage(self, directory: int, record: dict[str, object]) -> str:
        """Capture into the private namespace before validating and removing.

        A competing public-root entry can be renamed during capture. It is then
        preserved in the cleanup directory unless its inode AND token match.
        Unlink never re-resolves the untrusted public stage pathname.
        """
        name = str(record['stage_name'])
        captured = str(record['publication_id'])
        retained = f'{_CLEANUP_DIRECTORY}/{captured}'
        try:
            token = self._check_root_token(directory, create=False)
            if token is None or token.decode('ascii') != record['root_token']:
                return 'ownership_uncertain: destination token'
            if record['state'] in {'ready', 'committed'} and not self._owned(
                directory, str(record['final_name']), record
            ):
                return 'cleanup_pending: final file is missing or replaced'
            stage_exists = self._exists(directory, name)
            if not stage_exists and not self._exists(directory, _CLEANUP_DIRECTORY):
                return 'absent'
            with self._cleanup_directory(directory, str(record['root_token']), create=stage_exists) as cleanup:
                if not self._exists(cleanup, captured):
                    if not stage_exists:
                        os.fsync(cleanup)
                        return 'absent'
                    if not self._owned(directory, name, record):
                        return 'ownership_uncertain: staging entry preserved'
                    # The destination is in a private namespace under the root
                    # lock. Capture the entry, then check what was actually moved.
                    os.rename(name, captured, src_dir_fd=directory, dst_dir_fd=cleanup)
                    os.fsync(cleanup)
                    os.fsync(directory)
                    self.checkpoint('cleanup_captured')
                if not self._owned(cleanup, captured, record):
                    return f'ownership_uncertain: retained {retained}'
                if record['state'] in {'ready', 'committed'} and not self._owned(
                    directory, str(record['final_name']), record
                ):
                    return f'cleanup_pending: final changed; retained {retained}'
                self.checkpoint('before_cleanup_unlink')
                os.unlink(captured, dir_fd=cleanup)
                os.fsync(cleanup)
                self.checkpoint('cleanup_unlinked')
                if self._exists(directory, name):
                    return 'ownership_uncertain: additional staging entry preserved'
                return 'removed_owned_stage'
        except Exception as error:
            return f'cleanup_pending: {error}'

    def _abandon(self, directory: int, record: dict[str, object], error: str) -> str:
        self.store.update_publication(str(record['publication_id']), state='abandoned', error=error)
        if record['job_id'] is not None:
            self.store.fail_execution(str(record['job_id']), str(record['attempt_id']), error, now())
        return self._clean_stage(directory, record)

    def publish(self, writer: Callable[[Path, BinaryIO], object], factory: Callable[[ImageInfo, Path], Artifact],
                *, artifact_id: str, sources: tuple[ArtifactSource, ...] = (),
                job_id: str | None = None, attempt_id: str | None = None) -> Artifact:
        """Write and publish one image, retaining any uncertain durable publication.

        The writer receives a preallocated private file. It must write that file
        without replacing it. Exceptions after a successful metadata commit
        return the committed artifact; uncertain precommit outcomes are left for
        explicit reconciliation and never converted into a failed success.
        """
        with self._locked(publishing=True) as directory:
            publication_id = 'pub_' + uuid.uuid4().hex
            identity = os.fstat(directory)
            record = {
                'publication_id': publication_id, 'artifact_id': artifact_id,
                'root': str(self.root), 'root_dev': identity.st_dev, 'root_ino': identity.st_ino,
                'root_token': read_token(directory, _ROOT_TOKEN).decode('ascii'),
                'stage_name': f'.{publication_id}.stage', 'state': 'allocated',
                'job_id': job_id, 'attempt_id': attempt_id,
                'sources_json': json.dumps([source.to_dict() for source in sources]),
                'created_at': now(),
            }
            self.store.create_publication(record)
            try:
                self.checkpoint('intent_committed')
                descriptor = os.open(str(record['stage_name']),
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(descriptor, 'r+b') as staged:
                    create_token(staged.fileno(), _STAGE_TOKEN, publication_id.encode('ascii'))
                    os.fsync(staged.fileno())
                    identity = os.fstat(staged.fileno())
                    self.store.update_publication(publication_id, stage_dev=identity.st_dev,
                                                  stage_ino=identity.st_ino)
                    os.fsync(directory)
                    record = self.store.publication(publication_id)
                    self.checkpoint('stage_created')
                    self.checkpoint('before_stage_write')
                    writer(self.root / str(record['stage_name']), staged)
                    staged.flush()
                    self.checkpoint('stage_written')
                    if not self._owned(directory, str(record['stage_name']), record):
                        raise PublicationError('writer replaced its private staging file')
                    self.checkpoint('before_validation')
                    info = validate_image(staged)
                    self.checkpoint('validated')
                    artifact = factory(info, self.root / (artifact_id + (
                        '.png' if info.image_format == 'PNG' else '.jpg')))
                    if artifact.artifact_id != artifact_id:
                        raise PublicationError('artifact identity changed during publication')
                    self.checkpoint('before_file_sync')
                    os.fsync(staged.fileno())
                    self.checkpoint('file_synced')
                    self.store.update_publication(publication_id, state='ready',
                        final_name=Path(artifact.path).name,
                        artifact_json=json.dumps(artifact.to_dict(), sort_keys=True))
                    self.checkpoint('ready_committed')
                    record = self.store.publication(publication_id)
                    self._finish(directory, record)
                self.checkpoint('after_commit')
                self._clean_stage(directory, record)
                self.checkpoint('cleanup_complete')
                self.checkpoint('before_reply')
                return artifact
            except Exception as error:
                # Re-read the durable decision. A commit may have succeeded even
                # when its caller observed an exception or lost acknowledgement.
                record = self.store.publication(publication_id)
                if record['state'] == 'committed':
                    self._clean_stage(directory, record)
                    return self.store.get_artifact(artifact_id)
                if record['state'] == 'allocated':
                    self._abandon(directory, record, str(error))
                else:
                    self.store.update_publication(publication_id, error=str(error))
                raise PublicationError(f'{publication_id}: {error}; inspect/reconcile publication') from error

    @staticmethod
    def _artifact(record: dict[str, object]) -> Artifact:
        payload = json.loads(str(record['artifact_json']))
        payload['image_format'] = payload.pop('format')
        if payload.pop('origin', 'generated') == 'imported':
            return ImportedArtifact(**payload)
        return GenerationArtifact(**payload)

    @staticmethod
    def _matches(info: ImageInfo, artifact: Artifact) -> bool:
        return all(getattr(info, key) == getattr(artifact, key) for key in (
            'media_type', 'image_format', 'width', 'height', 'file_size', 'sha256'))

    def _finish(self, directory: int, record: dict[str, object]) -> None:
        """Replay a validated publication without invoking a generation adapter."""
        if (record['root_dev'], record['root_ino']) != self._identity(os.fstat(directory)):
            raise PublicationError('publication belongs to a different destination inode')
        artifact = self._artifact(record)
        final_name = str(record['final_name'])
        if final_name != Path(artifact.path).name or Path(artifact.path).parent != self.root:
            raise PublicationError('publication path is not its authoritative destination')
        self.checkpoint('before_publish')
        try:
            os.stat(final_name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            if not self._owned(directory, str(record['stage_name']), record):
                raise PublicationError('owned staging content is missing or replaced')
            os.link(str(record['stage_name']), final_name,
                    src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        if not self._owned(directory, final_name, record):
            raise PublicationError('final path collision: existing content is not owned by publication')
        self.checkpoint('file_published')
        # Decode and hash the final inode too, including on every recovery.
        descriptor = os.open(final_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        with os.fdopen(descriptor, 'rb') as content:
            observed = os.fstat(content.fileno())
            if (not stat.S_ISREG(observed.st_mode)
                or self._identity(observed) != (record['stage_dev'], record['stage_ino'])
                or read_token(content.fileno(), _STAGE_TOKEN) != str(record['publication_id']).encode('ascii')):
                raise PublicationError('published file changed while opening')
            if not self._matches(validate_image(content), artifact):
                raise PublicationError('published bytes do not match validated metadata')
            os.fsync(content.fileno())
            self.checkpoint('before_directory_sync')
            os.fsync(directory)
            self.checkpoint('directory_synced')
            self.checkpoint('before_commit')
            self._assert_root(directory)
            current = os.fstat(content.fileno())
            if (not self._owned(directory, final_name, record) or any(
                getattr(observed, field) != getattr(current, field)
                for field in ('st_size', 'st_mtime_ns', 'st_ctime_ns')
            )):
                raise PublicationError('published file changed before metadata commit')
            sources = tuple(ArtifactSource(**source) for source in json.loads(str(record['sources_json'])))
            # Keep the validated inode pinned until SQLite commits its identity.
            if isinstance(artifact, GenerationArtifact):
                self.store.complete_execution(artifact, now(),
                    publication_id=str(record['publication_id']), sources=sources)
            else:
                self.store.complete_import(artifact, str(record['publication_id']), sources)

    def integrity(self, artifact_id: str) -> dict[str, object]:
        """Observe current content without altering the immutable artifact record."""
        artifact = self.store.get_artifact(artifact_id)
        status, detail = 'ok', None
        try:
            with open_regular(Path(artifact.path)) as content:
                if not self._matches(validate_image(content), artifact):
                    status, detail = 'corrupt', 'stored content differs from immutable metadata'
        except FileNotFoundError:
            status, detail = 'missing', 'authoritative file is missing'
        except Exception as error:
            # Decoder and safe-open errors must remain inspectable, not trusted.
            status, detail = 'corrupt', str(error)
        checked = now()
        self.store.record_integrity(artifact_id, status, checked, detail)
        return {'artifact_id': artifact_id, 'status': status, 'checked_at': checked, 'detail': detail}

    def reconcile(self) -> dict[str, object]:
        """Recover owned journal entries and report unknown files without deleting them."""
        with self._locked() as directory:
            results: list[dict[str, object]] = []
            known = {'.artifact-publication.lock'}
            for record in self.store.publications(str(self.root)):
                known.add(str(record['stage_name']))
                if record['final_name']:
                    known.add(str(record['final_name']))
                result = {'publication_id': record['publication_id'], 'artifact_id': record['artifact_id']}
                try:
                    if (record['root_dev'], record['root_ino']) != self._identity(os.fstat(directory)):
                        raise PublicationError('publication destination identity changed')
                    if record['state'] == 'ready':
                        self._finish(directory, record)
                        record = self.store.publication(str(record['publication_id']))
                    if record['state'] == 'allocated':
                        cleanup = self._abandon(directory, record, 'interrupted before validated publication')
                        record = self.store.publication(str(record['publication_id']))
                    else:
                        cleanup = self._clean_stage(directory, record)
                        if record['state'] == 'abandoned' and record['job_id'] is not None:
                            self.store.fail_execution(str(record['job_id']), str(record['attempt_id']),
                                str(record['error']), now())
                    result.update(state=record['state'], cleanup=cleanup)
                except Exception as error:
                    # A failed response after commit is still a committed result.
                    current = self.store.publication(str(record['publication_id']))
                    result.update(state=current['state'], error=str(error))
                results.append(result)
            integrity = []
            for artifact in self.store.artifacts():
                if Path(artifact.path).parent == self.root:
                    known.add(Path(artifact.path).name)
                    integrity.append(self.integrity(artifact.artifact_id))
            orphans = []
            try:
                token = read_token(directory, _ROOT_TOKEN).decode('ascii')
                with self._cleanup_directory(directory, token, create=False) as cleanup:
                    known.add(_CLEANUP_DIRECTORY)
                    expected = {str(row['publication_id']) for row in self.store.publications(str(self.root))}
                    orphans.extend(f'{_CLEANUP_DIRECTORY}/{name}' for name in os.listdir(cleanup)
                                   if name not in expected)
            except (OSError, PublicationError):
                pass  # An unrecognized cleanup directory remains an orphan.
            orphans.extend(name for name in os.listdir(directory) if name not in known)
            orphans.sort()
            incomplete = bool(orphans) or any(item['status'] != 'ok' for item in integrity) or any(
                item['state'] not in {'committed', 'abandoned'} or 'error' in item
                or item.get('cleanup') not in {'removed_owned_stage', 'absent'} for item in results
            )
            return {'root': str(self.root), 'status': 'attention_required' if incomplete else 'complete',
                    'publications': results,
                    'integrity': integrity, 'orphan_files': orphans}
