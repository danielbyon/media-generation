"""Application-owned supervision of one direct local inference process.

The supervisor starts exactly one direct child without a shell, drains both
output pipes while the child runs, reaps the child, and records transport-level
facts: exit status, byte counts, complete output digests, and a bounded
text-free output classification. Captured output never reaches a persisted
record. It makes no claim about descendant processes, filesystem confinement,
or network isolation.

The execution service constructs the supervisor and binds it to one claimed
attempt, the exact argument vector and child environment produced by pre-dispatch
resolution, and an application-owned evidence authority. Adapter code receives
the bound supervisor and calls one of its process execution methods. The
supervisor itself spawns the process and writes launch and observation evidence;
an adapter cannot supply those facts or substitute a different invocation.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from .backend_provenance import (
    LAUNCH_SCHEMA,
    OBSERVED_SCHEMA,
    RECORD_SCHEMA_VERSION,
    OutputClassification,
    classify_output,
)
from .errors import BackendEvidenceError, BackendPreparationError

_CAPTURE_BYTES = 2048
_READ_BYTES = 65536
_PROBE_BYTES = 262144
_DEFAULT_DRAIN_TIMEOUT_SECONDS = 1.0
_PROMPT_ARGUMENTS = frozenset({"-p", "--prompt"})


@dataclass(frozen=True, slots=True)
class LaunchFact:
    """The observable fact that one direct child process started.

    ``pid`` identifies the application process supervising the direct child.
    The child's own process identifier is deliberately not part of the durable
    record because process identifiers are reused by the operating system and
    cannot prove identity later. ``argv`` and ``environment`` are the exact
    values passed to the spawn call, retained so a reader can compare them with
    the resolved pre-dispatch plan.
    """

    attempt_id: str
    pid: int
    monotonic_start_ns: int
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]

    def to_mapping(self) -> dict[str, object]:
        """Return the versioned launch record persisted by the service."""
        return {
            "schema": LAUNCH_SCHEMA,
            "schema_version": RECORD_SCHEMA_VERSION,
            "attempt_id": self.attempt_id,
            "listener_pid": self.pid,
            "monotonic_start_ns": self.monotonic_start_ns,
            "launched": True,
            "argv": list(self.argv),
            "environment": dict(self.environment),
        }


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    """Facts measured for one reaped direct child.

    The observation holds no captured output. It records byte counts, complete
    stream digests, and a bounded text-free classification, because subprocess
    stdout and stderr may repeat prompts or credentials. Stream fields describe
    only pipes the direct child inherited; nothing here identifies or counts
    descendant processes.
    """

    attempt_id: str
    exit_code: int | None
    signal: int | None
    duration_seconds: float
    stdout_bytes: int
    stderr_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_classification: str
    stderr_classification: str
    stdout_codes: tuple[str, ...]
    stderr_codes: tuple[str, ...]
    inherited_streams_retained_after_reap: bool
    stream_state_unknown: bool

    def to_mapping(self) -> dict[str, object]:
        """Return the versioned observation record persisted by the service."""

        return {
            "schema": OBSERVED_SCHEMA,
            "schema_version": RECORD_SCHEMA_VERSION,
            "attempt_id": self.attempt_id,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "direct_child_reaped": True,
            "duration_seconds": self.duration_seconds,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_classification": self.stdout_classification,
            "stderr_classification": self.stderr_classification,
            "stdout_codes": list(self.stdout_codes),
            "stderr_codes": list(self.stderr_codes),
            "process_tree_containment": False,
            "inherited_streams_retained_after_reap": (
                self.inherited_streams_retained_after_reap
            ),
            "stream_state_unknown": self.stream_state_unknown,
        }


class ExecutionEvidenceAuthority(ABC):
    """Application-owned persistence bound to one claimed attempt."""

    @property
    @abstractmethod
    def attempt_id(self) -> str:
        """Return the claimed attempt this authority is bound to."""

    @abstractmethod
    def verify_current(self) -> bool:
        """Return whether the bound claim still has current execution authority."""

    @abstractmethod
    def record_launch(self, fact: LaunchFact) -> None:
        """Persist one validated launch fact for the bound attempt."""

    @abstractmethod
    def record_observation(self, fact: ProcessObservation) -> None:
        """Persist one validated reaped-child fact for the bound attempt."""


class ManagedProcessControl:
    """Control one live direct child owned by a managed supervisor call.

    The control exposes only liveness, authority verification, and direct-child
    termination. It never reports process-tree containment or persists facts.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        authority: ExecutionEvidenceAuthority,
        listener_owner_pid: Callable[[str, int], int] | None = None,
    ) -> None:
        self._process = process
        self._authority = authority
        self._listener_owner_pid = listener_owner_pid
        self._lock = threading.Lock()
        self._termination_requested = False

    @property
    def pid(self) -> int:
        """Return the operating-system identifier of the direct child."""
        return self._process.pid

    def is_running(self) -> bool:
        """Return whether the direct child has not yet exited."""
        return self._process.poll() is None

    def require_listener_owner(self, host: str, port: int) -> None:
        """Require that the direct child uniquely owns one requested listener."""
        self.require_current()
        if not self.is_running():
            raise BackendEvidenceError("managed child exited before listener identity check")
        if self._listener_owner_pid is None:
            raise BackendEvidenceError("listener ownership proof is unavailable")
        try:
            owner_pid = self._listener_owner_pid(host, port)
        except BackendEvidenceError:
            raise
        except Exception as error:
            raise BackendEvidenceError("listener ownership proof failed") from error
        if (
            isinstance(owner_pid, bool)
            or not isinstance(owner_pid, int)
            or owner_pid != self._process.pid
        ):
            raise BackendEvidenceError(
                "loopback listener is not owned by the managed direct child"
            )
        self.require_current()
        if not self.is_running():
            raise BackendEvidenceError("managed child exited during listener identity check")

    def require_current(self) -> None:
        """Refuse a later protocol step after attempt authority is revoked."""
        if not self._authority.verify_current():
            raise BackendEvidenceError(
                "attempt authority was revoked while the managed child was live"
            )

    def terminate(self, *, timeout_seconds: float = 5.0) -> None:
        """Terminate and reap the direct child, escalating after one timeout."""
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 <= float(timeout_seconds) <= 60.0
        ):
            raise ValueError("timeout_seconds must be between 0 and 60")
        with self._lock:
            if self._termination_requested:
                return
            self._termination_requested = True
        if self._process.poll() is not None:
            return
        try:
            self._process.terminate()
        except OSError:
            pass
        deadline = time.monotonic() + float(timeout_seconds)
        while self._process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if self._process.poll() is None:
            try:
                self._process.kill()
            except OSError:
                pass


class _PipeCapture:
    """Drain one pipe while retaining a bounded prefix and a full digest."""

    def __init__(self) -> None:
        self.byte_count = 0
        self._prefix = bytearray()
        self._digest = hashlib.sha256()

    def consume(self, chunk: bytes) -> None:
        """Record one chunk without unbounded buffering."""

        self.byte_count += len(chunk)
        self._digest.update(chunk)
        remaining = _CAPTURE_BYTES - len(self._prefix)
        if remaining > 0:
            self._prefix.extend(chunk[:remaining])

    @property
    def sha256(self) -> str:
        """Return the digest of every byte read from the pipe."""

        return self._digest.hexdigest()

    @property
    def prefix(self) -> bytes:
        """Return the retained leading bytes, used only for classification.

        The prefix never reaches a persisted record. It exists so the
        supervisor can classify output in memory and then discard the text.
        """

        return bytes(self._prefix)

    def classification(
        self, *, prompt_markers: Sequence[str] = ()
    ) -> OutputClassification:
        """Return the bounded, text-free description of the captured prefix."""

        return classify_output(
            self.prefix,
            total_bytes=self.byte_count,
            prompt_markers=prompt_markers,
        )


class ProcessSupervisor:
    """Run one direct child and report post-reap evidence about it.

    Pipes are drained by non-blocking reads in a dedicated drain thread. After
    the direct child is reaped, the supervisor keeps reading for at most
    ``drain_timeout_seconds``. A descendant that inherited a pipe can keep it
    open indefinitely; the supervisor stops observing and closes its own ends
    instead of waiting for that descendant. No containment is claimed.

    The supervisor is bound to the exact argv and environment produced by the
    resolved execution plan. A different invocation is refused before a spawn.
    """

    def __init__(
        self,
        authority: ExecutionEvidenceAuthority,
        *,
        expected_argv: Sequence[str],
        expected_environment: Mapping[str, str],
        drain_timeout_seconds: float = _DEFAULT_DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(authority, ExecutionEvidenceAuthority):
            raise TypeError("authority must implement ExecutionEvidenceAuthority")
        if not isinstance(authority.attempt_id, str) or not authority.attempt_id:
            raise ValueError("authority must expose a non-empty attempt_id")
        argv = tuple(expected_argv)
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("expected argv must contain non-empty strings")
        if not isinstance(expected_environment, Mapping) or any(
            not isinstance(name, str) or not name or not isinstance(value, str)
            for name, value in expected_environment.items()
        ):
            raise ValueError("expected environment must map names to strings")
        if (
            isinstance(drain_timeout_seconds, bool)
            or not isinstance(drain_timeout_seconds, (int, float))
            or not 0.0 <= float(drain_timeout_seconds) <= 60.0
        ):
            raise ValueError("drain_timeout_seconds must be between 0 and 60")
        self._authority = authority
        self._expected_argv = argv
        self._expected_environment = dict(expected_environment)
        self._drain_timeout_seconds = float(drain_timeout_seconds)
        self._used = False
        self._process_started = False
        self._lock = threading.Lock()

    @property
    def attempt_id(self) -> str:
        """Return the claimed attempt this supervisor is bound to."""
        return self._authority.attempt_id

    @property
    def process_started(self) -> bool:
        """Return whether this supervisor successfully started a direct child."""
        return self._process_started

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        cwd: Path,
    ) -> ProcessObservation:
        """Spawn, drain, reap, and persist facts for one direct child.

        The launch recorder runs immediately after a successful spawn and
        before the supervisor waits. If it raises, the child is killed and
        reaped before the original error is re-raised. The observation recorder
        runs only after the direct child is reaped. A second call is refused.
        """
        actual_argv, actual_environment, started = self._begin_invocation(
            argv, env, already_used_message="supervisor run may be called only once"
        )
        process = self._spawn_and_record_launch(actual_argv, actual_environment, cwd)
        _, observation = self._finish_child(
            process,
            actual_argv,
            started,
        )
        return observation

    def run_managed(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        cwd: Path,
        session: Callable[[ManagedProcessControl], object],
        shutdown_timeout_seconds: float = 5.0,
        listener_owner_pid: Callable[[str, int], int] | None = None,
    ) -> tuple[object, ProcessObservation]:
        """Run one live direct child while an application callback owns IPC.

        Existing callers retain the finite ``run`` behavior. This additive path
        drains both streams concurrently, gives the callback only liveness and
        direct-child termination control, then reaps the exact child and writes
        the same launch and observation records. A failure after spawn still
        attempts bounded termination and records observation when reaping is
        proven. Descendant containment is never claimed.
        """
        if not callable(session):
            raise TypeError("session must be callable")
        if (
            isinstance(shutdown_timeout_seconds, bool)
            or not isinstance(shutdown_timeout_seconds, (int, float))
            or not 0.0 <= float(shutdown_timeout_seconds) <= 60.0
        ):
            raise ValueError("shutdown_timeout_seconds must be between 0 and 60")
        actual_argv, actual_environment, started = self._begin_invocation(
            argv,
            env,
            already_used_message="supervisor execution may be called only once",
        )
        process = self._spawn_and_record_launch(actual_argv, actual_environment, cwd)
        return self._finish_child(
            process,
            actual_argv,
            started,
            session=session,
            listener_owner_pid=listener_owner_pid,
            shutdown_timeout_seconds=float(shutdown_timeout_seconds),
        )

    def _begin_invocation(
        self,
        argv: Sequence[str],
        env: Mapping[str, str],
        *,
        already_used_message: str,
    ) -> tuple[tuple[str, ...], dict[str, str], float]:
        """Validate and claim the one exact invocation owned by this supervisor."""
        actual_argv = tuple(argv)
        if not actual_argv or any(
            not isinstance(item, str) or not item for item in actual_argv
        ):
            raise ValueError("process argv must contain non-empty strings")
        if not isinstance(env, Mapping) or any(
            not isinstance(name, str) or not name or not isinstance(value, str)
            for name, value in env.items()
        ):
            raise ValueError("process environment must map names to strings")
        actual_environment = dict(env)
        if actual_argv != self._expected_argv:
            raise BackendEvidenceError(
                "supervisor argv does not match the resolved pre-dispatch plan"
            )
        if actual_environment != self._expected_environment:
            raise BackendEvidenceError(
                "supervisor environment does not match the resolved pre-dispatch plan"
            )
        with self._lock:
            if self._used:
                raise RuntimeError(already_used_message)
            self._used = True
        if not self._authority.verify_current():
            raise BackendEvidenceError(
                "attempt ownership, epoch, or current-job authority is stale; "
                "no process was started"
            )
        return actual_argv, actual_environment, time.monotonic()

    def _spawn_and_record_launch(
        self,
        argv: tuple[str, ...],
        environment: Mapping[str, str],
        cwd: Path,
    ) -> subprocess.Popen[bytes]:
        """Start the direct child and persist its exact launch facts once."""
        try:
            process = subprocess.Popen(
                list(argv),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(environment),
                cwd=str(cwd),
                start_new_session=True,
                close_fds=True,
                bufsize=0,
            )
        except (OSError, ValueError) as error:
            raise BackendPreparationError(
                "engine_launch_failed",
                "the resolved engine invocation could not be started",
            ) from error
        self._process_started = True
        try:
            self._authority.record_launch(
                LaunchFact(
                    attempt_id=self._authority.attempt_id,
                    pid=os.getpid(),
                    monotonic_start_ns=time.monotonic_ns(),
                    argv=argv,
                    environment=tuple(sorted(environment.items())),
                )
            )
        except BaseException as error:
            if not self._terminate_after_drain_failure(process):
                raise BackendEvidenceError(
                    "direct child termination could not be proven after launch recording failed"
                ) from error
            raise
        return process

    def _finish_child(
        self,
        process: subprocess.Popen[bytes],
        argv: tuple[str, ...],
        started: float,
        *,
        session: Callable[[ManagedProcessControl], object] | None = None,
        listener_owner_pid: Callable[[str, int], int] | None = None,
        shutdown_timeout_seconds: float = 5.0,
    ) -> tuple[object, ProcessObservation]:
        """Drain, reap, and persist common direct-child completion evidence.

        ``run`` leaves a finite process to exit on its own. ``run_managed``
        executes its protocol callback while this same drain and evidence path
        runs, then terminates the direct child within the supplied bound.
        """
        stdout_capture = _PipeCapture()
        stderr_capture = _PipeCapture()
        drain_result: list[tuple[int, bool, bool]] = []
        drain_error: list[BaseException] = []

        def drain() -> None:
            try:
                drain_result.append(
                    self._drain_until_reaped(
                        process,
                        stdout_capture=stdout_capture,
                        stderr_capture=stderr_capture,
                    )
                )
            except BaseException as error:
                drain_error.append(error)

        drain_thread = threading.Thread(
            target=drain,
            name=f"managed-process-drain-{self._authority.attempt_id}",
            daemon=True,
        )
        try:
            drain_thread.start()
        except BaseException as error:
            if not self._terminate_after_drain_failure(process):
                raise BackendEvidenceError(
                    "direct child termination could not be proven after drain startup failed"
                ) from error
            raise
        callback_result: object = None
        callback_error: BaseException | None = None
        termination_error: BaseException | None = None
        if session is None:
            try:
                drain_thread.join()
            except BaseException:
                self._terminate_after_drain_failure(process)
                raise
        else:
            control = ManagedProcessControl(
                process, self._authority, listener_owner_pid
            )
            try:
                callback_result = session(control)
            except BaseException as error:
                callback_error = error
            finally:
                try:
                    control.terminate(timeout_seconds=shutdown_timeout_seconds)
                except BaseException as error:
                    termination_error = error
                drain_thread.join(
                    timeout=shutdown_timeout_seconds + self._drain_timeout_seconds + 5.0
                )
                if drain_thread.is_alive():
                    try:
                        process.kill()
                    except OSError:
                        pass
                    drain_thread.join(timeout=2.0)

        if drain_error:
            self._terminate_after_drain_failure(process)
            raise drain_error[0]
        if not drain_result:
            raise BackendEvidenceError(
                "direct-child stream draining did not reach a reaped result"
            )
        if termination_error is not None and callback_error is None:
            raise termination_error
        returncode, inherited_streams_retained, stream_state_unknown = drain_result[0]
        duration = max(0.0, time.monotonic() - started)
        exit_code = returncode if returncode >= 0 else None
        signal_number = -returncode if returncode < 0 else None
        prompt_markers = _prompt_markers(argv)
        stdout_classification = stdout_capture.classification(
            prompt_markers=prompt_markers
        )
        stderr_classification = stderr_capture.classification(
            prompt_markers=prompt_markers
        )
        observation = ProcessObservation(
            attempt_id=self._authority.attempt_id,
            exit_code=exit_code,
            signal=signal_number,
            duration_seconds=duration,
            stdout_bytes=stdout_capture.byte_count,
            stderr_bytes=stderr_capture.byte_count,
            stdout_sha256=stdout_capture.sha256,
            stderr_sha256=stderr_capture.sha256,
            stdout_classification=stdout_classification.classification,
            stderr_classification=stderr_classification.classification,
            stdout_codes=stdout_classification.codes,
            stderr_codes=stderr_classification.codes,
            inherited_streams_retained_after_reap=inherited_streams_retained,
            stream_state_unknown=stream_state_unknown,
        )
        self._authority.record_observation(observation)
        if callback_error is not None:
            raise callback_error
        return callback_result, observation

    def _drain_until_reaped(
        self,
        process: subprocess.Popen[bytes],
        *,
        stdout_capture: _PipeCapture,
        stderr_capture: _PipeCapture,
    ) -> tuple[int, bool, bool]:
        """Drain pipes until the child is reaped and report stream state.

        Returns the waited process status, whether an inherited pipe still had
        a live writer after the bounded post-reap drain, and whether any read
        failed in a way that left stream state unknown. Output read after the
        child is reaped is recorded only while the deadline is open; bytes
        still buffered by a surviving process never have to be read for
        supervision to finish.

        Only an empty read establishes end of stream. Any other read failure
        leaves uncertainty for its affected pipe and prevents the attempt from
        serving as termination proof. The selector is created inside the
        protected block, so construction or registration failure still runs
        cleanup when a selector exists. The supervisor's outer failure path
        kills, reaps, and closes the direct child.
        """

        stdout = process.stdout
        stderr = process.stderr
        if stdout is None or stderr is None:
            raise RuntimeError("supervised process is missing an output pipe")
        os.set_blocking(stdout.fileno(), False)
        os.set_blocking(stderr.fileno(), False)
        selector: selectors.BaseSelector | None = None
        open_streams = 0
        returncode: int | None = None
        deadline: float | None = None
        stream_state_unknown = False
        try:
            selector = selectors.DefaultSelector()
            selector.register(stdout, selectors.EVENT_READ, stdout_capture)
            selector.register(stderr, selectors.EVENT_READ, stderr_capture)
            open_streams = 2
            while True:
                if returncode is None:
                    returncode = process.poll()
                    if returncode is not None:
                        deadline = time.monotonic() + self._drain_timeout_seconds
                timeout = 0.05
                if returncode is not None and deadline is not None:
                    remaining = deadline - time.monotonic()
                    if open_streams == 0 or remaining <= 0:
                        break
                    timeout = min(timeout, remaining)
                for key, _ in selector.select(timeout):
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), _READ_BYTES)
                    except BlockingIOError:
                        continue
                    except Exception:
                        stream_state_unknown = True
                        selector.unregister(stream)
                        open_streams -= 1
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        open_streams -= 1
                    else:
                        key.data.consume(chunk)
            inherited, probe_unknown = self._streams_still_open(
                ((stdout, stdout_capture), (stderr, stderr_capture))
            )
            return process.wait(), inherited, stream_state_unknown or probe_unknown
        finally:
            if selector is not None:
                selector.close()
            for stream in (stdout, stderr):
                try:
                    stream.close()
                except OSError:
                    pass

    @staticmethod
    def _streams_still_open(
        streams: Sequence[tuple[BinaryIO, _PipeCapture]],
    ) -> tuple[bool, bool]:
        """Probe pipes after reaping, reporting a live writer and uncertainty.

        Every chunk read by the probe is consumed by the same capture used
        during normal draining, so recorded byte counts and SHA-256 values
        cover every byte the supervisor read from the pipes. The probe stays
        bounded and never blocks: a blocking read on a pipe with a live writer,
        or an exhausted probe budget, means a writer is still attached.

        Only an empty read establishes end of stream. ``EOFError``,
        ``ValueError``, ``EBADF``, and every other unexpected read failure leave
        stream state unknown, so an unsuccessful read is not evidence that the
        pipe closed normally.
        """

        stream_state_unknown = False
        for stream, capture in streams:
            budget = _PROBE_BYTES
            while True:
                try:
                    chunk = os.read(stream.fileno(), _READ_BYTES)
                except BlockingIOError:
                    return True, stream_state_unknown
                except Exception:
                    stream_state_unknown = True
                    break
                if not chunk:
                    break
                capture.consume(chunk)
                budget -= len(chunk)
                if budget <= 0:
                    return True, stream_state_unknown
        return False, stream_state_unknown

    @staticmethod
    def _terminate_after_drain_failure(process: subprocess.Popen[bytes]) -> bool:
        """Kill and reap the direct child, returning whether reaping was proven."""
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                reaped = process.poll() is not None
            except OSError:
                reaped = False
        else:
            reaped = process.returncode is not None
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        return reaped


def _prompt_markers(argv: Sequence[str]) -> tuple[str, ...]:
    """Return request text carried on the command line, for in-memory checks.

    Only argument values are returned. The supervisor compares them with
    captured output to decide whether the engine echoed the request, and never
    persists them.
    """

    markers = []
    for index in range(len(argv) - 1):
        if argv[index] in _PROMPT_ARGUMENTS:
            markers.append(argv[index + 1])
    return tuple(markers)
