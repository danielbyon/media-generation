"""Adversarial local HTTPS tests for the private acquisition transport."""

from __future__ import annotations

import contextlib
import email.parser
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest

from media_generation import candidate
from media_generation import _candidate_transport as transport
from test_candidate_preparation import linux_acquisition_on_darwin


@pytest.fixture
def acquisition_descriptors(monkeypatch: pytest.MonkeyPatch) -> set[int]:
    """Track owner close events; server sockets can reuse a closed FD number."""
    live: set[int] = set()
    real_close = os.close

    def close(descriptor: int) -> None:
        real_close(descriptor)
        live.discard(descriptor)

    monkeypatch.setattr(os, "close", close)
    return live


@pytest.fixture
def tls_material(tmp_path: Path) -> tuple[Path, ssl.SSLContext]:
    certificate = tmp_path / "localhost.pem"
    private_key = tmp_path / "localhost.key"
    certificate.write_text(_CERTIFICATE, encoding="ascii")
    private_key.write_text(_PRIVATE_KEY, encoding="ascii")
    private_key.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    return certificate, context


def _install_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, prefix: str = "",
    *, preload: int = 0,
) -> list[subprocess.Popen[bytes]]:
    """Inject system stalls; optionally preload workers for a phase test.

    Preloaded workers wait for their requests on stdin and have done no network
    work. This isolates short phase deadlines from interpreter startup. The
    startup cancellation tests exercise cold workers separately.
    """
    wrapper = tmp_path / "worker.py"
    ready = tmp_path / "worker-ready"
    wrapper.write_text(
        "import os, runpy\nfrom pathlib import Path\n" + prefix + "\n_module = runpy.run_path("
        + repr(str(Path(transport.__file__).resolve()))
        + ")\nPath(" + repr(str(ready)) + " + '.' + str(os.getpid())).touch()\n"
        + "_module['_worker_main']()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        transport, "_worker_command",
        lambda: [sys.executable, "-I", "-S", "-u", str(wrapper)],
    )
    processes: list[subprocess.Popen[bytes]] = []
    original = subprocess.Popen
    preloaded: list[subprocess.Popen[bytes]] = []
    for _ in range(preload):
        process = original(
            transport._worker_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True, env={}, cwd="/",
            start_new_session=True,
        )
        processes.append(process)
        preloaded.append(process)
        ready_file = ready.with_name(f"{ready.name}.{process.pid}")
        bootstrap_deadline = time.monotonic() + 3
        while not ready_file.exists():
            if process.poll() is not None or time.monotonic() >= bootstrap_deadline:
                with _cleanup_test_workers(processes):
                    pytest.fail("test transport worker did not finish isolated startup")
            time.sleep(0.005)

    def start(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        if preloaded:
            return preloaded.pop(0)
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", start)
    return processes


@contextlib.contextmanager
def _cleanup_test_workers(processes: list[subprocess.Popen[bytes]]) -> Iterator[None]:
    """Reap a preloaded fixture even if server setup or an assertion fails."""
    try:
        yield
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def _assert_reaped(processes: list[subprocess.Popen[bytes]]) -> None:
    assert processes
    for process in processes:
        assert process.poll() is not None
        assert process.wait(timeout=0) is not None
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)
        assert process.stdin is not None and process.stdin.closed
        assert process.stdout is not None and process.stdout.closed


def _trust_certificate(certificate: Path) -> str:
    """Prepare the test trust context before a preloaded worker is ready."""
    return (
        "import ssl\n"
        "_test_context = ssl.create_default_context(cafile="
        + repr(str(certificate)) + ")\n"
        "ssl.create_default_context = lambda: _test_context\n"
    )


def _delay_tls_context_creation(seconds: float) -> str:
    """Model slow test trust-store setup without delaying the network phase."""
    return (
        "import ssl, time\n"
        "_undelayed_context = ssl.create_default_context\n"
        "def _delayed_context(*args, **kwargs):\n"
        f"    time.sleep({seconds!r})\n"
        "    return _undelayed_context(*args, **kwargs)\n"
        "ssl.create_default_context = _delayed_context\n"
    )


def _preconnect_https(url: str) -> str:
    """Finish TCP/TLS setup before a parser test starts its absolute deadline.

    The worker still sends the request and parses the real TLS response under
    one unchanged deadline. Cold connection cancellation is covered separately.
    The prefix must follow ``_trust_certificate`` to use its test trust context.
    """
    return (
        "import http.client\nfrom urllib.parse import urlsplit\n"
        "_test_target = urlsplit(" + repr(url) + ")\n"
        "_prepared_connection = http.client.HTTPSConnection(\n"
        "    _test_target.hostname, _test_target.port,\n"
        "    context=_test_context, timeout=3)\n"
        "_prepared_connection.connect()\n"
        "def _use_prepared_connection(self):\n"
        "    self.sock = _prepared_connection.sock\n"
        "    _prepared_connection.sock = None\n"
        "    if self.sock is None:\n"
        "        raise AssertionError('prepared TLS connection already consumed')\n"
        "    self.sock.settimeout(self.timeout)\n"
        "http.client.HTTPSConnection.connect = _use_prepared_connection\n"
    )


def _stall_phase(phase: str, marker: Path) -> str:
    """Block an actual worker at an otherwise uninterruptible system boundary."""
    if phase == "startup":
        return (
            "import time\nfrom pathlib import Path\n"
            "Path(" + repr(str(marker)) + ").write_text('entered')\n"
            "time.sleep(30)\n"
        )
    target = {
        "dns": "socket.getaddrinfo",
        "connect": "socket.socket.connect",
        "tls": "ssl.SSLContext.wrap_socket",
        "send": "ssl.SSLSocket.sendall",
    }[phase]
    return (
        "import socket, ssl, time\nfrom pathlib import Path\n"
        "def _blocked(*args, **kwargs):\n"
        "    Path(" + repr(str(marker)) + ").write_text('entered')\n"
        "    time.sleep(30)\n"
        + target + " = _blocked\n"
    )


@contextlib.contextmanager
def _server(
    context: ssl.SSLContext, handler: Any
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Serve controlled TLS exchanges and join every test-owned thread."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.05)
    stop = threading.Event()
    observations: dict[str, Any] = {"requests": [], "connections": [], "errors": []}

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            observations["connections"].append(raw)
            raw.settimeout(1)
            try:
                with context.wrap_socket(raw, server_side=True) as connection:
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        part = connection.recv(4096)
                        if not part:
                            break
                        request.extend(part)
                    if request:
                        observations["requests"].append(bytes(request))
                        handler(connection, bytes(request), stop, observations)
            except (OSError, ssl.SSLError) as error:
                observations["errors"].append(type(error).__name__)
            finally:
                raw.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{listener.getsockname()[1]}/artifact", observations
    finally:
        stop.set()
        listener.close()
        for connection in observations["connections"]:
            connection.close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _drip(connection: ssl.SSLSocket, payload: bytes, stop: threading.Event) -> None:
    for byte in payload:
        connection.sendall(bytes([byte]))
        if stop.wait(0.04):
            return


def _slow_response(phase: str, body: bytes = b"abcdefghijklmnopqrst") -> Any:
    def respond(
        connection: ssl.SSLSocket, request: bytes, stop: threading.Event,
        observations: dict[str, Any],
    ) -> None:
        observations["phase_started"] = time.monotonic()
        if phase == "status":
            _drip(connection, b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx", stop)
        elif phase == "headers":
            connection.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            _drip(connection, b"abcdefghijklmnop\r\nContent-Length: 1\r\n\r\nx", stop)
        elif phase == "interim":
            for _ in range(20):
                connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                if stop.wait(0.04):
                    return
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
        elif phase in {"extension", "chunk_size"}:
            if phase == "chunk_size":
                connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                _drip(connection, b"0000000000000001\r\nx\r\n0\r\n\r\n", stop)
                return
            connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;")
            _drip(connection, b"abcdefghijklmnop\r\nx\r\n0\r\n\r\n", stop)
        elif phase == "trailers":
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Slow: "
            )
            _drip(connection, b"abcdefghijklmnop\r\n\r\n", stop)
        elif phase in {"body", "eof", "chunk_body"}:
            if phase == "body":
                headers = b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            elif phase == "chunk_body":
                headers = b"Transfer-Encoding: chunked\r\n"
            else:
                headers = b"Connection: close\r\n"
            connection.sendall(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n")
            if phase == "chunk_body":
                connection.sendall(f"{len(body):x}\r\n".encode())
            _drip(connection, body, stop)
        else:
            raise AssertionError(phase)
    return respond


@pytest.mark.parametrize(
    "phase", ["status", "headers", "interim", "chunk_size", "extension",
              "trailers", "body", "eof", "chunk_body"]
)
def test_slow_http_parsing_cannot_extend_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    phase: str,
    record_property: Any,
) -> None:
    """A peer sending every 40 ms cannot retain a 100 ms acquisition."""
    certificate, context = tls_material
    slow_connection = (
        "import http.client, time\n"
        "_real_connect = http.client.HTTPSConnection.connect\n"
        "def _slow_connect(self):\n"
        "    time.sleep(0.2)\n"
        "    _real_connect(self)\n"
        "http.client.HTTPSConnection.connect = _slow_connect\n"
    )
    with _server(context, _slow_response(phase)) as (url, observations):
        processes = _install_worker(
            tmp_path, monkeypatch,
            _trust_certificate(certificate) + slow_connection + _preconnect_https(url),
            preload=1,
        )
        with _cleanup_test_workers(processes):
            assert len(observations["connections"]) == 1
            assert observations["requests"] == []
            response = None
            failure: BaseException | None = None
            started = time.monotonic()
            try:
                response = candidate._acquisition._open_remote(
                    url, headers={}, timeout_seconds=0.1
                )
                while response.read(64):
                    pass
            except TimeoutError as error:
                failure = error
            finally:
                if response is not None:
                    response.close()
            elapsed = time.monotonic() - started
            record_property("deadline_elapsed_seconds", elapsed)
            assert observations["phase_started"] >= started
            assert isinstance(failure, TimeoutError), "slow parsing escaped the deadline"
            assert elapsed < 0.3, f"100 ms deadline returned after {elapsed:.4f}s"
            _assert_reaped(processes)


@pytest.mark.parametrize("phase", ["dns", "connect", "tls", "send"])
def test_deadline_kills_and_reaps_stalled_network_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    phase: str,
    record_property: Any,
) -> None:
    certificate, context = tls_material
    marker = tmp_path / "entered-phase"
    startup_delay = "import time\ntime.sleep(0.2)\n" if phase == "send" else ""
    context_delay = _delay_tls_context_creation(0.2) if phase == "send" else ""
    processes = _install_worker(
        tmp_path, monkeypatch,
        startup_delay + context_delay + _trust_certificate(certificate) + _stall_phase(phase, marker),
        preload=1,
    )
    with _cleanup_test_workers(processes), _server(context, _slow_response("headers")) as (url, _):
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            candidate._acquisition._open_remote(url, headers={}, timeout_seconds=0.15)
        elapsed = time.monotonic() - started
        record_property("deadline_elapsed_seconds", elapsed)
        assert marker.read_text() == "entered"
        assert elapsed < 0.35
        _assert_reaped(processes)
        assert processes[0].returncode == -9


@pytest.mark.parametrize(
    "phase", ["startup", "dns", "dns_budget", "connect", "tls", "send", "status", "headers", "interim",
              "chunk_size", "extension", "trailers", "body", "eof",
              "chunk_body", "redirect", "retry"]
)
def test_preparation_timeout_cleans_staging_and_releases_journal_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    phase: str,
    record_property: Any,
    acquisition_descriptors: set[int],
) -> None:
    """A cancelled transport cannot publish or retain acquisition resources."""
    from test_candidate_preparation import (
        _acquisition_config, _assert_descriptor_closed, _fixture, _payload,
        _rewrite, _tree_snapshot, _trusted_evidence,
    )

    acquisition = candidate._acquisition
    certificate, context = tls_material
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()
    initial_files = _tree_snapshot(artifact.parent)
    manifest = tmp_path / "prepared.json"
    journal = tmp_path / "journal.json"
    marker = tmp_path / "stalled-phase"
    context_delay = {"send": 0.3, "retry": 0.15}.get(phase)
    prefix = (
        (_delay_tls_context_creation(context_delay) if context_delay is not None else "")
        + _trust_certificate(certificate)
    )
    if phase in {"send", "retry"}:
        # Model a slow interpreter startup independently of the phase deadline.
        prefix = "import time\ntime.sleep(0.2)\n" + prefix
    if phase in {"startup", "dns", "dns_budget", "connect", "tls", "send"}:
        prefix += _stall_phase("dns" if phase == "dns_budget" else phase, marker)
    preload = 0 if phase == "startup" else 2 if phase in {"redirect", "retry"} else 1
    processes = _install_worker(tmp_path, monkeypatch, prefix, preload=preload)
    expirations: list[float] = []
    deadlines: list[float] = []
    real_start = acquisition._TransferDeadline.start
    real_open = acquisition._open_remote

    def start(cls: Any, timeout_seconds: float) -> Any:
        deadline = real_start(timeout_seconds)
        deadlines.append(deadline.expires_at)
        return deadline

    def open_remote(*args: Any, **kwargs: Any) -> Any:
        expirations.append(kwargs["deadline"].expires_at)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(acquisition._TransferDeadline, "start", classmethod(start))
    monkeypatch.setattr(acquisition, "_open_remote", open_remote)
    parent_fds: list[int] = []
    journal_fds: list[int] = []
    real_target = acquisition._open_output_target
    real_lock = acquisition._JournalLock.acquire

    def open_target(*args: Any, **kwargs: Any) -> Any:
        target = real_target(*args, **kwargs)
        parent_fds.append(target.parent_fd)
        acquisition_descriptors.add(target.parent_fd)
        return target

    def acquire_lock(cls: Any, *args: Any, **kwargs: Any) -> Any:
        lock = real_lock(*args, **kwargs)
        journal_fds.append(lock.descriptor)
        acquisition_descriptors.add(lock.descriptor)
        return lock

    monkeypatch.setattr(acquisition, "_open_output_target", open_target)
    monkeypatch.setattr(acquisition._JournalLock, "acquire", classmethod(acquire_lock))
    staging_fds: list[int] = []
    real_staging = acquisition._open_staging_file

    def open_staging(parent_fd: int) -> Any:
        stage = real_staging(parent_fd)
        staging_fds.extend((parent_fd, stage.descriptor))
        acquisition_descriptors.update((parent_fd, stage.descriptor))
        return stage

    monkeypatch.setattr(acquisition, "_open_staging_file", open_staging)

    def respond(
        connection: ssl.SSLSocket, request: bytes, stop: threading.Event,
        observations: dict[str, Any],
    ) -> None:
        if phase in {"redirect", "retry"} and len(observations["requests"]) == 1:
            if phase == "redirect":
                if stop.wait(0.04):
                    return
                connection.sendall(
                    b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
                )
            else:
                connection.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
        else:
            slow_phase = phase if phase in {
                "status", "headers", "interim", "chunk_size", "extension",
                "trailers", "body", "eof", "chunk_body"
            } else "headers"
            _slow_response(slow_phase, body)(connection, request, stop, observations)

    with _cleanup_test_workers(processes), _server(context, respond) as (url, observations):
        payload = _payload(declaration)
        payload["acquisition"]["sources"][0]["url"] = url
        _rewrite(declaration, payload)
        config = _acquisition_config(
            tmp_path, timeout_seconds=0.25, max_attempts=2,
            max_total_bytes=len(body) * (1 if phase == "dns_budget" else 2),
            allowed_origins=[url.rsplit("/", 1)[0]],
            credentials=[{"origin": url.rsplit("/", 1)[0],
                          "headers": {"Authorization": "Bearer transport-secret"}}],
        )
        with pytest.raises(candidate.CandidateAcquisitionError, match="transfer_timeout"):
            candidate.prepare_candidate(
                declaration, manifest_output=manifest, journal_output=journal,
                acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
            )
        finished = time.monotonic()
        assert len(deadlines) == 1
        elapsed = finished - (deadlines[0] - 0.25)
        record_property("deadline_elapsed_seconds", elapsed)
        assert elapsed < 0.43
        assert expirations and set(expirations) == set(deadlines)
        _assert_reaped(processes)
        if phase in {"startup", "dns", "dns_budget", "connect", "tls", "send"}:
            assert marker.read_text() == "entered"
        if phase in {"redirect", "retry"}:
            assert len(observations["requests"]) == 2
            assert len(processes) == 2
        assert not artifact.exists() and not manifest.exists()
        assert _tree_snapshot(artifact.parent) == initial_files
        assert not list(artifact.parent.glob(".t07-*"))
        events = _payload(journal)
        assert events["status"] != "ready"
        assert events["events"][-1]["code"] == "transfer_timeout"
        if phase == "dns_budget":
            assert len(processes) == 1
            assert [event["state"] for event in events["events"]] == [
                "attempted", "failed",
            ]
        assert not any(event["state"] == "succeeded" for event in events["events"])
        assert "transport-secret" not in journal.read_text()
        assert journal_fds and parent_fds and staging_fds
        assert not acquisition_descriptors
        with journal.with_name(".journal.json.lock").open("rb") as handle:
            acquisition.fcntl.flock(
                handle.fileno(), acquisition.fcntl.LOCK_EX | acquisition.fcntl.LOCK_NB
            )
            acquisition.fcntl.flock(handle.fileno(), acquisition.fcntl.LOCK_UN)


def test_http_retry_exhaustion_reaps_every_response_without_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
) -> None:
    from test_candidate_preparation import (
        _acquisition_config, _fixture, _payload, _rewrite, _tree_snapshot, _trusted_evidence,
    )

    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body_size = artifact.stat().st_size
    artifact.unlink()
    initial = _tree_snapshot(artifact.parent)

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")

    with _server(context, respond) as (url, observations):
        payload = _payload(declaration)
        payload["acquisition"]["sources"][0]["url"] = url
        _rewrite(declaration, payload)
        config = _acquisition_config(
            tmp_path, timeout_seconds=1, max_attempts=2,
            max_total_bytes=body_size * 2, allowed_origins=[url.rsplit("/", 1)[0]],
        )
        started = time.monotonic()
        with pytest.raises(candidate.CandidateAcquisitionError, match="http_503"):
            candidate.prepare_candidate(
                declaration, manifest_output=tmp_path / "prepared.json",
                journal_output=tmp_path / "journal.json", acquire=True,
                acquisition_config=config, trusted_evidence=_trusted_evidence(),
            )
        assert time.monotonic() - started < 1
        assert len(observations["requests"]) == 2
        _assert_reaped(processes)
        assert _tree_snapshot(artifact.parent) == initial
        assert not (tmp_path / "prepared.json").exists()
        journal = _payload(tmp_path / "journal.json")
        assert [(event["state"], event["attempt"]) for event in journal["events"]] == [
            ("attempted", 1), ("failed", 1), ("attempted", 2), ("failed", 2),
        ]
        with (tmp_path / ".journal.json.lock").open("rb") as handle:
            candidate._acquisition.fcntl.flock(
                handle.fileno(), candidate._acquisition.fcntl.LOCK_EX
                | candidate._acquisition.fcntl.LOCK_NB,
            )


def test_verified_https_redirect_scopes_credentials_and_ignores_environment_proxy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
) -> None:
    from test_candidate_preparation import (
        _acquisition_config, _fixture, _payload, _rewrite, _trusted_evidence,
    )

    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()

    def target(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body
        )

    with _server(context, target) as (target_url, target_observations):
        def source(connection: Any, request: Any, stop: Any, observations: Any) -> None:
            connection.sendall(
                b"HTTP/1.1 302 Found\r\nLocation: " + target_url.encode()
                + b"\r\nContent-Length: 0\r\n\r\n"
            )

        with _server(context, source) as (source_url, source_observations):
            payload = _payload(declaration)
            payload["acquisition"]["sources"][0]["url"] = source_url
            _rewrite(declaration, payload)
            source_origin, target_origin = (
                url.rsplit("/", 1)[0] for url in (source_url, target_url)
            )
            config = _acquisition_config(
                tmp_path, timeout_seconds=1, allowed_origins=[source_origin, target_origin],
                credentials=[
                    {"origin": source_origin, "headers": {"Authorization": "Bearer source-secret"}},
                    {"origin": target_origin, "headers": {"Authorization": "Bearer target-secret"}},
                ],
            )
            report = candidate.prepare_candidate(
                declaration, manifest_output=tmp_path / "prepared.json",
                journal_output=tmp_path / "journal.json", acquire=True,
                acquisition_config=config, trusted_evidence=_trusted_evidence(),
            )
            assert report["status"] == "ready"
            assert artifact.read_bytes() == body
            assert len(source_observations["requests"]) == 1
            assert len(target_observations["requests"]) == 1
            first = source_observations["requests"][0]
            second = target_observations["requests"][0]
            assert first.startswith(b"GET /artifact HTTP/1.1\r\n")
            assert second.startswith(b"GET /artifact HTTP/1.1\r\n")
            assert b"Authorization: Bearer source-secret\r\n" in first
            assert b"Authorization: Bearer target-secret\r\n" in second
            assert b"source-secret" not in second
            assert b"target-secret" not in first
            assert first.endswith(b"\r\n\r\n") and second.endswith(b"\r\n\r\n")
            for output in ("prepared.json", "journal.json"):
                document = (tmp_path / output).read_text()
                assert "source-secret" not in document and "target-secret" not in document
            _assert_reaped(processes)


@pytest.mark.parametrize("mismatch", [False, True], ids=["untrusted", "hostname"])
def test_transport_rejects_untrusted_certificate_and_wrong_hostname(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    mismatch: bool,
) -> None:
    certificate, context = tls_material
    prefix = _trust_certificate(certificate) if mismatch else ""
    if mismatch:
        prefix += (
            "import socket\n_getaddrinfo = socket.getaddrinfo\n"
            "socket.getaddrinfo = lambda host, *a, **kw: _getaddrinfo('127.0.0.1', *a, **kw)\n"
        )
    processes = _install_worker(tmp_path, monkeypatch, prefix)
    with _server(context, _slow_response("body")) as (url, observations):
        if mismatch:
            url = url.replace("127.0.0.1", "wrong.invalid")
        with pytest.raises(OSError, match="transport failed") as error:
            candidate._acquisition._open_remote(
                url, headers={"Authorization": "Bearer certificate-secret"}, timeout_seconds=1
            )
        assert "certificate-secret" not in str(error.value)
        assert not observations["requests"]
        _assert_reaped(processes)


def test_worker_isolation_and_verified_tls_sni(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
) -> None:
    """Project descriptors/environment stay local; verified HTTPS retains SNI."""
    certificate, context = tls_material
    monkeypatch.setenv("T07_PROJECT_SECRET", "synthetic-project-secret")
    names: list[str | None] = []
    context.set_servername_callback(lambda _socket, name, _context: names.append(name))

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with (tmp_path / "private-project-file").open("w+b") as project:
        descriptor = project.fileno()
        os.set_inheritable(descriptor, True)
        identity = os.fstat(descriptor)
        prefix = (
            "import os, sys\n"
            "assert 'T07_PROJECT_SECRET' not in os.environ\n"
            "assert sys.flags.isolated and sys.flags.no_site\n"
            "assert os.getcwd() == '/'\n"
            "try:\n"
            f"    facts = os.fstat({descriptor})\n"
            f"    assert (facts.st_dev, facts.st_ino) != {(identity.st_dev, identity.st_ino)!r}\n"
            "except OSError:\n"
            "    pass\n"
            + _trust_certificate(certificate)
        )
        processes = _install_worker(tmp_path, monkeypatch, prefix)
        with _server(context, respond) as (url, observations):
            response = transport.open_response(
                url.replace("127.0.0.1", "localhost"),
                headers={"Authorization": "Bearer synthetic-credential"},
                expires_at=time.monotonic() + 1,
            )
            try:
                assert response.status == 200
                assert response.read(2) == b"ok"
                assert response.read(2) == b""
            finally:
                response.close()
            assert names == ["localhost"]
            assert b"Authorization: Bearer synthetic-credential\r\n" in observations["requests"][0]
            assert "synthetic-credential" not in repr(processes[0].args)
            _assert_reaped(processes)
        assert os.fstat(descriptor).st_ino == identity.st_ino


def test_parent_rejects_oversized_transport_control_packet_and_reaps_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    processes = _install_worker(
        tmp_path, monkeypatch,
        "import sys, struct, time\n"
        "sys.stdout.buffer.write(struct.pack('!cI', b'H', 65537))\n"
        "sys.stdout.buffer.flush()\ntime.sleep(30)\n",
    )
    with pytest.raises(OSError, match="packet exceeds limit"):
        transport.open_response("https://example.invalid/", headers={}, expires_at=time.monotonic() + 1)
    _assert_reaped(processes)


def test_worker_rejects_oversized_http_header_without_retaining_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
) -> None:
    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 17000 + b"\r\n\r\n")

    with _server(context, respond) as (url, _):
        with pytest.raises(OSError, match="transport failed"):
            candidate._acquisition._open_remote(url, headers={}, timeout_seconds=1)
        _assert_reaped(processes)


def test_timeout_terminates_tls_socket_as_observed_by_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
) -> None:
    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))
    peer_closed = threading.Event()

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
        try:
            if connection.recv(1) == b"":
                peer_closed.set()
        except (ConnectionResetError, ssl.SSLEOFError):
            peer_closed.set()

    with _server(context, respond) as (url, _):
        response = candidate._acquisition._open_remote(url, headers={}, timeout_seconds=0.15)
        with pytest.raises(TimeoutError):
            response.read(1)
        assert peer_closed.wait(timeout=0.2)
        _assert_reaped(processes)


def test_expired_artifact_deadline_does_not_start_a_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("expired artifact started a transport process")

    monkeypatch.setattr(transport.subprocess, "Popen", forbidden)
    with pytest.raises(TimeoutError):
        transport.open_response("https://example.invalid/", headers={}, expires_at=time.monotonic() - 1)


def test_deadline_kills_worker_stalled_during_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The production deadline includes isolated worker startup and imports."""
    processes = _install_worker(tmp_path, monkeypatch, "import time\ntime.sleep(30)\n")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        transport.open_response(
            "https://example.invalid/", headers={}, expires_at=started + 0.1,
        )
    assert time.monotonic() - started < 0.3
    _assert_reaped(processes)
    assert processes[0].returncode == -9


def _framed_response(case: str, body: bytes) -> bytes:
    """Build exact peer bytes, including deliberately malformed framing."""
    length = str(len(body)).encode("ascii")
    chunk = f"{len(body):x}".encode("ascii") + b"\r\n" + body
    fixed = b"Content-Length: " + length + b"\r\n"
    if case == "lf_header_terminator":
        return b"HTTP/1.1 200 OK\r\n" + fixed + b"\n" + body
    if case == "malformed_interim_header":
        return (
            b"HTTP/1.1 100 Continue\r\nBad Header: ignored\r\n\r\n"
            + b"HTTP/1.1 200 OK\r\n" + fixed + b"\r\n" + body
        )
    chunked = b"Transfer-Encoding: chunked\r\n"
    normal_chunks = chunk + b"\r\n0\r\n\r\n"
    # Three full lines, one line two bytes shorter, and the final CRLF
    # exercise the 64 KiB section limit without hitting the field-count limit.
    full_trailer = b"X-Large: " + b"x" * (16384 - 11) + b"\r\n"
    split = max(1, len(body) // 2)
    multiple_chunks = b"".join(
        f"{len(part):x}\r\n".encode() + part + b"\r\n"
        for part in (body[:split], body[split:])
    ) + b"0\r\n\r\n"
    cases = {
        "conflicting_lengths": (fixed + b"Content-Length: 99999\r\n", body),
        "hidden_conflicting_length": (
            fixed + b"Bad Header: ignored\r\nContent-Length: 99999\r\n", body,
        ),
        "hidden_transfer_encoding": (
            fixed + b"Bad Header: ignored\r\nTransfer-Encoding: chunked\r\n", body,
        ),
        "header_missing_colon": (fixed + b"Bad-Header ignored\r\n", body),
        "header_control_character": (fixed + b"X-Safe: y\x00es\r\n", body),
        "folded_header": (fixed + b"X-Safe: yes\r\n folded\r\n", body),
        "lf_terminated_header": (fixed + b"X-Safe: yes\n", body),
        "conflicting_length_list": (b"Content-Length: " + length + b", 99999\r\n", body),
        "negative_length": (b"Content-Length: -1\r\n", body),
        "signed_length": (b"Content-Length: +" + length + b"\r\n", body),
        "nondecimal_length": (b"Content-Length: 0x10\r\n", body),
        "empty_length": (b"Content-Length:\r\n", body),
        "empty_length_member": (b"Content-Length: " + length + b",\r\n", body),
        "truncated_fixed_body": (fixed, body[:-1]),
        "length_and_encoding": (fixed + chunked, normal_chunks),
        "unsupported_encoding": (b"Transfer-Encoding: gzip\r\n", body),
        "encoding_chain": (b"Transfer-Encoding: gzip, chunked\r\n", normal_chunks),
        "duplicate_encoding": (chunked + chunked, normal_chunks),
        "empty_encoding": (b"Transfer-Encoding:\r\n", body),
        "encoding_empty_member": (b"Transfer-Encoding: chunked,\r\n", normal_chunks),
        "encoding_parameters": (b"Transfer-Encoding: chunked;foo=bar\r\n", normal_chunks),
        "invalid_chunk_delimiter": (chunked, chunk + b"XY0\r\n\r\n"),
        "lf_chunk_delimiter": (chunked, chunk + b"\n0\r\n\r\n"),
        "truncated_chunk_delimiter": (chunked, chunk + b"\r"),
        "truncated_chunk_data": (chunked, chunk[:-1]),
        "signed_chunk_size": (chunked, b"+" + normal_chunks),
        "invalid_chunk_size": (chunked, b"g\r\n" + body + b"\r\n0\r\n\r\n"),
        "lf_chunk_size": (chunked, chunk.replace(b"\r\n", b"\n", 1) + b"\r\n0\r\n\r\n"),
        "missing_extension_name": (chunked, chunk.replace(b"\r\n", b";=value\r\n", 1) + b"\r\n0\r\n\r\n"),
        "invalid_extension_name": (chunked, chunk.replace(b"\r\n", b";bad name=yes\r\n", 1) + b"\r\n0\r\n\r\n"),
        "missing_extension_value": (chunked, chunk.replace(b"\r\n", b";flag=\r\n", 1) + b"\r\n0\r\n\r\n"),
        "unterminated_extension_quote": (chunked, chunk.replace(b"\r\n", b';flag="value\r\n', 1) + b"\r\n0\r\n\r\n"),
        "oversized_chunk_line": (chunked, chunk.replace(b"\r\n", b";flag=" + b"x" * 17000 + b"\r\n", 1) + b"\r\n0\r\n\r\n"),
        "invalid_zero_chunk_extension": (chunked, chunk + b"\r\n0;=bad\r\n\r\n"),
        "missing_zero_chunk": (chunked, chunk + b"\r\n"),
        "missing_trailer_terminator": (chunked, chunk + b"\r\n0\r\n"),
        "unterminated_trailers": (chunked, chunk + b"\r\n0\r\nX-Safe: yes\r\n"),
        "lf_trailer_terminator": (chunked, chunk + b"\r\n0\r\n\n"),
        "lf_trailer_line": (chunked, chunk + b"\r\n0\r\nX-Safe: yes\n\r\n"),
        "invalid_trailer_name": (chunked, chunk + b"\r\n0\r\nBad Name: yes\r\n\r\n"),
        "missing_trailer_colon": (chunked, chunk + b"\r\n0\r\nX-Safe yes\r\n\r\n"),
        "folded_trailer": (chunked, chunk + b"\r\n0\r\nX-Safe: yes\r\n folded\r\n\r\n"),
        "trailer_control_character": (chunked, chunk + b"\r\n0\r\nX-Safe: y\x00es\r\n\r\n"),
        "oversized_trailer_line": (chunked, chunk + b"\r\n0\r\nX-Large: " + b"x" * 17000 + b"\r\n\r\n"),
        "trailer_count_limit": (chunked, chunk + b"\r\n0\r\n" + b"X-Safe: yes\r\n" * 101 + b"\r\n"),
        "trailer_byte_limit": (chunked, chunk + b"\r\n0\r\n" + full_trailer * 3 + full_trailer[1:] + b"\r\n"),
        "reported_200_trailers": (chunked, chunk + b"\r\n0\r\n" + (b"X-Large: " + b"x" * 1000 + b"\r\n") * 200 + b"\r\n"),
        "valid_fixed": (fixed, body),
        "valid_header_obs_text": (fixed + b"X-Description: \xff\r\n", body),
        "valid_duplicate_lengths": (fixed + fixed, body),
        "valid_length_list": (b"Content-Length: " + length + b", " + length + b"\r\n", body),
        "valid_eof": (b"Connection: close\r\n", body),
        "valid_chunked": (chunked, normal_chunks),
        "valid_multiple_chunks": (chunked, multiple_chunks),
        "valid_mixed_case_encoding": (b"Transfer-Encoding: \tChUnKeD \t\r\n", normal_chunks),
        "valid_extensions_and_trailers": (
            chunked,
            chunk.replace(b"\r\n", b';name=token;flag;quoted="a;\\\"b"\r\n', 1)
            + b'\r\n0;last="yes"\r\nX-Checksum: ignored\r\n\r\n',
        ),
        "valid_trailer_count_boundary": (chunked, chunk + b"\r\n0\r\n" + b"X-Safe: yes\r\n" * 100 + b"\r\n"),
        "valid_trailer_byte_boundary": (chunked, chunk + b"\r\n0\r\n" + full_trailer * 3 + full_trailer[2:] + b"\r\n"),
        "valid_chunk_line_boundary": (
            chunked,
            chunk.replace(b"\r\n", b";flag=" + b"x" * (16384 - len(f"{len(body):x}") - 8) + b"\r\n", 1)
            + b"\r\n0\r\n\r\n",
        ),
    }
    if case.startswith("forbidden_trailer:"):
        field = case.partition(":")[2].encode("ascii")
        headers, data = chunked, chunk + b"\r\n0\r\n" + field + b": invalid\r\n\r\n"
    else:
        headers, data = cases[case]
    return b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + data


@pytest.mark.parametrize("framing", [
    "conflicting_lengths", "hidden_conflicting_length", "hidden_transfer_encoding",
    "header_missing_colon", "header_control_character", "folded_header", "lf_terminated_header",
    "lf_header_terminator",
    "malformed_interim_header",
    "conflicting_length_list", "negative_length",
    "signed_length", "nondecimal_length", "empty_length", "empty_length_member", "truncated_fixed_body",
    "length_and_encoding", "unsupported_encoding", "encoding_chain",
    "duplicate_encoding", "empty_encoding", "encoding_empty_member", "encoding_parameters",
    "invalid_chunk_delimiter", "lf_chunk_delimiter", "truncated_chunk_delimiter", "truncated_chunk_data",
    "signed_chunk_size", "invalid_chunk_size", "lf_chunk_size",
    "missing_extension_name", "invalid_extension_name", "missing_extension_value",
    "unterminated_extension_quote", "oversized_chunk_line", "invalid_zero_chunk_extension",
    "missing_zero_chunk", "missing_trailer_terminator", "unterminated_trailers",
    "lf_trailer_terminator", "lf_trailer_line", "invalid_trailer_name",
    "missing_trailer_colon", "folded_trailer", "trailer_control_character",
    "oversized_trailer_line", "trailer_count_limit", "trailer_byte_limit", "reported_200_trailers",
    "forbidden_trailer:Content-Length", "forbidden_trailer:Transfer-Encoding",
    "forbidden_trailer:Trailer", "forbidden_trailer:Host", "forbidden_trailer:Connection",
    "forbidden_trailer:Content-Encoding", "forbidden_trailer:Authorization",
])
def test_malformed_https_framing_never_publishes_or_retains_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    framing: str,
    record_property: Any,
    acquisition_descriptors: set[int],
) -> None:
    """Correct pinned bytes cannot make an ambiguously framed response ready."""
    from test_candidate_preparation import (
        _acquisition_config, _assert_descriptor_closed, _fixture, _payload,
        _rewrite, _tree_snapshot, _trusted_evidence,
    )

    acquisition = candidate._acquisition
    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    if framing in {"hidden_conflicting_length", "hidden_transfer_encoding"}:
        assert len(body) == 27
    artifact.unlink()
    initial = _tree_snapshot(artifact.parent)
    preserved = {
        path: (path.read_bytes(), path.stat().st_ino)
        for path in artifact.parent.iterdir() if path.is_file()
    }
    assert preserved
    manifest, journal = tmp_path / "prepared.json", tmp_path / "journal.json"
    descriptors: list[int] = []
    real_target = acquisition._open_output_target
    real_lock = acquisition._JournalLock.acquire
    real_staging = acquisition._open_staging_file

    def open_target(*args: Any, **kwargs: Any) -> Any:
        target = real_target(*args, **kwargs)
        descriptors.append(target.parent_fd)
        acquisition_descriptors.add(target.parent_fd)
        return target

    def acquire_lock(cls: Any, *args: Any, **kwargs: Any) -> Any:
        lock = real_lock(*args, **kwargs)
        descriptors.append(lock.descriptor)
        acquisition_descriptors.add(lock.descriptor)
        return lock

    def open_staging(parent_fd: int) -> Any:
        stage = real_staging(parent_fd)
        descriptors.extend((parent_fd, stage.descriptor))
        acquisition_descriptors.update((parent_fd, stage.descriptor))
        return stage

    monkeypatch.setattr(acquisition, "_open_output_target", open_target)
    monkeypatch.setattr(acquisition._JournalLock, "acquire", classmethod(acquire_lock))
    monkeypatch.setattr(acquisition, "_open_staging_file", open_staging)

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(_framed_response(framing, body))

    with _cleanup_test_workers(processes), _server(context, respond) as (url, observations):
        payload = _payload(declaration)
        payload["acquisition"]["sources"][0]["url"] = url
        _rewrite(declaration, payload)
        origin = url.rsplit("/", 1)[0]
        config = _acquisition_config(
            tmp_path, timeout_seconds=2, max_attempts=1,
            max_total_bytes=len(body) * 2, allowed_origins=[origin],
            credentials=[{"origin": origin, "headers": {"Authorization": "Bearer framing-secret"}}],
        )
        started = time.monotonic()
        with pytest.raises(candidate.CandidateAcquisitionError):
            candidate.prepare_candidate(
                declaration, manifest_output=manifest, journal_output=journal,
                acquire=True, acquisition_config=config, trusted_evidence=_trusted_evidence(),
            )
        elapsed = time.monotonic() - started
        record_property("framing_failure_elapsed_seconds", elapsed)
        assert elapsed < 1.5, "invalid framing was not rejected before the transport deadline"
        assert observations["requests"]
        _assert_reaped(processes)
        assert not artifact.exists() and not manifest.exists()
        assert _tree_snapshot(artifact.parent) == initial
        for path, (contents, inode) in preserved.items():
            assert path.read_bytes() == contents and path.stat().st_ino == inode
        events = _payload(journal)
        assert events["status"] != "ready"
        assert events["events"][-1]["state"] == "failed"
        assert events["events"][-1]["code"] != "transfer_timeout"
        assert not any(event["state"] == "succeeded" for event in events["events"])
        assert "framing-secret" not in journal.read_text()
        assert descriptors and not acquisition_descriptors
        with journal.with_name(".journal.json.lock").open("rb") as handle:
            acquisition.fcntl.flock(handle.fileno(), acquisition.fcntl.LOCK_EX | acquisition.fcntl.LOCK_NB)
            acquisition.fcntl.flock(handle.fileno(), acquisition.fcntl.LOCK_UN)


@pytest.mark.parametrize(
    "hidden_header",
    [b"Content-Length: 99999\r\n", b"Transfer-Encoding: chunked\r\n"],
    ids=["conflicting-length", "transfer-encoding"],
)
def test_raw_header_reader_rejects_hidden_framing(hidden_header: bytes) -> None:
    raw_headers = io.BytesIO(
        b"Content-Length: 27\r\nBad Header: ignored\r\n" + hidden_header + b"\r\n"
    )
    with pytest.raises(ValueError, match="invalid response header field"):
        transport._read_strict_response_headers(raw_headers)


def test_response_framing_rejects_reported_header_parser_defects() -> None:
    headers = email.parser.Parser().parsestr(
        "Content-Length: 27\r\nBad Header: ignored\r\nContent-Length: 99999\r\n\r\n"
    )
    assert headers.defects
    with pytest.raises(ValueError):
        transport._response_framing(headers)


@pytest.mark.parametrize("framing", [
    "valid_fixed", "valid_header_obs_text", "valid_duplicate_lengths", "valid_length_list", "valid_eof",
    "valid_chunked", "valid_multiple_chunks", "valid_mixed_case_encoding", "valid_extensions_and_trailers",
    "valid_trailer_count_boundary", "valid_trailer_byte_boundary", "valid_chunk_line_boundary",
])
def test_supported_https_framing_publishes_only_verified_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tls_material: tuple[Path, ssl.SSLContext],
    framing: str,
) -> None:
    from test_candidate_preparation import (
        _acquisition_config, _fixture, _payload, _rewrite, _trusted_evidence,
    )

    certificate, context = tls_material
    processes = _install_worker(tmp_path, monkeypatch, _trust_certificate(certificate))
    declaration = _fixture(tmp_path)
    artifact = tmp_path / "files" / "diffusion.safetensors"
    body = artifact.read_bytes()
    artifact.unlink()

    def respond(connection: Any, request: Any, stop: Any, observations: Any) -> None:
        connection.sendall(_framed_response(framing, body))

    with _cleanup_test_workers(processes), _server(context, respond) as (url, _):
        payload = _payload(declaration)
        payload["acquisition"]["sources"][0]["url"] = url
        _rewrite(declaration, payload)
        config = _acquisition_config(tmp_path, timeout_seconds=2, allowed_origins=[url.rsplit("/", 1)[0]])
        report = candidate.prepare_candidate(
            declaration, manifest_output=tmp_path / "prepared.json",
            journal_output=tmp_path / "journal.json", acquire=True,
            acquisition_config=config, trusted_evidence=_trusted_evidence(),
        )
        assert report["status"] == "ready"
        assert artifact.read_bytes() == body
        _assert_reaped(processes)


# Fixed test-only localhost identity; never used by production transport.
_CERTIFICATE = '-----BEGIN CERTIFICATE-----\nMIIDBDCCAeygAwIBAgIUCB3v4W35kX3GqaLvj/CFxHBWPgcwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAyOTIyMTkwOVoXDTM2MTAy\nNjIyMTkwOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEA023qJggams2IP8u+7ZJYO7YonVRtJMtIyPtm6PtkA//U\nOM2Lo7AE8uZlKwKGTjXnwNRVsnnKyUv5z8UwPLRi9lX19mqKOJ0PPFquUmsn/ajg\ngg0HrykPqDSBE0Fl63AVP91C16aDfjtOmyzgFhmbkJLKsSaWFUOprNXTSQhoNjDU\nVjkjEJHBrV34IRQPI33er3ZLVGArrONde+vGhAXm3qMczBWHG7UNdLNrDAIngdyM\n4zzPCDSGzsS5mJpaKycIqK6ImkJuFMXc4n72SlexPKlbI/LdKb2e0cmveLtTesNn\nXNPyZbV7gwxZFmn1E6C863V8b9SVksv8Z8gaQEYvawIDAQABo04wTDAdBgNVHQ4E\nFgQUwozfPPMe9p8uDJRLN/2O8ZZKHeswGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/\nAAABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAMNBzRiAENuT\nVvffVtS4qPj0Dq1IaQVhQjr/8ZIdyzzv699Pp2qqNGgNLcfDQBJO3jopRlx3citf\nEDOgaacY0pGVdwsWl++4Wm7dAEnZM9dStApNnIkoR6yTlBkcH07qWZ44aY69/qBy\n25ULg8lgMS8RayUpz58irv5p8DtEL7xr5OqFQoAw7emr/c+0vCwzsCUywKrth5k0\nN8SRutdgig0qMQ4L6qceq1QBDYMlhnBYh2UHodsYRtpKvEP5lQFJ8I2nQkf+6Dp/\nIUJ5HRi0kbR2dhKfSM/IM+jyy02HZkIlajl5HmUt1vvqsKXAPnhcRM0QVfchShog\njwAxjnuiJb8=\n-----END CERTIFICATE-----\n'
_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTbeomCBqazYg/\ny77tklg7tiidVG0ky0jI+2bo+2QD/9Q4zYujsATy5mUrAoZONefA1FWyecrJS/nP\nxTA8tGL2VfX2aoo4nQ88Wq5Sayf9qOCCDQevKQ+oNIETQWXrcBU/3ULXpoN+O06b\nLOAWGZuQksqxJpYVQ6ms1dNJCGg2MNRWOSMQkcGtXfghFA8jfd6vdktUYCus4117\n68aEBebeoxzMFYcbtQ10s2sMAieB3IzjPM8INIbOxLmYmlorJwioroiaQm4Uxdzi\nfvZKV7E8qVsj8t0pvZ7Rya94u1N6w2dc0/JltXuDDFkWafUToLzrdXxv1JWSy/xn\nyBpARi9rAgMBAAECggEACRC7a2oJif2qC+I2i4Us11KWJzjJfTxiIIv2+6JbxXgg\np1bY1+niLHAIgnGXRJ83EqOIESD7uunRCkGQMeoiHCHPbANhbc/+KT5SHyKNEmk9\nRxY78By4mSO3LRYuwouJvbVE+m4fUThFxI2GBiyO6QICQto+sSa3jbuVVZpQrZIS\ncey8TG8U5/5IvKwn3iNKL6e9Zs0X8We611H+wzzZmqTZOaEHcN0D5bh6ITeQgRjm\n9p48XNWFkHnVYW8zX6owwuLIuUusKkePzdRnYsC+ZGVmPdKQcn8SIvhqUROlO+oM\n0YwBBi/hniRyOF7YxNM0P+wCbxTD4E9v3WjeV6d7wQKBgQDxOD6BFc6Va0cokiVy\nDnz9xVQKkfa8TtclmZOkMnN1N+cgP0hAkLqCKvg9HEHgqQsML3SuMSECz/1ripp1\nTEgKbGH6YkpaWjoyo9yY38GXgR5IB3Fc2rYncdQlW47AKhnUUoA6p0C1mlDpSsrQ\nS2XgkcoiVwZNEsjb+RktVnq0cQKBgQDgYmGPGxHDkuFbloDgShos/aL6A5i9q7KM\n4P4d1VeyYXRkLpP3HFZ9MOq/usHCgTstS6H1MgH8zFy6K3bNGttPZstoIVbfnz1P\nA8M7yPUbog2ol2v57QvIFqlxMq2MnRJ1YJ4wKj1mbkidFyPeTFUAJHEDcxIosrpp\nDjqzSdVfmwKBgQCaGD4FpHKmDTQV/Nai+BJs4wP/BKPEQ/E4+dTRTdFoDmA9v29e\nn5Yl1WFjWIvVAuglzqMRLB1UeJ4BdzeYuzRCRF6K3wN0mLMY6ojfuAEp0bgQd4C5\nupYmuJa3jrewlrSNaG62CWZTHNOXVMofKitYvImOSl2iGt/pdkXZKqeUYQKBgBuf\ngOshJfqxplSkHpF+DeLkBqBIuREAhiaZvC7oCLfJD48VvNl6/5rB3uRjlV7gkext\nly6cTWpVrkSs/R8a40zPFtNm5074R4/moq5Fewc/1/adTYmjCQRE5e8tkffxjkgs\n8Mx1JsHpab8NDjlbpEs0MUV/cQjZl+E/AzL3L/FpAoGAZ6hxYXO0aXq/2Z822yWb\n2/lAecWOSg+YRKTpHpOxB8qKpfjjx3UdPkHUGSE2wLuTWVxhP9UTAvQZ+OcEDocS\nmTLJ3dzcD0xfc0IcLoJJZ9iPxcm2HZNy4lHY79u0ag0t7sBmrirItJvKTqdpb40T\n8EcchKmegk+j/E1RbPvnwOk=\n-----END PRIVATE KEY-----\n'
