"""Private, supervised HTTPS transport for explicitly authorized acquisition.

Blocking DNS, TLS, and HTTP parsing run in one disposable process. Raw response
headers and parser defects are checked before accepting framing or body data.
Body framing is validated strictly with bounded chunk lines and trailers. The parent
retains the artifact's absolute monotonic deadline and supervises every pipe
operation against it. Expiry kills and reaps the worker, closing its sockets
even when libc resolution or HTTP framing has not returned. No worker thread,
credential-bearing command line, temporary request file, proxy, redirect
following, connection pool, or public networking interface is involved.
"""

from __future__ import annotations

import email.message
import http.client
import json
import os
import re
import selectors
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import BinaryIO, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

_MAX_CONTROL_BYTES = 64 * 1024
_BODY_CHUNK_BYTES = 64 * 1024
_PACKET_HEADER = struct.Struct("!cI")
# Framing bytes are separate from the pinned artifact's body-byte allowance.
# Bound each chunk/trailer line, the complete trailer section (including its
# final CRLF), and its field count before accepting the end of the body.
_MAX_FRAMING_LINE_BYTES = 16 * 1024
_MAX_TRAILER_BYTES = 64 * 1024
_MAX_TRAILER_FIELDS = 100
_TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QUOTED_STRING = rb'"(?:[\t\x20-\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e\x80-\xff])*"'
_CHUNK_LINE = re.compile(
    rb"([0-9A-Fa-f]+)(?:[ \t]*;[ \t]*" + _TOKEN
    + rb"(?:[ \t]*=[ \t]*(?:" + _TOKEN + rb"|" + _QUOTED_STRING + rb"))?)*"
)
_FORBIDDEN_TRAILER_FIELDS = frozenset({
    b"content-length", b"transfer-encoding", b"trailer", b"host", b"connection",
    b"te", b"upgrade", b"authorization", b"proxy-authorization",
    b"proxy-authenticate", b"www-authenticate", b"content-encoding",
    b"content-type", b"content-range",
})
# Keep the standard library's bounded reader while validating its raw output
# before its permissive email parser can discard malformed fields.
_read_http_headers = http.client._read_headers


def _remaining(expires_at: float) -> float:
    remaining = expires_at - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("acquisition deadline expired")
    return remaining


def _read_strict_response_headers(stream: BinaryIO) -> list[bytes]:
    """Validate final and interim field lines before the email parser sees them.

    The standard parser can discard a malformed field and everything after it,
    hiding conflicting framing headers. Require token field names, CRLF line
    endings, and field values without forbidden controls or folded lines. The
    worker installs this reader for both final headers and skipped 100 responses.
    """
    lines = _read_http_headers(stream)
    if not lines or lines[-1] != b"\r\n":
        raise ValueError("incomplete response headers")
    for line in lines[:-1]:
        if not line.endswith(b"\r\n"):
            raise ValueError("invalid response header line ending")
        name, separator, value = line[:-2].partition(b":")
        if (
            not separator or re.fullmatch(_TOKEN, name) is None
            or re.fullmatch(rb"[\t\x20-\x7e\x80-\xff]*", value) is None
        ):
            raise ValueError("invalid response header field")
    return lines


def _response_framing(headers: email.message.Message) -> tuple[int | None, bool]:
    """Validate framing before metadata or body bytes leave the HTTPS worker.

    Only the single chunked transfer coding is supported. Repeated lengths
    are accepted only when every comma-separated decimal value agrees, then
    normalized so the acquisition layer sees the same unambiguous length.
    """
    if headers.defects:
        raise ValueError("defective response headers")
    lengths = headers.get_all("Content-Length", [])
    encodings = headers.get_all("Transfer-Encoding", [])
    if encodings:
        if lengths or len(encodings) != 1 or encodings[0].strip(" \t").lower() != "chunked":
            raise ValueError("ambiguous or unsupported response framing")
        return None, True
    if not lengths:
        return None, False
    values = [part.strip(" \t") for value in lengths for part in value.split(",")]
    if any(re.fullmatch(r"[0-9]+", value) is None for value in values):
        raise ValueError("invalid response length")
    length = int(values[0])
    if any(int(value) != length for value in values[1:]):
        raise ValueError("conflicting response lengths")
    del headers["Content-Length"]
    headers["Content-Length"] = str(length)
    return length, False


class _FramedBody:
    """Read the undecoded HTTPS stream with strict, bounded HTTP/1.1 framing.

    The owning response closes the stream. Each read checks the artifact's
    original deadline; parent supervision also kills and reaps the worker if
    a stream read blocks past expiry. The standard library's permissive chunk
    decoder is deliberately bypassed, including its unbounded trailer loop.
    """

    def __init__(
        self, stream: BinaryIO, *, expires_at: float,
        length: int | None, chunked: bool,
    ) -> None:
        self._stream = stream
        self._expires_at = expires_at
        self._length = length
        self._chunked = chunked
        self._chunk_left = 0
        self._needs_delimiter = False
        self._finished = False

    def _read_some(self, size: int) -> bytes:
        _remaining(self._expires_at)
        data = self._stream.read1(size)
        _remaining(self._expires_at)
        return data

    def _line(self) -> bytes:
        _remaining(self._expires_at)
        line = self._stream.readline(_MAX_FRAMING_LINE_BYTES + 1)
        _remaining(self._expires_at)
        if len(line) > _MAX_FRAMING_LINE_BYTES or not line.endswith(b"\r\n"):
            raise ValueError("invalid or excessive framing line")
        return line

    def _trailers(self) -> None:
        total_bytes = 0
        fields = 0
        while True:
            line = self._line()
            total_bytes += len(line)
            if total_bytes > _MAX_TRAILER_BYTES:
                raise ValueError("trailers exceed byte limit")
            if line == b"\r\n":
                return
            fields += 1
            if fields > _MAX_TRAILER_FIELDS:
                raise ValueError("trailers exceed field limit")
            name, separator, value = line[:-2].partition(b":")
            if (
                not separator or re.fullmatch(_TOKEN, name) is None
                or name.lower() in _FORBIDDEN_TRAILER_FIELDS
                or re.fullmatch(rb"[\t\x20-\x7e\x80-\xff]*", value) is None
            ):
                raise ValueError("invalid or forbidden trailer field")

    def read(self, size: int) -> bytes:
        """Return bounded body data; EOF requires complete, valid framing."""
        _remaining(self._expires_at)
        if self._finished:
            return b""
        if self._chunked:
            if self._chunk_left == 0:
                if self._needs_delimiter:
                    delimiter = bytearray()
                    while len(delimiter) < 2:
                        data = self._read_some(2 - len(delimiter))
                        if not data:
                            raise ValueError("incomplete chunk delimiter")
                        delimiter.extend(data)
                    if delimiter != b"\r\n":
                        raise ValueError("invalid chunk delimiter")
                match = _CHUNK_LINE.fullmatch(self._line()[:-2])
                if match is None:
                    raise ValueError("invalid chunk size or extension")
                self._chunk_left = int(match[1], 16)
                if self._chunk_left == 0:
                    self._trailers()
                    self._finished = True
                    return b""
            data = self._read_some(min(size, self._chunk_left))
            if not data:
                raise ValueError("incomplete chunk data")
            self._chunk_left -= len(data)
            self._needs_delimiter = True
            return data
        if self._length == 0:
            self._finished = True
            return b""
        data = self._read_some(size if self._length is None else min(size, self._length))
        if not data:
            if self._length is not None:
                raise ValueError("incomplete response body")
            self._finished = True
        elif self._length is not None:
            self._length -= len(data)
        return data


def _worker_command() -> list[str]:
    """Use this installed source and interpreter without project startup hooks."""
    return [sys.executable, "-I", "-S", "-u", str(Path(__file__).resolve())]


class _Response:
    """One owned worker response; close always terminates and reaps the worker."""

    def __init__(self, process: subprocess.Popen[bytes], expires_at: float) -> None:
        self._process = process
        self._expires_at = expires_at
        self._buffer = b""
        self._finished = False
        self.closed = False
        self.status = 0
        self.headers = email.message.Message()

    def _wait(self, stream: BinaryIO, events: int) -> None:
        with selectors.DefaultSelector() as selector:
            selector.register(stream, events)
            while True:
                if selector.select(_remaining(self._expires_at)):
                    _remaining(self._expires_at)
                    return

    def _send(self, request: bytes) -> None:
        assert self._process.stdin is not None
        stream = self._process.stdin
        offset = 0
        while offset < len(request):
            self._wait(stream, selectors.EVENT_WRITE)
            try:
                offset += os.write(stream.fileno(), request[offset:])
            except BlockingIOError:
                continue

    def _read_exact(self, size: int) -> bytes:
        assert self._process.stdout is not None
        stream = self._process.stdout
        result = bytearray()
        while len(result) < size:
            self._wait(stream, selectors.EVENT_READ)
            try:
                data = os.read(stream.fileno(), size - len(result))
            except BlockingIOError:
                continue
            if not data:
                raise OSError("acquisition transport ended unexpectedly")
            result.extend(data)
        return bytes(result)

    def _packet(self) -> tuple[bytes, bytes]:
        kind, size = _PACKET_HEADER.unpack(self._read_exact(_PACKET_HEADER.size))
        if size > max(_MAX_CONTROL_BYTES, _BODY_CHUNK_BYTES):
            raise OSError("acquisition transport packet exceeds limit")
        payload = self._read_exact(size)
        if kind == b"E":
            if payload == b"transfer_timeout":
                raise TimeoutError("acquisition deadline expired")
            raise OSError("acquisition transport failed")
        return kind, payload

    def read(self, size: int = _BODY_CHUNK_BYTES) -> bytes:
        """Return bounded body bytes while supervising blocking worker parsing."""
        if self.closed:
            raise ValueError("acquisition response is closed")
        if size < 0:
            size = _BODY_CHUNK_BYTES
        if size == 0:
            return b""
        try:
            _remaining(self._expires_at)
            if not self._buffer and not self._finished:
                self._send(struct.pack("!I", min(size, _BODY_CHUNK_BYTES)))
                kind, payload = self._packet()
                if kind == b"D" and not payload:
                    self._finished = True
                elif kind == b"B" and payload:
                    self._buffer = payload
                else:
                    raise OSError("acquisition transport body is invalid")
            result, self._buffer = self._buffer[:size], self._buffer[size:]
            return result
        except BaseException:
            self.close()
            raise

    read1 = read

    def close(self) -> None:
        """Kill before reaping; never wait for a blocked network call to finish."""
        if self.closed:
            return
        self.closed = True
        try:
            if self._process.poll() is None:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
        finally:
            # Reap synchronously: returning with a live resolver/HTTP worker
            # would violate cancellation, even if the caller had timed out.
            try:
                self._process.wait()
            finally:
                for stream in (self._process.stdin, self._process.stdout):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass


def open_response(
    url: str, *, headers: Mapping[str, str], expires_at: float
) -> _Response:
    """Open one HTTPS GET under an existing absolute acquisition deadline.

    Redirect and credential policy belongs to the caller. Secrets travel only
    through anonymous pipes; the isolated child receives no caller environment,
    inherited project descriptors, or working-directory imports.
    """
    _remaining(expires_at)
    request = json.dumps(
        {"url": url, "headers": dict(headers), "expires_at": expires_at},
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(request) > _MAX_CONTROL_BYTES:
        raise OSError("acquisition request headers exceed limit")
    process = subprocess.Popen(
        _worker_command(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        close_fds=True,
        env={},
        cwd="/",
        start_new_session=True,
    )
    response = _Response(process, expires_at)
    try:
        assert process.stdin is not None and process.stdout is not None
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        response._send(struct.pack("!I", len(request)) + request)
        kind, metadata = response._packet()
        if kind != b"H":
            raise OSError("acquisition response headers are invalid")
        value = json.loads(metadata)
        response.status = int(value["status"])
        for name, content in value["headers"]:
            response.headers[name] = content
        _remaining(expires_at)
        return response
    except BaseException:
        response.close()
        raise


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _emit(kind: bytes, payload: bytes = b"") -> None:
    sys.stdout.buffer.write(_PACKET_HEADER.pack(kind, len(payload)))
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _worker_main() -> None:
    """Perform one exchange; emit only bounded frames or fixed error codes."""
    response = None
    try:
        request_size = struct.unpack("!I", sys.stdin.buffer.read(4))[0]
        if request_size > _MAX_CONTROL_BYTES:
            raise ValueError("request exceeds limit")
        request_bytes = sys.stdin.buffer.read(request_size)
        control = json.loads(request_bytes)
        expires_at = float(control["expires_at"])
        url = control["url"]
        target = urlsplit(url)
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
        ):
            raise ValueError("HTTPS target required")
        # The disposable process bounds the standard library's synchronous
        # resolver, TLS setup, interim responses, and headers. Body framing is
        # read directly from its raw response stream by the strict parser.
        # Its ordinary socket timeout is secondary to parent-enforced expiry.
        http.client._MAXLINE = 16 * 1024
        http.client._MAXHEADERS = 100
        http.client._read_headers = _read_strict_response_headers
        opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )
        request = Request(url, headers=control["headers"], data=None, method="GET")
        request.add_header("Connection", "close")
        try:
            response = opener.open(request, timeout=_remaining(expires_at))
        except HTTPError as error:
            response = error
        length, chunked = _response_framing(response.headers)
        metadata = json.dumps(
            {"status": response.status, "headers": list(response.headers.items())},
            ensure_ascii=True,
        ).encode("ascii")
        if len(metadata) > _MAX_CONTROL_BYTES:
            raise ValueError("headers exceed limit")
        _emit(b"H", metadata)
        if response.status == 200:
            body_reader = _FramedBody(
                response.fp, expires_at=expires_at, length=length, chunked=chunked,
            )
            while True:
                _remaining(expires_at)
                command = sys.stdin.buffer.read(4)
                if len(command) != 4:
                    return
                read_size = struct.unpack("!I", command)[0]
                if not 0 < read_size <= _BODY_CHUNK_BYTES:
                    raise ValueError("invalid body read limit")
                body = body_reader.read(read_size)
                if not body:
                    break
                _emit(b"B", body)
        _emit(b"D")
    except (TimeoutError, URLError) as error:
        timeout = isinstance(error, TimeoutError) or isinstance(
            getattr(error, "reason", None), TimeoutError
        )
        _emit(b"E", b"transfer_timeout" if timeout else b"network_error")
    except Exception:
        # Neither request URLs nor raw TLS/HTTP exceptions cross this boundary.
        _emit(b"E", b"network_error")
    finally:
        if response is not None:
            response.close()


if __name__ == "__main__":
    _worker_main()
