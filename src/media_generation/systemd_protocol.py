"""Bounded JSON line framing shared by the systemd broker and attempt runner."""

from __future__ import annotations

import array
import json
import os
import socket
from collections.abc import Mapping
from typing import BinaryIO


MAX_RUNNER_LINE_BYTES = 1024 * 1024


def encode_json_line(value: Mapping[str, object]) -> bytes:
    """Encode one JSON object using the broker-runner line framing contract."""
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    frame = payload + b"\n"
    if len(frame) > MAX_RUNNER_LINE_BYTES:
        raise ValueError("runner control message exceeds protocol limit")
    return frame


def read_json_line(stream: BinaryIO) -> dict[str, object]:
    """Read and validate one bounded JSON object terminated by a newline."""
    raw = stream.readline(MAX_RUNNER_LINE_BYTES + 1)
    if (
        not raw
        or len(raw) > MAX_RUNNER_LINE_BYTES
        or not raw.endswith(b"\n")
    ):
        raise EOFError("runner control stream ended or exceeded its limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("runner control message malformed") from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("runner control message must be a JSON object")
    return value

def received_descriptors(ancillary, flags: int, *, limit: int) -> list[int]:
    """Own every received descriptor or close them all when framing is invalid."""
    descriptors: list[int] = []
    invalid = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    for level, kind, data in ancillary:
        if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
            invalid = True
            continue
        integers = array.array("i")
        size = len(data) - len(data) % integers.itemsize
        integers.frombytes(data[:size])
        descriptors.extend(integers)
        invalid |= size != len(data) or not integers
    try:
        if invalid or len(descriptors) > limit:
            raise ValueError("invalid broker descriptor frame")
        for fd in descriptors:
            os.set_inheritable(fd, False)
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise
    return descriptors
