from __future__ import annotations

from io import BytesIO

import pytest

from media_generation import attempt_runner
from media_generation.errors import BackendEvidenceError
from media_generation.systemd_broker import _read_line, _write_line


def test_runner_and_broker_reject_unterminated_control_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b'{"ok":true}'

    class Input:
        buffer = BytesIO(raw)

    monkeypatch.setattr(attempt_runner, "_write_object", lambda _: None)
    monkeypatch.setattr(attempt_runner.sys, "stdin", Input())
    with pytest.raises(BackendEvidenceError, match="missing or oversized"):
        attempt_runner._exchange({"operation": "verify_current"})

    with pytest.raises(EOFError):
        _read_line(BytesIO(raw))


def test_runner_and_broker_encode_the_same_json_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message = {"operation": "verify_current", "attempt": "attempt-1"}
    runner_output = BytesIO()
    monkeypatch.setattr(attempt_runner.sys, "stdout", type("Output", (), {"buffer": runner_output})())

    attempt_runner._write_object(message)
    broker_output = BytesIO()
    _write_line(broker_output, message)

    assert runner_output.getvalue() == broker_output.getvalue()
    assert runner_output.getvalue().endswith(b"\n")


def test_truncated_ancillary_frame_closes_received_descriptor(tmp_path) -> None:
    import array
    import os
    import socket

    from media_generation.systemd_protocol import received_descriptors

    fd = os.open(tmp_path, os.O_RDONLY)
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]).tobytes())]
    with pytest.raises(ValueError, match="descriptor frame"):
        received_descriptors(ancillary, socket.MSG_CTRUNC, limit=1)
    with pytest.raises(OSError):
        os.fstat(fd)
