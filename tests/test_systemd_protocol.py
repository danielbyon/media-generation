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
