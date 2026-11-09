import errno
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path


FIXTURE_SOURCE = Path(__file__).parent / "fixtures" / "comfyui-server.py"


def test_comfyui_fixture_records_listener_bind_failure(tmp_path: Path) -> None:
    source_root = tmp_path / "comfyui-source"
    source_root.mkdir()
    server = source_root / "comfyui-server.py"
    shutil.copyfile(FIXTURE_SOURCE, server)
    directories = {
        name: tmp_path / name
        for name in ("base", "frontend", "output", "temp", "input")
    }
    for directory in directories.values():
        directory.mkdir()

    with socket.socket() as occupied_socket:
        occupied_socket.bind(("127.0.0.1", 0))
        occupied_socket.listen()
        port = occupied_socket.getsockname()[1]
        result = subprocess.run(
            [
                sys.executable,
                str(server),
                "--listen",
                "127.0.0.1",
                "--port",
                str(port),
                "--disable-all-custom-nodes",
                "--disable-auto-launch",
                "--offline",
                "--feature-flag",
                "enable_telemetry=false",
                "--base-directory",
                str(directories["base"]),
                "--front-end-root",
                str(directories["frontend"]),
                "--output-directory",
                str(directories["output"]),
                "--temp-directory",
                str(directories["temp"]),
                "--input-directory",
                str(directories["input"]),
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    assert result.returncode == 7
    bind_error = json.loads(
        (source_root / "listener-bind-error.json").read_text(encoding="utf-8")
    )
    assert bind_error["host"] == "127.0.0.1"
    assert bind_error["port"] == port
    assert bind_error["errno"] == errno.EADDRINUSE
    assert bind_error["error"]
