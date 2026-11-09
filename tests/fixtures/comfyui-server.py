#!/usr/bin/env python3
"""Deterministic synthetic ComfyUI HTTP peer for ComfyUI adapter tests.

This fixture is not ComfyUI and provides no qualification evidence. It models
only the bounded API surface exercised by the application adapter.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import zlib
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def png(width: int, height: int) -> bytes:
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rows.extend(((x + y) & 0xFF, (2 * x + y) & 0xFF, (x + 3 * y) & 0xFF))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


class State:
    def __init__(self, mode: dict[str, object], cwd: Path) -> None:
        self.mode = mode
        self.cwd = cwd
        self.lock = threading.Lock()
        self.prompt_count = 0
        self.accepted_prompt_ids: set[str] = set()
        self.request_counts: dict[str, int] = {}
        self.output_nodes: dict[str, str] = {}
        self.detached_descendant_spawned = False

    def spawn_detached_descendant(self) -> None:
        """Start one descriptor-isolated child that outlives this server."""
        pid_path = self.mode.get("detached_descendant_pid_path")
        if not isinstance(pid_path, str) or self.detached_descendant_spawned:
            return
        self.detached_descendant_spawned = True
        sleep_seconds = float(self.mode.get("detached_descendant_sleep_seconds", 30.0))
        process = subprocess.Popen(
            [sys.executable, "-c", f"import time; time.sleep({sleep_seconds!r})"],
            cwd=self.cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        Path(pid_path).write_text(str(process.pid), encoding="ascii")

    def record(self, name: str, data: bytes, prompt_id: str) -> None:
        with self.lock:
            (self.cwd / name).write_bytes(data)
            self.prompt_count += 1
            self.accepted_prompt_ids.add(prompt_id)
            (self.cwd / "prompt-count.txt").write_text(str(self.prompt_count), encoding="ascii")

    def output_node(self, prompt_id: str) -> str:
        with self.lock:
            return self.output_nodes.get(prompt_id, "9")


def load_mode(cwd: Path) -> dict[str, object]:
    path = cwd / "comfy-mode.json"
    if not path.exists():
        return {"mode": "success"}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {"mode": "success"}


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--base-directory", required=True)
    parser.add_argument("--disable-all-custom-nodes", action="store_true")
    parser.add_argument("--disable-auto-launch", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--front-end-root", required=True)
    parser.add_argument("--feature-flag", action="append", default=[])
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--temp-directory", required=True)
    parser.add_argument("--input-directory", required=True)
    options, unknown = parser.parse_known_args()
    if (
        unknown
        or not options.disable_all_custom_nodes
        or not options.disable_auto_launch
        or not options.offline
        or not Path(options.base_directory).is_dir()
        or options.feature_flag != ["enable_telemetry=false"]
        or not Path(options.front_end_root).is_dir()
    ):
        return 9
    cwd = Path(__file__).resolve().parent
    mode = load_mode(cwd)
    state = State(mode, cwd)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _json(self, status: int, payload: object) -> None:
            data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

        def _record_request(self) -> None:
            with state.lock:
                path = urlsplit(self.path).path
                state.request_counts[path] = state.request_counts.get(path, 0) + 1
                (state.cwd / "request-counts.json").write_text(
                    json.dumps(state.request_counts, sort_keys=True), encoding="utf-8"
                )

        def _write_deeply_nested_json(self, group: str) -> bool:
            if mode.get("deeply_nested_json") != group:
                return False
            depth = 100_000
            data = b"[" * depth + b"0" + b"]" * depth
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            return True

        def do_GET(self) -> None:
            self._record_request()
            parsed = urlsplit(self.path)
            if parsed.path == "/system_stats":
                if mode.get("readiness_delay"):
                    time.sleep(float(mode["readiness_delay"]))
                identity = str(mode.get("identity", "synthetic-unqualified-comfyui/v1"))
                system = {"comfyui_version": identity}
                if not mode.get("omit_web_root"):
                    system["web_root"] = str(
                        Path(mode.get("web_root", options.front_end_root)).resolve()
                    )
                self._json(
                    200,
                    {"system": system},
                )
                return
            if parsed.path == "/node_replacements":
                self._json(200, mode.get("node_replacements", {}))
                return
            if parsed.path == "/queue":
                if self._write_deeply_nested_json("queue"):
                    return
                if mode.get("queue_unknown"):
                    self._json(200, {"queue_running": [], "queue_pending": []})
                    return
                with state.lock:
                    accepted_ids = sorted(state.accepted_prompt_ids)
                pending = [
                    [index + 1, prompt_id, {}, {}, []]
                    for index, prompt_id in enumerate(accepted_ids)
                ]
                self._json(200, {"queue_running": [], "queue_pending": pending})
                return
            if parsed.path == "/api/jobs":
                if self._write_deeply_nested_json("jobs"):
                    return
                if mode.get("jobs_unknown"):
                    self._json(200, {"jobs": [], "total": 0, "has_more": False})
                    return
                with state.lock:
                    accepted_ids = sorted(state.accepted_prompt_ids)
                jobs = [{"id": prompt_id, "status": "pending"} for prompt_id in accepted_ids]
                self._json(
                    200,
                    {"jobs": jobs, "total": len(jobs), "has_more": False},
                )
                return
            if parsed.path.startswith("/history/"):
                if self._write_deeply_nested_json("history"):
                    return
                if mode.get("unsafe_output"):
                    prompt_id = parsed.path.removeprefix("/history/")
                    output_node = state.output_node(prompt_id)
                    name = str(mode["unsafe_output"])
                    self._json(
                        200,
                        {
                            prompt_id: {
                                "status": {"completed": True, "status_str": "success"},
                                "outputs": {output_node: {"images": [{"filename": name, "subfolder": str(mode.get("unsafe_subfolder", "")), "type": "output"}]}},
                            }
                        },
                    )
                    return
                if "unsafe_filename" in mode or "unsafe_subfolder" in mode:
                    prompt_id = parsed.path.removeprefix("/history/")
                    output_node = state.output_node(prompt_id)
                    filename = str(mode.get("unsafe_filename", "result.png"))
                    subfolder = str(mode.get("unsafe_subfolder", ""))
                    self._json(
                        200,
                        {
                            prompt_id: {
                                "status": {"completed": True, "status_str": "success"},
                                "outputs": {output_node: {"images": [{"filename": filename, "subfolder": subfolder, "type": "output"}]}},
                            }
                        },
                    )
                    return
                if mode.get("exit_on_history"):
                    os._exit(23)
                prompt_id = parsed.path.removeprefix("/history/")
                if mode.get("history_unknown"):
                    self._json(200, {})
                    return
                if mode.get("history_delay"):
                    time.sleep(float(mode["history_delay"]))
                if mode.get("malformed_history"):
                    self.send_response(200)
                    self.send_header("Content-Length", "3")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"not")
                    return
                with state.lock:
                    accepted = prompt_id in state.accepted_prompt_ids
                if not accepted:
                    self._json(200, {})
                    return
                if mode.get("history_wrong_id"):
                    self._json(200, {str(uuid.uuid4()): {"status": {"completed": True, "status_str": "success"}}})
                    return
                state.spawn_detached_descendant()
                output_node = state.output_node(prompt_id)
                self._json(
                    200,
                    {
                        prompt_id: {
                            "status": {"completed": True, "status_str": "success"},
                            "outputs": {output_node: {"images": [{"filename": "result.png", "subfolder": "", "type": "output"}]}},
                        }
                    },
                )
                return
            if parsed.path == "/view":
                query = parse_qs(parsed.query)
                if query.get("filename") != ["result.png"]:
                    self._json(404, {"error": "missing"})
                    return
                data = png(64, 64)
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()
                return
            self._json(404, {"error": "missing"})

        def do_POST(self) -> None:
            self._record_request()
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            if self.path == "/upload/image":
                if mode.get("upload_hang"):
                    time.sleep(float(mode["upload_hang"]))
                marker = b'filename="'
                start = body.index(marker) + len(marker)
                end = body.index(b'"', start)
                filename = body[start:end].decode("utf-8")
                self._json(200, {"name": filename, "subfolder": "", "type": "input"})
                return
            if self.path == "/prompt":
                payload = json.loads(body.decode("utf-8"))
                supplied_prompt_id = payload.get("prompt_id")
                if supplied_prompt_id is None:
                    prompt_id = str(uuid.uuid4())
                else:
                    try:
                        parsed_prompt_id = uuid.UUID(supplied_prompt_id)
                    except (ValueError, TypeError, AttributeError):
                        self._json(400, {"error": {"type": "invalid_prompt_id"}, "node_errors": {}})
                        return
                    if str(parsed_prompt_id) != supplied_prompt_id:
                        self._json(400, {"error": {"type": "invalid_prompt_id"}, "node_errors": {}})
                        return
                    prompt_id = supplied_prompt_id
                prompt_graph = payload.get("prompt")
                output_nodes = (
                    [
                        str(node_id)
                        for node_id, node in prompt_graph.items()
                        if isinstance(node, dict) and node.get("class_type") == "SaveImage"
                    ]
                    if isinstance(prompt_graph, dict)
                    else []
                )
                if len(output_nodes) == 1:
                    with state.lock:
                        state.output_nodes[prompt_id] = output_nodes[0]
                state.record("captured-prompt.bin", body, prompt_id)
                if mode.get("prompt_hang"):
                    time.sleep(float(mode["prompt_hang"]))
                if mode.get("exit_on_prompt"):
                    os._exit(24)
                if mode.get("lose_response") or mode.get("lose_response_history"):
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                if mode.get("malformed_prompt_response"):
                    self.send_response(200)
                    self.send_header("Content-Length", "3")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"bad")
                    return
                response_prompt_id = str(uuid.uuid4()) if mode.get("wrong_prompt_id") else prompt_id
                self._json(
                    200,
                    {"prompt_id": response_prompt_id, "number": 1, "node_errors": {}},
                )
                return
            self._json(404, {"error": "missing"})

    (cwd / "listener-pre-bind.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "host": options.listen,
                "port": options.port,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    try:
        server = ThreadingHTTPServer((options.listen, options.port), Handler)
    except OSError as error:
        (cwd / "listener-bind-error.json").write_text(
            json.dumps(
                {
                    "error": str(error),
                    "errno": error.errno,
                    "host": options.listen,
                    "port": options.port,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return 7
    server.daemon_threads = True
    (cwd / "listener-bound.json").write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "host": server.server_address[0],
                "port": server.server_address[1],
            }
        ),
        encoding="utf-8",
    )

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.serve_forever(poll_interval=0.05)
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
