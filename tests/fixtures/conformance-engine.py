#!/usr/bin/env python3
"""Pinned stand-in for a stable-diffusion.cpp executable.

The script parses the documented command line, writes a valid PNG of the
requested size, and can be told to fail, write invalid or partial bytes, sleep,
leave a grandchild process behind, print a credential while echoing the request,
or leave a detached descendant that closes its inherited pipes. Behavior is
selected by an optional
``conformance-mode.json`` file beside this script. A report file, when named in
that document, captures the parsed argument values for assertions.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)


def _png(width: int, height: int, seed: int) -> bytes:
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        for x in range(width):
            scanlines.extend(
                (
                    (x * 7 + y * 3 + seed) & 0xFF,
                    (x * 5 + y * 11 + seed // 3) & 0xFF,
                    (x + y * 2 + seed // 7) & 0xFF,
                )
            )
    data = bytearray(b"\x89PNG\r\n\x1a\n")
    data.extend(_png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
    data.extend(_png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)))
    data.extend(_png_chunk(b"IEND", b""))
    return bytes(data)


def _next_value(argv: list[str], index: int) -> tuple[str, int]:
    if index + 1 >= len(argv):
        raise SystemExit(f"missing value for {argv[index]}")
    return argv[index + 1], index + 2


def main(argv: list[str]) -> int:
    if "--version" in argv:
        sys.stdout.write("stable-diffusion.cpp conformance-1\n")
        return 0
    mode_path = Path(__file__).resolve().parent / "conformance-mode.json"
    mode = json.loads(mode_path.read_text(encoding="utf-8")) if mode_path.exists() else {}
    parsed: dict[str, object] = {
        "references": [],
        "model_args": [],
        "zero_conditioning_bare": False,
    }
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument in {"-r", "--ref-image"}:
            value, index = _next_value(argv, index)
            parsed["references"].append(value)  # type: ignore[union-attr]
        elif argument in {"-i", "--init-img"}:
            parsed["init_image"], index = _next_value(argv, index)
        elif argument in {"-o", "--output"}:
            parsed["output"], index = _next_value(argv, index)
        elif argument in {"-W", "--width"}:
            value, index = _next_value(argv, index)
            parsed["width"] = int(value)
        elif argument in {"-H", "--height"}:
            value, index = _next_value(argv, index)
            parsed["height"] = int(value)
        elif argument in {"-p", "--prompt"}:
            parsed["prompt"], index = _next_value(argv, index)
        elif argument == "--seed":
            value, index = _next_value(argv, index)
            parsed["seed"] = int(value)
        elif argument == "--steps":
            value, index = _next_value(argv, index)
            parsed["steps"] = int(value)
        elif argument in {"--cfg-scale", "--cfg_scale"}:
            value, index = _next_value(argv, index)
            parsed["cfg_scale"] = float(value)
        elif argument == "--flow-shift":
            value, index = _next_value(argv, index)
            parsed["flow_shift"] = float(value)
        elif argument == "--sampling-method":
            parsed["sampling_method"], index = _next_value(argv, index)
        elif argument == "--strength":
            value, index = _next_value(argv, index)
            parsed["strength"] = float(value)
        elif argument == "--model-args":
            value, index = _next_value(argv, index)
            parsed["model_args"] = value.split(",")
        elif argument == "--qwen-image-zero-cond-t":
            parsed["zero_conditioning_bare"] = True
            index += 1
        elif argument in {
            "--diffusion-model",
            "--vae",
            "--llm",
            "--llm_vision",
            "--lora-model-dir",
        }:
            value, index = _next_value(argv, index)
            parsed[argument.lstrip("-")] = value
        else:
            sys.stderr.write(f"unsupported argument: {argument}\n")
            return 2
    parsed["argv"] = list(argv)
    report_path = mode.get("report_path")
    if report_path:
        Path(str(report_path)).write_text(json.dumps(parsed), encoding="utf-8")
    behavior = mode.get("behavior", "ok")
    if behavior == "sleep":
        time.sleep(float(mode.get("sleep_seconds", 0.3)))
    if behavior == "exit_nonzero":
        sys.stderr.write("conformance engine refused\n")
        return int(mode.get("exit_code", 3))
    output = Path(str(parsed.get("output", "output.png")))
    width = int(parsed.get("width", 512))
    height = int(parsed.get("height", 512))
    seed = int(parsed.get("seed", 42))
    if behavior == "invalid_bytes":
        output.write_bytes(b"not-a-png")
    elif behavior == "partial_bytes":
        output.write_bytes(_png(width, height, seed)[:32])
    else:
        output.write_bytes(_png(width, height, seed))
    if behavior == "echo_secrets":
        # Repeat the request and a credential so tests can prove that neither
        # value reaches persisted evidence or command output.
        sys.stdout.write(f"prompt={parsed.get('prompt', '')}\n")
        sys.stdout.flush()
        sys.stderr.write("api_key=sk-live-CONFORMANCE-0123456789\n")
        sys.stderr.flush()
        return 0

    if behavior == "detached_grandchild":
        # The descendant closes the inherited pipes and keeps running after
        # this process exits, so supervision cannot observe it.
        sleep_seconds = float(mode.get("descendant_sleep_seconds", 2))
        descendant = subprocess.Popen(
            [sys.executable, "-c", f"import time; time.sleep({sleep_seconds})"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid_path = mode.get("descendant_pid_path")
        if pid_path:
            Path(str(pid_path)).write_text(str(descendant.pid), encoding="utf-8")
        sys.stdout.write("conformance-engine ok\n")
        sys.stdout.flush()
        return 0

    if behavior == "grandchild":
        subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    sys.stdout.write("conformance-engine ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
