#!/usr/bin/env python3
"""Run a cooperating producer while holding this worktree's cleanup lock."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import clean


def main(argv: Sequence[str] | None = None) -> int:
    """Acquire the directory lock, execute one command, and preserve its status."""

    parser = argparse.ArgumentParser(
        description=(
            "Run a cooperative build or test command while holding the same "
            "worktree-scoped advisory lock used by cleanup."
        )
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = list(arguments.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a command is required after --")

    try:
        authority = clean.resolve_worktree_pinned(Path(__file__))
        try:
            with clean.worktree_lock(authority, blocking=True):
                result = subprocess.run(command, check=False)
        finally:
            os.close(authority.root_fd)
    except KeyboardInterrupt:
        return 130
    except (clean.CleanupError, OSError) as error:
        print(f"worktree lock: {error}", file=sys.stderr)
        return 2
    if result.returncode < 0:
        return 128 + abs(result.returncode)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
