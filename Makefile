# Canonical development commands. The first target is the GNU/BSD make default.

PYTHON ?= python3
PYTEST_ARGS ?=
CLI ?=

export PYTHON
export CLI

LOCK_RUNNER = "$$PYTHON" scripts/with_worktree_lock.py --

.PHONY: help setup install test smoke check clean clean-dry-run clean-deep

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  help            Show this target catalog (default)."
	@echo "  setup           Create or refresh the .venv environment with PYTHON."
	@echo "  install         Install the package and test dependencies with PYTHON."
	@echo "  test            Run the full pytest suite."
	@echo "  smoke           Run the installed media-generation CLI help command."
	@echo "  check           Run test and smoke as the aggregate validation gate."
	@echo "  clean           Remove verified regenerable outputs through scripts/clean.py."
	@echo "  clean-dry-run   Show the cleanup plan without changing files."
	@echo "  clean-deep      Prompt to remove a validated worktree-local .venv."
	@echo ""
	@echo "PYTHON defaults to python3; smoke uses the matching console script."
	@echo "Run make clean-dry-run before make clean and compare the two reports."

setup:
	@$(LOCK_RUNNER) "$$PYTHON" -m venv .venv

install:
	@$(LOCK_RUNNER) "$$PYTHON" -m pip install -e '.[test]'

test:
	@$(LOCK_RUNNER) "$$PYTHON" -m pytest $(PYTEST_ARGS)

smoke:
	@cli="$$CLI"; if [ -z "$$cli" ]; then cli="$$(dirname "$$(command -v "$$PYTHON")")/media-generation"; fi; exec $(LOCK_RUNNER) "$$cli" --help

check: test smoke

clean:
	@"$$PYTHON" scripts/clean.py

clean-dry-run:
	@"$$PYTHON" scripts/clean.py --dry-run

clean-deep:
	@"$$PYTHON" scripts/clean.py deep --include-venv
