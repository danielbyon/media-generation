# Development cleanup

## 1. Operating contract

Cleanup is a manual utility for a trusted operator in an idle checkout. Stop all
build, test, install, generation and other cleanup processes before running it.
The command does not detect all active processes and is not a security boundary
against hostile same-user writers or deliberate path replacement. No OS sandbox,
privileged helper or atomic compare-and-delete guarantee is provided.

## 2. Commands

`make help` is the harmless default. `make setup` creates `.venv` using `PYTHON`
(default `python3`); the selected interpreter must already exist. `make install`
installs the project and test dependencies. `make test` runs pytest; `make smoke`
runs the selected installed CLI's help; `make check` aggregates test and smoke.
`PYTHON` selects an interpreter and `CLI` can select an explicit console script.
All targets are phony and use portable Make syntax.

`make clean` delegates to the same standalone stdlib-and-Git cleanup engine as:

```sh
python3 scripts/clean.py --dry-run
python3 scripts/clean.py
python3 scripts/clean.py deep --include-venv --dry-run
python3 scripts/clean.py deep --include-venv
```

`make clean-dry-run` is the corresponding default dry run. Cleanup never installs
dependencies, runs tests, accesses the network or invokes Git clean. The CLI
disables import bytecode before loading internal modules; help and dry-run
produce no cache, lock or log files, even without PYTHONDONTWRITEBYTECODE.

## 3. Default allowlist and exclusions

Default cleanup recognizes bytecode (`__pycache__`, `.pyc`, `.pyo`), the canonical
pytest cache layout with its signature, and this project's validated editable
metadata. A setuptools build tree is eligible only when its package files match
current source exactly. Mixed, suspicious or unknown build trees and all `dist`
content remain untouched. Unknown entries inside a candidate cause refusal.
Missing candidates and repeated cleanup safely no-op.

Default mode preserves `.venv`, `.chatgpt`, `.serena`, `.codegraph`, credentials,
configuration, models, fixtures, snapshots, evidence, local indexes, SQLite
databases and sidecars, media/output, `.artifact-publication.lock`, journals,
private stages and `.artifact-cleanup`. Application data is never a default
cleanup candidate. Source is protected except for the named generated metadata.

## 4. Worktree boundaries

Authority follows the physical cleanup script's Git worktree, not the shell's
working directory. Symlinked script ancestors, ambiguous Git routing, candidate
symlinks, tracked/indexed paths, hard-linked files, nested working or bare Git repositories and
cross-filesystem trees are refused. Directory descriptors and no-follow opens
keep ordinary traversal inside the validated checkout. Linked worktrees are
independent; common Git metadata and sibling checkouts are never cleanup roots.
Traversal depth and entry budgets produce controlled errors. These checks are
ordinary boundary protections, not promises against concurrent hostile mutation.

## 5. Confirmed deep cleanup

`make clean-deep` or direct `deep --include-venv` is separate and opt-in. Interactive
use warns and requires the exact phrase `remove .venv`; noninteractive use needs
`--confirm`. Without confirmation no cleanup takes place. Deep dry-run needs no
confirmation and preserves every byte.

WARNING: confirmed deep cleanup deletes the ENTIRE verified local `.venv`,
including custom files, credentials, media, manually installed packages and
operator notes inside that environment. Back up anything needed first. Operator
confirmation authorizes disposal of all those contents; package ownership,
RECORD hashes and ensurepip wheel layout are not disposal requirements.

The environment must be a real checkout-root `.venv` directory with plausible
`pyvenv.cfg` containing a Python home and `include-system-site-packages = false`.
Symlinked/external/shared environments, active Python environments, tracked
contents, nested working or bare Git repositories and unsafe traversal are refused. Internal venv
symlinks are unlinked as entries, never followed to external targets. Standard
Python 3.11/3.13/3.14 and distro-created environments need no package attestation.
Default help/test/check/clean never select deep removal implicitly.

## 6. Reports and failures

Human and `--json` reports identify candidates, categories, estimated bytes,
planned/removed/skipped/error counts and reasons. `estimated_removable_bytes`
is an allocation estimate; actual reclaimed space is a worktree-wide free-space
observation and can differ. Per-entry/category reclaimed values remain zero.
Compare `make clean-dry-run` against the actual run before removal.

Genuine I/O, permission, ownership, nested-repository and validation failures
produce nonzero partial reports. Independent candidates can still succeed.
An interrupted or failed directory removal can leave an incompletely removed
candidate at its original path; the error names partial removal and the number
of child entries already removed, retaining the validated byte estimate. Inspect
the report before retrying. No capture
quarantine is created. A simple advisory directory lock may refuse a cooperating
producer, but the operator must stop every writer regardless: direct tools do
not necessarily take the lock.
