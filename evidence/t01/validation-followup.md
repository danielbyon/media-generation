# Historical local validation record

Validation ID `validation-2026-10-21T21-35-37-067Z-736f8f73` was a **pre-commit** validation of the then-current uncommitted T01 worktree. It predates the later Cubic finding and relocation atomicity fix, so it is historical evidence and does not validate the final local changes.

- Branch: `codex/t01-generation-service`
- Checked-out commit: `cdf9349dbe2fbaa8743f00df3ad68528112ccc53`
- Working-tree fingerprint: `43251f095f715ff194d3033a822fe5b55464caddc360884c2803ae37d96033cc`
- Validation ID: `validation-2026-10-21T21-35-37-067Z-736f8f73`
- Timestamp: `2026-10-21T21:35:37.108Z`
- Approved profile: `test`
- Selected command: `.venv/bin/python -m pytest`
- Result: passed, 1/1 validation commands, exit code 0

The validator tied this run to base SHA `cdf9349dbe2fbaa8743f00df3ad68528112ccc53` and worktree fingerprint `43251f095f715ff194d3033a822fe5b55464caddc360884c2803ae37d96033cc`. The SHA identifies the checked-out base commit; the fingerprint identifies the uncommitted tree that was tested. No commit or hosted CI was validated by this run.

The historical `validator-result.json` was preserved byte-for-byte. Its SHA-256 before and after evidence relocation was `c108c065e67e7d19c2ef28a7c5078dcb2668188487d1820a7ae39f90b0292bdd`.

The exact approved validator result is in `validation-followup.json`; its captured pytest output records 26 tests. The separate `full-suite-transcript.txt` records 27 tests and is associated with `validation-post-cubic-fix.md`. The later `full-suite-after-nested-config-fix.txt` records 29 tests.
