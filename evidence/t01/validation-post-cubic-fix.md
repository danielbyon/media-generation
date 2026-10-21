# Approved validation after relocation atomicity fix

The full approved test profile was rerun after the evidence relocation atomicity fix.

- Branch: `codex/t01-generation-service`
- Checked-out base SHA: `cdf9349dbe2fbaa8743f00df3ad68528112ccc53`
- Worktree fingerprint: `b0265dd2a839ff2eb308636ee09af315e67fcc555505118b4ec0137cf6971be0`
- Validation ID: `validation-2026-10-21T21-43-06-918Z-47b11dfe`
- Timestamp: `2026-10-21T21:43:07.052Z`
- Profile: `test`
- Command: `.venv/bin/python -m pytest`
- Result: passed, 1/1 commands, exit code 0
- Full direct pytest transcript: `full-suite-transcript.txt` (27 passed)

The validator associates this result with the checked-out base commit and the exact uncommitted worktree fingerprint above. No commit was created and no hosted CI run is claimed. The earlier validation ID `validation-2026-10-21T21-35-37-067Z-736f8f73` remains separately documented as a pre-commit result in `validation-followup.md`; it was run against base SHA `cdf9349dbe2fbaa8743f00df3ad68528112ccc53` with worktree fingerprint `43251f095f715ff194d3033a822fe5b55464caddc360884c2803ae37d96033cc`.

The original historical `validator-result.json` was not modified.
