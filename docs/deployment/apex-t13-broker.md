# APEX broker installation and operation

The broker runs on a trusted Linux workstation with systemd, unified cgroup v2,
and the supported ROCm GPU. The owner runs privileged installation and activation
in their own terminal after the applicable source and deployment review. See
[ADR 0007](../adr/0007-systemd-contained-attempt-lifecycle.md) for the lifecycle
and trust model.

## 1. Setup

Before changing an existing installation, identify its active unit, drop-ins,
broker configuration, executable, accounts, and data paths. Stop if the target
host or paths differ from this layout, if an ID is already assigned to an
unrelated identity, or if any change would affect another workload. Settle
active attempts and publications through the existing worker and recovery
commands before taking the installation offline.

| Account or group | UID / GID | Supplementary groups |
| --- | --- | --- |
| `media-generation-runner` | 970 / 970 | 971, 973, 990 |
| `media-generation-worker` | 972 / 972 | 973 |
| `media-generation-scratch` | GID 971 | Runner access to private scratch |
| `media-generation-model-read` | GID 973 | Read access to the protected candidate |
| `render` | GID 990 | Existing group for the two approved GPU devices |

Check keyed account and group records and the effective group list with `id`
under each identity. Give the runner no worker publication group, and the worker
no render or scratch group. Check the existing device assignments and access to
`/dev/kfd` and `/dev/dri/renderD128`. Leave device permissions and the other GPU
devices alone.

Use Python 3.14 or later and install the reviewed package and its dependencies in
a root-owned virtual environment built with `venv --copies`. Use the reviewed
source revision and verify the package from its trusted release reference before
installation. Keep the package tree root-owned and free of group/other write
access and extended ACLs. A stock `lib64 -> lib` symlink may remain if it resolves
inside the protected venv. Verify both console scripts and the interpreter
resolve to that installation. Run `pip check` once.

| Path | Owner / mode |
| --- | --- |
| `/opt/media-generation` | `root:media-generation-model-read 0710` |
| `/opt/media-generation/venv` | `root:root 0755` |
| `/etc/media-generation`, `broker.json` inside it | `root:root 0750`, `root:root 0600` |
| `/var/lib/media-generation-v9` | `root:root 0755` |
| `/var/lib/media-generation-v9/db`, `jobs.sqlite3` inside it | `root:media-generation-worker 1770`, `media-generation-worker:media-generation-worker 0660` |
| `/var/lib/media-generation-v9/systemd-evidence` | `root:media-generation-worker 0750` |
| `/var/lib/media-generation-v9/artifacts` | `media-generation-worker:media-generation-worker 0700` |
| `/var/lib/media-generation/scratch` | `root:media-generation-scratch 0710` |

Before changing the existing `/opt/media-generation` parent, inspect its
contents, ownership, ACLs, and users. Apply the listed mode only if newly granted
group traversal exposes no unintended path and existing services can still
operate. Scope setup to the listed paths. Keep the existing model and database
trees and any present deployment evidence intact.

Keep the candidate under `/srv/media-generation/candidates/qwen-image-edit-2511`.
Use the owner-selected protected mirror. For a new mirror, stage the copy, keep
runtime aliases usable without references to a service-writable location, and
verify the candidate declaration and model and recipe identities before making
it available. Check root ownership, traversal, ACLs, and write protection on the
installed files and directories. Use `root:973 2750` for ordinary mirror
directories, `0640` for data and libraries, and `0750` for files that must
execute. Existing mirror contents and historical qualification records remain
available for diagnosis.

For a fresh installation only, initialize the v9 database as the worker in the
new directory shown above. Verify the path is absent and its parents meet the
listed ownership and access policy before running this command:

```sh
runuser -u media-generation-worker -- /bin/sh -eu -c \
    'umask 0007; exec /opt/media-generation/venv/bin/python -' <<'PYTHON'
from pathlib import Path
from media_generation.store import SQLiteStore

SQLiteStore(Path("/var/lib/media-generation-v9/db/jobs.sqlite3"))
PYTHON
```

For an upgrade, preserve the v9 database, root ledger, artifacts, scratch, and
candidate. Check the schema in read-only mode. Broker startup creates the root
ledger if absent on a fresh install. It accepts the complete v1 schema and
leaves unsupported or incomplete existing ledgers untouched. If an established
installation has lost its ledger, stop and investigate before starting the
broker. The worker can read the ledger file, which is `root:972 0640`. The
runner has no database or ledger access.

### Broker configuration

Write `/etc/media-generation/broker.json` with these fields. For a staged
upgrade, set `runner_executable` and the unit's `ExecStart` to the same staged
venv and include the venv's mount in `RequiresMountsFor`.

```json
{
  "database_path": "/var/lib/media-generation-v9/db/jobs.sqlite3",
  "socket_path": "/run/media-generation/attempt-broker.sock",
  "scratch_root": "/var/lib/media-generation/scratch",
  "runner_executable": "/opt/media-generation/venv/bin/media-generation-attempt-runner",
  "runner_uid": 970,
  "runner_gid": 970,
  "runner_supplementary_gids": [
    971,
    973,
    990
  ],
  "worker_uid": 972,
  "worker_gid": 972,
  "scratch_gid": 971,
  "model_read_gid": 973,
  "device_allow": [
    "/dev/kfd",
    "/dev/dri/renderD128"
  ],
  "read_roots": [
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime",
    "/srv/media-generation/candidates/qwen-image-edit-2511/inputs"
  ],
  "environment_path_allowlist": [
    "/usr/bin",
    "/opt/media-generation/loader-priority",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/llvm/lib",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/rocm_sysdeps/lib"
  ],
  "empty_timeout_seconds": 30
}
```

Install the unit as
`/etc/systemd/system/media-generation-systemd-broker.service`, owned by
`root:root` with mode `0644`:

```ini
[Unit]
Description=Media Generation systemd attempt broker
After=local-fs.target
RequiresMountsFor=/opt/media-generation /etc/media-generation \
    /var/lib/media-generation-v9/db /var/lib/media-generation-v9/systemd-evidence \
    /var/lib/media-generation/scratch \
    /srv/media-generation/candidates/qwen-image-edit-2511

[Service]
Type=exec
User=root
Group=root
UMask=0077
WorkingDirectory=/
RuntimeDirectory=media-generation
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=no
ExecStart=/opt/media-generation/venv/bin/media-generation-systemd-broker /etc/media-generation/broker.json
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/run/media-generation /var/lib/media-generation-v9/db /var/lib/media-generation-v9/systemd-evidence /var/lib/media-generation/scratch
```

The broker sets the runtime directory group in its main process before binding
the socket. Keep the single `ExecStart`. The worker uses only the broker socket.
The transient service uses the separate runner identity, the two allowed GPU
devices, and the attempt scratch directory. Its engine runs with `/` as its
working directory.

## 2. Readiness

1. Verify the selected engine path, supported CLI and recipe, and readable model
   and recipe files under the protected candidate roots. A compatible
   replacement at the same path can run with the existing declaration. New
   attempts record the executable they observe. Old executable hashes and
   version markers are historical or diagnostic data. The runtime is usable
   when the configured engine can perform the required work.
2. Set `PATH=/usr/bin` and set `ROCM_PATH` to the SDK directory in the broker
   allowlist. Set the worker's `LD_LIBRARY_PATH` to
   `/opt/media-generation/loader-priority:$ROCM_PATH/lib:$ROCM_PATH/lib/llvm/lib:$ROCM_PATH/lib/rocm_sysdeps/lib`.
   Create the root-owned, non-writable priority directory with a
   `libgomp.so.1` symlink to the host's GNU system `libgomp.so.1`. Verify
   once with the runner's credentials, environment, and working directory
   that the system dynamic loader's `--list` output resolves that soname
   to the GNU package and has no unresolved dependencies. This is a
   readiness diagnostic for the configured engine and run environment.
3. Run `systemd-analyze verify` on the staged unit. Confirm the service
   identities, socket path, GPU devices, scratch, database, and ledger paths
   match this configuration. Keep the installation paused if a path,
   ownership, or credentials check fails.

## 3. Manual activation

After review and approval of the installation, reload systemd and inspect the
loaded fragment, drop-ins, `ExecStart`, and writable paths. Start the broker
manually with `systemctl start media-generation-systemd-broker.service`. Leave
boot activation disabled.

Check service health and its startup diagnostics. The broker checks private
runtime file permissions before serving requests. Verify the worker can reach
the `root:972 0660` socket and an unrelated account cannot. Confirm with the
actual service credentials that the runner can access the approved devices and
scratch and cannot read the worker's database or artifacts. The worker should
read the ledger with write access denied and have no access to scratch or the GPU
devices. Keep the worker stopped until these checks pass.

For separately approved real-engine qualification, run one small generation,
one running cancellation, and one bounded process-loss recovery in a quiet GPU
window. Record the candidate and host once, then record publication, matching
cgroup proof, and GPU reuse or quarantine for each exercise. Static readiness
and software tests alone leave APEX qualification pending.

## 4. Recovery and rollback

Use the worker's existing `recover` command with the configured database, output
directory, socket, scratch root, and runner UID/GID. Resolve uncertain attempts
before starting new work. If exact termination or publication reconciliation
cannot be established, leave the resource quarantined and preserve the ledger,
database, unit evidence, and scratch for investigation.

For an update, pause admission and dispatch, settle every active attempt and
publication, and stop the broker. Retain the previous venv, broker
configuration, unit, and worker runtime environment as a matched set. Stage
changes separately, repeat readiness checks, and restart manually. For
rollback, repeat the same quiescence checks, restore the matched set, reload
systemd, and verify the loaded unit before manual activation. Keep the v9
database, v1 ledger, artifacts, and candidate in place. If their status is
uncertain or the old software cannot read them, stop for recovery before
switching back.
