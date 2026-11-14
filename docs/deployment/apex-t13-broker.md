# APEX T13 broker deployment proposal

This file records a host-specific deployment proposal for T13. It is not an
installation record. No account, group, directory, permission, unit, or device
change is authorized by approval of the software design.

## 1. Read-only host facts

The latest SSH inspection found Ubuntu 26.04.1, kernel `7.0.0-43-generic`,
systemd `259.9`, and the unified cgroup v2 hierarchy. The existing engine is
`sd-cli` from stable-diffusion.cpp commit `b13a482`; `sd-cli --version` reports
`master-975-95b3090-2-gb13a482` and the recorded build is
`rocm-10.1.0-gfx1151-hipblas`. Its dynamic loader resolves `libamdhip64.so.7`
and ROCm BLAS/solver libraries from the existing ROCm virtual environment.
The missing `rocminfo`, `rocm-smi`, and `amd-smi` commands therefore do not mean
the runtime libraries are absent.

The current candidate files are under `/home/daniel`, whose home directory is
mode `0750`. A new runner with UID 970 cannot traverse that tree. The existing
T07 declaration and trusted evidence are at:

```text
/home/daniel/ai/qualification-runs/t08-20261031T045433Z/evidence/t07-candidate-signed/candidate.json
/home/daniel/ai/qualification-runs/t08-20261031T045433Z/evidence/t07-candidate-signed/trusted-evidence.json
```

The declaration currently points at these roots:

```text
engine_bin  /home/daniel/ai/qualification-runs/t08-20261031T045433Z/runtime/sd-cpp-hip-b13a482-develvenv/bin
models      /home/daniel/ai/qualification-runs/t08-20261031T045433Z/inputs/models
vae         /home/daniel/ai/hf-repos/qwen-image-components/split_files/vae
draft       /home/daniel/ai/qualification-runs/t08-20261031T045433Z/evidence/t07-candidate-draft
```

The engine SHA-256 is
`884100c873d73f4e969664a3093ffd3a20b1cb24fdc8aea341933aa81e73a847`.
The pinned model files are `qwen-image-edit-2511-Q4_K_M.gguf` (12,842,830,432
bytes) and `qwen_2.5_vl_7b.safetensors` (16,584,415,576 bytes). The VAE is
`qwen_image_vae.safetensors` (253,806,246 bytes). The existing T07 signed
candidate was previously evaluated `READY` at its original paths; that result
does not qualify a copied or path-rewritten mirror. The mirror declaration
must be evaluated again with its trusted evidence before it can be selected.

The GPU nodes are `root:render` (`/dev/kfd` and
`/dev/dri/renderD128`, GID 990) and `root:video` (`/dev/dri/card1`, GID 44),
all mode `0660`. The proposed `/srv/media-generation` mirror and
`/run/media-generation` directory do not exist. `/srv` is `root:root 0755`;
`/run` is `root:root 0755`. UIDs 970 and 972 and GIDs 970 through 973 were
free at the latest check. UID 973 belongs to the existing `sshd` account with
primary GID 65534; that UID is not part of this proposal. GIDs 990 and 44
already exist. Recheck each UID and GID separately, along with device modes,
immediately before any owner-authorized provisioning.

The current `/etc/nsswitch.conf` uses `passwd: files systemd sss` and
`group: files systemd sss`. The Linux broker requires complete local `files`
sources for both databases and for an explicit `initgroups` source. It reads
the protected `/etc/passwd` file directly to include every primary GID;
`getpwall()` can return a partial list without reporting an enumeration error.
The current APEX NSS policy therefore blocks broker startup. The owner must
authorize either a reviewed NSS policy change or a separate, verifiable
identity-enumeration design. No NSS configuration was changed.

The proposed service accounts are not installed, so effective access has not
been tested under UIDs 970 and 972. The owner checks in section 6 cover model,
runtime, ROCm marker, GPU, and socket access after the identities are approved.

The existing `daniel` account is a member of both GID 44 and GID 990 and keeps
that access. No existing account or device permission is changed by this
proposal. Broker admission covers only its own attempts, so real-engine
qualification must confirm that no unrelated inference workload is competing
for the GPU.

## 2. Identities and access policy

| Name | ID | Membership and access |
| --- | ---: | --- |
| `media-generation-runner` user and primary group | UID/GID 970 | Supplementary GIDs 44 (`video`), 971 (scratch), 973 (model/runtime read), and 990 (`render`). No GID 972. |
| `media-generation-scratch` group | GID 971 | Runner only. The broker creates each attempt directory as `root:media-generation-scratch 2770`. |
| `media-generation-worker` user and primary group | UID/GID 972 | Supplementary GID 973 only. No GPU or scratch groups. Owns the worker database and publication output. |
| `media-generation-model-read` group | GID 973 | Runner and worker only. Read/traverse access to the immutable candidate mirror. |
| Existing `video` and `render` groups | GIDs 44 and 990 | Add the runner for GPU access. Preserve the existing `daniel` membership; these shared host groups are not private access boundaries. |

The broker requires the runner's actual NSS groups to be a subset of its
configured list and the worker's actual groups to equal `{972, 973}`. It also
enumerates group records and primary account GIDs. The runner primary group
must contain only the runner; the worker primary group only the worker; the
scratch group only the runner; and the model-read group exactly the runner and
worker. It refuses startup if NSS cannot provide that membership data. The
worker is not the existing `daniel` account.

The broker checks Unix owner/group/other bits. Named ACL entries are not an
accepted substitute. The scratch-root path and the mirror must have no extended
or default ACLs. Set mirror directories to `root:973 2750`, ordinary files to
`root:973 0640`, and executable files such as `sd-cli` to `root:973 0750`.
These modes give the runner and worker read access without granting either
write access to runtime or model data. The worker can execute the group-
executable engine file but has no GPU or scratch device access.

The original `/home/daniel` trees remain untouched. Copy the engine runtime,
ROCm runtime, models, VAE, request fixtures, candidate declaration, trusted
evidence, recipe, and evidence documents into this proposed mirror:

```text
/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1
```

Rewrite only the copied candidate declaration's four root paths to the mirror,
preserve the pinned content hashes, remove extended ACLs from the mirror, apply
the modes above, and rerun T07 evaluation. Any trusted-evidence mismatch,
content hash mismatch, symlink, unreadable path, or non-`READY` result blocks
qualification. Do not make the original model or runtime tree accessible by
changing its permissions.

## 3. Broker policy file

After provisioning the mirror, write this exact field set to
`/etc/media-generation/broker.json` as `root:root 0600`. The paths are fixed to
the proposed APEX layout; the broker refuses unknown or missing fields.

```json
{
  "database_path": "/var/lib/media-generation-v9/db/jobs.sqlite3",
  "socket_path": "/run/media-generation/attempt-broker.sock",
  "scratch_root": "/var/lib/media-generation/scratch",
  "runner_executable": "/opt/media-generation/t13/venv/bin/media-generation-attempt-runner",
  "runner_uid": 970,
  "runner_gid": 970,
  "runner_supplementary_gids": [44, 971, 973, 990],
  "worker_uid": 972,
  "worker_gid": 972,
  "scratch_gid": 971,
  "model_read_gid": 973,
  "device_allow": [
    "/dev/kfd",
    "/dev/dri/renderD128",
    "/dev/dri/card1"
  ],
  "read_roots": [
    "/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1/runtime",
    "/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1/inputs"
  ],
  "environment_path_allowlist": [
    "/usr/bin",
    "/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel",
    "/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib"
  ],
  "empty_timeout_seconds": 30
}
```

Set the worker process environment to the corresponding approved values:
`PATH=/usr/bin`, `ROCM_PATH` to the mirrored `_rocm_sdk_devel` directory, and
`LD_LIBRARY_PATH` to its `lib` directory. The existing SHA-256 environment
binding remains in force: every resolved invocation records and verifies the
effective values. Do not bypass the digest or silently add search paths; if
runtime inspection shows another required directory, add that exact root to
the broker allowlist and re-review the policy before any execution.

At launch, the broker inspects every direct entry in `PATH` and every file and
directory beneath each `LD_LIBRARY_PATH` entry, including loader-selected
`glibc-hwcaps` subdirectories. Search directories, files, and symlink targets
must be root-owned and must not be writable by the worker or runner or have
group/world write bits. A symlink to a loader subdirectory is rejected. File
symlink resolution checks each path component; its directories must be
root-owned and nonreplaceable. Both services must be able to read runtime
libraries, and the runner must be able to execute executable `PATH` entries.
Private engine and model files must not be world-readable. An unsafe or
uninspectable entry blocks the launch.

The read roots above cover the mirrored engine, model, VAE, and fixture paths.
Every engine input, including `-r`, must be a root-owned file with no
group/world write permission, no world-read permission, and no symlink in its
path. Published artifacts are mode `0600`, and the runner is not a member of
the worker publication group. Therefore reference-conditioned commands that
pass a published artifact through `-r` cannot pass current validation. Do not
add the runner to GID 972 or make every artifact group-readable. Such execution
remains blocked until a separately reviewed per-attempt read-only reference
handoff is implemented and qualified.

## 4. Data and runtime paths

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/opt/media-generation/t13` and `venv` | `root:root 0755`; package files not group/world writable | Isolated Python 3.14.4 installation of the exact T13 commit; contains both console scripts. |
| `/etc/media-generation` | `root:root 0750` | Fixed broker configuration directory. |
| `/etc/media-generation/broker.json` | `root:root 0600` | Exact broker policy above. |
| `/var/lib/media-generation-v9` | `root:root 0755` | Fresh schema-v9 deployment root. |
| `/var/lib/media-generation-v9/db` | `root:media-generation-worker 1770` | Sticky, worker-writable SQLite directory beneath root-owned ancestors. |
| `jobs.sqlite3` | `media-generation-worker:media-generation-worker 0660` | Fresh v9 database created as the worker; the root broker also writes it. |
| `/var/lib/media-generation-v9/systemd-evidence` | `root:media-generation-worker 0750` | Precreated, root-owned ledger directory. The worker can traverse and read ledger files but cannot create SQLite sidecars. |
| `/var/lib/media-generation-v9/systemd-evidence/db-jobs.sqlite3.systemd-evidence.sqlite3` | `root:media-generation-worker 0640` | Root-authored evidence ledger, created by the broker on first start. |
| `/var/lib/media-generation-v9/artifacts` | `media-generation-worker:media-generation-worker 0700` | Worker-only publication output. The runner cannot read or publish these files. |
| `/var/lib/media-generation/scratch` | `root:media-generation-scratch 0710` | Root-owned, non-group-writable parent with runner group traversal only. |
| `/var/lib/media-generation/scratch/<attempt-id>` | `root:media-generation-scratch 2770` | Broker-created private attempt directory; the worker is not a member of GID 971. |
| `/run/media-generation` while broker runs | `root:media-generation-worker 0750` | Worker-traversable socket directory; not group-writable. |
| `/run/media-generation/attempt-broker.sock` | `root:media-generation-worker 0660` | The only worker-to-broker control socket. |
| `/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1` | `root:media-generation-model-read 2750` directories | Read-only mirror; ordinary files `0640`, engine executable `0750`, no extended ACLs. |

The old database is not migrated or reused. Initialize only the new v9 path as
the worker with umask `0007`; this creates the schema with a worker-owned
`0660` database file in the sticky root-owned `db` directory. After creating
the worker group, provision the root-owned evidence directory before starting
the broker:

```sh
install -d -o root -g media-generation-worker -m 0750 \
    /var/lib/media-generation-v9/systemd-evidence
```

The broker creates the root-owned evidence ledger there. The engine runner
receives no database path or database group membership.

## 5. Broker service unit

Install as `/etc/systemd/system/media-generation-systemd-broker.service`:

```ini
[Unit]
Description=Media Generation systemd attempt broker
After=local-fs.target
RequiresMountsFor=/opt/media-generation/t13 /etc/media-generation /var/lib/media-generation-v9/db /var/lib/media-generation/scratch /srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1

[Service]
Type=exec
User=root
Group=root
UMask=0077
WorkingDirectory=/
RuntimeDirectory=media-generation
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=no
ExecStart=/opt/media-generation/t13/venv/bin/media-generation-systemd-broker /etc/media-generation/broker.json
Restart=on-failure
RestartSec=2s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/run/media-generation /var/lib/media-generation-v9/db /var/lib/media-generation-v9/systemd-evidence /var/lib/media-generation/scratch
```

`RuntimeDirectoryGroup=` and `ExecStartPre=` are deliberately absent. systemd
creates `/run/media-generation` as `root:root 0750` before the single broker
`ExecStart`. During that main process invocation, the root broker changes the
directory to `root:media-generation-worker 0750`, verifies its owner, group,
mode, ACL state, and worker traversal, then binds the socket. systemd 259 sets
up runtime directories for each command invocation; no later command runs
after the broker changes ownership, so systemd does not reset it while that
process remains active. On restart, systemd removes the directory because
`RuntimeDirectoryPreserve=no`, recreates it, and the next broker invocation
repeats the checked ownership change. See the versioned
[systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/259/systemd.exec.html)
and [systemd.service(5)](https://www.freedesktop.org/software/systemd/man/259/systemd.service.html)
manuals and [systemd 259's runtime-directory setup](https://github.com/systemd/systemd/blob/v259/src/core/exec-invoke.c).

The root-owned broker is the actual authorization boundary. It calls the
system manager as root, so polkit is not a property-level sandbox for it. The
worker has only the socket protocol, whose peer UID/GID are checked; it gets no
systemd manager access. The broker builds the transient runner unit from fixed
properties and the immutable attempt identity. The unit-name prefix by itself
does not authorize an executable, user, property, or unit operation.

The broker invokes `/usr/bin/systemd-run` with `--system --quiet --pipe --wait`,
the canonical attempt unit name, `--service-type=exec`, the attempt scratch
directory as the service working directory, and the fixed runner executable.
It sets these properties on every attempt:

| Property | Value |
| --- | --- |
| `User`, `Group` | `970`, `970` |
| `SupplementaryGroups` | `44 971 973 990` |
| `RemainAfterExit`, `KillMode`, `Delegate` | `yes`, `control-group`, `no` |
| `NoNewPrivileges`, `ProtectSystem`, `ProtectHome` | `yes`, `strict`, `read-only` |
| `PrivateDevices`, `DevicePolicy` | `no`, `closed` |
| `ReadWritePaths` | The absolute per-attempt scratch directory |
| `CapabilityBoundingSet` | Empty |
| `RestrictSUIDSGID`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictNamespaces` | `yes` |
| `UMask` | `0077` |
| `DeviceAllow` | `/dev/kfd rw`, `/dev/dri/renderD128 rw`, `/dev/dri/card1 rw` |

The runner service starts in its scratch directory. Its `ProcessSupervisor`
launches the engine with `/` as its current directory and passes absolute
scratch, model, and output paths. This keeps writable scratch out of the
engine's dynamic-loader search through an empty path entry.

## 6. Owner-only installation and verification sequence

The installation commands require separate owner authorization. The service
unit passed `systemd-analyze verify` with systemd 259.9 in an isolated temporary
root containing a stub broker executable. No unit was installed or started.

1. Before creating users or groups, run this read-only preflight. It checks
   the assigned numeric IDs, preserves UID 973 for `sshd`, verifies the
   existing GPU groups, and stops if NSS cannot provide complete local
   identity records. The current `files systemd sss` configuration fails the
   NSS check; do not continue until the owner authorizes a verified identity
   source.

   ```sh
   set -eu
   for uid in 970 972; do
       if getent passwd "$uid" >/dev/null; then
           echo "UID $uid is already assigned" >&2
           exit 1
       fi
   done
   test "$(getent passwd 973 | cut -d: -f1)" = sshd
   test "$(getent passwd 973 | cut -d: -f4)" = 65534
   for gid in 970 971 972 973; do
       if getent group "$gid" >/dev/null; then
           echo "GID $gid is already assigned" >&2
           exit 1
       fi
   done
   test "$(getent group 44 | cut -d: -f1)" = video
   test "$(getent group 990 | cut -d: -f1)" = render
   python3 - <<'PY'
   from pathlib import Path

   entries = {}
   for raw_line in Path("/etc/nsswitch.conf").read_text(encoding="utf-8").splitlines():
       line = raw_line.split("#", 1)[0].strip()
       if not line or ":" not in line:
           continue
       name, value = line.split(":", 1)
       sources = []
       for token in value.split():
           if token.startswith("[") and token.endswith("]"):
               continue
           if "[" in token or "]" in token:
               raise SystemExit(f"malformed NSS action: {token}")
           sources.append(token)
       if name.strip() in {"passwd", "group", "initgroups"}:
           if name.strip() in entries:
               raise SystemExit(f"duplicate NSS rule: {name.strip()}")
           entries[name.strip()] = sources
   for database in ("passwd", "group"):
       if entries.get(database) != ["files"]:
           raise SystemExit(f"{database} NSS source must be exactly files")
   if "initgroups" in entries and entries["initgroups"] != ["files"]:
       raise SystemExit("initgroups NSS source must be exactly files")
   PY
   stat -c '%n %u:%g %a' /dev/kfd /dev/dri/renderD128 /dev/dri/card1 /srv /run
   namei -l /home/daniel/ai/qualification-runs/t08-20261031T045433Z/runtime/sd-cpp-hip-b13a482-develvenv/bin/sd-cli
   namei -l /home/daniel/ai/qualification-runs/t08-20261031T045433Z/inputs/models
   namei -l /home/daniel/ai/hf-repos/qwen-image-components/split_files/vae
   ```

2. After the owner authorizes the identities and the preflight passes, create
   the four groups and the two non-login accounts. UID 973 remains assigned to
   `sshd`; GID 973 is the model-read group.

   ```sh
   set -eu
   groupadd --gid 970 media-generation-runner
   groupadd --gid 971 media-generation-scratch
   groupadd --gid 972 media-generation-worker
   groupadd --gid 973 media-generation-model-read
   useradd --system --uid 970 --gid 970 --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin media-generation-runner
   useradd --system --uid 972 --gid 972 --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin media-generation-worker
   usermod --append --groups 44,971,973,990 media-generation-runner
   usermod --append --groups 973 media-generation-worker

   test "$(id -u media-generation-runner)" = 970
   test "$(id -g media-generation-runner)" = 970
   test "$(id -u media-generation-worker)" = 972
   test "$(id -g media-generation-worker)" = 972
   test "$(getent group media-generation-scratch | cut -d: -f3)" = 971
   test "$(getent group media-generation-model-read | cut -d: -f3)" = 973
   runner_groups=$(id -G media-generation-runner | tr ' ' '\n' | sort -n | paste -sd ' ' -)
   worker_groups=$(id -G media-generation-worker | tr ' ' '\n' | sort -n | paste -sd ' ' -)
   test "$runner_groups" = '44 970 971 973 990'
   test "$worker_groups" = '972 973'
   id -G daniel | tr ' ' '\n' | grep -qx 44
   id -G daniel | tr ' ' '\n' | grep -qx 990
   ```

3. Copy candidate inputs into the new `/srv` mirror. Re-own and mode only the
   mirror; remove its extended ACLs; verify every path using both service
   identities. Rewrite the copied T07 root paths and require a fresh `READY`
   evaluation with matching trusted evidence.

   Before T07 evaluation, run this read-only check as root. It rejects
   named/default ACLs and world-readable private files, then checks effective
   traversal, read, and write access under each service identity. It checks all
   three GPU nodes for the runner and confirms the worker can neither read nor
   write them.

   ```sh
   set -eu
   candidate=/srv/media-generation/candidates/t08-qwen-image-edit-2511-apex-draft-r1
   engine="$candidate/runtime/sd-cpp-hip-b13a482-develvenv/bin/sd-cli"
   rocm="$candidate/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel"
   acl_report=$(mktemp)
   trap 'rm -f "$acl_report"' EXIT

   getfacl -R -cpn "$candidate/runtime" "$candidate/inputs" > "$acl_report"
   if grep -Eq '^(default:|user:[^:]|group:[^:]|mask::)' "$acl_report"; then
       echo 'extended or default ACL found in candidate mirror' >&2
       exit 1
   fi
   symlink=$(find "$candidate/runtime" "$candidate/inputs" -type l -print -quit)
   if [ -n "$symlink" ]; then
       echo "symlink found in candidate mirror: $symlink" >&2
       exit 1
   fi
   world_readable=$(find "$candidate/runtime" "$candidate/inputs" -type f -perm -0004 -print -quit)
   if [ -n "$world_readable" ]; then
       echo "private mirror file is world-readable: $world_readable" >&2
       exit 1
   fi
   for identity in media-generation-runner media-generation-worker; do
       runuser -u "$identity" -- find "$candidate/runtime" "$candidate/inputs" \
           -exec sh -eu -c '
               for item do
                   test -e "$item"
                   if [ -d "$item" ]; then
                       test -r "$item" && test -x "$item"
                   else
                       test -f "$item" && test -r "$item"
                   fi
                   test ! -w "$item"
               done
           ' sh {} +
       runuser -u "$identity" -- test -r "$rocm/.info/version"
       runuser -u "$identity" -- find "$rocm/lib" -mindepth 1 \
           -exec sh -eu -c 'for item do test -r "$item"; test ! -w "$item"; done' sh {} +
   done
   runuser -u media-generation-runner -- test -x "$engine"
   for device in /dev/kfd /dev/dri/renderD128 /dev/dri/card1; do
       runuser -u media-generation-runner -- test -r "$device"
       runuser -u media-generation-runner -- test -w "$device"
       if runuser -u media-generation-worker -- test -r "$device" \
           || runuser -u media-generation-worker -- test -w "$device"; then
           echo "worker unexpectedly has GPU access: $device" >&2
           exit 1
       fi
   done
   ```

4. Install the exact candidate commit in the isolated `/opt` virtual
   environment. Do not use or modify the existing inference virtual
   environments. Install only the reviewed dependency set, then verify the
   broker and runner entry points are root-owned and not group/world writable.
5. Create the `/var/lib` paths with the ownership and modes in section 4. As
   the worker, initialize the new database with the exact v9 code and umask
   `0007`. Confirm `PRAGMA user_version` is `9`; do not open the old database
   with this build. Confirm `/var/lib/media-generation/scratch` is
   `root:media-generation-scratch 0710` and has no extended or default ACLs.
6. Install the configuration and unit exactly as shown. Before any service
   start, run `systemd-analyze verify
   /etc/systemd/system/media-generation-systemd-broker.service`. Do not grant
   broad systemd or sudo permissions to the worker.
7. After separate authorization to start the service, run these checks. They
   prove the worker can reach the socket and `nobody` cannot traverse or
   connect. The broker also rejects any peer whose `SO_PEERCRED` UID/GID is not
   972/972.

   ```sh
   set -eu
   test "$(stat -c '%u:%g %a' /run/media-generation)" = '0:972 750'
   test "$(stat -c '%u:%g %a' /run/media-generation/attempt-broker.sock)" = '0:972 660'
   namei -l /run/media-generation/attempt-broker.sock
   runuser -u media-generation-worker -- /usr/bin/python3 -c '
   import socket
   client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
   client.connect("/run/media-generation/attempt-broker.sock")
   client.close()
   '
   if runuser -u nobody -- test -x /run/media-generation; then
       echo 'nobody unexpectedly traverses the broker socket directory' >&2
       exit 1
   fi
   if runuser -u nobody -- /usr/bin/python3 -c '
   import socket
   client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
   client.connect("/run/media-generation/attempt-broker.sock")
   '; then
       echo 'nobody unexpectedly connected to the broker socket' >&2
       exit 1
   fi
   unit=media-generation-systemd-broker.service
   test "$(id -u "$(systemctl show "$unit" --property=User --value)")" = 0
   test "$(getent group "$(systemctl show "$unit" --property=Group --value | cut -d: -f1)" | cut -d: -f3)" = 0
   exec_start=$(systemctl show "$unit" --property=ExecStart --value)
   printf '%s\n' "$exec_start" | grep -Fq \
       '/opt/media-generation/t13/venv/bin/media-generation-systemd-broker'
   printf '%s\n' "$exec_start" | grep -Fq '/etc/media-generation/broker.json'
   test "$(stat -c '%u:%g %a' /opt/media-generation/t13/venv/bin/media-generation-systemd-broker)" = '0:0 755'
   test "$(stat -c '%u:%g %a' /etc/media-generation/broker.json)" = '0:0 600'
   systemctl show "$unit" --property=NoNewPrivileges \
       --property=ProtectSystem --property=ProtectHome \
       --property=RuntimeDirectory --property=RuntimeDirectoryMode \
       --property=ReadWritePaths
   ```

   Run the worker connection check only after the worker, group, and broker
   exist. The socket probe may be rejected as an incomplete request after
   connect; that response still verifies the filesystem and socket path.
8. Keep APEX qualification `UNVERIFIED` until the exact mirror is `READY`,
   native Linux tests pass at the published source SHA, and separately
   authorized real-engine tests have exercised the successful, canceled, and
   recovered lifecycle. Do not run destructive fault injection without
   separate authorization.

Before a future rollback, stop submissions, drain attempts, prove no
`media-generation-attempt-*.service` cgroup remains, then stop and disable the
broker. Preserve the database, evidence ledger, artifacts, and mirror. Remove
or archive only the exact service unit/configuration and package path after
checking their identities. Leave the service accounts and groups in place
until an owner confirms that no retained files or evidence use those IDs.

## 7. Authorization still required

The owner must separately authorize runner UID/GID 970, scratch GID 971,
worker UID/GID 972, and model-read GID 973. The existing `sshd` account uses
UID 973 and must remain unchanged. Authorization is also required for the
service accounts, protected candidate mirror and rewritten T07 declaration,
isolated package installation, fresh schema-v9 database and ledger, broker
configuration and unit, socket path, scratch path, and runner membership in
the existing `video` and `render` groups. Approval of PR #56 or this proposal
does not authorize those host changes. No broker service has been installed
or started, no original model/runtime permissions were changed, and no
real-engine inference or destructive fault injection was run.

The present `passwd` and `group` NSS source lists include `systemd` and `sss`.
The owner must approve a complete identity source before provisioning. A
files-only NSS change affects host-wide account and group lookups; it requires
separate review and authorization. If that is not acceptable, a scoped source
that can prove complete `systemd` and SSSD membership must be designed and
reviewed before broker startup.

Reference-conditioned inference additionally needs an approved per-attempt
read-only reference handoff. The current `0600` publication files remain
worker-only; APEX must not be marked ready for edit/reference workloads until
that gap is closed and tested.
