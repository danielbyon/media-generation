# APEX T13 broker deployment proposal

Sections 1 through 6 describe a first-time installation. Their commands assume `/var/tmp/media-generation-package` and `/opt/media-generation/venv` are absent. The owner installed the application from source revision `3bc8041b332f7fcf1e0873ac2cb526625b6456ee`; preserve that installation and use Section 7 for an upgrade.

This manifest defines the isolated APEX installation under
`/opt/media-generation`. The owner authorized this permanent root and the
isolated installation. The parent-directory change may proceed only after the
section 6 read-only audit is reviewed and ChatGPT approves this manifest. No
privileged installation has been performed.

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

The candidate's original ID, source paths, and signed provenance are historical
evidence. Keep them unchanged in the evidence record. Only the four root paths
in the copied declaration are rewritten for the protected mirror.

The engine SHA-256 is
`884100c873d73f4e969664a3093ffd3a20b1cb24fdc8aea341933aa81e73a847`.
The pinned model files are `qwen-image-edit-2511-Q4_K_M.gguf` (12,842,830,432
bytes) and `qwen_2.5_vl_7b.safetensors` (16,584,415,576 bytes). The VAE is
`qwen_image_vae.safetensors` (253,806,246 bytes). The existing T07 signed
candidate was previously evaluated `READY` at its original paths; that result
does not qualify a copied or path-rewritten mirror. The mirror declaration
must be evaluated again with its trusted evidence before it can be selected.

The proposed GPU allowlist contains only `/dev/kfd` and
`/dev/dri/renderD128`; both are `root:render`, GID 990, mode `0660`. APEX also
has `/dev/dri/card1` as `root:video`, GID 44, mode `0660`. That node and GID 44
are excluded from this proposal because no need has been demonstrated. The
proposed `/srv/media-generation` mirror and
`/run/media-generation` directory do not exist. `/srv` is `root:root 0755`;
`/run` is `root:root 0755`. UIDs 970 and 972 and GIDs 970 through 973 were
free at the latest check. UID 973 belongs to the existing `sshd` account with
primary GID 65534; that UID is not part of this proposal. GIDs 990 and 44
already exist. Recheck each UID and GID separately, along with the two approved
device modes, immediately before any owner-authorized provisioning. Keep the
runner out of GID 44; do not change the existing `daniel` membership.

The current `/etc/nsswitch.conf` uses `passwd: files systemd sss` and
`group: files systemd sss`. A read-only check on 2026-11-13 found that global
account and group enumeration did not return records from every configured NSS
provider. This is recorded as a host fact, not a deployment blocker under the
owner-approved trusted-workstation model. The broker does not require
files-only NSS sources or exhaustive host-wide enumeration.

A read-only check on 2026-11-13 found `libnss_sss.so.2` installed,
`sssd.service` enabled but inactive, no `/etc/sssd/sssd.conf`, and no `sssctl`
command. `getent -s sss passwd` and `getent -s sss group` each exited zero with
no entries. The `systemd` source also returned no entries during enumeration,
while keyed lookups resolved its synthetic `root` and `nobody` records. Under
the approved model, the broker instead validates keyed records for the exact
runner and worker IDs, checks the exact expected groups for those two service
accounts, and verifies the live process credentials supplied by the kernel.
It does not require protected groups to exclude every other host account.
Leave `/etc/nsswitch.conf` unchanged. The host administrator and account
configuration are trusted; hostile local accounts and arbitrary third-party
execution are outside the supported threat model.

The proposed service accounts are not installed, so effective access has not
been tested under UIDs 970 and 972. The owner checks in section 6 cover model,
runtime, ROCm marker, GPU, and socket access after the identities are approved.

The existing `daniel` account is a member of GID 44 and GID 990 and keeps that
access. This proposal adds the runner to GID 990 only; it does not add the
runner to GID 44 or change any existing account or device permission. Broker
admission covers only its own attempts, so real-engine qualification must
confirm that no unrelated inference workload is competing for the GPU.

On 2026-11-14, an unprivileged SSH check observed the existing
`/opt/media-generation` directory as `root:root 0700` with basic ACL entries
`user::rwx`, `group::---`, and `other::---`. The SSH account cannot list or
traverse it, so its children, extended ACL state, symlinks, open files, and
service or executable dependencies have not been audited. An unprivileged
systemd listing found no currently loaded unit whose name matched this service;
that does not establish that no installed unit or process uses the directory.
Do not change this directory until the owner completes the read-only audit in
section 6 and confirms that the new group traversal exposes no unexpected
content or breaks an existing dependency. The only approved change is to this
existing directory itself: `root:media-generation-model-read 0710`. Do not
recursively change its contents or create a replacement root.

The 2026-11-14 source audit found 95 symlinks: 4 directory links and 91 file
links, with no broken targets. Their relative paths, raw targets, resolved
targets, and kinds are preserved in
`media-generation-apex-runtime-symlinks.jsonl` (SHA-256
`ce5a23fb8c82919a75b6b35166a89f0a73dfe07b1e881d29222e77d39d528539`). The four
links in `rocm-devel-venv/bin` (`python`, `python3`, `python3.14`, and `𝜋thon`)
resolve to `/usr/bin/python3.14`, whose SHA-256 is
`52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41`. The
other links resolve within the runtime tree. A read-only invocation of all
four source aliases reported Python 3.14.4, the source venv prefix, and `/usr`
as `sys.base_prefix`; the exact JSONL output is
`media-generation-apex-python-aliases.jsonl` (SHA-256
`17d8c162e0711d9ae0bcf75c29b255e3c2556d12cdadd6107337fe305b7dc800`). The
`sd-cli` loader resolves HIP, rocBLAS, rocSOLVER, and related libraries from
that runtime; both ROCm 10.1.0 release markers are present. The mirror still
needs a fresh copy and loader verification.

`readelf -d` on the existing `sd-cli` reports this absolute `DT_RUNPATH`,
including a trailing empty search-path entry:

```text
/home/daniel/ai/qualification-runs/t08-20261031T045433Z/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib:
```

The source `ldd` output has 31 non-vdso dependencies: 22 runtime libraries
and 9 system libraries. `media-generation-apex-ldd-map.jsonl` records each
library name, whether it comes from the copied runtime or the host, its exact
relative or canonical path, and its SHA-256. The map hash is
`125d2cde81f5e268d4f2f019453d5b0bebec68ac2c63374c46336db230c6f482`; the raw
source `ldd` and `readelf` output is preserved in
`media-generation-apex-source-ldd.txt` (SHA-256
`bc68300154a4e333731f05a6cc1b956281ab0b214b234906c42a25bf5c489f73`). The
runtime libraries resolve across `_rocm_sdk_devel/lib`,
`_rocm_sdk_devel/lib/llvm/lib`, and `_rocm_sdk_devel/lib/rocm_sysdeps/lib`.
The mirror keeps the exact engine bytes and embedded RUNPATH. For glibc
libraries without a slash in their names, `LD_LIBRARY_PATH` is searched before
`DT_RUNPATH`. Set all three mirror directories in that order ([`ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html)). The engine runs with `/` as
its current directory, so the RUNPATH's trailing empty entry cannot refer to
writable attempt scratch. Do not patch or rebuild `sd-cli`. Compare the mirror's
complete normalized loader map to the pinned map, including each resolved path
and file hash. Any changed, unresolved, or out-of-root dependency blocks
qualification.

## 2. Identities and access policy

| Name | ID | Membership and access |
| --- | ---: | --- |
| `media-generation-runner` user and primary group | UID/GID 970 | Supplementary GIDs 971 (scratch), 973 (model/runtime read), and 990 (`render`). No GID 44 or 972. |
| `media-generation-scratch` group | GID 971 | Runner only. The broker creates each attempt directory as `root:media-generation-scratch 2770`. |
| `media-generation-worker` user and primary group | UID/GID 972 | Supplementary GID 973 only. No GPU or scratch groups. Owns the worker database and publication output. |
| `media-generation-model-read` group | GID 973 | Runner and worker only. Read/traverse access to the immutable candidate mirror. |
| Existing `render` group | GID 990 | Add the runner for `/dev/kfd` and `/dev/dri/renderD128`. Do not add the runner to GID 44 (`video`) or change existing membership. |

The broker validates the runner's keyed account record and exact account group
set `{970, 971, 973, 990}`; the worker's exact set is `{972, 973}`. Before
binding a service to its attempt cgroup, it checks the runner process's live
UIDs, GIDs, supplementary groups, and unified cgroup through `/proc`. For each
worker socket request, it checks `SO_PEERCRED` and the peer process's live
UIDs, GIDs, and supplementary groups. The account group list in configuration
does not substitute for those live checks. These checks reject extra groups on
either service account while allowing unrelated host accounts to share a group
under the approved trust model. The worker is not the existing `daniel`
account.

The broker checks Unix owner/group/other bits. Named ACL entries are not an
accepted substitute. The scratch-root path and the mirror must have no extended
or default ACLs. Set mirror directories to `root:973 2750`, ordinary files to
`root:973 0640`, and executable files such as `sd-cli` to `root:973 0750`.
These modes give the runner and worker read access without granting either
write access to runtime or model data. The worker can execute the group-
executable engine file but has no GPU or scratch device access.

The original `/home/daniel` trees remain untouched. Copy the engine runtime,
ROCm runtime, models, VAE, candidate declaration, trusted evidence, recipe, and
evidence documents into this stable mirror path:

```text
/srv/media-generation/candidates/qwen-image-edit-2511
```

Before copying, compare every source symlink's relative path, raw target,
resolved target, and kind to the pinned symlink manifest. Dereference only those
approved links; preserve each alias path and target bytes. The four Python
aliases to `/usr/bin/python3.14` are the only permitted links outside the
runtime tree. Compare their target hash and behavior with the source. Reject any
changed or newly discovered link. Compare a relative-path SHA-256 manifest for
every dereferenced runtime file against the mirror and require the mirror to
contain no symlinks. Compare the mirror's complete `ldd` map to the pinned map:
all 22 runtime dependencies and all 9 host libraries must retain their exact
names, target paths, and hashes. Also reject unresolved dependencies and any
path outside the mirror or the approved system roots.

Rewrite only the copied declaration's four root paths. Preserve its candidate
ID, pinned hashes, and source provenance. Remove extended/default ACLs from the
mirror, apply the modes above, and rerun T07 evaluation with the copied trusted
evidence. Require `status == "ready"` and the original candidate ID
`sha256:645ce14ebb1134c591ff60af8947a504d91e695c3f043df52cc7bfcdfcd66700`.
Any inventory, hash, evidence, access, loader, or readiness mismatch blocks
qualification. Leave the original model and runtime trees unchanged.

## 3. Broker policy file

After provisioning the mirror, write this exact field set to
`/etc/media-generation/broker.json` as `root:root 0600`. The paths are fixed to
the proposed APEX layout; the broker refuses unknown or missing fields.

```json
{
  "database_path": "/var/lib/media-generation-v9/db/jobs.sqlite3",
  "socket_path": "/run/media-generation/attempt-broker.sock",
  "scratch_root": "/var/lib/media-generation/scratch",
  "runner_executable": "/opt/media-generation/venv/bin/media-generation-attempt-runner",
  "runner_uid": 970,
  "runner_gid": 970,
  "runner_supplementary_gids": [971, 973, 990],
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
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/llvm/lib",
    "/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/rocm_sysdeps/lib"
  ],
  "empty_timeout_seconds": 30
}
```

Set the worker process environment used to prepare the engine invocation to
these exact values:

```text
PATH=/usr/bin
ROCM_PATH=/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel
LD_LIBRARY_PATH=/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib:/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/llvm/lib:/srv/media-generation/candidates/qwen-image-edit-2511/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/rocm_sysdeps/lib
```

The adapter records these values in the immutable resolved invocation; the
worker sends that record and environment to the broker, which validates every
search directory against the exact allowlist before launch. The existing
SHA-256 environment binding remains in force. Do not bypass the digest or add
paths silently. If runtime inspection shows another required directory, stop
and re-review the policy before any execution.

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
| `/opt/media-generation` | `root:media-generation-model-read 0710` after the audit gate | Existing permanent installation root. Group 973 receives search/traverse only, not directory listing. This is the only approved parent-directory ownership/mode change. |
| `/opt/media-generation/venv` | `root:root 0755`; package files not group/world writable | Isolated Python 3.14.4 installation of the exact reviewed commit; contains both console scripts. |
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
| `/srv/media-generation/candidates/qwen-image-edit-2511` | `root:media-generation-model-read 2750` directories | Read-only mirror; ordinary files `0640`, source-executable files `0750`, no extended ACLs or symlinks. |

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
RequiresMountsFor=/opt/media-generation /etc/media-generation \
    /var/lib/media-generation-v9/db /var/lib/media-generation/scratch \
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
| `SupplementaryGroups` | `971 973 990` |
| `RemainAfterExit`, `KillMode`, `Delegate` | `yes`, `control-group`, `no` |
| `NoNewPrivileges`, `ProtectSystem`, `ProtectHome` | `yes`, `strict`, `read-only` |
| `PrivateDevices`, `DevicePolicy` | `no`, `closed` |
| `ReadWritePaths` | The absolute per-attempt scratch directory |
| `CapabilityBoundingSet` | Empty |
| `RestrictSUIDSGID`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictNamespaces` | `yes` |
| `UMask` | `0077` |
| `DeviceAllow` | `/dev/kfd rw`, `/dev/dri/renderD128 rw` |

The runner service starts in its scratch directory. Its `ProcessSupervisor`
launches the engine with `/` as its current directory and passes absolute
scratch, model, and output paths. This keeps writable scratch out of the
engine's dynamic-loader search through an empty path entry.

## 6. Owner-authorized installation and verification sequence

The owner has authorized the isolated installation described here. The owner
must run the privileged commands interactively over SSH after final ChatGPT
review of this exact source revision. Passwords stay in the owner's terminal;
Codex does not collect or handle them. Read-only audit and identity preflight
may run before that review. The unit passed `systemd-analyze verify` with
systemd 259.9 in an isolated temporary root containing a stub broker
executable. No unit was installed or started.

Run the identity preflight as the SSH account; the `/opt` audit uses read-only
commands through interactive sudo. After final review, the owner authenticates
with `sudo -i` in that SSH terminal and runs the privileged installation blocks
as root. No password is entered into a script, file, or Codex chat.

Before changing `/opt/media-generation`, run this read-only audit in the
owner's interactive SSH session. It writes the report under `/var/tmp`, outside
the repository. Review the complete report for existing children, mounts,
ACLs, symlinks, open processes, and service references. Changing the group on
the parent grants GID 973 search access through it; it does not grant directory
listing, but paths already known to runner or worker may become reachable when
their child permissions allow it. Stop if any existing content, access, or
dependency is unexpected. Do not run the following permission change until
the audit has been reviewed:

```sh
set -eu
set -o pipefail
umask 077
report="/var/tmp/media-generation-opt-audit-$(date -u +%Y%m%dT%H%M%SZ).txt"
test ! -e "$report"
test ! -L "$report"
sudo -- sh -eu -c '
    root=/opt/media-generation
    test -d /opt
    test ! -L /opt
    test "$(stat -c "%F %u:%g %a" /opt)" = "directory 0:0 755"
    getfacl -cpn /opt
    test "$(getfacl -cpn /opt)" = "$(printf "user::rwx\\ngroup::r-x\\nother::r-x")"
    test -d "$root"
    test ! -L "$root"
    stat -c "%n %F %u:%g %a %d:%i" /opt "$root"
    findmnt --target "$root" --list --noheadings --output TARGET,SOURCE,FSTYPE,OPTIONS
    root_mount=$(findmnt --target "$root" --list --noheadings --output TARGET)
    if [ "$root_mount" = "$root" ]; then
        echo "$root is unexpectedly a mount point" >&2
        exit 1
    fi
    findmnt --submounts --target "$root" --list --noheadings --output TARGET,SOURCE,FSTYPE,OPTIONS
    mount_targets=$(findmnt --submounts --target "$root" --list --noheadings --output TARGET)
    nested_mount=$(printf "%s\n" "$mount_targets" | awk -v root="$root" "index(\$0, root \"/\") == 1")
    if [ -n "$nested_mount" ]; then
        echo "nested mount under $root: $nested_mount" >&2
        exit 1
    fi
    namei -l "$root"
    find -P "$root" -xdev -printf "%y %m %u:%g %p -> %l\\n"
    echo "--- files owned by or grouped to proposed service IDs ---"
    find -P "$root" -xdev \( -uid 970 -o -uid 972 -o -gid 970 -o -gid 971 \
        -o -gid 972 -o -gid 973 -o -gid 990 \) -printf "%u:%g %m %p\\n"
    echo "--- complete ACL report ---"
    acl_report=$(getfacl -R -cpn "$root") || { echo "getfacl scan failed" >&2; exit 1; }
    printf "%s\\n" "$acl_report"
    scan_tree() {
        scan_directory=$1
        if [ ! -d "$scan_directory" ]; then return 0; fi
        scan_status=0
        scan_output=$(grep -RniF "$root" "$scan_directory" 2>&1) || scan_status=$?
        case "$scan_status" in
            0) printf "%s\\n" "$scan_output";;
            1) ;;
            *) printf "%s\\n" "$scan_output" >&2; return "$scan_status";;
        esac
    }
    echo "--- matching systemd unit references ---"
    for directory in /etc/systemd/system /run/systemd/system \
        /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        scan_tree "$directory"
    done
    echo "--- matching user systemd unit definitions ---"
    for directory in /etc/systemd/user /run/systemd/user \
        /usr/lib/systemd/user /lib/systemd/user /usr/local/lib/systemd/user \
        /home/*/.config/systemd/user /root/.config/systemd/user; do
        scan_tree "$directory"
    done
    systemd_units=$(systemctl list-units --all --type=service --no-legend --plain --no-pager 2>&1) \
        || { printf "%s\\n" "$systemd_units" >&2; exit 1; }
    unit_names=$(printf "%s\\n" "$systemd_units" | awk "NF {print \$1}")
    test -n "$unit_names"
    systemd_properties=$(systemctl show $unit_names \
        --property=Id,FragmentPath,ExecCondition,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost \
        --property=Environment,EnvironmentFiles,LoadCredential,LoadCredentialEncrypted \
        --property=WorkingDirectory,RootDirectory,RootImage,RequiresMountsFor \
        --property=ReadOnlyPaths,ReadWritePaths,InaccessiblePaths,BindPaths,BindReadOnlyPaths,TemporaryFileSystem \
        2>&1) || { printf "%s\\n" "$systemd_properties" >&2; exit 1; }
    test -n "$systemd_properties"
    systemd_status=0
    systemd_matches=$(printf "%s\\n" "$systemd_properties" | grep -F "$root" 2>&1) || systemd_status=$?
    case "$systemd_status" in
        0) printf "%s\\n" "$systemd_matches";;
        1) ;;
        *) printf "%s\\n" "$systemd_matches" >&2; exit "$systemd_status";;
    esac
    echo "--- processes executing from the path ---"
    /usr/bin/python3.14 - "$root" <<PY
import os, sys

root = os.path.abspath(sys.argv[1])
for pid in os.listdir("/proc"):
    if not pid.isdecimal():
        continue
    executable = f"/proc/{pid}/exe"
    try:
        target = os.readlink(executable)
    except FileNotFoundError:
        continue
    except OSError as exc:
        raise SystemExit(f"cannot inspect {executable}: {exc}")
    if target.startswith(root + "/"):
        print(f"{pid} {target}")
PY
    echo "--- open files and mappings ---"
    command -v lsof >/dev/null 2>&1 || { echo "lsof is required for a complete open-file audit" >&2; exit 1; }
    verify_lsof_exclusion() {
        excluded_mountpoint=$1
        expected_fstype=$2
        if ! actual_target=$(findmnt --mountpoint "$excluded_mountpoint" \
            --noheadings --output TARGET 2>&1); then
            printf "%s\\n" "$actual_target" >&2
            echo "cannot verify lsof exclusion mount $excluded_mountpoint" >&2
            exit 1
        fi
        if ! actual_fstype=$(findmnt --mountpoint "$excluded_mountpoint" \
            --noheadings --output FSTYPE 2>&1); then
            printf "%s\\n" "$actual_fstype" >&2
            echo "cannot verify lsof exclusion filesystem $excluded_mountpoint" >&2
            exit 1
        fi
        if [ "$actual_target" != "$excluded_mountpoint" ] || \
            [ "$actual_fstype" != "$expected_fstype" ]; then
            printf "unexpected lsof exclusion mount: expected %s (%s), found %s (%s)\\n" \
                "$excluded_mountpoint" "$expected_fstype" "$actual_target" "$actual_fstype" >&2
            exit 1
        fi
        case "$excluded_mountpoint" in
            "$root"|"$root"/*)
                echo "lsof exclusion lies inside the audited root: $excluded_mountpoint" >&2
                exit 1
                ;;
        esac
        case "$root" in
            "$excluded_mountpoint"|"$excluded_mountpoint"/*)
                echo "the audited root lies inside an lsof exclusion: $root" >&2
                exit 1
                ;;
        esac
        echo "verified lsof exclusion mount: $actual_target ($actual_fstype), outside $root"
    }
    verify_lsof_exclusion /run/user/1000/doc fuse.portal
    verify_lsof_exclusion /run/user/1000/gvfs fuse.gvfsd-fuse
    lsof_status=0
    lsof_output=$(lsof \
        -e /run/user/1000/doc \
        -e /run/user/1000/gvfs \
        +D "$root" 2>&1) || lsof_status=$?
    case "$lsof_status" in
        0) printf "%s\\n" "$lsof_output";;
        1)
            if [ -n "$lsof_output" ]; then
                printf "%s\\n" "$lsof_output" >&2
                echo "lsof reported a scan diagnostic; audit is incomplete" >&2
                exit 1
            fi
            echo "lsof found no open files under $root"
            ;;
        *)
            printf "%s\\n" "$lsof_output" >&2
            exit "$lsof_status"
            ;;
    esac
    echo APEX_OPT_AUDIT_COMPLETE
' 2>&1 | tee "$report"
printf 'Audit report: %s\n' "$report"
sha256sum "$report"
```

The current unprivileged observation is `root:root 0700` with only the basic
ACL entries. Continue only if the sudo report confirms that same parent state,
shows no existing ACL entry or numeric owner/group that would give the new
service IDs access, and identifies no dependent service or executable. Review
every child path's group mode, ACL, and symlink target to determine whether GID
973 traversal would expose it. If any access effect or dependency is unclear,
stop and leave the parent unchanged. On APEX, `lsof +D` produced diagnostics
while traversing the user's FUSE mounts at `/run/user/1000/doc` and
`/run/user/1000/gvfs`. `findmnt` identified them as `fuse.portal` and
`fuse.gvfsd-fuse`. The owner reran the scan with exclusions for those exact
mounts; it emitted no warnings, reported no matching files, and returned
status 1. The audit verifies each mount's exact target and filesystem type
immediately before the scan. It rejects either mount if missing, replaced, or
inside the audited root, and rejects the root if it falls inside an excluded
mount. The `+D` scan therefore still covers all of `/opt/media-generation`.
Status 0 output remains in the report for owner review. Status 1 is accepted
only with empty output; diagnostics or any higher status make the audit
incomplete. Rollback restores this audited baseline.
A complete report ends with exactly one `APEX_OPT_AUDIT_COMPLETE` line. Step 3
checks that marker before accepting the report.

1. Before creating users or groups, run this read-only preflight. It checks
   exact keyed lookups for the assigned numeric IDs, preserves UID 973 for
   `sshd`, verifies the approved `render` group, and stops on an occupied or
   substituted identity. It does not enumerate global accounts or groups and
   does not inspect or change `/etc/nsswitch.conf`.

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
   test "$(getent group 990 | cut -d: -f1)" = render
   stat -c '%n %u:%g %a' /dev/kfd /dev/dri/renderD128 /srv /run
   namei -l /home/daniel/ai/qualification-runs/t08-20261031T045433Z/runtime/sd-cpp-hip-b13a482-develvenv/bin/sd-cli
   namei -l /home/daniel/ai/qualification-runs/t08-20261031T045433Z/inputs/models
   namei -l /home/daniel/ai/hf-repos/qwen-image-components/split_files/vae
   ```

2. After the source/security review gate and the preflight succeed, create the
   four groups and the two non-login accounts. UID 973 remains assigned to
   `sshd`; GID 973 is the model-read group. Validate only these service
   accounts' keyed identity and group results; host-wide group exclusivity is
   not part of the approved threat model. The owner runs this block in the
   interactive root shell after checking the preflight output.

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
   usermod --append --groups 971,973,990 media-generation-runner
   usermod --append --groups 973 media-generation-worker

   test "$(id -u media-generation-runner)" = 970
   test "$(id -g media-generation-runner)" = 970
   test "$(id -u media-generation-worker)" = 972
   test "$(id -g media-generation-worker)" = 972
   test "$(getent group media-generation-scratch | cut -d: -f3)" = 971
   test "$(getent group media-generation-model-read | cut -d: -f3)" = 973
   runner_groups=$(id -G media-generation-runner | tr ' ' '\n' | sort -n | paste -sd ' ' -)
   worker_groups=$(id -G media-generation-worker | tr ' ' '\n' | sort -n | paste -sd ' ' -)
   test "$runner_groups" = '970 971 973 990'
   test "$worker_groups" = '972 973'
   id -G daniel | tr ' ' '\n' | grep -qx 44
   id -G daniel | tr ' ' '\n' | grep -qx 990
   ```

### Step 3. Approved parent-directory change

After reviewing the read-only report and creating GID 973, the owner may
change only the existing parent directory. Run these commands in the
interactive SSH session. Stop if the observed owner, group, mode, ACL, or path
type differs from the audited state. Enter the exact report path and SHA-256
printed by the completed audit; the device/inode check binds this change to
the directory whose contents were reviewed:

```sh
set -eu
printf 'Audit report path: '
IFS= read -r audit_report
case "$audit_report" in
    /var/tmp/media-generation-opt-audit-*.txt) ;;
    *) echo 'unexpected audit report path' >&2; exit 1;;
esac
test -f "$audit_report"
test ! -L "$audit_report"
printf 'Reviewed report SHA-256: '
IFS= read -r reviewed_report_sha
test "$(sha256sum "$audit_report" | cut -d' ' -f1)" = "$reviewed_report_sha"
test "$(grep -Fxc 'APEX_OPT_AUDIT_COMPLETE' "$audit_report")" = 1
test "$(tail -n 1 "$audit_report")" = 'APEX_OPT_AUDIT_COMPLETE'
test "$(awk '$1 == "/opt/media-generation" {count++} END {print count+0}' "$audit_report")" = 1
audited_identity=$(awk '$1 == "/opt/media-generation" {print $5}' "$audit_report")
test -d /opt
test ! -L /opt
test "$(stat -c '%F %u:%g %a' /opt)" = 'directory 0:0 755'
test "$(getfacl -cpn /opt)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /opt/media-generation
test ! -L /opt/media-generation
test "$(stat -c '%d:%i' /opt/media-generation)" = "$audited_identity"
test "$(stat -c '%F %u:%g %a' /opt/media-generation)" = 'directory 0:0 700'
test "$(getfacl -cpn /opt/media-generation)" = "$(printf 'user::rwx\ngroup::---\nother::---')"
test "$(getent group media-generation-model-read | cut -d: -f3)" = 973
chgrp media-generation-model-read /opt/media-generation
chmod 0710 /opt/media-generation
test "$(stat -c '%F %u:%g %a' /opt/media-generation)" = 'directory 0:973 710'
test "$(getfacl -cpn /opt/media-generation)" = "$(printf 'user::rwx\ngroup::--x\nother::---')"
```

Do not run `chown` or a recursive permission command on `/opt`. The expected
ACL mode entries after this step are `user::rwx`, `group::--x`, and
`other::---`. Confirm the report showed no unexpected existing child paths
that the runner or worker could reach through this new group traversal.

### Step 4. Exact package build and installation

The historical handoff bundle at `/var/tmp/media-generation-apex-install`
records the APEX installed source SHA
`3bc8041b332f7fcf1e0873ac2cb526625b6456ee`; keep it unchanged. Prepare the
replacement final review bundle at
`/var/tmp/media-generation-apex-install-reviewed`. It contains `SOURCE_SHA`,
the exact wheel built from that clean reviewed commit, the Pillow wheel, broker
configuration, systemd unit, runtime file manifest, symlink manifest, source
loader map, raw loader output, source Python-alias output, and `SHA256SUMS`.
Build the package wheel with Python 3.14.4 from a clean Git archive of
`SOURCE_SHA`. Do not rebuild it during installation. Compare the bundle's
source SHA and checksum-manifest SHA with the final review handoff, then verify
every bundled file with `sha256sum -c`.
The Pillow artifact is
`pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`,
SHA-256 `e91c2b1cbeae768c98752e67e717e283d68dae45717b41f2d91eaee648e37b7d`,
as published in [PyPI's Pillow 13.0.0 release record](https://pypi.org/pypi/Pillow/13.0.0/json).

On the Mac, verify that the worktree is still the reviewed clean commit and
that the bundle names the same source revision. Compare the `SHA256SUMS` digest
with the value in the final review handoff before copying it to APEX:

```sh
set -eu
worktree=/Users/daniel/Projects/media-generation-t13-issue14-safe-cancellation
bundle=/var/tmp/media-generation-apex-install-reviewed
test -d "$bundle" && test ! -L "$bundle"
test -f "$bundle/SOURCE_SHA" && test ! -L "$bundle/SOURCE_SHA"
test -f "$bundle/SHA256SUMS" && test ! -L "$bundle/SHA256SUMS"
source_sha=$(cat "$bundle/SOURCE_SHA")
test "$(git -C "$worktree" rev-parse HEAD)" = "$source_sha"
test -z "$(git -C "$worktree" status --porcelain=v1 --untracked-files=all)"
printf 'Reviewed source SHA: %s\n' "$source_sha"
shasum -a 256 "$bundle/SHA256SUMS"
ssh apex 'set -eu; test ! -e /var/tmp/media-generation-package; test ! -L /var/tmp/media-generation-package; umask 077; mkdir -m 0700 /var/tmp/media-generation-package'
scp "$bundle"/* apex:/var/tmp/media-generation-package/
ssh apex 'set -eu; test ! -L /var/tmp/media-generation-package; cd /var/tmp/media-generation-package; sha256sum -c SHA256SUMS'
```

The owner verifies the printed source and `SHA256SUMS` hashes against the final
review handoff. If either differs, stop. The remote package directory must be
new and mode `0700`; do not overwrite an existing staging directory or file.
The checksum file covers the package and Pillow wheels, `broker.json`, the
broker unit, and the source runtime manifests, loader output, and Python-alias record.

After the approved parent change, create the venv and install only those two
wheels in the interactive root shell. These commands use the supplied wheels;
they do not contact a package index or alter another Python environment:

```sh
set -eu
test "$(/usr/bin/python3.14 --version)" = 'Python 3.14.4'
test ! -e /opt/media-generation/venv
test ! -L /opt/media-generation/venv
cd /var/tmp/media-generation-package
sha256sum -c SHA256SUMS
cd -
test "$(sha256sum /var/tmp/media-generation-package/pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl | cut -d' ' -f1)" = 'e91c2b1cbeae768c98752e67e717e283d68dae45717b41f2d91eaee648e37b7d'
/usr/bin/python3.14 -m venv --copies /opt/media-generation/venv
/opt/media-generation/venv/bin/python -m pip install \
    --no-index --no-deps --find-links=/var/tmp/media-generation-package \
    media-generation==0.1.0 Pillow==13.0.0
/opt/media-generation/venv/bin/python -m pip check
test -f /opt/media-generation/venv/bin/media-generation-attempt-runner
test ! -L /opt/media-generation/venv/bin/media-generation-attempt-runner
test -f /opt/media-generation/venv/bin/media-generation-systemd-broker
test ! -L /opt/media-generation/venv/bin/media-generation-systemd-broker
test "$(stat -c '%u:%g %a' /opt/media-generation/venv/bin/media-generation-attempt-runner)" = '0:0 755'
test "$(stat -c '%u:%g %a' /opt/media-generation/venv/bin/media-generation-systemd-broker)" = '0:0 755'
sh -eu <<'CHECK_VENV'
venv=/opt/media-generation/venv
fail() {
    printf 'venv permission check failed: %s\n' "$1" >&2
    exit 1
}

[ -d "$venv" ] || fail 'venv is missing or is not a directory'
[ ! -L "$venv" ] || fail 'venv must not be a symlink'
if ! venv_owner=$(stat -c '%u:%g' -- "$venv"); then
    fail 'stat failed for the venv directory'
fi
[ "$venv_owner" = '0:0' ] || fail 'venv directory must be owned by root:root'

if ! symlink_markers=$(find -P "$venv" -type l -printf x); then
    fail 'find failed while enumerating venv symlinks'
fi
[ "$symlink_markers" = x ] || fail 'venv must contain exactly one symlink'

lib64=$venv/lib64
[ -L "$lib64" ] || fail 'venv/lib64 must be a symlink'
if ! link_owner=$(stat -c '%u:%g' -- "$lib64"); then
    fail 'stat failed for the venv/lib64 symlink'
fi
[ "$link_owner" = '0:0' ] || fail 'venv/lib64 symlink must be owned by root:root'

if ! target_bytes=$(mktemp /tmp/media-generation-venv-link.XXXXXX); then
    fail 'mktemp failed while checking the venv/lib64 target'
fi
trap 'rm -f "$target_bytes"' EXIT
if ! readlink -z -- "$lib64" > "$target_bytes"; then
    fail 'readlink failed for the venv/lib64 symlink'
fi
if ! printf 'lib\0' | cmp -s - "$target_bytes"; then
    fail 'venv/lib64 must have the exact literal target lib'
fi

if ! resolved=$(realpath -e -- "$lib64"); then
    fail 'realpath failed for the venv/lib64 target'
fi
[ "$resolved" = "$venv/lib" ] || fail 'venv/lib64 must resolve exactly to venv/lib'
[ -d "$resolved" ] || fail 'resolved venv/lib target is not a directory'
if ! target_owner=$(stat -c '%u:%g' -- "$resolved"); then
    fail 'stat failed for the resolved venv/lib directory'
fi
[ "$target_owner" = '0:0' ] || fail 'resolved venv/lib directory must be owned by root:root'

if ! non_root_entry=$(find -P "$venv" ! -uid 0 -print -quit); then
    fail 'find failed while checking venv ownership'
fi
[ -z "$non_root_entry" ] || fail 'every venv entry must be owned by root'

if ! writable_entry=$(find -P "$venv" ! -type l -perm /022 -print -quit); then
    fail 'find failed while checking venv write permissions'
fi
[ -z "$writable_entry" ] || fail 'a non-symlink venv entry is group- or world-writable'
CHECK_VENV
runuser -u media-generation-runner -- \
    test -x /opt/media-generation/venv/bin/media-generation-attempt-runner
runuser -u media-generation-worker -- \
    test -r /opt/media-generation/venv/bin/media-generation-systemd-broker
```

Verify the broker and runner console scripts are root-owned regular files with
mode `0755`. The permission check allows only the root-owned `lib64` symlink
with the literal target `lib`, resolving to `/opt/media-generation/venv/lib`.
It rejects any other symlink, non-root-owned entry, or group/world-writable
non-symlink entry. A failed `find`, `stat`, `readlink`, or `realpath` check stops
installation. Do not repair a failed check with a recursive `chown` or `chmod`;
stop and report the partial installation state.

### Step 5. Copy and qualify the candidate mirror

Copy candidate inputs into the new `/srv` mirror. The copy dereferences the
   source links, keeps each resolved path name and file bytes, and changes only
   the new mirror's owner and mode. Do not alter the source trees. Stop if the
   source symlink inventory differs from the audit in section 1.

   The full runtime inventory is bundled as
   `/var/tmp/media-generation-package/media-generation-apex-runtime-sha256.jsonl`:
   68,342 relative-path records, SHA-256
   `76478175b83fe4679d27dcfbf5e561fa9d7a5cd1efaeff56f3d75b7714079c1d`.
   The package bundle also carries the exact symlink manifest and normalized
   loader map. Verify their pinned digests before comparing the mirror.

   ```sh
   set -eu
   source=/home/daniel/ai/qualification-runs/t08-20261031T045433Z
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511
   validation=/var/tmp/media-generation-package/validation
   test -d /srv
   test ! -L /srv
   test "$(stat -c '%F %u:%g %a' /srv)" = 'directory 0:0 755'
   test "$(getfacl -cpn /srv)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
   test ! -e "$validation"
   test ! -L "$validation"
   mkdir -m 0700 "$validation"
   test "$(stat -c '%u:%g %a' "$validation")" = "$(id -u):$(id -g) 700"
   test ! -e /srv/media-generation
   test ! -L /srv/media-generation
   test ! -e "$candidate"
   test ! -L "$candidate"

   expected_links=/var/tmp/media-generation-package/media-generation-apex-runtime-symlinks.jsonl
   current_links="$validation/runtime-symlinks-current.jsonl"
   test ! -e "$current_links"
   test ! -L "$current_links"
   test "$(sha256sum "$expected_links" | cut -d' ' -f1)" = \
       'ce5a23fb8c82919a75b6b35166a89f0a73dfe07b1e881d29222e77d39d528539'
   test ! -e "$current_links"
   python3 - "$source/runtime" > "$current_links" <<'PY'
   import json, os, sys
   base=os.path.abspath(sys.argv[1])
   rows=[]
   for root, dirs, files in os.walk(base, followlinks=False):
       dirs.sort()
       files.sort()
       for name in dirs + files:
           path=os.path.join(root, name)
           if not os.path.islink(path):
               continue
           if not os.path.exists(path):
               raise SystemExit(f"broken source link: {path}")
           resolved=os.path.realpath(path)
           kind="directory" if os.path.isdir(path) else "file"
           rows.append([os.path.relpath(path,base),os.readlink(path),resolved,kind])
   rows.sort(key=lambda row: row[0])
   if len(rows) != 95 or sum(row[3] == "directory" for row in rows) != 4:
       raise SystemExit(f"runtime link inventory changed: {len(rows)} links")
   outside=[row for row in rows if os.path.commonpath((base,row[2])) != base]
   expected={
       "rocm-devel-venv/bin/python": ("python3.14","/usr/bin/python3.14","file"),
       "rocm-devel-venv/bin/python3": ("python3.14","/usr/bin/python3.14","file"),
       "rocm-devel-venv/bin/python3.14": ("/usr/bin/python3.14","/usr/bin/python3.14","file"),
       "rocm-devel-venv/bin/𝜋thon": ("python3.14","/usr/bin/python3.14","file"),
   }
   actual={row[0]:(row[1],row[2],row[3]) for row in outside}
   if actual != expected or len(outside) != 4:
       raise SystemExit(f"unexpected external runtime links: {outside!r}")
   for row in rows:
       print(json.dumps(row,separators=(",",":"),ensure_ascii=True))
   PY
   cmp "$expected_links" "$current_links"
   test "$(sha256sum /usr/bin/python3.14 | cut -d' ' -f1)" = \
       '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
   for source_root in "$source/inputs/models" \
       /home/daniel/ai/hf-repos/qwen-image-components/split_files/vae \
       "$source/evidence/t07-candidate-draft" "$source/evidence/t07-candidate-signed"; do
       test -d "$source_root"
       test -z "$(find "$source_root" -type l -print -quit)"
   done

   install -d -o root -g root -m 0755 \
       /srv/media-generation /srv/media-generation/candidates
   install -d -o root -g 973 -m 2750 \
       "$candidate" "$candidate/runtime" "$candidate/inputs/models" \
       "$candidate/inputs/vae" "$candidate/evidence/t07-candidate-draft" \
       "$candidate/evidence/t07-candidate-signed"
   for protected_directory in /srv /srv/media-generation \
       /srv/media-generation/candidates "$candidate" "$candidate/runtime" \
       "$candidate/inputs" "$candidate/inputs/models" "$candidate/inputs/vae" \
       "$candidate/evidence" "$candidate/evidence/t07-candidate-draft" \
       "$candidate/evidence/t07-candidate-signed"; do
       test -d "$protected_directory"
       test ! -L "$protected_directory"
   done
   test "$(stat -c '%F %u:%g %a' /srv)" = 'directory 0:0 755'
   test "$(stat -c '%F %u:%g %a' /srv/media-generation)" = 'directory 0:0 755'
   test "$(stat -c '%F %u:%g %a' /srv/media-generation/candidates)" = 'directory 0:0 755'
   test "$(stat -c '%F %u:%g %a' "$candidate")" = 'directory 0:973 2750'
   rsync -rtpL --chown=0:973 "$source/runtime/" "$candidate/runtime/"
   rsync -rtpL --chown=0:973 "$source/inputs/models/" "$candidate/inputs/models/"
   rsync -rtpL --chown=0:973 \
       /home/daniel/ai/hf-repos/qwen-image-components/split_files/vae/ \
       "$candidate/inputs/vae/"
   rsync -rtpL --chown=0:973 \
       "$source/evidence/t07-candidate-draft/" \
       "$candidate/evidence/t07-candidate-draft/"
   rsync -rtpL --chown=0:973 \
       "$source/evidence/t07-candidate-signed/" \
       "$candidate/evidence/t07-candidate-signed/"

   setfacl -R -b -k "$candidate"
   find "$candidate" -type d -exec chmod 2750 {} +
   find "$candidate" -type f -perm /111 -exec chmod 0750 {} +
   find "$candidate" -type f ! -perm /111 -exec chmod 0640 {} +
   ```

   Generate the same relative-path hash manifest for the copied runtime and
   require byte-for-byte equality with the transferred source manifest. The
   source manifest records file bytes reached through the approved source
   symlinks. The mirror check rejects any remaining symlink before hashing:

   ```sh
   set -eu
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511
   validation=/var/tmp/media-generation-package/validation
   mirror_manifest="$validation/runtime-sha256.jsonl"
   test -d "$validation" && test ! -L "$validation"
   test ! -e "$mirror_manifest" && test ! -L "$mirror_manifest"
   python3 - "$candidate/runtime" > "$mirror_manifest" <<'PY'
   import hashlib, json, os, sys
   base=os.path.abspath(sys.argv[1])
   for root, dirs, files in os.walk(base, followlinks=False):
       dirs.sort()
       files.sort()
       for name in dirs + files:
           if os.path.islink(os.path.join(root, name)):
               raise SystemExit(f"symlink in protected mirror: {os.path.join(root, name)}")
       for name in files:
           path=os.path.join(root, name)
           with open(path, 'rb') as stream:
               digest=hashlib.file_digest(stream, 'sha256').hexdigest()
           print(json.dumps([os.path.relpath(path,base),digest],separators=(',',':'),ensure_ascii=True))
   PY
   runtime_manifest=/var/tmp/media-generation-package/media-generation-apex-runtime-sha256.jsonl
   test "$(sha256sum "$runtime_manifest" | cut -d' ' -f1)" = \
       '76478175b83fe4679d27dcfbf5e561fa9d7a5cd1efaeff56f3d75b7714079c1d'
   cmp "$runtime_manifest" "$mirror_manifest"
   ```

Compare the four copied Python aliases with the source. Each must report
Python 3.14.4, the same `/usr` base prefix, and its own source or mirror venv
prefix. This confirms dereferencing kept the interpreter behavior while
moving the venv prefix to the stable mirror:

   ```sh
   set -eu
   source=/home/daniel/ai/qualification-runs/t08-20261031T045433Z/runtime
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511/runtime
   /usr/bin/python3.14 - "$source" "$candidate" <<'PY'
   import json, subprocess, sys
   from pathlib import Path

   source, mirror = (Path(value) for value in sys.argv[1:])
   aliases = ("python", "python3", "python3.14", "𝜋thon")
   code = "import json,sys; print(json.dumps([sys.version.split()[0],sys.prefix,sys.base_prefix,sys.executable]))"
   for alias in aliases:
       source_bin = source / "rocm-devel-venv/bin" / alias
       mirror_bin = mirror / "rocm-devel-venv/bin" / alias
       original = json.loads(subprocess.check_output([source_bin, "-c", code], text=True))
       copied = json.loads(subprocess.check_output([
           "runuser", "-u", "media-generation-runner", "--", str(mirror_bin), "-c", code
       ], text=True))
       if original[:3] != ["3.14.4", str(source / "rocm-devel-venv"), "/usr"]:
           raise SystemExit(f"unexpected source Python behavior for {alias}: {original!r}")
       if copied[:3] != ["3.14.4", str(mirror / "rocm-devel-venv"), "/usr"]:
           raise SystemExit(f"unexpected mirror Python behavior for {alias}: {copied!r}")
       if copied[3] != str(mirror_bin):
           raise SystemExit(f"mirror Python executable path mismatch for {alias}: {copied[3]!r}")
   print("all four Python aliases retain Python 3.14.4 and use the mirror venv prefix")
   PY
   ```

After hash equality, rewrite only the copied declaration's four root paths.
This script checks the root IDs and preserves all other declaration fields:

   ```sh
   set -eu
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511
   declaration="$candidate/evidence/t07-candidate-signed/candidate.json"
   /usr/bin/python3.14 - "$declaration" "$candidate" <<'PY'
   import copy, json, os, sys, tempfile
   from pathlib import Path
   path=Path(sys.argv[1])
   root=Path(sys.argv[2])
   value=json.loads(path.read_text(encoding="utf-8"))
   before=copy.deepcopy(value)
   replacement={
       "engine_bin": str(root / "runtime/sd-cpp-hip-b13a482-develvenv/bin"),
       "models": str(root / "inputs/models"),
       "vae": str(root / "inputs/vae"),
       "draft": str(root / "evidence/t07-candidate-draft"),
   }
   roots=value.get("roots")
   if not isinstance(roots,list) or {entry.get("id") for entry in roots} != set(replacement):
       raise SystemExit("candidate root IDs differ from the reviewed four-root declaration")
   for entry in roots:
       entry["path"]=replacement[entry["id"]]
   for old,new in zip(before["roots"],roots,strict=True):
       if {k:v for k,v in old.items() if k != "path"} != {k:v for k,v in new.items() if k != "path"}:
           raise SystemExit("a non-path candidate root field changed")
   fd,temp=tempfile.mkstemp(dir=path.parent,prefix=".candidate.")
   try:
       with os.fdopen(fd,"w",encoding="utf-8") as stream:
           json.dump(value,stream,separators=(",",":"),ensure_ascii=False)
           stream.write("\n")
           stream.flush()
           os.fsync(stream.fileno())
       written=json.loads(Path(temp).read_text(encoding="utf-8"))
       if written != value:
           raise SystemExit("rewritten candidate declaration failed JSON round-trip validation")
       os.chown(temp,0,973)
       os.chmod(temp,0o640)
       os.replace(temp,path)
   finally:
       if os.path.exists(temp): os.unlink(temp)
   PY
   ```

   Then verify the protected paths and actual service identities. This check
   also runs `sd-cli --version` with the approved runner environment; it does
   not start inference or open a GPU workload.

   Before T07 evaluation, run this read-only check as root. It rejects
   named/default ACLs and world-readable private files, then checks effective
   traversal, read, and write access under each service identity. It checks the
   two approved GPU nodes for the runner and confirms the worker can neither
   read nor write them.

   ```sh
   set -eu
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511
   engine="$candidate/runtime/sd-cpp-hip-b13a482-develvenv/bin/sd-cli"
   rocm="$candidate/runtime/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel"
   library_path="$rocm/lib:$rocm/lib/llvm/lib:$rocm/lib/rocm_sysdeps/lib"
   acl_report=$(mktemp)
   trap 'rm -f "$acl_report"' EXIT

   getfacl -R -cpn "$candidate" > "$acl_report"
   if grep -Eq '^(default:|user:[^:]|group:[^:]|mask::)' "$acl_report"; then
       echo 'extended or default ACL found in candidate mirror' >&2
       exit 1
   fi
   symlink=$(find "$candidate" -type l -print -quit)
   if [ -n "$symlink" ]; then
       echo "symlink found in candidate mirror: $symlink" >&2
       exit 1
   fi
   world_readable=$(find "$candidate" -type f -perm -0004 -print -quit)
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
   runuser -u media-generation-runner -- env \
       PATH=/usr/bin ROCM_PATH="$rocm" LD_LIBRARY_PATH="$library_path" \
       "$engine" --version
   validation=/var/tmp/media-generation-package/validation
   mirror_ldd="$validation/ldd.txt"
   mirror_ldd_map="$validation/ldd-map.jsonl"
   test -d "$validation" && test ! -L "$validation"
   test ! -e "$mirror_ldd" && test ! -L "$mirror_ldd"
   test ! -e "$mirror_ldd_map" && test ! -L "$mirror_ldd_map"
   runuser -u media-generation-runner -- env \
       PATH=/usr/bin ROCM_PATH="$rocm" LD_LIBRARY_PATH="$library_path" \
       ldd "$engine" > "$mirror_ldd"
   /usr/bin/python3.14 - "$mirror_ldd" "$candidate/runtime" \
       > "$mirror_ldd_map" <<'PY'
   import hashlib, json, sys
   from pathlib import Path

   report=Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
   runtime=Path(sys.argv[2]).absolute()
   records=[]
   system_roots=tuple(Path(root).resolve() for root in ("/usr/lib","/lib","/usr/lib64","/lib64"))
   for line in report:
       if "linux-vdso.so." in line:
           continue
       if "=>" in line:
           name,right=line.split("=>",1)
           target=right.strip().split()[0]
           if target == "not":
               raise SystemExit(f"unresolved engine dependency: {line.strip()}")
           name=name.strip()
       else:
           target=line.strip().split()[0]
           name=Path(target).name
       path=Path(target)
       if not path.is_absolute():
           raise SystemExit(f"non-absolute dependency path: {line.strip()}")
       try:
           relative=path.relative_to(runtime)
       except ValueError:
           canonical=path.resolve(strict=True)
           if not any(canonical.is_relative_to(root) for root in system_roots):
               raise SystemExit(f"dependency resolved outside approved roots: {canonical}")
           kind,recorded_path,path="system",str(canonical),canonical
       else:
           kind,recorded_path="runtime",relative.as_posix()
       with path.open("rb") as stream:
           digest=hashlib.file_digest(stream,"sha256").hexdigest()
       records.append([name,kind,recorded_path,digest])
   records.sort(key=lambda row:(row[0],row[1],row[2]))
   if len(records) != 31 or len({row[0] for row in records}) != 31:
       raise SystemExit(f"expected 31 distinct dependencies, found {len(records)}")
   runtime_count=sum(row[1] == "runtime" for row in records)
   if runtime_count != 22 or sum(row[1] == "system" for row in records) != 9:
       raise SystemExit(f"unexpected runtime/system dependency counts: {runtime_count}")
   for record in records:
       print(json.dumps(record,separators=(",",":"),ensure_ascii=True))
   PY
   expected_ldd_map=/var/tmp/media-generation-package/media-generation-apex-ldd-map.jsonl
   test "$(sha256sum "$expected_ldd_map" | cut -d' ' -f1)" = \
       '125d2cde81f5e268d4f2f019453d5b0bebec68ac2c63374c46336db230c6f482'
   cmp "$expected_ldd_map" "$mirror_ldd_map"
   for device in /dev/kfd /dev/dri/renderD128; do
       runuser -u media-generation-runner -- test -r "$device"
       runuser -u media-generation-runner -- test -w "$device"
       if runuser -u media-generation-worker -- test -r "$device" \
           || runuser -u media-generation-worker -- test -w "$device"; then
           echo "worker unexpectedly has GPU access: $device" >&2
           exit 1
       fi
   done
   ```

   Run T07 verification as the non-root worker and preserve its report outside
   the mirror. Qualification requires `status == "ready"` and matching trusted
   evidence:

   ```sh
   set -eu
   candidate=/srv/media-generation/candidates/qwen-image-edit-2511
   validation=/var/tmp/media-generation-package/validation
   report="$validation/candidate-verification.json"
   test -d "$validation" && test ! -L "$validation"
   test ! -e "$report" && test ! -L "$report"
   runuser -u media-generation-worker -- env PYTHONDONTWRITEBYTECODE=1 \
       /opt/media-generation/venv/bin/python -m media_generation candidate verify \
       --declaration "$candidate/evidence/t07-candidate-signed/candidate.json" \
       --trusted-evidence "$candidate/evidence/t07-candidate-signed/trusted-evidence.json" \
       > "$report"
   /usr/bin/python3.14 - "$report" <<'PY'
   import json, sys
   report=json.load(open(sys.argv[1],encoding="utf-8"))
   expected_id="sha256:645ce14ebb1134c591ff60af8947a504d91e695c3f043df52cc7bfcdfcd66700"
   if report.get("status") != "ready":
       raise SystemExit(f"candidate is not READY: {report.get('status')!r}")
   if report.get("candidate_id") != expected_id:
       raise SystemExit(f"candidate ID changed: {report.get('candidate_id')!r}")
   print(json.dumps({"status":report["status"],"candidate_id":report["candidate_id"]},sort_keys=True))
   PY
   ```

### Step 6. Create the v9 database and scratch paths

Stop if any target already exists; this procedure never reuses or migrates an
older database. The owner creates only the listed new paths, then the worker
initializes the database with the exact installed package:

```sh
set -eu
test ! -e /var/lib/media-generation-v9
test ! -L /var/lib/media-generation-v9
test ! -e /var/lib/media-generation-v9/db/jobs.sqlite3
test ! -e /var/lib/media-generation-v9/artifacts
test ! -L /var/lib/media-generation-v9/artifacts
test ! -e /var/lib/media-generation-v9/systemd-evidence
test ! -L /var/lib/media-generation-v9/systemd-evidence
test ! -e /var/lib/media-generation/scratch
test ! -L /var/lib/media-generation/scratch
for ancestor in /var /var/lib; do
    test -d "$ancestor"
    test ! -L "$ancestor"
    test "$(stat -c '%F %u:%g %a' "$ancestor")" = 'directory 0:0 755'
    test "$(getfacl -cpn "$ancestor")" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
done
if [ -L /var/lib/media-generation ]; then
    echo '/var/lib/media-generation is a symlink' >&2
    exit 1
elif [ -e /var/lib/media-generation ]; then
    test -d /var/lib/media-generation
    test "$(stat -c '%F %u:%g %a' /var/lib/media-generation)" = 'directory 0:0 755'
    test "$(getfacl -cpn /var/lib/media-generation)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
fi
install -d -o root -g root -m 0755 /var/lib/media-generation-v9
install -d -o root -g media-generation-worker -m 1770 \
    /var/lib/media-generation-v9/db
install -d -o media-generation-worker -g media-generation-worker -m 0700 \
    /var/lib/media-generation-v9/artifacts
install -d -o root -g media-generation-worker -m 0750 \
    /var/lib/media-generation-v9/systemd-evidence
if [ ! -e /var/lib/media-generation ] && [ ! -L /var/lib/media-generation ]; then
    install -d -o root -g root -m 0755 /var/lib/media-generation
fi
test -d /var/lib/media-generation
test ! -L /var/lib/media-generation
test "$(stat -c '%F %u:%g %a' /var/lib/media-generation)" = 'directory 0:0 755'
test "$(getfacl -cpn /var/lib/media-generation)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
install -d -o root -g media-generation-scratch -m 0710 \
    /var/lib/media-generation/scratch
test -d /var/lib/media-generation/scratch
test ! -L /var/lib/media-generation/scratch
test "$(stat -c '%F %u:%g %a' /var/lib/media-generation/scratch)" = 'directory 0:971 710'
test "$(getfacl -cpn /var/lib/media-generation/scratch)" = "$(printf 'user::rwx\ngroup::--x\nother::---')"
runuser -u media-generation-worker -- /bin/sh -eu -c \
    'umask 0007; exec /opt/media-generation/venv/bin/python -' <<'PY'
from pathlib import Path
import sqlite3
from media_generation.store import SQLiteStore
path = Path("/var/lib/media-generation-v9/db/jobs.sqlite3")
SQLiteStore(path)
with sqlite3.connect(path) as connection:
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 9
PY
test "$(stat -c '%u:%g %a' /var/lib/media-generation-v9/db/jobs.sqlite3)" = '972:972 660'
test "$(stat -c '%u:%g %a' /var/lib/media-generation-v9/systemd-evidence)" = '0:972 750'
test "$(stat -c '%u:%g %a' /var/lib/media-generation/scratch)" = '0:971 710'
getfacl -cpn /var/lib/media-generation-v9/db \
    /var/lib/media-generation-v9/artifacts \
    /var/lib/media-generation-v9/systemd-evidence \
    /var/lib/media-generation/scratch
```

### Step 7. Install and verify the broker unit

Install the configuration and unit exactly as shown. Before any service
start, run `systemd-analyze verify
/etc/systemd/system/media-generation-systemd-broker.service`. Do not grant
broad systemd or sudo permissions to the worker. Install only these exact
files from the verified staging directory:

```sh
set -eu
test -d /etc
test ! -L /etc
test "$(stat -c '%F %u:%g %a' /etc)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /etc/systemd
test ! -L /etc/systemd
test "$(stat -c '%F %u:%g %a' /etc/systemd)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc/systemd)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /etc/systemd/system
test ! -L /etc/systemd/system
test "$(stat -c '%F %u:%g %a' /etc/systemd/system)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc/systemd/system)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test ! -e /etc/media-generation
test ! -L /etc/media-generation
test ! -e /etc/systemd/system/media-generation-systemd-broker.service
test ! -L /etc/systemd/system/media-generation-systemd-broker.service
install -d -o root -g root -m 0750 /etc/media-generation
test -d /etc/media-generation
test ! -L /etc/media-generation
test "$(stat -c '%F %u:%g %a' /etc/media-generation)" = 'directory 0:0 750'
test "$(getfacl -cpn /etc/media-generation)" = "$(printf 'user::rwx\ngroup::r-x\nother::---')"
test ! -e /etc/media-generation/broker.json
test ! -L /etc/media-generation/broker.json
install -o root -g root -m 0600 \
    /var/tmp/media-generation-package/broker.json \
    /etc/media-generation/broker.json
install -o root -g root -m 0644 \
    /var/tmp/media-generation-package/media-generation-systemd-broker.service \
    /etc/systemd/system/media-generation-systemd-broker.service
test -f /etc/media-generation/broker.json
test ! -L /etc/media-generation/broker.json
test "$(stat -c '%F %u:%g %a' /etc/media-generation/broker.json)" = 'regular file 0:0 600'
test "$(getfacl -cpn /etc/media-generation/broker.json)" = "$(printf 'user::rw-\ngroup::---\nother::---')"
test -f /etc/systemd/system/media-generation-systemd-broker.service
test ! -L /etc/systemd/system/media-generation-systemd-broker.service
test "$(stat -c '%F %u:%g %a' /etc/systemd/system/media-generation-systemd-broker.service)" = 'regular file 0:0 644'
test "$(getfacl -cpn /etc/systemd/system/media-generation-systemd-broker.service)" = "$(printf 'user::rw-\ngroup::r--\nother::r--')"
systemd-analyze verify \
    /etc/systemd/system/media-generation-systemd-broker.service
```

After the final security gate passes, reload systemd and manually start
`media-generation-systemd-broker.service`; do not enable it at boot.

### Step 8. Verify broker access

After the manually started broker is healthy, run these checks. They prove the
worker can reach the socket and `nobody` cannot traverse or connect. The broker
also rejects a peer unless `SO_PEERCRED` and its live process credentials match
worker UID/GID 972/972 and supplementary GID 973.

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
   expected_broker=$(awk '$2 == "broker.json" {print $1}' \
       /var/tmp/media-generation-package/SHA256SUMS)
   expected_unit=$(awk '$2 == "media-generation-systemd-broker.service" {print $1}' \
       /var/tmp/media-generation-package/SHA256SUMS)
   test -n "$expected_broker"
   test -n "$expected_unit"
   test "$(sha256sum /etc/media-generation/broker.json | cut -d' ' -f1)" = "$expected_broker"
   test "$(sha256sum /etc/systemd/system/$unit | cut -d' ' -f1)" = "$expected_unit"
   test "$(id -u "$(systemctl show "$unit" --property=User --value)")" = 0
   test "$(getent group "$(systemctl show "$unit" --property=Group --value | cut -d: -f1)" | cut -d: -f3)" = 0
   exec_start=$(systemctl show "$unit" --property=ExecStart --value)
   expected_exec_start='{ path=/opt/media-generation/venv/bin/media-generation-systemd-broker ; argv[]=/opt/media-generation/venv/bin/media-generation-systemd-broker ; argv[]=/etc/media-generation/broker.json ; ignore_errors=no'
   case "$exec_start" in
       "$expected_exec_start"*) ;;
       *) printf 'unexpected broker ExecStart: %s\n' "$exec_start" >&2; exit 1;;
   esac
   test "$(stat -c '%u:%g %a' /opt/media-generation/venv/bin/media-generation-systemd-broker)" = '0:0 755'
   test "$(stat -c '%u:%g %a' /etc/media-generation/broker.json)" = '0:0 600'
   require_unit_property() {
       property=$1
       expected=$2
       actual=$(systemctl show "$unit" --property="$property" --value)
       if [ "$actual" != "$expected" ]; then
           printf 'unexpected %s: expected <%s>, received <%s>\n' \
               "$property" "$expected" "$actual" >&2
           exit 1
       fi
   }
   require_unit_property FragmentPath /etc/systemd/system/media-generation-systemd-broker.service
   require_unit_property DropInPaths ''
   require_unit_property User root
   require_unit_property Group root
   require_unit_property Type exec
   require_unit_property UMask 0077
   require_unit_property Restart on-failure
   require_unit_property RestartUSec 2s
   require_unit_property WorkingDirectory /
   require_unit_property RootDirectory ''
   require_unit_property RootImage ''
   require_unit_property ExecCondition ''
   require_unit_property ExecStartPre ''
   require_unit_property ExecStartPost ''
   require_unit_property ExecReload ''
   require_unit_property ExecStop ''
   require_unit_property ExecStopPost ''
   require_unit_property Environment ''
   require_unit_property EnvironmentFiles ''
   require_unit_property NoNewPrivileges yes
   require_unit_property ProtectSystem strict
   require_unit_property ProtectHome read-only
   require_unit_property PrivateTmp yes
   require_unit_property RuntimeDirectory media-generation
   require_unit_property RuntimeDirectoryMode 0750
   require_unit_property RuntimeDirectoryPreserve no
   require_unit_property ReadWritePaths '/run/media-generation /var/lib/media-generation-v9/db /var/lib/media-generation-v9/systemd-evidence /var/lib/media-generation/scratch'
   systemctl show "$unit" --property=NoNewPrivileges \
       --property=ProtectSystem --property=ProtectHome \
       --property=RuntimeDirectory --property=RuntimeDirectoryMode \
       --property=ReadWritePaths
   ```

   Run the worker connection check only after the worker, group, and broker
   exist. The socket probe may be rejected as an incomplete request after
   connect; that response still verifies the filesystem and socket path.
### Step 9. Qualification gate

Keep APEX qualification `UNVERIFIED` until the exact mirror is `READY`,
   native Linux tests pass at the published source SHA, and separately
   authorized real-engine tests have exercised the successful, canceled, and
   recovered lifecycle. Do not run destructive fault injection without
   separate authorization.

Rollback is owner-run after the worker has stopped accepting submissions and
has exited. This deployment does not install a worker unit; stop the worker
through its existing launch mechanism. The pre-stop check below requires no
process with real or effective UID 972. Keep the broker available while first
checking for active attempt units and cgroups, then validate every systemd
attempt against durable root-ledger cgroup-empty evidence, publication state,
and resource state. Only after those checks pass may the owner stop the broker.
Verify it is inactive, then repeat the attempt-unit and cgroup checks before
removing its files. A missing unit or cgroup directory is not proof by itself.
Keep the installation and quarantine capacity if an attempt identity, cgroup
proof, resource state, or publication state cannot be read and matched.
Preserve the v9 database, evidence ledger, artifacts, candidate mirror, and
owner audit reports. Do not recursively remove `/opt/media-generation` or
touch sibling content.

```sh
set -eu
set -o pipefail
printf 'Audited /opt report path: '
IFS= read -r audit_report
case "$audit_report" in
    /var/tmp/media-generation-opt-audit-*.txt) ;;
    *) echo 'unexpected audit report path' >&2; exit 1;;
esac
test -f "$audit_report"
test ! -L "$audit_report"
printf 'Reviewed report SHA-256: '
IFS= read -r reviewed_report_sha
test "$(sha256sum "$audit_report" | cut -d' ' -f1)" = "$reviewed_report_sha"
test "$(awk '$1 == "/opt/media-generation" {count++} END {print count+0}' "$audit_report")" = 1
audited_identity=$(awk '$1 == "/opt/media-generation" {print $5}' "$audit_report")
test -d /opt
test ! -L /opt
test "$(stat -c '%F %u:%g %a' /opt)" = 'directory 0:0 755'
test -d /opt/media-generation
test ! -L /opt/media-generation
test "$(stat -c '%d:%i' /opt/media-generation)" = "$audited_identity"
test "$(stat -c '%F %u:%g %a' /opt/media-generation)" = 'directory 0:973 710'
test "$(getfacl -cpn /opt/media-generation)" = "$(printf 'user::rwx\ngroup::--x\nother::---')"
test -d /opt/media-generation/venv
test ! -L /opt/media-generation/venv
test "$(stat -c '%F %u:%g %a' /opt/media-generation/venv)" = 'directory 0:0 755'
test "$(systemctl show -p ActiveState --value media-generation-systemd-broker.service)" = active
worker_processes=$(ps -eo ruid=,euid=,pid= | awk '$1 == 972 || $2 == 972 {print $3}')
test -z "$worker_processes"
attempt_units=$(systemctl list-units --all --type=service --no-legend 'media-generation-attempt-*.service')
test -z "$attempt_units"
test -d /sys/fs/cgroup/system.slice
attempt_cgroups=$(find /sys/fs/cgroup/system.slice -mindepth 1 -maxdepth 1 -type d \
    -name 'media-generation-attempt-*.service' -print)
test -z "$attempt_cgroups"

/opt/media-generation/venv/bin/python - <<'PY'
import sqlite3
from pathlib import Path

from media_generation.store import SQLiteStore
from media_generation.systemd_attempts import SYSTEMD_CGROUP_CONTAINMENT_CONTRACT

database = Path('/var/lib/media-generation-v9/db/jobs.sqlite3')
ledger = Path('/var/lib/media-generation-v9/systemd-evidence/db-jobs.sqlite3.systemd-evidence.sqlite3')
for path in (database, ledger):
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"required database missing or unsafe: {path}")
    with path.open('rb') as stream:
        header = stream.read(100)
    if header[:16] != b'SQLite format 3\x00' or header[18:20] != b'\x01\x01':
        raise SystemExit(f"database is not in rollback-journal format: {path}")
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            raise SystemExit(f"SQLite sidecar exists; preserve and investigate: {sidecar}")
store = SQLiteStore(database, read_only=True)
with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
    attempts = {
        tuple(row)
        for row in connection.execute(
            'SELECT job_id, attempt_id FROM execution_attempts WHERE containment_contract = ?',
            (SYSTEMD_CGROUP_CONTAINMENT_CONTRACT,),
        )
    }
    containments = {
        tuple(row)
        for row in connection.execute(
            'SELECT job_id, attempt_id FROM execution_containment'
        )
    }
    pending_publications = connection.execute(
        "SELECT publication_id FROM artifact_publications WHERE state NOT IN ('committed','abandoned')"
    ).fetchall()
with sqlite3.connect(ledger.as_uri() + '?mode=ro', uri=True) as connection:
    ledger_rows = connection.execute(
        'SELECT job_id, attempt_id, termination_json FROM systemd_attempt_evidence'
    ).fetchall()
ledger_keys = {(row[0], row[1]) for row in ledger_rows}
if attempts != containments or containments != ledger_keys:
    raise SystemExit('systemd attempt, containment, and ledger identities differ')
if any(row[2] is None for row in ledger_rows):
    raise SystemExit('root ledger has an attempt without durable cgroup-empty proof')
if pending_publications:
    raise SystemExit('an artifact publication is incomplete or unresolved')
for job_id, attempt_id in sorted(attempts):
    if not store.attempt_termination_proven(
        job_id, attempt_id, require_current_attempt=False
    ):
        raise SystemExit(f'validated cgroup termination proof missing: {attempt_id}')
resource = store.resource_snapshot()
if resource.get('job_id') is not None or resource.get('attempt_id') is not None:
    raise SystemExit('execution resource is still reserved')
print(f'validated {len(attempts)} systemd attempts and no active resource/publication')
PY

systemctl stop media-generation-systemd-broker.service
test "$(systemctl show -p ActiveState --value media-generation-systemd-broker.service)" = inactive
attempt_units=$(systemctl list-units --all --type=service --no-legend 'media-generation-attempt-*.service')
test -z "$attempt_units"
attempt_cgroups=$(find /sys/fs/cgroup/system.slice -mindepth 1 -maxdepth 1 -type d \
    -name 'media-generation-attempt-*.service' -print)
test -z "$attempt_cgroups"

expected_broker=$(awk '$2 == "broker.json" {print $1}' \
    /var/tmp/media-generation-package/SHA256SUMS)
expected_unit=$(awk '$2 == "media-generation-systemd-broker.service" {print $1}' \
    /var/tmp/media-generation-package/SHA256SUMS)
test -n "$expected_broker"
test -n "$expected_unit"
test -d /etc
test ! -L /etc
test "$(stat -c '%F %u:%g %a' /etc)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /etc/systemd
test ! -L /etc/systemd
test "$(stat -c '%F %u:%g %a' /etc/systemd)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc/systemd)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /etc/systemd/system
test ! -L /etc/systemd/system
test "$(stat -c '%F %u:%g %a' /etc/systemd/system)" = 'directory 0:0 755'
test "$(getfacl -cpn /etc/systemd/system)" = "$(printf 'user::rwx\ngroup::r-x\nother::r-x')"
test -d /etc/media-generation
test ! -L /etc/media-generation
test "$(stat -c '%F %u:%g %a' /etc/media-generation)" = 'directory 0:0 750'
test "$(getfacl -cpn /etc/media-generation)" = "$(printf 'user::rwx\ngroup::r-x\nother::---')"
test -f /etc/media-generation/broker.json
test ! -L /etc/media-generation/broker.json
test "$(stat -c '%F %u:%g %a' /etc/media-generation/broker.json)" = 'regular file 0:0 600'
test "$(getfacl -cpn /etc/media-generation/broker.json)" = "$(printf 'user::rw-\ngroup::---\nother::---')"
test -f /etc/systemd/system/media-generation-systemd-broker.service
test ! -L /etc/systemd/system/media-generation-systemd-broker.service
test "$(stat -c '%F %u:%g %a' /etc/systemd/system/media-generation-systemd-broker.service)" = 'regular file 0:0 644'
test "$(getfacl -cpn /etc/systemd/system/media-generation-systemd-broker.service)" = "$(printf 'user::rw-\ngroup::r--\nother::r--')"
test "$(systemctl show media-generation-systemd-broker.service --property=FragmentPath --value)" = /etc/systemd/system/media-generation-systemd-broker.service
test -z "$(systemctl show media-generation-systemd-broker.service --property=DropInPaths --value)"
test "$(sha256sum /etc/media-generation/broker.json | cut -d' ' -f1)" = "$expected_broker"
test "$(sha256sum /etc/systemd/system/media-generation-systemd-broker.service | cut -d' ' -f1)" = "$expected_unit"
rm -f /etc/systemd/system/media-generation-systemd-broker.service
rm -f /etc/media-generation/broker.json
systemctl daemon-reload
rm -rf --one-file-system -- /opt/media-generation/venv
chgrp root /opt/media-generation
chmod 0700 /opt/media-generation
test "$(stat -c '%F %u:%g %a' /opt/media-generation)" = 'directory 0:0 700'
test "$(getfacl -cpn /opt/media-generation)" = "$(printf 'user::rwx\ngroup::---\nother::---')"
```

Run this block from the owner's interactive root shell. Leave service identities
and groups in place until the owner confirms that no retained files or evidence
use those IDs. Remove the empty configuration directory only after checking it
contains no unrelated file.

## 7. Upgrade an existing installation

This procedure prepares a candidate beside the installed application and keeps activation under the owner's control. It has not been run on APEX. The document does not authorize a host change. The owner must first complete the source review and approve the candidate revision and bundle hashes.

### Existing installation and expected service contract

The existing application was installed from source revision `3bc8041b332f7fcf1e0873ac2cb526625b6456ee`. Preserve `/opt/media-generation/venv`, `/var/tmp/media-generation-package`, the schema-v9 job database, the artifact database, the root evidence ledger, the candidate mirror, and all scratch and publication data.

The previously reviewed installation bundle records these hashes for the broker configuration and unit:

| File | Expected SHA-256 |
| --- | --- |
| `/etc/media-generation/broker.json` | `8e93c5f78217522b0271d2af63149cc69178389a496ca1bab9465381a9be07c0` |
| `/etc/systemd/system/media-generation-systemd-broker.service` | `ee4c154521729d1ea510895c6c6a5628bf11232016589efbde993b242977719f` |

The expected old broker entry point is `/opt/media-generation/venv/bin/media-generation-systemd-broker`. The broker configuration points `runner_executable` at `/opt/media-generation/venv/bin/media-generation-attempt-runner`. The root broker runs as `root`; the attempt runner runs as UID/GID `970:970` with supplementary GIDs `971,973,990`. The worker remains UID/GID `972:972` with supplementary GID `973`. The only allowed GPU devices remain `/dev/kfd` and `/dev/dri/renderD128`.

The owner must compare the active files with the hashes and paths above before proceeding. The owner must also inspect the loaded unit, every drop-in, live process credentials, ACLs, symlinks, mount state, and file ownership. Stop if the active unit has an unexpected fragment path, drop-in, `ExecStart`, service identity, broker configuration, or permission. Do not infer the current host state from this document or from the previous installation report.

The application database remains schema version 9. The candidate source must continue to report `_CURRENT_SCHEMA_VERSION = 9`. The upgrade must not run a migration, copy a database, restore a database snapshot, or change the artifact or ledger paths.

### Read-only preflight

The preflight has two read-only stages. Stage A checks the reviewed bundle on the Mac with a portable Python command. Stage B repeats the bundle checks on APEX and adds Linux host inventory checks. These stages do not authorize candidate installation or activation. The release handoff records the exact off-host bundle path, the separate APEX inbound path, `EXPECTED_SOURCE_SHA`, and `EXPECTED_SUMS_SHA`. Do not substitute a branch name or a manually chosen revision.

#### A. Off-host Mac bundle validation

Run the portable validator below on the Mac. Set `PYTHON_BIN` to a Python interpreter available on the Mac; the command does not assume the APEX interpreter path. It uses only the Python standard library, reads the bundle, and writes no files. It checks the flat payload inventory and hashes, then validates the release-bound configuration and systemd unit.

#### Before Stage B: transfer the reviewed bundle

After Stage A passes and the owner approves the source revision and bundle hashes, copy the bundle to a new owner-only inbox on APEX. The Mac bundle path is `/var/tmp/media-generation-release-${EXPECTED_SOURCE_SHA}`; the APEX inbox is `/var/tmp/media-generation-incoming-${EXPECTED_SOURCE_SHA}`. Set `BUNDLE` to the Mac path for Stage A and to the APEX inbox for Stage B. Keep the inbox separate from `PACKAGE_STAGE`: Stage B reads the inbox and requires `PACKAGE_STAGE` to be absent, and Stage C copies the verified payload into `PACKAGE_STAGE`.

The earlier initial-install transfer path, `/var/tmp/media-generation-package`, belongs to the existing installation and remains untouched. The following owner-run transfer writes only the new inbox. It has not been run as part of this candidate review.

Before running the transfer, inspect `/var/tmp` on APEX with `namei -l`, `stat`, `getfacl`, and `findmnt`. Confirm the parent matches the expected host state and the revision-specific inbox does not exist. Stop if ownership, mode, ACLs, or mount state differs. This inspection is read-only. The command creates a uniquely named partial directory and publishes the inbox only after checksum verification.

```sh
set -eu
: "${EXPECTED_SOURCE_SHA:?set EXPECTED_SOURCE_SHA from the release handoff}"
: "${EXPECTED_SUMS_SHA:?set EXPECTED_SUMS_SHA from the release handoff}"
case "$EXPECTED_SOURCE_SHA" in
  (*[!0-9a-f]*|'') printf 'transfer failed: EXPECTED_SOURCE_SHA must be lowercase hexadecimal\n' >&2; exit 1 ;;
esac
if [ "${#EXPECTED_SOURCE_SHA}" -ne 40 ]; then
  printf 'transfer failed: EXPECTED_SOURCE_SHA must be 40 characters\n' >&2
  exit 1
fi
case "$EXPECTED_SUMS_SHA" in
  (*[!0-9a-f]*|'') printf 'transfer failed: EXPECTED_SUMS_SHA must be lowercase hexadecimal\n' >&2; exit 1 ;;
esac
if [ "${#EXPECTED_SUMS_SHA}" -ne 64 ]; then
  printf 'transfer failed: EXPECTED_SUMS_SHA must be 64 characters\n' >&2
  exit 1
fi
bundle="/var/tmp/media-generation-release-$EXPECTED_SOURCE_SHA"
apex_bundle="/var/tmp/media-generation-incoming-$EXPECTED_SOURCE_SHA"
test -d "$bundle" && test ! -L "$bundle"
sums_record=$(shasum -a 256 "$bundle/SHA256SUMS")
actual_sums_sha=${sums_record%% *}
test "$actual_sums_sha" = "$EXPECTED_SUMS_SHA"
apex_partial=$(ssh apex "set -eu; test ! -e '$apex_bundle'; test ! -L '$apex_bundle'; umask 077; mktemp -d '/var/tmp/media-generation-incoming-$EXPECTED_SOURCE_SHA.partial.XXXXXXXX'")
case "$apex_partial" in
  "$apex_bundle".partial.*) ;;
  *) printf 'transfer failed: unexpected APEX partial path\n' >&2; exit 1 ;;
esac
partial_suffix=${apex_partial##*.partial.}
case "$partial_suffix" in
  (*[!A-Za-z0-9]*|'') printf 'transfer failed: unsafe APEX partial path\n' >&2; exit 1 ;;
esac
if [ "${#partial_suffix}" -ne 8 ]; then
  printf 'transfer failed: unexpected APEX partial path length\n' >&2
  exit 1
fi
scp "$bundle"/* "apex:$apex_partial/"
ssh apex "set -eu; test -d '$apex_partial'; test ! -L '$apex_partial'; cd '$apex_partial'; sha256sum --strict -c SHA256SUMS"
ssh apex "set -eu; test ! -e '$apex_bundle'; test ! -L '$apex_bundle'; mv -nT -- '$apex_partial' '$apex_bundle'; test -d '$apex_bundle'; test ! -L '$apex_bundle'; test ! -e '$apex_partial'; cd '$apex_bundle'; sha256sum --strict -c SHA256SUMS"
```

The transfer needs GNU `mktemp`, `mv -nT`, and `sha256sum` on APEX. Stage B also needs GNU `find`, `sort`, and `cmp`; stop if any required command is missing. The transfer creates a unique partial directory, checks all payloads there, then publishes the complete directory with GNU `mv -nT`. A partial copy or failed checksum leaves that directory in place; a retry gets a different partial path and does not overwrite it. The final inbox appears only after the no-clobber rename and a second checksum pass. Stage B checks the manifest digest against `EXPECTED_SUMS_SHA`, verifies the exact file inventory, and runs the portable validator. Stop if the final inbox already exists, either handoff hash differs, a partial path is unexpected, or a checksum fails. Keep partial directories and the completed inbox for inspection; do not replace or remove them during candidate installation.

#### B. APEX read-only host preflight

Set `BUNDLE` to the APEX inbound path above. Run the Linux inventory checks below on APEX with GNU `find`, `sort`, `cmp`, and `sha256sum`. Set `PYTHON_BIN` to an interpreter available on APEX only after verifying its path. Then run the same portable Python validator from Stage A on APEX. The shell inventory uses temporary files under `TMPDIR` (or `/tmp`) and removes them when it exits.

The proposed revision-specific destinations are:

| Purpose | Proposed path |
| --- | --- |
| Off-host reviewed bundle (`BUNDLE` on Mac) | `/var/tmp/media-generation-release-${EXPECTED_SOURCE_SHA}` |
| APEX inbound bundle (`BUNDLE` on APEX) | `/var/tmp/media-generation-incoming-${EXPECTED_SOURCE_SHA}` |
| APEX partial transfer directory | `/var/tmp/media-generation-incoming-${EXPECTED_SOURCE_SHA}.partial.<random>` |
| Root-owned package-stage copy (`PACKAGE_STAGE`) | `/var/tmp/media-generation-package-${EXPECTED_SOURCE_SHA}` |
| Candidate application environment | `/opt/media-generation/releases/${EXPECTED_SOURCE_SHA}/venv` |
| Versioned candidate configuration and unit | `/etc/media-generation/releases/${EXPECTED_SOURCE_SHA}` |
| Preserved active configuration and unit | `/etc/media-generation/rollback/3bc8041b332f7fcf1e0873ac2cb526625b6456ee` |

These paths are proposed names. Inspect each parent with `namei -l`, `stat`, `getfacl`, and `findmnt` first. Reject a symlink, unexpected owner or mode, unexpected ACL, mount, or existing revision destination. Do not reuse or overwrite a destination left by an earlier attempt. Preserve any partial candidate for inspection.

After transferring the bundle into the APEX inbox, verify its provenance and all payload checksums before making the package-stage copy:

```sh
set -euf
: "${BUNDLE:?set BUNDLE to the reviewed bundle path}"
: "${EXPECTED_SOURCE_SHA:?set EXPECTED_SOURCE_SHA to the reviewed commit}"
: "${EXPECTED_SUMS_SHA:?set EXPECTED_SUMS_SHA to the reviewed SHA256SUMS digest}"
PACKAGE_STAGE="/var/tmp/media-generation-package-${EXPECTED_SOURCE_SHA}"
CANDIDATE_RELEASE="/opt/media-generation/releases/${EXPECTED_SOURCE_SHA}"
CONFIG_RELEASE="/etc/media-generation/releases/${EXPECTED_SOURCE_SHA}"
fail() {
  printf 'bundle preflight failed: %s\n' "$*" >&2
  exit 1
}
case "$BUNDLE" in
  /*) ;;
  *) fail "BUNDLE must be an absolute path" ;;
esac
if [ -L "$BUNDLE" ] || [ ! -d "$BUNDLE" ]; then
  fail "BUNDLE must be a real directory"
fi
case "$EXPECTED_SOURCE_SHA" in
  (*[!0-9a-f]*|'') fail "EXPECTED_SOURCE_SHA must contain 40 lowercase hexadecimal characters" ;;
esac
if [ "${#EXPECTED_SOURCE_SHA}" -ne 40 ]; then
  fail "EXPECTED_SOURCE_SHA must contain 40 lowercase hexadecimal characters"
fi
case "$EXPECTED_SUMS_SHA" in
  (*[!0-9a-f]*|'') fail "EXPECTED_SUMS_SHA must contain 64 lowercase hexadecimal characters" ;;
esac
if [ "${#EXPECTED_SUMS_SHA}" -ne 64 ]; then
  fail "EXPECTED_SUMS_SHA must contain 64 lowercase hexadecimal characters"
fi
for required_file in SOURCE_SHA SHA256SUMS; do
  if [ -L "$BUNDLE/$required_file" ] || [ ! -f "$BUNDLE/$required_file" ]; then
    fail "$required_file is missing, a symlink, or not a regular file"
  fi
done
preflight_tmp_root=${TMPDIR:-/tmp}
case "$preflight_tmp_root" in
  /*) ;;
  *) fail "TMPDIR must be an absolute path" ;;
esac
if ! preflight_dir=$(mktemp -d "$preflight_tmp_root/media-generation-preflight.XXXXXXXX"); then
  fail "could not create a temporary inventory directory"
fi
trap 'rm -rf -- "$preflight_dir"' 0
trap 'exit 1' HUP INT TERM

# GNU find reports directories, symlinks, and other non-regular entries here.
if ! find "$BUNDLE" -mindepth 1 -maxdepth 1 ! -type f -print -quit \
    > "$preflight_dir/non-regular"; then
  fail "find failed while checking bundle entry types"
fi
if [ -s "$preflight_dir/non-regular" ]; then
  fail "bundle contains a non-regular entry such as a directory or symlink"
fi

# NUL delimiters keep unusual filenames from being mistaken for multiple entries.
if ! find "$BUNDLE" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' \
    > "$preflight_dir/actual.unsorted"; then
  fail "find failed while enumerating bundle files"
fi
if ! printf '%s\000' \
    SHA256SUMS \
    SOURCE_SHA \
    broker.json \
    media-generation-apex-ldd-map.jsonl \
    media-generation-apex-python-aliases.jsonl \
    media-generation-apex-runtime-sha256.jsonl \
    media-generation-apex-runtime-symlinks.jsonl \
    media-generation-apex-source-ldd.txt \
    media-generation-systemd-broker.service \
    media_generation-0.1.0-py3-none-any.whl \
    pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl \
    > "$preflight_dir/expected.unsorted"; then
  fail "could not build the fixed bundle inventory"
fi
if ! LC_ALL=C sort -z "$preflight_dir/actual.unsorted" \
    > "$preflight_dir/actual.sorted"; then
  fail "sort failed while ordering bundle files"
fi
if ! LC_ALL=C sort -z "$preflight_dir/expected.unsorted" \
    > "$preflight_dir/expected.sorted"; then
  fail "sort failed while ordering the required bundle inventory"
fi
if cmp -s "$preflight_dir/expected.sorted" "$preflight_dir/actual.sorted"; then
  :
else
  compare_status=$?
  case "$compare_status" in
    1) fail "bundle inventory does not match the required regular files" ;;
    *) fail "cmp failed while checking the bundle inventory (status $compare_status)" ;;
  esac
fi

if ! printf '%s\n' "$EXPECTED_SOURCE_SHA" \
    > "$preflight_dir/expected-source-sha"; then
  fail "could not prepare the expected SOURCE_SHA record"
fi
if cmp -s "$BUNDLE/SOURCE_SHA" "$preflight_dir/expected-source-sha"; then
  :
else
  compare_status=$?
  case "$compare_status" in
    1) fail "SOURCE_SHA does not match EXPECTED_SOURCE_SHA exactly" ;;
    *) fail "cmp failed while checking SOURCE_SHA (status $compare_status)" ;;
  esac
fi
if ! sums_record=$(sha256sum "$BUNDLE/SHA256SUMS"); then
  fail "sha256sum failed while reading SHA256SUMS"
fi
actual_sums_sha=${sums_record%% *}
if [ "$actual_sums_sha" != "$EXPECTED_SUMS_SHA" ]; then
  fail "SHA256SUMS digest does not match the independent handoff record"
fi

if ! (
  cd "$BUNDLE" &&
  sha256sum -- \
    SOURCE_SHA \
    broker.json \
    media-generation-apex-ldd-map.jsonl \
    media-generation-apex-python-aliases.jsonl \
    media-generation-apex-runtime-sha256.jsonl \
    media-generation-apex-runtime-symlinks.jsonl \
    media-generation-apex-source-ldd.txt \
    media-generation-systemd-broker.service \
    media_generation-0.1.0-py3-none-any.whl \
    pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl \
    > "$preflight_dir/canonical-SHA256SUMS"
); then
  fail "sha256sum failed while hashing the required payloads"
fi
if cmp -s "$preflight_dir/canonical-SHA256SUMS" "$BUNDLE/SHA256SUMS"; then
  :
else
  compare_status=$?
  case "$compare_status" in
    1) fail "SHA256SUMS does not match the canonical payload manifest" ;;
    *) fail "cmp failed while checking the canonical payload manifest (status $compare_status)" ;;
  esac
fi
for destination in "$PACKAGE_STAGE" "$CANDIDATE_RELEASE" "$CONFIG_RELEASE"; do
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    fail "revision destination already exists: $destination"
  fi
done
printf 'bundle preflight passed: source, inventory, and payload hashes verified\n'
```

`SOURCE_SHA` must match `EXPECTED_SOURCE_SHA` and its digest must appear in
`SHA256SUMS`. The filename comparison covers every regular payload except the
checksum file itself.

Compare the `SHA256SUMS` digest and every payload digest with the independently reviewed handoff record. Verify the wheel, Pillow wheel, `broker.json`, unit, runtime inventories, Python alias inventory, loader map, and source-loader report. Require the bundle's `broker.json` to point to `${EXPECTED_SOURCE_SHA}/venv/bin/media-generation-attempt-runner`. Require the bundled unit's `ExecStart` and `RequiresMountsFor` to name the same candidate release path. Stop on any other difference or hash mismatch.

Run the portable validator on either host with this command. On APEX, run it after the Linux inventory block above. The shell requires all four environment variables, passes their values as quoted arguments, and returns the interpreter's exit status.

```sh
set -eu
: "${BUNDLE:?set BUNDLE to the reviewed bundle path}"
: "${EXPECTED_SOURCE_SHA:?set EXPECTED_SOURCE_SHA to the reviewed commit}"
: "${EXPECTED_SUMS_SHA:?set EXPECTED_SUMS_SHA to the reviewed SHA256SUMS digest}"
: "${PYTHON_BIN:?set PYTHON_BIN to an available Python interpreter}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  printf 'configuration validation failed: Python interpreter not found: %s\n' "$PYTHON_BIN" >&2
  exit 1
fi
"$PYTHON_BIN" - "$BUNDLE" "$EXPECTED_SOURCE_SHA" "$EXPECTED_SUMS_SHA" \
  /etc/systemd/system/media-generation-systemd-broker.service \
  "/etc/media-generation/releases/${EXPECTED_SOURCE_SHA}/broker.json" <<'MEDIA_GENERATION_BUNDLE_VALIDATION'
import argparse
import hashlib
import json
import re
from pathlib import Path


PAYLOAD_NAMES = {
    "SOURCE_SHA",
    "broker.json",
    "media-generation-apex-ldd-map.jsonl",
    "media-generation-apex-python-aliases.jsonl",
    "media-generation-apex-runtime-sha256.jsonl",
    "media-generation-apex-runtime-symlinks.jsonl",
    "media-generation-apex-source-ldd.txt",
    "media-generation-systemd-broker.service",
    "media_generation-0.1.0-py3-none-any.whl",
    "pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl",
}
UNIT_PATH = "/etc/systemd/system/media-generation-systemd-broker.service"


def require(condition, message):
    if not condition:
        raise SystemExit(f"configuration validation failed: {message}")


def matches_json_value_exactly(observed, expected):
    """Compare JSON values while preserving the types of nested values."""
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return observed.keys() == expected.keys() and all(
            matches_json_value_exactly(observed[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(
            matches_json_value_exactly(actual, value)
            for actual, value in zip(observed, expected)
        )
    return observed == expected


parser = argparse.ArgumentParser(
    description="Validate a release-bound media-generation deployment bundle."
)
parser.add_argument("bundle", type=Path)
parser.add_argument("source_sha")
parser.add_argument("expected_sums_sha")
parser.add_argument("unit_path")
parser.add_argument("config_path")
arguments = parser.parse_args()

require(re.fullmatch(r"[0-9a-f]{40}", arguments.source_sha) is not None,
        "EXPECTED_SOURCE_SHA must be 40 lowercase hexadecimal characters")
require(re.fullmatch(r"[0-9a-f]{64}", arguments.expected_sums_sha) is not None,
        "EXPECTED_SUMS_SHA must be 64 lowercase hexadecimal characters")
require(arguments.bundle.is_absolute(), "BUNDLE must be an absolute path")
require(not arguments.bundle.is_symlink() and arguments.bundle.is_dir(),
        "BUNDLE must be a real directory")
require(arguments.unit_path == UNIT_PATH, "expected unit path")
candidate_venv = f"/opt/media-generation/releases/{arguments.source_sha}/venv"
candidate_config = (
    f"/etc/media-generation/releases/{arguments.source_sha}/broker.json"
)
require(arguments.config_path == candidate_config, "expected configuration path")

try:
    entries = list(arguments.bundle.iterdir())
except OSError as error:
    raise SystemExit(f"configuration validation failed: cannot enumerate bundle: {error}")
expected_entries = PAYLOAD_NAMES | {"SHA256SUMS"}
require({entry.name for entry in entries} == expected_entries,
        "bundle inventory does not match the required regular files")
for entry in entries:
    try:
        regular = entry.is_file() and not entry.is_symlink()
    except OSError as error:
        raise SystemExit(
            f"configuration validation failed: cannot inspect bundle entry {entry.name}: {error}"
        )
    require(regular, f"bundle entry is not a regular file: {entry.name}")

try:
    source_bytes = (arguments.bundle / "SOURCE_SHA").read_bytes()
    sums_bytes = (arguments.bundle / "SHA256SUMS").read_bytes()
except OSError as error:
    raise SystemExit(f"configuration validation failed: cannot read bundle metadata: {error}")
require(source_bytes == f"{arguments.source_sha}\n".encode("ascii"),
        "SOURCE_SHA does not match EXPECTED_SOURCE_SHA")
require(hashlib.sha256(sums_bytes).hexdigest() == arguments.expected_sums_sha,
        "SHA256SUMS digest does not match the independent handoff record")

try:
    sums_text = sums_bytes.decode("ascii")
except UnicodeDecodeError as error:
    raise SystemExit(f"configuration validation failed: SHA256SUMS is not ASCII: {error}")
require(sums_bytes.endswith(b"\n"), "SHA256SUMS must end with an LF newline")
require(
    not any(separator in sums_bytes for separator in (b"\r", b"\v", b"\f")),
    "SHA256SUMS must use LF line separators",
)
manifest_names = set()
manifest_order = []
for line_number, line in enumerate(sums_text[:-1].split("\n"), start=1):
    if (
        len(line) < 67
        or line[64:66] != "  "
        or re.fullmatch(r"[0-9a-f]{64}", line[:64]) is None
    ):
        raise SystemExit(
            f"configuration validation failed: malformed SHA256SUMS entry at line {line_number}"
        )
    name = line[66:]
    require(re.fullmatch(r"[A-Za-z0-9._-]+", name) is not None,
            f"unsafe SHA256SUMS filename at line {line_number}")
    require(name in PAYLOAD_NAMES, f"unapproved SHA256SUMS filename: {name}")
    require(name not in manifest_names, f"duplicate SHA256SUMS filename: {name}")
    manifest_names.add(name)
    manifest_order.append(name)
require(manifest_names == PAYLOAD_NAMES, "SHA256SUMS does not list the exact payload set")
require(manifest_order == sorted(PAYLOAD_NAMES), "SHA256SUMS entries are not in canonical order")
for line in sums_text.splitlines():
    expected_digest = line[:64]
    name = line[66:]
    digest = hashlib.sha256()
    try:
        with (arguments.bundle / name).open("rb") as payload:
            for chunk in iter(lambda: payload.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise SystemExit(
            f"configuration validation failed: cannot hash payload {name}: {error}"
        )
    require(digest.hexdigest() == expected_digest, f"payload checksum mismatch: {name}")

try:
    configuration = json.loads(
        (arguments.bundle / "broker.json").read_text(encoding="utf-8")
    )
    unit_text = (
        arguments.bundle / "media-generation-systemd-broker.service"
    ).read_bytes().decode("utf-8")
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"configuration validation failed: cannot read configuration or unit: {error}")

runtime_root = "/srv/media-generation/candidates/qwen-image-edit-2511/runtime"
expected_configuration = {
    "database_path": "/var/lib/media-generation-v9/db/jobs.sqlite3",
    "socket_path": "/run/media-generation/attempt-broker.sock",
    "scratch_root": "/var/lib/media-generation/scratch",
    "runner_executable": f"{candidate_venv}/bin/media-generation-attempt-runner",
    "runner_uid": 970,
    "runner_gid": 970,
    "runner_supplementary_gids": [971, 973, 990],
    "worker_uid": 972,
    "worker_gid": 972,
    "scratch_gid": 971,
    "model_read_gid": 973,
    "device_allow": ["/dev/kfd", "/dev/dri/renderD128"],
    "read_roots": [
        runtime_root,
        "/srv/media-generation/candidates/qwen-image-edit-2511/inputs",
    ],
    "environment_path_allowlist": [
        "/usr/bin",
        f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel",
        f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib",
        f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/llvm/lib",
        f"{runtime_root}/rocm-devel-venv/lib/python3.14/site-packages/_rocm_sdk_devel/lib/rocm_sysdeps/lib",
    ],
    "empty_timeout_seconds": 30,
}
require(isinstance(configuration, dict), "broker configuration must be an object")
require(set(configuration) == set(expected_configuration), "broker configuration field set")
for key, expected_value in expected_configuration.items():
    require(matches_json_value_exactly(configuration.get(key), expected_value), key)

expected_unit = (
    "[Unit]\n"
    "Description=Media Generation systemd attempt broker\n"
    "After=local-fs.target\n"
    "RequiresMountsFor=/opt/media-generation "
    f"{candidate_venv} /etc/media-generation/releases/{arguments.source_sha} \\\n"
    "    /var/lib/media-generation-v9/db /var/lib/media-generation/scratch \\\n"
    "    /srv/media-generation/candidates/qwen-image-edit-2511\n"
    "\n"
    "[Service]\n"
    "Type=exec\n"
    "User=root\n"
    "Group=root\n"
    "UMask=0077\n"
    "WorkingDirectory=/\n"
    "RuntimeDirectory=media-generation\n"
    "RuntimeDirectoryMode=0750\n"
    "RuntimeDirectoryPreserve=no\n"
    f"ExecStart={candidate_venv}/bin/media-generation-systemd-broker {candidate_config}\n"
    "Restart=on-failure\n"
    "RestartSec=2s\n"
    "NoNewPrivileges=yes\n"
    "ProtectSystem=strict\n"
    "ProtectHome=read-only\n"
    "PrivateTmp=yes\n"
    "ReadWritePaths=/run/media-generation /var/lib/media-generation-v9/db "
    "/var/lib/media-generation-v9/systemd-evidence /var/lib/media-generation/scratch\n"
)
require(unit_text == expected_unit,
        "systemd unit does not exactly match the release-bound security template")
print("bundle configuration and systemd unit validation passed")
MEDIA_GENERATION_BUNDLE_VALIDATION
```

The expected unit and configuration paths are fixed by this command. It binds the candidate runner and broker executables, candidate configuration, and mount requirements to `EXPECTED_SOURCE_SHA`; it also rejects extra unit properties and any change to the protected broker fields. A failure means the bundle does not select the reviewed candidate or does not preserve the approved identity, device, filesystem, or systemd boundary.

The validator checks JSON types as well as values. For example, 970.0 does not satisfy an integer UID field.

On APEX, this command uses the host's selected `PYTHON_BIN`; it does not assume the Mac path or `/usr/bin/python3.14`. The deployment steps that follow remain a separate candidate-installation phase and require owner review before activation.

Confirm the active unit and broker file are regular root-owned files, have no unexpected ACLs, and match the hashes above. Require `DropInPaths` to be empty and the loaded `ExecStart` to match the unit file. Check all service identities and supplementary groups with both keyed account lookups and live process credentials. Check that the worker cannot read runner scratch or access either GPU device, and that the runner cannot write worker publication output.

Check the installed venv without modifying it. Require Python 3.14.4, root ownership, no group or world write permission, the expected `lib64 -> lib` link, and the documented console-script permissions. Record a sorted file hash inventory and symlink inventory before candidate installation. Record `pip list --format=json` and `pip check` output for the existing environment.

Verify that the model and runtime mirror still matches the pinned runtime inventories and has fresh T07 `READY` evidence. Check every path component, runtime library, model input, scratch directory, database directory, ledger directory, and approved device using the actual runner and worker accounts. Do not change permissions on the original model tree, the runtime source, or existing databases to make a check pass.

Inspect broker and worker state before stopping anything. Confirm the loaded broker unit and its `MainPID`, identify the worker's actual launcher, and inspect active attempt units and cgroups. Do not use `pkill` or stop an unrelated GPU process. Run the following check as the worker with the installed venv's Python. It opens the schema-v9 database read-only, checks its integrity and idle state, and prints a logical database digest for the rollback check.

```python
import hashlib
import sqlite3
import sys
from pathlib import Path

database = Path(sys.argv[1]).resolve()
uri = f"{database.as_uri()}?mode=ro"
with sqlite3.connect(uri, uri=True) as connection:
    connection.execute("PRAGMA query_only = ON")
    assert connection.execute("PRAGMA user_version").fetchone() == (9,)
    assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert connection.execute(
        "SELECT state FROM execution_resource WHERE id = 1"
    ).fetchone() == ("available",)
    checks = (
        "SELECT count(*) FROM execution_jobs "
        "WHERE status IN ('running', 'ambiguous')",
        "SELECT count(*) FROM execution_attempts "
        "WHERE status IN ('running', 'ambiguous')",
        "SELECT count(*) FROM execution_cancellations WHERE state = 'requested'",
        "SELECT count(*) FROM artifact_publications "
        "WHERE state IN ('allocated', 'ready')",
    )
    assert all(connection.execute(query).fetchone() == (0,) for query in checks)
    snapshot = "\n".join(connection.iterdump()).encode()
    print(hashlib.sha256(snapshot).hexdigest())
```

Run it as `media-generation-worker` with `/opt/media-generation/venv/bin/python` and `/var/lib/media-generation-v9/db/jobs.sqlite3`. Require success and zero counts. If the resource is claimed or quarantined, an attempt is active or ambiguous, a cancellation is still requested, or a publication is incomplete, stop and use the existing recovery path before considering an upgrade. Record logical integrity digests for any separate artifact database and the root evidence ledger using their own read-only SQLite schemas. Compare them again before rollback. Any unexplained change blocks rollback.

Measure free space on both `/var/tmp` and `/opt`. Include the copied bundle, the new venv, the versioned configuration, and temporary build or install files in the estimate. Require enough free space for two copies of the larger of the bundle or the installed venv. Keep all preflight output and hashes outside the Git repository.

### C. Candidate installation and qualification

Copy the verified APEX inbox at `BUNDLE` into `/var/tmp/media-generation-package-${EXPECTED_SOURCE_SHA}` only after verifying that the destination and its parent are safe and the destination does not exist. Set the new directory to `root:root 0700`. Verify its complete `SHA256SUMS` again after copying. Leave both the inbound bundle and the existing `/var/tmp/media-generation-package` untouched.

Create `/opt/media-generation/releases` only if the owner has verified that it is absent. If it already exists, inspect its owner, mode, ACLs, and contents before using it. Create a new `/opt/media-generation/releases/${EXPECTED_SOURCE_SHA}` directory with owner `root`, group `media-generation-model-read`, and mode `0710`. Stop if that exact release path exists or is a symlink. Do not change the owner or mode of `/opt/media-generation` or the existing `venv`.

Create the candidate venv at `/opt/media-generation/releases/${EXPECTED_SOURCE_SHA}/venv` with `/usr/bin/python3.14 -m venv --copies`. Install only the two bundled wheels with `--no-index --no-deps`, then run `pip check`. Do not install build tools or resolve dependencies from the network. Record Python and pip versions, package metadata, console-script hashes, ownership, modes, and symlinks. Require the candidate venv's `lib64 -> lib` link and verify both console scripts are root-owned regular files whose shebangs name the candidate venv. Run read-only imports and candidate checks as the worker and runner accounts.

Require the candidate venv to be `root:root 0755`. Create `/etc/media-generation/releases` only if the owner has verified that it is absent. If it exists, inspect it before use. Create `/etc/media-generation/releases/${EXPECTED_SOURCE_SHA}` as `root:root 0700`. Keep the candidate `broker.json` and systemd unit there. Require owner `root`, mode `0600` for the configuration, and mode `0644` for the unit. Run `systemd-analyze verify` on the candidate unit. Compared with the existing approved bundle, the broker configuration may change only `runner_executable`; the unit may change only `ExecStart` and the matching `RequiresMountsFor` entry. Keep all other broker values, identities, device allowlists, read roots, systemd restrictions, and writable paths unchanged. The active unit remains a root-owned regular file with mode `0644` and no unexpected ACLs.

After candidate installation, repeat the old venv's file hash and symlink inventories. They must match the pre-install inventories exactly. Verify the current systemd unit, broker configuration, database, ledger, candidate mirror, artifacts, and scratch data still have their preflight hashes or read-only state. Do not clean up a failed candidate automatically.

This phase qualifies only the offline package and filesystem layout. It does not start the broker or run inference.

### D. Owner-controlled activation

Keep installation and activation separate. The owner must review the candidate bundle hashes, install results, database report, permissions, and rollback state, then explicitly approve activation for `EXPECTED_SOURCE_SHA` in an interactive session.

Immediately before activation, repeat the active-unit and database checks. Stop if any worker, broker, runner, or transient attempt unit is active. Stop the worker through the exact launcher identified during preflight. Stop the broker only after confirming that no attempt requires cancellation, recovery, or cgroup termination. Require the broker unit to be inactive with `MainPID=0`, no active attempt cgroups, no unresolved publications, no requested cancellation, and an available resource row. If any process or state is uncertain, leave the active configuration unchanged and retain quarantine.

Before replacing either active file, create the revision-specific rollback directory. Require it to be absent or verify that an existing copy matches the original installation hashes. Copy the active broker configuration and unit there without replacing existing backups. Verify the backup hashes and permissions. The original venv remains in place at `/opt/media-generation/venv`.

Install the candidate configuration to a temporary regular file on the same filesystem as `/etc/media-generation/broker.json`, verify its hash and mode, then atomically rename it over the active configuration. Repeat for `/etc/systemd/system/media-generation-systemd-broker.service`, with mode `0644`. Do not use symlinks. Keep the broker stopped until both files have passed hash, owner, mode, path, and `systemd-analyze verify` checks. If either replacement is interrupted or fails, do not start the service; restore and verify the original pair from the rollback directory.

Run `systemctl daemon-reload`, inspect `systemctl show` and `systemctl cat`, and verify the loaded fragment, absence of drop-ins, exact `ExecStart`, unit identity, systemd restrictions, and mount requirements. The owner makes a second explicit decision before manually starting the broker. Do not enable it at boot. Check broker health, socket permissions, unauthorized-account rejection, service credentials, database and ledger boundaries, runner access to the two allowed GPU devices, and model/runtime readability. Do not run real-engine inference as part of offline startup verification.

### Rollback conditions

The old venv, old broker configuration, and old systemd unit form the rollback set. Restore them only as a matched set after confirming that no old or candidate broker, worker, runner, or attempt cgroup remains active. Verify that the schema is still version 9, no migration ran, the database and root ledger are consistent, and the original config and unit hashes match the recorded values. Restore the pair, run `systemctl daemon-reload`, verify the loaded old executable/configuration pair, and start the old broker manually only after another owner decision.

Do not restore a database snapshot, reset claim epochs, clear cancellation records, or restore publication authority. Roll back to the old application only if the candidate has not claimed or executed an attempt and has not changed durable execution, cancellation, publication, or termination evidence. If a candidate attempt started, if evidence changed, or if the before/after state cannot prove those facts, keep the broker stopped, preserve all data, retain GPU quarantine where required, and recover with the reviewed candidate. The old application predates later lifecycle corrections and is not a safe rollback target after it would need to interpret state produced by the candidate.

Never remove the candidate venv, package copy, rollback files, database, ledger, scratch, artifacts, or candidate mirror automatically. Preserve partial state for review when a check fails. If rollback preconditions are not proven, report that rollback is unavailable and request an owner recovery decision.

### Qualification and acceptance stages

Record each stage separately:

1. Candidate package installation and offline integrity checks.
2. Service-account and filesystem qualification.
3. Broker startup and restricted-socket qualification.
4. Controlled negative and fault tests in an approved quiet GPU window.
5. Real-engine GPU qualification against the exact candidate and T07-ready model/runtime mirror.
6. Owner acceptance of the replacement installation.

Passing stages 1 through 3 does not qualify real-engine execution. Do not run disruptive fault injection or accept the replacement installation until its reviewed source, bundle, deployment procedure, and APEX evidence have been inspected.

## 8. Qualification status and remaining gates

The statements in this section that described an unprovisioned host were
recorded before the first installation and are not current-state claims. The
owner later reported that installation from source revision
`3bc8041b332f7fcf1e0873ac2cb526625b6456ee` succeeded, that
`/opt/media-generation/venv` and `/var/tmp/media-generation-package` exist, and
that the installed venv permission diagnostics passed, including the
root-owned `lib64 -> lib` link. This task did not inspect APEX live. Section 7
requires a new host-side preflight before any upgrade step; the earlier
statements that no installation changes had occurred or that provisioning was
still blocked must not be used to infer current state.

The last recorded inventory said UID 973 was assigned to `sshd`, while the
proposed model-read GID was 973. Revalidate both keyed account and group
lookups, live service credentials, and effective access during the Section 7
preflight. The proposed runner supplementary GIDs remain 970, 971, 973, and
990. They do not include GID 44, and the unit does not allow `/dev/dri/card1`.

The last reported `passwd` and `group` NSS source lists included `systemd` and
`sss`. This task did not inspect the current file, and no NSS change is proposed.
The broker policy relies on keyed service-account lookups and live kernel
process credentials; it does not claim global group exclusivity. Section 7
rechecks those identities and credentials without requiring global account or
group enumeration. This candidate remains `UNVERIFIED` on APEX until its exact
protected mirror, service identity and access checks, native Linux tests, and
non-disruptive real-engine qualification are complete.

Reference-conditioned inference additionally needs an approved per-attempt
read-only reference handoff. The earlier deployment report recorded the
publication files as mode `0600` and worker-only; verify their current ownership
and access during the Section 7 preflight. APEX must not be marked ready for
edit/reference workloads until the reference handoff gap is closed and tested.
