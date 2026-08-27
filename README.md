# vdr

**vdr** stands for *Voyage Data Recorder* — the maritime equivalent of a
flight data recorder. Ships record what happens during a voyage; vdr records
what happens when a process crashes.

A modern, secure Linux core dump handler in Rust. Supports both pipe and
socket modes.

## Development

This project was developed with AI assistance. The security claims below
are written so that they can be verified independently of how the code
was produced.

## Where's the Security?

vdr runs as root, invoked by the kernel to capture core dumps — memory
snapshots that may contain `/etc/shadow` hashes, API keys, private keys,
and other credentials from crashed processes.

### Who are we protecting against?

The primary attacker is a **local unprivileged user** who can:

- Crash arbitrary programs, including SUID binaries
- Control `argv[0]` and environment variables
- Fork processes and manipulate PID namespaces
- Trigger crashes in remote daemons (nginx, postgres workers), effectively
  gaining the same capability through crashed processes

The crashing process's memory image and `/proc/pid/*` snapshot are treated
as potentially malicious input.

### How vdr defends

**Access control**

- **No ACL attack surface** — Core files are 0600 root-only via
  `O_CREAT|O_EXCL`. No `setfacl`, no `libacl`. The `fs.suid_dumpable=2`
  sysctl drop-in ships with vdrd to enable SUID/SGID core dumps; this
  is safe because 0600 root-only access control eliminates the
  CVE-2022-4415 class entirely (the CVE's mechanism was an ACL entry
  granting read access to the real UID — impossible without ACL code,
  and the 0600 root-only default covers other leak paths too).

**Hot path safety**

- **No DWARF in the hot path** — vdr never parses DWARF in the recording
  path. A separate cold-path analysis tool (`vdr-analyze`) is planned but
  not yet implemented. gimli's maintainer explicitly states it is not a
  security boundary [gimli PR #889](https://github.com/gimli-rs/gimli/pull/889);
  libdwarf's design goal includes handling corrupted input
  ([libdwarf README](https://github.com/davea42/libdwarf-code/blob/main/README.md)),
  but its own vulnerability database lists 239 entries as of July 2026
  ([dwarfbug.html](https://www.prevanders.net/dwarfbug.html), latest:
  DW202605-008). Neither should be relied upon as a security boundary
  in the recording path.

- **Streaming, bounded memory** — Core data streams through `io::copy`
  into a zstd encoder to disk, never fully loaded into RAM. Per-core
  limit: 2 GB. Executable size limit for build ID extraction: 64 MB.
  The systemd unit enforces `MemoryMax=256M`, `TasksMax=4`, and a
  `@system-service` syscall filter.

**Credential integrity (pipe mode)**

- **Race condition protection** — vdr trusts the kernel's `%d` dumpable
  flag, not `/proc/pid/auxv`. A handler that reads auxv is vulnerable
  (CVE-2025-4598): an attacker can SIGKILL the crashing SUID process,
  wait for PID recycling, then fork a new non-SUID process to occupy the
  same PID — causing the handler to read the new process's auxv and
  misclassify the core dump as non-sensitive. vdr avoids this by not
  reading auxv.

**Credential integrity (socket mode, Linux ≥ 6.16)**

- **Kernel-tracked sensitivity** — The kernel's judgment of whether a
  core dump is sensitive (`PIDFD_COREDUMP_ROOT`, set for SUID/SGID/
  privileged processes) is stored in kernel data structures tied to the
  process ID, not the process's memory. It remains readable even after
  the crashing process is cleaned up. Individual credentials (UID/GID)
  from `pidfd_info` are time-sensitive: they require the crashing
  process to remain alive. `core_pipe_limit > 0` makes the kernel
  block until vdrd closes the connection, keeping the crashing process
  alive during credential retrieval.

- **Recursion prevention** — vdrd marks itself
  `prctl(PR_SET_DUMPABLE, 0)` to prevent recursive core dumps.

**Socket authentication (socket mode)**

Four layers, all implemented:

- **L1** — Socket file permissions (0600 root:root), verified at startup
- **L2** — `PIDFD_COREDUMPED` kernel flag (see note below)
- **L3** — `SO_PEERPIDFD` (kernel-provided process reference, no race)
- **L4** — `pidfd_info` credentials + `PIDFD_COREDUMP_ROOT`

> **On L2**: `PIDFD_COREDUMPED` is set only by the kernel when a process
> crashes. No userspace API currently exists to set it directly, so a
> non-crashing process cannot fake this flag. However, this guarantee
> holds only because no such API exists today — it is not a structural
> impossibility. If a future kernel exposes a way to set the flag from
> userspace, L2 would weaken. The other layers (L1, L3, L4) would still
> apply, but L2 alone would no longer be sufficient.

**Journal hygiene**

- **Minimal metadata** — `cmdline` logging is currently not implemented.
  Environment variables and stack contents are not read. If `cmdline`
  logging is added in the future, it will use a whitelist-based scrub
  (only known-safe fields such as `argv[0]` basename and known valueless
  flags; everything else redacted). Operational fields currently logged:
  path, sizes, build ID, exe (truncated), comm, signal, hostname, pid,
  uid, gid, dumpable, core_limit.

**Filesystem**

- **Symlink hardening** — Storage directory is root-only 0700.
  `O_CREAT|O_EXCL` rejects symbolic links on the final path component.

## Socket Mode Limitations

Socket mode (Linux ≥ 6.16) currently supports only the `@` (simple)
coredump socket protocol. The `@@` (request/ack handshake) protocol is
not yet implemented.

## License

vdr is licensed under the GNU General Public License version 2 only
([GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)).

SPDX-License-Identifier: GPL-2.0-only
