// vdrd: coredump socket daemon.
//
// Accepts coredump connections from the kernel and stores compressed
// core dumps via the shared vdr-core processing pipeline.
//
// Socket mode: @/run/vdr/coredump.sock (simple mode, no request/ack).
// The @@ request/ack protocol is not implemented.
//
// The listening socket is owned by vdrd.socket (systemd socket
// activation): the service manager creates the socket file at boot
// and hands the listening fd to this daemon on activation. The
// socket therefore exists regardless of this daemon's state — a
// crash is never lost merely because the handler was not running.
// This daemon takes the fd from the service manager; it never binds
// the path itself, which would race the manager for the same file.

#![deny(unsafe_code)]

mod ffi;

use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use signal_hook::consts::{SIGINT, SIGTERM};
use tracing::{error, info, warn};
use vdr_core::{CrashMetadata, StorageConfig, process_core_dump, resolve_exe_path};

const SOCKET_DIR: &str = "/run/vdr";
const SOCKET_PATH: &str = "/run/vdr/coredump.sock";

fn main() -> Result<()> {
    check_kernel_version()?;
    init_logging();

    // Prevent core-dump recursion: if vdrd crashes, do not send
    // our own core back to the coredump socket.
    if let Err(e) = ffi::disable_core_dump() {
        warn!(error = %e, "failed to disable core dump for vdrd; recursion protection may be inactive");
    }

    let signal_pipe = register_signal_pipe()?;

    // Refuse to run without a service-manager-provided fd rather than
    // binding the path: the socket file belongs to vdrd.socket, and a
    // second bind would conflict with the manager.
    let listener = match ffi::systemd_listen_fd()? {
        Some(l) => l,
        None => bail!(
            "no listening socket passed by systemd; start vdrd via vdrd.socket, not standalone"
        ),
    };

    // The socket directory and file are created by the service manager
    // (vdrd.socket DirectoryMode/SocketMode). Verification only;
    // failure means the unit was misconfigured.
    verify_perms(SOCKET_DIR, 0o700, "directory")?;
    verify_perms(SOCKET_PATH, 0o600, "socket")?;

    info!(path = SOCKET_PATH, "vdrd listening");

    run_accept_loop(&listener, &signal_pipe)?;

    info!("shutting down");
    Ok(())
}

fn check_kernel_version() -> Result<()> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("failed to read kernel version")?;

    let mut parts = release.split(|c| c == '.' || c == '-');
    let major: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .context("failed to parse kernel major version")?;
    let minor: u32 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .context("failed to parse kernel minor version")?;

    if major < 6 || (major == 6 && minor < 16) {
        bail!(
            "kernel {} does not support coredump sockets; Linux 6.16+ required",
            release.trim()
        );
    }

    Ok(())
}

fn init_logging() {
    let kmsg = OpenOptions::new()
        .write(true)
        .open("/dev/kmsg")
        .unwrap_or_else(|_| {
            OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .expect("failed to open /dev/null for log fallback")
        });

    tracing_subscriber::fmt()
        .with_writer(Mutex::new(kmsg))
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

/// Create the shutdown channel and register it for SIGTERM/SIGINT.
///
/// The accept loop blocks in poll(2), so shutdown must arrive as a
/// readable descriptor rather than as a flag: nothing re-checks a
/// flag inside a blocked syscall, while a byte on the channel wakes
/// the poll directly. A socketpair keeps the channel anonymous —
/// no filesystem path exists that another process could use to send
/// a spurious shutdown byte.
fn register_signal_pipe() -> Result<UnixStream> {
    let (read_end, write_end) = UnixStream::pair().context("failed to create signal pipe")?;

    // Each registration takes ownership of a clone of the write end
    // and keeps it open until deregistration; the original can drop
    // here without closing the channel.
    signal_hook::low_level::pipe::register(SIGTERM, write_end.try_clone()?)
        .context("failed to register SIGTERM handler")?;
    signal_hook::low_level::pipe::register(SIGINT, write_end.try_clone()?)
        .context("failed to register SIGINT handler")?;

    Ok(read_end)
}

/// Verify that a path is owned by root:root with the expected mode.
///
/// The socket directory and file are created by the service manager
/// (vdrd.socket DirectoryMode/SocketMode); this re-stats them to
/// confirm the filesystem actually honored those settings. It catches:
/// - filesystems that silently ignore mode changes (some FUSE mounts)
/// - unit regressions if DirectoryMode/SocketMode is loosened
///
/// Not a substitute for credential-based verification: a path-based
/// stat follows symlinks, so this is sound only when the parent
/// directory is 0700 root:root.
fn verify_perms(path: &str, expected: u32, kind: &str) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("failed to stat {} {}", kind, path))?;
    let mode = meta.mode() & 0o777;
    let uid = meta.uid();
    let gid = meta.gid();
    if mode != expected || uid != 0 || gid != 0 {
        bail!(
            "{} {} has mode {:o}, owner {}:{}, expected {:o} root:root",
            kind,
            path,
            mode,
            uid,
            gid,
            expected
        );
    }
    Ok(())
}

/// Accept loop: block until the listener or the shutdown channel is
/// ready. No timer, so zero wakeups while idle and no latency floor
/// for a crashing task — poll(2) returns the moment the kernel
/// completes a connection.
///
/// Returns on SIGTERM/SIGINT, or when the listener fails in a way
/// accept(2) cannot recover from; a dump already in progress is
/// always allowed to finish first.
fn run_accept_loop(listener: &UnixListener, signal_pipe: &UnixStream) -> Result<()> {
    loop {
        // The shutdown channel comes first so a signal delivered during
        // a burst of crashes is examined before any pending connection
        // and cannot be starved by accept traffic.
        let mut fds = [
            ffi::PollFd::readable(signal_pipe.as_raw_fd()),
            ffi::PollFd::readable(listener.as_raw_fd()),
        ];
        ffi::poll(&mut fds)?;

        if fds[0].is_readable() {
            return Ok(());
        }

        if !fds[1].is_readable() {
            continue;
        }

        match listener.accept() {
            Ok((stream, addr)) => handle_connection(stream, addr),
            // Spurious readiness (see the spurious-readiness notes under
            // select(2) BUGS) and a peer that aborted between the wake-up
            // and accept(2) are transient; wait again.
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::ConnectionAborted
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            // A persistent error means the listener itself is broken
            // (for example EBADF after a supervisor mishap). Continuing
            // would spin and flood the journal, so surface the failure
            // and let the service manager restart vdrd — the socket
            // file is owned by vdrd.socket and survives the restart.
            Err(e) => {
                error!(error = %e, "accept failed unrecoverably");
                return Err(e).context("accept failed");
            }
        }
    }
}

fn handle_connection(mut stream: UnixStream, addr: SocketAddr) {
    let pidfd = match ffi::get_peer_pidfd(&stream) {
        Ok(pidfd) => pidfd,
        Err(e) => {
            error!(
                peer = ?addr,
                error = %e,
                "failed to obtain peer pidfd; dropping connection"
            );
            return;
        }
    };

    let info = match ffi::pidfd_get_info(&pidfd) {
        Ok(info) => info,
        Err(e) => {
            error!(
                peer = ?addr,
                error = %e,
                "failed to query pidfd info; dropping connection"
            );
            return;
        }
    };

    if !info.is_coredump() {
        error!(
            peer = ?addr,
            info_mask = info.mask,
            coredump_mask = info.coredump_mask,
            "not a crashing task; dropping connection"
        );
        return;
    }

    if !info.has_creds() {
        warn!(
            peer = ?addr,
            pid = info.pid,
            "crashing task already reaped; credentials unavailable"
        );
    }

    let metadata = CrashMetadata {
        pid: info.pid,
        uid: info.has_creds().then_some(info.ruid),
        gid: info.has_creds().then_some(info.rgid),
        signal: info.coredump_signal,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        hostname: read_hostname(),
        exe_path: resolve_exe_path(info.pid, ""),
        core_limit: 0,
        dumpable: info.dumpable(),
        argv_parse_error: None,
    };

    let storage = StorageConfig::default();

    if let Err(e) = process_core_dump(&mut stream, &metadata, &storage) {
        error!(
            pid = metadata.pid,
            error = ?e,
            "failed to store core dump"
        );
    }
}

/// Read the system hostname from /proc.
///
/// Reads from vdrd's UTS namespace via /proc/sys/kernel/hostname.
/// This may differ from pipe mode's %h, which reads from the
/// crashing task's UTS namespace. For containerized workloads with
/// separate UTS namespaces, the hostname may not match the
/// crashing container's hostname.
///
/// Returns an empty string on failure.
fn read_hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
