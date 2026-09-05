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
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use tracing::{error, info, warn};
use vdr_core::{CrashMetadata, StorageConfig, process_core_dump, resolve_exe_path};

const SOCKET_DIR: &str = "/run/vdr";
const SOCKET_PATH: &str = "/run/vdr/coredump.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn main() -> Result<()> {
    check_kernel_version()?;
    init_logging();

    // Prevent core-dump recursion: if vdrd crashes, do not send
    // our own core back to the coredump socket.
    if let Err(e) = ffi::disable_core_dump() {
        warn!(error = %e, "failed to disable core dump for vdrd; recursion protection may be inactive");
    }

    let shutdown = register_signals()?;

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

    listener
        .set_nonblocking(true)
        .context("failed to set socket non-blocking")?;

    info!(path = SOCKET_PATH, "vdrd listening");

    run_accept_loop(&listener, &shutdown);

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

fn register_signals() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    flag::register(SIGTERM, shutdown.clone()).context("failed to register SIGTERM handler")?;
    flag::register(SIGINT, shutdown.clone()).context("failed to register SIGINT handler")?;
    Ok(shutdown)
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

fn run_accept_loop(listener: &UnixListener, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, addr)) => {
                handle_connection(stream, addr);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(ref e) => {
                error!(error = %e, "accept failed");
                std::thread::sleep(POLL_INTERVAL);
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
