// vdrd: coredump socket daemon.
//
// Current state: bind, accept, log. Core dumps are discarded;
// processing is not yet implemented.
//
// Socket mode: @/run/vdr/coredump.sock (simple mode, no request/ack).
// The @@ request/ack protocol is not implemented.

#![deny(unsafe_code)]

mod ffi;

use std::fs::{self, OpenOptions, Permissions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use tracing::{error, info, warn};

const SOCKET_DIR: &str = "/run/vdr";
const SOCKET_PATH: &str = "/run/vdr/coredump.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn main() -> Result<()> {
    check_kernel_version()?;
    init_logging();

    if let Err(e) = ffi::disable_core_dump() {
        warn!(error = %e, "failed to disable core dump for vdrd; recursion protection may be inactive");
    }

    let shutdown = register_signals()?;

    create_socket_dir()?;
    verify_perms(SOCKET_DIR, 0o700, "directory")?;

    let listener = bind_socket()?;
    verify_perms(SOCKET_PATH, 0o600, "socket")?;

    info!(path = SOCKET_PATH, "vdrd listening");

    run_accept_loop(&listener, &shutdown);

    cleanup();
    Ok(())
}

fn check_kernel_version() -> Result<()> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("failed to read kernel version")?;

    let mut parts = release.split('.');
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

fn create_socket_dir() -> Result<()> {
    fs::create_dir_all(SOCKET_DIR)
        .with_context(|| format!("failed to create socket directory {}", SOCKET_DIR))?;
    fs::set_permissions(SOCKET_DIR, Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", SOCKET_DIR))?;
    Ok(())
}

/// Verify that a path is owned by root:root with the expected mode.
///
/// This re-stats after `create_socket_dir` / `bind_socket` to confirm
/// the filesystem actually honored `set_permissions`. It catches:
/// - filesystems that silently ignore mode changes (some FUSE mounts)
/// - future regressions if umask or set_permissions is removed
/// - externally-provided sockets when socket activation is added
///
/// Not a substitute for R13 L2-L4: a path-based stat follows symlinks,
/// so this is sound only when the parent directory is 0700 root:root.
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

fn bind_socket() -> Result<UnixListener> {
    let _ = fs::remove_file(SOCKET_PATH);

    let _umask_guard = ffi::UmaskGuard::new(0o177);

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("failed to bind socket {}", SOCKET_PATH))?;

    listener
        .set_nonblocking(true)
        .context("failed to set socket non-blocking")?;
    fs::set_permissions(SOCKET_PATH, Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", SOCKET_PATH))?;
    Ok(listener)
}

fn run_accept_loop(listener: &UnixListener, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, addr)) => {
                match ffi::get_peer_pidfd(&stream) {
                    Ok(pidfd) => {
                        info!(
                            peer = ?addr,
                            pidfd = pidfd.as_raw_fd(),
                              "connection received (pidfd obtained; core discarded)"
                        );
                    }
                    Err(e) => {
                        error!(
                            peer = ?addr,
                            error = %e,
                            "failed to obtain peer pidfd; dropping connection"
                        );
                    }
                }
                // stream and pidfd (if any) dropped at end of arm.
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

fn cleanup() {
    info!("shutting down");
    let _ = fs::remove_file(SOCKET_PATH);
}
