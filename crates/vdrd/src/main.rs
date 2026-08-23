// vdrd: coredump socket daemon.
// Skeleton: bind, accept, log. Core processing begins in Feature #7.

#![deny(unsafe_code)]

mod ffi;

use std::fs::{self, OpenOptions, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use tracing::{error, info, warn};

const SOCKET_DIR: &str = "/run/vdr";
const SOCKET_PATH: &str = "/run/vdr/coredump.sock";
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn main() -> Result<()> {
    init_logging();

    // Prevent core-dump recursion: if vdrd crashes, do not send
    // our own core back to the coredump socket.
    if let Err(e) = ffi::disable_core_dump() {
        warn!(error = %e, "failed to disable core dump for vdrd; recursion protection may be inactive");
    }

    let shutdown = register_signals()?;

    create_socket_dir()?;
    let listener = bind_socket()?;

    info!(path = SOCKET_PATH, "vdrd listening");

    run_accept_loop(&listener, &shutdown);

    cleanup();
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
    flag::register(SIGTERM, shutdown.clone())
    .context("failed to register SIGTERM handler")?;
    flag::register(SIGINT, shutdown.clone())
    .context("failed to register SIGINT handler")?;
    Ok(shutdown)
}

fn create_socket_dir() -> Result<()> {
    fs::create_dir_all(SOCKET_DIR)
    .with_context(|| format!("failed to create socket directory {}", SOCKET_DIR))?;
    fs::set_permissions(SOCKET_DIR, Permissions::from_mode(0o700))
    .with_context(|| format!("failed to set permissions on {}", SOCKET_DIR))?;
    Ok(())
}

fn bind_socket() -> Result<UnixListener> {
    let _ = fs::remove_file(SOCKET_PATH);

    // umask 0177 makes bind() create the socket file at 0600,
    // eliminating the bind → set_permissions race window.
    // Process-global; vdrd is single-threaded here.
    let old_umask = ffi::set_umask(0o177);

    let listener = UnixListener::bind(SOCKET_PATH)
    .with_context(|| format!("failed to bind socket {}", SOCKET_PATH))?;

    ffi::set_umask(old_umask);

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
            Ok((_stream, addr)) => {
                info!(peer = ?addr, "connection received (skeleton: core discarded)");
                // Stream is dropped at end of arm; no processing in skeleton.
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
