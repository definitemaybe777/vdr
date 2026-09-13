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
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use signal_hook::consts::{SIGINT, SIGTERM};
use tracing::{error, info, warn};
use vdr_core::{CrashMetadata, StorageConfig, process_core_dump, resolve_exe_path};

const SOCKET_DIR: &str = "/run/vdr";
const SOCKET_PATH: &str = "/run/vdr/coredump.sock";

/// Upper bound on dumps processed concurrently. Connections beyond this
/// count stay queued in the kernel's listen backlog and are accepted as
/// slots free. The cap bounds concurrent zstd contexts and streaming
/// buffers within the MemoryMax budget and turns a crash storm into
/// bounded queueing rather than unbounded load.
const MAX_CONCURRENT_DUMPS: usize = 4;

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

/// Accept loop: block until the listener, the shutdown channel, or a
/// worker-completion notification is ready. Each accepted connection is
/// handled on its own scoped thread, at most MAX_CONCURRENT_DUMPS at a
/// time; further connections queue in the kernel's listen backlog.
///
/// All exits go through a single drain that joins every worker, so
/// shutdown and fatal listener errors both let in-flight dumps finish,
/// and a panicked worker is logged rather than propagated as a scope
/// panic.
fn run_accept_loop(listener: &UnixListener, signal_pipe: &UnixStream) -> Result<()> {
    let active = AtomicUsize::new(0);
    // A move closure captures referenced variables by value, which
    // would move the counter itself into the first spawned worker;
    // sharing it as a reference lets every worker account against
    // the same slot counter.
    let slots = &active;
    let (mut wake_read, wake_write) =
        UnixStream::pair().context("failed to create completion pipe")?;
    wake_read
        .set_nonblocking(true)
        .context("failed to set completion pipe non-blocking")?;

    thread::scope(|scope| {
        let mut workers = Vec::new();
        let mut fatal = None;

        loop {
            let at_capacity = active.load(Ordering::Acquire) >= MAX_CONCURRENT_DUMPS;

            // Shutdown first so a signal during a crash burst is examined
            // before any pending connection and cannot be starved by
            // accept traffic.
            let mut fds = [
                ffi::PollFd::readable(signal_pipe.as_raw_fd()),
                ffi::PollFd::readable(wake_read.as_raw_fd()),
                ffi::PollFd::readable(listener.as_raw_fd()),
            ];
            // At capacity the listener is left out of the wait: a queued
            // connection would only busy-spin a loop that cannot accept
            // it. The kernel holds queued connections in the listen
            // backlog until a completion re-admits the listener.
            let watched = if at_capacity {
                &mut fds[..2]
            } else {
                &mut fds[..3]
            };
            if let Err(e) = ffi::poll(watched) {
                fatal = Some(e);
                break;
            }

            if fds[0].is_readable() {
                break;
            }

            if fds[1].is_readable() {
                // Drain completion notifications so stale bytes cannot keep
                // waking the loop. Content is irrelevant — a byte only
                // means "re-evaluate capacity".
                let mut buf = [0u8; 32];
                loop {
                    match wake_read.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => continue,
                    }
                }
            }

            if !at_capacity && fds[2].is_readable() {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        // Counted before the spawn: the worker can finish
                        // (and release the slot through its guard) before
                        // this thread reaches the match below, so the slot
                        // must be accounted for before the thread exists.
                        active.fetch_add(1, Ordering::Release);
                        let spawned = wake_write.try_clone().and_then(|wake| {
                            thread::Builder::new()
                                .name("vdrd-dump".to_string())
                                .spawn_scoped(scope, move || {
                                    let _slot = SlotGuard {
                                        active: slots,
                                        wake,
                                    };
                                    handle_connection(stream, addr);
                                })
                        });
                        match spawned {
                            Ok(handle) => workers.push(handle),
                            // Thread creation failed (memory or thread
                            // limits). The failed spawn consumed the
                            // connection when its closure was dropped, so
                            // the kernel-side writer sees the socket close
                            // and this crash goes unrecorded. Ownership
                            // rules leave no way to hand the connection
                            // back for inline handling; log the loss and
                            // release the slot.
                            Err(e) => {
                                error!(error = %e, "dump worker spawn failed; connection dropped");
                                active.fetch_sub(1, Ordering::Release);
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::ConnectionAborted
                            || e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        error!(error = %e, "accept failed unrecoverably");
                        fatal = Some(e);
                        break;
                    }
                }
            }
        }

        // Single exit path: joining (instead of dropping) the handles
        // keeps a panicked worker from re-panicking the scope after the
        // join. The default panic hook already printed the message; this
        // only records its origin.
        for handle in workers.drain(..) {
            if handle.join().is_err() {
                error!("dump worker panicked");
            }
        }

        match fatal {
            Some(e) => Err(e).context("accept loop failed"),
            None => Ok(()),
        }
    })
}

/// Releases a dump slot and notifies the accept loop on drop.
struct SlotGuard<'a> {
    active: &'a AtomicUsize,
    wake: UnixStream,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        // Runs on normal return and unwind alike: a panicking worker must
        // still free its slot and wake the accept loop, so a bug in one
        // dump cannot wedge the daemon at capacity.
        self.active.fetch_sub(1, Ordering::Release);
        // At most MAX_CONCURRENT_DUMPS bytes can be queued between drains,
        // orders of magnitude below the socket's send buffer, so this
        // write cannot fail for lack of space.
        let _ = self.wake.write(&[1]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_guard_releases_slot_on_panic() {
        let active = AtomicUsize::new(1);
        let (mut wake_read, wake_write) = UnixStream::pair().unwrap();
        wake_read.set_nonblocking(true).unwrap();

        thread::scope(|scope| {
            // Same pattern as the accept loop: share the counter as a
            // reference instead of letting the move closure take it.
            let slots = &active;
            let spawned = thread::Builder::new()
                .spawn_scoped(scope, move || {
                    let _slot = SlotGuard {
                        active: slots,
                        wake: wake_write,
                    };
                    panic!("simulated dump-worker bug");
                })
                .unwrap();
            assert!(spawned.join().is_err());
        });

        assert_eq!(active.load(Ordering::Acquire), 0);
        // The guard's wake byte must be readable even after the unwind.
        let mut buf = [0u8; 1];
        assert!(wake_read.read(&mut buf).is_ok_and(|n| n > 0));
    }
}
