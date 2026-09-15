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

use crate::ffi::PollFd;

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
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

    // A hard kill (SIGKILL after TimeoutStopSec, or an OOM kill)
    // leaves half-written temp files behind. No dump can be in
    // progress yet at this point, so every temp file in the storage
    // directory is an orphan from a previous run.
    match vdr_core::cleanup_stale_temp_files(&StorageConfig::default()) {
        Ok(0) => {}
        Ok(n) => info!(count = n, "removed stale temp files from previous run"),
        Err(e) => warn!(error = ?e, "failed to scan storage directory for stale temp files"),
    }

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
/// time; further connections queue in the kernel's listen backlog. The
/// one exception is wake-pipe clone failure: that connection is handled
/// inline on the accept thread, so an accepted dump is never dropped at
/// the cost of delaying further accepts and shutdown.
///
/// Every exit — shutdown, a fatal accept error, or an error condition
/// on a watched descriptor — goes through the same drain that joins
/// every worker, so in-flight dumps finish on all of them, and a
/// panicked worker or inline handler is logged rather than propagated
/// as a scope panic.
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

            let mut fds = [
                PollFd::readable(signal_pipe.as_raw_fd()),
                PollFd::readable(wake_read.as_raw_fd()),
                PollFd::readable(listener.as_raw_fd()),
            ];
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

            // POLLERR / POLLHUP / POLLNVAL are level-triggered: poll(2)
            // returns immediately on every call while the condition
            // persists, and is_readable() alone ignores them. Without
            // this check a persistent error on any watched descriptor
            // becomes a silent busy spin. Every descriptor here is
            // expected to live as long as the loop, so an error
            // condition is fatal rather than something to wait out.
            // fds[2] was not watched while at capacity, but its
            // revents is zero-initialized each iteration, so checking
            // it unconditionally is safe.
            if let Some((source, _)) = [
                ("signal pipe", fds[0].has_error()),
                ("worker wake pipe", fds[1].has_error()),
                ("listener socket", fds[2].has_error()),
            ]
            .into_iter()
            .find(|(_, e)| *e)
            {
                fatal = Some(std::io::Error::other(format!(
                    "poll reported an error condition on the {source}"
                )));
                break;
            }

            if fds[1].is_readable() {
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
                        let wake = match wake_write.try_clone() {
                            Ok(wake) => wake,
                            Err(e) => {
                                // The wake-pipe clone exists only so a
                                // worker thread can signal completion;
                                // this connection can still be served on
                                // the accept thread, and the stream has
                                // not been moved yet. Losing an
                                // already-accepted dump is the worst
                                // outcome for a recorder, so degrade to
                                // serial handling instead of dropping
                                // it. Blocking here delays further
                                // accepts and shutdown, same as the
                                // pre-worker design.
                                warn!(
                                error = %e,
                                "failed to clone worker wake pipe; handling connection inline"
                                );
                                active.fetch_add(1, Ordering::Release);
                                // This call runs on the accept thread, not inside a worker:
                                // an uncontained panic would unwind out of the scope closure
                                // and re-panic after the worker drain, taking the daemon down.
                                // catch_unwind gives the inline path the same containment the
                                // join in the drain gives workers. AssertUnwindSafe matches
                                // what std::thread already guarantees (nothing): the closure
                                // owns its inputs outright, and the slot counter is only
                                // touched outside it.
                                let outcome = catch_unwind(AssertUnwindSafe(move || {
                                handle_connection(stream, addr);
                                }));
                                active.fetch_sub(1, Ordering::Release);
                                if outcome.is_err() {
                                error!("inline dump panicked");
                                }
                                continue;
                                }
                            }
                        };
                        active.fetch_add(1, Ordering::Release);
                        match thread::Builder::new()
                            .name("vdrd-dump".to_string())
                            .spawn_scoped(scope, move || {
                                let _slot = SlotGuard {
                                    active: slots,
                                    wake,
                                };
                                handle_connection(stream, addr);
                            }) {
                            Ok(handle) => workers.push(handle),
                            Err(e) => {
                                // spawn_scoped consumed the closure, so
                                // the connection is unrecoverable here:
                                // the socket closes and the kernel-side
                                // writer gives up. Only reachable under
                                // thread-resource exhaustion (ENOMEM or
                                // pids.max).
                                error!(error = %e, "dump worker spawn failed; connection dropped");
                                active.fetch_sub(1, Ordering::Release);
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == ErrorKind::WouldBlock
                            || e.kind() == ErrorKind::ConnectionAborted
                            || e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => {
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
