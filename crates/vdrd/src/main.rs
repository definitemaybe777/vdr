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

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
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
/// worker-completion notification is ready. Dump workers are spawned
/// once at startup, so handing off an accepted connection allocates
/// nothing — no thread creation, no wake-pipe duplication — and an
/// accepted dump can no longer be lost to resource exhaustion at the
/// memory peak of a crash storm. At most MAX_CONCURRENT_DUMPS dumps
/// run at a time; further connections queue in the kernel's listen
/// backlog.
///
/// Every exit — shutdown, a fatal accept error, or an error condition
/// on a watched descriptor — goes through the same drain: queued jobs
/// are processed, every worker is joined, and a panicked worker is
/// logged rather than propagated as a scope panic.
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

    // std's mpsc Receiver is !Sync (single consumer), so a shared
    // channel cannot feed multiple workers; a Mutex+Condvar queue is
    // the std-only multi-consumer handoff.
    //
    // Declared outside the scope closure: workers borrow these until
    // the scope joins them, which happens after the closure body
    // returns. Locals of the closure body would not live long
    // enough (E0597).
    let queue = Mutex::new(VecDeque::<(UnixStream, SocketAddr)>::new());
    let job_ready = Condvar::new();
    let closing = AtomicBool::new(false);

    thread::scope(|scope| {
        let queue_ref = &queue;
        let ready_ref = &job_ready;
        let closing_ref = &closing;

        // Workers are spawned once, before any crash: thread creation
        // and wake-pipe cloning happen at startup, where failure is a
        // visible start failure handled by the service manager,
        // instead of at the memory peak of a crash storm, where
        // failure loses an accepted dump.
        let mut workers = Vec::with_capacity(MAX_CONCURRENT_DUMPS);
        let mut fatal = None;
        for _ in 0..MAX_CONCURRENT_DUMPS {
            let wake = match wake_write.try_clone() {
                Ok(wake) => wake,
                Err(e) => {
                    fatal = Some(e);
                    break;
                }
            };
            match thread::Builder::new()
                .name("vdrd-dump".to_string())
                .spawn_scoped(scope, move || {
                    worker_loop(queue_ref, ready_ref, closing_ref, slots, &wake);
                }) {
                Ok(handle) => workers.push(handle),
                Err(e) => {
                    fatal = Some(e);
                    break;
                }
            }
        }

        while fatal.is_none() {
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
                        // Handoff allocates nothing: the worker
                        // already exists with its stack mapped and
                        // its wake-pipe clone held, so an accepted
                        // dump cannot be lost to resource
                        // exhaustion mid-handoff.
                        slots.fetch_add(1, Ordering::Release);
                        queue.lock().unwrap().push_back((stream, addr));
                        job_ready.notify_one();
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

        // Retire idle workers: they observe `closing` on their next
        // queue check. A worker mid-dump is unaffected — it finishes,
        // drops its slot guard, and only then sees `closing`; jobs
        // already queued were accepted from the kernel and are still
        // processed during this drain.
        //
        // The store happens under the queue mutex so it cannot slip
        // between a worker's `closing` check and its `Condvar::wait`
        // snapshot: landing in that window is exactly how a notify
        // gets absorbed into the counter value the worker then
        // sleeps on, losing the wakeup.
        {
            let _q = queue_ref.lock().unwrap();
            closing_ref.store(true, Ordering::Release);
        }
        ready_ref.notify_all();

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
    wake: &'a UnixStream,
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

/// Pool worker body: block on the job queue, run one dump per
/// iteration.
///
/// Queue is checked before `closing`: a job already handed off was
/// accepted from the kernel, so queued jobs are still processed
/// during shutdown drain. A panicked worker would be a permanent
/// capacity loss in a fixed pool, so panics are absorbed here
/// instead of ending the thread.
fn worker_loop(
    queue: &Mutex<VecDeque<(UnixStream, SocketAddr)>>,
    job_ready: &Condvar,
    closing: &AtomicBool,
    slots: &AtomicUsize,
    wake: &UnixStream,
) {
    loop {
        let (stream, addr) = {
            let mut q = queue.lock().unwrap();
            loop {
                match q.pop_front() {
                    Some(job) => break job,
                    // Spurious wakeups re-run this check; wait()
                    // releases the lock while blocked so the accept
                    // thread can push. The critical section is
                    // panic-free (pop/check only), so lock
                    // poisoning is unreachable.
                    None if closing.load(Ordering::Acquire) => return,
                    None => q = job_ready.wait(q).unwrap(),
                }
            }
        };
        let _slot = SlotGuard {
            active: slots,
            wake,
        };
        if catch_unwind(AssertUnwindSafe(move || {
            handle_connection(stream, addr);
        }))
        .is_err()
        {
            error!("dump worker panicked");
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
                        wake: &wake_write,
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
