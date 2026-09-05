// FFI wrappers for kernel syscalls not covered by std.
// All unsafe is confined to this module.
// main.rs keeps #![deny(unsafe_code)].

#![allow(unsafe_code)]

use std::env;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

// Request flags for pidfd_info.mask (input to PIDFD_GET_INFO).
//
// PIDFD_INFO_EXIT comes from libc to avoid transcription errors.
// PIDFD_INFO_COREDUMP is not yet in libc (added in kernel 6.16).
const PIDFD_INFO_EXIT: u64 = libc::PIDFD_INFO_EXIT as u64;
const PIDFD_INFO_COREDUMP: u64 = 1 << 4;

// Response flags in pidfd_info.mask (output).
// PIDFD_INFO_CREDS is "Always returned, even if not requested" when
// the task is alive — no need to set it in the request mask. Its
// presence indicates the task was still alive and credentials are
// populated. Absence means the task was reaped and credentials are gone.
const PIDFD_INFO_CREDS: u64 = libc::PIDFD_INFO_CREDS as u64;

// Flags in pidfd_info.coredump_mask (output).
// Not yet in libc (added in kernel 6.16).
const PIDFD_COREDUMPED: u32 = 1 << 0;
const PIDFD_COREDUMP_USER: u32 = 1 << 2;
const PIDFD_COREDUMP_ROOT: u32 = 1 << 3;

/// Subset of the kernel's `struct pidfd_info` (include/uapi/linux/pidfd.h).
///
/// Includes all fields through `coredump_signal` (72 bytes, matching
/// PIDFD_INFO_SIZE_VER1). Fields beyond this (coredump_code, coredump_pad,
/// supported_mask) are omitted; they can be added when needed.
///
/// libc's `pidfd_info` stops at `exit_code` (64 bytes) and lacks coredump
/// fields, so a custom struct and ioctl number are necessary.
#[repr(C)]
#[derive(Default)]
pub struct PidfdInfo {
    pub mask: u64,
    pub cgroupid: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub exit_code: i32,
    pub coredump_mask: u32,
    pub coredump_signal: u32,
}

const _: () = assert!(std::mem::size_of::<PidfdInfo>() == 72);

impl PidfdInfo {
    /// Returns true if this pidfd belongs to a task that triggered a
    /// core dump.
    ///
    /// Two conditions must hold:
    /// - The kernel filled coredump information (struct was large enough
    ///   and the task has coredump attributes).
    /// - The PIDFD_COREDUMPED flag is set in coredump_mask.
    ///
    /// A connection that fails this check is not from a crashing task
    /// and should be rejected.
    pub fn is_coredump(&self) -> bool {
        (self.mask & PIDFD_INFO_COREDUMP) != 0 && (self.coredump_mask & PIDFD_COREDUMPED) != 0
    }

    /// Returns true if credentials are available in this response.
    ///
    /// Credentials are unconditionally populated by the kernel when
    /// the task is still alive. For a reaped task, the kernel takes a
    /// shortcut path that skips credential population, so this bit is
    /// absent — credentials are gone with the task_struct.
    pub fn has_creds(&self) -> bool {
        (self.mask & PIDFD_INFO_CREDS) != 0
    }

    /// Map kernel coredump flags to the dumpable value used by pipe
    /// mode for log compatibility.
    ///
    /// ROOT takes priority over USER: a root-level dump is always
    /// sensitive regardless of whether USER is also set. When neither
    /// flag is set, returns 0.
    pub fn dumpable(&self) -> u32 {
        if (self.coredump_mask & PIDFD_COREDUMP_ROOT) != 0 {
            2
        } else if (self.coredump_mask & PIDFD_COREDUMP_USER) != 0 {
            1
        } else {
            0
        }
    }
}

// PIDFD_GET_INFO = _IOWR(PIDFS_IOCTL_MAGIC, 11, struct pidfd_info)
//
// The ioctl number encodes the struct size. libc's PIDFD_GET_INFO uses
// the 64-byte struct and won't fill coredump fields. This const uses
// our 72-byte PidfdInfo so the kernel fills through coredump_signal.
//
// Formula: (dir << 30) | (size << 16) | (type << 8) | nr
// dir = 3 (_IOC_READ | _IOC_WRITE)
// type = 0xFF (PIDFS_IOCTL_MAGIC)
// nr = 11
// size = sizeof(PidfdInfo) = 72
//
// Expected value: 0xC048FF0B
const PIDFD_GET_INFO: libc::c_ulong = {
    let struct_size = std::mem::size_of::<PidfdInfo>() as libc::c_ulong;
    let dir: libc::c_ulong = 3;
    let magic: libc::c_ulong = 0xFF;
    let nr: libc::c_ulong = 11;
    (dir << 30) | (struct_size << 16) | (magic << 8) | nr
};

/// Disable core dump generation for the current process.
///
/// The kernel leaves core-dump recursion protection to userspace
/// (fs/coredump.c: "Userspace should just mark itself non dumpable").
/// If vdrd itself crashes while in socket mode, the kernel would
/// try to send vdrd's own core back to the coredump socket —
/// which is vdrd's own accept socket, creating a recursion.
pub fn disable_core_dump() -> io::Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// First fd number the socket-activation protocol passes
// (sd_listen_fds(3): SD_LISTEN_FDS_START).
const SD_LISTEN_FDS_START: libc::c_int = 3;

/// Take the listening socket the service manager passed via socket
/// activation.
///
/// Implements the sd_listen_fds(3) protocol by hand, so the daemon
/// carries no sd-daemon dependency. The LISTEN_* variables are plain
/// environment and are inherited by any child of the service manager,
/// so they are a trust boundary: every claim is validated against
/// this process before fd 3 is treated as ours.
///
/// Returns Ok(None) when no socket was handed to this process. The
/// caller must refuse to run in that case; binding the path directly
/// would race the service manager, which owns the socket file.
pub fn systemd_listen_fd() -> io::Result<Option<UnixListener>> {
    // $LISTEN_PID must name this process. Absent, unparsable, or stale
    // values (set for an earlier process and inherited through an
    // intermediary) mean fd 3 was not prepared for us.
    let declared_pid: u32 = match env::var("LISTEN_PID").ok().and_then(|v| v.parse().ok()) {
        Some(pid) => pid,
        None => return Ok(None),
    };
    if declared_pid != std::process::id() {
        return Ok(None);
    }

    // This deployment passes exactly one listener.
    if env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<libc::c_int>().ok())
        != Some(1)
    {
        return Ok(None);
    }

    // SAFETY: the checks above established that fd 3 was allocated for
    // this process. Taking it into OwnedFd makes Rust close it on drop,
    // including the early-return paths below.
    let fd = unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) };

    // Reject anything but a stream socket. A datagram listener would
    // pass activation and then fail confusingly on accept(2); the
    // service manager passes the same socket again on every restart,
    // so a unit edited to the wrong Listen* type would otherwise only
    // surface as accept errors, not as a clear startup failure.
    if !is_stream_socket(&fd)? {
        return Ok(None);
    }

    // sd_listen_fds(3) sets FD_CLOEXEC on every fd it hands out; doing
    // the same here keeps identical semantics. The fd must not survive
    // into an exec'd child together with the (now unset) LISTEN_*
    // variables.
    set_cloexec(&fd)?;

    // Unset the full marker set, matching sd_listen_fds(unset_environment).
    // LISTEN_PIDFDID is unset but not compared: matching it against
    // this process' pidfd inode guards against PID recycling when the
    // environment was inherited through an intermediary. Socket
    // activation spawns vdrd directly, so the recycling window does
    // not apply; the comparison is a follow-up if vdrd ever supports
    // being re-spawned by something other than the service manager.
    unset_env(&[
        b"LISTEN_PID\0",
        b"LISTEN_FDS\0",
        b"LISTEN_PIDFDID\0",
        b"LISTEN_FDNAMES\0",
    ]);

    // From<OwnedFd> for UnixListener (stable since 1.63); ownership
    // moves into the listener, which closes the fd on drop.
    Ok(Some(fd.into()))
}

fn is_stream_socket(fd: &OwnedFd) -> io::Result<bool> {
    let mut ty: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&ty) as libc::socklen_t;
    // SAFETY: getsockopt with a correctly sized, writable buffer.
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut ty as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ty == libc::SOCK_STREAM)
}

fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl(F_SETFD) only touches descriptor flags of a valid fd.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unset_env(names: &[&[u8]]) {
    for name in names {
        // SAFETY: each slice is a NUL-terminated string literal.
        unsafe { libc::unsetenv(name.as_ptr().cast()) };
    }
}

/// Obtain a kernel-pinned pidfd for the peer of an accepted connection.
///
/// Uses SO_PEERPIDFD (Linux 6.5+, coredump socket 6.16+) to get a
/// stable fd reference to the crashing task. The pidfd is pinned by
/// the kernel at connect time, not derived from /proc or command-line
/// arguments, so it cannot be spoofed or replaced after the fact.
///
/// On Linux 6.16+, the pidfs entry is stashed at connect time, so the
/// pidfd remains valid even if the crashing task has exited and been
/// reaped before this call. On 6.5-6.15, EINVAL is returned for reaped
/// peers entirely; no pidfd is obtained.
///
/// Note: while the pidfd itself is stable, credentials are only
/// available while the task_struct exists. A reaped task's credentials
/// are gone — the pidfd is valid but credential queries return no data.
/// Callers that need credentials must handle the missing case.
pub fn get_peer_pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut pidfd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            &mut pidfd as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    if len != std::mem::size_of::<libc::c_int>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "SO_PEERPIDFD returned truncated length",
        ));
    }

    // OwnedFd::from_raw_fd panics on -1; guard against the kernel
    // returning an invalid fd despite reporting success.
    if pidfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERPIDFD returned negative pidfd",
        ));
    }

    // The kernel allocates a new fd and transfers ownership to us.
    // OwnedFd closes it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// Query pidfd information via PIDFD_GET_INFO ioctl.
///
/// Requests exit and coredump info. Exit info is requested to avoid
/// ESRCH when the crashing task has already been reaped; coredump
/// info is the actual target. Credentials are always returned when
/// the task is alive and do not need to be requested.
///
/// The caller should check `is_coredump()` to verify the connection
/// is from a crashing task, and `has_creds()` to determine whether
/// credentials are available. `dumpable()` maps kernel sensitivity
/// flags to the value used by pipe mode for log compatibility.
pub fn pidfd_get_info(pidfd: &OwnedFd) -> io::Result<PidfdInfo> {
    let mut info = PidfdInfo {
        mask: PIDFD_INFO_EXIT | PIDFD_INFO_COREDUMP,
        ..Default::default()
    };

    let ret = unsafe {
        libc::ioctl(
            pidfd.as_raw_fd(),
            PIDFD_GET_INFO,
            &mut info as *mut _ as *mut libc::c_void,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(info)
}
