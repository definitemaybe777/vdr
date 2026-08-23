// FFI wrappers for kernel syscalls not covered by std.
// All unsafe is confined to this module.
// main.rs keeps #![deny(unsafe_code)].

#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

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

/// RAII guard for the process file-creation mask.
///
/// umask is process-global; the guard restores the previous value
/// on drop, including on early return via `?` or panic.
pub struct UmaskGuard {
    prev: u32,
}

impl UmaskGuard {
    pub fn new(mask: u32) -> Self {
        let prev = unsafe { libc::umask(mask) };
        Self { prev }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe { libc::umask(self.prev) };
    }
}

/// Obtain a kernel-pinned pidfd for the peer of an accepted connection.
///
/// Uses SO_PEERPIDFD (Linux 6.5+, coredump socket 6.16+) to get a
/// stable fd reference to the crashing task. The pidfd remains valid
/// even if the task is SIGKILLed during coredump generation — there
/// is no race window between reading the pid and using it.
///
/// The pidfd is pinned by the kernel at accept time, not derived from
/// /proc or command-line arguments, so it cannot be spoofed by the
/// crashing task or replaced after the fact.
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
