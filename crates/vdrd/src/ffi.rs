// FFI wrappers for kernel syscalls not covered by std.
// All unsafe is confined to this module.
// main.rs keeps #![deny(unsafe_code)].

#![allow(unsafe_code)]

use std::io;

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
