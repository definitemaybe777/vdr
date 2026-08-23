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

/// Set the process file-creation mask and return the previous value.
///
/// umask is process-global; callers must ensure single-threaded
/// execution during the masked window.
pub fn set_umask(mask: u32) -> u32 {
    unsafe { libc::umask(mask) }
}
