// FFI wrappers for kernel syscalls not covered by std.
// All unsafe is confined to this module.
// main.rs keeps #![deny(unsafe_code)].

#![allow(unsafe_code)]

use std::io;

/// Disable core dump generation for the current process.
///
/// In pipe mode, the kernel sets RLIMIT_CORE to 1 as a recursion
/// sentinel: if the pipe handler crashes, the kernel sees the
/// sentinel and aborts the core dump. This prctl call is
/// defense-in-depth — it stops the kernel from entering the coredump
/// path entirely, whereas the sentinel is checked only after the
/// pipe path is chosen. It also prevents ptrace attachment to a
/// root process that is handling SUID core dumps.
pub fn disable_core_dump() -> io::Result<()> {
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
