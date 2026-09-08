#![deny(unsafe_code)]

mod ffi;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use vdr_core::{
    CrashMetadata, StorageConfig, process_core_dump, resolve_exe_path, truncate_for_log,
};

/// vdr — Voyage Data Recorder
///
/// A crash dump handler invoked by the kernel via core_pattern.
/// The kernel pipes the core dump to stdin and passes crash
/// metadata as positional arguments.
///
/// Example core_pattern:
///   |/usr/bin/vdr %P %u %g %s %t %h %E %c %d
#[derive(Parser, Debug)]
// The kernel expands core_pattern specifiers into argv, and %h expands
// to the crashing process's UTS hostname — settable by any user inside
// a private user namespace, so argv elements can carry flag-shaped
// strings. clap's built-in help and version flags turn such an element
// into a request to exit before stdin is drained, silently discarding
// the core. Disabling both flags makes those argv values ordinary
// parse errors, which degrade the metadata instead of discarding the
// dump. The version attribute stays for package metadata.
#[command(
    version,
    about = "Voyage Data Recorder — crash dump handler",
    disable_help_flag = true,
    disable_version_flag = true,
)]
struct Args {
    /// %P — PID of the crashed process
    pid: u32,

    /// %u — Real UID of the crashed process
    uid: u32,

    /// %g — Real GID of the crashed process
    gid: u32,

    /// %s — Signal number that caused the crash
    signal: u32,

    /// %t — Unix timestamp of the crash
    timestamp: u64,

    // A process crashing inside its own UTS namespace can have a
    // non-UTF-8 hostname; clap's String parsing rejects such argv
    // with a hard exit, abandoning the core on fd 0 before it is
    // stored. Raw bytes are kept here; the lossy display conversion
    // happens when CrashMetadata is built.
    /// %h — Hostname
    hostname: OsString,

    // Paths may contain non-UTF-8 bytes (argv is arbitrary bytes from
    // execve); PathBuf keeps them, and the lossy display conversion
    // happens when CrashMetadata is built — consistent with the
    // to_string_lossy already applied to /proc/<pid>/exe in
    // resolve_exe_path().
    /// %E — Path of the executable (slashes replaced with '!' by kernel since Linux 3.0)
    executable: PathBuf,

    /// %c — Core file size limit (RLIMIT_CORE).
    /// The kernel ignores this for pipe mode; informational only.
    #[arg(default_value_t = 0)]
    core_limit: u64,

    /// %d — Dumpable flag (controls whether SUID processes dump).
    /// See CVE-2022-4415. The kernel checks this before invoking the
    /// handler; logged for audit.
    #[arg(default_value_t = 0)]
    dumpable: u32,
}

fn main() -> anyhow::Result<()> {
    // Occupy fd 1 and fd 2 with /dev/null before doing anything else.
    //
    // In pipe mode, the kernel only sets up fd 0 (stdin = core dump pipe).
    // fd 1 and fd 2 are not open. The first file we open would get fd 1,
    // and tracing's default stdout writer would write into our core dump
    // file — corrupting it.
    //
    // These handles are intentionally leaked: they hold fd 1 and 2
    // for the process lifetime so no data file can claim them.
    let _null1 = std::fs::OpenOptions::new().write(true).open("/dev/null");
    let _null2 = std::fs::OpenOptions::new().write(true).open("/dev/null");

    // Log to /dev/kmsg (kernel ring buffer, readable via `dmesg`).
    // /dev/kmsg works even when the disk is full (stored in memory),
    // which is exactly when a crash handler needs logging most.
    let kmsg = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/kmsg")
        .unwrap_or_else(|_| {
            // /dev/kmsg unavailable — fall back to /dev/null.
            // Logging is lost, but fd 1/2 are already safe.
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/null")
                .expect("failed to open /dev/null")
        });

    tracing_subscriber::fmt()
        .with_writer(Mutex::new(kmsg))
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Defense-in-depth against core-dump recursion: the kernel's
    // RLIMIT_CORE=1 sentinel is the primary guard, but
    // PR_SET_DUMPABLE=0 stops the kernel from entering the coredump
    // path at all.
    if let Err(e) = ffi::disable_core_dump() {
        tracing::warn!(error = %e, "failed to disable core dump; defense-in-depth inactive, kernel sentinel still applies");
    }

    // clap's parse() prints the error to stderr and exits; stderr is
    // /dev/null here, and the kernel only checks that exec succeeded
    // (UMH_WAIT_EXEC), so the exit code is invisible. A hard exit
    // therefore silently abandons the core waiting on fd 0. The dump
    // is independent of argv, so parse failures degrade the metadata
    // instead of discarding it.
    let metadata = match Args::try_parse() {
        Ok(args) => {
            // Resolve the real executable path.
            // %E has '/' replaced with '!' (since Linux 3.0), which is ambiguous.
            // /proc/<pid>/exe symlink is the kernel-maintained real path.
            let exe_path = resolve_exe_path(args.pid, &args.executable.to_string_lossy());
            CrashMetadata {
                pid: args.pid,
                uid: Some(args.uid),
                gid: Some(args.gid),
                signal: args.signal,
                timestamp: args.timestamp,
                hostname: args.hostname.to_string_lossy().into_owned(),
                exe_path,
                core_limit: args.core_limit,
                dumpable: args.dumpable,
                argv_parse_error: None,
            }
        }
        Err(e) => {
            let reason = sanitize_reason(&e);
            tracing::warn!(error = %reason, "argv parse failed, storing core with degraded metadata");
            degraded_metadata(&reason)
        }
    };

    let storage = StorageConfig::default();

    // Read core dump from stdin (pipe mode) and process it.
    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();

    // The kernel uses UMH_WAIT_EXEC — it only checks that exec succeeded,
    // not the exit code. Since fd 2 is /dev/null, anyhow's default error
    // output is lost. We must log failures ourselves.
    if let Err(e) = process_core_dump(&mut stdin_lock, &metadata, &storage) {
        tracing::error!(error = ?e, "failed to store core dump");
    }
    Ok(())
}

/// Byte budget for the sanitized argv parse failure reason.
///
/// The reason ends up in both the kmsg warn line and the
/// "core dump stored" line. The degraded path empties the hostname
/// field, so even a full-size reason keeps that line well under
/// kmsg's record limit (992 bytes on kernels before the 2023
/// printk rework, ~1024 after) — writes over the limit are dropped
/// with EINVAL, not truncated.
const REASON_MAX_BYTES: usize = 400;

/// Printable, single-line, bounded rendering of a clap parse
/// failure, used for the kmsg warn line and the argv_parse_error
/// metadata field.
///
/// clap's rendering is multi-line and echoes the offending argv
/// value, which can carry attacker-controlled %E/%h content. Raw
/// rendering fails three ways on the kmsg path: writes over the
/// record limit are dropped entirely (EINVAL, not truncated),
/// embedded newlines are split into forged separate records, and
/// control characters reach terminal emulators reading
/// dmesg/journalctl output (CWE-117). Quotes and backslashes are
/// rejected as well, because Debug formatting of the stored field
/// backslash-escapes them, which would defeat the length budget.
fn sanitize_reason(e: &clap::Error) -> String {
    let rendered = e.to_string();
    let truncated = truncate_for_log(&rendered, REASON_MAX_BYTES);
    let mut sanitized = String::with_capacity(truncated.len());
    for ch in truncated.chars() {
        if (ch.is_ascii_graphic() && ch != '"' && ch != '\\') || ch == ' ' {
            sanitized.push(ch);
        } else {
            sanitized.push('?');
        }
    }
    sanitized
}

/// Metadata for a core dump whose argv could not be parsed (wrong argc
/// from a misconfigured core_pattern, or unparseable values). The dump
/// on fd 0 is valid regardless of what the kernel wrote into argv, so
/// it is stored with sentinel values: uid/gid None means unknown
/// (Some(0) would falsely claim root), pid 0 is never a valid crashing
/// PID, and the timestamp falls back to the processing time — the same
/// fallback socket mode uses, as documented on the timestamp field.
fn degraded_metadata(reason: &str) -> CrashMetadata {
    CrashMetadata {
        pid: 0,
        uid: None,
        gid: None,
        signal: 0,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        hostname: String::new(),
        exe_path: String::new(),
        core_limit: 0,
        dumpable: 0,
        argv_parse_error: Some(reason.to_owned()),
    }
}
