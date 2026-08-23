#![deny(unsafe_code)]

use std::sync::Mutex;

use clap::Parser;
use vdr::{CrashMetadata, StorageConfig, process_core_dump, resolve_exe_path};

/// vdr — Voyage Data Recorder
///
/// A crash dump handler invoked by the kernel via core_pattern.
/// The kernel pipes the core dump to stdin and passes crash
/// metadata as positional arguments.
///
/// Example core_pattern:
///   |/usr/bin/vdr %P %u %g %s %t %h %E %c %d
#[derive(Parser, Debug)]
#[command(version, about = "Voyage Data Recorder — crash dump handler")]
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

    /// %h — Hostname
    hostname: String,

    /// %E — Path of the executable (slashes replaced with '!' by kernel since Linux 3.0)
    executable: String,

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

    let args = Args::parse();

    // Resolve the real executable path.
    // %E has '/' replaced with '!' (since Linux 3.0), which is ambiguous.
    // /proc/<pid>/exe symlink is the kernel-maintained real path.
    let exe_path = resolve_exe_path(args.pid, &args.executable);

    let metadata = CrashMetadata {
        pid: args.pid,
        uid: args.uid,
        gid: args.gid,
        signal: args.signal,
        timestamp: args.timestamp,
        hostname: args.hostname,
        exe_path,
        core_limit: args.core_limit,
        dumpable: args.dumpable,
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
