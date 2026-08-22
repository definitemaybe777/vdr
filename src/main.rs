#![deny(unsafe_code)]

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

    /// %c — Core file size limit (RLIMIT_CORE)
    #[arg(default_value_t = 0)]
    core_limit: u64,

    /// %d — Dumpable flag (controls whether SUID processes dump).
    /// CVE-2022-4415 was systemd-coredump failing to honor this.
    /// Kernel checks this before invoking the handler; logged for audit.
    #[arg(default_value_t = 0)]
    dumpable: u32,
}

fn main() -> anyhow::Result<()> {
    // Initialize structured logging to stderr.
    // Default to "info" if RUST_LOG is unset — crash events should be
    // visible without extra configuration.
    tracing_subscriber::fmt()
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

    // Exit code 0 — kernel checks this; non-zero may trigger fallback behavior.
    let _stored = process_core_dump(&mut stdin_lock, &metadata, &storage)?;
    Ok(())
}
