#![deny(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use elf::ElfBytes;
use elf::endian::AnyEndian;
use elf::note::{Note, NoteGnuBuildId};
use tracing::{info, warn};

pub const ZSTD_LEVEL: i32 = 3;
pub const STORAGE_DIR: &str = "/var/lib/vdr";
pub const MAX_CORE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

/// Metadata about the crash, provided by the kernel.
///
/// Both the pipe handler (vdr) and the socket daemon (vdrd) populate
/// this from their respective sources and pass it to process_core_dump().
#[derive(Debug, Clone)]
pub struct CrashMetadata {
    /// %P — PID of the crashed process
    pub pid: u32,

    /// %u — Real UID of the crashed process
    pub uid: u32,

    /// %g — Real GID of the crashed process
    pub gid: u32,

    /// %s — Signal number that caused the crash
    pub signal: u32,

    /// %t — Unix timestamp of the crash
    pub timestamp: u64,

    /// %h — Hostname
    pub hostname: String,

    /// Resolved executable path (from /proc/<pid>/exe or %E with ! restored)
    pub exe_path: String,

    /// %c — Core file size limit (RLIMIT_CORE)
    pub core_limit: u64,

    /// %d — Dumpable flag (CVE-2022-4415 was systemd-coredump failing to honor this)
    pub dumpable: u32,
}

/// Storage configuration for core dumps.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Directory to store compressed core dumps
    pub storage_dir: PathBuf,

    /// Maximum core dump size in bytes (truncated if exceeded)
    pub max_core_size: u64,

    /// zstd compression level (1-19)
    pub zstd_level: i32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from(STORAGE_DIR),
            max_core_size: MAX_CORE_SIZE,
            zstd_level: ZSTD_LEVEL,
        }
    }
}

/// Result of processing a core dump.
#[derive(Debug)]
pub struct StoredDump {
    /// Final path of the stored compressed core dump
    pub path: PathBuf,

    /// Uncompressed size in bytes
    pub bytes_in: u64,

    /// Compressed size in bytes
    pub bytes_out: u64,

    /// GNU build ID extracted from the executable, if available
    pub build_id: Option<String>,

    /// /proc/<pid>/cmdline contents, if readable
    pub cmdline: Option<String>,

    /// /proc/<pid>/comm contents, if readable
    pub comm: Option<String>,
}

/// Process a core dump from any Read source.
///
/// This is the shared core logic called by both:
///   - vdr (pipe handler): reads from stdin
///   - vdrd (socket daemon): reads from UnixStream
///
/// Steps:
///   1. Extract build ID from the executable file
///   2. Read /proc/<pid>/ metadata (best-effort)
///   3. Stream reader → zstd → temp file (core dump never in memory)
///   4. fsync file + atomic rename + fsync directory
///   5. Return stored dump info
pub fn process_core_dump(
    reader: &mut impl Read,
    metadata: &CrashMetadata,
    storage: &StorageConfig,
) -> anyhow::Result<StoredDump> {
    info!(
        pid = metadata.pid,
        uid = metadata.uid,
        gid = metadata.gid,
        signal = metadata.signal,
        exe = %metadata.exe_path,
        "received core dump"
    );

    // Build ID lives in the executable's .note.gnu.build-id section,
    // not in the core dump. Core dumps (ET_CORE) have no section
    // header table. The executable is a trusted input (system file
    // on disk), unlike the core dump which contains attacker-
    // controlled memory.
    let build_id = parse_executable_build_id(&metadata.exe_path);

    // Best-effort: the crashed process's /proc entry disappears
    // after the handler exits. WARNING: if the PID has been
    // recycled, these reads may return data from a different
    // process. Treat all /proc reads as advisory.
    let cmdline = read_proc_string(metadata.pid, "cmdline");
    let comm = read_proc_string(metadata.pid, "comm");

    // The core dump is never fully held in memory. The reader
    // (stdin or UnixStream) is piped directly through the zstd
    // encoder to a temp file. Input is capped at max_core_size.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&storage.storage_dir)
        .with_context(|| {
            format!(
                "creating storage directory {}",
                storage.storage_dir.display()
            )
        })?;

    // Ensure correct permissions even if directory already existed
    // (DirBuilder doesn't modify permissions of pre-existing dirs).
    std::fs::set_permissions(&storage.storage_dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", storage.storage_dir.display()))?;

    // Generate unique filename: PID + timestamp + nanoseconds.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let filename = format!(
        "core.{}.{}.{:09}.zst",
        metadata.pid,
        metadata.timestamp,
        now.subsec_nanos()
    );
    let final_path = storage.storage_dir.join(&filename);
    let tmp_path = storage.storage_dir.join(format!(".{}.tmp", filename));

    // Create temp file with O_CREAT|O_EXCL (prevents symlink attacks)
    // and mode 0o600 (only root can read — core dumps contain secrets).
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("creating temp file {}", tmp_path.display()))?;

    // RAII guard: ensures temp file is cleaned up if any step below fails.
    let mut guard = TempGuard::new(tmp_path.clone());

    // Stream: reader → zstd encoder → file
    let mut encoder = zstd::stream::Encoder::new(file, storage.zstd_level)
        .with_context(|| "creating zstd encoder")?;

    let mut limited_reader = reader.take(storage.max_core_size);
    let bytes_in = std::io::copy(&mut limited_reader, &mut encoder)
        .with_context(|| "streaming core dump through zstd encoder")?;

    if bytes_in >= storage.max_core_size {
        warn!(
            bytes_in,
            max = storage.max_core_size,
            "core dump may be truncated (hit size limit)"
        );
    }

    // Finish encoding — flushes internal buffers and returns the
    // inner File handle so it can be fsync'd.
    let file = encoder
        .finish()
        .with_context(|| "finishing zstd encoding")?;

    // fsync file data before rename — ensure content reaches disk.
    file.sync_all().with_context(|| "fsync of core dump")?;
    drop(file); // close file handle before rename

    // Atomic rename: temp → final
    std::fs::rename(&tmp_path, &final_path)
        .with_context(|| format!("renaming temp file to {}", final_path.display()))?;

    // fsync parent directory — rename updates a directory entry,
    // which is separate from the file data already fsync'd.
    let dir = std::fs::File::open(&storage.storage_dir)
        .with_context(|| "opening storage dir for fsync")?;
    dir.sync_all()
        .with_context(|| "fsync of storage directory")?;

    // Everything committed — disarm the guard.
    guard.disarm();

    let compressed_size = std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);

    info!(
        path = %final_path.display(),
          bytes_in,
          bytes_out = compressed_size,
          build_id = ?build_id,
          cmdline = ?cmdline,
          comm = ?comm,
          core_limit = metadata.core_limit,
          dumpable = metadata.dumpable,
          hostname = %metadata.hostname,
          "core dump stored"
    );

    Ok(StoredDump {
        path: final_path,
        bytes_in,
        bytes_out: compressed_size,
        build_id,
        cmdline,
        comm,
    })
}

/// RAII guard that removes a temp file on drop unless disarmed.
///
/// Ensures temp files are cleaned up if any step between creation
/// and atomic rename fails. Temp files leak on every failed crash
/// handling; without cleanup, they accumulate and fill the disk.
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Resolve the real executable path for the crashed process.
///
/// Primary: /proc/<pid>/exe symlink — kernel-maintained real path,
/// no '!' substitution ambiguity.
///
/// Fallback: %E from core_pattern, with '!' restored to '/'.
/// Ambiguous if the original path contained '!'.
///
/// The symlink may have " (deleted)" appended if the executable
/// was unlinked after the process started; stripped if present.
pub fn resolve_exe_path(pid: u32, kernel_provided: &str) -> String {
    let proc_exe = format!("/proc/{}/exe", pid);
    match std::fs::read_link(&proc_exe) {
        Ok(path) => {
            let s = path.to_string_lossy().into_owned();
            s.strip_suffix(" (deleted)").unwrap_or(&s).to_string()
        }
        Err(_) => kernel_provided.replace('!', "/"),
    }
}

/// Read a file from /proc/<pid>/<name> and return its contents as a String.
///
/// Returns None if the file doesn't exist or can't be read. Uses
/// from_utf8_lossy because cmdline can contain non-UTF-8 bytes
/// (argv is arbitrary bytes from execve, not validated by kernel).
///
/// WARNING: If the PID has been recycled by the kernel, this may
/// return data from a completely different process. All /proc reads
/// should be treated as advisory, not authoritative.
pub(crate) fn read_proc_string(pid: u32, name: &str) -> Option<String> {
    let path = format!("/proc/{}/{}", pid, name);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let content = String::from_utf8_lossy(&bytes);
            if name == "cmdline" {
                Some(content.replace('\0', " ").trim().to_string())
            } else {
                Some(content.trim().to_string())
            }
        }
        Err(e) => {
            warn!(path = %path, error = %e, "failed to read /proc entry");
            None
        }
    }
}

/// Parse the executable's ELF header to extract the GNU build ID.
///
/// Core dumps (ET_CORE) do not contain a .note.gnu.build-id section;
/// the build ID lives in the executable itself.
///
/// The executable may be attacker-controlled — users can crash their
/// own binaries. However, elf crate 0.8 is pure safe Rust (zero unsafe)
/// and designed to handle untrusted input, returning ParseError rather
/// than panicking on malformed data. Build ID extraction failure safely
/// degrades to None.
///
/// File size is capped at MAX_EXE_SIZE to avoid loading large executables
/// (e.g., static Go binaries can be 80+ MB) into memory.
///
/// TODO: Use ElfStream instead of reading the entire file into memory.
pub(crate) fn parse_executable_build_id(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;

    let file = match ElfBytes::<AnyEndian>::minimal_parse(&data) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path, error = %e, "failed to parse executable ELF");
            return None;
        }
    };

    file.section_header_by_name(".note.gnu.build-id")
        .ok()?
        .and_then(|shdr| file.section_data_as_notes(&shdr).ok())
        .and_then(|notes| {
            notes
                .filter_map(|note| match note {
                    Note::GnuBuildId(NoteGnuBuildId(id)) => {
                        Some(id.iter().map(|b| format!("{:02x}", b)).collect())
                    }
                    _ => None,
                })
                .next()
        })
}
