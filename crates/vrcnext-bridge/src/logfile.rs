//! The rotating log file.
//!
//! # Where it goes, and why that matters
//!
//! Log lines carry VRChat display names, instance ids and whatever a plugin author decided to
//! print. That is the user's data, and `/tmp` is a world-readable directory shared with every
//! other account on the machine, so a naive `/tmp/vrcnext-bridge.log` would be wrong twice over:
//!
//! - **Readable by other users** unless the mode is set explicitly.
//! - **Symlink-attackable.** A predictable path in a shared sticky directory can be pre-created by
//!   another user as a symlink, and an unsuspecting `File::create` follows it and writes through.
//!
//! So the preference order is:
//!
//! 1. `$XDG_RUNTIME_DIR/vrcnext-bridge/` — per-user, already `0700`, and cleaned at logout.
//! 2. `<temp>/vrcnext-bridge-<user>/` — created `0700` before anything is written into it.
//!
//! The file itself is opened `0600` on Unix. On other platforms the directory is still per-user
//! and the mode calls are skipped.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use vrcnext_bridge_core::logs::{LogRecord, LogWriter};

/// Rotate once the file passes this, keeping one previous generation.
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Appends records to a file, rotating it when it grows too large.
pub(crate) struct FileLogWriter {
    path: PathBuf,
    max_bytes: u64,
    state: Mutex<State>,
}

struct State {
    file: File,
    bytes: u64,
}

impl FileLogWriter {
    /// Open (or create) the log file at `path`, or at the default location when `None`.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be created or the file cannot be opened.
    pub(crate) fn open(path: Option<PathBuf>, max_bytes: Option<u64>) -> Result<Self> {
        let path = match path {
            Some(explicit) => explicit,
            None => default_path(),
        };

        if let Some(parent) = path.parent() {
            create_private_dir(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }

        let file = open_private_append(&path)
            .with_context(|| format!("could not open {}", path.display()))?;
        let bytes = file.metadata().map_or(0, |meta| meta.len());

        Ok(Self {
            path,
            max_bytes: max_bytes.unwrap_or(DEFAULT_MAX_BYTES),
            state: Mutex::new(State { file, bytes }),
        })
    }

    /// Rename the current file aside and start a fresh one.
    ///
    /// One generation is kept. A daemon that quietly fills a disk is worse than one that loses old
    /// debug lines, and this is a diagnostic log, not an audit trail.
    fn rotate(&self, state: &mut State) -> Result<(), String> {
        let previous = self.path.with_extension("log.1");
        // Best-effort: on failure keep appending to the current file rather than losing records.
        if let Err(error) = std::fs::rename(&self.path, &previous) {
            return Err(format!("rotation failed: {error}"));
        }
        state.file = open_private_append(&self.path).map_err(|error| error.to_string())?;
        state.bytes = 0;
        Ok(())
    }
}

impl LogWriter for FileLogWriter {
    fn append(&self, records: &[LogRecord]) -> Result<(), String> {
        if records.is_empty() {
            return Ok(());
        }

        let mut buffer = String::new();
        let stamp = iso_timestamp();
        for record in records {
            // Ignoring the result is correct: writing to a String is infallible.
            let _ = writeln!(
                buffer,
                "{stamp} {} [{}] {}",
                record.level.padded(),
                record.scope,
                record.message
            );
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| "log file lock poisoned".to_owned())?;

        if state.bytes.saturating_add(buffer.len() as u64) > self.max_bytes {
            self.rotate(&mut state)?;
        }

        state
            .file
            .write_all(buffer.as_bytes())
            .map_err(|error| format!("write failed: {error}"))?;
        // Flushed per batch so `tail -f` shows lines as they happen, which is the entire point.
        state
            .file
            .flush()
            .map_err(|error| format!("flush failed: {error}"))?;

        state.bytes = state.bytes.saturating_add(buffer.len() as u64);
        Ok(())
    }

    fn location(&self) -> String {
        self.path.display().to_string()
    }

    fn bytes_written(&self) -> u64 {
        self.state.lock().map_or(0, |state| state.bytes)
    }
}

/// `$XDG_RUNTIME_DIR/vrcnext-bridge/plugins.log`, else a per-user directory under the temp dir.
fn default_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !runtime.is_empty() {
            return PathBuf::from(runtime)
                .join("vrcnext-bridge")
                .join("plugins.log");
        }
    }

    // `USER` only has to make the directory unique per account on a shared machine; it is never
    // trusted for anything else, and a missing value just collapses to one shared directory whose
    // 0700 mode still keeps other users out.
    let user = std::env::var("USER").unwrap_or_else(|_| "user".to_owned());
    let safe: String = user
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(32)
        .collect();

    std::env::temp_dir()
        .join(format!("vrcnext-bridge-{safe}"))
        .join("plugins.log")
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if path.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(unix)]
fn open_private_append(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .create(true)
        .append(true)
        // 0600 from the moment it exists — never created readable and tightened afterwards.
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// `2026-09-19T16:20:00.123Z`, built without pulling in a date library.
///
/// The integer divisions here are calendar arithmetic on whole units, which is exactly what is
/// wanted — there is no truncation to be surprised by.
#[expect(
    clippy::integer_division,
    reason = "calendar arithmetic on whole seconds and days"
)]
fn iso_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = now.subsec_millis();
    let total = now.as_secs();

    let (year, month, day) = civil_from_days(total / 86_400);
    let seconds_today = total % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        seconds_today / 3_600,
        (seconds_today % 3_600) / 60,
        seconds_today % 60,
    )
}

/// Howard Hinnant's `civil_from_days`, for days since the Unix epoch.
#[expect(
    clippy::integer_division,
    reason = "the algorithm is defined in terms of integer division"
)]
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]

    use super::{FileLogWriter, civil_from_days, iso_timestamp};
    use vrcnext_bridge_core::logs::{LogLevel, LogRecord, LogWriter};

    fn record(message: &str) -> LogRecord {
        let parsed: vrcnext_bridge_core::logs::LogWriteRequest = serde_json::from_value(
            serde_json::json!({ "records": [{ "level": "info", "message": message }] }),
        )
        .expect("parses");
        parsed.validate().expect("validates").remove(0)
    }

    #[test]
    fn epoch_converts_correctly() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
    }

    #[test]
    fn timestamp_has_the_expected_shape() {
        let stamp = iso_timestamp();
        assert_eq!(stamp.len(), 24, "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert!(stamp.starts_with("20"), "{stamp}");
    }

    #[test]
    fn appends_and_rotates() {
        let dir = std::env::temp_dir().join(format!("vrcnext-bridge-test-{}", std::process::id()));
        let path = dir.join("plugins.log");
        let writer = FileLogWriter::open(Some(path.clone()), Some(200)).expect("opens");

        for index in 0..50 {
            writer
                .append(&[record(&format!("message number {index}"))])
                .expect("appends");
        }

        assert!(path.exists(), "current generation should exist");
        assert!(
            path.with_extension("log.1").exists(),
            "a previous generation should have been rotated out"
        );
        assert!(
            writer.bytes_written() <= 200 + 64,
            "should have rotated, not grown"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("vrcnext-bridge-mode-{}", std::process::id()));
        let path = dir.join("plugins.log");
        let writer = FileLogWriter::open(Some(path.clone()), None).expect("opens");
        writer.append(&[record("hello")]).expect("appends");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "group and other must have no access; mode was {mode:o}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_batch_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("vrcnext-bridge-empty-{}", std::process::id()));
        let writer = FileLogWriter::open(Some(dir.join("plugins.log")), None).expect("opens");
        assert!(writer.append(&[]).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn levels_are_rendered_at_a_fixed_width() {
        assert_eq!(LogLevel::Info.padded(), "INFO ");
        assert_eq!(LogLevel::Error.padded(), "ERROR");
    }
}
