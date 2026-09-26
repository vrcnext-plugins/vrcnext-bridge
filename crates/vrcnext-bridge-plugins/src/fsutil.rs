//! Small filesystem helpers with the properties the rest of the crate relies on.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

/// Write `bytes` to `path` so that a reader sees either the old content or the new, never a
/// prefix of the new.
///
/// The bytes go to a sibling temp file, are synced, and the temp file is renamed over the target.
/// A crash at any point leaves either the previous file intact or a `.tmp` that the next write
/// overwrites. The file is created `0600` on Unix: state carries plugin settings, which may be
/// API keys.
///
/// # Errors
///
/// Any I/O error from creating, writing, syncing or renaming.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = temp_sibling(path);
    {
        let mut file = open_private(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, path)
}

/// `<path>.tmp` beside the target, so the rename never crosses a filesystem.
fn temp_sibling(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().map_or_else(
        || std::ffi::OsString::from("file"),
        std::ffi::OsStr::to_os_string,
    );
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    // No mode bits on Windows; %LOCALAPPDATA% is per-user already.
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
}

/// Create `dir` and every missing parent, privately on Unix.
///
/// # Errors
///
/// Any I/O error from creating the directories.
#[cfg(unix)]
pub fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Create `dir` and every missing parent.
///
/// # Errors
///
/// Any I/O error from creating the directories.
#[cfg(not(unix))]
pub fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// A scratch directory unique to this process and `name`, for tests.
#[cfg(test)]
pub(crate) fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vrcnext-plugins-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok();
    dir
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use super::{scratch_dir, temp_sibling, write_atomic};

    #[test]
    fn atomic_write_replaces_the_file_and_leaves_no_temp() {
        let dir = scratch_dir("atomic");
        let path = dir.join("state.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!temp_sibling(&path).exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
