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
