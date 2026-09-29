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
