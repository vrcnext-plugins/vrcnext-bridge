#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::{base64url, is_token, load_or_create, rotate};

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vrcnext-token-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("token")
}

#[test]
fn base64url_matches_the_rfc_vectors() {
    assert_eq!(base64url(b""), "");
    assert_eq!(base64url(b"f"), "Zg");
    assert_eq!(base64url(b"fo"), "Zm8");
    assert_eq!(base64url(b"foo"), "Zm9v");
    assert_eq!(base64url(b"foob"), "Zm9vYg");
    assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
}

#[test]
fn a_token_is_generated_once_and_then_reused() {
    let path = scratch("reuse");
    let first = load_or_create(&path).expect("created");
    let second = load_or_create(&path).expect("read back");
    assert_eq!(first, second);
    assert!(is_token(&first), "{first}");
    assert_ne!(rotate(&path).expect("rotated"), first);
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[test]
fn a_malformed_token_file_is_refused_rather_than_trusted() {
    let path = scratch("bad");
    std::fs::write(&path, "hello\n").unwrap();
    assert!(load_or_create(&path).is_err());
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}

#[cfg(unix)]
#[test]
fn the_token_file_is_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let path = scratch("mode");
    rotate(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "mode was {mode:o}");
    std::fs::remove_dir_all(path.parent().unwrap()).ok();
}
