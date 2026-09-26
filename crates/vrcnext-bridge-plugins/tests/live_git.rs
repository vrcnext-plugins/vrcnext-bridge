//! Talks to GitHub. Ignored by default; run with `cargo test -p vrcnext-bridge-plugins --test
//! live_git -- --ignored` to prove the pure-Rust transport works from this machine.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]

use vrcnext_bridge_plugins::git::{Git as _, GixGit};

const URL: &str = "https://github.com/vrcnext-plugins/vrcnext-plugin-system";

#[test]
#[ignore = "needs network access"]
fn a_depth_one_clone_and_a_fetch_work_over_https() {
    let dir = std::env::temp_dir().join(format!("vrcnext-live-git-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("clone");

    let commit = GixGit.clone_repo(URL, &dest).expect("clone");
    assert_eq!(commit.len(), 40, "{commit}");
    assert!(dest.join("package.json").is_file());
    assert!(dest.join(".git").is_dir());

    let status = GixGit.fetch_status(&dest).expect("fetch");
    assert_eq!(status.current, commit);
    assert_eq!(status.latest, commit);
    assert!(status.changelog.is_empty());
    std::fs::remove_dir_all(dir).ok();
}
