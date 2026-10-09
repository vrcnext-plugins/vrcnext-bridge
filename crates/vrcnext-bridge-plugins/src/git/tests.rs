#![allow(
    clippy::unwrap_used,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{Git as _, GitError, with_deadline};

#[test]
fn the_watchdog_leaves_with_the_operation() {
    // The watchdog is joined before this returns, so a quick operation must mean a quick
    // return: a watchdog that slept out the whole deadline would hold this for minutes, and
    // one that was never joined would leave a thread behind per clone.
    let started = Instant::now();
    let value = with_deadline(|interrupt| {
        assert!(!interrupt.load(Ordering::Relaxed));
        Ok::<_, GitError>(7)
    })
    .unwrap();
    assert_eq!(value, 7);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A repository with one commit, and a local identity so committing needs no global config.
fn origin(dir: &std::path::Path) -> gix::Repository {
    gix::init(dir).unwrap();
    std::fs::write(
        dir.join(".git/config"),
        "[user]\n\tname = Test\n\temail = test@localhost\n",
    )
    .unwrap();
    let repo = gix::open(dir).unwrap();
    let tree = repo.empty_tree().id();
    repo.commit("HEAD", "first", tree, gix::commit::NO_PARENT_IDS)
        .unwrap();
    repo
}

/// Add an empty commit on top of whatever `HEAD` is.
fn commit_on_top(repo: &gix::Repository, message: &str) -> gix::ObjectId {
    let parent = repo.head_id().unwrap().detach();
    let tree = repo.empty_tree().id();
    repo.commit("HEAD", message, tree, [parent])
        .unwrap()
        .detach()
}

#[test]
fn a_clone_whose_remote_moved_on_reports_itself_behind() {
    // `check_updates` reported nothing for every plugin for as long as it existed, because
    // `latest` came from `refs/remotes/origin/HEAD` — a ref the clone writes once and a fetch
    // never touches. Nothing caught it: the service's own test feeds it a canned status, and the
    // live test clones and fetches without moving the remote in between, so it asserted exactly
    // the case where a stale `latest` is still correct.
    //
    // No network: the remote is a second repository on disk, which `gix` fetches over its file
    // transport the same way it would over https.
    let dir = std::env::temp_dir().join(format!("vrcnext-git-behind-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let remote_dir = dir.join("remote");
    let clone_dir = dir.join("clone");
    std::fs::create_dir_all(&remote_dir).unwrap();

    let remote = origin(&remote_dir);
    let cloned_at = super::GixGit
        .clone_repo(remote_dir.to_str().unwrap(), &clone_dir)
        .unwrap();

    // Level with the remote: nothing to report, which is all the old code ever managed to say.
    let level = super::GixGit.fetch_status(&clone_dir).unwrap();
    assert_eq!(level.current, cloned_at);
    assert_eq!(level.latest, cloned_at);
    assert!(!level.is_behind(), "a fresh clone is not behind: {level:?}");

    let moved_on = commit_on_top(&remote, "second").to_string();
    let behind = super::GixGit.fetch_status(&clone_dir).unwrap();
    assert_eq!(behind.current, cloned_at, "the clone itself did not move");
    assert_eq!(behind.latest, moved_on, "and the remote's new head is seen");
    assert!(behind.is_behind(), "which is an update: {behind:?}");
    assert_eq!(
        behind
            .changelog
            .iter()
            .map(|e| e.summary.as_str())
            .collect::<Vec<_>>(),
        ["second"],
        "the one commit it is behind by"
    );

    std::fs::remove_dir_all(dir).ok();
}
