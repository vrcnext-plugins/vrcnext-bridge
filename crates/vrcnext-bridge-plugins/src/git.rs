//! Git, in-process: the [`Git`] trait and its `gix` implementation.
//!
//! The bridge never shells out to `git`. It does not exist on most Windows machines, its output
//! is a moving target, and every argument would be one more thing a repository could influence.
//! `gix` with a rustls transport does the two things that are needed — a shallow clone and a
//! fetch — in pure Rust.
//!
//! The trait exists so the install pipeline can be tested with a fake that writes files instead
//! of touching the network. [`GixGit`] is the only real implementation.
//!
//! Every operation runs under a 120 s deadline enforced through `gix`'s interrupt flag, which it
//! checks between pack chunks: a stalled remote costs at most that long, and never a thread.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gix::progress::Discard;

/// Longest a clone or fetch may run.
pub const NETWORK_DEADLINE: Duration = Duration::from_secs(120);

/// How much history a clone carries. One commit: the code, and nothing to walk.
const CLONE_DEPTH: u32 = 1;

/// How much history a fetch brings in for the changelog. Fifty is what `check_updates` reports
/// at most; fetching more would be paying for entries nobody sees.
pub const CHANGELOG_LIMIT: u32 = 50;

/// Where the clone's remote-tracking HEAD lives.
const REMOTE_HEAD: &str = "refs/remotes/origin/HEAD";

/// Why a git operation failed. The message is safe to show: it names the failure, not the
/// repository's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GitError {
    /// Clone failed; the destination has been removed.
    #[error("clone failed: {0}")]
    Clone(String),
    /// Fetch failed; the clone is unchanged.
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// The deadline passed.
    #[error("timed out after {}s", NETWORK_DEADLINE.as_secs())]
    Timeout,
    /// The clone directory is not a repository this bridge made.
    #[error("not a plugin clone: {0}")]
    NotARepository(String),
}

/// One commit on the remote that the local clone does not have.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangelogEntry {
    /// Full hex id.
    pub commit: String,
    /// First line of the message.
    pub summary: String,
    /// Commit time, seconds since the epoch.
    pub time: i64,
}

/// What a fetch found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStatus {
    /// The local HEAD.
    pub current: String,
    /// The remote default branch's head.
    pub latest: String,
    /// Commits on the remote not reachable locally, at most [`CHANGELOG_LIMIT`]. If the walk hit
    /// the limit without reaching `current`, the clone is *at least* this far behind.
    pub changelog: Vec<ChangelogEntry>,
}

impl RemoteStatus {
    /// Whether an update is available.
    #[must_use]
    pub fn is_behind(&self) -> bool {
        self.current != self.latest
    }
}

/// The two git operations the bridge needs.
pub trait Git: Send + Sync {
    /// Clone `url`'s default branch, depth 1, into `dest` (which must not exist). Returns the
    /// head commit's hex id. On failure `dest` is removed.
    ///
    /// # Errors
    ///
    /// [`GitError::Clone`] or [`GitError::Timeout`].
    fn clone_repo(&self, url: &str, dest: &Path) -> Result<String, GitError>;

    /// Fetch `origin` for the clone at `repo` and compare it with the local head.
    ///
    /// # Errors
    ///
    /// [`GitError::Fetch`], [`GitError::Timeout`] or [`GitError::NotARepository`].
    fn fetch_status(&self, repo: &Path) -> Result<RemoteStatus, GitError>;
}

/// The `gix` implementation.
pub struct GixGit;

impl Git for GixGit {
    fn clone_repo(&self, url: &str, dest: &Path) -> Result<String, GitError> {
        let result = with_deadline(|interrupt| clone_inner(url, dest, interrupt));
        if result.is_err() {
            // Whatever half-arrived must not be mistaken for a plugin later.
            let _ = std::fs::remove_dir_all(dest);
        }
        result
    }

    fn fetch_status(&self, repo: &Path) -> Result<RemoteStatus, GitError> {
        with_deadline(|interrupt| fetch_inner(repo, interrupt))
    }
}

/// Run `op` with an interrupt flag that a watchdog thread raises at the deadline.
///
/// The watchdog is a thread rather than a timer because `gix` is synchronous: nothing else is
/// awake to flip the flag. It exits on its own once the deadline passes; a finished operation
/// does not need to stop it.
fn with_deadline<T>(op: impl FnOnce(&AtomicBool) -> Result<T, GitError>) -> Result<T, GitError> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrupt);
    std::thread::spawn(move || {
        std::thread::sleep(NETWORK_DEADLINE);
        flag.store(true, Ordering::Relaxed);
    });
    let result = op(&interrupt);
    if interrupt.load(Ordering::Relaxed) && result.is_err() {
        return Err(GitError::Timeout);
    }
    result
}

fn depth(n: u32) -> gix::remote::fetch::Shallow {
    std::num::NonZeroU32::new(n).map_or(gix::remote::fetch::Shallow::NoChange, |depth| {
        gix::remote::fetch::Shallow::DepthAtRemote(depth)
    })
}

fn clone_inner(url: &str, dest: &Path, interrupt: &AtomicBool) -> Result<String, GitError> {
    let failed = |error: gix::Error| GitError::Clone(sanitise(&error.to_string()));
    let mut prepare = gix::prepare_clone(url, dest)
        .map_err(failed)?
        .with_shallow(depth(CLONE_DEPTH));
    let (mut checkout, _) = prepare
        .fetch_then_checkout(Discard, interrupt)
        .map_err(failed)?;
    let (repo, _) = checkout.main_worktree(Discard, interrupt).map_err(failed)?;
    let head = repo.head_id().map_err(failed)?;
    Ok(head.to_string())
}

fn fetch_inner(path: &Path, interrupt: &AtomicBool) -> Result<RemoteStatus, GitError> {
    let repo =
        gix::open(path).map_err(|error| GitError::NotARepository(sanitise(&error.to_string())))?;
    let failed = |error: gix::Error| GitError::Fetch(sanitise(&error.to_string()));

    let current = repo.head_id().map_err(failed)?.detach();
    repo.find_remote("origin")
        .map_err(failed)?
        .connect(gix::remote::Direction::Fetch)
        .map_err(failed)?
        .prepare_fetch(Discard, gix::remote::ref_map::Options::default())
        .map_err(failed)?
        .with_shallow(depth(CHANGELOG_LIMIT))
        .receive(Discard, interrupt)
        .map_err(failed)?;

    let latest = repo
        .find_reference(REMOTE_HEAD)
        .map_err(failed)?
        .into_fully_peeled_id()
        .map_err(failed)?
        .detach();

    let changelog = if latest == current {
        Vec::new()
    } else {
        changelog(&repo, latest, current).map_err(failed)?
    };
    Ok(RemoteStatus {
        current: current.to_string(),
        latest: latest.to_string(),
        changelog,
    })
}

/// Commits from `latest` back to (excluding) `current`, newest first, capped.
///
/// The clone is shallow, so the walk simply ends when history runs out; `with_hidden` handles
/// the case where `current` is still reachable.
fn changelog(
    repo: &gix::Repository,
    latest: gix::ObjectId,
    current: gix::ObjectId,
) -> gix::Result<Vec<ChangelogEntry>> {
    let mut entries = Vec::new();
    let walk = repo.rev_walk([latest]).with_hidden([current]).all()?;
    for info in walk.take(CHANGELOG_LIMIT as usize) {
        let info = info?;
        let commit = info.object()?;
        let summary = commit
            .message()
            .map(|message| message.summary().to_string())
            .unwrap_or_default();
        let time = commit.time().map(|time| time.seconds).unwrap_or_default();
        entries.push(ChangelogEntry {
            commit: info.id.to_string(),
            summary: truncate(&summary, 200),
            time,
        });
    }
    Ok(entries)
}

fn truncate(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Flatten a `gix` error for the wire: one line, bounded, backticks stripped.
fn sanitise(message: &str) -> String {
    let flat: String = message
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('`', "'");
    truncate(&flat, 300)
}
