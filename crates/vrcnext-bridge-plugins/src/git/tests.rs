#![allow(
    clippy::unwrap_used,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{GitError, with_deadline};

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
