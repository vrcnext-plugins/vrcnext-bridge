#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::RateLimiter;

#[test]
fn allows_a_burst_then_denies() {
    let limiter = RateLimiter::new(1.0, 3);
    assert!(limiter.try_acquire());
    assert!(limiter.try_acquire());
    assert!(limiter.try_acquire());
    assert!(!limiter.try_acquire(), "burst should be exhausted");
}

#[test]
fn refills_over_time() {
    let limiter = RateLimiter::new(1_000.0, 1);
    assert!(limiter.try_acquire());
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(limiter.try_acquire(), "should have refilled");
}

#[test]
fn degenerate_configuration_does_not_wedge_shut() {
    let limiter = RateLimiter::new(f64::NAN, 0);
    assert!(limiter.try_acquire());
}
