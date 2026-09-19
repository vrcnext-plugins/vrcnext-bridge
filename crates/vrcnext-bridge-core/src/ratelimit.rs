//! A token bucket, shared across worker threads.
//!
//! This is a safety control, not a fairness one. A notification sink puts pixels in front of
//! someone wearing a headset; a loop calling `notify/send` without a limiter is, at best, an
//! accident that needs the user to take the headset off, and at worst a deliberate one from a page
//! that got past the request guard. The bucket caps sustained rate while still allowing a short
//! burst, which is what legitimate use actually looks like.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A monotonic token bucket. Cheap enough to take on every request.
pub struct RateLimiter {
    per_second: f64,
    burst: f64,
    state: Mutex<State>,
}

struct State {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// Refill `per_second` tokens per second, up to a ceiling of `burst`.
    ///
    /// Both are clamped to at least a small positive value: a zero or negative configuration would
    /// otherwise wedge the daemon shut, which is a worse failure than an over-permissive limit.
    #[must_use]
    pub fn new(per_second: f64, burst: u32) -> Self {
        let per_second = if per_second.is_finite() && per_second > 0.0 {
            per_second
        } else {
            1.0
        };
        let burst = f64::from(burst.max(1));
        Self {
            per_second,
            burst,
            state: Mutex::new(State {
                tokens: burst,
                last: Instant::now(),
            }),
        }
    }

    /// Take one token. `false` means the caller should be answered with 429.
    ///
    /// A poisoned mutex — only reachable if another thread panicked mid-update — is treated as
    /// "deny". Failing closed on a rate limiter is the correct direction, and it cannot deadlock
    /// or panic the caller.
    pub fn try_acquire(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            log::error!("rate limiter state poisoned; denying request");
            return false;
        };

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(state.last);
        state.last = now;
        state.tokens = (state.tokens + elapsed.as_secs_f64() * self.per_second).min(self.burst);

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Roughly how long until a token is available. For the `Retry-After` header.
    #[must_use]
    pub fn retry_after(&self) -> Duration {
        let Ok(state) = self.state.lock() else {
            return Duration::from_secs(1);
        };
        let missing = (1.0 - state.tokens).max(0.0);
        Duration::from_secs_f64((missing / self.per_second).clamp(0.0, 60.0))
    }
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
}
