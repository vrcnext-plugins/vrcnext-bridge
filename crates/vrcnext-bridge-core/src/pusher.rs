//! How a service tells the page something it did not ask for.
//!
//! Services are synchronous and know nothing about sockets. When one has news — a build finished,
//! an install moved on to its next step — it hands the event to a [`Pusher`] and carries on. The
//! transport implements the trait over its broadcast channel and delivers a `push{event,data}`
//! frame to every open socket; a test implements it with a `Vec` and asserts on what was pushed.
//!
//! Push is fire-and-forget by design: a service must not block on, or fail because of, a page
//! that is not listening.

use std::sync::Mutex;

use serde_json::Value;

/// A sink for unsolicited `push` frames.
pub trait Pusher: Send + Sync {
    /// Deliver `event` with `data` to every connected page. Never blocks, never fails.
    fn push(&self, event: &'static str, data: Value);
}

/// Drops everything. For tools and tests that have no page to talk to.
pub struct NullPusher;

impl Pusher for NullPusher {
    fn push(&self, _event: &'static str, _data: Value) {}
}

/// Records everything, for tests to assert on.
#[derive(Default)]
pub struct RecordingPusher {
    events: Mutex<Vec<(&'static str, Value)>>,
}

impl RecordingPusher {
    /// Everything pushed so far, in order.
    #[must_use]
    pub fn events(&self) -> Vec<(&'static str, Value)> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Pusher for RecordingPusher {
    fn push(&self, event: &'static str, data: Value) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((event, data));
    }
}
