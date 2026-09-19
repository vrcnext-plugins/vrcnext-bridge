//! A sink is one place a notification can land.
//!
//! Sinks are the notification service's own extension axis, orthogonal to
//! [`Service`](crate::service::Service). WayVR over UDP and the desktop's freedesktop daemon over
//! D-Bus are the two that ship; an XSOverlay client, a second overlay, a headless log target or
//! anything else slots in by implementing [`Sink`] and registering it.
//!
//! Sink names are the vocabulary plugins use to target one and not another
//! (`"sinks": ["wayvr"]`), so they are stable API. Name a sink after **what it talks to**, not
//! after the transport — `wayvr`, not `udp`.
//!
//! # The one rule for sink authors
//!
//! **A sink must never execute a program, open a shell, or write to a caller-chosen path.** The
//! bridge listens on loopback; the moment a sink can run a command, a notification request becomes
//! arbitrary code execution for anything that gets past the request guard. Sinks send structured
//! messages to services that already exist. There is no sanctioned exception, and a pull request
//! adding one will not be merged.

use crate::notify::proto::Notification;

/// Why a delivery attempt failed.
///
/// Reported to the caller as a per-sink failure, never as a 500 — one dead overlay must not make
/// the whole endpoint look broken.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The transport is not currently usable (socket gone, bus disconnected).
    #[error("{0} is unavailable: {1}")]
    Unavailable(&'static str, String),
    /// The message was rejected or could not be encoded.
    #[error("{0} rejected the notification: {1}")]
    Rejected(&'static str, String),
}

/// Whether a sink believes it can currently deliver.
///
/// Advisory only. Fire-and-forget UDP cannot know whether anything is listening, so
/// [`SinkHealth::Unknown`] is the honest answer there rather than a fabricated `Up`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkHealth {
    /// Connected, and a receiver is known to exist.
    Up,
    /// Open, but whether anything is listening cannot be determined.
    Unknown,
    /// Known to be unusable.
    Down,
}

impl SinkHealth {
    /// A short lowercase label for JSON responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Unknown => "unknown",
            Self::Down => "down",
        }
    }
}

/// One delivery target.
///
/// Shared across worker threads behind an `Arc`, hence `Send + Sync`. [`Sink::deliver`] takes
/// `&self` so a sink needing a mutable socket owns a lock over it, rather than forcing the service
/// to serialise every delivery.
pub trait Sink: Send + Sync {
    /// Stable name used in requests, overrides, responses and logs. Lowercase, no spaces.
    fn name(&self) -> &'static str;

    /// One line describing where this sink sends things, for `describe` and the startup banner.
    fn describe(&self) -> String;

    /// Which optional [`Notification`] fields this sink actually honours.
    ///
    /// Purely informational, and it is how a plugin discovers that panel height means something to
    /// `wayvr` and nothing to `freedesktop` without hard-coding that knowledge.
    fn honours(&self) -> &'static [&'static str];

    /// Cheap, non-blocking liveness guess. Must not perform a round trip.
    fn health(&self) -> SinkHealth;

    /// Deliver the notification.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError`] if the transport is unusable or the receiver rejected the message.
    fn deliver(&self, notification: &Notification) -> Result<(), SinkError>;
}
