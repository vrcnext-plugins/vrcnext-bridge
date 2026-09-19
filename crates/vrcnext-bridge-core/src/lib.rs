//! Core of `vrcnext-bridge`: a small, extensible capability host for VRCNext plugins.
//!
//! # What this is
//!
//! VRCNext's page cannot open a UDP socket, talk to D-Bus, or reach a unix socket. Anything a
//! plugin wants to do that requires one of those needs a native process on the other side of an
//! HTTP call. That process is `vrcnext-bridge`, and this crate is its brain.
//!
//! # Shape
//!
//! The bridge is **not** a notification daemon. It is a registry of [`Service`]s, each of which
//! exposes named methods:
//!
//! ```text
//! POST /v1/<service>/<method>
//! ```
//!
//! Notifications are simply the first service. A future OSC service, clipboard service or
//! process-presence service slots in beside it by implementing [`Service`] and registering — no
//! change to the transport, the request guard, the rate limiter or the wiring.
//!
//! Within the notification service there is a second axis of extension: **sinks**. A sink is one
//! place a notification can land — a VR overlay, the desktop's own notification daemon, something
//! not written yet. Callers choose per request:
//!
//! ```json
//! { "title": "Friend online", "sinks": ["wayvr"],
//!   "overrides": { "wayvr": { "height": 220.0, "opacity": 0.85 } } }
//! ```
//!
//! `sinks` selects targets; `overrides` lets one request carry different content and presentation
//! per target, so "a customised panel in VR and nothing on the desktop" is a single call.
//!
//! # No I/O here
//!
//! This crate performs no I/O. Transports live in `vrcnext-bridge` and concrete sinks in
//! `vrcnext-bridge-sinks`, which keeps validation, dispatch and rate limiting testable without a
//! D-Bus session, a VR runtime or a listening socket.

pub mod limits;
pub mod notify;
pub mod ratelimit;
pub mod service;

pub use notify::{
    Notification, NotifyRequest, NotifyService, Sink, SinkError, SinkHealth, Urgency,
    ValidationError,
};
pub use ratelimit::RateLimiter;
pub use service::{Service, ServiceError, ServiceRegistry};
