//! Concrete [`Sink`](vrcnext_bridge_core::Sink) implementations.
//!
//! Two ship today:
//!
//! | Sink | Transport | Reaches |
//! | :--- | :--- | :--- |
//! | [`wayvr`] | UDP to `127.0.0.1:42069` | WayVR, and any other XSOverlay-protocol listener |
//! | [`freedesktop`] | D-Bus `org.freedesktop.Notifications` | The desktop's own notification daemon |
//!
//! They are separate sinks on purpose. The desktop route is what a user already sees on their
//! monitor — and, if they run an overlay that mirrors desktop notifications, incidentally in VR
//! too. The WayVR route goes straight to the overlay and supports presentation the desktop
//! protocol has no concept of: panel height, opacity, always-show-over-dashboard. A plugin that
//! wants a big translucent panel in VR *and nothing on the monitor* names `wayvr` alone.
//!
//! Neither sink executes anything. See the rule in [`vrcnext_bridge_core::Sink`].

pub mod freedesktop;
pub mod wayvr;

pub use freedesktop::FreedesktopSink;
pub use wayvr::{DEFAULT_WAYVR_ADDR, WayvrSink};
