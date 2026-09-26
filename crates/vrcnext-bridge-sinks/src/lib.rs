//! Concrete [`Sink`](vrcnext_bridge_core::Sink) implementations, and the native confirmation
//! prompt for the platforms that have a session bus.
//!
//! Two sinks ship today:
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
//! The freedesktop sink and the [`approve`] prompt exist only on unix: there is no session bus
//! elsewhere, and leaving them out is what lets the binary build for Windows.
//!
//! Neither sink executes anything. See the rule in [`vrcnext_bridge_core::Sink`].

#[cfg(unix)]
pub mod approve;
#[cfg(unix)]
pub mod freedesktop;
pub mod wayvr;

#[cfg(unix)]
pub use approve::FreedesktopApprover;
#[cfg(unix)]
pub use freedesktop::FreedesktopSink;
pub use wayvr::{DEFAULT_WAYVR_ADDR, WayvrSink};
