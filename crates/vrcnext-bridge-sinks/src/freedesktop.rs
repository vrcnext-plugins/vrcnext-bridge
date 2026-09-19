//! The `freedesktop` sink: `org.freedesktop.Notifications.Notify` over the session bus.
//!
//! This is the desktop's own notification service — the thing that draws the toast on the monitor.
//! On a KDE session that is Plasma's daemon; elsewhere it is whatever implements the spec.
//!
//! It is a *separate sink* from [`wayvr`](crate::wayvr) even though an overlay that monitors the
//! session bus will mirror these into VR as well. Keeping them separate is what lets a plugin say
//! "VR only, and make it a tall translucent panel" — presentation this protocol cannot express —
//! without also lighting up the user's monitor.
//!
//! ## What it does not carry
//!
//! `height`, `opacity` and `alwaysShow` have no equivalent in the freedesktop spec and are
//! silently unused here; [`Sink::honours`] reports that, so a plugin can discover it at runtime
//! rather than wonder why a panel height did nothing. Base64 icon data is also not forwarded — the
//! spec's `image-data` hint takes a raw pixel buffer, not an encoded image, and guessing at a
//! decode would be inventing behaviour. Icon *names* work.

use std::collections::HashMap;

use vrcnext_bridge_core::{Notification, Sink, SinkError, SinkHealth, Urgency};
use zbus::blocking::Connection;
use zbus::zvariant::Value;

const NAME: &str = "freedesktop";
const BUS_NAME: &str = "org.freedesktop.Notifications";
const OBJECT_PATH: &str = "/org/freedesktop/Notifications";

/// Sends notifications to the session's freedesktop notification daemon.
pub struct FreedesktopSink {
    connection: Connection,
}

impl FreedesktopSink {
    /// Connect to the session bus.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Unavailable`] when there is no session bus — a headless session, or a
    /// service started without `DBUS_SESSION_BUS_ADDRESS`. That is a normal condition, not a bug,
    /// and the daemon simply starts without this sink.
    pub fn connect() -> Result<Self, SinkError> {
        let connection = Connection::session()
            .map_err(|error| SinkError::Unavailable(NAME, format!("no session bus: {error}")))?;
        Ok(Self { connection })
    }

    /// Milliseconds for the spec's `expire_timeout`, where `-1` means "daemon default".
    ///
    /// Written as a clamp rather than a cast because the input is a float: `as` on an
    /// out-of-range or non-finite float is exactly the kind of silent nonsense this daemon should
    /// not put on a bus. Validation already bounds the value; this is the second line.
    fn expire_timeout_ms(notification: &Notification) -> i32 {
        let Some(secs) = notification.timeout_secs else {
            return -1;
        };
        let ms = (f64::from(secs) * 1_000.0).round();
        if !ms.is_finite() || ms < 1.0 {
            return -1;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "clamped to i32::MAX on the line above, so the cast cannot truncate"
        )]
        {
            ms.min(f64::from(i32::MAX)) as i32
        }
    }

    const fn urgency_hint(urgency: Urgency) -> u8 {
        match urgency {
            Urgency::Low => 0,
            Urgency::Normal => 1,
            Urgency::Critical => 2,
        }
    }
}

impl Sink for FreedesktopSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn describe(&self) -> String {
        format!("Desktop notification daemon, D-Bus {BUS_NAME}")
    }

    fn honours(&self) -> &'static [&'static str] {
        &[
            "title",
            "content",
            "timeoutSecs",
            "icon",
            "sourceApp",
            "urgency",
            "sound",
        ]
    }

    /// [`SinkHealth::Up`] once connected.
    ///
    /// Unlike UDP, a live D-Bus connection is real evidence: it was established against a running
    /// bus, and a dropped connection surfaces as a delivery error rather than a silent no-op.
    fn health(&self) -> SinkHealth {
        SinkHealth::Up
    }

    fn deliver(&self, notification: &Notification) -> Result<(), SinkError> {
        let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
        hints.insert(
            "urgency",
            Value::U8(Self::urgency_hint(notification.urgency)),
        );
        if !notification.sound {
            hints.insert("suppress-sound", Value::Bool(true));
        }

        // A base64 payload is not a valid icon *name*; sending it would put a megabyte of text
        // into the daemon's icon lookup. Drop it and say so.
        let icon = match (&notification.icon, notification.use_base64_icon) {
            (Some(icon), false) => icon.as_str(),
            (Some(_), true) => {
                log::debug!(
                    "{NAME}: base64 icon dropped; the spec takes a pixel buffer, not an encoded image"
                );
                ""
            }
            (None, _) => "",
        };

        self.connection
            .call_method(
                Some(BUS_NAME),
                OBJECT_PATH,
                Some(BUS_NAME),
                "Notify",
                &(
                    notification.source_app.as_str(),
                    0_u32, // replaces_id: never replace; each call is its own notification
                    icon,
                    notification.title.as_str(),
                    notification.content.as_str(),
                    &[] as &[&str], // actions: none — the bridge has no way to route a click back
                    hints,
                    Self::expire_timeout_ms(notification),
                ),
            )
            .map_err(|error| SinkError::Rejected(NAME, error.to_string()))?;
        Ok(())
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
    use super::FreedesktopSink;
    use vrcnext_bridge_core::{NotifyRequest, Urgency};

    fn with_timeout(timeout_secs: Option<f32>) -> vrcnext_bridge_core::Notification {
        NotifyRequest {
            title: "t".to_owned(),
            timeout_secs,
            ..NotifyRequest::default()
        }
        .validate()
        .expect("validates")
    }

    #[test]
    fn absent_timeout_means_daemon_default() {
        assert_eq!(FreedesktopSink::expire_timeout_ms(&with_timeout(None)), -1);
    }

    #[test]
    fn zero_timeout_means_daemon_default() {
        assert_eq!(
            FreedesktopSink::expire_timeout_ms(&with_timeout(Some(0.0))),
            -1
        );
    }

    #[test]
    fn seconds_become_milliseconds() {
        assert_eq!(
            FreedesktopSink::expire_timeout_ms(&with_timeout(Some(2.5))),
            2_500
        );
    }

    #[test]
    fn urgency_maps_to_the_spec_hint() {
        assert_eq!(FreedesktopSink::urgency_hint(Urgency::Low), 0);
        assert_eq!(FreedesktopSink::urgency_hint(Urgency::Normal), 1);
        assert_eq!(FreedesktopSink::urgency_hint(Urgency::Critical), 2);
    }
}
