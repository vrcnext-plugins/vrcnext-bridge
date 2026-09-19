//! The `wayvr` sink: a UDP datagram carrying an XSOverlay-protocol message.
//!
//! # Provenance, stated plainly
//!
//! WayVR (wlx-overlay-s) contains a `wayvr::subsystem::notifications` module that binds
//! `127.0.0.1:42069` and deserialises a `struct XsoMessage with 13 elements`. Twelve of those
//! field names were recovered contiguously from the binary's serde metadata:
//!
//! ```text
//! messageType index volume audioPath timeout title content height opacity useBase64Icon
//! sourceApp alwaysShow
//! ```
//!
//! The thirteenth is **inferred to be `icon`** — it is the one field XSOverlay's published message
//! has that the recovered twelve do not, and `useBase64Icon` is meaningless without it. If that
//! inference is wrong, this sink's icons are ignored and everything else still works: the receiver
//! deserialises with serde defaults and tolerates a field it does not know.
//!
//! # What has actually been observed
//!
//! Messages from this sink have been delivered to a **running** WayVR bound to `127.0.0.1:42069`,
//! and it logged no parse error. That is the limit of what was verified — whether the panel
//! rendered, and whether `icon` is the right spelling, was **not** confirmed from inside the
//! headset. Treat the field list as "read out of a binary and accepted without complaint", not
//! "read out of a specification and seen working".

use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;

use serde::Serialize;
use vrcnext_bridge_core::{Notification, Sink, SinkError, SinkHealth};

/// Where WayVR listens by default.
pub const DEFAULT_WAYVR_ADDR: &str = "127.0.0.1:42069";

/// The practical ceiling for a UDP payload, minus headroom for IP and UDP headers.
const MAX_DATAGRAM_BYTES: usize = 65_000;

const NAME: &str = "wayvr";

/// XSOverlay's `messageType` for an ordinary notification. `2` is its media-player message, which
/// this bridge has no reason to send.
const MESSAGE_TYPE_NOTIFICATION: i32 = 1;

/// The on-the-wire message. Field names and order mirror what WayVR expects.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XsoMessage<'a> {
    message_type: i32,
    index: i32,
    volume: f32,
    audio_path: &'a str,
    timeout: f32,
    title: &'a str,
    content: &'a str,
    height: f32,
    opacity: f32,
    use_base64_icon: bool,
    icon: &'a str,
    source_app: &'a str,
    always_show: bool,
}

/// Sends notifications to WayVR, or anything else speaking the XSOverlay UDP protocol.
pub struct WayvrSink {
    addr: SocketAddr,
    /// `UdpSocket::send_to` only needs `&self`, but keeping the socket behind a lock means a
    /// future re-bind on error does not need to change this type's public shape.
    socket: Mutex<UdpSocket>,
}

impl WayvrSink {
    /// Bind an ephemeral loopback socket pointed at `addr`.
    ///
    /// Binding to `127.0.0.1:0` rather than `0.0.0.0:0` is deliberate: this socket only ever talks
    /// to a local overlay, and a loopback-bound socket cannot be reached from the network.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Unavailable`] if the socket cannot be bound or connected.
    pub fn bind(addr: SocketAddr) -> Result<Self, SinkError> {
        if !addr.ip().is_loopback() {
            return Err(SinkError::Unavailable(
                NAME,
                format!("refusing to send notifications off-host, to {addr}"),
            ));
        }
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|error| SinkError::Unavailable(NAME, format!("bind failed: {error}")))?;
        socket
            .connect(addr)
            .map_err(|error| SinkError::Unavailable(NAME, format!("connect failed: {error}")))?;
        Ok(Self {
            addr,
            socket: Mutex::new(socket),
        })
    }

    /// Render a validated notification as an [`XsoMessage`] payload.
    fn encode(notification: &Notification) -> Result<Vec<u8>, SinkError> {
        let message = XsoMessage {
            message_type: MESSAGE_TYPE_NOTIFICATION,
            index: 0,
            volume: if notification.sound {
                notification.volume
            } else {
                0.0
            },
            audio_path: notification.audio_path.as_deref().unwrap_or_default(),
            // WayVR's own default applies when this is 0.0.
            timeout: notification.timeout_secs.unwrap_or(0.0),
            title: &notification.title,
            content: &notification.content,
            height: notification.height.unwrap_or(0.0),
            opacity: notification.opacity,
            use_base64_icon: notification.use_base64_icon,
            icon: notification.icon.as_deref().unwrap_or_default(),
            source_app: &notification.source_app,
            always_show: notification.always_show,
        };

        let bytes = serde_json::to_vec(&message)
            .map_err(|error| SinkError::Rejected(NAME, format!("encode failed: {error}")))?;

        if bytes.len() > MAX_DATAGRAM_BYTES {
            return Err(SinkError::Rejected(
                NAME,
                format!(
                    "message is {} bytes, over the {MAX_DATAGRAM_BYTES}-byte datagram limit; \
                     a base64 icon this large cannot be sent over UDP",
                    bytes.len()
                ),
            ));
        }
        Ok(bytes)
    }

    /// Whether **any** local socket holds `port`, according to `/proc/net/udp{,6}`.
    ///
    /// # What this does and does not tell you
    ///
    /// It answers "is that port taken", not "is WayVR listening and will it render". A different
    /// program squatting the port reads as `Up`. The useful half is the negative: nothing bound
    /// means a datagram is definitely going nowhere, which is worth surfacing.
    ///
    /// Only the port is compared, not the address. A socket bound to another interface entirely
    /// would be a false positive; matching the address would mean decoding `/proc`'s
    /// endian-swapped hex for v4, v6 and v4-mapped-v6, and then still having to treat wildcard
    /// binds as matches. Not worth the failure modes for an advisory signal.
    ///
    /// Returns `None` only when neither table could be read at all.
    #[cfg(target_os = "linux")]
    fn is_listener_bound(port: u16) -> Option<bool> {
        let suffix = format!(":{port:04X}");
        let mut read_any = false;

        for path in ["/proc/net/udp", "/proc/net/udp6"] {
            // A missing table is not a failure. IPv6 is routinely disabled, and letting that
            // discard a definitive answer from the IPv4 table reported Unknown on hosts where
            // the truth was perfectly knowable.
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            read_any = true;

            for line in content.lines().skip(1) {
                // `sl local_address rem_address st …` — the local address is the second column.
                //
                // The state column is deliberately not filtered on. A socket that has called
                // connect() shows `01` rather than `07`, and it still owns the port; requiring
                // `07` silently missed those.
                if line
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|local| local.ends_with(&suffix))
                {
                    return Some(true);
                }
            }
        }

        read_any.then_some(false)
    }
}

impl Sink for WayvrSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn describe(&self) -> String {
        format!("WayVR / XSOverlay protocol, UDP to {}", self.addr)
    }

    fn honours(&self) -> &'static [&'static str] {
        &[
            "title",
            "content",
            "timeoutSecs",
            "icon",
            "useBase64Icon",
            "sourceApp",
            "sound",
            "volume",
            "audioPath",
            "height",
            "opacity",
            "alwaysShow",
        ]
    }

    /// [`SinkHealth::Up`] if some local socket holds the target port, [`SinkHealth::Down`] if
    /// nothing does, or [`SinkHealth::Unknown`] where that cannot be determined.
    ///
    /// See [`WayvrSink::is_listener_bound`] for what this genuinely proves — the negative is
    /// trustworthy, the positive is only "the port is taken".
    fn health(&self) -> SinkHealth {
        #[cfg(target_os = "linux")]
        {
            match Self::is_listener_bound(self.addr.port()) {
                Some(true) => SinkHealth::Up,
                Some(false) => SinkHealth::Down,
                None => SinkHealth::Unknown,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            SinkHealth::Unknown
        }
    }

    fn deliver(&self, notification: &Notification) -> Result<(), SinkError> {
        let payload = Self::encode(notification)?;
        let socket = self
            .socket
            .lock()
            .map_err(|_| SinkError::Unavailable(NAME, "socket lock poisoned".to_owned()))?;

        let sent = socket
            .send(&payload)
            .map_err(|error| SinkError::Unavailable(NAME, error.to_string()))?;
        if sent != payload.len() {
            return Err(SinkError::Rejected(
                NAME,
                format!("short write: {sent} of {} bytes", payload.len()),
            ));
        }
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
    use super::{DEFAULT_WAYVR_ADDR, MAX_DATAGRAM_BYTES, WayvrSink};
    use vrcnext_bridge_core::{NotifyRequest, Sink};

    fn notification(request: NotifyRequest) -> vrcnext_bridge_core::Notification {
        request.validate().expect("request should validate")
    }

    fn base() -> NotifyRequest {
        NotifyRequest {
            title: "Friend online".to_owned(),
            ..NotifyRequest::default()
        }
    }

    #[test]
    fn encodes_all_thirteen_fields_in_camel_case() {
        let payload = WayvrSink::encode(&notification(base())).expect("encode");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("valid json");
        let object = json.as_object().expect("object");

        assert_eq!(object.len(), 13, "XsoMessage has 13 fields");
        for field in [
            "messageType",
            "index",
            "volume",
            "audioPath",
            "timeout",
            "title",
            "content",
            "height",
            "opacity",
            "useBase64Icon",
            "icon",
            "sourceApp",
            "alwaysShow",
        ] {
            assert!(object.contains_key(field), "missing `{field}`");
        }
    }

    #[test]
    fn silence_is_sent_as_zero_volume() {
        let request = NotifyRequest {
            sound: Some(false),
            volume: Some(1.0),
            ..base()
        };
        let payload = WayvrSink::encode(&notification(request)).expect("encode");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("valid json");
        assert_eq!(json["volume"], serde_json::json!(0.0));
    }

    #[test]
    fn oversized_icons_are_refused_rather_than_truncated() {
        let request = NotifyRequest {
            icon: Some("A".repeat(MAX_DATAGRAM_BYTES + 1)),
            use_base64_icon: Some(true),
            ..base()
        };
        let error = WayvrSink::encode(&notification(request)).expect_err("should refuse");
        assert!(error.to_string().contains("datagram limit"), "{error}");
    }

    #[test]
    fn refuses_a_non_loopback_target() {
        let addr = "192.0.2.1:42069".parse().expect("addr");
        let error = WayvrSink::bind(addr).err().expect("should refuse");
        assert!(error.to_string().contains("off-host"), "{error}");
    }

    #[test]
    fn default_address_is_parsable_and_loopback() {
        let addr: std::net::SocketAddr = DEFAULT_WAYVR_ADDR.parse().expect("addr");
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 42069);
    }

    /// The probe must be tested against a port the test itself controls.
    ///
    /// The original version asserted `Down` for WayVR's real port and then tried to bind it. That
    /// inverts whenever WayVR is actually running — the one configuration this feature exists to
    /// serve — so the suite went red exactly when the software worked. It passed in CI only
    /// because nothing was listening there.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_probe_sees_a_listener_appear_and_disappear() {
        // Port 0 lets the OS pick one that is definitely free, removing the assumption entirely.
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
        let port = listener.local_addr().expect("local addr").port();

        assert_eq!(
            WayvrSink::is_listener_bound(port),
            Some(true),
            "a socket we are holding open must read as bound"
        );

        drop(listener);
        assert_eq!(
            WayvrSink::is_listener_bound(port),
            Some(false),
            "the same port must read as free once released"
        );
    }

    /// Health is derived from the probe, whatever the machine happens to be running.
    #[test]
    fn health_agrees_with_the_probe() {
        let addr: std::net::SocketAddr = DEFAULT_WAYVR_ADDR.parse().expect("addr");
        let sink = WayvrSink::bind(addr).expect("bind");

        #[cfg(target_os = "linux")]
        {
            let expected = match WayvrSink::is_listener_bound(addr.port()) {
                Some(true) => vrcnext_bridge_core::SinkHealth::Up,
                Some(false) => vrcnext_bridge_core::SinkHealth::Down,
                None => vrcnext_bridge_core::SinkHealth::Unknown,
            };
            assert_eq!(sink.health(), expected);
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(sink.health(), vrcnext_bridge_core::SinkHealth::Unknown);
    }
}
