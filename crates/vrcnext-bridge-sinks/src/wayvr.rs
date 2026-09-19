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

    /// Always [`SinkHealth::Unknown`].
    ///
    /// UDP is fire-and-forget: the socket being open says nothing about whether an overlay is
    /// listening on the other side. Reporting `Up` here would be a guess dressed as a fact.
    fn health(&self) -> SinkHealth {
        SinkHealth::Unknown
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

    #[test]
    fn health_is_unknown_because_udp_cannot_know() {
        let addr = DEFAULT_WAYVR_ADDR.parse().expect("addr");
        let sink = WayvrSink::bind(addr).expect("bind");
        assert_eq!(sink.health(), vrcnext_bridge_core::SinkHealth::Unknown);
    }
}
