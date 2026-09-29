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

    /// Whether **any** local socket holds `port`, asked of the kernel by trying to bind it.
    ///
    /// # What this does and does not tell you
    ///
    /// It answers "is that port taken", not "is WayVR listening and will it render". A different
    /// program squatting the port reads as `Up`. The useful half is the negative: nothing bound
    /// means a datagram is definitely going nowhere, which is worth surfacing.
    ///
    /// # Why a bind and not `/proc/net/udp`
    ///
    /// The table in `/proc` is produced a page per `read`, and each read resumes by counting
    /// rows from the start. When sockets earlier in the table close between two reads, the count
    /// lands past rows it never showed, so a socket that is bound the whole time can be missing
    /// from the text. Any process creating and closing UDP sockets makes this happen; it cannot
    /// be read around. A bind is answered by the kernel's own port lookup, atomically.
    ///
    /// The probe binds the wildcard without `SO_REUSEADDR`, which conflicts with any socket on
    /// the port: IPv6 `[::]` first, which on Linux is dual-stack and so also collides with IPv4
    /// holders, then `0.0.0.0` for hosts with IPv6 off or a v6-only default. The socket is closed
    /// at once, so the port is held for the length of two syscalls.
    ///
    /// Returns `None` when neither bind gives an answer (a denied bind, say).
    #[cfg(target_os = "linux")]
    fn is_listener_bound(port: u16) -> Option<bool> {
        use std::io::ErrorKind;
        use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

        let mut answered = false;
        for addr in [
            std::net::SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
            std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        ] {
            match UdpSocket::bind(addr) {
                Ok(probe) => {
                    drop(probe);
                    answered = true;
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => return Some(true),
                // No IPv6 on this host, or a bind this process may not make: no answer here.
                Err(_) => {}
            }
        }
        answered.then_some(false)
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
    /// See `is_listener_bound` (private) for what this genuinely proves — the negative is
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
mod tests;
