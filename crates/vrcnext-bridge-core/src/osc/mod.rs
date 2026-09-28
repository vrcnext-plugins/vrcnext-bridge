//! The `osc` service: send OSC to VRChat, and receive what it sends back.
//!
//! ```text
//! POST /v1/osc/send     send one message to VRChat's input port
//! POST /v1/osc/listen   bind the receive port and push every message to the page
//! POST /v1/osc/stop     release the receive port
//! POST /v1/osc/status   ports, whether the socket is up, and what it has seen
//! ```
//!
//! This exists because VRCNext's own OSC is Windows-only: it drops every `osc*` action before
//! the backend sees it, so on Linux a plugin asking VRCNext to send OSC is talking to nothing.
//! The sockets are the same sockets either way — VRChat listens on 9000 and sends to 9001 —
//! so the bridge can hold them where VRCNext will not.
//!
//! Only loopback is used, in both directions. OSC has no authentication of any kind, and a
//! bridge that sent to or accepted from an arbitrary address would be a hole with a plugin API
//! in front of it.

mod listener;
mod proto;

pub use proto::{
    MAX_ADDRESS, MAX_ARGS, OscRequestError, ReceivedArg, SendRequest, check_address, from_osc,
    to_osc,
};

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::pusher::Pusher;
use crate::service::{Service, ServiceError};

use listener::Listener;

/// The port VRChat listens on.
pub const DEFAULT_SEND_PORT: u16 = 9000;

/// The port VRChat sends to.
pub const DEFAULT_LISTEN_PORT: u16 = 9001;

/// Ports, for a caller that talks to something other than VRChat's defaults.
#[derive(Debug, Clone, Deserialize)]
struct PortRequest {
    port: Option<u16>,
}

/// Send and receive OSC on loopback.
pub struct OscService {
    pusher: Arc<dyn Pusher>,
    listener: Mutex<Option<Listener>>,
}

impl OscService {
    /// A service with nothing bound yet; the receive socket opens on the first `listen`.
    #[must_use]
    pub fn new(pusher: Arc<dyn Pusher>) -> Self {
        Self {
            pusher,
            listener: Mutex::new(None),
        }
    }

    /// Encode one message and put it on the wire.
    ///
    /// Takes no receiver: sending owns no state, because UDP has no connection to keep and a
    /// socket held open for it would be one more port bound for the life of the bridge.
    fn send(params: Value) -> Result<Value, ServiceError> {
        let request: SendRequest = serde_json::from_value(params)
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;
        let port = request.port.unwrap_or(DEFAULT_SEND_PORT);
        let message = request
            .into_message()
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;
        let packet = rosc::OscPacket::Message(message);
        let bytes = rosc::encoder::encode(&packet).map_err(|error| {
            ServiceError::BadRequest(format!("this message cannot be encoded as OSC: {error}"))
        })?;

        // A fresh ephemeral socket per send. UDP has no connection to keep, and holding one open
        // would be one more port bound for the life of the bridge.
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| ServiceError::Internal(format!("no local socket: {error}")))?;
        socket
            .send_to(&bytes, SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .map_err(|error| {
                ServiceError::Internal(format!("the message could not be sent: {error}"))
            })?;
        Ok(json!({ "ok": true, "bytes": bytes.len(), "port": port }))
    }

    /// Bind the receive port, or report the one already bound.
    fn listen(&self, params: Value) -> Result<Value, ServiceError> {
        let port = port_of(params)?.unwrap_or(DEFAULT_LISTEN_PORT);
        let mut held = self.listener.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = held.as_ref() {
            if existing.port() == port {
                return Ok(json!({ "ok": true, "port": existing.port(), "started": false }));
            }
            existing.stop();
        }
        let listener = Listener::start(port, Arc::clone(&self.pusher)).map_err(|error| {
            // The common case by far, and the one with an explanation the caller can act on.
            ServiceError::Unavailable(format!(
                "port {port} could not be opened: {error}. VRChat sends to it, so only one \
                 program can hold it."
            ))
        })?;
        let bound = listener.port();
        *held = Some(listener);
        Ok(json!({ "ok": true, "port": bound, "started": true }))
    }

    fn stop(&self) -> Value {
        let mut held = self.listener.lock().unwrap_or_else(PoisonError::into_inner);
        let was = held.take();
        if let Some(listener) = was.as_ref() {
            listener.stop();
        }
        json!({ "ok": true, "stopped": was.is_some() })
    }

    fn status(&self) -> Value {
        let held = self.listener.lock().unwrap_or_else(PoisonError::into_inner);
        held.as_ref().map_or_else(
            || json!({ "listening": false, "sendPort": DEFAULT_SEND_PORT }),
            |listener| {
                json!({
                    "listening": true,
                    "sendPort": DEFAULT_SEND_PORT,
                    "listenPort": listener.port(),
                    "received": listener.received(),
                    "dropped": listener.dropped(),
                })
            },
        )
    }
}

fn port_of(params: Value) -> Result<Option<u16>, ServiceError> {
    if params.is_null() || matches!(&params, Value::Object(map) if map.is_empty()) {
        return Ok(None);
    }
    let request: PortRequest = serde_json::from_value(params)
        .map_err(|error| ServiceError::BadRequest(error.to_string()))?;
    if request.port == Some(0) {
        return Err(ServiceError::BadRequest(
            "port 0 would bind an arbitrary port that nothing is sending to".to_owned(),
        ));
    }
    Ok(request.port)
}

impl Service for OscService {
    fn name(&self) -> &'static str {
        "osc"
    }

    fn summary(&self) -> &'static str {
        "Send and receive OSC on loopback, for hosts where VRCNext's own OSC is unavailable"
    }

    fn describe(&self) -> Value {
        json!({
            "methods": ["send", "listen", "stop", "status"],
            "sendPort": DEFAULT_SEND_PORT,
            "listenPort": DEFAULT_LISTEN_PORT,
            "event": "osc",
            "status": self.status(),
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "send" => Self::send(params),
            "listen" => self.listen(params),
            "stop" => Ok(self.stop()),
            "status" => Ok(self.status()),
            other => Err(ServiceError::UnknownMethod {
                service: "osc",
                method: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::float_cmp,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use std::net::UdpSocket;
    use std::time::Duration;

    use crate::pusher::RecordingPusher;

    use super::*;

    /// A socket standing in for VRChat: bound on loopback, told to give up rather than hang.
    fn vrchat() -> (UdpSocket, u16) {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("loopback is bindable in a test");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a read timeout can be set");
        let port = socket
            .local_addr()
            .expect("a bound socket has an address")
            .port();
        (socket, port)
    }

    fn service() -> (OscService, Arc<RecordingPusher>) {
        let pusher = Arc::new(RecordingPusher::default());
        (
            OscService::new(Arc::clone(&pusher) as Arc<dyn Pusher>),
            pusher,
        )
    }

    #[test]
    fn a_send_reaches_the_port_as_a_decodable_osc_message() {
        let (socket, port) = vrchat();
        let (osc, _) = service();

        let reply = osc
            .call(
                "send",
                json!({ "address": "/avatar/parameters/Seated", "args": [true], "port": port }),
            )
            .expect("the message is well formed");
        assert_eq!(reply["ok"], json!(true));

        let mut buffer = [0_u8; 1024];
        let (read, _) = socket.recv_from(&mut buffer).expect("the datagram arrives");
        let (_, packet) = rosc::decoder::decode_udp(&buffer[..read]).expect("it is OSC");
        let rosc::OscPacket::Message(message) = packet else {
            panic!("a single message was sent, not a bundle");
        };
        assert_eq!(message.addr, "/avatar/parameters/Seated");
        assert_eq!(message.args, vec![rosc::OscType::Bool(true)]);
    }

    #[test]
    fn a_whole_number_can_still_be_sent_as_a_float_by_naming_the_kind() {
        let (socket, port) = vrchat();
        let (osc, _) = service();
        osc.call(
            "send",
            json!({ "address": "/avatar/parameters/Scale", "args": [{ "kind": "float", "value": 1 }], "port": port }),
        )
        .expect("the message is well formed");

        let mut buffer = [0_u8; 1024];
        let (read, _) = socket.recv_from(&mut buffer).expect("the datagram arrives");
        let (_, packet) = rosc::decoder::decode_udp(&buffer[..read]).expect("it is OSC");
        let rosc::OscPacket::Message(message) = packet else {
            panic!("one message")
        };
        assert_eq!(
            message.args,
            vec![rosc::OscType::Float(1.0)],
            "a bare 1 would have gone as an int, which VRChat drops silently"
        );
    }

    #[test]
    fn an_address_that_is_not_one_is_refused_before_anything_is_sent() {
        let (osc, _) = service();
        for address in [
            "",
            "avatar/parameters/X",
            "/avatar/*",
            "/with space",
            "/nul\0",
        ] {
            let error = osc
                .call("send", json!({ "address": address }))
                .expect_err("this is not a usable OSC address");
            assert_eq!(error.code(), "bad_request", "for {address:?}");
        }
    }

    #[test]
    fn what_arrives_on_the_receive_port_is_pushed_to_the_page() {
        let pusher = Arc::new(RecordingPusher::default());
        let listener = Listener::start(0, Arc::clone(&pusher) as Arc<dyn Pusher>)
            .expect("an ephemeral port is bindable");

        let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("loopback is bindable");
        let packet = rosc::OscPacket::Message(rosc::OscMessage {
            addr: "/avatar/parameters/VRCEmote".to_owned(),
            args: vec![rosc::OscType::Int(3)],
        });
        let bytes = rosc::encoder::encode(&packet).expect("it encodes");
        sender
            .send_to(
                &bytes,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.port()),
            )
            .expect("the datagram is sent");

        // The receive loop is a thread; give it the room to wake up and forward one message.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while pusher.events().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let events = pusher.events();
        let (event, data) = events.first().expect("the message was pushed");
        assert_eq!(*event, "osc");
        assert_eq!(data["address"], json!("/avatar/parameters/VRCEmote"));
        assert_eq!(data["args"][0], json!({ "kind": "int", "value": 3 }));
    }

    /// A port nothing is using: bind an ephemeral one, note it, and let it go.
    fn free_port() -> u16 {
        let (socket, port) = vrchat();
        drop(socket);
        port
    }

    #[test]
    fn listening_twice_on_one_port_keeps_the_socket_that_is_already_open() {
        let (osc, _) = service();
        let port = free_port();
        let first = osc
            .call("listen", json!({ "port": port }))
            .expect("the port was free a moment ago");
        assert_eq!(first["started"], json!(true));
        assert_eq!(first["port"], json!(port));

        let second = osc
            .call("listen", json!({ "port": port }))
            .expect("the same port is already held by this service");
        assert_eq!(second["started"], json!(false), "the socket is not rebound");

        let status = osc.call("status", Value::Null).expect("status answers");
        assert_eq!(status["listening"], json!(true));
        assert_eq!(status["listenPort"], json!(port));

        assert_eq!(
            osc.call("stop", Value::Null).expect("stop answers")["stopped"],
            json!(true)
        );
        assert_eq!(
            osc.call("status", Value::Null).expect("status answers")["listening"],
            json!(false),
            "stop releases the port"
        );
    }

    #[test]
    fn port_zero_is_refused_because_nothing_would_be_sending_to_it() {
        let (osc, _) = service();
        let error = osc
            .call("listen", json!({ "port": 0 }))
            .expect_err("refused");
        assert_eq!(error.code(), "bad_request");
    }
}
