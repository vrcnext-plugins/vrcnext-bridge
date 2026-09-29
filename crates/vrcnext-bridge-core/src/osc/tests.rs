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

    let sender =
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("loopback is bindable");
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
