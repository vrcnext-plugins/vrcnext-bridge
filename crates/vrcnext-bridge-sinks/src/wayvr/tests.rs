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
