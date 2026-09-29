#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::{ClientMessage, EnvelopeError, Inbound, ServerMessage, is_name};

fn parse(text: &str) -> ClientMessage {
    serde_json::from_str(text).expect("valid frame")
}

#[test]
fn a_request_round_trips_with_its_id() {
    let inbound = parse(
        r#"{"type":"request","id":"7","service":"notify","method":"send","params":{"title":"x"}}"#,
    )
    .validate()
    .expect("valid");
    let Inbound::Request(request) = inbound else {
        panic!("expected a request");
    };
    assert_eq!(request.id, "7");
    assert_eq!(request.service, "notify");
    assert_eq!(request.method, "send");
    assert_eq!(request.params["title"], "x");
}

#[test]
fn missing_params_become_an_empty_object() {
    let Inbound::Request(request) =
        parse(r#"{"type":"request","id":"a","service":"notify","method":"targets"}"#)
            .validate()
            .expect("valid")
    else {
        panic!("expected a request");
    };
    assert!(
        request
            .params
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
}

#[test]
fn non_object_params_are_refused() {
    let error =
        parse(r#"{"type":"request","id":"a","service":"notify","method":"send","params":[1]}"#)
            .validate()
            .expect_err("should refuse");
    assert_eq!(error, EnvelopeError::BadParams);
}

#[test]
fn ids_are_bounded() {
    let long = "x".repeat(129);
    let frame = format!(r#"{{"type":"request","id":"{long}","service":"a","method":"b"}}"#);
    assert_eq!(
        parse(&frame).validate().expect_err("too long"),
        EnvelopeError::BadId
    );
    assert_eq!(
        parse(r#"{"type":"request","id":"","service":"a","method":"b"}"#)
            .validate()
            .expect_err("empty"),
        EnvelopeError::BadId
    );
}

#[test]
fn names_must_be_plain_identifiers() {
    for (service, method, field) in [
        ("Notify", "send", "service"),
        ("notify", "../x", "method"),
        ("", "send", "service"),
    ] {
        let frame =
            format!(r#"{{"type":"request","id":"1","service":"{service}","method":"{method}"}}"#);
        assert_eq!(
            parse(&frame).validate().expect_err("should refuse"),
            EnvelopeError::BadName(field)
        );
    }
    assert!(is_name("notify"));
    assert!(is_name("game_log-2"));
    assert!(!is_name(&"a".repeat(65)));
}

#[test]
fn unknown_frame_types_and_fields_are_refused() {
    assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"exec","id":"1"}"#).is_err());
    assert!(
        serde_json::from_str::<ClientMessage>(r#"{"type":"logs","records":[],"extra":1}"#).is_err()
    );
}

#[test]
fn a_log_batch_is_passed_through_for_the_log_validator() {
    let inbound = parse(r#"{"type":"logs","records":[{"level":"info","message":"hi"}]}"#)
        .validate()
        .expect("valid");
    let Inbound::Logs(records) = inbound else {
        panic!("expected logs");
    };
    assert_eq!(records.len(), 1);
}

#[test]
fn responses_serialise_flat_with_the_http_error_shape() {
    let ok = serde_json::to_value(ServerMessage::ok(
        "1".to_owned(),
        serde_json::json!({"n": 1}),
    ))
    .unwrap();
    assert_eq!(
        ok,
        serde_json::json!({"type":"response","id":"1","ok":true,"result":{"n":1}})
    );

    let err =
        serde_json::to_value(ServerMessage::error("2".to_owned(), "bad_request", "no")).unwrap();
    assert_eq!(
        err,
        serde_json::json!({"type":"response","id":"2","ok":false,"error":{"code":"bad_request","message":"no"}})
    );

    let push = serde_json::to_value(ServerMessage::Push {
        event: "log",
        data: serde_json::json!({"message":"x"}),
    })
    .unwrap();
    assert_eq!(
        push,
        serde_json::json!({"type":"push","event":"log","data":{"message":"x"}})
    );
}
