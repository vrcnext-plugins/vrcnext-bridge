#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::{HelloRefusal, Welcome, check_hello, constant_time_eq};

const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

#[test]
fn a_correct_hello_is_accepted_with_its_client_string() {
    let frame =
        format!(r#"{{"type":"hello","token":"{TOKEN}","client":"vrcnext-plugin-system/0.2.0"}}"#);
    let accepted = check_hello(&frame, TOKEN).expect("accepted");
    assert_eq!(accepted.client, "vrcnext-plugin-system/0.2.0");
}

#[test]
fn a_wrong_token_is_unauthorized() {
    let frame = r#"{"type":"hello","token":"nope","client":"x"}"#;
    assert_eq!(
        check_hello(frame, TOKEN).expect_err("refused"),
        HelloRefusal::Unauthorized
    );
    assert_eq!(HelloRefusal::Unauthorized.close_reason(), "unauthorized");
}

#[test]
fn anything_but_a_hello_first_requires_a_hello() {
    for frame in [
        r#"{"type":"request","id":"1","service":"state","method":"get"}"#,
        r#"{"type":"logs","records":[]}"#,
        r#"{"type":"hello","token":"x"}"#,
        r#"{"type":"hello","token":"x","client":"c","extra":1}"#,
        "not json",
        "",
    ] {
        assert_eq!(
            check_hello(frame, TOKEN).expect_err("refused"),
            HelloRefusal::HelloRequired,
            "{frame}"
        );
    }
    assert_eq!(HelloRefusal::HelloRequired.close_reason(), "hello_required");
}

#[test]
fn the_client_string_is_bounded_and_escaped() {
    let long = "x".repeat(500);
    let frame = format!(r#"{{"type":"hello","token":"{TOKEN}","client":"{long}\n"}}"#);
    let accepted = check_hello(&frame, TOKEN).expect("accepted");
    assert_eq!(accepted.client.len(), super::MAX_CLIENT_CHARS);
    assert!(!accepted.client.contains('\n'));
}

#[test]
fn welcome_serialises_with_the_describe_payload() {
    let value = serde_json::to_value(Welcome::Welcome {
        version: "1.0.0",
        services: serde_json::json!({"state": {"summary": "s"}}),
    })
    .unwrap();
    assert_eq!(
        value,
        serde_json::json!({"type":"welcome","version":"1.0.0","services":{"state":{"summary":"s"}}})
    );
}

#[test]
fn token_comparison_rejects_mismatches() {
    assert!(constant_time_eq("abcdef", "abcdef"));
    assert!(!constant_time_eq("abcdef", "abcdeg"));
    assert!(!constant_time_eq("abcdef", "abcde"));
}
