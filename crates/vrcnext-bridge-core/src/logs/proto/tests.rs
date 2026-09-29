#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]

use super::{LogLevel, LogWriteRequest, MAX_BATCH_RECORDS};

fn request(json: serde_json::Value) -> LogWriteRequest {
    serde_json::from_value(json).expect("parses")
}

#[test]
fn strips_escape_sequences_rather_than_refusing_the_line() {
    let records = request(serde_json::json!({
        "records": [{ "level": "info", "message": "red \u{1b}[31malert" }]
    }))
    .validate()
    .expect("validates");

    assert_eq!(records[0].message, "red [31malert");
}

#[test]
fn an_embedded_newline_cannot_forge_a_second_entry() {
    let records = request(serde_json::json!({
        "records": [{ "level": "warn", "message": "line one\nERROR fake" }]
    }))
    .validate()
    .expect("validates");

    assert!(!records[0].message.contains('\n'));
}

#[test]
fn defaults_the_scope() {
    let records = request(serde_json::json!({
        "records": [{ "level": "info", "message": "hi" }]
    }))
    .validate()
    .expect("validates");

    assert_eq!(records[0].scope, "plugin");
}

#[test]
fn refuses_an_oversized_batch() {
    let records: Vec<serde_json::Value> = (0..=MAX_BATCH_RECORDS)
        .map(|_| serde_json::json!({ "level": "info", "message": "x" }))
        .collect();

    let error = request(serde_json::json!({ "records": records }))
        .validate()
        .expect_err("should refuse");
    assert!(error.to_string().contains("per batch"), "{error}");
}

#[test]
fn refuses_a_message_that_is_only_control_characters() {
    let error = request(serde_json::json!({
        "records": [{ "level": "info", "message": "\u{1b}\u{7}" }]
    }))
    .validate()
    .expect_err("should refuse");
    assert!(error.to_string().contains("empty"), "{error}");
}

#[test]
fn levels_are_padded_to_a_fixed_width() {
    for level in [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
    ] {
        assert_eq!(level.padded().len(), 5);
    }
}
