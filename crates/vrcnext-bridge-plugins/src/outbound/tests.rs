//! What one request is allowed to be, checked without making one.
//!
//! Everything here is refusal: the shape of a request is decided before the client is touched, so
//! these run with no network and no server. That the happy path reaches the far end is not
//! something a unit test can claim honestly — it is checked against a real host in the bridge's
//! own end-to-end run.

#![allow(clippy::indexing_slicing)]

use serde_json::json;
use vrcnext_bridge_core::Service;

use super::{
    HttpError, HttpService, MAX_HEADERS, MAX_REQUEST_BYTES, check_header, parse_method, parse_url,
    read_capped,
};

#[test]
fn only_http_and_https_are_addressable() {
    assert!(parse_url("https://api.steampowered.com/x").is_ok());
    assert!(parse_url("http://example.test/x").is_ok());
    for bad in [
        "file:///etc/passwd",
        "ftp://example.test/x",
        "data:text/plain,hi",
        "not a url",
    ] {
        assert!(
            matches!(parse_url(bad), Err(HttpError::BadUrl(_))),
            "{bad} must be refused"
        );
    }
}

#[test]
fn the_method_defaults_to_get_and_is_one_of_a_fixed_set() {
    assert_eq!(
        parse_method(None).unwrap_or(reqwest::Method::TRACE),
        reqwest::Method::GET
    );
    assert_eq!(
        parse_method(Some("post")).unwrap_or(reqwest::Method::TRACE),
        reqwest::Method::POST
    );
    for bad in ["TRACE", "CONNECT", "OPTIONS", "GET /x", ""] {
        assert!(
            matches!(parse_method(Some(bad)), Err(HttpError::BadMethod(_))),
            "{bad} must be refused"
        );
    }
}

#[test]
fn connection_headers_belong_to_the_bridge() {
    for name in [
        "Host",
        "host",
        "Content-Length",
        "Connection",
        "Transfer-Encoding",
        "Upgrade",
    ] {
        assert!(
            matches!(check_header(name, "x"), Err(HttpError::BadHeader(_))),
            "{name} must be refused"
        );
    }
    assert!(check_header("Authorization", "Bearer abc").is_ok());
    assert!(check_header("X-Api-Key", "abc").is_ok());
}

#[test]
fn a_header_cannot_smuggle_a_newline_or_a_space_into_the_request() {
    assert!(matches!(
        check_header("X-Key", "a\r\nX-Other: b"),
        Err(HttpError::BadHeader(_))
    ));
    assert!(matches!(
        check_header("X Key", "a"),
        Err(HttpError::BadHeader(_))
    ));
    assert!(matches!(
        check_header("", "a"),
        Err(HttpError::BadHeader(_))
    ));
}

#[test]
fn an_oversized_request_body_is_refused_before_anything_is_sent() {
    let service = HttpService::new();
    let body = "x".repeat(MAX_REQUEST_BYTES + 1);
    let error = service.call(
        "fetch",
        json!({ "url": "https://example.test/", "method": "POST", "body": body }),
    );
    assert!(error.is_err());
    assert_eq!(error.err().map(|e| e.code()), Some("bad_request"));
}

#[test]
fn too_many_headers_are_refused() {
    let service = HttpService::new();
    let mut headers = serde_json::Map::new();
    for index in 0..=MAX_HEADERS {
        headers.insert(format!("X-H{index}"), json!("v"));
    }
    let error = service.call(
        "fetch",
        json!({ "url": "https://example.test/", "headers": headers }),
    );
    assert_eq!(error.err().map(|e| e.code()), Some("bad_request"));
}

#[test]
fn an_unknown_method_is_named_rather_than_attempted() {
    let service = HttpService::new();
    let error = service.call("post", json!({}));
    assert_eq!(error.err().map(|e| e.code()), Some("unknown_method"));
}

#[test]
fn describe_states_the_reach_it_has() {
    let service = HttpService::new();
    let described = service.describe();
    assert_eq!(service.name(), "outbound");
    assert!(
        described["reach"]
            .as_str()
            .is_some_and(|text| text.contains("cross-origin"))
    );
    assert!(
        described["methods"]
            .as_array()
            .is_some_and(|list| list.len() == 1)
    );
}

#[test]
fn describe_states_that_redirects_are_not_followed() {
    let described = HttpService::new().describe();
    assert!(
        described["redirects"]
            .as_str()
            .is_some_and(|text| text.starts_with("not followed"))
    );
}

#[test]
fn a_body_is_refused_once_it_passes_the_cap_while_streaming() {
    assert_eq!(read_capped(&b"abcd"[..], 4).ok(), Some(b"abcd".to_vec()));
    assert_eq!(
        read_capped(&b"abcde"[..], 4).err(),
        Some(HttpError::ResponseTooLarge)
    );
    // An endless source ends at the cap plus one, rather than filling memory.
    assert_eq!(
        read_capped(std::io::repeat(b'x'), 1024).err(),
        Some(HttpError::ResponseTooLarge)
    );
}
