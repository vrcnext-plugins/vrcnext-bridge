//! What one request is allowed to be, checked without making one.
//!
//! Everything here is refusal: the shape of a request is decided before the client is touched, so
//! these run with no network and no server. That the happy path reaches the far end is not
//! something a unit test can claim honestly — it is checked against a real host in the bridge's
//! own end-to-end run.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use vrcnext_bridge_core::Service;

use super::{
    CREDENTIAL_HEADERS, HttpError, HttpService, MAX_HEADERS, MAX_REQUEST_BYTES,
    assert_no_credentials, check_header, is_public, outbound_headers, parse_method, parse_url,
    read_capped,
};

#[test]
fn only_http_and_https_are_addressable() {
    assert!(parse_url("https://api.steampowered.com/x").is_ok());
    assert!(parse_url("http://example.test/x").is_ok());
    assert!(parse_url("https://93.184.216.34/").is_ok());
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
        "User-Agent",
        "TE",
        "Trailer",
        "Keep-Alive",
        "Proxy-Connection",
    ] {
        assert!(
            matches!(check_header(name, "x"), Err(HttpError::BadHeader(_))),
            "{name} must be refused"
        );
    }
    // An API's own key header is the plugin's business; only the credentials this machine holds
    // are refused, and those are checked in their own test below.
    assert!(check_header("X-Api-Key", "abc").is_ok());
    assert!(check_header("X-Steam-Key", "abc").is_ok());
}

#[test]
fn a_credential_header_never_leaves_this_machine() {
    for name in [
        "Authorization",
        "authorization",
        "AUTHORIZATION",
        "Proxy-Authorization",
        "Cookie",
        "cookie",
        "Set-Cookie",
    ] {
        let refused = check_header(name, "Bearer abc");
        assert!(
            matches!(&refused, Err(HttpError::BadHeader(text)) if text.contains("credentials")),
            "{name} must be refused as a credential, got {refused:?}"
        );
        let map = BTreeMap::from([(name.to_owned(), "Bearer abc".to_owned())]);
        assert!(
            matches!(outbound_headers(&map), Err(HttpError::BadHeader(_))),
            "{name} must not survive into the header map"
        );
    }
}

#[test]
fn the_finished_request_is_re_checked_whoever_set_the_header() {
    // Not reachable through `fetch` — `outbound_headers` refuses first. This is the guard for the
    // header nobody asked for: a helper that copies an incoming map, a future feature with its
    // own reason. The map is built behind the caller's back, exactly as such a change would.
    for name in CREDENTIAL_HEADERS {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static(name),
            reqwest::header::HeaderValue::from_static("secret"),
        );
        assert!(
            matches!(
                assert_no_credentials(&headers),
                Err(HttpError::BadHeader(_))
            ),
            "{name} must be caught on the finished request"
        );
    }
    assert!(assert_no_credentials(&reqwest::header::HeaderMap::new()).is_ok());
}

#[test]
fn a_url_may_not_carry_credentials_of_its_own() {
    for url in [
        "https://user:token@api.example.com/x",
        "https://user@api.example.com/x",
        "https://:token@api.example.com/x",
    ] {
        let refused = parse_url(url);
        assert!(
            matches!(&refused, Err(HttpError::BadUrl(text)) if text.contains("credentials")),
            "{url} must be refused, got {refused:?}"
        );
    }
    assert!(
        parse_url("https://api.example.com/x?key=abc").is_ok(),
        "a key in the query is the API's own scheme"
    );
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
        described
            .get("reach")
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains("cross-origin"))
    );
    assert!(
        described
            .get("methods")
            .and_then(Value::as_array)
            .is_some_and(|list| list.len() == 1)
    );
}

#[test]
fn describe_states_that_redirects_are_not_followed() {
    let described = HttpService::new().describe();
    assert!(
        described
            .get("redirects")
            .and_then(Value::as_str)
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

#[test]
fn non_public_addresses_are_refused_as_literals() {
    for bad in [
        "http://127.0.0.1/",
        "http://2130706433/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://255.255.255.255/",
        "http://224.0.0.1/",
        "http://[::1]/",
        "http://[::]/",
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://[ff02::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[64:ff9b::a00:1]/",
    ] {
        assert!(
            matches!(parse_url(bad), Err(HttpError::NotPublic(_))),
            "{bad} must be refused"
        );
    }
    assert!(is_public("1.1.1.1".parse().unwrap_or([0, 0, 0, 0].into())));
    assert!(is_public(
        "2606:4700::1111".parse().unwrap_or([0, 0, 0, 0].into())
    ));
}

#[test]
fn a_name_that_resolves_to_this_machine_is_refused() {
    let error = HttpService::new().call("fetch", json!({ "url": "http://localhost:9/" }));
    let message = error.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("not a public address"), "{message}");
}
