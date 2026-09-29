#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use axum::http::HeaderMap;

use super::{Caller, Guard, OriginPolicy};

fn policy() -> OriginPolicy {
    OriginPolicy::new(vec!["https://vrcnext.example".to_owned()])
}

fn guard() -> Guard {
    use clap::Parser as _;
    let config =
        crate::config::Config::parse_from(["vrcnext-bridge", "--rate", "1", "--burst", "3"]);
    Guard::new(&config, "t".repeat(64))
}

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, value.parse().unwrap());
    }
    map
}

#[test]
fn callers_are_classified_by_what_the_browser_sent() {
    let g = guard();
    assert_eq!(g.caller(&headers(&[])), Caller::Trusted);
    assert_eq!(
        g.caller(&headers(&[("origin", "http://localhost:9000")])),
        Caller::Trusted
    );
    assert_eq!(
        g.caller(&headers(&[("sec-fetch-site", "none")])),
        Caller::Trusted
    );
    assert_eq!(
        g.caller(&headers(&[("origin", "https://evil.example")])),
        Caller::Untrusted
    );
    // An <img> from another site: fetch metadata, no Origin.
    assert_eq!(
        g.caller(&headers(&[("sec-fetch-site", "cross-site")])),
        Caller::Untrusted
    );
}

#[test]
fn another_site_cannot_drain_the_pages_bucket() {
    let g = guard();
    for _ in 0..50 {
        let _ = g.check_rate(Caller::Untrusted);
    }
    assert!(g.check_rate(Caller::Untrusted).is_err());
    assert_eq!(g.check_rate(Caller::Trusted), Ok(()));
    // And an authenticated socket has a bucket of its own, whatever HTTP did.
    for _ in 0..50 {
        let _ = g.check_rate(Caller::Trusted);
    }
    assert!(g.session_limiter().try_acquire());
}

#[test]
fn accepts_loopback_origins_on_any_port() {
    for origin in [
        "http://localhost:9000",
        "http://127.0.0.1:1234",
        "http://LOCALHOST:22500",
        "https://127.0.0.1",
        "http://[::1]:8080",
        "http://127.9.9.9:80",
    ] {
        assert!(policy().allows(origin), "should allow {origin}");
    }
}

#[test]
fn rejects_hosts_that_merely_contain_localhost() {
    for origin in [
        "http://localhost.example.com",
        "http://notlocalhost",
        "http://evil.com#localhost",
        "http://127.0.0.1.example.com",
        "http://user@localhost:80",
        "http://localhost:80/path",
    ] {
        assert!(!policy().allows(origin), "should reject {origin}");
    }
}

#[test]
fn rejects_non_http_schemes_and_null() {
    for origin in ["null", "file://", "chrome-extension://abc", ""] {
        assert!(!policy().allows(origin), "should reject {origin}");
    }
}

#[test]
fn rejects_public_addresses() {
    assert!(!policy().allows("http://192.168.2.11:8080"));
    assert!(!policy().allows("https://example.com"));
}

#[test]
fn honours_explicitly_allowed_origins_exactly() {
    assert!(policy().allows("https://vrcnext.example"));
    assert!(!policy().allows("https://vrcnext.example.evil.com"));
}
