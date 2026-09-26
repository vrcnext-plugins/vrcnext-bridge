//! The request guard: who is allowed to talk to this daemon, and how loudly.
//!
//! # The threat that actually matters
//!
//! A loopback HTTP daemon has three classes of caller:
//!
//! 1. **The VRCNext page.** The intended one.
//! 2. **Other processes running as this user.** They already have the user's privileges — they can
//!    call the notification daemon directly. The bridge grants them nothing new, *provided* no sink
//!    ever executes anything. That proviso is the rule in [`vrcnext_bridge_core::Sink`], and it is
//!    why it is written as an absolute.
//! 3. **Any web page in any browser on this machine.** This is the real one. A site the user
//!    happens to have open can issue cross-origin requests to `127.0.0.1`. CORS stops it *reading*
//!    the response, but a "simple" request is still **delivered** — and delivery is the whole
//!    effect here. Refusing to read the reply is no comfort when the payload already appeared in
//!    someone's headset.
//!
//! The defence against (3) is to make every request non-simple, so the browser must preflight it
//! and the preflight can be refused:
//!
//! - `POST` bodies must be `application/json`. That content type is not on the simple-request list,
//!   so a browser sends `OPTIONS` first.
//! - The preflight is answered only for allow-listed origins, and `Access-Control-Allow-Origin` is
//!   never set to `*` and never reflects an arbitrary `Origin`.
//! - A request carrying an `Origin` header that is not allow-listed is refused outright, preflight
//!   or not.
//!
//! A request with **no** `Origin` header is allowed: that is a native caller (curl, a script, a
//! future non-browser client), which is class (2) and gains nothing by being here.
//!
//! # WebSockets are not protected by CORS
//!
//! A browser will complete a `ws://127.0.0.1` handshake from any page, with no preflight and no
//! `Access-Control-Allow-Origin` to withhold. What it *does* send is an `Origin` header, and
//! checking it server-side is the only defence. The guard therefore runs as middleware in front of
//! every route, the upgrade included: an upgrade from an origin that is not allow-listed is
//! answered 403 before a single frame is read.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use vrcnext_bridge_core::RateLimiter;

use super::respond::{add_header, cors_headers, error};
use crate::config::Config;

/// Why a request was refused before it reached a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The `Origin` header is not allow-listed.
    ForbiddenOrigin,
    /// A bearer token is required and was absent or wrong.
    Unauthorized,
    /// The body was not `application/json`.
    UnsupportedMediaType,
    /// The body exceeded the size limit.
    PayloadTooLarge,
    /// The body was not valid UTF-8.
    MalformedBody,
    /// The rate limit was hit.
    RateLimited(Duration),
}

impl Refusal {
    /// HTTP status for this refusal.
    #[must_use]
    pub(crate) const fn status(&self) -> u16 {
        match self {
            Self::ForbiddenOrigin => 403,
            Self::Unauthorized => 401,
            Self::UnsupportedMediaType => 415,
            Self::PayloadTooLarge => 413,
            Self::MalformedBody => 400,
            Self::RateLimited(_) => 429,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::ForbiddenOrigin => "forbidden_origin",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::PayloadTooLarge => "payload_too_large",
            Self::MalformedBody => "malformed_body",
            Self::RateLimited(_) => "rate_limited",
        }
    }

    /// Caller-facing explanation. Never echoes anything the caller sent.
    #[must_use]
    pub(crate) const fn message(&self) -> &'static str {
        match self {
            Self::ForbiddenOrigin => "this origin is not allowed to use the bridge",
            Self::Unauthorized => "a valid bearer token is required",
            Self::UnsupportedMediaType => "request body must be application/json",
            Self::PayloadTooLarge => "request body is too large",
            Self::MalformedBody => "request body must be valid UTF-8",
            Self::RateLimited(_) => "too many requests",
        }
    }
}

/// Which origins may use the bridge.
pub(crate) struct OriginPolicy {
    extra: Vec<String>,
}

impl OriginPolicy {
    /// Loopback origins, plus any exact values the user added with `--allow-origin`.
    #[must_use]
    pub(crate) fn new(extra: Vec<String>) -> Self {
        Self { extra }
    }

    /// Whether `origin` may call the bridge.
    ///
    /// VRCNext's local HTTP port varies between installs and settings, so the policy is "any
    /// loopback origin" rather than one pinned port. Widening it to a specific port would break
    /// on the user's next port change; widening it to `*` would hand the bridge to the internet.
    #[must_use]
    pub(crate) fn allows(&self, origin: &str) -> bool {
        if self.extra.iter().any(|allowed| allowed == origin) {
            return true;
        }
        Self::is_loopback_origin(origin)
    }

    /// Parse an `Origin` strictly enough that `http://localhost.example.com` cannot pass as
    /// `localhost`. Host matching is exact, never a suffix or prefix test.
    fn is_loopback_origin(origin: &str) -> bool {
        let Some(authority) = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
        else {
            return false;
        };
        // An Origin has no path, no query and no userinfo. Anything that does is not one.
        if authority.contains('/') || authority.contains('?') || authority.contains('@') {
            return false;
        }

        let host = if let Some(rest) = authority.strip_prefix('[') {
            match rest.split_once(']') {
                Some((inner, tail)) if tail.is_empty() || tail.starts_with(':') => inner,
                _ => return false,
            }
        } else {
            authority.split(':').next().unwrap_or(authority)
        };

        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }
}

/// Everything checked before a request reaches a service.
pub(crate) struct Guard {
    origins: OriginPolicy,
    token: Option<String>,
    limiter: RateLimiter,
}

impl Guard {
    /// Build the guard from configuration.
    #[must_use]
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            origins: OriginPolicy::new(config.allow_origins.clone()),
            token: config.token.clone(),
            limiter: RateLimiter::new(config.rate, config.burst),
        }
    }

    /// Take a rate-limit token.
    ///
    /// Applies to **every** request, not just the ones that deliver something. `/v1/health` is
    /// cheap, but "cheap" times an unbounded request rate is still a busy loop in a daemon the
    /// user did not ask to think about.
    ///
    /// # Errors
    ///
    /// [`Refusal::RateLimited`] when the bucket is empty.
    pub(crate) fn check_rate(&self) -> Result<(), Refusal> {
        if self.limiter.try_acquire() {
            Ok(())
        } else {
            Err(Refusal::RateLimited(self.limiter.retry_after()))
        }
    }

    /// Check origin and credentials. Applies to preflights as well as real requests.
    ///
    /// # Errors
    ///
    /// Returns the first [`Refusal`] that applies.
    pub(crate) fn check_admission(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        if let Some(origin) = header(headers, header::ORIGIN) {
            if !self.origins.allows(origin) {
                log::warn!("refused request from origin {}", origin.escape_debug());
                return Err(Refusal::ForbiddenOrigin);
            }
        }

        if let Some(expected) = &self.token {
            let presented = header(headers, header::AUTHORIZATION)
                .and_then(|value| value.strip_prefix("Bearer "));
            if !presented.is_some_and(|token| constant_time_eq(token, expected)) {
                return Err(Refusal::Unauthorized);
            }
        }
        Ok(())
    }

    /// Check the things that only apply to a request with a body.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnsupportedMediaType`] if the content type is wrong — which is also what forces
    /// browsers to preflight — or [`Refusal::PayloadTooLarge`] if the declared length is over the
    /// limit. Rate limiting is handled separately by [`Guard::check_rate`], which covers every
    /// request rather than only those with a body.
    pub(crate) fn check_body(headers: &HeaderMap, max_bytes: usize) -> Result<(), Refusal> {
        let content_type = header(headers, header::CONTENT_TYPE).unwrap_or_default();
        let base = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if base != "application/json" {
            return Err(Refusal::UnsupportedMediaType);
        }

        let declared =
            header(headers, header::CONTENT_LENGTH).and_then(|v| v.parse::<usize>().ok());
        if declared.is_some_and(|declared| declared > max_bytes) {
            return Err(Refusal::PayloadTooLarge);
        }
        Ok(())
    }

    /// The `Origin` this request may be answered for, if it sent one that passes the policy.
    fn allowed_origin<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        header(headers, header::ORIGIN).filter(|origin| self.origins.allows(origin))
    }
}

/// The middleware in front of every route: rate limit, admission, preflight, CORS headers.
///
/// Order matters. The rate limit comes first so that a refused origin hammering the daemon still
/// costs it tokens; admission second so a preflight from a bad origin is refused rather than
/// answered; and the preflight answer third, so only an allow-listed origin ever gets its 204.
pub(crate) async fn middleware(
    State(guard): State<Arc<Guard>>,
    request: Request,
    next: Next,
) -> Response {
    // An access log, at debug. Without it a working request is indistinguishable from one that
    // never arrived, which makes "is the page actually reaching me?" unanswerable — the first
    // question anyone debugging this will have. Only the method and path are logged: the path
    // carries no caller content, and the body may carry notification text.
    log::debug!("{} {}", request.method(), request.uri().path());

    let cors = cors_headers(guard.allowed_origin(request.headers()));

    let mut response = match guard
        .check_rate()
        .and_then(|()| guard.check_admission(request.headers()))
    {
        Err(refusal) => refuse(&refusal),
        // The preflight. Answering it is what lets the browser send the real request; refusing
        // it, for an origin that is not allow-listed, is what stops a random page reaching us.
        Ok(()) if request.method() == Method::OPTIONS => StatusCode::NO_CONTENT.into_response(),
        Ok(()) => next.run(request).await,
    };

    response.headers_mut().extend(cors);
    response
}

/// The response for a refusal, with `Retry-After` when the caller should wait.
#[must_use]
pub(crate) fn refuse(refusal: &Refusal) -> Response {
    let mut response = error(refusal.status(), refusal.code(), refusal.message());
    if let Refusal::RateLimited(after) = refusal {
        add_header(
            &mut response,
            header::RETRY_AFTER,
            &after.as_secs().max(1).to_string(),
        );
    }
    response
}

/// A header's value as text, or `None` if absent or not UTF-8.
fn header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Compare two secrets without leaking their common prefix through timing.
///
/// The length difference is still observable, which is acceptable: the token is generated, not
/// user-chosen, and its length is not the secret.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use super::{OriginPolicy, constant_time_eq};

    fn policy() -> OriginPolicy {
        OriginPolicy::new(vec!["https://vrcnext.example".to_owned()])
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

    #[test]
    fn token_comparison_rejects_mismatches() {
        assert!(constant_time_eq("abcdef", "abcdef"));
        assert!(!constant_time_eq("abcdef", "abcdeg"));
        assert!(!constant_time_eq("abcdef", "abcde"));
    }
}
