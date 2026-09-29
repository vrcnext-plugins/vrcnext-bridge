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
//! answered 403 before a single frame is read. The pairing token is then presented in the first
//! frame — see [`vrcnext_bridge_core::handshake`] — because a browser cannot set headers on an
//! upgrade.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use vrcnext_bridge_core::RateLimiter;
use vrcnext_bridge_core::handshake::constant_time_eq;

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

/// Which rate-limit bucket a request is charged to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Caller {
    /// An allow-listed origin, or a native client that sent no browser headers at all.
    Trusted,
    /// A browser request from anywhere else: an origin that is not allow-listed (which is then
    /// refused), or a request a browser sent without an `Origin` — an `<img>` or `<link>` pointed
    /// at the bridge from some other site, which carries `Sec-Fetch-Site` but no `Origin`.
    Untrusted,
}

/// Everything checked before a request reaches a service.
///
/// There are two buckets, so that one caller cannot starve another. Any web page can make a
/// browser send requests here, and if those drew from the same bucket as the VRCNext page, a site
/// left open in another tab could keep the page answered with 429 indefinitely. So requests a
/// browser sent on behalf of some other site draw from their own bucket, and an authenticated
/// socket gets a bucket of its own for its calls (see [`Guard::session_limiter`]).
pub(crate) struct Guard {
    origins: OriginPolicy,
    token: String,
    rate: f64,
    burst: u32,
    limiter: RateLimiter,
    untrusted: RateLimiter,
}

impl Guard {
    /// Build the guard from configuration and the pairing token.
    #[must_use]
    pub(crate) fn new(config: &Config, token: String) -> Self {
        Self {
            origins: OriginPolicy::new(config.allow_origins.clone()),
            token,
            rate: config.rate,
            burst: config.burst,
            limiter: RateLimiter::new(config.rate, config.burst),
            untrusted: RateLimiter::new(config.rate, config.burst),
        }
    }

    /// A fresh bucket for one authenticated socket's calls, with the configured rate.
    ///
    /// Per connection, so a socket that has proven it holds the token is never slowed by traffic
    /// it did not send. The notification sinks still see at most this rate per connection.
    #[must_use]
    pub(crate) fn session_limiter(&self) -> RateLimiter {
        RateLimiter::new(self.rate, self.burst)
    }

    /// Classify a request by the headers a browser adds.
    #[must_use]
    pub(crate) fn caller(&self, headers: &HeaderMap) -> Caller {
        match header(headers, header::ORIGIN) {
            Some(origin) if self.origins.allows(origin) => Caller::Trusted,
            Some(_) => Caller::Untrusted,
            // No Origin. A native client sends no fetch metadata either; a browser always does,
            // and "none" means the user typed the URL, which is not another site acting.
            None => match header(headers, SEC_FETCH_SITE) {
                None | Some("none" | "same-origin") => Caller::Trusted,
                Some(_) => Caller::Untrusted,
            },
        }
    }

    /// The pairing token, for the socket handshake.
    #[must_use]
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// Charge one rate-limit token without asking whether one was available.
    ///
    /// A failed `hello` costs the peer as much as a request would: guessing tokens must not be
    /// free, and the bucket is the only thing on this path that slows a guesser down.
    pub(crate) fn penalise(&self) {
        let _ = self.limiter.try_acquire();
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
    pub(crate) fn check_rate(&self, caller: Caller) -> Result<(), Refusal> {
        let limiter = match caller {
            Caller::Trusted => &self.limiter,
            Caller::Untrusted => &self.untrusted,
        };
        if limiter.try_acquire() {
            Ok(())
        } else {
            Err(Refusal::RateLimited(limiter.retry_after()))
        }
    }

    /// Check the origin. Applies to preflights as well as real requests.
    ///
    /// # Errors
    ///
    /// [`Refusal::ForbiddenOrigin`] if an `Origin` is present and not allow-listed.
    pub(crate) fn check_origin(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        if let Some(origin) = header(headers, header::ORIGIN) {
            if !self.origins.allows(origin) {
                log::warn!("refused request from origin {}", origin.escape_debug());
                return Err(Refusal::ForbiddenOrigin);
            }
        }
        Ok(())
    }

    /// Require `Authorization: Bearer <token>`.
    ///
    /// Not part of the middleware, because a preflight cannot carry credentials and the health
    /// probe must answer before the page has a token to present. Every service call and the
    /// describe endpoint check it; the socket presents the same token in its `hello` instead.
    ///
    /// # Errors
    ///
    /// [`Refusal::Unauthorized`] if the header is absent or wrong.
    pub(crate) fn check_bearer(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let presented =
            header(headers, header::AUTHORIZATION).and_then(|value| value.strip_prefix("Bearer "));
        if presented.is_some_and(|token| constant_time_eq(token, &self.token)) {
            Ok(())
        } else {
            Err(Refusal::Unauthorized)
        }
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

/// The middleware in front of every route: rate limit, origin, preflight, CORS headers.
///
/// Order matters. The rate limit comes first so that a refused origin hammering the daemon still
/// costs it tokens — its own bucket's, never the page's; the origin check second so a preflight from a bad origin is refused rather
/// than answered; and the preflight answer third, so only an allow-listed origin ever gets its
/// 204. The bearer token is checked per route, not here: see [`Guard::check_bearer`].
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

    let caller = guard.caller(request.headers());
    let mut response = match guard
        .check_rate(caller)
        .and_then(|()| guard.check_origin(request.headers()))
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

/// Fetch metadata: which site a browser request was made on behalf of.
const SEC_FETCH_SITE: header::HeaderName = header::HeaderName::from_static("sec-fetch-site");

/// A header's value as text, or `None` if absent or not UTF-8.
fn header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
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
}
