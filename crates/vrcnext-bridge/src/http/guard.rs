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

use std::time::Duration;

use tiny_http::{Header, Request};
use vrcnext_bridge_core::RateLimiter;

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

    /// The origin policy, for building CORS response headers.
    #[must_use]
    pub(crate) const fn origins(&self) -> &OriginPolicy {
        &self.origins
    }

    /// Check origin and credentials. Applies to preflights as well as real requests.
    ///
    /// # Errors
    ///
    /// Returns the first [`Refusal`] that applies.
    pub(crate) fn check_admission(&self, request: &Request) -> Result<(), Refusal> {
        if let Some(origin) = header(request, "origin") {
            if !self.origins.allows(&origin) {
                log::warn!("refused request from origin {}", origin.escape_debug());
                return Err(Refusal::ForbiddenOrigin);
            }
        }

        if let Some(expected) = &self.token {
            let presented = header(request, "authorization")
                .and_then(|value| value.strip_prefix("Bearer ").map(str::to_owned));
            if !presented.is_some_and(|token| constant_time_eq(&token, expected)) {
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
    /// browsers to preflight — [`Refusal::PayloadTooLarge`] if the declared length is over the
    /// limit, or [`Refusal::RateLimited`] if the bucket is empty.
    pub(crate) fn check_body(&self, request: &Request, max_bytes: usize) -> Result<(), Refusal> {
        let content_type = header(request, "content-type").unwrap_or_default();
        let base = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if base != "application/json" {
            return Err(Refusal::UnsupportedMediaType);
        }

        if request
            .body_length()
            .is_some_and(|declared| declared > max_bytes)
        {
            return Err(Refusal::PayloadTooLarge);
        }

        if !self.limiter.try_acquire() {
            return Err(Refusal::RateLimited(self.limiter.retry_after()));
        }
        Ok(())
    }
}

/// Case-insensitive header lookup.
///
/// `name` is `&'static str` because `HeaderField::equiv` requires it — which is fine, since every
/// header this daemon looks for is a literal.
pub(crate) fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv(name))
        .map(|header| header.value.as_str().to_owned())
}

/// Build a header, discarding malformed ones rather than panicking.
pub(crate) fn make_header(name: &str, value: &str) -> Option<Header> {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).ok()
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
