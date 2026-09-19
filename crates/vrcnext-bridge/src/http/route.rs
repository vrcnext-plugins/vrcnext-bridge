//! Path parsing. Deliberately tiny — the bridge has exactly three shapes of URL.

/// What a request path resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Route {
    /// `GET /v1/health`
    Health,
    /// `GET /v1/describe`
    Describe,
    /// `POST /v1/<service>/<method>`
    Call {
        /// Service name.
        service: String,
        /// Method name.
        method: String,
    },
    /// Anything else.
    NotFound,
}

/// Longest path segment accepted, so an unknown-service error cannot echo a huge string.
const MAX_SEGMENT_CHARS: usize = 64;

impl Route {
    /// Parse a request target.
    ///
    /// The query string is discarded: no bridge endpoint takes parameters that way, and accepting
    /// them would invite plugins to put notification text in a URL, where it would land in logs.
    #[must_use]
    pub(crate) fn parse(url: &str) -> Self {
        let path = url.split(['?', '#']).next().unwrap_or(url);
        let mut segments = path.split('/').filter(|segment| !segment.is_empty());

        if segments.next() != Some("v1") {
            return Self::NotFound;
        }

        let Some(first) = segments.next() else {
            return Self::NotFound;
        };

        match (first, segments.next(), segments.next()) {
            ("health", None, _) => Self::Health,
            ("describe", None, _) => Self::Describe,
            (service, Some(method), None) if is_name(service) && is_name(method) => Self::Call {
                service: service.to_owned(),
                method: method.to_owned(),
            },
            _ => Self::NotFound,
        }
    }
}

/// Service and method names are lowercase identifiers. Anything else is not a route this daemon
/// has, and refusing it here keeps odd bytes out of error messages and logs.
fn is_name(segment: &str) -> bool {
    !segment.is_empty()
        && segment.chars().count() <= MAX_SEGMENT_CHARS
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
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
    use super::Route;

    #[test]
    fn parses_the_three_real_shapes() {
        assert_eq!(Route::parse("/v1/health"), Route::Health);
        assert_eq!(Route::parse("/v1/describe"), Route::Describe);
        assert_eq!(
            Route::parse("/v1/notify/send"),
            Route::Call {
                service: "notify".to_owned(),
                method: "send".to_owned()
            }
        );
    }

    #[test]
    fn ignores_query_and_fragment() {
        assert_eq!(Route::parse("/v1/health?verbose=1"), Route::Health);
        assert_eq!(Route::parse("/v1/health#x"), Route::Health);
    }

    #[test]
    fn tolerates_redundant_slashes() {
        assert_eq!(Route::parse("//v1//health//"), Route::Health);
    }

    #[test]
    fn rejects_unversioned_and_overlong_paths() {
        assert_eq!(Route::parse("/notify/send"), Route::NotFound);
        assert_eq!(Route::parse("/v1/notify/send/extra"), Route::NotFound);
        assert_eq!(Route::parse("/"), Route::NotFound);
    }

    #[test]
    fn rejects_names_that_are_not_plain_identifiers() {
        for url in [
            "/v1/../etc/passwd",
            "/v1/notify/SEND",
            "/v1/notify/send%20x",
            "/v1/notify/../../x",
        ] {
            assert_eq!(Route::parse(url), Route::NotFound, "should reject {url}");
        }
    }
}
