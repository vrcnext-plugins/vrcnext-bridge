//! Response construction.
//!
//! Two invariants live here, both small and both load-bearing:
//!
//! - `Access-Control-Allow-Origin` is either a single allow-listed origin or absent. Never `*`,
//!   never a reflection of whatever the caller sent.
//! - Every response body is JSON the daemon built. Caller-supplied bytes are never echoed back.

use tiny_http::{Header, Request, Response};

/// CORS headers for a response.
///
/// `allowed` is `Some` only when the request carried an `Origin` that passed the policy. When it
/// is `None`, no CORS headers are emitted at all — a browser will then block the response, which
/// is precisely the intended outcome for a page that should not be talking to the bridge.
#[must_use]
pub(crate) fn cors_headers(allowed: Option<&str>) -> Vec<Header> {
    let Some(origin) = allowed else {
        return Vec::new();
    };

    [
        ("Access-Control-Allow-Origin", origin),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        (
            "Access-Control-Allow-Headers",
            "content-type, authorization",
        ),
        ("Access-Control-Max-Age", "600"),
        // The origin varies, so caches must not serve one origin's response to another.
        ("Vary", "Origin"),
    ]
    .iter()
    .filter_map(|(name, value)| super::guard::make_header(name, value))
    .collect()
}

/// Send a response with an explicit body and content type.
pub(crate) fn reply(request: Request, status: u16, body: &str, headers: &[Header]) {
    let mut response = Response::from_string(body).with_status_code(status);
    for header in headers.iter().cloned() {
        response.add_header(header);
    }
    if let Some(header) = super::guard::make_header("Content-Type", "application/json") {
        response.add_header(header);
    }
    // Nothing here is cacheable, and a cached notification result would be actively confusing.
    if let Some(header) = super::guard::make_header("Cache-Control", "no-store") {
        response.add_header(header);
    }
    if let Err(error) = request.respond(response) {
        log::debug!("client went away before the response was written: {error}");
    }
}

/// Send a JSON value.
pub(crate) fn reply_json(
    request: Request,
    status: u16,
    body: &serde_json::Value,
    headers: &[Header],
) {
    match serde_json::to_string(body) {
        Ok(text) => reply(request, status, &text, headers),
        Err(error) => {
            log::error!("failed to encode response: {error}");
            reply(
                request,
                500,
                r#"{"ok":false,"error":{"code":"internal","message":"response encoding failed"}}"#,
                headers,
            );
        }
    }
}
