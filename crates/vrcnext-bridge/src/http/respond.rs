//! Response construction.
//!
//! Two invariants live here, both small and both load-bearing:
//!
//! - `Access-Control-Allow-Origin` is either a single allow-listed origin or absent. Never `*`,
//!   never a reflection of whatever the caller sent.
//! - Every response body is JSON the daemon built. Caller-supplied bytes are never echoed back.

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use serde_json::Value;

/// CORS headers for a response.
///
/// `allowed` is `Some` only when the request carried an `Origin` that passed the policy. When it
/// is `None`, no CORS headers are emitted at all — a browser will then block the response, which
/// is precisely the intended outcome for a page that should not be talking to the bridge.
#[must_use]
pub(crate) fn cors_headers(allowed: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let Some(origin) = allowed else {
        return headers;
    };
    let Ok(origin) = HeaderValue::from_str(origin) else {
        return headers;
    };
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, authorization"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    // The origin varies, so caches must not serve one origin's response to another.
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers
}

/// A JSON response with the daemon's standard headers.
///
/// Nothing the bridge answers is cacheable, and a cached notification result would be actively
/// confusing, so every response says so.
#[must_use]
pub(crate) fn json(status: u16, body: &Value) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let text = serde_json::to_string(body).unwrap_or_else(|error| {
        log::error!("failed to encode response: {error}");
        r#"{"ok":false,"error":{"code":"internal","message":"response encoding failed"}}"#
            .to_owned()
    });
    let mut response = (status, text).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `{ "ok": false, "error": { "code", "message" } }` — the one error shape, on both transports.
#[must_use]
pub(crate) fn error(status: u16, code: &str, message: &str) -> Response {
    json(
        status,
        &serde_json::json!({ "ok": false, "error": { "code": code, "message": message } }),
    )
}

/// Add a header, discarding a malformed value rather than panicking.
pub(crate) fn add_header(response: &mut Response, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(name, value);
    }
}
