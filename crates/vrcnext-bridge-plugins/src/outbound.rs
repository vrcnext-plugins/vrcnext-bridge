//! The `outbound` service: one HTTP request, made by the bridge rather than by the page.
//!
//! The page can only reach hosts that opt into cross-origin reads. Most plain HTTP APIs do not —
//! the Steam Web API, for one — so a plugin asking for them through `fetch` gets an opaque
//! network failure it cannot distinguish from the server being down. The bridge is not a browser
//! and is not bound by that rule, so a request routed through here reaches the same hosts a
//! `curl` on this machine would.
//!
//! That is deliberately more reach than the page has, and it is why the host asks the user about
//! the concrete host before every first request to it. This service does not decide who may call
//! it: by the time a call arrives the page has already been told yes. What it does own is the
//! shape of one request — the scheme, the size of what comes back, and how long it may take — and it never follows a redirect, since that would reach a host nobody approved.
//!
//! It is a service, not an endpoint. Like every other service it is reached over the shared
//! WebSocket; the bridge's own HTTP interface stays as small as it is and gains nothing here.
//!
//! Bodies are text in both directions. A response that is not valid UTF-8 is refused rather than
//! mangled: the plugin API is JSON end to end, and a binary payload has nowhere to go in it.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use vrcnext_bridge_core::{Service, ServiceError};

/// Largest response body accepted, before decompression is accounted for.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Largest request body accepted.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// Most request headers one call may set.
pub const MAX_HEADERS: usize = 32;

/// Deadline used when the caller names none.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Longest deadline a caller may ask for.
pub const MAX_TIMEOUT_MS: u64 = 120_000;

/// Headers the caller may not set: they describe the connection, not the request.
const REFUSED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
];

/// Why an `outbound` call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The URL did not parse, or is not `http(s)`.
    #[error("{0}")]
    BadUrl(String),
    /// The method is not a token, or is one this service does not make.
    #[error("{0} is not a method this service makes")]
    BadMethod(String),
    /// A header name or value is malformed, or the name is one the caller may not set.
    #[error("header {0}")]
    BadHeader(String),
    /// The request body is larger than [`MAX_REQUEST_BYTES`].
    #[error("request body exceeds {MAX_REQUEST_BYTES} bytes")]
    RequestTooLarge,
    /// The response is larger than [`MAX_RESPONSE_BYTES`].
    #[error("response exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    /// The response body is not valid UTF-8.
    #[error("response is not text")]
    NotText,
    /// The request did not complete.
    #[error("{0}")]
    Failed(String),
}

impl From<HttpError> for ServiceError {
    fn from(error: HttpError) -> Self {
        match error {
            HttpError::Failed(_) => Self::Unavailable(error.to_string()),
            other => Self::BadRequest(other.to_string()),
        }
    }
}

/// One outbound request, as the page describes it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// Methods this service makes. Anything else is refused rather than forwarded blindly.
const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// Outbound HTTP for plugins, over the bridge instead of the page.
///
/// The client is built on first use and then reused, so connections and the TLS session cache
/// are shared across calls. Building it needs a thread of its own, which is why it is not made
/// at startup: a bridge nobody asks for a request never pays for one.
#[derive(Debug, Default)]
pub struct HttpService {
    client: OnceLock<Result<reqwest::blocking::Client, String>>,
}

impl HttpService {
    /// A service with no client built yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            client: OnceLock::new(),
        }
    }

    fn client(&self) -> Result<&reqwest::blocking::Client, HttpError> {
        self.client
            .get_or_init(|| {
                reqwest::blocking::Client::builder()
                    // Identifies the bridge to the far end, so an operator seeing this traffic can
                    // tell what made it. The plugin may not override it.
                    .user_agent(concat!("vrcnext-bridge/", env!("CARGO_PKG_VERSION")))
                    // A redirect is handed back as it came. Following it would send the request
                    // to a host the user never approved, so the plugin sees the 3xx and its
                    // `location` header, and asks again — through the host's prompt — if it wants.
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|error| HttpError::Failed(error.clone()))
    }

    fn fetch(&self, params: Value) -> Result<Value, HttpError> {
        let request: Request =
            serde_json::from_value(params).map_err(|error| HttpError::BadUrl(error.to_string()))?;
        let url = parse_url(&request.url)?;
        let method = parse_method(request.method.as_deref())?;
        let body = request.body.unwrap_or_default();
        if body.len() > MAX_REQUEST_BYTES {
            return Err(HttpError::RequestTooLarge);
        }
        let timeout = Duration::from_millis(
            request
                .timeout_ms
                .unwrap_or(DEFAULT_TIMEOUT_MS)
                .clamp(1, MAX_TIMEOUT_MS),
        );

        let mut builder = self.client()?.request(method, url).timeout(timeout);
        if request.headers.len() > MAX_HEADERS {
            return Err(HttpError::BadHeader(format!("count exceeds {MAX_HEADERS}")));
        }
        for (name, value) in &request.headers {
            check_header(name, value)?;
            builder = builder.header(name, value);
        }
        if !body.is_empty() {
            builder = builder.body(body);
        }

        let response = builder
            .send()
            .map_err(|error| HttpError::Failed(error.to_string()))?;
        read_response(response)
    }
}

/// `http(s)` only, and absolute. Anything else never reaches the client.
pub(crate) fn parse_url(text: &str) -> Result<reqwest::Url, HttpError> {
    let url = reqwest::Url::parse(text).map_err(|error| HttpError::BadUrl(error.to_string()))?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(HttpError::BadUrl(format!("{other} is not http(s)"))),
    }
}

pub(crate) fn parse_method(text: Option<&str>) -> Result<reqwest::Method, HttpError> {
    let name = text.unwrap_or("GET").to_ascii_uppercase();
    if !METHODS.contains(&name.as_str()) {
        return Err(HttpError::BadMethod(name));
    }
    reqwest::Method::from_bytes(name.as_bytes()).map_err(|_| HttpError::BadMethod(name))
}

pub(crate) fn check_header(name: &str, value: &str) -> Result<(), HttpError> {
    let lower = name.to_ascii_lowercase();
    if REFUSED_HEADERS.contains(&lower.as_str()) {
        return Err(HttpError::BadHeader(format!("{name} is set by the bridge")));
    }
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(HttpError::BadHeader(format!("{name} is not a header name")));
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(HttpError::BadHeader(format!(
            "{name} has a control character in its value"
        )));
    }
    Ok(())
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Reads the response within [`MAX_RESPONSE_BYTES`], refusing anything that is not text.
fn read_response(response: reqwest::blocking::Response) -> Result<Value, HttpError> {
    let status = response.status();
    // Redirects are not followed, so this is the URL that was asked for.
    let final_url = response.url().to_string();
    let mut headers = Map::new();
    for (name, value) in response.headers() {
        if let Ok(text) = value.to_str() {
            headers.insert(name.as_str().to_owned(), Value::String(text.to_owned()));
        }
    }
    // Declared length first, so an oversized body is refused before it is read; the read is
    // bounded again because the declaration is the server's word, not a guarantee.
    let cap = u64::try_from(MAX_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if response.content_length().is_some_and(|len| len > cap) {
        return Err(HttpError::ResponseTooLarge);
    }
    let bytes = response
        .bytes()
        .map_err(|error| HttpError::Failed(error.to_string()))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(HttpError::ResponseTooLarge);
    }
    let body = String::from_utf8(bytes.to_vec()).map_err(|_| HttpError::NotText)?;
    Ok(json!({
        "status": status.as_u16(),
        "statusText": status.canonical_reason().unwrap_or(""),
        "ok": status.is_success(),
        "url": final_url,
        "headers": Value::Object(headers),
        "body": body,
    }))
}

impl Service for HttpService {
    fn name(&self) -> &'static str {
        "outbound"
    }

    fn summary(&self) -> &'static str {
        "One outbound HTTP request, made by the bridge rather than the page"
    }

    fn describe(&self) -> Value {
        json!({
            "methods": ["fetch"],
            "requestMethods": METHODS,
            "maxRequestBytes": MAX_REQUEST_BYTES,
            "maxResponseBytes": MAX_RESPONSE_BYTES,
            "maxHeaders": MAX_HEADERS,
            "defaultTimeoutMs": DEFAULT_TIMEOUT_MS,
            "maxTimeoutMs": MAX_TIMEOUT_MS,
            "bodies": "text",
            "redirects": "not followed; a 3xx is returned as-is, with its location header",
            // Stated because it is the whole point and the whole risk: this reaches what the
            // machine reaches, including its own network, which the page cannot.
            "reach": "whatever this machine can reach; not limited to hosts that allow cross-origin reads",
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "fetch" => Ok(self.fetch(params)?),
            other => Err(ServiceError::UnknownMethod {
                service: "outbound",
                method: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
#[path = "outbound/tests.rs"]
mod tests;
