//! The `outbound` service: one HTTP request, made by the bridge rather than by the page.
//!
//! The page can only reach hosts that opt into cross-origin reads. Most plain HTTP APIs do not —
//! the Steam Web API, for one — so a plugin asking for them through `fetch` gets an opaque
//! network failure it cannot distinguish from the server being down. The bridge is not a browser
//! and is not bound by that rule, so a request routed through here reaches the same hosts a
//! `curl` on this machine would.
//!
//! It does not reach this machine or its network, though: loopback, private, link-local and the
//! other non-public ranges are refused, both as literals in the URL and as what a name resolves
//! to (see [`is_public`]).
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
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use vrcnext_bridge_core::{Service, ServiceError};

/// Largest response body accepted, counted after decompression.
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
    /// The host is, or resolves only to, an address that is not on the public internet:
    /// loopback, a private or link-local network, or another range that names this machine or
    /// its neighbours rather than a server somewhere else.
    #[error("{0} is not a public address")]
    NotPublic(String),
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
                    // Every name is resolved here and only public addresses are handed on, so a
                    // name that resolves — or later re-resolves — to this machine or its network
                    // is never connected to.
                    .dns_resolver(Arc::new(PublicResolver))
                    // A proxy would be the one resolving the target, out of this check's sight.
                    .no_proxy()
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

        let response = builder.send().map_err(|error| send_error(&error))?;
        read_response(response)
    }
}

/// `http(s)` only, and absolute. Anything else never reaches the client.
pub(crate) fn parse_url(text: &str) -> Result<reqwest::Url, HttpError> {
    let url = reqwest::Url::parse(text).map_err(|error| HttpError::BadUrl(error.to_string()))?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(HttpError::BadUrl(format!("{other} is not http(s)"))),
    }
    // An address written into the URL never reaches the resolver, so it is checked here.
    let host = url
        .host_str()
        .ok_or_else(|| HttpError::BadUrl("the URL names no host".to_owned()))?;
    let literal = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    if let Some(ip) = literal.filter(|ip| !is_public(*ip)) {
        return Err(HttpError::NotPublic(ip.to_string()));
    }
    Ok(url)
}

/// Whether `ip` is an address on the public internet.
///
/// Refused: unspecified, loopback, private (RFC 1918 and `fc00::/7`), link-local (which holds
/// the cloud metadata address `169.254.169.254`, and `fe80::/10`), shared/CGNAT
/// (`100.64.0.0/10`), `0.0.0.0/8`, broadcast, reserved (`240.0.0.0/4`), multicast, and any IPv6
/// address that embeds one of those IPv4 addresses (IPv4-mapped, IPv4-compatible, NAT64).
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let [first, .., high, low] = segments;
            let embedded = ip.to_ipv4_mapped().or_else(|| {
                let prefix = matches!(
                    segments,
                    [0x64, 0xff9b, 0, 0, 0, 0, _, _] | [0, 0, 0, 0, 0, 0, _, _]
                );
                prefix.then(|| Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)))
            });
            if let Some(v4) = embedded {
                return is_public_v4(v4);
            }
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (second & 0xc0) == 64))
}

/// The address filter, as a resolver: only public addresses come out of it.
///
/// Doing it at resolution rather than once up front is what defeats DNS rebinding — there is no
/// second lookup between the check and the connect for a name to change its answer in.
struct PublicResolver;

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let lookup = host.clone();
            let found: Vec<SocketAddr> =
                tokio::task::spawn_blocking(move || (lookup.as_str(), 0).to_socket_addrs())
                    .await??
                    .collect();
            let public: Vec<SocketAddr> = found
                .iter()
                .copied()
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if public.is_empty() {
                let shown = found
                    .first()
                    .map_or_else(|| host.clone(), |addr| format!("{host} ({})", addr.ip()));
                return Err(Box::new(HttpError::NotPublic(shown)) as Box<_>);
            }
            let addrs: reqwest::dns::Addrs = Box::new(public.into_iter());
            Ok(addrs)
        })
    }
}

/// A failed send, with a refusal from [`PublicResolver`] brought back to its own variant.
fn send_error(error: &reqwest::Error) -> HttpError {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(refused) = current.downcast_ref::<HttpError>() {
            return refused.clone();
        }
        source = current.source();
    }
    HttpError::Failed(error.to_string())
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
    // The body is streamed through a limit one byte past the cap, after decompression: a body
    // that reaches the extra byte is refused, and nothing beyond it is ever buffered.
    let bytes = read_capped(response, MAX_RESPONSE_BYTES)?;
    let body = String::from_utf8(bytes).map_err(|_| HttpError::NotText)?;
    Ok(json!({
        "status": status.as_u16(),
        "statusText": status.canonical_reason().unwrap_or(""),
        "ok": status.is_success(),
        "url": final_url,
        "headers": Value::Object(headers),
        "body": body,
    }))
}

/// Reads `reader` to its end, refusing it once it yields more than `cap` bytes.
///
/// At most `cap + 1` bytes are ever read, however long the source is.
pub(crate) fn read_capped(reader: impl Read, cap: usize) -> Result<Vec<u8>, HttpError> {
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| HttpError::Failed(error.to_string()))?;
    if bytes.len() > cap {
        return Err(HttpError::ResponseTooLarge);
    }
    Ok(bytes)
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
            "reach": "public internet hosts, not limited to hosts that allow cross-origin reads; loopback, private, link-local, CGNAT, multicast and other non-public addresses are refused, by name or by literal",
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
