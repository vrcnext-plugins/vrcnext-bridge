//! The inbound transport: a small threaded HTTP server over loopback.
//!
//! HTTP because it is the only thing VRCNext's page can speak — `fetch` and nothing else. The
//! server itself is deliberately dull; everything security-relevant lives in [`guard`], and
//! everything capability-relevant lives behind [`ServiceRegistry`].

pub(crate) mod guard;
pub(crate) mod respond;
pub(crate) mod route;

use std::io::Read as _;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use serde_json::Value;
use tiny_http::{Header, Method, Request, Server};
use vrcnext_bridge_core::{ServiceRegistry, limits};

use crate::config::Config;
use guard::{Guard, Refusal};
use respond::{cors_headers, reply, reply_json};
use route::Route;

/// A running bridge.
pub(crate) struct BridgeServer {
    server: Arc<Server>,
    guard: Arc<Guard>,
    services: Arc<ServiceRegistry>,
    threads: usize,
}

impl BridgeServer {
    /// Bind the listener.
    ///
    /// # Errors
    ///
    /// Fails if the address is already in use or cannot be bound.
    pub(crate) fn bind(config: &Config, services: ServiceRegistry) -> Result<Self> {
        let server = Server::http(config.listen)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .with_context(|| format!("failed to listen on {}", config.listen))?;

        Ok(Self {
            server: Arc::new(server),
            guard: Arc::new(Guard::new(config)),
            services: Arc::new(services),
            threads: config.worker_threads(),
        })
    }

    /// Serve until the process is stopped.
    ///
    /// Each worker owns a clone of the `Arc`s and pulls from the shared accept queue. Work per
    /// request is short and I/O-bound, so a small fixed pool beats an async runtime here and keeps
    /// the dependency surface — and the audit surface — smaller.
    ///
    /// # Errors
    ///
    /// Fails only if a worker thread cannot be spawned.
    pub(crate) fn serve(&self) -> Result<()> {
        std::thread::scope(|scope| {
            for index in 0..self.threads {
                let server = Arc::clone(&self.server);
                let guard = Arc::clone(&self.guard);
                let services = Arc::clone(&self.services);
                std::thread::Builder::new()
                    .name(format!("bridge-worker-{index}"))
                    .spawn_scoped(scope, move || worker(&server, &guard, &services))
                    .context("failed to spawn worker thread")?;
            }
            Ok(())
        })
    }
}

/// One worker's accept loop.
///
/// A panic while handling a request unwinds into [`std::panic::catch_unwind`] rather than taking
/// the worker — and with it a share of the daemon's capacity — down with it. The lint set makes
/// panics very unlikely; this is the backstop for the ones that are not.
fn worker(server: &Server, guard: &Guard, services: &ServiceRegistry) {
    loop {
        let request = match server.recv() {
            Ok(request) => request,
            Err(error) => {
                log::error!("accept failed: {error}");
                continue;
            }
        };

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle(request, guard, services);
        }));
        if outcome.is_err() {
            log::error!("a request handler panicked; the worker is continuing");
        }
    }
}

/// Route, guard, dispatch, respond.
fn handle(request: Request, guard: &Guard, services: &ServiceRegistry) {
    // An access log, at debug. Without it a working request is indistinguishable from one that
    // never arrived, which makes "is the page actually reaching me?" unanswerable — the first
    // question anyone debugging this will have. Only the method and path are logged: the path
    // carries no caller content, and the body may carry notification text.
    log::debug!("{} {}", request.method(), request.url());

    let cors = cors_headers(
        guard::header(&request, "origin")
            .filter(|origin| guard.origins().allows(origin))
            .as_deref(),
    );

    if let Err(refusal) = guard
        .check_rate()
        .and_then(|()| guard.check_admission(&request))
    {
        reply_json(
            request,
            refusal.status(),
            &refusal_body(&refusal),
            &with_retry_after(cors, &refusal),
        );
        return;
    }

    // The preflight. Answering it is what lets the browser send the real request; refusing it,
    // for an origin that is not allow-listed, is what stops a random web page reaching the bridge.
    if *request.method() == Method::Options {
        reply(request, 204, "", &cors);
        return;
    }

    match (request.method().clone(), Route::parse(request.url())) {
        (Method::Get, Route::Health) => {
            reply_json(request, 200, &health_body(services), &cors);
        }
        (Method::Get, Route::Describe) => {
            let body =
                serde_json::json!({ "version": crate::VERSION, "services": services.describe() });
            reply_json(request, 200, &body, &cors);
        }
        (Method::Post, Route::Call { service, method }) => {
            dispatch(request, services, &service, &method, &cors);
        }
        (_, Route::NotFound) => {
            reply_json(
                request,
                404,
                &error_body("not_found", "no such endpoint"),
                &cors,
            );
        }
        _ => {
            let body = error_body("method_not_allowed", "wrong HTTP method for this endpoint");
            reply_json(request, 405, &body, &cors);
        }
    }
}

/// Read the body under the size cap and hand it to a service.
fn dispatch(
    mut request: Request,
    services: &ServiceRegistry,
    service: &str,
    method: &str,
    cors: &[Header],
) {
    if let Err(refusal) = Guard::check_body(&request, limits::MAX_BODY_BYTES) {
        reply_json(request, refusal.status(), &refusal_body(&refusal), cors);
        return;
    }

    let params = match read_params(&mut request) {
        Ok(params) => params,
        Err((status, body)) => {
            reply_json(request, status, &body, cors);
            return;
        }
    };

    match services.call(service, method, params) {
        Ok(value) => reply_json(request, 200, &value, cors),
        Err(error) => {
            let body = error_body(error.code(), &error.to_string());
            reply_json(request, error.status(), &body, cors);
        }
    }
}

/// Read and parse the request body, or produce the response that should be sent instead.
fn read_params(request: &mut Request) -> Result<Value, (u16, Value)> {
    let body = read_body(request, limits::MAX_BODY_BYTES)
        .map_err(|refusal| (refusal.status(), refusal_body(&refusal)))?;

    if body.trim().is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_str(&body).map_err(|error| {
        (
            400,
            error_body("bad_request", &format!("invalid JSON: {error}")),
        )
    })
}

/// Read at most `max` bytes, refusing rather than truncating.
///
/// `Read::take` bounds this independently of the `Content-Length` header, so a caller that lies
/// about its length — or sends none at all — still cannot push unbounded bytes into memory.
fn with_retry_after(mut headers: Vec<Header>, refusal: &Refusal) -> Vec<Header> {
    if let Refusal::RateLimited(after) = refusal {
        let seconds = after.as_secs().max(1).to_string();
        if let Some(header) = guard::make_header("Retry-After", &seconds) {
            headers.push(header);
        }
    }
    headers
}

fn read_body(request: &mut Request, max: usize) -> Result<String, Refusal> {
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut buffer = Vec::new();
    if request
        .as_reader()
        .take(limit)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return Err(Refusal::PayloadTooLarge);
    }
    if buffer.len() > max {
        return Err(Refusal::PayloadTooLarge);
    }
    String::from_utf8(buffer).map_err(|_| Refusal::MalformedBody)
}

fn health_body(services: &ServiceRegistry) -> Value {
    serde_json::json!({
        "ok": true,
        "version": crate::VERSION,
        "services": services.services().map(|service| service.name()).collect::<Vec<_>>(),
    })
}

fn error_body(code: &str, message: &str) -> Value {
    serde_json::json!({ "ok": false, "error": { "code": code, "message": message } })
}

fn refusal_body(refusal: &Refusal) -> Value {
    error_body(refusal.code(), refusal.message())
}
