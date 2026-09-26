//! The inbound transport: an `axum` server over loopback, on a `tokio` runtime.
//!
//! HTTP and WebSockets are the only things VRCNext's page can speak. The server itself is
//! deliberately dull; everything security-relevant lives in [`guard`], and everything
//! capability-relevant lives behind [`ServiceRegistry`]. Services stay synchronous and run on the
//! runtime's blocking pool, so a D-Bus round trip never stalls the sockets.

pub(crate) mod guard;
pub(crate) mod respond;
pub(crate) mod ws;

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::Value;
use vrcnext_bridge_core::envelope::is_name;
use vrcnext_bridge_core::logs::LogWriter;
use vrcnext_bridge_core::{ServiceError, ServiceRegistry, limits};

use crate::broadcast::Broadcaster;
use crate::config::Config;
use crate::startup::Wiring;
use guard::{Guard, Refusal, refuse};
use respond::{error, json};

/// Everything a handler can reach.
pub(crate) struct AppState {
    pub(crate) guard: Arc<Guard>,
    pub(crate) services: Arc<ServiceRegistry>,
    pub(crate) log_writer: Arc<dyn LogWriter>,
    pub(crate) broadcaster: Broadcaster,
}

/// Bind and serve until `SIGINT`.
///
/// # Errors
///
/// Fails if the address cannot be bound, or the server stops on an error.
pub(crate) async fn serve(config: &Config, wiring: Wiring, broadcaster: Broadcaster) -> Result<()> {
    let guard = Arc::new(Guard::new(config));
    let state = Arc::new(AppState {
        guard: Arc::clone(&guard),
        services: Arc::new(wiring.services),
        log_writer: wiring.log_writer,
        broadcaster,
    });

    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/describe", get(describe))
        .route("/v1/ws", get(ws::upgrade))
        .route("/v1/{service}/{method}", post(call))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::middleware::from_fn_with_state(
            guard,
            guard::middleware,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to listen on {}", config.listen))?;
    log::info!("listening on http://{}", config.listen);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                log::info!("shutting down");
            }
        })
        .await
        .context("server stopped")
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    json(
        200,
        &serde_json::json!({
            "ok": true,
            "version": crate::VERSION,
            "services": state.services.services().map(|service| service.name()).collect::<Vec<_>>(),
        }),
    )
}

async fn describe(State(state): State<Arc<AppState>>) -> Response {
    json(
        200,
        &serde_json::json!({
            "version": crate::VERSION,
            "socket": "/v1/ws",
            "services": state.services.describe(),
        }),
    )
}

async fn not_found() -> Response {
    error(404, "not_found", "no such endpoint")
}

async fn method_not_allowed() -> Response {
    error(
        405,
        "method_not_allowed",
        "wrong HTTP method for this endpoint",
    )
}

/// `POST /v1/<service>/<method>` — one call, for `curl` and anything else that is not the page.
async fn call(
    State(state): State<Arc<AppState>>,
    Path((service, method)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !is_name(&service) || !is_name(&method) {
        return not_found().await;
    }
    if let Err(refusal) = Guard::check_body(&headers, limits::MAX_BODY_BYTES) {
        return refuse(&refusal);
    }
    let params = match read_params(body).await {
        Ok(params) => params,
        Err(response) => return response,
    };

    match dispatch(&state.services, service, method, params).await {
        Ok(value) => json(200, &value),
        Err(failure) => error(failure.status(), failure.code(), &failure.to_string()),
    }
}

/// Run a service call on the blocking pool.
///
/// A panic inside a service is caught by the pool and reported as an internal error: it costs
/// that one request, never the daemon. The lint set makes panics very unlikely; this is the
/// backstop for the ones that are not.
pub(crate) async fn dispatch(
    services: &Arc<ServiceRegistry>,
    service: String,
    method: String,
    params: Value,
) -> Result<Value, ServiceError> {
    let services = Arc::clone(services);
    tokio::task::spawn_blocking(move || services.call(&service, &method, params))
        .await
        .unwrap_or_else(|join_error| {
            log::error!("a service call panicked: {join_error}");
            Err(ServiceError::Internal("the service failed".to_owned()))
        })
}

/// Read the body under the size cap and parse it, or produce the response to send instead.
///
/// `to_bytes` bounds the read independently of `Content-Length`, so a caller that lies about its
/// length — or sends none at all — still cannot push unbounded bytes into memory.
async fn read_params(body: Body) -> Result<Value, Response> {
    let bytes = to_bytes(body, limits::MAX_BODY_BYTES)
        .await
        .map_err(|_| refuse(&Refusal::PayloadTooLarge))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| refuse(&Refusal::MalformedBody))?;

    if text.trim().is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    serde_json::from_str(text)
        .map_err(|parse_error| error(400, "bad_request", &format!("invalid JSON: {parse_error}")))
}
