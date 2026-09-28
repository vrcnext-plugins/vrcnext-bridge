//! Which routes exist, and which only exist when they were asked for.
//!
//! The plugin system reaches the bridge over `/v1/ws` and opens with `/v1/health`; that pair is
//! the whole of normal operation. Everything else is a second way into the same services, and a
//! default bridge must not answer on it — which is a property of the router, not of a handler,
//! so it is checked here by asking the router itself.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use clap::Parser as _;
use tower::ServiceExt as _;
use vrcnext_bridge_core::{NullLogWriter, ServiceRegistry};

use super::{AppState, router};
use crate::broadcast::Broadcaster;
use crate::config::Config;
use crate::http::guard::Guard;

const TOKEN: &str = "test-token";

fn app(rest: bool) -> axum::Router {
    let config = Config::parse_from(["vrcnext-bridge"]);
    let guard = Arc::new(Guard::new(&config, TOKEN.to_owned()));
    let state = Arc::new(AppState {
        guard: Arc::clone(&guard),
        services: Arc::new(ServiceRegistry::new()),
        log_writer: Arc::new(NullLogWriter),
        broadcaster: Broadcaster::detached(),
    });
    router(rest, state, guard)
}

fn call(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("request")
}

async fn status(rest: bool, method: &str, path: &str) -> StatusCode {
    app(rest)
        .oneshot(call(method, path))
        .await
        .expect("response")
        .status()
}

async fn body_of(rest: bool, method: &str, path: &str) -> String {
    let response = app(rest)
        .oneshot(call(method, path))
        .await
        .expect("response");
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn the_socket_and_the_probe_are_always_served() {
    for rest in [false, true] {
        assert_eq!(
            status(rest, "GET", "/v1/health").await,
            StatusCode::OK,
            "rest={rest}"
        );
        // A plain GET on the socket route is a failed upgrade, not a missing route: 400, never 404.
        assert_ne!(
            status(rest, "GET", "/v1/ws").await,
            StatusCode::NOT_FOUND,
            "rest={rest}"
        );
    }
}

#[tokio::test]
async fn a_default_bridge_does_not_answer_on_the_rest_surface() {
    assert_eq!(
        status(false, "POST", "/v1/plugins/build").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(false, "POST", "/v1/remote/eval").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(false, "GET", "/v1/describe").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn with_rest_the_surface_is_there_and_reaches_the_registry() {
    assert_eq!(status(true, "GET", "/v1/describe").await, StatusCode::OK);
    // The registry is empty, so the call lands on "unknown_service" — a sentence only the `call`
    // handler produces. Both answers are 404; which one came back is what says the route exists.
    let reached = body_of(true, "POST", "/v1/plugins/build").await;
    assert!(reached.contains("unknown_service"), "{reached}");
    let missing = body_of(false, "POST", "/v1/plugins/build").await;
    assert!(missing.contains("not_found"), "{missing}");
}

#[tokio::test]
async fn the_refusal_names_the_flag_rather_than_looking_like_a_typo() {
    let text = body_of(false, "POST", "/v1/plugins/build").await;
    assert!(text.contains("--dev"), "{text}");
}

#[tokio::test]
async fn the_probe_names_no_services_without_a_token() {
    let response = app(false)
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["ok"], true);
    assert!(body["version"].is_string());
    assert_eq!(
        body.as_object().map(serde_json::Map::len),
        Some(2),
        "{body}"
    );
}
