#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

use super::{MAX_CODE_CHARS, RemoteService};
use crate::pusher::{Pusher, RecordingPusher};
use crate::service::{Service as _, ServiceError};

/// A pusher that plays the page: it answers every pushed snippet from another thread.
struct AnsweringPage {
    service: std::sync::Weak<RemoteService>,
    answer: fn(&str) -> Value,
}

impl Pusher for AnsweringPage {
    fn push(&self, event: &'static str, data: Value) {
        assert_eq!(event, "remote");
        let Some(service) = self.service.upgrade() else {
            return;
        };
        let answer = (self.answer)(data["code"].as_str().unwrap());
        let id = data["id"].as_str().unwrap().to_owned();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            let reply = service
                .call("result", json!({ "id": id, "ok": true, "value": answer }))
                .unwrap();
            assert_eq!(reply["delivered"], true);
        });
    }
}

/// Builds the service around a page that answers with `answer`. The pusher needs the service
/// and the service needs the pusher, hence the `Weak` and the late binding.
fn with_page(answer: fn(&str) -> Value) -> Arc<RemoteService> {
    Arc::new_cyclic(|weak| {
        RemoteService::new(Arc::new(AnsweringPage {
            service: weak.clone(),
            answer,
        }))
    })
}

#[test]
fn eval_returns_what_the_page_answered() {
    let service = with_page(|code| json!(code.len()));
    let result = service
        .call("eval", json!({ "code": "1 + 1", "timeoutMs": 2000 }))
        .expect("answered");
    assert_eq!(result, json!({ "ok": true, "value": 5, "error": null }));
    assert!(service.pending().is_empty(), "nothing left waiting");
}

#[test]
fn eval_times_out_when_no_page_answers() {
    let service = RemoteService::new(Arc::new(RecordingPusher::default()));
    let error = service
        .call("eval", json!({ "code": "x", "timeoutMs": 30 }))
        .expect_err("nobody answers");
    assert!(matches!(error, ServiceError::Unavailable(_)), "{error}");
    assert!(
        service.pending().is_empty(),
        "the slot is released on timeout"
    );
}

#[test]
fn eval_pushes_the_snippet_with_its_id() {
    let pusher = Arc::new(RecordingPusher::default());
    let service = RemoteService::new(pusher.clone());
    let _ = service.call("eval", json!({ "code": "document.title", "timeoutMs": 1 }));
    let events = pusher.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "remote");
    assert_eq!(events[0].1["code"], "document.title");
    assert!(events[0].1["id"].as_str().is_some_and(|id| id.len() == 22));
}

#[test]
fn code_is_bounded_and_required() {
    let service = RemoteService::new(Arc::new(RecordingPusher::default()));
    for params in [
        json!({}),
        json!({ "code": "" }),
        json!({ "code": "x".repeat(MAX_CODE_CHARS + 1) }),
        json!({ "code": "x", "extra": 1 }),
    ] {
        assert!(matches!(
            service.call("eval", params),
            Err(ServiceError::BadRequest(_))
        ));
    }
}

#[test]
fn a_result_for_an_unknown_id_is_not_delivered() {
    let service = RemoteService::new(Arc::new(RecordingPusher::default()));
    let reply = service
        .call(
            "result",
            json!({ "id": "AAAAAAAAAAAAAAAAAAAAAB", "ok": false, "error": "late" }),
        )
        .unwrap();
    assert_eq!(reply, json!({ "delivered": false }));
}

#[test]
fn a_page_error_is_reported_not_raised() {
    let service = Arc::new_cyclic(|weak: &std::sync::Weak<RemoteService>| {
        struct FailingPage(std::sync::Weak<RemoteService>);
        impl Pusher for FailingPage {
            fn push(&self, _event: &'static str, data: Value) {
                let service = self.0.upgrade().unwrap();
                let id = data["id"].as_str().unwrap().to_owned();
                thread::spawn(move || {
                    service
                        .call("result", json!({ "id": id, "ok": false, "error": "boom" }))
                        .unwrap();
                });
            }
        }
        RemoteService::new(Arc::new(FailingPage(weak.clone())))
    });
    let result = service
        .call("eval", json!({ "code": "throw 1", "timeoutMs": 2000 }))
        .expect("answered");
    assert_eq!(result["ok"], false);
    assert_eq!(result["error"], "boom");
}

#[test]
fn unknown_methods_are_refused() {
    let service = RemoteService::new(Arc::new(RecordingPusher::default()));
    assert!(matches!(
        service.call("run", json!({})),
        Err(ServiceError::UnknownMethod { .. })
    ));
}

#[test]
fn eval_ids_are_random_base64url() {
    let a = super::eval_id().unwrap();
    let b = super::eval_id().unwrap();
    assert_ne!(a, b);
    assert_eq!(a.len(), 22);
    assert!(
        a.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
}
