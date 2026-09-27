//! The `remote` service: run a snippet inside the VRCNext page and get its result back.
//!
//! # Why
//!
//! The page is a `WebKitGTK` window; nothing outside it can inspect its DOM, click its buttons or
//! read its state. Driving it with a synthetic mouse means taking the pointer away from whoever is
//! sitting at the desk. This service gives a token-holder a way in that does not touch the
//! desktop at all: `remote/eval` pushes the snippet to every paired page over the socket, the host
//! evaluates it and answers with `remote/result`, and the original call returns that answer.
//!
//! # Trust
//!
//! This is deliberately **off by default** (`--remote`). Anything holding the pairing token can
//! already do everything the page can do — install plugins, read state — and the page itself
//! runs the bundle this daemon compiles, so the service does not widen who is trusted. It does
//! make that trust very direct, which is why it has to be switched on and why the banner says so.
//!
//! # No I/O here
//!
//! The service only pushes a frame and waits on a channel. The transport delivers the push and
//! routes the page's answer back through [`RemoteService::call`] like any other request.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::pusher::Pusher;
use crate::service::{Service, ServiceError};

/// Longest snippet accepted, in Unicode scalar values.
pub const MAX_CODE_CHARS: usize = 64 * 1024;

/// How long `eval` waits for the page unless the caller says otherwise.
pub const DEFAULT_EVAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The most a caller may wait. A blocking-pool thread is held for the duration.
pub const MAX_EVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// Most evaluations in flight at once. Each one parks a worker thread.
pub const MAX_IN_FLIGHT: usize = 8;

/// The push event the page listens for.
pub const PUSH_EVENT: &str = "remote";

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvalParams {
    code: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultParams {
    id: u64,
    ok: bool,
    #[serde(default)]
    value: Value,
    #[serde(default)]
    error: Option<String>,
}

/// What the page sends back for one evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    ok: bool,
    value: Value,
    error: Option<String>,
}

/// Pushes snippets to the page and correlates the answers.
pub struct RemoteService {
    pusher: Arc<dyn Pusher>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, SyncSender<Answer>>>,
}

impl RemoteService {
    /// Wire the service. `pusher` is how the snippet reaches the page.
    #[must_use]
    pub fn new(pusher: Arc<dyn Pusher>) -> Self {
        Self {
            pusher,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<u64, SyncSender<Answer>>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, ServiceError> {
        serde_json::from_value(params)
            .map_err(|_| ServiceError::BadRequest("params do not match the method".to_owned()))
    }

    /// Push the snippet and block until the page answers or the deadline passes.
    fn eval(&self, params: Value) -> Result<Value, ServiceError> {
        let params: EvalParams = Self::parse(params)?;
        let length = params.code.chars().count();
        if length == 0 || length > MAX_CODE_CHARS {
            return Err(ServiceError::BadRequest(format!(
                "`code` must be 1 to {MAX_CODE_CHARS} characters"
            )));
        }
        let timeout = params
            .timeout_ms
            .map_or(DEFAULT_EVAL_TIMEOUT, Duration::from_millis)
            .min(MAX_EVAL_TIMEOUT);

        let (sender, receiver) = mpsc::sync_channel(1);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut pending = self.pending();
            if pending.len() >= MAX_IN_FLIGHT {
                return Err(ServiceError::Unavailable(format!(
                    "{MAX_IN_FLIGHT} evaluations are already waiting on the page"
                )));
            }
            pending.insert(id, sender);
        }

        self.pusher
            .push(PUSH_EVENT, json!({ "id": id, "code": params.code }));
        let outcome = receiver.recv_timeout(timeout);
        self.pending().remove(&id);

        match outcome {
            Ok(answer) => {
                Ok(json!({ "ok": answer.ok, "value": answer.value, "error": answer.error }))
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Err(
                ServiceError::Unavailable("no page answered before the deadline".to_owned()),
            ),
        }
    }

    /// The page's answer to an earlier `eval`. Unknown ids are ignored: the caller gave up.
    fn result(&self, params: Value) -> Result<Value, ServiceError> {
        let params: ResultParams = Self::parse(params)?;
        let delivered = self.pending().remove(&params.id).is_some_and(|sender| {
            sender
                .try_send(Answer {
                    ok: params.ok,
                    value: params.value,
                    error: params.error,
                })
                .is_ok()
        });
        Ok(json!({ "delivered": delivered }))
    }
}

impl Service for RemoteService {
    fn name(&self) -> &'static str {
        "remote"
    }

    fn summary(&self) -> &'static str {
        "evaluates snippets inside the paired VRCNext page (enabled with --remote)"
    }

    fn describe(&self) -> Value {
        json!({
            "methods": ["eval", "result"],
            "pushEvent": PUSH_EVENT,
            "maxCodeChars": MAX_CODE_CHARS,
            "defaultTimeoutMs": DEFAULT_EVAL_TIMEOUT.as_millis(),
            "maxTimeoutMs": MAX_EVAL_TIMEOUT.as_millis(),
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "eval" => self.eval(params),
            "result" => self.result(params),
            other => Err(ServiceError::UnknownMethod {
                service: self.name(),
                method: other.to_owned(),
            }),
        }
    }
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
            let id = data["id"].as_u64().unwrap();
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
        assert!(events[0].1["id"].is_u64());
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
            .call("result", json!({ "id": 99, "ok": false, "error": "late" }))
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
                    let id = data["id"].as_u64().unwrap();
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
}
