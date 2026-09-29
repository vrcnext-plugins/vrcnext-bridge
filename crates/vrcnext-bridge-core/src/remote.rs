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
//! This is deliberately **off by default** (`--dev`). Anything holding the pairing token can
//! already do everything the page can do — install plugins, read state — and the page itself
//! runs the bundle this daemon compiles, so the service does not widen who is trusted. It does
//! make that trust very direct, which is why it has to be switched on and why the banner says so.
//!
//! Each evaluation carries a random 128-bit id, and only a `remote/result` naming that id is
//! accepted. The result is not tied to the connection the snippet was pushed on: services know
//! nothing about sockets, and the push goes to every paired page, so any page may answer. The
//! unguessable id is what keeps a client that never saw the snippet from answering it.
//!
//! # No I/O here
//!
//! The service only pushes a frame and waits on a channel. The transport delivers the push and
//! routes the page's answer back through [`RemoteService::call`] like any other request.

use std::collections::HashMap;
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
    id: String,
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

/// A fresh evaluation id: 128 random bits, base64url without padding (22 characters).
///
/// The id is the only thing tying a `remote/result` to its `eval`, and results arrive over the
/// same shared socket every paired client uses, so it must not be guessable: a counter would let
/// any other client answer an evaluation it never saw.
fn eval_id() -> Result<String, ServiceError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| ServiceError::Internal(error.to_string()))?;
    let value = u128::from_be_bytes(bytes);
    // 22 six-bit digits cover 132 bits; the top four are always zero.
    Ok((0..22)
        .rev()
        .map(|digit| {
            let index = usize::try_from((value >> (digit * 6)) & 0x3f).unwrap_or(0);
            char::from(ALPHABET.get(index).copied().unwrap_or(b'A'))
        })
        .collect())
}

/// Pushes snippets to the page and correlates the answers.
pub struct RemoteService {
    pusher: Arc<dyn Pusher>,
    pending: Mutex<HashMap<String, SyncSender<Answer>>>,
}

impl RemoteService {
    /// Wire the service. `pusher` is how the snippet reaches the page.
    #[must_use]
    pub fn new(pusher: Arc<dyn Pusher>) -> Self {
        Self {
            pusher,
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<String, SyncSender<Answer>>> {
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
        let id = eval_id()?;
        {
            let mut pending = self.pending();
            if pending.len() >= MAX_IN_FLIGHT {
                return Err(ServiceError::Unavailable(format!(
                    "{MAX_IN_FLIGHT} evaluations are already waiting on the page"
                )));
            }
            pending.insert(id.clone(), sender);
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
        "evaluates snippets inside the paired VRCNext page (enabled with --dev)"
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
mod tests;
