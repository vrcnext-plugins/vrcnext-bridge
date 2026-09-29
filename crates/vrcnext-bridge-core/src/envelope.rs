//! The WebSocket envelope: one persistent socket carrying service calls, log batches and pushes.
//!
//! # Why an envelope
//!
//! Over HTTP, "which request is this the answer to" is free — one connection, one exchange. Over a
//! shared socket it is not, so every request carries a caller-chosen correlation `id` and its
//! response echoes it. The page can therefore have several calls in flight at once, and a slow
//! D-Bus round trip does not hold up a quick one.
//!
//! Log batches are the exception: they are fire-and-forget. A page mirroring its log stream does
//! not want an acknowledgement per frame, and a logging path that can fail loudly is worse than
//! no logging at all. They also get their own, much more permissive, frame budget.
//!
//! # Every string here is untrusted
//!
//! The socket is reachable by any page that passed the origin check, so the same discipline as
//! the HTTP protocol applies: names are bounded and shaped before they are looked up, and the
//! correlation id is bounded before it is echoed. [`ClientMessage::validate`] is the only way a
//! [`Request`] leaves this module.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::limits::{MAX_CORRELATION_ID_CHARS, MAX_NAME_CHARS};
use crate::logs::LogRecordIn;
use crate::service::ServiceError;

/// One frame from the page.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ClientMessage {
    /// Call `service`/`method` and answer under `id`.
    Request {
        /// Caller-chosen correlation id, echoed on the response.
        id: String,
        /// Service name.
        service: String,
        /// Method name.
        method: String,
        /// Method parameters. Absent means an empty object.
        #[serde(default)]
        params: Option<Value>,
    },
    /// A batch of log records. Never answered.
    Logs {
        /// The records to append.
        records: Vec<LogRecordIn>,
    },
}

/// One frame to the page.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    /// The answer to a [`ClientMessage::Request`].
    Response {
        /// The request's correlation id.
        id: String,
        /// Whether the call succeeded.
        ok: bool,
        /// The service's result, on success.
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        /// Why it failed, on failure.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ErrorBody>,
    },
    /// Something the daemon sends unprompted, such as its own log lines.
    Push {
        /// Event name.
        event: &'static str,
        /// Event payload.
        data: Value,
    },
}

/// The same error shape the HTTP transport uses, so a plugin has one thing to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// Stable machine-readable code.
    pub code: String,
    /// Human-readable explanation. Never echoes caller content.
    pub message: String,
}

impl ServerMessage {
    /// A successful response.
    #[must_use]
    pub const fn ok(id: String, result: Value) -> Self {
        Self::Response {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// A failed response.
    #[must_use]
    pub fn error(id: String, code: &str, message: &str) -> Self {
        Self::Response {
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.to_owned(),
                message: message.to_owned(),
            }),
        }
    }

    /// A failed response carrying a [`ServiceError`].
    #[must_use]
    pub fn from_service_error(id: String, error: &ServiceError) -> Self {
        Self::error(id, error.code(), &error.to_string())
    }
}

/// A validated service call. Construct only via [`ClientMessage::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// Bounded correlation id.
    pub id: String,
    /// Bounded, well-shaped service name.
    pub service: String,
    /// Bounded, well-shaped method name.
    pub method: String,
    /// Parameters, defaulting to an empty object.
    pub params: Value,
}

/// A validated inbound frame.
#[derive(Debug, Clone)]
pub enum Inbound {
    /// A service call.
    Request(Request),
    /// A log batch.
    Logs(Vec<LogRecordIn>),
}

/// Why a frame was refused before it reached a service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// The correlation id was empty or over its bound.
    #[error("`id` must be 1 to {MAX_CORRELATION_ID_CHARS} characters")]
    BadId,
    /// A service or method name was not a plain lowercase identifier within its bound.
    #[error("`{0}` must be a lowercase identifier of at most {MAX_NAME_CHARS} characters")]
    BadName(&'static str),
    /// `params` was present but not a JSON object.
    #[error("`params` must be an object")]
    BadParams,
}

impl EnvelopeError {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadId | Self::BadName(_) | Self::BadParams => "bad_request",
        }
    }
}

impl ClientMessage {
    /// Bound and shape every field.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError`] naming the first field that was wrong. Log records are *not* validated
    /// here: the batch is handed to [`crate::logs::LogWriteRequest::validate`] by the transport,
    /// which owns the log-specific bounds.
    pub fn validate(self) -> Result<Inbound, EnvelopeError> {
        match self {
            Self::Logs { records } => Ok(Inbound::Logs(records)),
            Self::Request {
                id,
                service,
                method,
                params,
            } => {
                let id_len = id.chars().count();
                if id_len == 0 || id_len > MAX_CORRELATION_ID_CHARS {
                    return Err(EnvelopeError::BadId);
                }
                if !is_name(&service) {
                    return Err(EnvelopeError::BadName("service"));
                }
                if !is_name(&method) {
                    return Err(EnvelopeError::BadName("method"));
                }
                let params = match params {
                    None | Some(Value::Null) => Value::Object(serde_json::Map::new()),
                    Some(object @ Value::Object(_)) => object,
                    Some(_) => return Err(EnvelopeError::BadParams),
                };
                Ok(Inbound::Request(Request {
                    id,
                    service,
                    method,
                    params,
                }))
            }
        }
    }
}

/// Service and method names are lowercase identifiers within [`MAX_NAME_CHARS`].
///
/// Shared with the HTTP path parser so the two transports agree on what a name is. Refusing
/// anything else keeps odd bytes out of error messages and logs.
#[must_use]
pub fn is_name(segment: &str) -> bool {
    !segment.is_empty()
        && segment.chars().count() <= MAX_NAME_CHARS
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests;
