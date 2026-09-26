//! The `logs` service: accept log records from the page and hand them to a sink.
//!
//! # Why this exists
//!
//! VRCNext's own activity log is written by its C# side; there is no page→C# action that logs
//! arbitrary text, so the plugin system cannot get a line into it. Until now the only way to read
//! plugin logs was the in-app Logs panel, which means having the window open and copying text out
//! by hand — useless for following a bug over time, and useless for anyone helping remotely.
//!
//! Streaming them here gives a real file on disk that `tail -f` can follow.
//!
//! ```text
//! {"type":"logs","records":[…]}   a batch over the WebSocket, fire-and-forget — the normal path
//! logs/write                       the same batch as an ordinary service call, acknowledged
//! logs/info                        where the file is and how big it has grown
//! ```
//!
//! # This is a write-only sink
//!
//! There is deliberately no method that reads the log back. The daemon accepts lines and writes
//! them somewhere the *user* can read; it never serves them to a caller. A localhost endpoint that
//! hands file contents to whoever asks is a data-exfiltration primitive, and log lines carry
//! VRChat display names and instance ids.

mod proto;
mod writer;

pub use proto::{
    LogLevel, LogRecord, LogRecordIn, LogValidationError, LogWriteRequest, MAX_BATCH_RECORDS,
    MAX_MESSAGE_CHARS, MAX_SCOPE_CHARS,
};
pub use writer::{LogWriter, NullLogWriter};

use std::sync::Arc;

use serde_json::Value;

use crate::service::{Service, ServiceError};

/// The logging capability, backed by whatever writer was configured at startup.
pub struct LogService {
    writer: Arc<dyn LogWriter>,
}

impl LogService {
    /// Wrap a writer as a service.
    #[must_use]
    pub const fn new(writer: Arc<dyn LogWriter>) -> Self {
        Self { writer }
    }

    /// Validate a batch and append it.
    ///
    /// # Errors
    ///
    /// [`ServiceError::BadRequest`] if the batch is malformed or over its bounds,
    /// [`ServiceError::Internal`] if the sink could not accept it.
    pub fn write(&self, params: Value) -> Result<Value, ServiceError> {
        let request: LogWriteRequest = serde_json::from_value(params)
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;

        let records = request
            .validate()
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?;

        let written = records.len();
        self.writer
            .append(&records)
            .map_err(ServiceError::Internal)?;

        Ok(serde_json::json!({ "ok": true, "written": written }))
    }

    fn info(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "location": self.writer.location(),
            "bytes": self.writer.bytes_written(),
        })
    }
}

impl Service for LogService {
    fn name(&self) -> &'static str {
        "logs"
    }

    fn summary(&self) -> &'static str {
        "Append plugin log records to a file on disk. Write-only."
    }

    fn describe(&self) -> Value {
        serde_json::json!({
            "methods": ["write", "info"],
            "location": self.writer.location(),
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "write" => self.write(params),
            "info" => Ok(self.info()),
            other => Err(ServiceError::UnknownMethod {
                service: "logs",
                method: other.to_owned(),
            }),
        }
    }
}
