//! Wire types for the `logs` service.
//!
//! Same discipline as the notification protocol: an inbound batch is untrusted, and a
//! [`LogRecord`] can only exist once every field is inside its bound. A log line is written to a
//! file a human later reads in a terminal, which makes control characters an escape-sequence
//! injection rather than a cosmetic problem — so they are stripped rather than merely counted.

use serde::{Deserialize, Serialize};

/// Longest accepted scope name, in characters.
pub const MAX_SCOPE_CHARS: usize = 64;

/// Longest accepted message, in characters. Generous enough for a stack trace fragment.
pub const MAX_MESSAGE_CHARS: usize = 4_000;

/// Most records one batch may carry.
pub const MAX_BATCH_RECORDS: usize = 200;

/// Severity, mirroring the plugin system's own levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Verbose detail.
    Debug,
    /// Normal operation.
    Info,
    /// Something unexpected that did not stop the operation.
    Warn,
    /// A failure.
    Error,
}

impl LogLevel {
    /// Fixed-width label, so the file's columns line up in a terminal.
    #[must_use]
    pub const fn padded(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
            Self::Error => "ERROR",
        }
    }
}

/// One inbound record. Untrusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogRecordIn {
    /// Severity.
    pub level: LogLevel,
    /// Which plugin or host subsystem emitted this.
    #[serde(default)]
    pub scope: String,
    /// The message.
    pub message: String,
    /// Milliseconds since the Unix epoch, as the page saw it.
    ///
    /// Recorded because the page's clock is what a plugin author correlates against; the daemon
    /// stamps its own arrival time too, and the two differing is itself useful information.
    pub ts: Option<f64>,
}

/// A batch, as posted or streamed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogWriteRequest {
    /// The records to append.
    pub records: Vec<LogRecordIn>,
}

/// A validated record. Construct only via [`LogWriteRequest::validate`].
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LogRecord {
    /// Severity.
    pub level: LogLevel,
    /// Sanitised scope.
    pub scope: String,
    /// Sanitised message.
    pub message: String,
    /// The page's timestamp, if it sent one.
    pub ts: Option<f64>,
}

/// Why a batch was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogValidationError {
    /// The batch carried more records than the limit allows.
    #[error("at most {max} records per batch")]
    TooManyRecords {
        /// The bound that was exceeded.
        max: usize,
    },
    /// A message was empty after sanitising.
    #[error("`message` must not be empty")]
    EmptyMessage,
}

impl LogWriteRequest {
    /// Bound and sanitise every record.
    ///
    /// # Errors
    ///
    /// [`LogValidationError::TooManyRecords`] or [`LogValidationError::EmptyMessage`].
    pub fn validate(self) -> Result<Vec<LogRecord>, LogValidationError> {
        if self.records.len() > MAX_BATCH_RECORDS {
            return Err(LogValidationError::TooManyRecords {
                max: MAX_BATCH_RECORDS,
            });
        }

        self.records
            .into_iter()
            .map(|record| {
                let message = sanitise(&record.message, MAX_MESSAGE_CHARS);
                if message.is_empty() {
                    return Err(LogValidationError::EmptyMessage);
                }
                let scope = sanitise(&record.scope, MAX_SCOPE_CHARS);
                Ok(LogRecord {
                    level: record.level,
                    scope: if scope.is_empty() {
                        "plugin".to_owned()
                    } else {
                        scope
                    },
                    message,
                    ts: record.ts.filter(|value| value.is_finite()),
                })
            })
            .collect()
    }
}

/// Truncate to `max` characters and drop every control character.
///
/// Control characters are **removed, not rejected**. This is the one place where silently
/// modifying caller input is right: a refused batch loses the line entirely, whereas a stripped
/// escape sequence keeps the diagnostic. Newlines go too — a record is one line in the file, and
/// an embedded newline would let a caller forge extra entries.
fn sanitise(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
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

    use super::{LogLevel, LogWriteRequest, MAX_BATCH_RECORDS};

    fn request(json: serde_json::Value) -> LogWriteRequest {
        serde_json::from_value(json).expect("parses")
    }

    #[test]
    fn strips_escape_sequences_rather_than_refusing_the_line() {
        let records = request(serde_json::json!({
            "records": [{ "level": "info", "message": "red \u{1b}[31malert" }]
        }))
        .validate()
        .expect("validates");

        assert_eq!(records[0].message, "red [31malert");
    }

    #[test]
    fn an_embedded_newline_cannot_forge_a_second_entry() {
        let records = request(serde_json::json!({
            "records": [{ "level": "warn", "message": "line one\nERROR fake" }]
        }))
        .validate()
        .expect("validates");

        assert!(!records[0].message.contains('\n'));
    }

    #[test]
    fn defaults_the_scope() {
        let records = request(serde_json::json!({
            "records": [{ "level": "info", "message": "hi" }]
        }))
        .validate()
        .expect("validates");

        assert_eq!(records[0].scope, "plugin");
    }

    #[test]
    fn refuses_an_oversized_batch() {
        let records: Vec<serde_json::Value> = (0..=MAX_BATCH_RECORDS)
            .map(|_| serde_json::json!({ "level": "info", "message": "x" }))
            .collect();

        let error = request(serde_json::json!({ "records": records }))
            .validate()
            .expect_err("should refuse");
        assert!(error.to_string().contains("per batch"), "{error}");
    }

    #[test]
    fn refuses_a_message_that_is_only_control_characters() {
        let error = request(serde_json::json!({
            "records": [{ "level": "info", "message": "\u{1b}\u{7}" }]
        }))
        .validate()
        .expect_err("should refuse");
        assert!(error.to_string().contains("empty"), "{error}");
    }

    #[test]
    fn levels_are_padded_to_a_fixed_width() {
        for level in [
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            assert_eq!(level.padded().len(), 5);
        }
    }
}
