//! Where validated records go.
//!
//! The trait keeps this crate I/O-free: the real implementation opens a file and lives in the
//! binary, while tests here use [`NullLogWriter`] or their own recorder.

use crate::logs::proto::LogRecord;

/// A sink for validated log records.
///
/// Shared across the HTTP workers and every WebSocket thread behind an `Arc`, hence `Send + Sync`
/// and the `&self` receiver — an implementation owning a file handle locks it internally rather
/// than forcing callers to serialise.
pub trait LogWriter: Send + Sync {
    /// Append a batch.
    ///
    /// # Errors
    ///
    /// A human-readable reason the batch could not be persisted.
    fn append(&self, records: &[LogRecord]) -> Result<(), String>;

    /// Where the records are going, for `logs/info` and the startup banner.
    fn location(&self) -> String;

    /// Bytes written since startup, for `logs/info`.
    fn bytes_written(&self) -> u64;
}

/// Discards everything. Used when log capture is switched off, and in tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullLogWriter;

impl LogWriter for NullLogWriter {
    fn append(&self, _records: &[LogRecord]) -> Result<(), String> {
        Ok(())
    }

    fn location(&self) -> String {
        "disabled".to_owned()
    }

    fn bytes_written(&self) -> u64 {
        0
    }
}
