//! Broadcasts internal daemon log events to active WebSocket connections.
//!
//! When connected, the VRCNext plugin system streams plugin log records to the bridge, and
//! the bridge broadcasts its own diagnostic logs back over the WebSocket.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Mutex, OnceLock};

use vrcnext_bridge_core::logs::LogLevel;

/// Maximum queued broadcast messages per WebSocket subscriber before dropping old records.
const SUBSCRIBER_QUEUE_BOUND: usize = 256;

use serde::Serialize;

/// Global broadcaster instance.
static BROADCASTER: OnceLock<LogBroadcaster> = OnceLock::new();

/// A formatted log message ready to be serialized to WebSocket subscribers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastRecord {
    pub(crate) level: LogLevel,
    pub(crate) scope: &'static str,
    pub(crate) message: String,
    pub(crate) ts: f64,
}

struct Subscriber {
    id: usize,
    sender: SyncSender<BroadcastRecord>,
}

/// Dispatches log records to registered subscribers.
pub(crate) struct LogBroadcaster {
    subscribers: Mutex<Vec<Subscriber>>,
    next_id: AtomicUsize,
}

impl LogBroadcaster {
    /// Get or initialise the global broadcaster.
    pub(crate) fn global() -> &'static Self {
        BROADCASTER.get_or_init(|| Self {
            subscribers: Mutex::new(Vec::new()),
            next_id: AtomicUsize::new(1),
        })
    }

    /// Register a new WebSocket subscriber channel.
    pub(crate) fn subscribe(&self) -> (usize, Receiver<BroadcastRecord>) {
        let (sender, receiver) = sync_channel(SUBSCRIBER_QUEUE_BOUND);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.push(Subscriber { id, sender });
        }
        (id, receiver)
    }

    /// Unregister a subscriber by id.
    pub(crate) fn unsubscribe(&self, id: usize) {
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.retain(|sub| sub.id != id);
        }
    }

    /// Broadcast a log record to all subscribers without blocking.
    pub(crate) fn broadcast(&self, record: &BroadcastRecord) {
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.retain(|sub| {
                // Non-blocking send: if the buffer is full, drop rather than blocking daemon execution.
                match sub.sender.try_send(record.clone()) {
                    Ok(()) | Err(std::sync::mpsc::TrySendError::Full(_)) => true,
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
                }
            });
        }
    }
}

/// A custom `log::Log` implementation that forwards to `env_logger` and broadcasts to active WebSockets.
pub(crate) struct BroadcastLogger {
    inner: env_logger::Logger,
    broadcaster: &'static LogBroadcaster,
}

impl BroadcastLogger {
    /// Wrap an initialized `env_logger::Logger` with broadcasting.
    #[must_use]
    pub(crate) fn new(inner: env_logger::Logger) -> Self {
        Self {
            inner,
            broadcaster: LogBroadcaster::global(),
        }
    }

    /// Install this logger as the global `log` handler.
    ///
    /// # Errors
    ///
    /// Returns an error if a logger was already installed.
    pub(crate) fn init(self) -> Result<(), log::SetLoggerError> {
        let max_level = self.inner.filter();
        log::set_boxed_logger(Box::new(self))?;
        log::set_max_level(max_level);
        Ok(())
    }
}

impl log::Log for BroadcastLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if self.inner.enabled(record.metadata()) {
            self.inner.log(record);

            let level = match record.level() {
                log::Level::Error => LogLevel::Error,
                log::Level::Warn => LogLevel::Warn,
                log::Level::Info => LogLevel::Info,
                log::Level::Debug | log::Level::Trace => LogLevel::Debug,
            };

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64() * 1000.0);

            self.broadcaster.broadcast(&BroadcastRecord {
                level,
                scope: "bridge",
                message: format!("{}", record.args()),
                ts: now_ms,
            });
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
