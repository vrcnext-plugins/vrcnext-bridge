//! Fan the daemon's own log lines out to every open WebSocket.
//!
//! The page mirrors its logs to the bridge; the bridge mirrors its logs back. Someone debugging a
//! notification that never arrived then sees both halves of the conversation in one place — the
//! in-app Logs panel — without a terminal.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::broadcast;
use vrcnext_bridge_core::logs::LogLevel;

/// Records a subscriber may fall behind by before it starts losing the oldest.
///
/// A subscriber only falls behind if its socket is not draining, and a socket that is not
/// draining is one the page is not reading; losing its oldest daemon log lines is the right
/// thing to lose.
const CHANNEL_CAPACITY: usize = 256;

/// One daemon log line, shaped like the records the page sends so the page can store it as one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BroadcastRecord {
    pub(crate) level: LogLevel,
    pub(crate) scope: &'static str,
    pub(crate) message: String,
    pub(crate) ts: f64,
}

/// A handle any socket can subscribe through.
#[derive(Clone)]
pub(crate) struct Broadcaster {
    sender: broadcast::Sender<BroadcastRecord>,
}

impl Broadcaster {
    /// Start receiving every record logged from now on.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<BroadcastRecord> {
        self.sender.subscribe()
    }
}

/// The global `log` handler: writes through `env_logger`, and broadcasts a copy.
pub(crate) struct BroadcastLogger {
    inner: env_logger::Logger,
    sender: broadcast::Sender<BroadcastRecord>,
}

impl BroadcastLogger {
    /// Install as the global logger and hand back the subscription handle.
    ///
    /// # Errors
    ///
    /// Fails if a logger was already installed.
    pub(crate) fn install(inner: env_logger::Logger) -> Result<Broadcaster, log::SetLoggerError> {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        let max_level = inner.filter();
        log::set_boxed_logger(Box::new(Self {
            inner,
            sender: sender.clone(),
        }))?;
        log::set_max_level(max_level);
        Ok(Broadcaster { sender })
    }
}

impl log::Log for BroadcastLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if !self.inner.enabled(record.metadata()) {
            return;
        }
        self.inner.log(record);

        let level = match record.level() {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug | log::Level::Trace => LogLevel::Debug,
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64() * 1000.0);

        // `send` only fails when nobody is subscribed, which is the normal state.
        let _ = self.sender.send(BroadcastRecord {
            level,
            scope: "bridge",
            message: record.args().to_string(),
            ts,
        });
    }

    fn flush(&self) {
        self.inner.flush();
    }
}
