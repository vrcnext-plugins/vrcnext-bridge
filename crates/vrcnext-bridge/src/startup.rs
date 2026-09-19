//! Wiring: turn a [`Config`] into a populated [`ServiceRegistry`], and say out loud what came up.
//!
//! This is the only place that knows which concrete services and sinks exist. Registering a new
//! capability means adding it here and nowhere else.

use std::sync::Arc;

use vrcnext_bridge_core::logs::{LogService, LogWriter, NullLogWriter};
use vrcnext_bridge_core::notify::{NotifyService, SinkSet};
use vrcnext_bridge_core::{Service, ServiceRegistry};
use vrcnext_bridge_sinks::{FreedesktopSink, WayvrSink};

use crate::config::{Config, SinkChoice};
use crate::logfile::FileLogWriter;

/// Everything the transport needs: the services, plus the log sink it shares with the stream.
pub(crate) struct Wiring {
    pub(crate) services: ServiceRegistry,
    pub(crate) log_writer: Arc<dyn LogWriter>,
}

/// Build every service this bridge will offer.
#[must_use]
pub(crate) fn build_services(config: &Config) -> Wiring {
    let log_writer = build_log_writer(config);

    let mut registry = ServiceRegistry::new();
    registry.register(Arc::new(NotifyService::new(build_sinks(config))) as Arc<dyn Service>);
    registry.register(Arc::new(LogService::new(Arc::clone(&log_writer))) as Arc<dyn Service>);

    Wiring {
        services: registry,
        log_writer,
    }
}

/// Open the log file, or fall back to discarding.
///
/// A log file that cannot be opened must not stop the daemon: notifications are the primary job,
/// and losing diagnostics is not worth refusing to start over. It is logged loudly instead.
fn build_log_writer(config: &Config) -> Arc<dyn LogWriter> {
    if config.no_log_capture {
        log::info!("plugin log capture disabled by --no-log-capture");
        return Arc::new(NullLogWriter);
    }

    match FileLogWriter::open(config.log_file.clone(), Some(config.log_max_bytes)) {
        Ok(writer) => Arc::new(writer),
        Err(error) => {
            log::error!("plugin log capture unavailable: {error:#}");
            Arc::new(NullLogWriter)
        }
    }
}

/// Bring up the requested sinks.
///
/// A sink that fails to start is logged and skipped rather than being fatal: no session bus is a
/// perfectly ordinary state, and a user who wants VR notifications should not be blocked by the
/// desktop route being unavailable. If *nothing* starts, the daemon still runs and `notify/send`
/// answers 503 — an honest "I cannot do this" beats a silent success.
fn build_sinks(config: &Config) -> SinkSet {
    let mut sinks = SinkSet::new();

    for choice in config.requested_sinks() {
        match choice {
            SinkChoice::Wayvr => match WayvrSink::bind(config.wayvr_addr) {
                Ok(sink) => sinks.register(Arc::new(sink)),
                Err(error) => log::warn!("wayvr sink unavailable: {error}"),
            },
            SinkChoice::Freedesktop => match FreedesktopSink::connect() {
                Ok(sink) => sinks.register(Arc::new(sink)),
                Err(error) => log::warn!("freedesktop sink unavailable: {error}"),
            },
        }
    }
    sinks
}

/// Log exactly what is running: which services, which sinks, and whether a token is required.
///
/// Deliberately explicit. A bridge that silently came up with zero sinks, or with the token
/// disabled because the environment variable was misspelled, is the kind of thing someone should
/// see in the first ten lines of output rather than discover later.
pub(crate) fn log_banner(config: &Config, services: &ServiceRegistry) {
    log::info!("vrcnext-bridge {}", crate::VERSION);

    for service in services.services() {
        log::info!("service `{}`: {}", service.name(), service.summary());
    }

    if let Some(targets) = services
        .describe()
        .get("notify")
        .and_then(|notify| notify.get("targets"))
        .and_then(|targets| targets.as_array().cloned())
    {
        if targets.is_empty() {
            log::warn!("no notification sinks started; notify/send will answer 503");
        }
        for target in &targets {
            let name = target.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let description = target
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let health = target.get("health").and_then(|v| v.as_str()).unwrap_or("?");
            log::info!("  sink `{name}` [{health}] — {description}");
        }
    }

    if let Some(logs) = services
        .describe()
        .get("logs")
        .and_then(|logs| logs.get("location"))
        .and_then(serde_json::Value::as_str)
    {
        log::info!("plugin logs: {logs}");
    }

    if config.token.is_some() {
        log::info!("bearer token required");
    } else {
        log::info!("no bearer token set; relying on the loopback bind and the origin allowlist");
    }
    if config.allow_origins.is_empty() {
        log::info!("origins: loopback only");
    } else {
        log::warn!(
            "origins: loopback, plus {} explicitly allowed: {}",
            config.allow_origins.len(),
            config.allow_origins.join(", ")
        );
    }
    log::info!(
        "rate limit: {}/s, burst {}, {} worker threads",
        config.rate,
        config.burst,
        config.worker_threads()
    );
}
