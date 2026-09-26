//! Wiring: turn a [`Config`] into a populated [`ServiceRegistry`], and say out loud what came up.
//!
//! This is the only place that knows which concrete services, sinks and approvers exist.
//! Registering a new capability means adding it here and nowhere else.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use vrcnext_bridge_core::logs::{LogService, LogWriter, NullLogWriter};
use vrcnext_bridge_core::notify::{NotifyService, SinkSet};
use vrcnext_bridge_core::{Approver, NullApprover, Paths, Pusher, Service, ServiceRegistry};
use vrcnext_bridge_plugins::{
    Builder, EsbuildBuilder, Git, GixGit, PluginsService, StateService, StateStore,
};
use vrcnext_bridge_sinks::WayvrSink;

use crate::config::{Config, SinkChoice};
use crate::logfile::FileLogWriter;

/// Everything the transport needs: the services, plus the log sink it shares with the stream.
pub(crate) struct Wiring {
    pub(crate) services: ServiceRegistry,
    pub(crate) log_writer: Arc<dyn LogWriter>,
}

/// Build every service this bridge will offer. `pusher` is how they reach the page.
///
/// # Errors
///
/// Fails if the state file exists but cannot be read: it holds the user's plugin settings, and
/// starting without it would let the next write silently replace them.
pub(crate) fn build_services(
    config: &Config,
    paths: &Paths,
    pusher: Arc<dyn Pusher>,
) -> Result<Wiring> {
    let log_writer = build_log_writer(config);
    let state =
        Arc::new(StateStore::open(paths.state_file()).context("cannot open the state store")?);
    let approver = build_approver();
    let builder = Arc::new(EsbuildBuilder::new(paths.clone(), Arc::clone(&pusher)));
    let plugins = PluginsService::new(
        paths.clone(),
        (
            Arc::new(GixGit) as Arc<dyn Git>,
            builder as Arc<dyn Builder>,
            Arc::clone(&state),
        ),
        pusher,
        approver,
    );

    let mut registry = ServiceRegistry::new();
    registry.register(Arc::new(NotifyService::new(build_sinks(config))) as Arc<dyn Service>);
    registry.register(Arc::new(LogService::new(Arc::clone(&log_writer))) as Arc<dyn Service>);
    registry.register(Arc::new(StateService::new(state)) as Arc<dyn Service>);
    registry.register(Arc::new(plugins) as Arc<dyn Service>);

    Ok(Wiring {
        services: registry,
        log_writer,
    })
}

/// The native confirmation prompt for this platform, or none.
///
/// None is not fatal: the daemon still serves state, notifications and builds. It is loud in
/// the banner, because every install will be refused until the user runs the bridge somewhere
/// a prompt can appear.
#[cfg(unix)]
fn build_approver() -> Arc<dyn Approver> {
    match vrcnext_bridge_sinks::FreedesktopApprover::connect() {
        Ok(approver) => Arc::new(approver),
        Err(error) => {
            log::warn!("no session bus for confirmation prompts: {error}");
            Arc::new(NullApprover)
        }
    }
}

#[cfg(windows)]
fn build_approver() -> Arc<dyn Approver> {
    Arc::new(vrcnext_bridge_win::MessageBoxApprover)
}

#[cfg(not(any(unix, windows)))]
fn build_approver() -> Arc<dyn Approver> {
    Arc::new(NullApprover)
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
            #[cfg(unix)]
            SinkChoice::Freedesktop => match vrcnext_bridge_sinks::FreedesktopSink::connect() {
                Ok(sink) => sinks.register(Arc::new(sink)),
                Err(error) => log::warn!("freedesktop sink unavailable: {error}"),
            },
        }
    }
    sinks
}

/// Log exactly what is running: which services, which sinks, where the data lives, how installs
/// are confirmed, and the pairing token.
///
/// Deliberately explicit. A bridge that silently came up with zero sinks, or with no way to
/// confirm an install, is the kind of thing someone should see in the first ten lines of output
/// rather than discover later. The token is printed on every start because the banner is where
/// a user goes to find it: the alternative is a file path they have to know about.
pub(crate) fn log_banner(config: &Config, paths: &Paths, token: &str, services: &ServiceRegistry) {
    log::info!("vrcnext-bridge {}", crate::VERSION);
    log::info!("data directory: {}", paths.root().display());
    log::info!("theme directory: {}", paths.theme_dir().display());
    log::info!("pairing token: {token}  (paste this into the Plugins tab)");

    for service in services.services() {
        log::info!("service `{}`: {}", service.name(), service.summary());
    }

    let described = services.describe();
    log_sinks(&described);

    match described
        .get("plugins")
        .and_then(|plugins| plugins.get("confirmation"))
        .and_then(serde_json::Value::as_str)
    {
        Some(prompt) if prompt.starts_with("none") => {
            log::warn!("confirmation prompt: {prompt}");
        }
        Some(prompt) => log::info!("confirmation prompt: {prompt}"),
        None => {}
    }

    if let Some(logs) = described
        .get("logs")
        .and_then(|logs| logs.get("location"))
        .and_then(serde_json::Value::as_str)
    {
        log::info!("plugin logs: {logs}");
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

fn log_sinks(described: &serde_json::Value) {
    let Some(targets) = described
        .get("notify")
        .and_then(|notify| notify.get("targets"))
        .and_then(|targets| targets.as_array())
    else {
        return;
    };
    if targets.is_empty() {
        log::warn!("no notification sinks started; notify/send will answer 503");
    }
    for target in targets {
        let name = target.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let description = target
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let health = target.get("health").and_then(|v| v.as_str()).unwrap_or("?");
        log::info!("  sink `{name}` [{health}] — {description}");
    }
}
