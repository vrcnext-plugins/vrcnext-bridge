//! Command-line configuration, and the reasoning behind the defaults.

use std::net::SocketAddr;

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use vrcnext_bridge_sinks::DEFAULT_WAYVR_ADDR;

/// Default listen address. Loopback, and a port unlikely to collide with anything else.
pub(crate) const DEFAULT_LISTEN: &str = "127.0.0.1:42081";

/// Which sinks to bring up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SinkChoice {
    /// WayVR / XSOverlay protocol over UDP.
    Wayvr,
    /// The desktop's freedesktop notification daemon over D-Bus.
    Freedesktop,
}

/// A loopback capability bridge for VRCNext plugins.
///
/// Serves `POST /v1/<service>/<method>` to the VRCNext page and nothing else. Notifications are
/// the first service; each notification target is a separately addressable sink.
#[derive(Debug, Parser)]
#[command(name = "vrcnext-bridge", version, about, long_about = None)]
pub(crate) struct Config {
    /// Address to listen on. Must be loopback.
    #[arg(long, default_value = DEFAULT_LISTEN, env = "VRCNEXT_BRIDGE_LISTEN")]
    pub(crate) listen: SocketAddr,

    /// Sinks to enable. Repeat the flag for more than one. Defaults to every sink that starts.
    #[arg(long = "sink", value_enum)]
    pub(crate) sinks: Vec<SinkChoice>,

    /// Where the WayVR-protocol listener is.
    #[arg(long, default_value = DEFAULT_WAYVR_ADDR, env = "VRCNEXT_BRIDGE_WAYVR_ADDR")]
    pub(crate) wayvr_addr: SocketAddr,

    /// Require this bearer token on every request.
    ///
    /// Optional because the CORS guard already stops drive-by requests from web pages, and the
    /// only other things that can reach loopback are processes already running as this user. Set
    /// it on a shared or multi-user machine, where that second assumption stops holding.
    #[arg(long, env = "VRCNEXT_BRIDGE_TOKEN", hide_env_values = true)]
    pub(crate) token: Option<String>,

    /// Additional exact `Origin` values to accept, beyond loopback origins.
    ///
    /// Rarely needed. Every added origin is a site allowed to put notifications in front of you.
    #[arg(long = "allow-origin")]
    pub(crate) allow_origins: Vec<String>,

    /// Sustained request ceiling, per second.
    #[arg(long, default_value_t = 5.0)]
    pub(crate) rate: f64,

    /// How many requests may arrive back to back before the rate limit bites.
    #[arg(long, default_value_t = 10)]
    pub(crate) burst: u32,

    /// Worker threads. Requests are short and I/O-bound, so a handful is plenty.
    #[arg(long, default_value_t = 4)]
    pub(crate) threads: usize,

    /// Where to write plugin logs. Defaults to a private per-user directory.
    ///
    /// Plugin log lines carry VRChat display names and instance ids, so the default lives under
    /// `$XDG_RUNTIME_DIR` (or a `0700` directory under the temp dir) with the file itself `0600`.
    /// Point this somewhere world-readable only if you mean to.
    #[arg(long, env = "VRCNEXT_BRIDGE_LOG_FILE")]
    pub(crate) log_file: Option<std::path::PathBuf>,

    /// Rotate the plugin log once it passes this many bytes. One previous generation is kept.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    pub(crate) log_max_bytes: u64,

    /// Accept no plugin logs at all.
    #[arg(long)]
    pub(crate) no_log_capture: bool,

    /// Log level: error, warn, info, debug, trace.
    #[arg(long, default_value = "info", env = "VRCNEXT_BRIDGE_LOG")]
    pub(crate) log: String,
}

impl Config {
    /// Reject configurations that would widen the daemon's reach beyond this machine.
    ///
    /// # Errors
    ///
    /// Fails if the listen address is not loopback, or if the token is present but trivially
    /// short. There is deliberately no flag to override the loopback requirement: a bridge that
    /// can put notifications on someone's screen has no business accepting connections from the
    /// network, and an override would exist only to be misused.
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.listen.ip().is_loopback() {
            bail!(
                "--listen must be a loopback address; {} would accept connections from the network",
                self.listen
            );
        }
        if let Some(token) = &self.token {
            if token.chars().count() < 16 {
                bail!("--token must be at least 16 characters to be worth having");
            }
        }
        if !self.wayvr_addr.ip().is_loopback() {
            bail!(
                "--wayvr-addr must be a loopback address; {} is not",
                self.wayvr_addr
            );
        }
        Ok(())
    }

    /// The sinks to attempt, honouring `--sink` or defaulting to all of them.
    #[must_use]
    pub(crate) fn requested_sinks(&self) -> Vec<SinkChoice> {
        if self.sinks.is_empty() {
            vec![SinkChoice::Wayvr, SinkChoice::Freedesktop]
        } else {
            let mut chosen = self.sinks.clone();
            chosen.dedup();
            chosen
        }
    }

    /// Worker thread count, floored at one.
    #[must_use]
    pub(crate) const fn worker_threads(&self) -> usize {
        if self.threads == 0 { 1 } else { self.threads }
    }
}
