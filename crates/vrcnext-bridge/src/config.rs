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
    /// The desktop's freedesktop notification daemon over D-Bus. Unix only.
    #[cfg(unix)]
    Freedesktop,
}

/// A loopback capability bridge for VRCNext plugins.
///
/// Serves one WebSocket and `POST /v1/<service>/<method>` to the VRCNext page, nothing else. It
/// installs and compiles plugins, keeps the page's state, and delivers notifications.
#[derive(Debug, Parser)]
#[command(name = "vrcnext-bridge", version, about, long_about = None)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent command-line switch; a state machine would hide that"
)]
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

    /// Data directory: plugins, host sources, state, token. Defaults to `~/.vrcnext-plugins`
    /// (`%LOCALAPPDATA%\vrcnext-plugins` on Windows).
    ///
    /// Overriding it is how a second instance on a spare port keeps its own token and state.
    #[arg(long, env = "VRCNEXT_BRIDGE_DATA_DIR")]
    pub(crate) data_dir: Option<std::path::PathBuf>,

    /// Replace the pairing token with a fresh one and exit. Every paired page must be re-paired.
    #[arg(long, conflicts_with = "print_token")]
    pub(crate) rotate_token: bool,

    /// Print the pairing token (generating it if this is the first run) and exit.
    #[arg(long)]
    pub(crate) print_token: bool,

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

    /// Runtime worker threads. Services run on a separate blocking pool, so a handful is plenty.
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

    /// Offer the `remote` service: `POST /v1/remote/eval` runs a snippet inside the paired
    /// VRCNext page and returns its result.
    ///
    /// Off by default. Anyone holding the pairing token can then drive the app directly, which
    /// is the point — a script or an agent can inspect and operate the page without touching the
    /// desktop's pointer — but it is also why it has to be asked for.
    #[arg(long, env = "VRCNEXT_BRIDGE_REMOTE")]
    pub(crate) remote: bool,

    /// Offer the REST call surface: `GET /v1/describe` and `POST /v1/<service>/<method>`.
    ///
    /// Off by default, and not part of normal use. The plugin system and its plugins reach the
    /// bridge over the shared WebSocket alone; `/v1/ws` and the `/v1/health` probe it opens with
    /// are always served, so an end user never needs this. It exists so a script or an agent can
    /// call the same services from outside the page — `curl` a service, drive `remote`, rebuild
    /// the bundle — which is a second way in, and therefore asked for rather than assumed.
    #[arg(long, env = "VRCNEXT_BRIDGE_REST")]
    pub(crate) rest: bool,

    /// Compile the installed plugins into the theme bundle and exit.
    ///
    /// The same work `plugins/build` does, without a running daemon or a way in: the installer
    /// needs one build before VRCNext first starts, and should not have to open the REST surface
    /// to get it.
    #[arg(long)]
    pub(crate) build_plugins: bool,

    /// Log level: error, warn, info, debug, trace.
    #[arg(long, default_value = "info", env = "VRCNEXT_BRIDGE_LOG")]
    pub(crate) log: String,
}

impl Config {
    /// Reject configurations that would widen the daemon's reach beyond this machine.
    ///
    /// # Errors
    ///
    /// Fails if the listen address is not loopback. There is deliberately no flag to override the loopback requirement: a bridge that
    /// can put notifications on someone's screen has no business accepting connections from the
    /// network, and an override would exist only to be misused.
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.listen.ip().is_loopback() {
            bail!(
                "--listen must be a loopback address; {} would accept connections from the network",
                self.listen
            );
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
            vec![
                SinkChoice::Wayvr,
                #[cfg(unix)]
                SinkChoice::Freedesktop,
            ]
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
