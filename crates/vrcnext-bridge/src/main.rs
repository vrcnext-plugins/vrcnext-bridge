//! `vrcnext-bridge` — a loopback capability bridge for VRCNext plugins.
//!
//! VRCNext's page can only speak HTTP and WebSockets. Anything a plugin wants that needs a UDP
//! socket, a D-Bus connection or a unix socket has to happen in a native process; this is that
//! process.
//!
//! The bridge is a **service host**, not a notification daemon. `plugins` installs and compiles
//! plugins, `state` keeps the page's data, `notify` delivers notifications, `logs` files the
//! page's log lines — and the transport, the request guard, the rate limiter and the wiring know
//! nothing about any of them.
//!
//! Run `vrcnext-bridge --help` for options, or `GET /v1/describe` for what a running instance
//! actually offers.

mod broadcast;
mod config;
mod http;
mod logfile;
mod startup;
mod token;

use anyhow::{Context as _, Result};
use broadcast::BroadcastLogger;
use clap::Parser as _;

use config::Config;
use vrcnext_bridge_core::Paths;

/// Reported by `/v1/health` and `/v1/describe` so a plugin can tell what it is talking to.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    let config = Config::parse();
    config.validate()?;

    let paths = Paths::detect(config.data_dir.clone())?;
    if config.rotate_token || config.print_token {
        return token_command(&config, &paths);
    }

    let logger = env_logger::Builder::new()
        .parse_filters(&config.log)
        .format_timestamp_secs()
        .build();

    let broadcaster = BroadcastLogger::install(logger).context("failed to initialise logger")?;

    let token = token::load_or_create(&paths.token_file())?;
    let wiring = startup::build_services(&config, &paths)?;
    startup::log_banner(&config, &paths, &token, &wiring.services);

    // Services and sinks are synchronous and stay that way; the runtime hands each call to a
    // blocking thread. The async runtime exists for the transport: many idle sockets, each
    // waiting on both its peer and the daemon's own log stream, is exactly what it is for.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads())
        .thread_name("bridge-worker")
        .enable_all()
        .build()
        .context("failed to start the runtime")?;

    runtime.block_on(http::serve(&config, token, wiring, broadcaster))
}

/// `--rotate-token` / `--print-token`: write the token to stdout and stop.
///
/// Stdout, not the log: this is the one output a script wants to capture, and the installer does.
fn token_command(config: &Config, paths: &Paths) -> Result<()> {
    use std::io::Write as _;
    let path = paths.token_file();
    let token = if config.rotate_token {
        token::rotate(&path)?
    } else {
        token::load_or_create(&path)?
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{token}").context("cannot write to stdout")
}
