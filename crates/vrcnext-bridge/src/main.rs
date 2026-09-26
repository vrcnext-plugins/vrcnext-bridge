//! `vrcnext-bridge` — a loopback capability bridge for VRCNext plugins.
//!
//! VRCNext's page can only speak HTTP and WebSockets. Anything a plugin wants that needs a UDP
//! socket, a D-Bus connection or a unix socket has to happen in a native process; this is that
//! process.
//!
//! The bridge is a **service host**, not a notification daemon. `notify` is the first service and
//! the only one that ships today, but the transport, the request guard, the rate limiter and the
//! wiring know nothing about notifications — a future OSC or presence service registers beside it
//! without touching any of that. Within `notify`, each destination is a separately addressable
//! sink, so a plugin can target VR alone, the desktop alone, or both with different presentation.
//!
//! Run `vrcnext-bridge --help` for options, or `GET /v1/describe` for what a running instance
//! actually offers.

mod broadcast;
mod config;
mod http;
mod logfile;
mod startup;

use anyhow::{Context as _, Result};
use broadcast::BroadcastLogger;
use clap::Parser as _;

use config::Config;

/// Reported by `/v1/health` and `/v1/describe` so a plugin can tell what it is talking to.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    let config = Config::parse();
    config.validate()?;

    let logger = env_logger::Builder::new()
        .parse_filters(&config.log)
        .format_timestamp_secs()
        .build();

    let broadcaster = BroadcastLogger::install(logger).context("failed to initialise logger")?;

    let wiring = startup::build_services(&config);
    startup::log_banner(&config, &wiring.services);

    // Services and sinks are synchronous and stay that way; the runtime hands each call to a
    // blocking thread. The async runtime exists for the transport: many idle sockets, each
    // waiting on both its peer and the daemon's own log stream, is exactly what it is for.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads())
        .thread_name("bridge-worker")
        .enable_all()
        .build()
        .context("failed to start the runtime")?;

    runtime.block_on(http::serve(&config, wiring, broadcaster))
}
