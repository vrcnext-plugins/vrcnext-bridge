//! `vrcnext-bridge` — a loopback capability bridge for VRCNext plugins.
//!
//! VRCNext's page can only speak HTTP. Anything a plugin wants that needs a UDP socket, a D-Bus
//! connection or a unix socket has to happen in a native process; this is that process.
//!
//! The bridge is a **service host**, not a notification daemon. `notify` is the first service and
//! the only one that ships today, but the transport, the request guard, the rate limiter and the
//! wiring know nothing about notifications — a future OSC or presence service registers beside it
//! without touching any of that. Within `notify`, each destination is a separately addressable
//! sink, so a plugin can target VR alone, the desktop alone, or both with different presentation.
//!
//! Run `vrcnext-bridge --help` for options, or `GET /v1/describe` for what a running instance
//! actually offers.

mod config;
mod http;
mod startup;

use anyhow::Result;
use clap::Parser as _;

use config::Config;
use http::BridgeServer;

/// Reported by `/v1/health` and `/v1/describe` so a plugin can tell what it is talking to.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    let config = Config::parse();
    config.validate()?;

    env_logger::Builder::new()
        .parse_filters(&config.log)
        .format_timestamp_secs()
        .init();

    let services = startup::build_services(&config);
    startup::log_banner(&config, &services);

    let server = BridgeServer::bind(&config, services)?;
    log::info!("listening on http://{}", config.listen);
    server.serve()
}
