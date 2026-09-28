//! The receive half: a socket, a thread, and a push per message.
//!
//! VRChat sends avatar parameters continuously — a few hundred a second while an avatar with
//! many parameters is moving — and every one of them would otherwise become a WebSocket frame.
//! The listener therefore caps how many it forwards per second and counts what it dropped, so a
//! plugin watching one parameter does not pay for every other parameter on the avatar. The count
//! is reported by `status`, because a silent drop is indistinguishable from a bug.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rosc::{OscBundle, OscMessage, OscPacket};
use serde_json::json;

use crate::pusher::Pusher;

use super::proto::from_osc;

/// Most messages forwarded to the page per second.
const MAX_PUSHES_PER_SECOND: u64 = 120;

/// How long a blocking read waits before the loop re-checks whether it was asked to stop.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Largest datagram read. OSC messages are small; a bundle of avatar parameters is far under this.
const MAX_DATAGRAM: usize = 8 * 1024;

/// The event name the page subscribes to.
const EVENT: &str = "osc";

/// A running receive loop.
pub(super) struct Listener {
    port: u16,
    running: Arc<AtomicBool>,
    received: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

impl Listener {
    /// Bind `port` on loopback and start forwarding what arrives.
    ///
    /// # Errors
    ///
    /// The bind error, which is almost always the port already being held by something else —
    /// on Windows, by VRCNext itself.
    pub(super) fn start(port: u16, pusher: Arc<dyn Pusher>) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
        socket.set_read_timeout(Some(READ_TIMEOUT))?;
        let bound = socket.local_addr()?.port();

        let running = Arc::new(AtomicBool::new(true));
        let received = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let listener = Self {
            port: bound,
            running: Arc::clone(&running),
            received: Arc::clone(&received),
            dropped: Arc::clone(&dropped),
        };

        std::thread::Builder::new()
            .name("osc-listener".to_owned())
            .spawn(move || {
                receive_loop(&socket, &running, &pusher, &received, &dropped);
            })?;
        Ok(listener)
    }

    pub(super) const fn port(&self) -> u16 {
        self.port
    }

    pub(super) fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    pub(super) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Ask the thread to finish. It notices within [`READ_TIMEOUT`].
    pub(super) fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A budget of pushes per second, refilled on the second.
struct Budget {
    window: Instant,
    used: u64,
}

impl Budget {
    fn new() -> Self {
        Self {
            window: Instant::now(),
            used: 0,
        }
    }

    /// Whether one more push fits in this second.
    fn allow(&mut self) -> bool {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.used = 0;
        }
        self.used += 1;
        self.used <= MAX_PUSHES_PER_SECOND
    }
}

fn receive_loop(
    socket: &UdpSocket,
    running: &AtomicBool,
    pusher: &Arc<dyn Pusher>,
    received: &AtomicU64,
    dropped: &AtomicU64,
) {
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    let mut budget = Budget::new();
    while running.load(Ordering::Relaxed) {
        let read = match socket.recv_from(&mut buffer) {
            Ok((size, _from)) => size,
            // A timeout is the loop working as intended: it is how `stop` is noticed.
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(error) => {
                log::warn!("osc: the receive socket failed: {error}");
                return;
            }
        };
        let Some(slice) = buffer.get(..read) else {
            continue;
        };
        match rosc::decoder::decode_udp(slice) {
            Ok((_rest, packet)) => {
                for message in flatten(packet) {
                    received.fetch_add(1, Ordering::Relaxed);
                    if budget.allow() {
                        pusher.push(EVENT, message_json(&message));
                    } else {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // Anything on this port that is not OSC is not ours to interpret or to log in full.
            Err(error) => log::debug!("osc: ignoring an undecodable datagram: {error}"),
        }
    }
}

/// A packet as a flat list of messages; a bundle may contain bundles.
fn flatten(packet: OscPacket) -> Vec<OscMessage> {
    match packet {
        OscPacket::Message(message) => vec![message],
        OscPacket::Bundle(OscBundle { content, .. }) => {
            content.into_iter().flat_map(flatten).collect()
        }
    }
}

fn message_json(message: &OscMessage) -> serde_json::Value {
    json!({
        "address": message.addr,
        "args": message.args.iter().map(from_osc).collect::<Vec<_>>(),
    })
}
