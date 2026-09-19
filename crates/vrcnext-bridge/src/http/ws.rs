//! The `/v1/logs/stream` WebSocket.
//!
//! # WebSockets are not protected by CORS
//!
//! This is the security point that matters here, and it is easy to get wrong. Every other endpoint
//! on this daemon is shielded by forcing a CORS preflight the browser will refuse for a
//! non-loopback origin. **That mechanism does not exist for WebSockets.** A browser will happily
//! complete a `ws://127.0.0.1` handshake from any page, and the page can then send whatever it
//! likes; there is no preflight and no `Access-Control-Allow-Origin` to withhold.
//!
//! What a browser *does* send is an `Origin` header, and checking it server-side is the only
//! defence. So the upgrade runs the same [`Guard`] admission check as everything else — origin
//! allowlist and bearer token — before a single frame is read. A handshake that fails it is
//! answered with 403 and the socket is dropped.
//!
//! The endpoint is also **write-only**: it accepts log records and sends nothing back but an
//! occasional acknowledgement. It never serves file contents.
//!
//! # Threading
//!
//! [`tiny_http`] hands requests to a small fixed worker pool. A WebSocket lives for as long as the
//! page is open, so handling it on the worker that accepted it would retire that worker for the
//! session — four connections would starve the HTTP endpoints completely. The upgraded socket is
//! therefore moved to its own thread and the worker returns to the pool immediately.

use std::sync::Arc;

use tiny_http::{Request, Response};
use tungstenite::protocol::{Role, WebSocketConfig};
use tungstenite::{Message, WebSocket};
use vrcnext_bridge_core::RateLimiter;
use vrcnext_bridge_core::logs::{LogWriteRequest, LogWriter};

use super::guard::{self, Guard};

/// Largest frame accepted. A batch of 200 records at 4000 characters each cannot exceed this.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Frames per second one connection may send before it is closed.
///
/// Separate from the HTTP rate limiter: a log stream is expected to be chatty, but a runaway loop
/// writing to a file on the user's disk still has to be stopped.
const FRAMES_PER_SECOND: f64 = 200.0;
const FRAME_BURST: u32 = 400;

/// Take over `request` as a WebSocket, or answer with an error.
///
/// Consumes the request either way, so the caller must not respond again.
pub(crate) fn serve_log_stream(request: Request, guard: &Guard, writer: Arc<dyn LogWriter>) {
    if let Err(refusal) = guard.check_admission(&request) {
        log::warn!("refused a log-stream upgrade: {}", refusal.code());
        let response = Response::from_string(refusal.message()).with_status_code(refusal.status());
        if let Err(error) = request.respond(response) {
            log::debug!("could not answer a refused upgrade: {error}");
        }
        return;
    }

    let Some(key) = guard::header(&request, "sec-websocket-key") else {
        respond_plain(request, 400, "missing Sec-WebSocket-Key");
        return;
    };

    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    let headers = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Accept", accept.as_str()),
    ];

    let mut response = Response::empty(101);
    for (name, value) in headers {
        if let Some(header) = guard::make_header(name, value) {
            response.add_header(header);
        }
    }

    let socket = request.upgrade("websocket", response);

    // Off the worker thread immediately — see the module note on threading.
    let spawned = std::thread::Builder::new()
        .name("bridge-log-stream".to_owned())
        .spawn(move || {
            let config = WebSocketConfig::default().max_message_size(Some(MAX_FRAME_BYTES));
            let websocket = WebSocket::from_raw_socket(socket, Role::Server, Some(config));
            pump(websocket, &writer);
        });

    if let Err(error) = spawned {
        log::error!("could not spawn a log-stream thread: {error}");
    }
}

fn respond_plain(request: Request, status: u16, body: &str) {
    let response = Response::from_string(body).with_status_code(status);
    if let Err(error) = request.respond(response) {
        log::debug!("could not answer an upgrade: {error}");
    }
}

/// Read frames until the peer goes away.
fn pump(mut socket: WebSocket<Box<dyn tiny_http::ReadWrite + Send>>, writer: &Arc<dyn LogWriter>) {
    log::info!("log stream opened; writing to {}", writer.location());
    let limiter = RateLimiter::new(FRAMES_PER_SECOND, FRAME_BURST);
    let mut written: u64 = 0;

    loop {
        let message = match socket.read() {
            Ok(message) => message,
            Err(error) => {
                log::debug!("log stream closed: {error}");
                break;
            }
        };

        match message {
            Message::Text(text) => {
                if !limiter.try_acquire() {
                    log::warn!("log stream exceeded its frame rate; closing");
                    let _ = socket.close(None);
                    break;
                }
                match ingest(text.as_str(), writer) {
                    Ok(count) => written = written.saturating_add(count),
                    Err(reason) => log::warn!("rejected a log frame: {reason}"),
                }
            }
            Message::Ping(payload) => {
                // tungstenite queues the pong itself on the next write; flush it.
                let _ = socket.write(Message::Pong(payload));
                let _ = socket.flush();
            }
            Message::Close(_) => break,
            // Binary and Pong carry nothing this endpoint understands.
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    log::info!("log stream ended after {written} record(s)");
}

/// Parse, validate and append one frame's worth of records.
fn ingest(text: &str, writer: &Arc<dyn LogWriter>) -> Result<u64, String> {
    let request: LogWriteRequest = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let records = request.validate().map_err(|error| error.to_string())?;
    writer.append(&records)?;
    Ok(records.len() as u64)
}
