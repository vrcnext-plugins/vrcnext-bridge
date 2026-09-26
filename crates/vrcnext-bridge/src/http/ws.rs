//! `/v1/ws` — the one socket the page keeps open.
//!
//! Everything the plugin system does with the bridge goes over this: service calls, correlated by
//! id so several can be in flight; log batches from the page, fire-and-forget; and the daemon's
//! own log lines pushed back the other way. The envelope is defined in
//! [`vrcnext_bridge_core::envelope`].
//!
//! # Admission
//!
//! The [`super::guard`] middleware has already run by the time the upgrade reaches this module,
//! so an origin that is not allow-listed never gets here. See the guard for why that is the only
//! defence a WebSocket has.
//!
//! # Shape of the session
//!
//! One task per socket, `select!`ing over three things: frames from the peer, responses coming
//! back from service calls, and the daemon's log broadcast. Nothing blocks in that loop — service
//! calls are spawned onto the blocking pool and answer through a channel — so a slow D-Bus call
//! neither delays a quick one nor stops log lines flowing.

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use tokio::sync::{broadcast, mpsc};
use vrcnext_bridge_core::RateLimiter;
use vrcnext_bridge_core::envelope::{ClientMessage, Inbound, Request, ServerMessage};
use vrcnext_bridge_core::logs::{LogRecordIn, LogWriteRequest, LogWriter};

use super::AppState;

/// Largest frame accepted. A batch of 200 records at 4000 characters each cannot exceed this.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Log frames per second one connection may send before it is closed.
///
/// Separate from the request rate limiter: a log stream is expected to be chatty, but a runaway
/// loop writing to a file on the user's disk still has to be stopped.
const LOG_FRAMES_PER_SECOND: f64 = 200.0;
const LOG_FRAME_BURST: u32 = 400;

/// Responses waiting to be written. Backpressure on the calls, not a drop.
const RESPONSE_QUEUE: usize = 64;

/// Upgrade and hand the socket to [`session`].
pub(crate) async fn upgrade(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| session(socket, state))
}

/// Everything one connection needs, so the frame handlers have one parameter.
struct Session {
    state: Arc<AppState>,
    log_limiter: RateLimiter,
    replies: mpsc::Sender<ServerMessage>,
    written: u64,
}

async fn session(mut socket: WebSocket, state: Arc<AppState>) {
    log::info!(
        "socket opened; plugin logs go to {}",
        state.log_writer.location()
    );

    let mut daemon_log = state.broadcaster.subscribe();
    let (replies, mut inbox) = mpsc::channel(RESPONSE_QUEUE);
    let mut session = Session {
        state,
        log_limiter: RateLimiter::new(LOG_FRAMES_PER_SECOND, LOG_FRAME_BURST),
        replies,
        written: 0,
    };
    let mut lagged: u64 = 0;

    loop {
        tokio::select! {
            inbound = socket.recv() => {
                let Some(Ok(message)) = inbound else { break };
                match message {
                    Message::Text(text) if session.on_text(text.as_str()).await => {}
                    Message::Text(_) | Message::Close(_) => break,
                    // Binary carries nothing this socket understands; ping and pong are axum's.
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) => {}
                }
            }
            Some(reply) = inbox.recv() => {
                if send(&mut socket, &reply).await.is_err() { break; }
            }
            pushed = daemon_log.recv() => {
                match pushed {
                    Ok(record) => {
                        let push = ServerMessage::Push { event: "log", data: serde_json::json!(record) };
                        if send(&mut socket, &push).await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => lagged = lagged.saturating_add(skipped),
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    log::info!(
        "socket closed after {} plugin log record(s); {lagged} daemon line(s) were not delivered",
        session.written
    );
}

/// Serialise and write one frame.
async fn send(socket: &mut WebSocket, message: &ServerMessage) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|error| {
        log::error!("failed to encode a frame: {error}");
    })?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|error| log::debug!("socket write failed: {error}"))
}

impl Session {
    /// Handle one text frame. `false` means the connection should be closed.
    async fn on_text(&mut self, text: &str) -> bool {
        let inbound = match serde_json::from_str::<ClientMessage>(text) {
            // The parse error is not surfaced: serde quotes field names from the input, and this
            // socket never echoes caller content.
            Err(_) => Err("frame is not a recognised envelope".to_owned()),
            Ok(message) => message.validate().map_err(|error| error.to_string()),
        };

        match inbound {
            Ok(Inbound::Request(request)) => {
                self.on_request(request);
                true
            }
            Ok(Inbound::Logs(records)) => self.on_logs(records).await,
            Err(message) => {
                log::warn!("rejected a frame: {message}");
                self.push_error(&message);
                true
            }
        }
    }

    /// Spawn the call and let its answer come back through the reply channel.
    ///
    /// The request rate limit is the same bucket HTTP uses, so a page cannot sidestep it by
    /// switching transports.
    fn on_request(&self, request: Request) {
        if let Err(refusal) = self.state.guard.check_rate() {
            let reply = ServerMessage::error(request.id, refusal.code(), refusal.message());
            self.queue(reply);
            return;
        }

        let services = Arc::clone(&self.state.services);
        let replies = self.replies.clone();
        tokio::spawn(async move {
            let id = request.id.clone();
            let reply =
                match super::dispatch(&services, request.service, request.method, request.params)
                    .await
                {
                    Ok(value) => ServerMessage::ok(id, value),
                    Err(error) => ServerMessage::from_service_error(id, &error),
                };
            let _ = replies.send(reply).await;
        });
    }

    /// Validate and append a log batch. `false` if the connection has exceeded its log budget.
    async fn on_logs(&mut self, records: Vec<LogRecordIn>) -> bool {
        if !self.log_limiter.try_acquire() {
            log::warn!("socket exceeded its log frame rate; closing");
            return false;
        }
        let writer = Arc::clone(&self.state.log_writer);
        match ingest(records, writer).await {
            Ok(count) => self.written = self.written.saturating_add(count),
            Err(reason) => log::warn!("rejected a log frame: {reason}"),
        }
        true
    }

    /// Tell the peer a frame was refused. There is no id to answer under, so it is a push.
    fn push_error(&self, message: &str) {
        self.queue(ServerMessage::Push {
            event: "error",
            data: serde_json::json!({ "code": "bad_request", "message": message }),
        });
    }

    /// Queue a frame for the session loop to write.
    ///
    /// `try_send` rather than `send`: the loop is the only thing draining this channel, and it is
    /// the thing calling here, so waiting on it would be waiting on ourselves. A full queue means
    /// the peer is not reading, and one dropped error frame is the least of its problems.
    fn queue(&self, message: ServerMessage) {
        if self.replies.try_send(message).is_err() {
            log::debug!("reply queue full; dropped a frame");
        }
    }
}

/// Validate and append one batch, off the runtime's async threads.
async fn ingest(records: Vec<LogRecordIn>, writer: Arc<dyn LogWriter>) -> Result<u64, String> {
    tokio::task::spawn_blocking(move || {
        let records = LogWriteRequest { records }
            .validate()
            .map_err(|error| error.to_string())?;
        writer.append(&records)?;
        Ok(records.len() as u64)
    })
    .await
    .unwrap_or_else(|join_error| Err(format!("log writer failed: {join_error}")))
}
