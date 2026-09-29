//! The `hello`/`welcome` exchange that unlocks a socket.
//!
//! # Why the socket needs its own credential check
//!
//! CORS does not protect a WebSocket upgrade: any page in any browser on the machine can complete
//! a `ws://127.0.0.1` handshake. The origin check at upgrade catches web pages, but a native
//! process running as another user on a shared machine sends no `Origin` at all. The pairing
//! token — a file only this user can read — is what tells the bridge the peer is *this* user's
//! VRCNext, and the first frame is where it is presented.
//!
//! Until a valid hello arrives the socket carries nothing: no request is dispatched, no log
//! batch is written, no push is sent. That is the "locked" state the transport enforces; this
//! module decides whether the first frame unlocks it, and with what close reason if not.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::limits::MAX_CLIENT_CHARS;

/// The first frame the page sends.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum FirstFrame {
    /// Present the pairing token.
    Hello {
        /// The pairing token, as read from the token file.
        token: String,
        /// What is connecting, for the daemon log: `vrcnext-plugin-system/<version>`.
        client: String,
    },
}

/// The frame that unlocks the socket.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Welcome {
    /// The socket is open for requests.
    Welcome {
        /// Bridge version.
        version: &'static str,
        /// The same payload as `GET /v1/describe`'s `services`.
        services: Value,
    },
}

/// Why the first frame did not unlock the socket. Each maps to a close reason the page can
/// distinguish: `unpaired` in its status is the `Unauthorized` case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloRefusal {
    /// The first frame was not a well-formed hello, or none arrived within the deadline.
    HelloRequired,
    /// The token was wrong.
    Unauthorized,
}

impl HelloRefusal {
    /// The WebSocket close reason. Both are sent with close code 1008 (policy violation).
    #[must_use]
    pub const fn close_reason(self) -> &'static str {
        match self {
            Self::HelloRequired => "hello_required",
            Self::Unauthorized => "unauthorized",
        }
    }
}

/// The WebSocket close code used for every refusal: 1008, policy violation.
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;

/// A hello that matched the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// The client string, bounded, for the log line.
    pub client: String,
}

/// Judge the first frame.
///
/// The token comparison is constant-time so a peer cannot learn the token byte by byte from
/// response timing; the length is not secret, since every token has the same length.
///
/// # Errors
///
/// [`HelloRefusal::HelloRequired`] if `text` is not a hello, [`HelloRefusal::Unauthorized`] if
/// its token does not match `expected`.
pub fn check_hello(text: &str, expected: &str) -> Result<Accepted, HelloRefusal> {
    let Ok(FirstFrame::Hello { token, client }) = serde_json::from_str::<FirstFrame>(text) else {
        return Err(HelloRefusal::HelloRequired);
    };
    if !constant_time_eq(&token, expected) {
        return Err(HelloRefusal::Unauthorized);
    }
    // Bounded and escaped before it can reach a log line: the client string is the one piece of
    // free text a not-yet-trusted peer gets to choose.
    let client: String = client.chars().take(MAX_CLIENT_CHARS).collect();
    Ok(Accepted {
        client: client.escape_debug().to_string(),
    })
}

/// Compare two secrets without leaking their common prefix through timing.
#[must_use]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests;
