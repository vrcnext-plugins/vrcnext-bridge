//! Native confirmation on a freedesktop session: a notification with Confirm and Deny buttons.
//!
//! The question is put through `org.freedesktop.Notifications` with two actions. The daemon
//! draws it as a toast with buttons on the monitor; an overlay that mirrors desktop
//! notifications shows it in VR too. The page cannot reach the session bus, so a click here is
//! the user's, not a plugin's.
//!
//! Urgency is critical so the daemon does not expire the prompt on its own, and the bridge
//! enforces its own deadline instead. Dismissing the notification is a denial: the user waved
//! the question away, and "did not say yes" has to mean no.

use std::sync::mpsc;
use std::time::Duration;

use vrcnext_bridge_core::{APPROVAL_DEADLINE_SECS, Approval, ApprovalRequest, Approver};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::Value;

const BUS_NAME: &str = "org.freedesktop.Notifications";
const OBJECT_PATH: &str = "/org/freedesktop/Notifications";
const APP_NAME: &str = "VRCNext Bridge";
const ACTION_CONFIRM: &str = "confirm";

/// Asks through the session's notification daemon.
pub struct FreedesktopApprover {
    connection: Connection,
}

/// A signal that concerns one notification.
enum Signal {
    /// `ActionInvoked(id, action_key)`.
    Action(u32, String),
    /// `NotificationClosed(id, reason)`.
    Closed(u32),
}

impl FreedesktopApprover {
    /// Connect to the session bus.
    ///
    /// # Errors
    ///
    /// The bus error, when there is no session bus. The caller falls back to refusing every
    /// privileged operation and says so in the banner.
    pub fn connect() -> zbus::Result<Self> {
        Ok(Self {
            connection: Connection::session()?,
        })
    }

    fn ask(&self, request: &ApprovalRequest) -> zbus::Result<Approval> {
        let proxy = Proxy::new(&self.connection, BUS_NAME, OBJECT_PATH, BUS_NAME)?;

        // Subscribe before showing the prompt, or a fast click could be missed. The iterator
        // blocks, so it lives on its own thread and reports through a channel that gives the
        // deadline a place to live; once the answer is in, the thread ends on its next signal.
        let signals = proxy.receive_all_signals()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for message in signals {
                let Some(signal) = decode(&message) else {
                    continue;
                };
                if tx.send(signal).is_err() {
                    break;
                }
            }
        });

        let hints: std::collections::HashMap<&str, Value<'_>> =
            [("urgency", Value::U8(2))].into_iter().collect();
        let id: u32 = proxy.call(
            "Notify",
            &(
                APP_NAME,
                0_u32,
                "dialog-warning",
                request.summary.as_str(),
                request.detail.as_str(),
                &[ACTION_CONFIRM, "Confirm", "deny", "Deny"][..],
                hints,
                0_i32,
            ),
        )?;

        let deadline = Duration::from_secs(APPROVAL_DEADLINE_SECS);
        let started = std::time::Instant::now();
        loop {
            let remaining = deadline.saturating_sub(started.elapsed());
            match rx.recv_timeout(remaining) {
                Ok(Signal::Action(that, action)) if that == id => {
                    return Ok(if action == ACTION_CONFIRM {
                        Approval::Approved
                    } else {
                        Approval::Denied
                    });
                }
                Ok(Signal::Closed(that)) if that == id => return Ok(Approval::Denied),
                Ok(_) => {}
                Err(_) => {
                    // Take the stale prompt down so a later click cannot answer a dead question.
                    let _ = proxy.call_method("CloseNotification", &(id,));
                    return Ok(Approval::Denied);
                }
            }
        }
    }
}

fn decode(message: &zbus::Message) -> Option<Signal> {
    let header = message.header();
    let member = header.member()?.as_str();
    let body = message.body();
    match member {
        "ActionInvoked" => body
            .deserialize::<(u32, String)>()
            .ok()
            .map(|(id, action)| Signal::Action(id, action)),
        "NotificationClosed" => body
            .deserialize::<(u32, u32)>()
            .ok()
            .map(|(id, _)| Signal::Closed(id)),
        _ => None,
    }
}

impl Approver for FreedesktopApprover {
    fn approve(&self, request: &ApprovalRequest) -> Approval {
        match self.ask(request) {
            Ok(answer) => answer,
            Err(error) => {
                log::error!("confirmation prompt failed on the session bus: {error}");
                Approval::Unavailable
            }
        }
    }

    fn describe(&self) -> &'static str {
        "desktop notification with Confirm/Deny buttons (org.freedesktop.Notifications)"
    }
}
