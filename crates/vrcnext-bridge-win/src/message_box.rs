//! `MessageBoxW`, Yes/No, topmost, on its own thread.
//!
//! The box is modal to the thread that shows it, so it gets a thread of its own: the service
//! call that asked is already on the blocking pool and simply waits for the answer. There is
//! no timeout — the box stays until the user answers, which is the point of a native prompt —
//! but the caller's `recv_timeout` still turns silence past the deadline into a denial, and the
//! box is left for the user to dismiss.

use std::sync::mpsc;
use std::time::Duration;

use vrcnext_bridge_core::{APPROVAL_DEADLINE_SECS, Approval, ApprovalRequest, Approver};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MessageBoxW,
};

const TITLE: &str = "VRCNext Bridge";

/// Asks with a Yes/No message box.
pub struct MessageBoxApprover;

/// NUL-terminated UTF-16, which is what the W entry points take.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn show(text: String) -> Approval {
    let text = wide(&text);
    let title = wide(TITLE);
    // SAFETY: both buffers are NUL-terminated and outlive the call; a null owner window is
    // documented as valid; the flags are constants from the same crate.
    #[allow(unsafe_code, reason = "the one FFI call this crate exists for")]
    let answer = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    if answer == IDYES {
        Approval::Approved
    } else {
        Approval::Denied
    }
}

impl Approver for MessageBoxApprover {
    fn approve(&self, request: &ApprovalRequest) -> Approval {
        let text = format!("{}\n\n{}", request.summary, request.detail);
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(show(text));
        });
        rx.recv_timeout(Duration::from_secs(APPROVAL_DEADLINE_SECS))
            .unwrap_or(Approval::Denied)
    }

    fn describe(&self) -> &'static str {
        "Yes/No message box"
    }
}
