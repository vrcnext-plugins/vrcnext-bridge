//! Native confirmation of privileged operations.
//!
//! Installing, updating or removing a plugin puts code into the page. The page itself cannot be
//! the thing that confirms that: any script already running there — including a plugin — can
//! click its own dialog. So the bridge asks the *user* through something the page cannot reach:
//! a desktop notification with Confirm/Deny buttons on unix, a message box on Windows.
//!
//! The rule is fail closed. No approver, a broken bus, a dismissed prompt or a timeout all mean
//! the operation does not happen. [`Approval::Unavailable`] exists so the service can tell the
//! user *why* nothing happened, but it is never a pass.

/// What the user is being asked to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The operation, e.g. `install`. Fixed vocabulary, never caller text.
    pub operation: &'static str,
    /// One line, e.g. `Install plugin friend-alerts?`.
    pub summary: String,
    /// What exactly will happen: the URL, the commit, the directory.
    pub detail: String,
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// The user confirmed.
    Approved,
    /// The user declined, dismissed the prompt, or did not answer in time.
    Denied,
    /// No prompt could be shown. Treated exactly like a denial by every caller.
    Unavailable,
}

/// Something that can put a question in front of the user, outside the page.
///
/// `approve` blocks the calling thread until the user answers or the approver's own deadline
/// (120 s) passes. Services run on the blocking pool, so that is fine.
pub trait Approver: Send + Sync {
    /// Ask. Blocks.
    fn approve(&self, request: &ApprovalRequest) -> Approval;

    /// One line for the banner, so the user knows which prompt to expect.
    fn describe(&self) -> &'static str;
}

/// Longest an approver waits for an answer before treating silence as a denial.
pub const APPROVAL_DEADLINE_SECS: u64 = 120;

/// The approver used when no native prompt exists on this platform or session.
pub struct NullApprover;

impl Approver for NullApprover {
    fn approve(&self, _request: &ApprovalRequest) -> Approval {
        Approval::Unavailable
    }

    fn describe(&self) -> &'static str {
        "none: privileged operations will be refused"
    }
}
