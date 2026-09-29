use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Approval, ApprovalRequest, Approver as _, DevApprover, NullApprover};

fn request() -> ApprovalRequest {
    ApprovalRequest {
        operation: "update",
        summary: "Update plugin patches?".into(),
        detail: "From https://example.invalid/p\nCurrently at abc123".into(),
    }
}

#[test]
fn no_approver_is_never_a_pass() {
    assert_eq!(NullApprover.approve(&request()), Approval::Unavailable);
}

#[test]
fn dev_approves_and_announces_every_request() {
    static ANNOUNCED: AtomicUsize = AtomicUsize::new(0);
    let approver = DevApprover::new(|request| {
        assert_eq!(request.summary, "Update plugin patches?");
        ANNOUNCED.fetch_add(1, Ordering::Relaxed);
    });

    assert_eq!(approver.approve(&request()), Approval::Approved);
    assert_eq!(approver.approve(&request()), Approval::Approved);

    assert_eq!(
        ANNOUNCED.load(Ordering::Relaxed),
        2,
        "every skipped prompt is announced, not just the first"
    );
}
