#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::FreedesktopSink;
use vrcnext_bridge_core::{NotifyRequest, Urgency};

fn with_timeout(timeout_secs: Option<f32>) -> vrcnext_bridge_core::Notification {
    NotifyRequest {
        title: "t".to_owned(),
        timeout_secs,
        ..NotifyRequest::default()
    }
    .validate()
    .expect("validates")
}

#[test]
fn absent_timeout_means_daemon_default() {
    assert_eq!(FreedesktopSink::expire_timeout_ms(&with_timeout(None)), -1);
}

#[test]
fn zero_timeout_means_daemon_default() {
    assert_eq!(
        FreedesktopSink::expire_timeout_ms(&with_timeout(Some(0.0))),
        -1
    );
}

#[test]
fn seconds_become_milliseconds() {
    assert_eq!(
        FreedesktopSink::expire_timeout_ms(&with_timeout(Some(2.5))),
        2_500
    );
}

#[test]
fn urgency_maps_to_the_spec_hint() {
    assert_eq!(FreedesktopSink::urgency_hint(Urgency::Low), 0);
    assert_eq!(FreedesktopSink::urgency_hint(Urgency::Normal), 1);
    assert_eq!(FreedesktopSink::urgency_hint(Urgency::Critical), 2);
}
