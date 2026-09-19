//! End-to-end behaviour of the `notify` service, against a recording sink.
//!
//! These exercise the part plugins actually depend on: that naming one target reaches only that
//! target, that per-target overrides land on the right target, and that every bound is enforced.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "a failing assertion is how a test reports; the float comparisons check values \
              that passed through unchanged, so exact equality is the property under test"
)]

use std::sync::{Arc, Mutex};

use serde_json::json;
use vrcnext_bridge_core::notify::{NotifyService, SinkSet};
use vrcnext_bridge_core::{
    Notification, NotifyRequest, Service, ServiceRegistry, Sink, SinkError, SinkHealth,
};

/// A sink that records what it was asked to deliver, and optionally always fails.
struct Recorder {
    name: &'static str,
    fail: bool,
    seen: Mutex<Vec<Notification>>,
}

impl Recorder {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            fail: false,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn failing(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            fail: true,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<Notification> {
        self.seen.lock().expect("lock").clone()
    }
}

impl Sink for Recorder {
    fn name(&self) -> &'static str {
        self.name
    }
    fn describe(&self) -> String {
        format!("recorder {}", self.name)
    }
    fn honours(&self) -> &'static [&'static str] {
        &["title", "content"]
    }
    fn health(&self) -> SinkHealth {
        SinkHealth::Up
    }
    fn deliver(&self, notification: &Notification) -> Result<(), SinkError> {
        if self.fail {
            return Err(SinkError::Unavailable(self.name, "not running".to_owned()));
        }
        self.seen.lock().expect("lock").push(notification.clone());
        Ok(())
    }
}

fn service_with(sinks: Vec<Arc<dyn Sink>>) -> NotifyService {
    let mut set = SinkSet::new();
    for sink in sinks {
        set.register(sink);
    }
    NotifyService::new(set)
}

#[test]
fn naming_one_sink_reaches_only_that_sink() {
    let vr = Recorder::new("wayvr");
    let desktop = Recorder::new("freedesktop");
    let service = service_with(vec![
        Arc::clone(&vr) as Arc<dyn Sink>,
        Arc::clone(&desktop) as _,
    ]);

    let result = service
        .call("send", json!({ "title": "VR only", "sinks": ["wayvr"] }))
        .expect("should deliver");

    assert_eq!(result["delivered"], json!(["wayvr"]));
    assert_eq!(vr.seen().len(), 1);
    assert!(
        desktop.seen().is_empty(),
        "desktop must not have been touched"
    );
}

#[test]
fn omitting_sinks_reaches_every_target() {
    let vr = Recorder::new("wayvr");
    let desktop = Recorder::new("freedesktop");
    let service = service_with(vec![
        Arc::clone(&vr) as Arc<dyn Sink>,
        Arc::clone(&desktop) as _,
    ]);

    service
        .call("send", json!({ "title": "Both" }))
        .expect("deliver");

    assert_eq!(vr.seen().len(), 1);
    assert_eq!(desktop.seen().len(), 1);
}

#[test]
fn overrides_apply_per_target_and_leave_others_alone() {
    let vr = Recorder::new("wayvr");
    let desktop = Recorder::new("freedesktop");
    let service = service_with(vec![
        Arc::clone(&vr) as Arc<dyn Sink>,
        Arc::clone(&desktop) as _,
    ]);

    service
        .call(
            "send",
            json!({
                "title": "Friend online",
                "content": "shared",
                "opacity": 1.0,
                "overrides": {
                    "wayvr": { "content": "tall panel", "height": 220.0, "opacity": 0.85 }
                }
            }),
        )
        .expect("deliver");

    let in_vr = &vr.seen()[0];
    assert_eq!(in_vr.content, "tall panel");
    assert_eq!(in_vr.height, Some(220.0));
    assert_eq!(in_vr.opacity, 0.85);
    assert_eq!(
        in_vr.title, "Friend online",
        "unpatched fields are inherited"
    );

    let on_desktop = &desktop.seen()[0];
    assert_eq!(on_desktop.content, "shared");
    assert_eq!(on_desktop.height, None);
    assert_eq!(on_desktop.opacity, 1.0);
}

#[test]
fn an_override_for_an_untargeted_sink_is_ignored() {
    let vr = Recorder::new("wayvr");
    let service = service_with(vec![Arc::clone(&vr) as Arc<dyn Sink>]);

    service
        .call(
            "send",
            json!({
                "title": "t",
                "sinks": ["wayvr"],
                "overrides": { "freedesktop": { "title": "never used" } }
            }),
        )
        .expect("deliver");

    assert_eq!(vr.seen()[0].title, "t");
}

#[test]
fn one_failing_sink_does_not_stop_the_others() {
    let broken = Recorder::failing("wayvr");
    let desktop = Recorder::new("freedesktop");
    let service = service_with(vec![broken as Arc<dyn Sink>, Arc::clone(&desktop) as _]);

    let result = service
        .call("send", json!({ "title": "t" }))
        .expect("deliver");

    assert_eq!(
        result["ok"],
        json!(true),
        "partial success is still success"
    );
    assert_eq!(result["delivered"], json!(["freedesktop"]));
    assert_eq!(result["failed"][0]["sink"], json!("wayvr"));
    assert_eq!(desktop.seen().len(), 1);
}

#[test]
fn an_unknown_sink_is_a_400_naming_what_exists() {
    let service = service_with(vec![Recorder::new("wayvr") as Arc<dyn Sink>]);

    let error = service
        .call("send", json!({ "title": "t", "sinks": ["xsoverlay"] }))
        .expect_err("should refuse");

    assert_eq!(error.status(), 400);
    assert!(error.to_string().contains("wayvr"), "{error}");
}

#[test]
fn a_bridge_with_no_sinks_says_so_rather_than_claiming_success() {
    let service = service_with(vec![]);
    let error = service
        .call("send", json!({ "title": "t" }))
        .expect_err("should refuse");
    assert_eq!(error.status(), 503);
}

#[test]
fn unknown_methods_and_services_are_404() {
    let mut registry = ServiceRegistry::new();
    registry.register(Arc::new(service_with(vec![
        Recorder::new("wayvr") as Arc<dyn Sink>
    ])));

    assert_eq!(
        registry
            .call("notify", "explode", json!({}))
            .expect_err("no such method")
            .status(),
        404
    );
    assert_eq!(
        registry
            .call("osc", "send", json!({}))
            .expect_err("no such service")
            .status(),
        404
    );
}

#[test]
fn describe_advertises_targets_so_plugins_can_adapt() {
    let mut registry = ServiceRegistry::new();
    registry.register(Arc::new(service_with(vec![
        Recorder::new("wayvr") as Arc<dyn Sink>
    ])));

    let described = registry.describe();
    assert_eq!(described["notify"]["methods"], json!(["send", "targets"]));
    assert_eq!(described["notify"]["targets"][0]["name"], json!("wayvr"));
    assert_eq!(described["notify"]["targets"][0]["health"], json!("up"));
}

// Validation

fn request(title: &str) -> NotifyRequest {
    NotifyRequest {
        title: title.to_owned(),
        ..NotifyRequest::default()
    }
}

#[test]
fn a_title_is_required() {
    assert!(request("   ").validate().is_err());
}

#[test]
fn over_long_strings_are_refused() {
    let error = request(&"a".repeat(10_000))
        .validate()
        .expect_err("too long");
    assert!(error.to_string().contains("character limit"), "{error}");
}

#[test]
fn control_characters_are_refused_in_titles_but_allowed_in_bodies() {
    let mut sneaky = request("ok");
    sneaky.title = "line\u{1b}[31mone".to_owned();
    assert!(
        sneaky.validate().is_err(),
        "escape sequences do not belong in a title"
    );

    let mut multiline = request("ok");
    multiline.content = "first\nsecond\tthird".to_owned();
    assert!(
        multiline.validate().is_ok(),
        "newlines are legitimate body text"
    );
}

#[test]
fn non_finite_and_out_of_range_numbers_are_refused() {
    for bad in [f32::NAN, f32::INFINITY] {
        let mut value = request("t");
        value.opacity = Some(bad);
        assert!(value.validate().is_err(), "{bad} should be refused");
    }

    let mut too_long = request("t");
    too_long.timeout_secs = Some(3_600.0);
    let error = too_long.validate().expect_err("out of range");
    assert!(error.to_string().contains("between"), "{error}");
}

#[test]
fn a_zero_timeout_means_use_the_sink_default() {
    let mut value = request("t");
    value.timeout_secs = Some(0.0);
    assert_eq!(value.validate().expect("valid").timeout_secs, None);
}

#[test]
fn defaults_are_what_the_docs_claim() {
    let notification = request("t").validate().expect("valid");
    assert_eq!(notification.source_app, "VRCNext");
    assert_eq!(notification.opacity, 1.0);
    assert!(!notification.sound);
    assert!(!notification.always_show);
    assert_eq!(notification.height, None);
}

#[test]
fn a_typo_in_a_field_name_is_an_error_not_a_silent_drop() {
    let error = serde_json::from_value::<NotifyRequest>(json!({ "title": "t", "timeoutSec": 3 }))
        .expect_err("unknown field");
    assert!(error.to_string().contains("timeoutSec"), "{error}");
}
