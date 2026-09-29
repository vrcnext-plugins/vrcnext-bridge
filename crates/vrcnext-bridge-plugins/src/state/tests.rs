#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use std::sync::Arc;

use serde_json::{Value, json};
use vrcnext_bridge_core::{Service as _, ServiceError};

use super::{StateError, StateService, StateStore};
use crate::fsutil::scratch_dir;

fn service(name: &str) -> (StateService, std::path::PathBuf) {
    let dir = scratch_dir(name);
    let store = StateStore::open(dir.join("state.json")).unwrap();
    (StateService::new(Arc::new(store)), dir)
}

#[test]
fn set_get_list_delete_round_trip() {
    let (svc, dir) = service("roundtrip");
    svc.call(
        "set",
        json!({"ns": "host", "key": "enabled", "value": ["a"]}),
    )
    .unwrap();
    assert_eq!(
        svc.call("get", json!({"ns": "host", "key": "enabled"}))
            .unwrap(),
        json!({"value": ["a"]})
    );
    assert_eq!(
        svc.call("list", json!({"ns": "host"})).unwrap(),
        json!({"entries": {"enabled": ["a"]}})
    );
    svc.call("delete", json!({"ns": "host", "key": "enabled"}))
        .unwrap();
    assert_eq!(
        svc.call("get", json!({"ns": "host", "key": "enabled"}))
            .unwrap(),
        json!({"value": null})
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn values_survive_a_reopen() {
    let dir = scratch_dir("reopen");
    let path = dir.join("state.json");
    StateStore::open(path.clone())
        .unwrap()
        .set("plugin:x", "k", json!(1))
        .unwrap();
    let again = StateStore::open(path).unwrap();
    assert_eq!(again.get("plugin:x", "k"), Some(json!(1)));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn names_are_shaped_and_reserved_namespaces_refused() {
    let (svc, dir) = service("names");
    for bad in ["", "a b", "a/b", &"a".repeat(65)] {
        let err = svc.call("get", json!({"ns": bad, "key": "k"})).unwrap_err();
        assert!(matches!(err, ServiceError::BadRequest(_)), "{bad:?}");
    }
    let err = svc
        .call(
            "set",
            json!({"ns": "bridge.plugins", "key": "k", "value": 1}),
        )
        .unwrap_err();
    assert_eq!(
        err,
        ServiceError::BadRequest(StateError::Reserved.to_string())
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn oversized_values_are_refused_and_nothing_is_written() {
    let (svc, dir) = service("oversize");
    let big = Value::String("x".repeat(super::MAX_VALUE_BYTES));
    let err = svc
        .call("set", json!({"ns": "n", "key": "k", "value": big}))
        .unwrap_err();
    assert_eq!(
        err,
        ServiceError::BadRequest(StateError::ValueTooLarge.to_string())
    );
    assert_eq!(
        svc.call("get", json!({"ns": "n", "key": "k"})).unwrap(),
        json!({"value": null})
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_corrupt_file_is_an_error_not_a_reset() {
    let dir = scratch_dir("corrupt");
    let path = dir.join("state.json");
    std::fs::write(&path, b"{ not json").unwrap();
    assert!(matches!(StateStore::open(path), Err(StateError::Io(_))));
    std::fs::remove_dir_all(dir).ok();
}
