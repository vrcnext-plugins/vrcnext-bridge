#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::{Manifest, ManifestError};

/// A manifest with every field, as a JSON string so the tests can patch it.
pub(crate) fn full() -> serde_json::Value {
    serde_json::json!({
        "id": "friend-alerts",
        "name": "Friend alerts",
        "version": "1.2.0",
        "apiVersion": "^0.2.0",
        "description": "Alerts when friends come online.",
        "author": "someone",
        "homepage": "https://example.com",
        "tags": ["notifications"],
        "permissions": ["host:events", "native"],
        "optionalPermissions": ["network"],
        "actions": ["getFriends"],
        "events": ["friendOnline"],
        "hosts": ["api.example.com"],
        "dependencies": ["presence-core"]
    })
}

fn parse(value: &serde_json::Value) -> Result<Manifest, ManifestError> {
    Manifest::parse(&serde_json::to_vec(value).unwrap())
}

fn patched(field: &str, value: serde_json::Value) -> Result<Manifest, ManifestError> {
    let mut m = full();
    m[field] = value;
    parse(&m)
}

#[test]
fn the_full_example_parses_and_round_trips() {
    let manifest = parse(&full()).unwrap();
    assert_eq!(manifest.id, "friend-alerts");
    assert_eq!(serde_json::to_value(&manifest).unwrap(), full());
}

#[test]
fn only_the_required_fields_are_required() {
    let minimal = serde_json::json!({
        "id": "ab", "name": "n", "version": "0.0.1", "apiVersion": "0.2.0", "description": "d"
    });
    assert!(parse(&minimal).is_ok());
    for required in ["id", "name", "version", "apiVersion", "description"] {
        let mut m = full();
        m.as_object_mut().unwrap().remove(required);
        assert!(
            matches!(parse(&m), Err(ManifestError::Shape(_))),
            "{required}"
        );
    }
}

#[test]
fn unknown_fields_are_refused() {
    assert!(matches!(
        patched("main", serde_json::json!("x.ts")),
        Err(ManifestError::Shape(_))
    ));
}

#[test]
fn each_field_rule_bites() {
    let cases: &[(&str, serde_json::Value)] = &[
        ("id", serde_json::json!("../x")),
        ("id", serde_json::json!("Caps")),
        ("name", serde_json::json!("")),
        ("version", serde_json::json!("1.2")),
        ("version", serde_json::json!("v1.2.3")),
        ("apiVersion", serde_json::json!("")),
        ("apiVersion", serde_json::json!("^0.2.0; rm")),
        ("apiVersion", serde_json::json!("*")),
        ("apiVersion", serde_json::json!(">=0.2.0 || <0.1.0")),
        ("apiVersion", serde_json::json!("1.x")),
        ("version", serde_json::json!("1.2.3-beta")),
        ("dependencies", serde_json::json!(["Not-An-Id"])),
        ("dependencies", serde_json::json!(["friend-alerts"])),
        ("description", serde_json::json!("x".repeat(201))),
        (
            "tags",
            serde_json::json!(["a", "b", "c", "d", "e", "f", "g", "h", "i"]),
        ),
        ("permissions", serde_json::json!(["root"])),
        ("permissions", serde_json::json!(["native", "native"])),
        ("optionalPermissions", serde_json::json!(["everything"])),
        ("actions", serde_json::json!(["get*"])),
        ("events", serde_json::json!(["friend online"])),
        ("hosts", serde_json::json!(["*.example.com"])),
        ("hosts", serde_json::json!(["https://example.com"])),
        ("hosts", serde_json::json!(["example.com/path"])),
        ("hosts", serde_json::json!(["example.com:abc"])),
    ];
    for (field, value) in cases {
        let result = patched(field, value.clone());
        assert!(
            matches!(&result, Err(ManifestError::Field { field: f, .. }) if f == field),
            "{field}={value}: {result:?}"
        );
    }
}

#[test]
fn hosts_with_ports_and_every_accepted_range_shape_are_fine() {
    assert!(patched("hosts", serde_json::json!(["api.example.com:8443"])).is_ok());
    for range in [
        "0.2.0",
        "=0.2.0",
        "^0.2.0",
        "~0.2.1",
        ">=0.2.0 <1.0.0",
        ">0.1.0 <=0.9.9",
    ] {
        assert!(
            patched("apiVersion", serde_json::json!(range)).is_ok(),
            "{range}"
        );
    }
}
