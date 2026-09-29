#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use super::TrustStore;
use crate::fsutil::scratch_dir;
use crate::state::StateStore;

fn store(name: &str) -> (std::path::PathBuf, StateStore) {
    let dir = scratch_dir(&format!("trust-{name}"));
    let state = StateStore::open(dir.join("state.json")).unwrap();
    (dir, state)
}

#[test]
fn trusting_twice_keeps_the_first_decision_and_collects_the_plugins() {
    let (dir, state) = store("twice");
    let keys = TrustStore::new(&state);
    keys.record("ab-cd", "00ff", "club-security", "club-security", 10)
        .unwrap();
    keys.record("ab-cd", "00ff", "patches", "patches", 20)
        .unwrap();

    let entry = keys.get("ab-cd").unwrap();
    assert_eq!(entry.trusted_at, 10);
    assert_eq!(entry.last_used_at, 20);
    assert_eq!(entry.label, "club-security");
    assert_eq!(entry.plugins, ["club-security", "patches"]);
    assert_eq!(keys.list().len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn forgetting_a_key_makes_it_unknown_again() {
    let (dir, state) = store("forget");
    let keys = TrustStore::new(&state);
    keys.record("ab-cd", "00ff", "demo", "demo", 10).unwrap();
    keys.forget("ab-cd").unwrap();
    assert!(keys.get("ab-cd").is_none());
    assert!(keys.list().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}
