//! The trust store: which signing keys the user has accepted, and for what.
//!
//! [`crate::signing`] can only say "one key made this tree". Deciding that a key belongs to the
//! author is not a cryptographic question, so it is not answered here either: the store just
//! remembers the answer the user gave at the native prompt, so they are asked once per key
//! rather than once per install.
//!
//! Two facts are kept, and the difference between them matters:
//!
//! - **A key is trusted.** Recorded here, under its [`crate::signing::key_id`].
//! - **A plugin is installed under a key.** Recorded on the plugin's own record in
//!   [`crate::service`], because that is what makes an update by a *different* trusted key still
//!   a change worth asking about. Trusting an author does not let them take over someone else's
//!   plugin.
//!
//! The store lives in the bridge's own reserved state namespace, so a plugin cannot read or
//! write it: `state` refuses every namespace beginning with `bridge.`.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::StateStore;

/// The state namespace holding one record per trusted key.
pub const KEYS_NS: &str = "bridge.plugin-keys";

/// A signing key the user has accepted, and what has been seen signed with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedKey {
    /// The key itself, hex. Kept so the fingerprint can be re-derived and shown.
    pub public_key: String,
    /// What the user was told the key belongs to when they accepted it: the plugin id and the
    /// URL it came from. Not a claim about identity, a reminder of the moment.
    pub label: String,
    /// Milliseconds since the epoch.
    pub trusted_at: u64,
    /// Milliseconds since the epoch; the last install or update this key signed.
    pub last_used_at: u64,
    /// Plugin ids installed or updated under this key, in the order first seen.
    pub plugins: Vec<String>,
}

/// Reads and writes [`TrustedKey`] records. Cheap to construct; the state store is the state.
pub struct TrustStore<'a> {
    state: &'a StateStore,
}

impl<'a> TrustStore<'a> {
    /// Wrap a state store.
    #[must_use]
    pub fn new(state: &'a StateStore) -> Self {
        Self { state }
    }

    /// The record for `key_id`, if the user has accepted that key.
    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<TrustedKey> {
        self.state
            .get(KEYS_NS, key_id)
            .and_then(|value| serde_json::from_value(value).ok())
    }

    /// Every trusted key, by fingerprint.
    #[must_use]
    pub fn list(&self) -> Vec<(String, TrustedKey)> {
        self.state
            .list(KEYS_NS)
            .into_iter()
            .filter_map(|(id, value)| Some((id, serde_json::from_value(value).ok()?)))
            .collect()
    }

    /// Record that `key_id` is trusted and has just signed `plugin`.
    ///
    /// Trusting is idempotent: a key that is already trusted keeps its original `trustedAt` and
    /// label, and only gains the plugin and the timestamp. That is deliberate — the moment the
    /// user made the decision is the interesting one, and nothing later should quietly rewrite
    /// it.
    ///
    /// # Errors
    ///
    /// Any error from the state store.
    pub fn record(
        &self,
        key_id: &str,
        public_key: &str,
        label: &str,
        plugin: &str,
        now: u64,
    ) -> Result<(), crate::state::StateError> {
        let mut entry = self.get(key_id).unwrap_or_else(|| TrustedKey {
            public_key: public_key.to_owned(),
            label: label.to_owned(),
            trusted_at: now,
            last_used_at: now,
            plugins: Vec::new(),
        });
        entry.last_used_at = now;
        if !entry.plugins.iter().any(|known| known == plugin) {
            entry.plugins.push(plugin.to_owned());
        }
        self.state.set(KEYS_NS, key_id, json!(entry))
    }

    /// Forget `key_id`. The next tree it signs is treated as a new author again.
    ///
    /// Nothing is uninstalled: code already on disk stays until the user removes it. Forgetting a
    /// key is about what happens next, not about undoing what happened.
    ///
    /// # Errors
    ///
    /// Any error from the state store.
    pub fn forget(&self, key_id: &str) -> Result<(), crate::state::StateError> {
        self.state.delete(KEYS_NS, key_id)
    }
}

#[cfg(test)]
mod tests {
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
}
