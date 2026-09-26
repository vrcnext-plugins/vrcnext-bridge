//! The `state` service: the page's key-value store, kept by the bridge in `state.json`.
//!
//! The page has nowhere reliable to keep data. Its origin is `http://localhost:<port>`, and the
//! port changes whenever VRCNext cannot bind its saved one, which orphans anything in
//! `localStorage` or `IndexedDB`. The bridge owns a plain file instead, so a plugin's settings and
//! the host's enabled flags survive a port change, a VRCNext reinstall and a cleared browser
//! profile.
//!
//! Every write goes through one lock and one atomic replace of the whole file. The file is small
//! by construction — see [`MAX_VALUE_BYTES`] and [`MAX_FILE_BYTES`] — so rewriting it whole is
//! cheaper than being clever, and a crash mid-write cannot leave a half-written file behind.
//!
//! Namespaces starting with `bridge.` belong to the bridge's own records (installed plugins) and
//! are refused over the service: a page should not be able to make the bridge believe a plugin
//! is installed that never went through validation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::{Map, Value};
use vrcnext_bridge_core::{Service, ServiceError};

use crate::fsutil::write_atomic;

/// Longest namespace or key, in characters.
pub const MAX_NAME_CHARS: usize = 64;

/// Largest single value, serialised.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;

/// Largest the whole file may grow to. A write that would cross it is refused, not truncated.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// Namespace prefix the bridge keeps for itself.
pub const RESERVED_PREFIX: &str = "bridge.";

/// Why a `state` call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// A namespace or key is not `[a-zA-Z0-9_.:-]{1,64}`.
    #[error("{0} must match [a-zA-Z0-9_.:-]{{1,64}}")]
    BadName(&'static str),
    /// The namespace is reserved for the bridge.
    #[error("namespaces starting with `bridge.` are reserved")]
    Reserved,
    /// The serialised value exceeds [`MAX_VALUE_BYTES`].
    #[error("value exceeds {MAX_VALUE_BYTES} bytes serialised")]
    ValueTooLarge,
    /// The write would push the file past [`MAX_FILE_BYTES`].
    #[error("state file would exceed {MAX_FILE_BYTES} bytes")]
    FileFull,
    /// The file could not be read or written.
    #[error("state file: {0}")]
    Io(String),
}

impl From<StateError> for ServiceError {
    fn from(error: StateError) -> Self {
        match error {
            StateError::Io(message) => Self::Internal(message),
            other => Self::BadRequest(other.to_string()),
        }
    }
}

/// Whether `name` is a namespace or key the store accepts.
#[must_use]
pub fn is_name(name: &str) -> bool {
    (1..=MAX_NAME_CHARS).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

type Namespaces = BTreeMap<String, BTreeMap<String, Value>>;

/// The store itself: an in-memory map, mirrored to `state.json` on every write.
pub struct StateStore {
    path: PathBuf,
    inner: Mutex<Namespaces>,
}

impl StateStore {
    /// Load `path`, or start empty if it does not exist.
    ///
    /// A file that exists but does not parse is an error rather than silently replaced: it holds
    /// the user's plugin settings, and losing them to a typo-level corruption should be a
    /// decision someone makes, not one the daemon makes on their behalf.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if the file exists and cannot be read or parsed.
    pub fn open(path: PathBuf) -> Result<Self, StateError> {
        let namespaces = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                StateError::Io(format!("{} is not valid: {error}", path.display()))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Namespaces::new(),
            Err(error) => return Err(StateError::Io(format!("{}: {error}", path.display()))),
        };
        Ok(Self {
            path,
            inner: Mutex::new(namespaces),
        })
    }

    /// Where the file lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read one value. `None` if the namespace or key is absent.
    #[must_use]
    pub fn get(&self, ns: &str, key: &str) -> Option<Value> {
        self.lock()
            .get(ns)
            .and_then(|entries| entries.get(key))
            .cloned()
    }

    /// Every entry in a namespace.
    #[must_use]
    pub fn list(&self, ns: &str) -> BTreeMap<String, Value> {
        self.lock().get(ns).cloned().unwrap_or_default()
    }

    /// Write one value, replacing any previous one.
    ///
    /// # Errors
    ///
    /// [`StateError::ValueTooLarge`], [`StateError::FileFull`], or an I/O failure. On any error
    /// the in-memory map and the file are unchanged.
    pub fn set(&self, ns: &str, key: &str, value: Value) -> Result<(), StateError> {
        if serialised_len(&value) > MAX_VALUE_BYTES {
            return Err(StateError::ValueTooLarge);
        }
        let mut namespaces = self.lock();
        let previous = namespaces
            .entry(ns.to_owned())
            .or_default()
            .insert(key.to_owned(), value);
        match self.persist(&namespaces) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Undo, so memory never claims something the file does not hold.
                let entries = namespaces.entry(ns.to_owned()).or_default();
                match previous {
                    Some(old) => entries.insert(key.to_owned(), old),
                    None => entries.remove(key),
                };
                Err(error)
            }
        }
    }

    /// Remove one value. Removing an absent key is not an error.
    ///
    /// # Errors
    ///
    /// An I/O failure writing the file.
    pub fn delete(&self, ns: &str, key: &str) -> Result<(), StateError> {
        let mut namespaces = self.lock();
        let Some(entries) = namespaces.get_mut(ns) else {
            return Ok(());
        };
        if entries.remove(key).is_none() {
            return Ok(());
        }
        if entries.is_empty() {
            namespaces.remove(ns);
        }
        self.persist(&namespaces)
    }

    /// Remove a whole namespace. Used when a plugin is uninstalled.
    ///
    /// # Errors
    ///
    /// An I/O failure writing the file.
    pub fn delete_namespace(&self, ns: &str) -> Result<(), StateError> {
        let mut namespaces = self.lock();
        if namespaces.remove(ns).is_none() {
            return Ok(());
        }
        self.persist(&namespaces)
    }

    /// Serialise and replace the file, refusing to grow past the cap.
    fn persist(&self, namespaces: &Namespaces) -> Result<(), StateError> {
        let bytes = serde_json::to_vec(namespaces)
            .map_err(|error| StateError::Io(format!("cannot serialise state: {error}")))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(StateError::FileFull);
        }
        write_atomic(&self.path, &bytes)
            .map_err(|error| StateError::Io(format!("{}: {error}", self.path.display())))
    }

    /// Take the lock. A poisoned lock means a thread panicked while holding it; the map is
    /// still a valid map (every mutation is a single insert or remove), so carry on rather than
    /// take the whole store down.
    fn lock(&self) -> std::sync::MutexGuard<'_, Namespaces> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Bytes `value` takes as compact JSON.
fn serialised_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// The `state` service over a [`StateStore`].
pub struct StateService {
    store: std::sync::Arc<StateStore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    ns: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetParams {
    ns: String,
    key: String,
    value: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    ns: String,
}

impl StateService {
    /// Serve `store`.
    #[must_use]
    pub fn new(store: std::sync::Arc<StateStore>) -> Self {
        Self { store }
    }

    fn check_ns(ns: &str) -> Result<(), StateError> {
        if !is_name(ns) {
            return Err(StateError::BadName("ns"));
        }
        if ns.starts_with(RESERVED_PREFIX) {
            return Err(StateError::Reserved);
        }
        Ok(())
    }

    fn check_key(key: &str) -> Result<(), StateError> {
        if is_name(key) {
            Ok(())
        } else {
            Err(StateError::BadName("key"))
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, ServiceError> {
        // The parse error is not surfaced verbatim: serde quotes input, and responses never echo
        // caller content.
        serde_json::from_value(params)
            .map_err(|_| ServiceError::BadRequest("params do not match the method".to_owned()))
    }

    fn get(&self, params: Value) -> Result<Value, ServiceError> {
        let p: GetParams = Self::parse(params)?;
        Self::check_ns(&p.ns)?;
        Self::check_key(&p.key)?;
        let value = self.store.get(&p.ns, &p.key).unwrap_or(Value::Null);
        Ok(serde_json::json!({ "value": value }))
    }

    fn set(&self, params: Value) -> Result<Value, ServiceError> {
        let p: SetParams = Self::parse(params)?;
        Self::check_ns(&p.ns)?;
        Self::check_key(&p.key)?;
        self.store.set(&p.ns, &p.key, p.value)?;
        Ok(Value::Object(Map::new()))
    }

    fn delete(&self, params: Value) -> Result<Value, ServiceError> {
        let p: GetParams = Self::parse(params)?;
        Self::check_ns(&p.ns)?;
        Self::check_key(&p.key)?;
        self.store.delete(&p.ns, &p.key)?;
        Ok(Value::Object(Map::new()))
    }

    fn list(&self, params: Value) -> Result<Value, ServiceError> {
        let p: ListParams = Self::parse(params)?;
        Self::check_ns(&p.ns)?;
        let entries: Map<String, Value> = self.store.list(&p.ns).into_iter().collect();
        Ok(serde_json::json!({ "entries": entries }))
    }
}

impl Service for StateService {
    fn name(&self) -> &'static str {
        "state"
    }

    fn summary(&self) -> &'static str {
        "Key-value store for the page: settings, enabled flags, grants"
    }

    fn describe(&self) -> Value {
        serde_json::json!({
            "methods": ["get", "set", "delete", "list"],
            "location": self.store.path().display().to_string(),
            "limits": {
                "nameChars": MAX_NAME_CHARS,
                "valueBytes": MAX_VALUE_BYTES,
                "fileBytes": MAX_FILE_BYTES,
            },
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "get" => self.get(params),
            "set" => self.set(params),
            "delete" => self.delete(params),
            "list" => self.list(params),
            other => Err(ServiceError::UnknownMethod {
                service: "state",
                method: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
