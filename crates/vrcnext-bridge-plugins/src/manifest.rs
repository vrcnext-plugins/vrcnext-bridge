//! `plugin.json`: the contract a plugin repository must meet before its code is compiled in.
//!
//! The schema is enforced here, once, at install and update. Everything downstream — the import
//! table, the `list` entries, the consent dialog in the page — trusts a [`Manifest`] because it
//! could only have come from [`Manifest::parse`].
//!
//! The lists (`permissions`, `actions`, `events`, `hosts`) are what the host's permission gate
//! checks against at runtime, so their shape matters as much as the id's: an `actions` entry
//! with a wildcard would be a hole in the gate, so entries are exact names only.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use vrcnext_bridge_core::PluginId;

/// The fixed permission vocabulary. Mirrors `packages/api/src/permissions.ts`.
pub const PERMISSIONS: &[&str] = &[
    "host:events",
    "host:actions",
    "host:intercept",
    "network",
    "notifications",
    "native",
    "osc",
    "gamelog",
    "context-menu",
    "routes",
    "clipboard",
];

/// Longest `description`, in characters.
pub const MAX_DESCRIPTION_CHARS: usize = 200;

/// Most `tags`.
pub const MAX_TAGS: usize = 8;

/// Longest `name`, `author`, `homepage` and each list entry, in characters. Not in the spec's
/// table, but every string here is shown in the page and stored in the import table, so it is
/// bounded like everything else a repository controls.
pub const MAX_STRING_CHARS: usize = 200;

/// Most entries in each of `actions`, `events`, `hosts` and `tags`.
pub const MAX_LIST_ENTRIES: usize = 64;

/// A validated `plugin.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    /// `[a-z0-9][a-z0-9-]{1,39}`; equals the folder name.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Semver.
    pub version: String,
    /// Semver range against `@vrcnext/plugin-api`.
    pub api_version: String,
    /// One or two sentences.
    pub description: String,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Optional, at most eight.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Required at enable; may be empty.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Requested lazily.
    #[serde(default)]
    pub optional_permissions: Vec<String>,
    /// Exact VRCNext action names.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Exact host event names.
    #[serde(default)]
    pub events: Vec<String>,
    /// Exact hosts; no wildcards.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Why a manifest was refused. The message is what `manifest_invalid: …` carries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Not JSON, or not this shape.
    #[error("not a valid plugin.json ({0})")]
    Shape(String),
    /// A field failed its rule.
    #[error("{field}: {rule}")]
    Field {
        /// Which field.
        field: &'static str,
        /// What it must satisfy.
        rule: String,
    },
}

impl Manifest {
    /// Parse and validate the bytes of a `plugin.json`.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] naming the first rule the file breaks.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::Shape(error.to_string().replace('`', "'")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The id, typed.
    ///
    /// # Errors
    ///
    /// Cannot fail on a parsed manifest; the signature exists so no `unwrap` is needed.
    pub fn plugin_id(&self) -> Result<PluginId, ManifestError> {
        PluginId::parse(&self.id).map_err(|error| ManifestError::Field {
            field: "id",
            rule: error.to_string(),
        })
    }

    fn validate(&self) -> Result<(), ManifestError> {
        self.plugin_id()?;
        bounded("name", &self.name, MAX_STRING_CHARS)?;
        semver("version", &self.version)?;
        semver_range("apiVersion", &self.api_version)?;
        bounded("description", &self.description, MAX_DESCRIPTION_CHARS)?;
        if let Some(author) = &self.author {
            bounded("author", author, MAX_STRING_CHARS)?;
        }
        if let Some(homepage) = &self.homepage {
            bounded("homepage", homepage, MAX_STRING_CHARS)?;
        }
        list("tags", &self.tags, MAX_TAGS, |_| true)?;
        list("permissions", &self.permissions, PERMISSIONS.len(), |p| {
            PERMISSIONS.contains(&p)
        })?;
        list(
            "optionalPermissions",
            &self.optional_permissions,
            PERMISSIONS.len(),
            |p| PERMISSIONS.contains(&p),
        )?;
        list("actions", &self.actions, MAX_LIST_ENTRIES, is_exact_name)?;
        list("events", &self.events, MAX_LIST_ENTRIES, is_exact_name)?;
        list("hosts", &self.hosts, MAX_LIST_ENTRIES, is_exact_host)?;
        Ok(())
    }
}

fn field(field: &'static str, rule: impl Into<String>) -> ManifestError {
    ManifestError::Field {
        field,
        rule: rule.into(),
    }
}

/// Non-empty, at most `max` characters, no control characters.
fn bounded(name: &'static str, value: &str, max: usize) -> Result<(), ManifestError> {
    let count = value.chars().count();
    if count == 0 || count > max {
        return Err(field(name, format!("must be 1 to {max} characters")));
    }
    if value.chars().any(char::is_control) {
        return Err(field(name, "must not contain control characters"));
    }
    Ok(())
}

/// A list of at most `max` distinct entries, each bounded and passing `accept`.
fn list(
    name: &'static str,
    values: &[String],
    max: usize,
    accept: impl Fn(&str) -> bool,
) -> Result<(), ManifestError> {
    if values.len() > max {
        return Err(field(name, format!("at most {max} entries")));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        bounded(name, value, MAX_STRING_CHARS)?;
        if !accept(value) {
            return Err(field(name, format!("'{value}' is not allowed")));
        }
        if !seen.insert(value) {
            return Err(field(name, format!("'{value}' is listed twice")));
        }
    }
    Ok(())
}

/// `MAJOR.MINOR.PATCH` with optional `-pre` and `+build`. Enough of semver to reject junk; the
/// host does the range comparison in JavaScript where the real semver library lives.
fn semver(name: &'static str, value: &str) -> Result<(), ManifestError> {
    let core = value.split_once('+').map_or(value, |(core, _)| core);
    let core = core.split_once('-').map_or(core, |(core, _)| core);
    let parts: Vec<&str> = core.split('.').collect();
    let ok = parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(field(name, "must be semver MAJOR.MINOR.PATCH"))
    }
}

/// A semver range: `^1.2.0`, `~1.2`, `>=1.0.0 <2.0.0`, `1.x`, `*`. Checked for character set
/// and length only; the host evaluates it.
fn semver_range(name: &'static str, value: &str) -> Result<(), ManifestError> {
    let ok = (1..=64).contains(&value.len())
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '^' | '~' | '>' | '<' | '=' | '.' | '-' | '|' | ' ' | '*')
        });
    if ok {
        Ok(())
    } else {
        Err(field(name, "must be a semver range"))
    }
}

/// An exact action or event name: identifier characters only, no globs.
fn is_exact_name(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// An exact host name, optionally with a port. No wildcards, no scheme, no path.
fn is_exact_host(value: &str) -> bool {
    let host = value.split_once(':').map_or(value, |(host, port)| {
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            "*"
        } else {
            host
        }
    });
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
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
            "hosts": ["api.example.com"]
        })
    }

    fn parse(value: serde_json::Value) -> Result<Manifest, ManifestError> {
        Manifest::parse(&serde_json::to_vec(&value).unwrap())
    }

    fn patched(field: &str, value: serde_json::Value) -> Result<Manifest, ManifestError> {
        let mut m = full();
        m[field] = value;
        parse(m)
    }

    #[test]
    fn the_full_example_parses_and_round_trips() {
        let manifest = parse(full()).unwrap();
        assert_eq!(manifest.id, "friend-alerts");
        assert_eq!(serde_json::to_value(&manifest).unwrap(), full());
    }

    #[test]
    fn only_the_required_fields_are_required() {
        let minimal = serde_json::json!({
            "id": "ab", "name": "n", "version": "0.0.1", "apiVersion": "*", "description": "d"
        });
        assert!(parse(minimal).is_ok());
        for required in ["id", "name", "version", "apiVersion", "description"] {
            let mut m = full();
            m.as_object_mut().unwrap().remove(required);
            assert!(
                matches!(parse(m), Err(ManifestError::Shape(_))),
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
    fn hosts_with_ports_and_prerelease_versions_are_fine() {
        assert!(patched("hosts", serde_json::json!(["api.example.com:8443"])).is_ok());
        assert!(patched("version", serde_json::json!("1.0.0-beta.1+build.5")).is_ok());
        assert!(patched("apiVersion", serde_json::json!(">=0.2.0 <1.0.0 || 2.x")).is_ok());
    }
}
