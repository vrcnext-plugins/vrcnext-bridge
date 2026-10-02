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
    "sql",
    "gamelog",
    "vrchat",
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
    /// Plugin ids that must be enabled first. The host orders activation by these.
    #[serde(default)]
    pub dependencies: Vec<String>,
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
        list("dependencies", &self.dependencies, MAX_LIST_ENTRIES, |id| {
            PluginId::parse(id).is_ok()
        })?;
        if self.dependencies.iter().any(|id| id == &self.id) {
            return Err(field("dependencies", "a plugin cannot depend on itself"));
        }
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
/// Plain `MAJOR.MINOR.PATCH`, as the host's matcher understands it: no prerelease, no build
/// metadata, no leading zeros.
fn is_plain_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

fn semver(name: &'static str, value: &str) -> Result<(), ManifestError> {
    if is_plain_version(value) {
        Ok(())
    } else {
        Err(field(name, "must be MAJOR.MINOR.PATCH"))
    }
}

/// The range shapes the host's own matcher accepts, and nothing else: exact, `^`, `~`, and
/// space-separated comparators (`>=0.2.0 <0.4.0`). No `||`, `x`, `*` or hyphen ranges. A range the
/// bridge accepts but the host cannot evaluate would install a plugin that then never activates.
fn semver_range(name: &'static str, value: &str) -> Result<(), ManifestError> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    let ok = !parts.is_empty()
        && parts.len() <= 4
        && parts.iter().all(|part| {
            let version = part
                .strip_prefix(">=")
                .or_else(|| part.strip_prefix("<="))
                .or_else(|| part.strip_prefix(['^', '~', '>', '<', '=']))
                .unwrap_or(part);
            is_plain_version(version)
        });
    if ok {
        Ok(())
    } else {
        Err(field(
            name,
            "must be a version range: exact, ^, ~ or comparators",
        ))
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
mod tests;
