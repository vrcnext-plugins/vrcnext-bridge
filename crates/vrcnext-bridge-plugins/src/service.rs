//! The `plugins` service: install, list, check for updates, update, uninstall, build.
//!
//! The pipeline for anything that brings code in is always the same and always in this order:
//! confirm natively → clone into a temporary directory → read and validate `plugin.json` → scan
//! the source policy → move into place → record → rebuild. Validation happens on the temporary
//! copy, so a plugin that fails never has a directory under `plugins/` and never reaches the
//! import table. An update is the same pipeline with a swap at the end: the fresh clone replaces
//! the old tree only once it has passed, which is what "leave the old tree if invalid" means in
//! practice and also what makes "no merges, ever" trivially true.
//!
//! One mutex serialises everything that changes the installed set or runs a build. Reads
//! (`list`, `check_updates`) do not take it.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};
use vrcnext_bridge_core::{
    Approval, ApprovalRequest, Approver, Paths, PluginId, Pusher, Service, ServiceError,
};

use crate::build::{BuildReport, Builder};
use crate::git::Git;
use crate::manifest::Manifest;
use crate::policy;
use crate::state::StateStore;

/// The state namespace that holds one record per installed plugin.
pub const RECORDS_NS: &str = "bridge.plugins";

/// Longest install URL accepted.
const MAX_URL_CHARS: usize = 512;

/// What `list` returns per plugin, and what `install`/`update` return under `plugin`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEntry {
    /// The manifest, flattened in.
    #[serde(flatten)]
    pub manifest: Manifest,
    /// Where it was installed from.
    pub url: String,
    /// The checked-out commit.
    pub commit: String,
    /// Milliseconds since the epoch.
    pub installed_at: u64,
    /// Milliseconds since the epoch; equals `installedAt` until the first update.
    pub updated_at: u64,
}

/// What the state store remembers per plugin.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    url: String,
    commit: String,
    installed_at: u64,
    updated_at: u64,
}

/// Everything the service is built from.
pub struct PluginsService {
    paths: Paths,
    git: Arc<dyn Git>,
    builder: Arc<dyn Builder>,
    state: Arc<StateStore>,
    pusher: Arc<dyn Pusher>,
    approver: Arc<dyn Approver>,
    /// Held across install/update/uninstall/build. Nothing is stored in it; it is the lock.
    mutating: Mutex<()>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UrlParams {
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    id: String,
}

/// A validated clone that has not been moved into place yet.
struct Candidate {
    dir: PathBuf,
    manifest: Manifest,
    id: PluginId,
    commit: String,
}

fn bad(code: &str, detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::BadRequest(format!("{code}: {detail}"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl PluginsService {
    /// Wire the service. `git` and `builder` are traits so the pipeline can be tested without
    /// a network or esbuild.
    #[must_use]
    pub fn new(
        paths: Paths,
        parts: (Arc<dyn Git>, Arc<dyn Builder>, Arc<StateStore>),
        pusher: Arc<dyn Pusher>,
        approver: Arc<dyn Approver>,
    ) -> Self {
        let (git, builder, state) = parts;
        Self {
            paths,
            git,
            builder,
            state,
            pusher,
            approver,
            mutating: Mutex::new(()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn parse<T: serde::de::DeserializeOwned>(params: Value) -> Result<T, ServiceError> {
        serde_json::from_value(params)
            .map_err(|_| ServiceError::BadRequest("params do not match the method".to_owned()))
    }

    fn progress(&self, op: &str, id: Option<&PluginId>, step: &str, message: impl Into<String>) {
        let message = message.into();
        log::info!("{op}: {step}: {message}");
        self.pusher.push(
            "progress",
            json!({ "op": op, "id": id.map(ToString::to_string), "step": step, "message": message }),
        );
    }

    /// Ask the user, natively. Fails closed: anything but an explicit yes refuses the operation.
    fn confirm(
        &self,
        op: &'static str,
        id: Option<&PluginId>,
        summary: String,
        detail: String,
    ) -> Result<(), ServiceError> {
        self.progress(op, id, "awaiting_confirmation", summary.clone());
        let request = ApprovalRequest {
            operation: op,
            summary,
            detail,
        };
        match self.approver.approve(&request) {
            Approval::Approved => Ok(()),
            Approval::Denied => Err(bad("denied", "the user did not confirm")),
            Approval::Unavailable => {
                log::error!(
                    "{op} refused: no native confirmation is available ({})",
                    self.approver.describe()
                );
                Err(bad(
                    "approval_unavailable",
                    "no native confirmation prompt is available on this machine; refusing",
                ))
            }
        }
    }

    // ---- records ----------------------------------------------------------------------------

    fn record(&self, id: &PluginId) -> Option<Record> {
        self.state
            .get(RECORDS_NS, id.as_str())
            .and_then(|value| serde_json::from_value(value).ok())
    }

    fn installed_ids(&self) -> Vec<PluginId> {
        self.state
            .list(RECORDS_NS)
            .keys()
            .filter_map(|key| PluginId::parse(key).ok())
            .collect()
    }

    fn save_record(&self, id: &PluginId, record: &Record) -> Result<(), ServiceError> {
        self.state
            .set(RECORDS_NS, id.as_str(), json!(record))
            .map_err(|error| ServiceError::Internal(error.to_string()))
    }

    fn entry(&self, id: &PluginId) -> Option<ListEntry> {
        let record = self.record(id)?;
        let bytes = std::fs::read(self.paths.plugin_dir(id).join("plugin.json")).ok()?;
        let manifest = match Manifest::parse(&bytes) {
            Ok(manifest) if manifest.id == id.as_str() => manifest,
            Ok(_) => return None,
            Err(error) => {
                log::warn!("plugin {id}: manifest no longer valid ({error}); hidden from list");
                return None;
            }
        };
        Some(ListEntry {
            manifest,
            url: record.url,
            commit: record.commit,
            installed_at: record.installed_at,
            updated_at: record.updated_at,
        })
    }

    fn entries(&self) -> Vec<ListEntry> {
        self.installed_ids()
            .iter()
            .filter_map(|id| self.entry(id))
            .collect()
    }

    fn push_installed(&self) {
        self.pusher
            .push("plugins", json!({ "plugins": self.entries() }));
    }

    fn rebuild(&self) -> BuildReport {
        self.builder.build(&self.installed_ids())
    }

    // ---- the pipeline -----------------------------------------------------------------------

    fn check_url(url: &str) -> Result<(), ServiceError> {
        if !url.starts_with("https://") {
            return Err(bad("not_https", "only https:// URLs can be installed"));
        }
        if url.chars().count() > MAX_URL_CHARS
            || url.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(bad("not_https", "URL is not well formed"));
        }
        Ok(())
    }

    /// A fresh directory under `plugins/`, named so it can never be a plugin id (ids do not
    /// start with a dot).
    fn temp_dir(&self) -> Result<PathBuf, ServiceError> {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|error| ServiceError::Internal(error.to_string()))?;
        let name = bytes.iter().fold(String::from(".tmp-"), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        });
        crate::fsutil::create_dir_private(&self.paths.plugins_dir())
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(self.paths.plugins_dir().join(name))
    }

    /// Clone and validate, without touching `plugins/<id>`. On any error the temporary
    /// directory is gone.
    fn fetch_candidate(&self, op: &str, url: &str) -> Result<Candidate, ServiceError> {
        let dir = self.temp_dir()?;
        self.progress(op, None, "clone", format!("cloning {url}"));
        let commit = self
            .git
            .clone_repo(url, &dir)
            .map_err(|error| bad("clone_failed", error))?;
        let result = Self::validate_candidate(&dir, op, self);
        match result {
            Ok((manifest, id)) => Ok(Candidate {
                dir,
                manifest,
                id,
                commit,
            }),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(error)
            }
        }
    }

    fn validate_candidate(
        dir: &std::path::Path,
        op: &str,
        this: &Self,
    ) -> Result<(Manifest, PluginId), ServiceError> {
        this.progress(op, None, "validate", "checking plugin.json");
        let bytes = std::fs::read(dir.join("plugin.json")).map_err(|_| {
            bad(
                "no_manifest",
                "the repository has no plugin.json at its root",
            )
        })?;
        let manifest = Manifest::parse(&bytes).map_err(|error| bad("manifest_invalid", error))?;
        let id = manifest
            .plugin_id()
            .map_err(|error| bad("manifest_invalid", error))?;
        if !dir.join("main.ts").is_file() {
            return Err(bad("manifest_invalid", "main.ts is missing"));
        }
        this.progress(op, Some(&id), "policy", "scanning sources");
        policy::scan_tree(dir).map_err(|error| bad("policy", error))?;
        Ok((manifest, id))
    }

    fn install(&self, params: Value) -> Result<Value, ServiceError> {
        let p: UrlParams = Self::parse(params)?;
        Self::check_url(&p.url)?;
        let _guard = self.lock();
        self.confirm(
            "install",
            None,
            "Install a plugin?".to_owned(),
            format!(
                "From {}\nInto {}",
                p.url,
                self.paths.plugins_dir().display()
            ),
        )?;

        let candidate = self.fetch_candidate("install", &p.url)?;
        let target = self.paths.plugin_dir(&candidate.id);
        if target.exists() || self.record(&candidate.id).is_some() {
            let _ = std::fs::remove_dir_all(&candidate.dir);
            return Err(bad("already_installed", candidate.id));
        }
        self.progress("install", Some(&candidate.id), "move", "moving into place");
        std::fs::rename(&candidate.dir, &target).map_err(|error| {
            let _ = std::fs::remove_dir_all(&candidate.dir);
            ServiceError::Internal(format!("cannot move the clone into place: {error}"))
        })?;
        let now = now_ms();
        self.save_record(
            &candidate.id,
            &Record {
                url: p.url,
                commit: candidate.commit,
                installed_at: now,
                updated_at: now,
            },
        )?;
        self.push_installed();
        self.progress(
            "install",
            Some(&candidate.id),
            "build",
            "rebuilding the bundle",
        );
        self.rebuild();
        self.finished(&candidate.id, &candidate.manifest.name)
    }

    fn finished(&self, id: &PluginId, name: &str) -> Result<Value, ServiceError> {
        let entry = self
            .entry(id)
            .ok_or_else(|| ServiceError::Internal(format!("{name} vanished after install")))?;
        Ok(json!({ "plugin": entry }))
    }

    fn update(&self, params: Value) -> Result<Value, ServiceError> {
        let p: IdParams = Self::parse(params)?;
        let id = PluginId::parse(&p.id).map_err(|error| bad("invalid_id", error))?;
        let _guard = self.lock();
        let record = self.record(&id).ok_or_else(|| bad("not_installed", &id))?;
        self.confirm(
            "update",
            Some(&id),
            format!("Update plugin {id}?"),
            format!("From {}\nCurrently at {}", record.url, record.commit),
        )?;

        let candidate = self.fetch_candidate("update", &record.url)?;
        if candidate.id != id {
            let _ = std::fs::remove_dir_all(&candidate.dir);
            return Err(bad(
                "manifest_invalid",
                format!("the repository now declares id '{}'", candidate.id),
            ));
        }
        self.progress("update", Some(&id), "move", "swapping in the new tree");
        let target = self.paths.plugin_dir(&id);
        let retired = self.temp_dir()?;
        std::fs::rename(&target, &retired)
            .and_then(|()| std::fs::rename(&candidate.dir, &target))
            .map_err(|error| {
                // Put the old tree back if the second rename failed; the first cannot half-fail.
                let _ = std::fs::rename(&retired, &target);
                let _ = std::fs::remove_dir_all(&candidate.dir);
                ServiceError::Internal(format!("cannot swap the plugin tree: {error}"))
            })?;
        let _ = std::fs::remove_dir_all(&retired);
        self.save_record(
            &id,
            &Record {
                commit: candidate.commit,
                updated_at: now_ms(),
                ..record
            },
        )?;
        self.push_installed();
        self.progress("update", Some(&id), "build", "rebuilding the bundle");
        self.rebuild();
        self.finished(&id, &candidate.manifest.name)
    }

    fn uninstall(&self, params: Value) -> Result<Value, ServiceError> {
        let p: IdParams = Self::parse(params)?;
        let id = PluginId::parse(&p.id).map_err(|error| bad("invalid_id", error))?;
        let _guard = self.lock();
        let record = self.record(&id).ok_or_else(|| bad("not_installed", &id))?;
        self.confirm(
            "uninstall",
            Some(&id),
            format!("Uninstall plugin {id}?"),
            format!(
                "Installed from {}\nIts settings will be deleted.",
                record.url
            ),
        )?;

        self.progress("uninstall", Some(&id), "remove", "removing the clone");
        let dir = self.paths.plugin_dir(&id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .map_err(|error| ServiceError::Internal(format!("cannot remove {id}: {error}")))?;
        }
        self.state
            .delete(RECORDS_NS, id.as_str())
            .and_then(|()| self.state.delete_namespace(&format!("plugin:{id}")))
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        self.push_installed();
        self.progress("uninstall", Some(&id), "build", "rebuilding the bundle");
        self.rebuild();
        Ok(json!({}))
    }

    fn check_updates(&self) -> Value {
        let mut updates = Vec::new();
        for id in self.installed_ids() {
            match self.git.fetch_status(&self.paths.plugin_dir(&id)) {
                Ok(status) if status.is_behind() => updates.push(json!({
                    "id": id,
                    "current": status.current,
                    "latest": status.latest,
                    "commitsBehind": status.changelog.len(),
                    "changelog": status.changelog,
                })),
                Ok(_) => {}
                Err(error) => log::warn!("check_updates: {id}: {error}"),
            }
        }
        json!({ "updates": updates })
    }
}

impl Service for PluginsService {
    fn name(&self) -> &'static str {
        "plugins"
    }

    fn summary(&self) -> &'static str {
        "Install, update and remove plugins from git, and compile the bundle"
    }

    fn describe(&self) -> Value {
        json!({
            "methods": ["install", "list", "check_updates", "update", "uninstall", "build"],
            "pluginsDir": self.paths.plugins_dir().display().to_string(),
            "bundle": self.paths.bundle().display().to_string(),
            "confirmation": self.approver.describe(),
            "installed": self.installed_ids(),
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, ServiceError> {
        match method {
            "install" => self.install(params),
            "list" => Ok(json!({ "plugins": self.entries() })),
            "check_updates" => Ok(self.check_updates()),
            "update" => self.update(params),
            "uninstall" => self.uninstall(params),
            "build" => {
                let _guard = self.lock();
                Ok(json!(self.rebuild()))
            }
            other => Err(ServiceError::UnknownMethod {
                service: "plugins",
                method: other.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests;
