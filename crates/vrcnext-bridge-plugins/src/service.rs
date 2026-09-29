//! The `plugins` service: install, list, check for updates, update, uninstall, build.
//!
//! The pipeline for anything that brings code in is always the same and always in this order:
//! confirm natively → clone into a temporary directory → read and validate `plugin.json` → scan
//! the source policy → verify the author's signature → move into place → record → rebuild. Validation happens on the temporary
//! copy, so a plugin that fails never has a directory under `plugins/` and never reaches the
//! import table. An update is the same pipeline with a swap at the end: the fresh clone replaces
//! the old tree only once it has passed, which is what "leave the old tree if invalid" means in
//! practice and also what makes "no merges, ever" trivially true.
//!
//! Signatures add a second question the pipeline has to answer, and it is not "is the signature
//! valid" — [`crate::signing`] settles that on its own — but "is this the key this plugin has
//! always had". An unknown key is confirmed once, natively, and remembered in [`crate::trust`];
//! a key that differs from the one the plugin was installed under is confirmed *every* time,
//! separately, because that is what an account takeover looks like from here.
//!
//! A signature says who made a tree, not that it is the newest one they made. Someone who
//! controls the repository but not the key could point it back at an older signed commit — one
//! with a known bug — and it would verify. So an update is also refused if its `version` is lower
//! than the installed one, or if its signature is older than the one it replaces; going back on
//! purpose is an uninstall and a fresh install.
//!
//! An install or update is only finished once the bundle builds with it. If the build fails, the
//! previous tree (or no tree, for an install) is put back and the bundle rebuilt without it, so a
//! plugin that cannot compile never wedges every later build.
//!
//! One mutex serialises everything that changes the installed set, runs a build, or touches a
//! plugin's git directory. `list` does not take it.

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
use crate::signing::{self, VerifiedSignature};
use crate::state::StateStore;
use crate::trust::TrustStore;

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
    /// Fingerprint of the key this plugin is installed under.
    pub key_id: String,
}

/// What the state store remembers per plugin.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    url: String,
    commit: String,
    installed_at: u64,
    updated_at: u64,
    /// The signing key this plugin belongs to.
    key_id: String,
    /// When the installed tree says it was signed. An update signed earlier is a rollback.
    /// Absent in records written before this was kept, which then compare as zero.
    #[serde(default)]
    signed_at: u64,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeyParams {
    key_id: String,
}

/// A validated clone that has not been moved into place yet.
struct Candidate {
    dir: PathBuf,
    manifest: Manifest,
    id: PluginId,
    commit: String,
    signature: VerifiedSignature,
}

fn bad(code: &str, detail: impl std::fmt::Display) -> ServiceError {
    ServiceError::BadRequest(format!("{code}: {detail}"))
}

/// The refusal for a change that was rolled back because the bundle would not build with it.
fn build_failed(report: &BuildReport) -> ServiceError {
    bad(
        "build_failed",
        report
            .errors
            .first()
            .map_or("the bundle did not build", String::as_str),
    )
}

/// A manifest version as numbers, for ordering. Manifests are validated as plain
/// `MAJOR.MINOR.PATCH`, so anything else does not reach here; it would sort as zero.
fn version_key(version: &str) -> [u64; 3] {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0));
    [
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    ]
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

    /// The record an update works from. A record that does not parse, or names no key, cannot
    /// say who the plugin belongs to; the only way forward is to uninstall and install again.
    fn signed_record(&self, id: &PluginId) -> Result<Record, ServiceError> {
        let value = self
            .state
            .get(RECORDS_NS, id.as_str())
            .ok_or_else(|| bad("not_installed", id))?;
        serde_json::from_value::<Record>(value)
            .ok()
            .filter(|record| !record.key_id.is_empty())
            .ok_or_else(|| {
                bad(
                    "reinstall_required",
                    format!("{id} has no recorded signing key; uninstall it and install it again"),
                )
            })
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
            key_id: record.key_id,
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
            Ok((manifest, id, signature)) => Ok(Candidate {
                dir,
                manifest,
                id,
                commit,
                signature,
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
    ) -> Result<(Manifest, PluginId, VerifiedSignature), ServiceError> {
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
        this.progress(
            op,
            Some(&id),
            "signature",
            "checking the author's signature",
        );
        let signature =
            signing::verify(dir, id.as_str()).map_err(|error| bad("unsigned", error))?;
        Ok((manifest, id, signature))
    }

    // ---- signing keys -----------------------------------------------------------------------

    /// Make sure the key that signed this tree is one the user has accepted, asking once if not.
    ///
    /// The prompt is deliberately separate from the install prompt. "Install from this URL" and
    /// "this key speaks for that plugin from now on" are different decisions with different
    /// lifetimes, and folding them together would make the second one invisible.
    fn ensure_trusted(
        &self,
        id: &PluginId,
        url: &str,
        signature: &VerifiedSignature,
    ) -> Result<(), ServiceError> {
        let keys = TrustStore::new(&self.state);
        if keys.get(&signature.key_id).is_none() {
            self.confirm(
                "trust_key",
                Some(id),
                format!("Trust a new signing key for {id}?"),
                format!(
                    "This machine has not seen this key before.\n\nKey {}\nFrom {url}\n\n\
                     Confirm only if that fingerprint is the one the author publishes. Anything \
                     it signs afterwards installs without asking again.",
                    signature.key_id
                ),
            )?;
        }
        keys.record(
            &signature.key_id,
            &signature.public_key,
            &format!("{id} ({url})"),
            id.as_str(),
            now_ms(),
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))
    }

    /// Ask separately when an update is signed by a key other than the one the plugin was
    /// installed under.
    ///
    /// This asks every time, and being already trusted for *another* plugin is not an excuse:
    /// trusting an author is not consenting to them taking over someone else's plugin.
    fn confirm_key_change(
        &self,
        id: &PluginId,
        was: &str,
        signature: &VerifiedSignature,
    ) -> Result<(), ServiceError> {
        if was == signature.key_id {
            return Ok(());
        }
        self.confirm(
            "rotate_key",
            Some(id),
            format!("The signing key for {id} changed"),
            format!(
                "Installed under {was}\nThis update is signed by {}\n\n\
                 Either the author rotated their key, or someone else is publishing as them. \
                 Confirm only if you can check the new fingerprint against the author.",
                signature.key_id
            ),
        )
    }

    /// Every trusted key, newest use first, with the plugins currently installed under each.
    fn keys(&self) -> Value {
        let installed: Vec<(PluginId, String)> = self
            .installed_ids()
            .into_iter()
            .filter_map(|id| self.record(&id).map(|record| (id, record.key_id)))
            .collect();
        let mut keys = TrustStore::new(&self.state).list();
        keys.sort_by_key(|(_, entry)| std::cmp::Reverse(entry.last_used_at));
        let keys: Vec<Value> = keys
            .into_iter()
            .map(|(key_id, entry)| {
                let using: Vec<String> = installed
                    .iter()
                    .filter(|(_, pinned)| *pinned == key_id)
                    .map(|(id, _)| id.to_string())
                    .collect();
                json!({
                    "keyId": key_id,
                    "publicKey": entry.public_key,
                    "label": entry.label,
                    "trustedAt": entry.trusted_at,
                    "lastUsedAt": entry.last_used_at,
                    "seenFor": entry.plugins,
                    "installed": using,
                })
            })
            .collect();
        json!({ "keys": keys })
    }

    /// Forget a trusted key. Confirmed natively, like everything else that changes what may run.
    fn forget_key(&self, params: Value) -> Result<Value, ServiceError> {
        let p: KeyParams = Self::parse(params)?;
        let _guard = self.lock();
        let keys = TrustStore::new(&self.state);
        let entry = keys
            .get(&p.key_id)
            .ok_or_else(|| bad("not_trusted", &p.key_id))?;
        self.confirm(
            "forget_key",
            None,
            "Stop trusting a signing key?".to_owned(),
            format!(
                "Key {}\nFirst trusted for {}\n\n\
                 Nothing is uninstalled. The next plugin this key signs will be confirmed again.",
                p.key_id, entry.label
            ),
        )?;
        keys.forget(&p.key_id)
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(json!({}))
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
        if let Err(error) = self.ensure_trusted(&candidate.id, &p.url, &candidate.signature) {
            let _ = std::fs::remove_dir_all(&candidate.dir);
            return Err(error);
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
                key_id: candidate.signature.key_id,
                signed_at: candidate.signature.signed_at,
            },
        )?;
        self.push_installed();
        self.progress(
            "install",
            Some(&candidate.id),
            "build",
            "rebuilding the bundle",
        );
        let report = self.rebuild();
        if !report.ok {
            // Take it out again, so the plugins that were working keep working.
            self.progress(
                "install",
                Some(&candidate.id),
                "rollback",
                "the bundle did not build",
            );
            let _ = std::fs::remove_dir_all(&target);
            let _ = self.state.delete(RECORDS_NS, candidate.id.as_str());
            let _ = self
                .state
                .delete_namespace(&format!("plugin:{}", candidate.id));
            self.push_installed();
            self.rebuild();
            return Err(build_failed(&report));
        }
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
        let record = self.signed_record(&id)?;
        self.confirm(
            "update",
            Some(&id),
            format!("Update plugin {id}?"),
            format!("From {}\nCurrently at {}", record.url, record.commit),
        )?;

        let candidate = self.fetch_candidate("update", &record.url)?;
        if let Err(error) = self.check_update(&id, &record, &candidate) {
            let _ = std::fs::remove_dir_all(&candidate.dir);
            return Err(error);
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
        let previous = record.clone();
        self.save_record(
            &id,
            &Record {
                commit: candidate.commit,
                updated_at: now_ms(),
                key_id: candidate.signature.key_id,
                signed_at: candidate.signature.signed_at,
                ..record
            },
        )?;
        self.push_installed();
        self.progress("update", Some(&id), "build", "rebuilding the bundle");
        let report = self.rebuild();
        if !report.ok {
            // Put the tree that built back, and the record that describes it.
            self.progress("update", Some(&id), "rollback", "the bundle did not build");
            let failed = self.temp_dir()?;
            if std::fs::rename(&target, &failed)
                .and_then(|()| std::fs::rename(&retired, &target))
                .is_ok()
            {
                let _ = self.save_record(&id, &previous);
            }
            let _ = std::fs::remove_dir_all(&failed);
            let _ = std::fs::remove_dir_all(&retired);
            self.push_installed();
            self.rebuild();
            return Err(build_failed(&report));
        }
        let _ = std::fs::remove_dir_all(&retired);
        self.finished(&id, &candidate.manifest.name)
    }

    /// Everything an update has to satisfy before the trees are swapped. Kept apart from
    /// [`Self::update`] so a refusal has exactly one place to clean up the clone.
    fn check_update(
        &self,
        id: &PluginId,
        record: &Record,
        candidate: &Candidate,
    ) -> Result<(), ServiceError> {
        if candidate.id != *id {
            return Err(bad(
                "manifest_invalid",
                format!("the repository now declares id '{}'", candidate.id),
            ));
        }
        if let Some(installed) = self.entry(id).map(|entry| entry.manifest.version)
            && version_key(&candidate.manifest.version) < version_key(&installed)
        {
            return Err(bad(
                "downgrade",
                format!(
                    "the repository now offers {} but {installed} is installed; uninstall and \
                     install again to go back on purpose",
                    candidate.manifest.version
                ),
            ));
        }
        if candidate.signature.signed_at < record.signed_at {
            return Err(bad(
                "downgrade",
                "the repository now offers a tree signed before the installed one",
            ));
        }
        self.confirm_key_change(id, &record.key_id, &candidate.signature)?;
        self.ensure_trusted(id, &record.url, &candidate.signature)
    }

    fn uninstall(&self, params: Value) -> Result<Value, ServiceError> {
        let p: IdParams = Self::parse(params)?;
        let id = PluginId::parse(&p.id).map_err(|error| bad("invalid_id", error))?;
        let _guard = self.lock();
        // Read loosely: a record too broken for anything else must still be removable, since
        // uninstalling is how it gets fixed.
        let record = self
            .state
            .get(RECORDS_NS, id.as_str())
            .ok_or_else(|| bad("not_installed", &id))?;
        let url = record.get("url").and_then(Value::as_str).unwrap_or("?");
        self.confirm(
            "uninstall",
            Some(&id),
            format!("Uninstall plugin {id}?"),
            format!("Installed from {url}\nIts settings will be deleted."),
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
        // Fetching writes into `plugins/<id>/.git`, the directory an update renames away.
        let _guard = self.lock();
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
            "methods": [
                "install", "list", "check_updates", "update", "uninstall", "build",
                "keys", "forget_key",
            ],
            "pluginsDir": self.paths.plugins_dir().display().to_string(),
            "bundle": self.paths.bundle().display().to_string(),
            "confirmation": self.approver.describe(),
            "signatures": "ed25519, required",
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
            "keys" => Ok(self.keys()),
            "forget_key" => self.forget_key(params),
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
