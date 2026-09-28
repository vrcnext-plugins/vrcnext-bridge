#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
//! The install → validate → policy → move → build pipeline, with the network and esbuild
//! replaced by fakes that record what they were asked to do.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use vrcnext_bridge_core::{
    Approval, ApprovalRequest, Approver, Paths, PluginId, RecordingPusher, Service as _,
    ServiceError,
};

use super::{PluginsService, RECORDS_NS};
use crate::build::{BuildReport, Builder};
use crate::fsutil::scratch_dir;
use crate::git::{ChangelogEntry, Git, GitError, RemoteStatus};
use crate::state::StateStore;

/// A "remote": the files a clone of a given URL produces.
type Tree = Vec<(&'static str, String)>;

/// The key every fixture is signed with unless a test asks for another one.
const AUTHOR: u8 = 1;

/// Sign `tree` as its own manifest id would be read, and return it with `plugin.sig` appended.
///
/// The digest is taken over the files as they land on disk rather than recomputed here, so the
/// fixtures exercise the real [`crate::signing::tree_digest`] rather than a copy of it that
/// could drift away from it.
fn sign(tree: Tree, seed: u8) -> Tree {
    use ed25519_dalek::{Signer as _, SigningKey};

    let id = tree
        .iter()
        .find(|(name, _)| *name == "plugin.json")
        .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
        .and_then(|value| value["id"].as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());

    let dir = scratch_dir(&format!(
        "sig-{seed}-{id}-{:?}",
        std::thread::current().id()
    ));
    for (name, content) in &tree {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let digest = crate::signing::tree_digest(&dir).unwrap();
    std::fs::remove_dir_all(&dir).ok();

    let key = SigningKey::from_bytes(&[seed; 32]);
    let hex = crate::signing::hex;
    let file = json!({
        "version": 1,
        "algorithm": "ed25519",
        "id": id,
        "publicKey": hex(&key.verifying_key().to_bytes()),
        "digest": digest,
        "signature": hex(&key.sign(&crate::signing::message(&id, &digest)).to_bytes()),
        "signedAt": 1_759_000_000,
    });
    let mut tree = tree;
    tree.push(("plugin.sig", file.to_string()));
    tree
}

struct FakeGit {
    remotes: Mutex<std::collections::BTreeMap<String, Tree>>,
    clones: AtomicUsize,
    status: Mutex<Option<RemoteStatus>>,
}

impl FakeGit {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            remotes: Mutex::new(std::collections::BTreeMap::new()),
            clones: AtomicUsize::new(0),
            status: Mutex::new(None),
        })
    }

    /// Serve `tree` signed by the usual author, which is what every install is expected to
    /// look like.
    fn serve(&self, url: &str, tree: Tree) {
        self.serve_signed_by(url, tree, AUTHOR);
    }

    fn serve_signed_by(&self, url: &str, tree: Tree, seed: u8) {
        self.remotes
            .lock()
            .unwrap()
            .insert(url.to_owned(), sign(tree, seed));
    }

    /// Serve `tree` exactly as given: no signature, or whatever one it already carries.
    fn serve_raw(&self, url: &str, tree: Tree) {
        self.remotes.lock().unwrap().insert(url.to_owned(), tree);
    }
}

impl Git for FakeGit {
    fn clone_repo(&self, url: &str, dest: &Path) -> Result<String, GitError> {
        self.clones.fetch_add(1, Ordering::SeqCst);
        let tree = self
            .remotes
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| GitError::Clone("no such remote".to_owned()))?;
        for (name, content) in tree {
            let path = dest.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        Ok("c0ffee".to_owned())
    }

    fn fetch_status(&self, _repo: &Path) -> Result<RemoteStatus, GitError> {
        self.status
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| GitError::Fetch("offline".to_owned()))
    }
}

#[derive(Default)]
struct FakeBuilder {
    calls: Mutex<Vec<Vec<String>>>,
}

impl Builder for FakeBuilder {
    fn build(&self, plugins: &[PluginId]) -> BuildReport {
        let ids: Vec<String> = plugins.iter().map(ToString::to_string).collect();
        self.calls.lock().unwrap().push(ids.clone());
        BuildReport {
            ok: true,
            duration_ms: 1,
            plugins: ids,
            errors: Vec::new(),
        }
    }
}

struct FakeApprover {
    answer: Mutex<Approval>,
    /// One operation to refuse whatever `answer` says, so a test can approve the install and
    /// still deny the key.
    deny: Mutex<Option<&'static str>>,
    asked: Mutex<Vec<ApprovalRequest>>,
}

impl Approver for FakeApprover {
    fn approve(&self, request: &ApprovalRequest) -> Approval {
        self.asked.lock().unwrap().push(request.clone());
        if *self.deny.lock().unwrap() == Some(request.operation) {
            return Approval::Denied;
        }
        *self.answer.lock().unwrap()
    }

    fn describe(&self) -> &'static str {
        "fake"
    }
}

struct Rig {
    dir: std::path::PathBuf,
    paths: Paths,
    git: Arc<FakeGit>,
    builder: Arc<FakeBuilder>,
    pusher: Arc<RecordingPusher>,
    approver: Arc<FakeApprover>,
    state: Arc<StateStore>,
    service: PluginsService,
}

impl Drop for Rig {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn rig(name: &str, answer: Approval) -> Rig {
    let dir = scratch_dir(&format!("svc-{name}"));
    let paths = Paths::new(dir.join("data"), &dir.join("cfg"));
    std::fs::create_dir_all(paths.root()).unwrap();
    let git = FakeGit::new();
    let builder = Arc::new(FakeBuilder::default());
    let pusher = Arc::new(RecordingPusher::default());
    let approver = Arc::new(FakeApprover {
        answer: Mutex::new(answer),
        deny: Mutex::new(None),
        asked: Mutex::new(Vec::new()),
    });
    let state = Arc::new(StateStore::open(paths.state_file()).unwrap());
    let service = PluginsService::new(
        paths.clone(),
        (
            Arc::clone(&git) as Arc<dyn Git>,
            Arc::clone(&builder) as Arc<dyn Builder>,
            Arc::clone(&state),
        ),
        Arc::clone(&pusher) as Arc<dyn vrcnext_bridge_core::Pusher>,
        Arc::clone(&approver) as Arc<dyn Approver>,
    );
    Rig {
        dir,
        paths,
        git,
        builder,
        pusher,
        approver,
        state,
        service,
    }
}

const URL: &str = "https://example.com/friend-alerts.git";

fn manifest(version: &str) -> String {
    json!({
        "id": "friend-alerts", "name": "Friend alerts", "version": version,
        "apiVersion": "^0.2.0", "description": "d", "permissions": ["host:events"]
    })
    .to_string()
}

fn good_tree() -> Tree {
    vec![
        ("plugin.json", manifest("1.0.0")),
        ("main.ts", "export default definePlugin({})".to_owned()),
        ("src/util.ts", "export const x = 1".to_owned()),
    ]
}

fn code(error: &ServiceError) -> String {
    match error {
        ServiceError::BadRequest(message) => message.split(':').next().unwrap().to_owned(),
        other => panic!("expected bad_request, got {other:?}"),
    }
}

fn operations(approver: &FakeApprover) -> Vec<String> {
    approver
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.operation.to_owned())
        .collect()
}

fn key_id_of(seed: u8) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    crate::signing::key_id(&crate::signing::hex(&key.verifying_key().to_bytes()))
}

fn steps(pusher: &RecordingPusher) -> Vec<String> {
    pusher
        .events()
        .into_iter()
        .filter(|(event, _)| *event == "progress")
        .map(|(_, data)| data["step"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn install_runs_the_pipeline_in_order_and_records_the_plugin() {
    let r = rig("install", Approval::Approved);
    r.git.serve(URL, good_tree());
    let result = r.service.call("install", json!({ "url": URL })).unwrap();

    let plugin = &result["plugin"];
    assert_eq!(plugin["id"], "friend-alerts");
    assert_eq!(plugin["version"], "1.0.0");
    assert_eq!(plugin["url"], URL);
    assert_eq!(plugin["commit"], "c0ffee");
    assert_eq!(plugin["installedAt"], plugin["updatedAt"]);
    assert_eq!(plugin["permissions"], json!(["host:events"]));

    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(r.paths.plugin_dir(&id).join("src/util.ts").is_file());
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_some());
    assert_eq!(
        steps(&r.pusher),
        [
            "awaiting_confirmation",
            "clone",
            "validate",
            "policy",
            "signature",
            "awaiting_confirmation",
            "move",
            "build"
        ]
    );
    assert_eq!(
        *r.builder.calls.lock().unwrap(),
        vec![vec!["friend-alerts"]]
    );
    assert!(
        r.pusher
            .events()
            .iter()
            .any(|(e, d)| *e == "plugins" && d["plugins"][0]["id"] == "friend-alerts")
    );
    assert_eq!(
        operations(&r.approver),
        ["install", "trust_key"],
        "a first install asks to install and then to trust the key"
    );
    assert_eq!(plugin["keyId"], key_id_of(AUTHOR));

    // No temp directories left behind, and the list agrees.
    let leftovers: Vec<_> = std::fs::read_dir(r.paths.plugins_dir()).unwrap().collect();
    assert_eq!(leftovers.len(), 1);
    assert_eq!(
        r.service.call("list", json!({})).unwrap()["plugins"][0]["id"],
        "friend-alerts"
    );
}

#[test]
fn a_policy_violation_leaves_nothing_behind() {
    let r = rig("policy", Approval::Approved);
    let mut tree = good_tree();
    tree.push((
        "src/evil.ts",
        "const k = localStorage.getItem('t')".to_owned(),
    ));
    r.git.serve(URL, tree);
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(
        error,
        ServiceError::BadRequest("policy: src/evil.ts:1 localStorage".to_owned())
    );
    assert!(
        std::fs::read_dir(r.paths.plugins_dir())
            .unwrap()
            .next()
            .is_none()
    );
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
    assert!(r.builder.calls.lock().unwrap().is_empty());
}

#[test]
fn manifest_problems_are_named() {
    let r = rig("manifest", Approval::Approved);
    r.git.serve_raw(URL, vec![("main.ts", String::new())]);
    assert_eq!(
        code(
            &r.service
                .call("install", json!({ "url": URL }))
                .unwrap_err()
        ),
        "no_manifest"
    );

    r.git.serve_raw(
        URL,
        vec![("plugin.json", "{}".to_owned()), ("main.ts", String::new())],
    );
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "manifest_invalid");

    r.git
        .serve_raw(URL, vec![("plugin.json", manifest("1.0.0"))]);
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert!(error.to_string().contains("main.ts is missing"), "{error}");
}

#[test]
fn only_https_urls_and_only_once() {
    let r = rig("url", Approval::Approved);
    for bad in ["http://example.com/x", "git@github.com:a/b", "https://a b"] {
        let error = r
            .service
            .call("install", json!({ "url": bad }))
            .unwrap_err();
        assert_eq!(code(&error), "not_https", "{bad}");
    }
    assert_eq!(r.git.clones.load(Ordering::SeqCst), 0);

    r.git.serve(URL, good_tree());
    r.service.call("install", json!({ "url": URL })).unwrap();
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "already_installed");
    r.git.serve("https://other/x", good_tree());
    let error = r
        .service
        .call("install", json!({ "url": "https://other/x" }))
        .unwrap_err();
    assert_eq!(code(&error), "already_installed");
}

#[test]
fn a_clone_failure_is_reported_and_cleaned_up() {
    let r = rig("clone-fail", Approval::Approved);
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "clone_failed");
    assert!(
        std::fs::read_dir(r.paths.plugins_dir())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_denied_confirmation_clones_nothing() {
    let r = rig("denied", Approval::Denied);
    r.git.serve(URL, good_tree());
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "denied");
    assert_eq!(r.git.clones.load(Ordering::SeqCst), 0);
    assert_eq!(steps(&r.pusher), ["awaiting_confirmation"]);
}

#[test]
fn no_approver_means_refusal_not_a_pass() {
    let r = rig("unavailable", Approval::Unavailable);
    r.git.serve(URL, good_tree());
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "approval_unavailable");
    assert_eq!(r.git.clones.load(Ordering::SeqCst), 0);
}

fn installed(name: &str) -> Rig {
    let r = rig(name, Approval::Approved);
    r.git.serve(URL, good_tree());
    r.service.call("install", json!({ "url": URL })).unwrap();
    r.state.set("plugin:friend-alerts", "k", json!(1)).unwrap();
    r
}

#[test]
fn update_swaps_in_the_new_tree_and_keeps_installed_at() {
    let r = installed("update");
    let before = r.service.call("list", json!({})).unwrap()["plugins"][0].clone();
    let mut tree = good_tree();
    tree[0] = ("plugin.json", manifest("1.1.0"));
    tree.retain(|(name, _)| *name != "src/util.ts");
    r.git.serve(URL, tree);

    let result = r
        .service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap();
    assert_eq!(result["plugin"]["version"], "1.1.0");
    assert_eq!(result["plugin"]["installedAt"], before["installedAt"]);
    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(!r.paths.plugin_dir(&id).join("src/util.ts").exists());
    assert_eq!(r.builder.calls.lock().unwrap().len(), 2);
    assert_eq!(
        operations(&r.approver),
        ["install", "trust_key", "update"],
        "an update signed by the pinned key asks once"
    );
    assert_eq!(std::fs::read_dir(r.paths.plugins_dir()).unwrap().count(), 1);
}

#[test]
fn an_invalid_update_leaves_the_old_tree_untouched() {
    let r = installed("update-invalid");
    let mut tree = good_tree();
    tree[1] = ("main.ts", "eval('x')".to_owned());
    r.git.serve(URL, tree);
    let error = r
        .service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap_err();
    assert_eq!(code(&error), "policy");
    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(r.paths.plugin_dir(&id).join("src/util.ts").is_file());
    assert_eq!(
        r.service.call("list", json!({})).unwrap()["plugins"][0]["version"],
        "1.0.0"
    );
    assert_eq!(r.builder.calls.lock().unwrap().len(), 1);

    let mut tree = good_tree();
    tree[0] = (
        "plugin.json",
        manifest("1.2.0").replace("friend-alerts", "other-id"),
    );
    r.git.serve(URL, tree);
    let error = r
        .service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap_err();
    assert_eq!(code(&error), "manifest_invalid");
    assert_eq!(std::fs::read_dir(r.paths.plugins_dir()).unwrap().count(), 1);
}

#[test]
fn uninstall_removes_the_clone_the_record_and_the_settings() {
    let r = installed("uninstall");
    r.service
        .call("uninstall", json!({ "id": "friend-alerts" }))
        .unwrap();
    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(!r.paths.plugin_dir(&id).exists());
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
    assert!(r.state.list("plugin:friend-alerts").is_empty());
    assert_eq!(
        *r.builder.calls.lock().unwrap().last().unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        r.service.call("list", json!({})).unwrap()["plugins"],
        json!([])
    );

    let error = r
        .service
        .call("uninstall", json!({ "id": "friend-alerts" }))
        .unwrap_err();
    assert_eq!(code(&error), "not_installed");
    let error = r
        .service
        .call("update", json!({ "id": "../x" }))
        .unwrap_err();
    assert_eq!(code(&error), "invalid_id");
}

#[test]
fn check_updates_lists_only_plugins_that_are_behind() {
    let r = installed("updates");
    *r.git.status.lock().unwrap() = Some(RemoteStatus {
        current: "c0ffee".to_owned(),
        latest: "c0ffee".to_owned(),
        changelog: Vec::new(),
    });
    assert_eq!(
        r.service.call("check_updates", json!({})).unwrap(),
        json!({ "updates": [] })
    );

    *r.git.status.lock().unwrap() = Some(RemoteStatus {
        current: "c0ffee".to_owned(),
        latest: "beef".to_owned(),
        changelog: vec![ChangelogEntry {
            commit: "beef".to_owned(),
            summary: "Fix".to_owned(),
            time: 7,
        }],
    });
    let updates = r.service.call("check_updates", json!({})).unwrap();
    assert_eq!(
        updates,
        json!({ "updates": [{
            "id": "friend-alerts", "current": "c0ffee", "latest": "beef", "commitsBehind": 1,
            "changelog": [{ "commit": "beef", "summary": "Fix", "time": 7 }]
        }] })
    );
}

#[test]
fn build_returns_the_report_and_describe_names_the_approver() {
    let r = installed("build");
    let report = r.service.call("build", json!({})).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["plugins"], json!(["friend-alerts"]));
    let describe: Value = r.service.describe();
    assert_eq!(describe["confirmation"], "fake");
    assert_eq!(describe["installed"], json!(["friend-alerts"]));
}

#[test]
fn an_unsigned_tree_is_never_installed() {
    let r = rig("unsigned", Approval::Approved);
    r.git.serve_raw(URL, good_tree());
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "unsigned");
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
    assert!(r.builder.calls.lock().unwrap().is_empty());
    assert!(
        std::fs::read_dir(r.paths.plugins_dir())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn a_tree_changed_after_signing_is_never_installed() {
    // What a compromised mirror or a rewritten branch looks like: the signature is the author's,
    // the files are not.
    let r = rig("tampered", Approval::Approved);
    let mut tree = sign(good_tree(), AUTHOR);
    tree[1] = (
        "main.ts",
        "export default definePlugin({ evil: 1 })".to_owned(),
    );
    r.git.serve_raw(URL, tree);
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "unsigned");
    assert!(
        error.to_string().contains("changed after it was signed"),
        "{error}"
    );
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
}

#[test]
fn declining_to_trust_the_key_installs_nothing() {
    // The install itself is approved; only the key is refused. Nothing may reach `plugins/`.
    let r = rig("untrusted-key", Approval::Approved);
    *r.approver.deny.lock().unwrap() = Some("trust_key");
    r.git.serve(URL, good_tree());
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "denied");
    assert_eq!(operations(&r.approver), ["install", "trust_key"]);
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
    assert!(r.builder.calls.lock().unwrap().is_empty());
    assert!(
        std::fs::read_dir(r.paths.plugins_dir())
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(
        r.service.call("keys", json!({})).unwrap(),
        json!({ "keys": [] })
    );
}

#[test]
fn a_trusted_key_is_not_asked_about_twice() {
    let r = rig("trust-once", Approval::Approved);
    r.git.serve(URL, good_tree());
    r.service.call("install", json!({ "url": URL })).unwrap();

    // A second plugin from the same author: the key is already trusted, so only the install
    // itself is confirmed.
    let other = "https://example.com/other.git";
    let mut tree = good_tree();
    tree[0] = (
        "plugin.json",
        manifest("1.0.0").replace("friend-alerts", "other-id"),
    );
    r.git.serve(other, tree);
    r.service.call("install", json!({ "url": other })).unwrap();

    assert_eq!(operations(&r.approver), ["install", "trust_key", "install"]);
    let keys = r.service.call("keys", json!({})).unwrap();
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        keys["keys"][0]["seenFor"],
        json!(["friend-alerts", "other-id"])
    );
    assert_eq!(
        keys["keys"][0]["installed"],
        json!(["friend-alerts", "other-id"])
    );
}

#[test]
fn an_update_signed_by_a_different_key_is_confirmed_separately() {
    let r = installed("rotate");
    r.git.serve_signed_by(URL, good_tree(), 2);
    r.service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap();

    assert_eq!(
        operations(&r.approver),
        ["install", "trust_key", "update", "rotate_key", "trust_key"],
        "a key change is its own question, and the new key is its own question too"
    );
    assert_eq!(
        r.service.call("list", json!({})).unwrap()["plugins"][0]["keyId"],
        key_id_of(2),
        "the plugin is now pinned to the key the user accepted"
    );
}

#[test]
fn a_refused_key_change_leaves_the_old_tree_in_place() {
    let r = installed("rotate-denied");
    *r.approver.deny.lock().unwrap() = Some("rotate_key");
    r.git.serve_signed_by(URL, good_tree(), 2);
    let error = r
        .service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap_err();
    assert_eq!(code(&error), "denied");

    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(r.paths.plugin_dir(&id).join("src/util.ts").is_file());
    assert_eq!(
        r.service.call("list", json!({})).unwrap()["plugins"][0]["keyId"],
        key_id_of(AUTHOR)
    );
    assert_eq!(std::fs::read_dir(r.paths.plugins_dir()).unwrap().count(), 1);
    assert_eq!(r.builder.calls.lock().unwrap().len(), 1);
}

#[test]
fn trusting_another_author_does_not_hand_them_an_existing_plugin() {
    // The second author's key is already trusted in its own right; the update still asks,
    // because the question is about this plugin, not about the key in general.
    let r = installed("crossover");
    let other = "https://example.com/other.git";
    let mut tree = good_tree();
    tree[0] = (
        "plugin.json",
        manifest("1.0.0").replace("friend-alerts", "other-id"),
    );
    r.git.serve_signed_by(other, tree, 2);
    r.service.call("install", json!({ "url": other })).unwrap();

    r.git.serve_signed_by(URL, good_tree(), 2);
    r.service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap();
    assert!(
        operations(&r.approver).contains(&"rotate_key".to_owned()),
        "{:?}",
        operations(&r.approver)
    );
}

#[test]
fn forgetting_a_key_asks_first_and_uninstalls_nothing() {
    let r = installed("forget");
    let key = key_id_of(AUTHOR);
    let error = r
        .service
        .call("forget_key", json!({ "keyId": "nope" }))
        .unwrap_err();
    assert_eq!(code(&error), "not_trusted");

    r.service
        .call("forget_key", json!({ "keyId": key }))
        .unwrap();
    assert_eq!(
        r.service.call("keys", json!({})).unwrap(),
        json!({ "keys": [] })
    );
    let id = PluginId::parse("friend-alerts").unwrap();
    assert!(r.paths.plugin_dir(&id).join("main.ts").is_file());
    assert_eq!(operations(&r.approver).last().unwrap(), "forget_key");

    // The plugin still knows which key it belongs to, so the next update asks again.
    r.git.serve(URL, good_tree());
    r.service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap();
    assert_eq!(operations(&r.approver).last().unwrap(), "trust_key");
}

#[test]
fn a_record_without_a_key_must_be_reinstalled_but_can_be_uninstalled() {
    let r = installed("keyless");
    let mut record = r.state.get(RECORDS_NS, "friend-alerts").unwrap();
    record.as_object_mut().unwrap().remove("keyId");
    r.state.set(RECORDS_NS, "friend-alerts", record).unwrap();

    let error = r
        .service
        .call("update", json!({ "id": "friend-alerts" }))
        .unwrap_err();
    assert!(error.to_string().contains("reinstall_required"), "{error}");

    r.service
        .call("uninstall", json!({ "id": "friend-alerts" }))
        .unwrap();
    assert!(r.state.get(RECORDS_NS, "friend-alerts").is_none());
}
