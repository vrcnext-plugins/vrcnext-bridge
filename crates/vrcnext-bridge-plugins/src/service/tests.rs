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

    fn serve(&self, url: &str, tree: Tree) {
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
    answer: Approval,
    asked: Mutex<Vec<ApprovalRequest>>,
}

impl Approver for FakeApprover {
    fn approve(&self, request: &ApprovalRequest) -> Approval {
        self.asked.lock().unwrap().push(request.clone());
        self.answer
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
        answer,
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
    assert_eq!(r.approver.asked.lock().unwrap()[0].operation, "install");

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
    r.git.serve(URL, vec![("main.ts", String::new())]);
    assert_eq!(
        code(
            &r.service
                .call("install", json!({ "url": URL }))
                .unwrap_err()
        ),
        "no_manifest"
    );

    r.git.serve(
        URL,
        vec![("plugin.json", "{}".to_owned()), ("main.ts", String::new())],
    );
    let error = r
        .service
        .call("install", json!({ "url": URL }))
        .unwrap_err();
    assert_eq!(code(&error), "manifest_invalid");

    r.git.serve(URL, vec![("plugin.json", manifest("1.0.0"))]);
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
    assert_eq!(r.approver.asked.lock().unwrap()[1].operation, "update");
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
