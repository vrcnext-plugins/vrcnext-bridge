//! Compiling the host and every installed plugin into the one bundle VRCNext loads.
//!
//! This is the one place in the bridge that spawns a process. The rule that makes that
//! acceptable: it spawns exactly one binary, `bin/esbuild`, only after its SHA-256 matches the
//! checksum the installer wrote beside it, with a fixed argument list in which the only
//! caller-derived input is the list of plugin ids — and those are regex-validated
//! [`PluginId`]s that appear in a generated file, not on the command line. Nothing from a
//! plugin, a request or a manifest reaches argv or the environment.
//!
//! The bundle is built to a temporary file beside the real one and renamed into place on
//! success, so a failed build leaves the previous bundle — and the user's working page — exactly
//! as it was.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use vrcnext_bridge_core::{Paths, PluginId, Pusher};

use crate::fsutil::{create_dir_private, write_atomic};

/// Longest esbuild may run. A bundle of a few hundred kilobytes takes well under a second; a
/// minute means something is wrong, not slow.
pub const ESBUILD_DEADLINE: Duration = Duration::from_secs(60);

/// The entry point inside `host/`.
const HOST_ENTRY: &str = "host/packages/host/src/index.ts";

/// What `@vrcnext/plugin-api` resolves to.
const API_ENTRY: &str = "host/packages/api/src/index.ts";

/// What `@vrcnext/static-plugins` resolves to, relative to the data root.
const STATIC_PLUGINS: &str = "build/static-plugins.ts";

/// What the `build` push carries, and what `plugins/build` returns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildReport {
    /// Whether the bundle was replaced.
    pub ok: bool,
    /// Wall time.
    pub duration_ms: u64,
    /// The plugins compiled in, in import order.
    pub plugins: Vec<String>,
    /// esbuild's output, or the bridge's reason for not running it. Empty on success.
    pub errors: Vec<String>,
}

/// Something that turns the installed set into a bundle.
///
/// A trait so the `plugins` service can be tested without esbuild; [`EsbuildBuilder`] is the
/// only real implementation.
pub trait Builder: Send + Sync {
    /// Build with exactly these plugins. Never fails: a failure is a report with `ok: false`,
    /// because the caller's own operation (an install, say) has already succeeded.
    fn build(&self, plugins: &[PluginId]) -> BuildReport;
}

/// Why a build stopped before, or while, running esbuild.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum BuildError {
    #[error("esbuild binary or checksum missing at {0}")]
    Missing(String),
    #[error("esbuild checksum mismatch: refusing to run it")]
    Checksum,
    #[error("host sources missing at {0}")]
    NoHost(String),
    #[error("cannot write {0}: {1}")]
    Write(String, String),
    #[error("cannot start esbuild: {0}")]
    Spawn(String),
    #[error("esbuild did not finish within {}s", ESBUILD_DEADLINE.as_secs())]
    Timeout,
    #[error("esbuild failed:\n{0}")]
    Failed(String),
}

/// The real builder.
pub struct EsbuildBuilder {
    paths: Paths,
    pusher: Arc<dyn Pusher>,
}

impl EsbuildBuilder {
    /// Build into the layout `paths` describes, announcing results through `pusher`.
    #[must_use]
    pub fn new(paths: Paths, pusher: Arc<dyn Pusher>) -> Self {
        Self { paths, pusher }
    }

    fn run(&self, plugins: &[PluginId]) -> Result<(), BuildError> {
        log::info!("build: verifying esbuild checksum");
        verify_checksum(&self.paths.esbuild(), &self.paths.esbuild_checksum())?;

        let host_entry = self.paths.root().join(HOST_ENTRY);
        if !host_entry.is_file() {
            return Err(BuildError::NoHost(host_entry.display().to_string()));
        }

        log::info!(
            "build: generating static-plugins.ts for {} plugin(s)",
            plugins.len()
        );
        let table = self.paths.static_plugins();
        create_dir_private(&self.paths.build_dir())
            .and_then(|()| write_atomic(&table, generate_static_plugins(plugins).as_bytes()))
            .map_err(|error| BuildError::Write(table.display().to_string(), error.to_string()))?;

        // Built beside the real bundle so the final rename never crosses a filesystem.
        let staging = self.paths.theme_dir().join(".build");
        std::fs::create_dir_all(&staging)
            .map_err(|error| BuildError::Write(staging.display().to_string(), error.to_string()))?;
        let staged = staging.join(vrcnext_bridge_core::paths::BUNDLE_NAME);

        log::info!("build: running esbuild");
        let outcome = run_esbuild(&self.paths, &staged)
            .and_then(|()| write_theme_info(self.paths.theme_dir()))
            .and_then(|()| self.promote(&staged));
        // Whatever happened, the staging directory is scratch; only the renames are a result.
        let _ = std::fs::remove_dir_all(&staging);
        outcome
    }

    /// Rename the staged bundle and its map over the live ones. The map goes first so a bundle
    /// that references a map is never newer than the map it references.
    fn promote(&self, staged: &Path) -> Result<(), BuildError> {
        let bundle = self.paths.bundle();
        for (from, to) in [
            (
                staged.with_extension("js.map"),
                bundle.with_extension("js.map"),
            ),
            (staged.to_path_buf(), bundle),
        ] {
            std::fs::rename(&from, &to)
                .map_err(|error| BuildError::Write(to.display().to_string(), error.to_string()))?;
        }
        Ok(())
    }
}

impl Builder for EsbuildBuilder {
    fn build(&self, plugins: &[PluginId]) -> BuildReport {
        let started = Instant::now();
        let outcome = self.run(plugins);
        let report = BuildReport {
            ok: outcome.is_ok(),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            plugins: plugins.iter().map(ToString::to_string).collect(),
            errors: outcome
                .err()
                .map(|e| vec![e.to_string()])
                .unwrap_or_default(),
        };
        match &report.errors.first() {
            None => log::info!(
                "build: bundle written to {} in {}ms",
                self.paths.bundle().display(),
                report.duration_ms
            ),
            Some(error) => log::error!("build: {error}"),
        }
        self.pusher.push("build", serde_json::json!(report));
        report
    }
}

/// The generated import table. Ids are validated, so they are safe inside a path literal;
/// the manifest JSON is validated, so importing it is safe.
#[must_use]
pub fn generate_static_plugins(plugins: &[PluginId]) -> String {
    let mut out = String::from("// Generated by vrcnext-bridge. Do not edit.\n");
    for (index, id) in plugins.iter().enumerate() {
        let _ = writeln!(out, "import p{index} from '../plugins/{id}/main.ts';");
        let _ = writeln!(out, "import m{index} from '../plugins/{id}/plugin.json';");
    }
    out.push_str("export const COMPILED_PLUGINS = [");
    for index in 0..plugins.len() {
        if index > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{{ manifest: m{index}, plugin: p{index} }}");
    }
    out.push_str("] as const;\n");
    out
}

/// Refuse unless the binary's SHA-256 equals the first token of the checksum file.
fn verify_checksum(binary: &Path, checksum: &Path) -> Result<(), BuildError> {
    let expected = std::fs::read_to_string(checksum)
        .map_err(|_| BuildError::Missing(checksum.display().to_string()))?;
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let bytes =
        std::fs::read(binary).map_err(|_| BuildError::Missing(binary.display().to_string()))?;
    let actual = hex(&Sha256::digest(&bytes));
    if expected.len() == 64 && actual == expected {
        Ok(())
    } else {
        Err(BuildError::Checksum)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The fixed argument list. `outfile` is the staging path; everything else is relative to the
/// data root, which is the working directory.
fn esbuild_args(outfile: &Path) -> Vec<String> {
    vec![
        HOST_ENTRY.to_owned(),
        "--bundle".to_owned(),
        "--format=iife".to_owned(),
        "--target=es2022".to_owned(),
        "--platform=browser".to_owned(),
        "--minify".to_owned(),
        "--sourcemap=linked".to_owned(),
        format!("--alias:@vrcnext/plugin-api=./{API_ENTRY}"),
        format!("--alias:@vrcnext/static-plugins=./{STATIC_PLUGINS}"),
        format!("--outfile={}", outfile.display()),
        "--log-level=warning".to_owned(),
        "--color=false".to_owned(),
    ]
}

/// Spawn esbuild with a cleared environment, capture its output, and enforce the deadline.
fn run_esbuild(paths: &Paths, outfile: &Path) -> Result<(), BuildError> {
    let mut child = Command::new(paths.esbuild())
        .args(esbuild_args(outfile))
        .current_dir(paths.root())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| BuildError::Spawn(error.to_string()))?;

    // Drain both pipes on their own threads: a child that fills one while we wait on the other
    // would deadlock, and esbuild writes warnings to stderr while emitting nothing on stdout.
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > ESBUILD_DEADLINE => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(BuildError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(BuildError::Spawn(error.to_string())),
        }
    };
    let output = [stdout, stderr]
        .into_iter()
        .flatten()
        .filter_map(|handle| handle.join().ok())
        .collect::<Vec<_>>()
        .join("\n");
    if status.success() {
        if !output.trim().is_empty() {
            log::warn!("esbuild: {}", output.trim());
        }
        Ok(())
    } else {
        Err(BuildError::Failed(truncate(output.trim(), 4_000)))
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = pipe.read_to_string(&mut text);
        text
    })
}

/// `info.json`, which VRCNext expects beside a theme's files.
fn write_theme_info(theme_dir: &Path) -> Result<(), BuildError> {
    let info = serde_json::json!({
        "author": "vrcnext-plugins",
        "version": env!("CARGO_PKG_VERSION"),
    });
    let path = theme_dir.join("info.json");
    write_atomic(&path, &serde_json::to_vec_pretty(&info).unwrap_or_default())
        .map_err(|error| BuildError::Write(path.display().to_string(), error.to_string()))
}

fn truncate(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// The staging path for tests and diagnostics.
#[must_use]
pub fn staging_bundle(paths: &Paths) -> PathBuf {
    paths
        .theme_dir()
        .join(".build")
        .join(vrcnext_bridge_core::paths::BUNDLE_NAME)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use std::sync::Arc;

    use sha2::Digest as _;
    use vrcnext_bridge_core::{Paths, PluginId, Pusher, RecordingPusher};

    use super::{Builder as _, EsbuildBuilder, generate_static_plugins, hex, verify_checksum};
    use crate::fsutil::scratch_dir;

    fn ids(names: &[&str]) -> Vec<PluginId> {
        names.iter().map(|n| PluginId::parse(n).unwrap()).collect()
    }

    #[test]
    fn the_import_table_has_one_pair_per_plugin_in_order() {
        let table = generate_static_plugins(&ids(&["friend-alerts", "b2"]));
        assert_eq!(
            table,
            "// Generated by vrcnext-bridge. Do not edit.\n\
             import p0 from '../plugins/friend-alerts/main.ts';\n\
             import m0 from '../plugins/friend-alerts/plugin.json';\n\
             import p1 from '../plugins/b2/main.ts';\n\
             import m1 from '../plugins/b2/plugin.json';\n\
             export const COMPILED_PLUGINS = [{ manifest: m0, plugin: p0 }, { manifest: m1, plugin: p1 }] as const;\n"
        );
        assert_eq!(
            generate_static_plugins(&[]),
            "// Generated by vrcnext-bridge. Do not edit.\nexport const COMPILED_PLUGINS = [] as const;\n"
        );
    }

    #[test]
    fn the_checksum_must_match_exactly() {
        let dir = scratch_dir("checksum");
        let bin = dir.join("esbuild");
        let sum = dir.join("esbuild.sha256");
        std::fs::write(&bin, b"binary").unwrap();
        let good = hex(&sha2::Sha256::digest(b"binary"));
        std::fs::write(&sum, format!("{good}  esbuild\n")).unwrap();
        assert_eq!(verify_checksum(&bin, &sum), Ok(()));
        std::fs::write(&sum, good.to_uppercase()).unwrap();
        assert_eq!(verify_checksum(&bin, &sum), Ok(()));
        std::fs::write(&bin, b"tampered").unwrap();
        assert_eq!(
            verify_checksum(&bin, &sum),
            Err(super::BuildError::Checksum)
        );
        std::fs::remove_file(&sum).unwrap();
        assert!(matches!(
            verify_checksum(&bin, &sum),
            Err(super::BuildError::Missing(_))
        ));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_missing_binary_is_reported_not_spawned_and_pushed() {
        let dir = scratch_dir("build-missing");
        let paths = Paths::new(dir.join("data"), &dir.join("cfg"));
        let pusher = Arc::new(RecordingPusher::default());
        let builder = EsbuildBuilder::new(paths, Arc::clone(&pusher) as Arc<dyn Pusher>);
        let report = builder.build(&ids(&["ab"]));
        assert!(!report.ok);
        assert_eq!(report.plugins, vec!["ab"]);
        assert!(report.errors[0].contains("missing"), "{:?}", report.errors);
        let events = pusher.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "build");
        assert_eq!(events[0].1["ok"], false);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A stand-in "esbuild": a shell script with the right checksum that writes its outfile and
    /// its sourcemap. Proves the spawn, the argument shape, the staging rename and the
    /// theme info file without a real binary.
    #[cfg(unix)]
    #[test]
    fn a_verified_binary_is_spawned_and_the_bundle_renamed_into_place() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir("build-fake");
        let paths = Paths::new(dir.join("data"), &dir.join("cfg"));
        std::fs::create_dir_all(paths.bin_dir()).unwrap();
        std::fs::create_dir_all(paths.root().join("host/packages/host/src")).unwrap();
        std::fs::write(paths.root().join(super::HOST_ENTRY), "").unwrap();
        let script = "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --outfile=*) out=\"${a#--outfile=}\";; esac; done\n\
                      printf '%s\\n' \"$@\" > \"$out\"\nprintf '{}' > \"$out.map\"\n";
        std::fs::write(paths.esbuild(), script).unwrap();
        std::fs::set_permissions(paths.esbuild(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(paths.esbuild_checksum(), hex(&sha2::Sha256::digest(script))).unwrap();

        let builder = EsbuildBuilder::new(paths.clone(), Arc::new(RecordingPusher::default()));
        let report = builder.build(&ids(&["ab"]));
        assert!(report.ok, "{:?}", report.errors);
        let argv = std::fs::read_to_string(paths.bundle()).unwrap();
        assert!(argv.contains("--alias:@vrcnext/static-plugins=./build/static-plugins.ts"));
        assert!(argv.contains("--format=iife"));
        assert!(paths.bundle().with_extension("js.map").is_file());
        assert!(!super::staging_bundle(&paths).exists());
        assert!(paths.theme_dir().join("info.json").is_file());
        assert!(paths.static_plugins().is_file());

        // A failing run leaves the previous bundle alone.
        std::fs::write(paths.esbuild(), "#!/bin/sh\necho boom >&2\nexit 1\n").unwrap();
        std::fs::write(
            paths.esbuild_checksum(),
            hex(&sha2::Sha256::digest(b"#!/bin/sh\necho boom >&2\nexit 1\n")),
        )
        .unwrap();
        let report = builder.build(&ids(&["ab"]));
        assert!(!report.ok);
        assert!(report.errors[0].contains("boom"));
        assert_eq!(std::fs::read_to_string(paths.bundle()).unwrap(), argv);
        std::fs::remove_dir_all(dir).ok();
    }
}
