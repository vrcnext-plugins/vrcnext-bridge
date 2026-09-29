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
//!
//! esbuild resolves whatever a plugin imports, and a relative specifier can climb out of the
//! plugin's directory: `import s from '../../state.json'` would inline every plugin's settings,
//! and `../../host/packages/host/src/…` would hand a plugin the host's own module instances,
//! past the permission gate. The source policy refuses the obvious spellings, but the resolver is
//! the authority on what a specifier means, so every build also asks esbuild for its metafile and
//! refuses the bundle unless each input is one a plugin may reach: see [`check_inputs`].

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
/// The only compiler options esbuild is allowed to see. Mirrored in the host repo's scripts/build.sh.
const TSCONFIG_RAW: &str =
    r#"{"compilerOptions":{"target":"es2022","useDefineForClassFields":true}}"#;

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
    #[error("{0}")]
    Boundary(String),
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
        let metafile = staging.join(METAFILE_NAME);

        log::info!("build: running esbuild");
        let outcome = run_esbuild(&self.paths, &staged, &metafile)
            .and_then(|()| read_metafile(&metafile))
            .and_then(|meta| check_inputs(&meta, plugins).map_err(BuildError::Boundary))
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

/// The metafile's name inside the staging directory, which is removed after every build.
const METAFILE_NAME: &str = "meta.json";

/// Where the plugin API's sources live. A plugin may import anything under it: it is the public
/// surface, and it imports nothing from the host.
const API_DIR: &str = "host/packages/api/src/";

/// Where every host package lives. Only the host and the API may be inputs from here.
const HOST_DIR: &str = "host/packages/";

/// Read the metafile esbuild wrote beside the staged bundle.
fn read_metafile(path: &Path) -> Result<serde_json::Value, BuildError> {
    let bytes = std::fs::read(path)
        .map_err(|error| BuildError::Boundary(format!("esbuild wrote no metafile: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| BuildError::Boundary(format!("esbuild's metafile is unreadable: {error}")))
}

/// Refuse a bundle that read a file no plugin may reach.
///
/// The metafile lists every input the bundle was made from, relative to the data root, and every
/// import edge each one resolved. The rules:
///
/// - every input is under `host/packages/`, is the generated `build/static-plugins.ts`, or is
///   under `plugins/<id>/` for a plugin in this build — nothing else on disk (`state.json`, a
///   config file, a data: URL) may be bundled;
/// - a file under `plugins/<id>/` imports only its own plugin's files and the plugin API, never
///   the host's internals or another plugin;
/// - a file of the plugin API imports only the plugin API, so it cannot be a stepping stone;
/// - no plugin input is a test file (`*.test.*`, `*.spec.*`): the source policy does not scan
///   those, so they must never reach the page.
///
/// # Errors
///
/// A one-line reason naming the first input or edge that broke a rule.
pub fn check_inputs(meta: &serde_json::Value, plugins: &[PluginId]) -> Result<(), String> {
    let inputs = meta
        .get("inputs")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "esbuild's metafile lists no inputs".to_owned())?;
    for (input, detail) in inputs {
        // esbuild writes `/` everywhere, but a rule that a backslash could dodge is no rule.
        let input = &input.replace('\\', "/");
        let owner = plugin_of(input, plugins);
        let allowed = input.starts_with(HOST_DIR) || input == STATIC_PLUGINS || owner.is_some();
        if !allowed {
            return Err(format!("the bundle may not include {input}"));
        }
        if owner.is_some() && crate::policy::is_test_file(input) {
            return Err(format!("{input} is a test file and may not be bundled"));
        }
        let imports = detail
            .get("imports")
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        // An edge esbuild left external (a type-only import it erased) bundled nothing.
        for target in imports
            .iter()
            .filter(|edge| edge.get("external").and_then(serde_json::Value::as_bool) != Some(true))
            .filter_map(|edge| edge.get("path").and_then(serde_json::Value::as_str))
            .map(|target| target.replace('\\', "/"))
        {
            let reachable = match owner {
                Some(id) => target.starts_with(API_DIR) || plugin_of(&target, plugins) == Some(id),
                None if input.starts_with(API_DIR) => target.starts_with(API_DIR),
                None => true,
            };
            if !reachable {
                return Err(format!("{input} may not import {target}"));
            }
        }
    }
    Ok(())
}

/// The plugin in this build whose directory holds `path`, if any.
fn plugin_of<'a>(path: &str, plugins: &'a [PluginId]) -> Option<&'a PluginId> {
    let rest = path.strip_prefix("plugins/")?;
    let (dir, _) = rest.split_once('/')?;
    plugins.iter().find(|id| id.as_str() == dir)
}

/// The fixed argument list. `outfile` is the staging path and `metafile` sits beside it;
/// everything else is relative to the data root, which is the working directory.
fn esbuild_args(outfile: &Path, metafile: &Path) -> Vec<String> {
    vec![
        HOST_ENTRY.to_owned(),
        "--bundle".to_owned(),
        "--format=iife".to_owned(),
        "--target=es2022".to_owned(),
        // Compiler options are given inline so the build never depends on a tsconfig.json being
        // present: the host tarball ships only sources, and a plugin's own tsconfig must not be
        // able to change how the bundle is compiled.
        format!("--tsconfig-raw={TSCONFIG_RAW}"),
        "--platform=browser".to_owned(),
        "--minify".to_owned(),
        "--sourcemap=linked".to_owned(),
        format!("--alias:@vrcnext/plugin-api=./{API_ENTRY}"),
        format!("--alias:@vrcnext/static-plugins=./{STATIC_PLUGINS}"),
        format!("--outfile={}", outfile.display()),
        format!("--metafile={}", metafile.display()),
        "--log-level=warning".to_owned(),
        "--color=false".to_owned(),
    ]
}

/// Spawn esbuild with a cleared environment, capture its output, and enforce the deadline.
fn run_esbuild(paths: &Paths, outfile: &Path, metafile: &Path) -> Result<(), BuildError> {
    let mut child = Command::new(paths.esbuild())
        .args(esbuild_args(outfile, metafile))
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
mod tests;
