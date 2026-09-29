//! Every filesystem location the bridge uses, derived from one root.
//!
//! There is exactly one place that knows the layout of `~/.vrcnext-plugins/` and of the VRCNext
//! theme folder, and this is it. Anything that needs a path asks a [`Paths`] rather than joining
//! strings itself, so a rename of one directory is a one-line change and a caller-supplied
//! string can never become a path without going through a validated accessor.
//!
//! ```text
//! ~/.vrcnext-plugins/            (Windows: %LOCALAPPDATA%\vrcnext-plugins\)
//!   bin/esbuild  bin/esbuild.sha256
//!   host/                        host + api sources from a release tarball
//!   plugins/<id>/                one git clone per plugin
//!   build/static-plugins.ts      generated import table
//!   state.json  token  bridge.log
//! ```
//!
//! The VRCNext config directory (`~/.config/VRCNext`, `%APPDATA%\VRCNext`) holds the theme folder
//! the build writes into. Its name is fixed: VRCNext enables themes by folder name.

use std::path::{Path, PathBuf};

/// The name of the theme folder VRCNext loads the bundle from.
pub const THEME_NAME: &str = "vrcnext-plugin-system";

/// The bundle file name inside the theme folder.
pub const BUNDLE_NAME: &str = "vrcnext-plugin-host.js";

/// The one layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    root: PathBuf,
    theme_dir: PathBuf,
    vrcnext_config: PathBuf,
}

/// Why the platform directories could not be determined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathsError {
    /// No home / local-data directory is known for this account.
    #[error("cannot determine the user's data directory")]
    NoDataDir,
    /// No config directory is known for this account.
    #[error("cannot determine the user's config directory")]
    NoConfigDir,
}

impl Paths {
    /// A layout rooted at `root`, with the theme folder under `vrcnext_config`.
    #[must_use]
    pub fn new(root: PathBuf, vrcnext_config: &Path) -> Self {
        Self {
            root,
            theme_dir: vrcnext_config.join("custom-themes").join(THEME_NAME),
            vrcnext_config: vrcnext_config.to_path_buf(),
        }
    }

    /// The platform layout: `~/.vrcnext-plugins` (or `%LOCALAPPDATA%\vrcnext-plugins`) and the
    /// VRCNext config directory. `root_override` replaces the data root only, which is what a
    /// second instance on a spare port needs.
    ///
    /// # Errors
    ///
    /// [`PathsError`] if the platform directories cannot be determined.
    pub fn detect(root_override: Option<PathBuf>) -> Result<Self, PathsError> {
        let root = match root_override {
            Some(root) => root,
            None => default_root().ok_or(PathsError::NoDataDir)?,
        };
        let config = dirs::config_dir().ok_or(PathsError::NoConfigDir)?;
        Ok(Self::new(root, &config.join("VRCNext")))
    }

    /// The data root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `bin/` — the bridge and esbuild binaries.
    #[must_use]
    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// The pinned esbuild binary.
    #[must_use]
    pub fn esbuild(&self) -> PathBuf {
        self.bin_dir().join(exe_name("esbuild"))
    }

    /// The checksum the esbuild binary must match before it is spawned.
    #[must_use]
    pub fn esbuild_checksum(&self) -> PathBuf {
        self.bin_dir().join("esbuild.sha256")
    }

    /// `host/` — the host and api sources.
    #[must_use]
    pub fn host_dir(&self) -> PathBuf {
        self.root.join("host")
    }

    /// `plugins/` — one clone per plugin.
    #[must_use]
    pub fn plugins_dir(&self) -> PathBuf {
        self.root.join("plugins")
    }

    /// `plugins/<id>/` for a validated plugin id.
    ///
    /// Takes a [`PluginId`] rather than a string precisely so that nothing unvalidated can be
    /// joined into a path.
    #[must_use]
    pub fn plugin_dir(&self, id: &PluginId) -> PathBuf {
        self.plugins_dir().join(id.as_str())
    }

    /// `build/` — generated files that are aliased into the bundle.
    #[must_use]
    pub fn build_dir(&self) -> PathBuf {
        self.root.join("build")
    }

    /// The generated import table.
    #[must_use]
    pub fn static_plugins(&self) -> PathBuf {
        self.build_dir().join("static-plugins.ts")
    }

    /// The state store.
    #[must_use]
    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    /// The pairing token.
    #[must_use]
    pub fn token_file(&self) -> PathBuf {
        self.root.join("token")
    }

    /// The daemon's own log.
    #[must_use]
    pub fn bridge_log(&self) -> PathBuf {
        self.root.join("bridge.log")
    }

    /// The VRCNext theme folder the bundle is written into.
    #[must_use]
    pub fn theme_dir(&self) -> &Path {
        &self.theme_dir
    }

    /// VRCNext's own configuration directory, which is also where it keeps its databases.
    ///
    /// Found through the platform's config directory rather than assembled from the home
    /// directory, so it is `%APPDATA%\VRCNext` on Windows and `~/.config/VRCNext` here.
    #[must_use]
    pub fn vrcnext_config(&self) -> &Path {
        &self.vrcnext_config
    }

    /// The bundle the page loads.
    #[must_use]
    pub fn bundle(&self) -> PathBuf {
        self.theme_dir.join(BUNDLE_NAME)
    }
}

/// `~/.vrcnext-plugins`, or `%LOCALAPPDATA%\vrcnext-plugins` on Windows.
fn default_root() -> Option<PathBuf> {
    if cfg!(windows) {
        dirs::data_local_dir().map(|dir| dir.join("vrcnext-plugins"))
    } else {
        dirs::home_dir().map(|home| home.join(".vrcnext-plugins"))
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

/// A plugin id that has passed the manifest's id rule: `[a-z0-9][a-z0-9-]{1,39}`.
///
/// The id names a directory, so its shape is a security boundary, not a style preference. It is
/// the only thing this module will join into a path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct PluginId(String);

/// Why a string is not a plugin id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("plugin id must match [a-z0-9][a-z0-9-]{{1,39}}")]
pub struct InvalidPluginId;

impl PluginId {
    /// Validate `candidate`.
    ///
    /// # Errors
    ///
    /// [`InvalidPluginId`] unless it is 2 to 40 characters of lowercase ASCII letters, digits and
    /// hyphens, not starting with a hyphen.
    pub fn parse(candidate: &str) -> Result<Self, InvalidPluginId> {
        let len = candidate.len();
        let mut chars = candidate.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if (2..=40).contains(&len) && first_ok && rest_ok {
            Ok(Self(candidate.to_owned()))
        } else {
            Err(InvalidPluginId)
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PluginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
