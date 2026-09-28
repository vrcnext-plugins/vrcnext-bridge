//! Plugin management for `vrcnext-bridge`: install, validate, compile, and keep the page's state.
//!
//! This is the crate that touches the filesystem and the network on the page's behalf. It is
//! split by the invariant each module protects:
//!
//! | Module | Protects |
//! | :--- | :--- |
//! | [`state`] | the page's data survives, atomically, within fixed bounds |
//! | [`manifest`] | only a well-formed `plugin.json` reaches the import table |
//! | [`policy`] | no plugin source reaches past `ctx.*` |
//! | [`obfuscation`] | the source a reviewer reads is the source that runs |
//! | [`signing`] | only a tree an author signed is installed, and only under their own key |
//! | [`trust`] | a signing key becomes trusted once, natively, and stays the plugin's own |
//! | [`git`] | cloning and fetching happen in-process, under a deadline |
//! | [`build`] | one checksum-verified binary, fixed arguments, previous bundle kept on failure |
//! | [`service`] | the pipeline runs in order, confirmed natively, and the record matches the disk |
//!
//! Everything a caller can name — a namespace, a key, a plugin id, a URL — is validated in the
//! module that owns it before it is used, and never joined into a path or a command line.

pub mod build;
pub mod fsutil;
pub mod git;
pub mod manifest;
pub mod obfuscation;
pub mod policy;
pub mod service;
pub mod signing;
pub mod state;
pub mod trust;

pub use build::{BuildReport, Builder, EsbuildBuilder};
pub use git::{Git, GixGit};
pub use manifest::Manifest;
pub use service::PluginsService;
pub use signing::{SignatureError, VerifiedSignature, tree_digest, verify};
pub use state::{StateService, StateStore};
pub use trust::{TrustStore, TrustedKey};
