//! Plugin signatures: what `plugin.sig` says, and whether the tree it names is really this one.
//!
//! A plugin is compiled into the same bundle as the host and runs with the page's authority, so
//! the only real question at install time is *whose code is this*. Git alone cannot answer it: a
//! URL is not an identity, a repository can change hands, and an account takeover rewrites every
//! branch at once. So every tree that reaches [`crate::service`] has to carry an Ed25519
//! signature made by a key the author holds, and the bridge remembers which key each plugin was
//! first installed with. A later tree signed by a different key is a different author until the
//! user says otherwise, natively.
//!
//! The format is deliberately boring, because the author has to be able to produce it from a
//! GitHub Actions step with nothing but Node's built-in crypto:
//!
//! ```json
//! {
//!   "version": 1,
//!   "algorithm": "ed25519",
//!   "id": "club-security",
//!   "publicKey": "<64 hex>",
//!   "digest": "<64 hex>",
//!   "signature": "<128 hex>",
//!   "signedAt": 1759000000
//! }
//! ```
//!
//! `digest` is [`tree_digest`] over every file in the checkout except `.git/` and the signature
//! file itself, and `signature` covers a domain-separated message that also names the plugin id,
//! so a signature cannot be lifted from one plugin onto another.
//!
//! What this does **not** do: it does not say the key is trustworthy, only that one key made this
//! tree. Deciding a key is the author's is the user's call, asked once through the native
//! approver and remembered in the trust store; see [`crate::service`].

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// The signature file at the root of a plugin repository.
pub const SIGNATURE_FILE: &str = "plugin.sig";

/// The only signature format this bridge understands.
pub const SIGNATURE_VERSION: u32 = 1;

/// Prefix of the bytes [`tree_digest`] hashes, so a digest can never be mistaken for a hash of
/// anything else.
const TREE_DOMAIN: &[u8] = b"vrcnext-plugin-tree-v1\n";

/// Prefix of the signed message, for the same reason, and to bind the signature to one plugin id.
const MESSAGE_DOMAIN: &[u8] = b"vrcnext-plugin-signature-v1\n";

/// Most files a digest walk will visit before giving up. The source policy allows 200 source
/// files; this is the whole tree, which also carries docs, licences and lockfiles.
const MAX_TREE_FILES: usize = 2000;

/// Most bytes the digest walk will read, in total. A lockfile is large; a plugin is not.
const MAX_TREE_BYTES: u64 = 16 * 1024 * 1024;

/// Why a tree was refused. Every message is safe to show: it names the failure, never the
/// repository's content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The repository has no `plugin.sig`.
    #[error("the repository has no {SIGNATURE_FILE}; unsigned plugins cannot be installed")]
    Missing,
    /// `plugin.sig` is not JSON in the expected shape, or names an algorithm or version this
    /// bridge does not implement.
    #[error("{SIGNATURE_FILE} is not usable: {0}")]
    Malformed(String),
    /// The signature is well formed but covers a different tree: the files have been changed
    /// since it was made.
    #[error("the files do not match the signature; the tree was changed after it was signed")]
    DigestMismatch,
    /// The signature names a different plugin than the manifest does.
    #[error("the signature is for plugin '{0}', not this one")]
    WrongPlugin(String),
    /// The signature does not verify against the public key it carries.
    #[error("the signature is not valid for the key it names")]
    Invalid,
    /// The tree could not be read, or is larger than a plugin is allowed to be.
    #[error("the tree cannot be digested: {0}")]
    Unreadable(String),
}

/// A verified signature: this key signed exactly this tree, for exactly this plugin.
///
/// Only [`verify`] constructs one, so holding a `VerifiedSignature` is the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The signing key, hex, 64 characters.
    pub public_key: String,
    /// A short, comparable name for the key: see [`key_id`].
    pub key_id: String,
    /// The tree digest the signature covers, hex.
    pub digest: String,
    /// When the author says they signed, seconds since the epoch. Advisory: the signer chose it.
    pub signed_at: u64,
}

/// `plugin.sig` as it is written, before anything about it has been checked.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignatureFile {
    version: u32,
    algorithm: String,
    id: String,
    public_key: String,
    digest: String,
    signature: String,
    #[serde(default)]
    signed_at: u64,
}

/// A short name for a key: the first 16 bytes of its SHA-256, hex, in groups of four.
///
/// Fingerprints are compared by eye — in a confirmation dialog, against a README — so they are
/// grouped rather than run together. 128 bits is far more than a collision needs to be out of
/// reach, and short enough to read aloud.
#[must_use]
pub fn key_id(public_key_hex: &str) -> String {
    let digest = Sha256::digest(public_key_hex.to_lowercase().as_bytes());
    digest
        .iter()
        .take(16)
        .enumerate()
        .fold(String::with_capacity(39), |mut out, (index, byte)| {
            if index > 0 && index % 2 == 0 {
                out.push('-');
            }
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The digest of every file in `root` except `.git/` and [`SIGNATURE_FILE`].
///
/// Paths are relative, `/`-separated, and sorted by their bytes, so the digest does not depend on
/// the order a filesystem hands entries back. Each file contributes its path, a NUL, its length
/// and its contents; the length is what stops `a/b` + `c` from hashing like `a/bc`. File modes
/// and timestamps are not covered: git does not carry the latter, and the bundler ignores both.
///
/// # Errors
///
/// [`SignatureError::Unreadable`] if a file cannot be read, or the tree exceeds
/// its file-count or total-size limit (2000 files, 16 MiB).
pub fn tree_digest(root: &Path) -> Result<String, SignatureError> {
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    hasher.update(TREE_DOMAIN);
    let mut total: u64 = 0;
    for relative in &files {
        let bytes = std::fs::read(root.join(relative))
            .map_err(|_| SignatureError::Unreadable(relative.clone()))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_TREE_BYTES {
            return Err(SignatureError::Unreadable(
                "the tree is too large".to_owned(),
            ));
        }
        hasher.update(relative.as_bytes());
        hasher.update([0_u8]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hex(&hasher.finalize()))
}

/// Append the relative path of every file under `dir` to `out`.
///
/// Symlinks are not followed and not recorded: a symlink cannot contribute content to the
/// bundle, and following one would let a repository digest files outside its own tree.
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), SignatureError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|_| SignatureError::Unreadable(display(root, dir)))?
        .flatten();
    for entry in entries {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect(root, &path, out)?;
            continue;
        }
        let relative = display(root, &path);
        if relative == SIGNATURE_FILE {
            continue;
        }
        if out.len() >= MAX_TREE_FILES {
            return Err(SignatureError::Unreadable(
                "the tree has too many files".to_owned(),
            ));
        }
        out.push(relative);
    }
    Ok(())
}

/// `path` relative to `root`, with forward slashes, so a digest made on Windows matches one made
/// on Linux.
fn display(root: &Path, path: &Path) -> String {
    let relative: PathBuf = path.strip_prefix(root).unwrap_or(path).to_path_buf();
    relative.to_string_lossy().replace('\\', "/")
}

/// Check that `root` carries a signature for `id` that covers the files actually there.
///
/// # Errors
///
/// [`SignatureError`], one variant per way this can fail; every one of them refuses the tree.
pub fn verify(root: &Path, id: &str) -> Result<VerifiedSignature, SignatureError> {
    let bytes = std::fs::read(root.join(SIGNATURE_FILE)).map_err(|_| SignatureError::Missing)?;
    let file: SignatureFile = serde_json::from_slice(&bytes)
        .map_err(|error| SignatureError::Malformed(error.to_string()))?;
    if file.version != SIGNATURE_VERSION {
        return Err(SignatureError::Malformed(format!(
            "version {} is not supported; this bridge reads version {SIGNATURE_VERSION}",
            file.version
        )));
    }
    if file.algorithm != "ed25519" {
        return Err(SignatureError::Malformed(format!(
            "algorithm '{}' is not supported",
            file.algorithm
        )));
    }
    if file.id != id {
        return Err(SignatureError::WrongPlugin(file.id));
    }

    let public_key = unhex::<32>(&file.public_key)
        .ok_or_else(|| SignatureError::Malformed("publicKey is not 32 bytes of hex".to_owned()))?;
    let signature = unhex::<64>(&file.signature)
        .ok_or_else(|| SignatureError::Malformed("signature is not 64 bytes of hex".to_owned()))?;
    let key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| SignatureError::Malformed("publicKey is not a valid key".to_owned()))?;

    // The digest first: a mismatch means the tree was edited after signing, which is a more
    // useful thing to say than "invalid signature", and says nothing the attacker does not know.
    let actual = tree_digest(root)?;
    if !actual.eq_ignore_ascii_case(&file.digest) {
        return Err(SignatureError::DigestMismatch);
    }

    key.verify(
        &message(id, &actual),
        &DalekSignature::from_bytes(&signature),
    )
    .map_err(|_| SignatureError::Invalid)?;

    Ok(VerifiedSignature {
        key_id: key_id(&file.public_key),
        public_key: file.public_key.to_lowercase(),
        digest: actual,
        signed_at: file.signed_at,
    })
}

/// The bytes a signature covers: the domain, the plugin id and the tree digest, newline
/// separated. Naming the id here is what stops a valid signature for one plugin from being
/// copied onto another.
#[must_use]
pub fn message(id: &str, digest: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(MESSAGE_DOMAIN.len() + id.len() + digest.len() + 2);
    out.extend_from_slice(MESSAGE_DOMAIN);
    out.extend_from_slice(id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(digest.as_bytes());
    out.push(b'\n');
    out
}

/// Lowercase hex, the only encoding this format uses.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Exactly `N` bytes from `2N` hex characters, or `None`.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; N];
    let bytes = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = bytes.get(index * 2..index * 2 + 2)?;
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests;
