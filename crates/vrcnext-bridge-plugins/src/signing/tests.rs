#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
//! One test per way a tree can be refused, plus the properties the digest has to have for any
//! of it to mean anything: order independence, and sensitivity to every byte.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};

use super::{SIGNATURE_FILE, SignatureError, hex, key_id, message, tree_digest, verify};
use crate::fsutil::scratch_dir;

/// A fixed key, so the tests are reproducible and never need randomness.
fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_hex(key: &SigningKey) -> String {
    hex(&key.verifying_key().to_bytes())
}

/// Write `files` into a fresh directory and sign it as `id` with `key`.
fn signed_tree(
    name: &str,
    id: &str,
    key: &SigningKey,
    files: &[(&str, &str)],
) -> std::path::PathBuf {
    let dir = scratch_dir(&format!("sign-{name}"));
    for (path, content) in files {
        let full = dir.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    write_signature(&dir, id, key);
    dir
}

fn write_signature(dir: &Path, id: &str, key: &SigningKey) {
    let digest = tree_digest(dir).unwrap();
    let signature = hex(&key.sign(&message(id, &digest)).to_bytes());
    let file = serde_json::json!({
        "version": 1,
        "algorithm": "ed25519",
        "id": id,
        "publicKey": public_hex(key),
        "digest": digest,
        "signature": signature,
        "signedAt": 1_759_000_000,
    });
    std::fs::write(dir.join(SIGNATURE_FILE), file.to_string()).unwrap();
}

const FILES: &[(&str, &str)] = &[
    ("plugin.json", "{\"id\":\"demo\"}"),
    ("main.ts", "export default 1"),
    ("src/a.ts", "export const a = 1"),
];

#[test]
fn a_tree_signed_for_this_plugin_verifies() {
    let dir = signed_tree("ok", "demo", &signer(1), FILES);
    let verified = verify(&dir, "demo").unwrap();
    assert_eq!(verified.public_key, public_hex(&signer(1)));
    assert_eq!(verified.key_id, key_id(&verified.public_key));
    assert_eq!(verified.digest, tree_digest(&dir).unwrap());
    assert_eq!(verified.signed_at, 1_759_000_000);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_unsigned_tree_is_refused() {
    let dir = scratch_dir("sign-none");
    std::fs::write(dir.join("main.ts"), "export default 1").unwrap();
    assert_eq!(verify(&dir, "demo").unwrap_err(), SignatureError::Missing);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_file_changed_after_signing_is_refused() {
    let dir = signed_tree("edited", "demo", &signer(1), FILES);
    std::fs::write(dir.join("src/a.ts"), "export const a = 2").unwrap();
    assert_eq!(
        verify(&dir, "demo").unwrap_err(),
        SignatureError::DigestMismatch
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_file_added_after_signing_is_refused() {
    let dir = signed_tree("added", "demo", &signer(1), FILES);
    std::fs::write(dir.join("src/b.ts"), "export const b = 1").unwrap();
    assert_eq!(
        verify(&dir, "demo").unwrap_err(),
        SignatureError::DigestMismatch
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_signature_by_another_key_over_the_same_digest_is_refused() {
    // The attacker keeps the author's publicKey but signs with their own: the digest still
    // matches the files, and only the verification fails.
    let dir = signed_tree("swapped", "demo", &signer(1), FILES);
    let digest = tree_digest(&dir).unwrap();
    let forged = hex(&signer(2).sign(&message("demo", &digest)).to_bytes());
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(SIGNATURE_FILE)).unwrap()).unwrap();
    file["signature"] = forged.into();
    std::fs::write(dir.join(SIGNATURE_FILE), file.to_string()).unwrap();
    assert_eq!(verify(&dir, "demo").unwrap_err(), SignatureError::Invalid);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_signature_for_another_plugin_cannot_be_reused() {
    let dir = signed_tree("transplant", "other", &signer(1), FILES);
    assert_eq!(
        verify(&dir, "demo").unwrap_err(),
        SignatureError::WrongPlugin("other".to_owned())
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_unreadable_or_future_format_is_refused_rather_than_ignored() {
    let dir = scratch_dir("sign-shape");
    std::fs::write(dir.join("main.ts"), "export default 1").unwrap();

    std::fs::write(dir.join(SIGNATURE_FILE), "not json").unwrap();
    assert!(matches!(
        verify(&dir, "demo").unwrap_err(),
        SignatureError::Malformed(_)
    ));

    write_signature(&dir, "demo", &signer(1));
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(SIGNATURE_FILE)).unwrap()).unwrap();
    file["version"] = 2.into();
    std::fs::write(dir.join(SIGNATURE_FILE), file.to_string()).unwrap();
    assert!(matches!(
        verify(&dir, "demo").unwrap_err(),
        SignatureError::Malformed(_)
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_signature_file_and_git_are_outside_the_digest() {
    // Otherwise the digest could never cover the file that carries it, and a clone would never
    // match a signature made in a working tree.
    let dir = signed_tree("excluded", "demo", &signer(1), FILES);
    let before = tree_digest(&dir).unwrap();
    std::fs::create_dir_all(dir.join(".git/objects")).unwrap();
    std::fs::write(dir.join(".git/objects/x"), "anything").unwrap();
    assert_eq!(tree_digest(&dir).unwrap(), before);
    assert!(verify(&dir, "demo").is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_digest_covers_names_as_well_as_contents() {
    let one = signed_tree("name-a", "demo", &signer(1), &[("a.ts", "x")]);
    let two = signed_tree("name-b", "demo", &signer(1), &[("b.ts", "x")]);
    assert_ne!(tree_digest(&one).unwrap(), tree_digest(&two).unwrap());
    std::fs::remove_dir_all(&one).ok();
    std::fs::remove_dir_all(&two).ok();
}

#[test]
fn a_key_id_is_stable_grouped_and_case_insensitive() {
    let hex = public_hex(&signer(1));
    let id = key_id(&hex);
    assert_eq!(id, key_id(&hex.to_uppercase()));
    assert_eq!(id.len(), 39);
    assert_eq!(id.matches('-').count(), 7);
    assert_ne!(id, key_id(&public_hex(&signer(2))));
}

#[cfg(unix)]
#[test]
fn a_symlink_anywhere_in_the_tree_is_refused() {
    let dir = signed_tree("symlink", "demo", &signer(1), FILES);
    std::os::unix::fs::symlink("/etc/hostname", dir.join("src/link.txt")).unwrap();
    assert_eq!(
        tree_digest(&dir),
        Err(SignatureError::Symlink("src/link.txt".to_owned()))
    );
    std::fs::remove_dir_all(dir).ok();
}
