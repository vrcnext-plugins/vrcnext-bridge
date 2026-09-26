//! The pairing token: the one secret that ties the page to this user's bridge.
//!
//! Generated on first run, never chosen by a human, and readable only by the account that runs
//! the daemon. The page learns it once — the user pastes it from the banner or the installer's
//! output — and presents it in every `hello` and every bearer header. Anything that can read the
//! file already runs as this user, so the token adds nothing against that caller and everything
//! against a page or a process that does not.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

/// Bytes of entropy. 256 bits is more than the transport around it will ever justify.
const TOKEN_BYTES: usize = 32;

/// Characters in a valid token: base64url of [`TOKEN_BYTES`] without padding.
const TOKEN_CHARS: usize = 43;

/// Read the token, generating one first if the file does not exist.
///
/// # Errors
///
/// Fails if the file exists but is unreadable or malformed, or cannot be created.
pub(crate) fn load_or_create(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let token = text.trim();
            if !is_token(token) {
                bail!(
                    "{} does not contain a token; delete it or run --rotate-token",
                    path.display()
                );
            }
            Ok(token.to_owned())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let token = rotate(path)?;
            log::info!("generated a new pairing token at {}", path.display());
            Ok(token)
        }
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Generate a fresh token and write it, replacing any previous one.
///
/// The file is created `0600` from the moment it exists, never widened and then tightened. It
/// is written to a sibling temp file and renamed so a crash mid-write cannot leave a half token
/// that the next start would refuse.
///
/// # Errors
///
/// Fails if the OS cannot supply randomness or the file cannot be written.
pub(crate) fn rotate(path: &Path) -> Result<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).context("the OS could not supply random bytes")?;
    let token = base64url(&bytes);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let temp = path.with_extension("tmp");
    {
        let mut file =
            open_private(&temp).with_context(|| format!("cannot create {}", temp.display()))?;
        file.write_all(token.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", temp.display()))?;
    }
    std::fs::rename(&temp, path)
        .with_context(|| format!("cannot move the token into {}", path.display()))?;
    Ok(token)
}

/// Whether `candidate` has the shape [`rotate`] produces. Guards against a stray file at the
/// token path being silently accepted as a credential.
fn is_token(candidate: &str) -> bool {
    candidate.len() == TOKEN_CHARS
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    // Windows has no mode bits; %LOCALAPPDATA% is already per-user and not readable by others.
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
}

/// Unpadded base64url. Hand-rolled rather than a dependency: it is twenty lines, used once.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut buffer = [0_u8; 3];
        for (slot, byte) in buffer.iter_mut().zip(chunk) {
            *slot = *byte;
        }
        let triple = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            let shift = 18 - 6 * index;
            let sextet = (triple >> shift) & 0x3f;
            // `sextet` is six bits, so it always indexes the 64-entry alphabet.
            out.push(char::from(
                ALPHABET.get(sextet as usize).copied().unwrap_or(b'A'),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use super::{base64url, is_token, load_or_create, rotate};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vrcnext-token-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("token")
    }

    #[test]
    fn base64url_matches_the_rfc_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_");
    }

    #[test]
    fn a_token_is_generated_once_and_then_reused() {
        let path = scratch("reuse");
        let first = load_or_create(&path).expect("created");
        let second = load_or_create(&path).expect("read back");
        assert_eq!(first, second);
        assert!(is_token(&first), "{first}");
        assert_ne!(rotate(&path).expect("rotated"), first);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn a_malformed_token_file_is_refused_rather_than_trusted() {
        let path = scratch("bad");
        std::fs::write(&path, "hello\n").unwrap();
        assert!(load_or_create(&path).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = scratch("mode");
        rotate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode was {mode:o}");
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
