#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
//! One test per rule, each paired with the honest code nearest to it — a rule that refuses real
//! source is worse than no rule, so every case here says what is allowed as well as what is not.

use super::{MAX_LINE_CHARS, MIN_BLOB_CHARS, entropy, scan};
use crate::policy::PolicyError;

/// The rule a scan refused on, or `None` if it passed.
fn refused(text: &str) -> Option<&'static str> {
    match scan("src/a.ts", text) {
        Ok(()) => None,
        Err(PolicyError::Violation { rule, .. }) => Some(rule),
        Err(other) => panic!("unexpected {other:?}"),
    }
}

/// A pseudo-random base64-ish run, deterministic so the test never flakes.
fn blob(length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(ALPHABET[(state % 64) as usize])
        })
        .collect()
}

#[test]
fn ordinary_source_passes() {
    let text = "import { thing } from './thing.js';\n\
                \n\
                /** A comment that is long enough to be a real sentence about the code below. */\n\
                export function greet(name: string): string {\n\
                  return `hello ${name}, welcome to the instance`;\n\
                }\n";
    assert_eq!(refused(text), None);
}

#[test]
fn a_minified_line_is_refused_and_a_merely_long_one_is_not() {
    let long = format!("const url = '{}';", "a".repeat(MAX_LINE_CHARS - 50));
    assert_eq!(refused(&long), None, "a long but human line is fine");

    let minified = format!("const x = '{}';", "a".repeat(MAX_LINE_CHARS + 1));
    assert_eq!(refused(&minified), Some("minified"));
}

#[test]
fn a_wrapped_bundle_is_refused_by_its_mean_line() {
    // Every line is under the single-line limit; the file is still plainly generated.
    let line = format!("{};\n", "x".repeat(400));
    assert_eq!(refused(&line.repeat(25)), Some("packed source"));

    // A short file of the same lines says nothing, so it is left alone.
    assert_eq!(refused(&line.repeat(3)), None);
}

#[test]
fn a_run_of_escapes_is_refused_and_a_few_are_not() {
    assert_eq!(refused(r"const nl = '\x0a\x0d';"), None);
    assert_eq!(refused(r"const accents = '\u00e9\u00e8\u00ea';"), None);
    assert_eq!(
        refused(r"const f = this['\x65\x76\x61\x6c\x5f\x66\x6e\x5f\x78'];"),
        Some("escape sequences"),
    );
}

#[test]
fn the_obfuscator_signature_is_refused() {
    assert_eq!(
        refused("const a = _0x3a2b[17];"),
        Some("mangled identifiers")
    );
    assert_eq!(
        refused("function _0xabcdef(){}"),
        Some("mangled identifiers")
    );
    // Names that merely start the same way are ordinary.
    assert_eq!(refused("const _0xy = 1; const _private = 2;"), None);
    assert_eq!(refused("const offset_0x = 1;"), None);
}

#[test]
fn a_long_high_entropy_token_is_refused() {
    assert_eq!(
        refused(&format!("const payload = '{}';", blob(MIN_BLOB_CHARS))),
        Some("opaque blob"),
    );
}

#[test]
fn hashes_urls_and_long_names_are_not_blobs() {
    // A sha-256 is 64 characters: far under the length that makes a run suspicious.
    assert_eq!(
        refused("const sha = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';"),
        None,
    );
    // A URL is broken up by dots and slashes, so no single run gets long.
    assert_eq!(
        refused(&format!(
            "const u = 'https://example.com/{}/{}';",
            blob(80),
            blob(80)
        )),
        None,
    );
    // A long run of low entropy is filler or a name, not data.
    assert_eq!(
        refused(&format!("const x = '{}';", "ab".repeat(MIN_BLOB_CHARS))),
        None,
    );
}

#[test]
fn invisible_and_bidirectional_characters_are_refused() {
    assert_eq!(
        refused("const admin\u{200b}Check = false;"),
        Some("invisible characters"),
    );
    assert_eq!(
        refused("if (user.isAdmin) { /*\u{202e} } \u{2066}*/ grant(); }"),
        Some("invisible characters"),
    );
    // A byte-order mark at the start of the file is ordinary.
    assert_eq!(refused("\u{feff}export default 1;\n"), None);
    // Anywhere else it is not.
    assert_eq!(
        refused("export default 1;\nconst a\u{feff}b = 2;\n"),
        Some("invisible characters"),
    );
}

#[test]
fn the_line_reported_is_the_offending_one() {
    let text = "const a = 1;\nconst b = 2;\nconst c = _0xdead[0];\n";
    match scan("src/a.ts", text) {
        Err(PolicyError::Violation { file, line, rule }) => {
            assert_eq!(
                (file.as_str(), line, rule),
                ("src/a.ts", 3, "mangled identifiers")
            );
        }
        other => panic!("expected a violation, got {other:?}"),
    }
}

#[test]
fn entropy_is_zero_for_one_symbol_and_maximal_for_a_uniform_alphabet() {
    assert!(entropy("aaaaaaaa").abs() < 1e-9);
    // Sixteen symbols used equally often: exactly four bits each.
    let hex: String = "0123456789abcdef".repeat(4);
    assert!((entropy(&hex) - 4.0).abs() < 1e-9, "{}", entropy(&hex));
    assert!(entropy("").abs() < 1e-9);
}
