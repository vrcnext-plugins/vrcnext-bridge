//! Enforces the same source-size limits the TypeScript side enforces with eslint.
//!
//! Lives in a test rather than a lint because rustc has no `max-lines` equivalent; clippy's
//! `too_many_lines` covers functions, which is why only the file limit is checked here. Walking up
//! to the workspace root means one test covers every crate, including ones added later.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]

use std::path::{Path, PathBuf};

/// Matches the 1000-line ceiling used across these repositories.
const MAX_LINES: usize = 1_000;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <root>/crates/<crate>.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn no_source_file_exceeds_the_line_limit() {
    let root = workspace_root();
    let mut sources = Vec::new();
    rust_sources(&root.join("crates"), &mut sources);

    assert!(!sources.is_empty(), "found no Rust sources to check");

    let oversized: Vec<String> = sources
        .iter()
        .filter_map(|path| {
            let lines = std::fs::read_to_string(path).ok()?.lines().count();
            (lines > MAX_LINES).then(|| {
                let shown = path.strip_prefix(&root).unwrap_or(path);
                format!("{} has {lines} lines", shown.display())
            })
        })
        .collect();

    assert!(
        oversized.is_empty(),
        "source files over {MAX_LINES} lines:\n  {}",
        oversized.join("\n  ")
    );
}
