//! The source policy: what a plugin's code may not contain.
//!
//! A plugin is compiled into the same bundle as the host and runs with the page's authority.
//! There is no sandbox to put it in, so the next best thing is to refuse, before compiling, the
//! handful of constructs that let code reach past the `ctx.*` API: evaluating strings, touching
//! `window` or storage directly, opening its own sockets, loading code at runtime. A plugin that
//! needs the network uses `ctx.http.fetch`, which the permission gate can see.
//!
//! This is a text scan, not a parser. It is meant to catch honest mistakes and make dishonest
//! ones obvious in a review, not to be unbypassable; the docs say so. The rules live in one
//! table, [`RULES`], mirrored in the documentation, with one unit test each.
//!
//! A table of names only works on code a person could have read, so every file goes through
//! [`crate::obfuscation`] first: source shaped like a bundle, an escape sequence or a payload is
//! refused before the names are looked for, because otherwise the names would not be there.

use std::path::{Path, PathBuf};

/// Most source files a plugin may contain.
pub const MAX_SOURCE_FILES: usize = 200;

/// Most bytes of source a plugin may contain, in total.
pub const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

/// File extensions that are scanned. Broader than `.ts`/`.js` because esbuild resolves all of
/// them, and a rule that only looked at `.ts` would be bypassed by renaming a file.
const SOURCE_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/// Tooling configs at the repository root, which the bundler never reaches and this daemon
/// never executes.
///
/// They are exempt because their whole job is to *name* the things the rules below ban: a lint
/// config that forbids `localStorage` has to write the word down, and refusing the file that
/// enforces the policy would be absurd. The exemption is narrow — exact names, root only — and
/// [`imports_exempt_file`] refuses any source that imports one, so nothing can be smuggled into
/// the bundle through a name on this list.
const EXEMPT_ROOT_FILES: &[&str] = &[
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "vitest.config.ts",
    "vitest.config.js",
    "vitest.config.mts",
];

/// Exempt files that are not at the root, by exact relative path.
///
/// One entry, for the same reason as [`EXEMPT_ROOT_FILES`] and with the same narrowness: the
/// signing tool every plugin repository carries runs under Node at release time, never in the
/// page, and it has to say `process` and `Buffer` to do its job. It is never imported — nothing
/// in a bundle could use it — and [`imports_exempt_file`] refuses any source that names it.
const EXEMPT_PATHS: &[&str] = &["scripts/sign-plugin.mjs"];

/// How a rule is matched.
#[derive(Debug, Clone, Copy)]
enum Match {
    /// The text, preceded by something that is not an identifier character or `.`. Catches
    /// `fetch(` but not `ctx.http.fetch(` or `prefetch(`.
    Bare(&'static str),
    /// The text anywhere.
    Anywhere(&'static str),
    /// `.innerHTML` followed by a single `=`.
    InnerHtmlAssign,
    /// `setTimeout(` whose first argument starts with a quote or backtick.
    StringTimeout,
}

/// One rule: what to look for and what to call it in the refusal.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// The name reported in `policy: file:line rule`.
    pub name: &'static str,
    matcher: Match,
}

/// The policy. Order is the order of the docs.
pub const RULES: &[Rule] = &[
    rule("eval", Match::Bare("eval(")),
    rule("new Function", Match::Bare("new Function")),
    rule("globalThis", Match::Bare("globalThis.")),
    rule("window", Match::Bare("window.")),
    rule("document.cookie", Match::Bare("document.cookie")),
    rule("localStorage", Match::Bare("localStorage")),
    rule("sessionStorage", Match::Bare("sessionStorage")),
    rule("indexedDB", Match::Bare("indexedDB")),
    rule("XMLHttpRequest", Match::Bare("XMLHttpRequest")),
    rule("bare fetch", Match::Bare("fetch(")),
    rule("WebSocket", Match::Bare("WebSocket(")),
    rule("dynamic import", Match::Bare("import(")),
    rule("script tag", Match::Anywhere("<script")),
    rule("innerHTML assignment", Match::InnerHtmlAssign),
    rule("insertAdjacentHTML", Match::Anywhere("insertAdjacentHTML")),
    rule("setTimeout with a string", Match::StringTimeout),
    rule("require", Match::Bare("require(")),
    rule("process", Match::Bare("process.")),
];

const fn rule(name: &'static str, matcher: Match) -> Rule {
    Rule { name, matcher }
}

/// Why a plugin's source was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// A rule matched. Formatted exactly as the `policy:` error prefix wants it.
    #[error("{file}:{line} {rule}")]
    Violation {
        /// Path relative to the plugin root.
        file: String,
        /// 1-based.
        line: usize,
        /// The rule's name.
        rule: &'static str,
    },
    /// More than [`MAX_SOURCE_FILES`] source files.
    #[error("more than {MAX_SOURCE_FILES} source files")]
    TooManyFiles,
    /// More than [`MAX_SOURCE_BYTES`] bytes of source.
    #[error("more than {MAX_SOURCE_BYTES} bytes of source")]
    TooLarge,
    /// A symlink, which could point outside the clone.
    #[error("{0} is a symlink")]
    Symlink(String),
    /// Could not read the tree.
    #[error("cannot read {0}")]
    Io(String),
}

/// Scan every source file under `root`.
///
/// # Errors
///
/// The first [`PolicyError`] found. Files are visited in sorted order so the answer is stable.
pub fn scan_tree(root: &Path) -> Result<(), PolicyError> {
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    if files.len() > MAX_SOURCE_FILES {
        return Err(PolicyError::TooManyFiles);
    }
    let mut total: u64 = 0;
    for path in files {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&path).map_err(|_| PolicyError::Io(relative.clone()))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > MAX_SOURCE_BYTES {
            return Err(PolicyError::TooLarge);
        }
        let text = String::from_utf8_lossy(&bytes);
        if let Some(name) = imports_exempt_file(&text) {
            return Err(PolicyError::Violation {
                file: relative.clone(),
                line: text
                    .lines()
                    .position(|line| line.contains(name))
                    .map_or(1, |index| index + 1),
                rule: "references a tooling config",
            });
        }
        scan_source(&relative, &text)?;
    }
    Ok(())
}

/// Walk `dir`, appending source files. `.git` is skipped: it is not compiled. Symlinks are
/// refused outright rather than followed, so nothing outside the clone can be read or bundled.
fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PolicyError> {
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned()
    };
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|_| PolicyError::Io(relative(dir)))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        let meta =
            std::fs::symlink_metadata(&path).map_err(|_| PolicyError::Io(relative(&path)))?;
        if meta.file_type().is_symlink() {
            return Err(PolicyError::Symlink(relative(&path)));
        }
        if meta.is_dir() {
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            collect(root, &path, out)?;
        } else if is_source(&path) {
            if (dir == root && is_exempt(&path)) || is_exempt_path(root, &path) {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

fn is_source(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| SOURCE_EXTENSIONS.contains(&ext))
}

/// Whether this is one of the root tooling configs the scan skips.
fn is_exempt(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| EXEMPT_ROOT_FILES.contains(&name))
}

/// Whether this is one of the exempt files below the root, by exact relative path.
fn is_exempt_path(root: &Path, path: &Path) -> bool {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    EXEMPT_PATHS.contains(&relative.as_str())
}

/// Whether `text` imports one of the exempt files, which would pull it into the bundle unscanned.
fn imports_exempt_file(text: &str) -> Option<&'static str> {
    EXEMPT_ROOT_FILES
        .iter()
        .chain(EXEMPT_PATHS)
        .copied()
        .find(|name| text.contains(name))
}

/// Scan one file's text.
///
/// # Errors
///
/// The first violation, with its 1-based line.
pub fn scan_source(file: &str, text: &str) -> Result<(), PolicyError> {
    // Shape before names: a minified or escaped file would pass every rule below by hiding the
    // words they look for, so it never reaches them.
    crate::obfuscation::scan(file, text)?;
    for (index, line) in text.lines().enumerate() {
        for rule in RULES {
            if matches(rule.matcher, line) {
                return Err(PolicyError::Violation {
                    file: file.to_owned(),
                    line: index.saturating_add(1),
                    rule: rule.name,
                });
            }
        }
    }
    Ok(())
}

fn matches(matcher: Match, line: &str) -> bool {
    match matcher {
        Match::Anywhere(needle) => line.contains(needle),
        Match::Bare(needle) => find_bare(line, needle).is_some(),
        Match::InnerHtmlAssign => find_all(line, ".innerHTML").any(|end| {
            let rest = line.get(end..).unwrap_or("").trim_start();
            rest.starts_with('=') && !rest.starts_with("==")
        }),
        Match::StringTimeout => find_bare(line, "setTimeout(").is_some_and(|end| {
            line.get(end..)
                .unwrap_or("")
                .trim_start()
                .starts_with(['\'', '"', '`'])
        }),
    }
}

/// Byte offset just past the first occurrence of `needle` that is not glued to an identifier
/// or a member access on its left.
fn find_bare(line: &str, needle: &str) -> Option<usize> {
    find_all(line, needle).find(|&end| {
        let start = end.saturating_sub(needle.len());
        let before = line.get(..start).and_then(|s| s.chars().next_back());
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '.'))
    })
}

/// End offsets of every occurrence of `needle`.
fn find_all<'a>(line: &'a str, needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        let found = line.get(from..)?.find(needle)?;
        let end = from.saturating_add(found).saturating_add(needle.len());
        from = end;
        Some(end)
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        reason = "a failing assertion is how a test reports; panicking here is the point"
    )]
    use super::{PolicyError, scan_source, scan_tree};
    use crate::fsutil::scratch_dir;

    fn hit(text: &str) -> &'static str {
        match scan_source("main.ts", text) {
            Err(PolicyError::Violation { rule, line, .. }) => {
                assert_eq!(line, 1);
                rule
            }
            other => panic!("expected a violation for {text:?}, got {other:?}"),
        }
    }

    fn clean(text: &str) {
        assert_eq!(scan_source("main.ts", text), Ok(()), "{text:?}");
    }

    #[test]
    fn rule_eval() {
        assert_eq!(hit("eval('1')"), "eval");
        clean("retrieval(x)");
    }

    #[test]
    fn rule_new_function() {
        assert_eq!(
            hit("const f = new Function('a', 'return a')"),
            "new Function"
        );
    }

    #[test]
    fn rule_global_this() {
        assert_eq!(hit("globalThis.foo = 1"), "globalThis");
    }

    #[test]
    fn rule_window() {
        assert_eq!(hit("const h = window.location.href"), "window");
        clean("ctx.window.open()");
    }

    #[test]
    fn rule_document_cookie() {
        assert_eq!(hit("document.cookie = 'a=b'"), "document.cookie");
    }

    #[test]
    fn rule_local_storage() {
        assert_eq!(hit("localStorage.setItem('a', 'b')"), "localStorage");
    }

    #[test]
    fn rule_session_storage() {
        assert_eq!(hit("sessionStorage.clear()"), "sessionStorage");
    }

    #[test]
    fn rule_indexed_db() {
        assert_eq!(hit("indexedDB.open('x')"), "indexedDB");
    }

    #[test]
    fn rule_xml_http_request() {
        assert_eq!(hit("new XMLHttpRequest()"), "XMLHttpRequest");
    }

    #[test]
    fn rule_bare_fetch() {
        assert_eq!(hit("await fetch('https://x')"), "bare fetch");
        clean("await ctx.http.fetch('https://x')");
        clean("prefetch(url)");
    }

    #[test]
    fn rule_web_socket() {
        assert_eq!(hit("new WebSocket('ws://x')"), "WebSocket");
    }

    #[test]
    fn rule_dynamic_import() {
        assert_eq!(hit("const m = await import('./x')"), "dynamic import");
        clean("import { a } from './x'");
    }

    #[test]
    fn rule_script_tag() {
        assert_eq!(hit("el.innerText = '<script>'"), "script tag");
    }

    #[test]
    fn rule_inner_html_assignment() {
        assert_eq!(hit("el.innerHTML = html"), "innerHTML assignment");
        assert_eq!(hit("el.innerHTML=html"), "innerHTML assignment");
        clean("if (el.innerHTML === '') {}");
        clean("const s = el.innerHTML");
    }

    #[test]
    fn rule_insert_adjacent_html() {
        assert_eq!(
            hit("el.insertAdjacentHTML('beforeend', s)"),
            "insertAdjacentHTML"
        );
    }

    #[test]
    fn rule_set_timeout_with_a_string() {
        assert_eq!(
            hit("setTimeout('alert(1)', 10)"),
            "setTimeout with a string"
        );
        assert_eq!(hit("setTimeout( `x`, 10)"), "setTimeout with a string");
        clean("setTimeout(() => tick(), 10)");
    }

    #[test]
    fn rule_require() {
        assert_eq!(hit("const fs = require('fs')"), "require");
    }

    #[test]
    fn rule_process() {
        assert_eq!(hit("process.env.HOME"), "process");
        clean("ctx.process.list()");
    }

    #[test]
    fn violations_carry_the_file_and_line() {
        let err = scan_source("src/a.ts", "ok\nok\neval(x)").unwrap_err();
        assert_eq!(err.to_string(), "src/a.ts:3 eval");
    }

    #[test]
    fn root_tooling_configs_are_exempt_but_cannot_be_imported() {
        let dir = scratch_dir("policy-exempt");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("main.ts"), "export default 1;").unwrap();
        // The lint config has to name what it bans; that must not be a violation.
        std::fs::write(
            dir.join("eslint.config.mjs"),
            "export default [{ rules: { 'no-restricted-globals': ['error', 'localStorage', 'eval'] } }];",
        )
        .unwrap();
        scan_tree(&dir).unwrap();

        // The same name one directory down is ordinary source and is scanned.
        std::fs::write(dir.join("src/eslint.config.mjs"), "localStorage.x").unwrap();
        assert!(matches!(
            scan_tree(&dir).unwrap_err(),
            PolicyError::Violation {
                rule: "localStorage",
                ..
            }
        ));
        std::fs::remove_file(dir.join("src/eslint.config.mjs")).unwrap();

        // Importing an exempt file would bundle it unscanned, so that is refused.
        std::fs::write(dir.join("main.ts"), "import './eslint.config.mjs';").unwrap();
        assert!(matches!(
            scan_tree(&dir).unwrap_err(),
            PolicyError::Violation {
                rule: "references a tooling config",
                ..
            }
        ));
    }

    #[test]
    fn the_signing_tool_is_exempt_at_its_one_path_and_nowhere_else() {
        let dir = scratch_dir("policy-signer");
        std::fs::create_dir_all(dir.join("scripts")).unwrap();
        std::fs::write(dir.join("main.ts"), "export default 1;").unwrap();
        // It runs under Node at release time and has to name `process`; the page never sees it.
        std::fs::write(
            dir.join("scripts/sign-plugin.mjs"),
            "process.stdout.write(Buffer.from('x').toString('hex'));",
        )
        .unwrap();
        scan_tree(&dir).unwrap();

        // Any other file under scripts/ is ordinary source.
        std::fs::write(dir.join("scripts/other.mjs"), "process.exit(0)").unwrap();
        let error = scan_tree(&dir).unwrap_err();
        assert_eq!(
            error.to_string(),
            "scripts/other.mjs:1 process",
            "{error:?}"
        );
        std::fs::remove_file(dir.join("scripts/other.mjs")).unwrap();

        // And importing the signer is refused, so it cannot be smuggled into the bundle.
        std::fs::write(dir.join("main.ts"), "import './scripts/sign-plugin.mjs';").unwrap();
        assert!(matches!(
            scan_tree(&dir).unwrap_err(),
            PolicyError::Violation {
                rule: "references a tooling config",
                ..
            }
        ));
    }

    #[test]
    fn the_tree_scan_skips_git_and_refuses_symlinks() {
        let dir = scratch_dir("policy-tree");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/hook.js"), "eval(x)").unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/b.tsx"), "clean").unwrap();
        std::fs::write(dir.join("main.ts"), "clean").unwrap();
        std::fs::write(dir.join("README.md"), "eval( in prose is fine").unwrap();
        assert_eq!(scan_tree(&dir), Ok(()));

        std::fs::write(dir.join("src/c.js"), "window.x").unwrap();
        assert_eq!(
            scan_tree(&dir),
            Err(PolicyError::Violation {
                file: "src/c.js".to_owned(),
                line: 1,
                rule: "window",
            })
        );
        std::fs::remove_file(dir.join("src/c.js")).unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", dir.join("link.ts")).unwrap();
            assert!(matches!(scan_tree(&dir), Err(PolicyError::Symlink(_))));
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_tree_scan_bounds_file_count_and_size() {
        let dir = scratch_dir("policy-bounds");
        for i in 0..=super::MAX_SOURCE_FILES {
            std::fs::write(dir.join(format!("f{i}.ts")), "x").unwrap();
        }
        assert_eq!(scan_tree(&dir), Err(PolicyError::TooManyFiles));
        std::fs::remove_dir_all(&dir).ok();

        let dir = scratch_dir("policy-size");
        // Ordinary-looking lines, so the size limit is what refuses this and not the shape rules.
        let line = format!("{};\n", "x".repeat(99));
        let mut big = String::new();
        while u64::try_from(big.len()).unwrap() <= super::MAX_SOURCE_BYTES {
            big.push_str(&line);
        }
        std::fs::write(dir.join("a.ts"), &big).unwrap();
        std::fs::write(dir.join("b.ts"), "y").unwrap();
        assert_eq!(scan_tree(&dir), Err(PolicyError::TooLarge));
        std::fs::remove_dir_all(dir).ok();
    }
}
