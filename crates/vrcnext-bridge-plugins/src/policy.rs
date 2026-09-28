//! The source policy: what a plugin's code may not contain.
//!
//! A plugin is compiled into the same bundle as the host and runs with the page's authority.
//! There is no sandbox to put it in, so the next best thing is to refuse, before compiling, the
//! handful of constructs that let code reach past the `ctx.*` API: evaluating strings, touching
//! `window` (by any of its names) or storage directly, opening its own sockets or workers,
//! loading code at runtime. A plugin that
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
/// nothing can be smuggled into the bundle through a name on this list: [`imports_exempt_file`]
/// refuses any source that imports one (in any letter case), and [`json_maps_exempt_file`]
/// refuses a `package.json` or tsconfig that maps a specifier onto one. The bundler has no
/// switch that would do this for us — esbuild's `--external` matches the specifier as written,
/// not the file it resolves to — so these two checks are the whole defence.
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
    /// The identifier as a whole word: not preceded by an identifier character or `.`, and not
    /// followed by an identifier character. Catches `fetch(url)`, `(0, fetch)(url)` and
    /// `const f = fetch`, but not `ctx.http.fetch(` or `prefetch`.
    Word(&'static str),
    /// The identifier as a whole word, even as a member (`self.localStorage`): not glued to an
    /// identifier on either side, but a `.` before it does not excuse it.
    Member(&'static str),
    /// A name that is another spelling of `window` (`top`, `parent`, `frames`), followed by `[`
    /// or by `.` and a member that only the window has. The member list keeps an ordinary local
    /// called `parent` or `top` (`parent.appendChild(li)`) out of it.
    WindowAlias(&'static str),
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
///
/// Globals that give network, storage or code-loading reach are matched as whole words, not as
/// calls, so taking a reference (`const f = fetch`, `(0, eval)(s)`) is refused like calling one;
/// storage is refused even as a member (`self.localStorage`). The other names of the window —
/// `self`, `top`, `parent`, `frames`, `opener`, `defaultView` — are refused as ways around the
/// `window` rule, `top`/`parent`/`frames` only when used like the window so a local variable of
/// that name stays usable. The host's own message table (`__receiveMessageCallbacks`) is never
/// a plugin's to touch.
pub const RULES: &[Rule] = &[
    rule("eval", Match::Word("eval")),
    rule("Function", Match::Word("Function")),
    rule("globalThis", Match::Word("globalThis")),
    rule("window", Match::Word("window")),
    rule("self", Match::Bare("self.")),
    rule("self", Match::Bare("self[")),
    rule("top", Match::WindowAlias("top")),
    rule("parent", Match::WindowAlias("parent")),
    rule("frames", Match::WindowAlias("frames")),
    rule("opener", Match::Word("opener")),
    rule("defaultView", Match::Member("defaultView")),
    rule(
        "__receiveMessageCallbacks",
        Match::Anywhere("__receiveMessageCallbacks"),
    ),
    rule("Reflect.get", Match::Bare("Reflect.get(")),
    rule("document.cookie", Match::Bare("document.cookie")),
    rule("localStorage", Match::Member("localStorage")),
    rule("sessionStorage", Match::Member("sessionStorage")),
    rule("indexedDB", Match::Member("indexedDB")),
    rule("XMLHttpRequest", Match::Word("XMLHttpRequest")),
    rule("fetch", Match::Word("fetch")),
    rule("WebSocket", Match::Word("WebSocket")),
    rule("EventSource", Match::Word("EventSource")),
    rule(
        "navigator.sendBeacon",
        Match::Anywhere("navigator.sendBeacon"),
    ),
    rule("Worker", Match::Word("Worker")),
    rule("SharedWorker", Match::Word("SharedWorker")),
    rule("importScripts", Match::Word("importScripts")),
    rule("dynamic import", Match::Bare("import(")),
    rule("script tag", Match::Anywhere("<script")),
    rule("innerHTML assignment", Match::InnerHtmlAssign),
    rule("insertAdjacentHTML", Match::Anywhere("insertAdjacentHTML")),
    rule("setTimeout with a string", Match::StringTimeout),
    rule("require", Match::Word("require")),
    rule("process", Match::Bare("process.")),
];

/// Members only the window object has, which make `top.x` / `parent.x` / `frames.x` a window
/// access rather than a local variable's.
const WINDOW_MEMBERS: &[&str] = &[
    "window",
    "self",
    "top",
    "parent",
    "frames",
    "opener",
    "document",
    "location",
    "history",
    "navigator",
    "postMessage",
    "globalThis",
    "eval",
    "Function",
    "fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "open",
    "__receiveMessageCallbacks",
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
    let mut manifests = Vec::new();
    collect(root, root, &mut files, &mut manifests)?;
    for path in manifests {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&path).map_err(|_| PolicyError::Io(relative.clone()))?;
        if let Some(line) = json_maps_exempt_file(&relative, &String::from_utf8_lossy(&bytes)) {
            return Err(PolicyError::Violation {
                file: relative,
                line,
                rule: "references a tooling config",
            });
        }
    }
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

/// Walk `dir`, appending source files to `out` and JSON files to `json`. `.git` is skipped: it
/// is not compiled. Symlinks are refused outright rather than followed, so nothing outside the
/// clone can be read or bundled.
fn collect(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
    json: &mut Vec<PathBuf>,
) -> Result<(), PolicyError> {
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
            collect(root, &path, out, json)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            json.push(path);
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
///
/// Only a quoted module specifier counts. Naming an exempt file in prose has to stay allowed:
/// the signing tool is the thing every plugin's own comments and README tell an author to run,
/// and a policy that refused a repository for explaining itself would be absurd.
fn imports_exempt_file(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    exempt_names().find(|name| is_specifier(&lower, name))
}

/// Every exempt file by its bare name, which is what a specifier or a mapping ends in.
fn exempt_names() -> impl Iterator<Item = &'static str> {
    EXEMPT_ROOT_FILES
        .iter()
        .chain(EXEMPT_PATHS)
        .map(|path| path.rsplit('/').next().unwrap_or(path))
}

/// Whether `name` appears in `text` as the tail of a quoted module specifier.
///
/// A specifier is delimited: the name ends at the closing quote, and walking left over the path
/// characters that can precede it (`./`, `../`, directories) must arrive at the opening one.
/// Dynamic `import(` and `require(` are refused by [`RULES`] anyway, so a static specifier is
/// the only way an exempt file could reach the bundle. `text` is expected lowercased: a
/// case-insensitive filesystem resolves `./ESLint.Config.mjs` to the exempt file too.
fn is_specifier(text: &str, name: &str) -> bool {
    const QUOTES: [char; 3] = ['\'', '"', '`'];
    text.match_indices(name).any(|(at, _)| {
        let after = text[at.saturating_add(name.len())..].chars().next();
        if !after.is_some_and(|c| QUOTES.contains(&c)) {
            return false;
        }
        let before = text[..at].trim_end_matches(|c: char| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '\\' | '-' | '_' | '@')
        });
        before.ends_with(QUOTES)
    })
}

/// The 1-based line on which a JSON file names an exempt file where a resolver would read it.
///
/// A specifier is not the only route into the bundle: a `package.json` `imports` or `browser`
/// map, or a tsconfig `paths` entry, can point an innocent-looking specifier at an exempt file.
/// Rather than track which fields each resolver honours, every JSON file is refused if it names
/// one, case-insensitively, anywhere — except a `package.json`'s `scripts`, which run commands
/// and resolve nothing, and are where the signing tool is legitimately invoked from. A file that
/// does not parse (a tsconfig with comments, say) is searched as plain text, with no exception.
fn json_maps_exempt_file(relative: &str, text: &str) -> Option<usize> {
    let is_package = relative.rsplit('/').next() == Some("package.json");
    let searched = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(mut value) => {
            if is_package && let Some(object) = value.as_object_mut() {
                object.remove("scripts");
            }
            value.to_string()
        }
        Err(_) => text.to_owned(),
    }
    .to_ascii_lowercase();
    let found = exempt_names().find(|name| searched.contains(name))?;
    // A mapping names the file as a whole string, so prefer the line where it closes one; a
    // `scripts` command mentioning it mid-string is not the line to point at.
    let lines: Vec<String> = text.lines().map(str::to_ascii_lowercase).collect();
    let quoted = format!("{found}\"");
    let line = lines
        .iter()
        .position(|line| line.contains(&quoted))
        .or_else(|| lines.iter().position(|line| line.contains(found)));
    Some(line.map_or(1, |index| index + 1))
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
        Match::Word(word) => find_word(line, word, false).is_some(),
        Match::Member(word) => find_word(line, word, true).is_some(),
        Match::WindowAlias(name) => find_all(line, name).any(|end| {
            if !is_word_at(line, end.saturating_sub(name.len()), end, false) {
                return false;
            }
            let rest = line.get(end..).unwrap_or("").trim_start();
            if rest.starts_with('[') {
                return true;
            }
            rest.strip_prefix('.').is_some_and(|rest| {
                let member: &str = rest.split(|c: char| !is_ident_char(c)).next().unwrap_or("");
                WINDOW_MEMBERS.contains(&member)
            })
        }),
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

/// Byte offset just past the first whole-word occurrence of `word`. With `after_dot`, a `.`
/// before it does not disqualify it.
fn find_word(line: &str, word: &str, after_dot: bool) -> Option<usize> {
    find_all(line, word)
        .find(|&end| is_word_at(line, end.saturating_sub(word.len()), end, after_dot))
}

/// Whether `line[start..end]` stands alone: no identifier character on either side, and no `.`
/// before it unless `after_dot`.
fn is_word_at(line: &str, start: usize, end: usize, after_dot: bool) -> bool {
    let before = line.get(..start).and_then(|s| s.chars().next_back());
    let after = line.get(end..).and_then(|s| s.chars().next());
    !before.is_some_and(|c| is_ident_char(c) || (!after_dot && c == '.'))
        && !after.is_some_and(is_ident_char)
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$')
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
        assert_eq!(hit("(0, eval)(s)"), "eval");
        clean("retrieval(x)");
        clean("const evaluation = 1");
    }

    #[test]
    fn rule_function() {
        assert_eq!(hit("const f = new Function('a', 'return a')"), "Function");
        assert_eq!(hit("const F = Function; F('return 1')"), "Function");
        clean("export function f() {}");
        clean("const Functional = 1");
    }

    #[test]
    fn rule_self() {
        assert_eq!(hit("self.postMessage(x)"), "self");
        assert_eq!(hit("self['fetch'](u)"), "self");
        clean("const me = self()?.id");
        clean("this.self.x");
    }

    #[test]
    fn rule_window_aliases() {
        assert_eq!(hit("top.location.href = u"), "top");
        assert_eq!(hit("parent.postMessage(m, '*')"), "parent");
        assert_eq!(hit("parent['document']"), "parent");
        assert_eq!(hit("frames.window.x"), "frames");
        clean("parent.appendChild(li)");
        clean("const top = rect.top; top.toFixed(1)");
        clean("style.top = '3px'");
    }

    #[test]
    fn rule_opener() {
        assert_eq!(hit("const w = opener"), "opener");
        clean("ctx.opener()");
    }

    #[test]
    fn rule_default_view() {
        assert_eq!(hit("el.ownerDocument.defaultView.fetch(u)"), "defaultView");
    }

    #[test]
    fn rule_receive_message_callbacks() {
        assert_eq!(
            hit("x.__receiveMessageCallbacks.push(f)"),
            "__receiveMessageCallbacks"
        );
    }

    #[test]
    fn rule_reflect_get() {
        assert_eq!(hit("Reflect.get(o, 'fetch')"), "Reflect.get");
    }

    #[test]
    fn rule_event_source() {
        assert_eq!(hit("new EventSource('/s')"), "EventSource");
    }

    #[test]
    fn rule_send_beacon() {
        assert_eq!(hit("navigator.sendBeacon(u, d)"), "navigator.sendBeacon");
    }

    #[test]
    fn rule_workers() {
        assert_eq!(hit("new Worker(url)"), "Worker");
        assert_eq!(hit("new SharedWorker(url)"), "SharedWorker");
        assert_eq!(hit("importScripts(u)"), "importScripts");
        clean("const ServiceWorkerish = 1");
    }

    #[test]
    fn rule_global_this() {
        assert_eq!(hit("globalThis.foo = 1"), "globalThis");
        assert_eq!(hit("globalThis['fe' + 'tch'](u)"), "globalThis");
        assert_eq!(hit("const g = globalThis"), "globalThis");
    }

    #[test]
    fn rule_window() {
        assert_eq!(hit("const h = window.location.href"), "window");
        assert_eq!(hit("const w = window; w['fetch'](u)"), "window");
        clean("ctx.window.open()");
        clean("const windowSize = 3");
    }

    #[test]
    fn rule_document_cookie() {
        assert_eq!(hit("document.cookie = 'a=b'"), "document.cookie");
    }

    #[test]
    fn rule_local_storage() {
        assert_eq!(hit("localStorage.setItem('a', 'b')"), "localStorage");
        assert_eq!(hit("const s = globalObj.localStorage"), "localStorage");
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
        assert_eq!(hit("await fetch('https://x')"), "fetch");
        assert_eq!(hit("(0, fetch)(url)"), "fetch");
        assert_eq!(hit("const f = fetch"), "fetch");
        clean("await ctx.http.fetch('https://x')");
        clean("prefetch(url)");
        clean("fetchStars(ctx)");
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
        assert_eq!(hit("const r = require"), "require");
        clean("const required = true");
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

        // Importing an exempt file would bundle it unscanned, so that is refused, in any case.
        for import in [
            "import './eslint.config.mjs';",
            "import './ESLint.Config.MJS';",
        ] {
            std::fs::write(dir.join("main.ts"), import).unwrap();
            assert!(matches!(
                scan_tree(&dir).unwrap_err(),
                PolicyError::Violation {
                    rule: "references a tooling config",
                    ..
                }
            ));
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_resolver_mapping_cannot_point_at_an_exempt_file() {
        let dir = scratch_dir("policy-mapping");
        std::fs::write(dir.join("main.ts"), "import { a } from '#x';").unwrap();
        std::fs::write(dir.join("eslint.config.mjs"), "export const a = 1;").unwrap();
        // Running the signing tool from `scripts` is how every plugin is meant to sign itself.
        std::fs::write(
            dir.join("package.json"),
            r#"{"scripts":{"sign":"node scripts/sign-plugin.mjs sign"}}"#,
        )
        .unwrap();
        scan_tree(&dir).unwrap();

        for (file, json) in [
            (
                "package.json",
                r##"{"imports":{"#x":"./ESLINT.config.mjs"}}"##,
            ),
            (
                "package.json",
                r#"{"browser":{"./y.js":"./eslint.config.mjs"}}"#,
            ),
            (
                "src/package.json",
                r#"{"alias":{"y":"../eslint.config.mjs"}}"#,
            ),
            (
                "tsconfig.json",
                "{\n  // paths\n  \"compilerOptions\": {\"paths\": {\"x\": [\"./eslint.config.mjs\"]}}\n}",
            ),
        ] {
            std::fs::remove_file(dir.join("package.json")).ok();
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join(file), json).unwrap();
            let error = scan_tree(&dir).unwrap_err();
            assert!(
                matches!(
                    error,
                    PolicyError::Violation {
                        rule: "references a tooling config",
                        ..
                    }
                ),
                "{file}: {json} -> {error:?}"
            );
            std::fs::remove_file(dir.join(file)).unwrap();
        }
        std::fs::remove_dir_all(dir).ok();
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

        // Naming it in prose is not importing it, and every plugin's comments will do exactly
        // that — telling the author to run it is the whole point of shipping it.
        std::fs::write(
            dir.join("main.ts"),
            "// Sign before pushing: node scripts/sign-plugin.mjs sign\nexport default 1;",
        )
        .unwrap();
        scan_tree(&dir).unwrap();

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
