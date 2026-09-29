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
    /// The member (`.innerHTML`, `.outerHTML`) followed by a single `=` or by `+=`.
    HtmlAssign(&'static str),
    /// A timer (`setTimeout(`, `setInterval(`) whose first argument starts with a quote or
    /// backtick, which the browser evaluates as code.
    StringTimer(&'static str),
    /// `import`, then optional whitespace, then `(`: a dynamic import however it is spaced.
    DynamicImport,
    /// `createElement(` whose argument is a quoted tag that loads or runs code of its own.
    ActiveElement,
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
    rule("sendBeacon", Match::Member("sendBeacon")),
    rule("Worker", Match::Word("Worker")),
    rule("SharedWorker", Match::Word("SharedWorker")),
    rule("importScripts", Match::Word("importScripts")),
    rule("dynamic import", Match::DynamicImport),
    rule("script tag", Match::Anywhere("<script")),
    rule("innerHTML assignment", Match::HtmlAssign(".innerHTML")),
    rule("outerHTML assignment", Match::HtmlAssign(".outerHTML")),
    rule("insertAdjacentHTML", Match::Anywhere("insertAdjacentHTML")),
    rule("srcdoc", Match::Member("srcdoc")),
    rule("createElement of a code-loading tag", Match::ActiveElement),
    rule(
        "setTimeout with a string",
        Match::StringTimer("setTimeout("),
    ),
    rule(
        "setInterval with a string",
        Match::StringTimer("setInterval("),
    ),
    rule("constructor", Match::Anywhere(".constructor")),
    rule("constructor", Match::Anywhere("['constructor']")),
    rule("constructor", Match::Anywhere("[\"constructor\"]")),
    rule("constructor", Match::Anywhere("[`constructor`]")),
    rule("document[", Match::Bare("document[")),
    rule("document.location", Match::Anywhere("document.location")),
    rule("location.href", Match::Bare("location.href")),
    rule("location.assign", Match::Bare("location.assign(")),
    rule("require", Match::Word("require")),
    rule("process", Match::Bare("process.")),
];

/// Tags whose element fetches or runs code by itself once it is in the document, so creating one
/// is a way to the network or to evaluation that `ctx.http` never sees.
const ACTIVE_TAGS: &[&str] = &["script", "iframe", "frame", "object", "embed"];

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
            if (dir == root && is_exempt(&path))
                || is_exempt_path(root, &path)
                || is_test_file(&relative(&path))
            {
                continue;
            }
            out.push(path);
        }
    }
    Ok(())
}

/// Whether a path names a test file by the usual conventions: `a.test.ts`, `a.spec.js`.
///
/// Tests are not scanned: a test that fakes `ctx.http` has to write `fetch`, and a plugin that
/// tests its network path would otherwise be refused for it. They are also never bundled, and
/// that is enforced rather than assumed — [`scan_source`] refuses a file that imports one, and
/// the build refuses a bundle that has one among its inputs.
#[must_use]
pub fn is_test_file(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    let mut parts = name.split('.').skip(1).collect::<Vec<_>>();
    parts.pop();
    parts.iter().any(|part| matches!(*part, "test" | "spec"))
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
        for specifier in specifiers(line) {
            // `./a.test` resolves to `./a.test.ts`, so an extensionless specifier counts too.
            let refused = if is_test_file(specifier) || is_test_file(&format!("{specifier}.ts")) {
                Some("imports a test file")
            } else if escapes_plugin(file, specifier) {
                Some("import outside the plugin")
            } else {
                None
            };
            if let Some(rule) = refused {
                return Err(PolicyError::Violation {
                    file: file.to_owned(),
                    line: index.saturating_add(1),
                    rule,
                });
            }
        }
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

/// The module specifiers on a line: a quoted string right after the word `from` or `import`.
///
/// Covers `import x from './a'`, `import './a'`, `export * from './a'` and the last line of a
/// multi-line import. Dynamic `import(` and `require(` are refused by [`RULES`] already.
fn specifiers(line: &str) -> impl Iterator<Item = &str> {
    ["from", "import"].into_iter().flat_map(move |word| {
        find_all(line, word).filter_map(move |end| {
            if !is_word_at(line, end.saturating_sub(word.len()), end, false) {
                return None;
            }
            let rest = line.get(end..)?.trim_start();
            let quote = rest
                .chars()
                .next()
                .filter(|c| matches!(c, '\'' | '"' | '`'))?;
            rest.get(quote.len_utf8()..)?.split(quote).next()
        })
    })
}

/// Whether `specifier`, imported from the plugin-relative `file`, names something outside the
/// plugin's own directory: an absolute path, a URL-ish scheme the bundler resolves itself, or a
/// relative path with more `..` than the file is deep.
///
/// The build checks what esbuild actually resolved, which is the authority; this refuses the
/// same thing at install time, so a plugin that would never build is never installed.
fn escapes_plugin(file: &str, specifier: &str) -> bool {
    let specifier = specifier.replace('\\', "/");
    let lower = specifier.to_ascii_lowercase();
    if specifier.starts_with('/')
        || lower.starts_with("file:")
        || lower.starts_with("data:")
        || specifier.as_bytes().get(1) == Some(&b':')
    {
        return true;
    }
    if !specifier.starts_with('.') {
        return false;
    }
    let mut depth = file.replace('\\', "/").matches('/').count();
    for segment in specifier.split('/') {
        match segment {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(up) => depth = up,
                None => return true,
            },
            _ => depth = depth.saturating_add(1),
        }
    }
    false
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
        Match::HtmlAssign(member) => find_all(line, member).any(|end| {
            if line
                .get(end..)
                .and_then(|s| s.chars().next())
                .is_some_and(is_ident_char)
            {
                return false;
            }
            let rest = line.get(end..).unwrap_or("").trim_start();
            (rest.starts_with('=') && !rest.starts_with("==")) || rest.starts_with("+=")
        }),
        Match::StringTimer(call) => find_bare(line, call).is_some_and(|end| {
            line.get(end..)
                .unwrap_or("")
                .trim_start()
                .starts_with(['\'', '"', '`'])
        }),
        Match::DynamicImport => find_all(line, "import").any(|end| {
            is_word_at(line, end.saturating_sub("import".len()), end, false)
                && line.get(end..).unwrap_or("").trim_start().starts_with('(')
        }),
        Match::ActiveElement => find_all(line, "createElement(").any(|end| {
            let rest = line.get(end..).unwrap_or("").trim_start();
            let Some(quote) = rest
                .chars()
                .next()
                .filter(|c| matches!(c, '\'' | '"' | '`'))
            else {
                return false;
            };
            let tag = rest
                .get(quote.len_utf8()..)
                .and_then(|inner| inner.split(quote).next())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            ACTIVE_TAGS.contains(&tag.as_str())
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
mod tests;
