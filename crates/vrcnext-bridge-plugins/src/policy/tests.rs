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
    assert_eq!(hit("navigator.sendBeacon(u, d)"), "sendBeacon");
    // Through another name for the navigator: the member alone is enough.
    assert_eq!(hit("const n = navigator; n.sendBeacon(u, d)"), "sendBeacon");
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
    assert_eq!(hit("const m = await import ('./x')"), "dynamic import");
    assert_eq!(hit("const m = await import\t(u)"), "dynamic import");
    clean("import { a } from './x'");
    clean("import './x'");
    clean("const u = import.meta.url");
    clean("reimport(x)");
}

#[test]
fn rule_script_tag() {
    assert_eq!(hit("el.innerText = '<script>'"), "script tag");
}

#[test]
fn rule_inner_html_assignment() {
    assert_eq!(hit("el.innerHTML = html"), "innerHTML assignment");
    assert_eq!(hit("el.innerHTML=html"), "innerHTML assignment");
    assert_eq!(hit("el.innerHTML += html"), "innerHTML assignment");
    clean("if (el.innerHTML === '') {}");
    clean("const s = el.innerHTML");
    clean("el.innerHTMLish = 1");
}

#[test]
fn rule_outer_html_assignment() {
    assert_eq!(hit("el.outerHTML = html"), "outerHTML assignment");
    assert_eq!(hit("el.outerHTML += html"), "outerHTML assignment");
    clean("const s = el.outerHTML");
}

#[test]
fn rule_srcdoc() {
    assert_eq!(hit("frame.srcdoc = html"), "srcdoc");
    assert_eq!(hit("frame.setAttribute('srcdoc', h)"), "srcdoc");
    clean("const srcdocs = 1");
}

#[test]
fn rule_code_loading_elements() {
    for tag in [
        "'script'",
        "\"iframe\"",
        "`object`",
        "'EMBED'",
        "'frame'",
        " 'script' ",
    ] {
        assert_eq!(
            hit(&format!("const e = document.createElement({tag})")),
            "createElement of a code-loading tag",
            "{tag}"
        );
    }
    clean("const e = document.createElement('div')");
    clean("const e = document.createElement('img')");
    clean("const e = document.createElement(tag)");
}

#[test]
fn rule_constructor() {
    assert_eq!(
        hit("const F = Object.getPrototypeOf(async () => {}).constructor"),
        "constructor"
    );
    assert_eq!(hit("const F = (() => 0).constructor"), "constructor");
    assert_eq!(hit("const F = f['constructor']"), "constructor");
    assert_eq!(hit("const F = f[\"constructor\"]"), "constructor");
    // A class's own constructor is ordinary code.
    clean("  constructor(ctx: PluginContext) {");
    clean("  constructor() { super(); }");
}

#[test]
fn rule_document_computed_access() {
    assert_eq!(hit("document['cook' + 'ie']"), "document[");
    clean("const x = ctx.document[0]");
}

#[test]
fn rule_navigation() {
    assert_eq!(hit("location.href = u"), "location.href");
    assert_eq!(hit("location.assign(u)"), "location.assign");
    assert_eq!(hit("document.location = u"), "document.location");
    // VRChat's own "location" is an instance id, and plugins name variables after it.
    clean("const location = instance?.location ?? ''");
    clean("if (this.#instance?.location === before) {}");
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
fn rule_set_interval_with_a_string() {
    assert_eq!(
        hit("setInterval('alert(1)', 10)"),
        "setInterval with a string"
    );
    clean("setInterval(() => tick(), 10)");
}

#[test]
fn imports_may_not_leave_the_plugin() {
    let refused = |file: &str, text: &str| match scan_source(file, text) {
        Err(PolicyError::Violation { rule, .. }) => rule,
        other => panic!("expected a violation for {text:?} in {file}, got {other:?}"),
    };
    for text in [
        "import state from '../../state.json';",
        "import s from '../x.ts';",
        "export * from './a/../../x';",
        "import cfg from \"/home/u/.config/VRCNext/settings.json\";",
        "import cfg from 'C:/Users/u/AppData/x.json';",
        "import x from 'data:text/javascript,export default 1';",
        "} from '../../host/packages/host/src/index.ts';",
    ] {
        assert_eq!(
            refused("main.ts", text),
            "import outside the plugin",
            "{text}"
        );
    }
    assert_eq!(
        refused("src/a.ts", "import x from '../../x';"),
        "import outside the plugin"
    );
    assert_eq!(
        scan_source("src/a.ts", "import x from '../main.ts';"),
        Ok(())
    );
    assert_eq!(
        scan_source("src/a/b.ts", "import x from '../../plugin.json';"),
        Ok(())
    );
    assert_eq!(
        scan_source("main.ts", "import { a } from '@vrcnext/plugin-api';"),
        Ok(())
    );
    assert_eq!(scan_source("main.ts", "// data comes from here"), Ok(()));
}

#[test]
fn test_files_are_skipped_but_cannot_be_imported() {
    let dir = scratch_dir("policy-tests");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("main.ts"), "export default 1;").unwrap();
    // A fake of `ctx.http` has to say `fetch`; that is what refused bio-updater.
    std::fs::write(
        dir.join("src/sources.test.ts"),
        "const http = { fetch: (url: string) => reply(url) };",
    )
    .unwrap();
    std::fs::write(dir.join("src/a.spec.js"), "window.x = 1;").unwrap();
    assert_eq!(scan_tree(&dir), Ok(()));

    std::fs::write(dir.join("main.ts"), "import './src/sources.test.ts';").unwrap();
    assert_eq!(
        scan_tree(&dir),
        Err(PolicyError::Violation {
            file: "main.ts".to_owned(),
            line: 1,
            rule: "imports a test file",
        })
    );
    std::fs::write(
        dir.join("main.ts"),
        "import { x } from './src/sources.test';",
    )
    .unwrap();
    assert!(scan_tree(&dir).is_err());
    std::fs::remove_dir_all(dir).ok();
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
