# Working on the VRCNext Bridge

The loopback daemon that installs, verifies and compiles plugins and serves the page's services.
Site pages: `bridge.md` (protocol, services, pipeline, security), `bridge-running.md` (flags,
troubleshooting), `source-policy.md` (mirrors `policy.rs` / `obfuscation.rs`), `signing.md`.

## Gate

`./scripts/build.sh` — fmt, clippy pedantic, tests, docs, release build, nothing filtered.

## Rules

- Tests live in `<module>/tests.rs` (`<dir>/tests.rs` for a `mod.rs`), never inline; no source file
  over 1000 lines. `crates/vrcnext-bridge-core/tests/source_limits.rs` enforces both.
- Scoped `#[allow(..., reason = "...")]` over blanket suppressions; `unsafe_code` is forbidden
  outside `vrcnext-bridge-win`.
- Services are synchronous and know nothing about sockets: implement `Service` and register it in
  `crates/vrcnext-bridge/src/startup.rs`. A privileged action takes an `Approver` and asks natively.
- No service runs a program or writes to a caller-chosen path; the build's checksum-verified
  esbuild is the one exception. Error messages never echo caller input.
- Each source-policy rule has a unit test and a row on the site's Source policy page.
- The permission vocabulary is mirrored in `crates/vrcnext-bridge-plugins/src/manifest.rs` and the
  plugin system's `packages/api/src/permissions.ts`; change both.
- `ctx.native` in the host reaches only `notify`; a new service meant for plugins needs a host API
  or an entry in its `PLUGIN_BRIDGE_SERVICES`.

## Deploying locally

Copy `target/release/vrcnext-bridge` to `~/.vrcnext-plugins/bin/` and restart the
`vrcnext-bridge.service` user unit; the page reconnects on its own. `--dev` (set in the owner's
unit) enables the REST surface and `remote/eval`.

## Every repository

- **Documentation lives only on the site** ([vrcnext-plugins.github.io](https://github.com/vrcnext-plugins/vrcnext-plugins.github.io)).
  This repository keeps a compact `README.md` (name, one line, docs link, one quick-start block,
  licence) and this file, nothing else. When behaviour changes, update the site pages named below
  in the same piece of work.
- Commit messages end with a `Co-Authored-By:` trailer naming the model that wrote the commit.
- Never drive VRCNext with a synthetic mouse or keyboard, and restart or reload it sparingly —
  both re-authenticate against VRChat. Inspect the page through the bridge's `remote` service
  (`vrcnext-eval '<async body>'`, bridge started with `--dev`).

## Other repositories

Each has its own `AGENTS.md`; read the one for any repository you change. Checkouts sit side by
side, so the local path is a sibling directory.

| Repository | Local | What it is |
| :--- | :--- | :--- |
| [`vrcnext-plugin-system`](https://github.com/vrcnext-plugins/vrcnext-plugin-system/blob/main/AGENTS.md) | `../vrcnext-plugin-system/AGENTS.md` | host, `@vrcnext/plugin-api`, installer, VRCNext protocol tools |
| [`vrcnext-plugins.github.io`](https://github.com/vrcnext-plugins/vrcnext-plugins.github.io/blob/main/AGENTS.md) | `../vrcnext-plugins.github.io/AGENTS.md` | the documentation site — the only docs |
| [`vrcnext-example-plugin`](https://github.com/vrcnext-plugins/vrcnext-example-plugin/blob/main/AGENTS.md) | `../vrcnext-example-plugin/AGENTS.md` | the template plugin; a submodule of the plugin system |
| [`vrcnext-club-security-plugin`](https://github.com/vrcnext-plugins/vrcnext-club-security-plugin/blob/main/AGENTS.md) | `../vrcnext-club-security-plugin/AGENTS.md` | Club Security plugin |
| [`vrcnext-bio-updater-plugin`](https://github.com/vrcnext-plugins/vrcnext-bio-updater-plugin/blob/main/AGENTS.md) | `../vrcnext-bio-updater-plugin/AGENTS.md` | Bio Updater plugin |
| [`vrcnext-patches-plugin`](https://github.com/vrcnext-plugins/vrcnext-patches-plugin/blob/main/AGENTS.md) | `../vrcnext-patches-plugin/AGENTS.md` | VRCNext Patches plugin |
