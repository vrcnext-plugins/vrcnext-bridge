# vrcnext-bridge

The loopback-only native companion of
[the VRCNext plugin system](https://github.com/vrcnext-plugins/vrcnext-plugin-system). It is
mandatory: the page runs one static bundle that the bridge compiles, and without the bridge there
is no install, no state and no build.

VRCNext's page can only speak HTTP and WebSockets. It cannot clone a repository, run a compiler,
keep a file, open a UDP socket or connect to D-Bus — so all of that happens here.

```
page  ──WebSocket──▶  vrcnext-bridge  ──gix (pure Rust, HTTPS)──▶  plugin repositories
                            │
                            ├── spawns bin/esbuild ─────────────▶  <VRCNext config>/custom-themes/
                            │      (checksum-verified, fixed args)     vrcnext-plugin-system/vrcnext-plugin-host.js
                            ├── state.json
                            ├──UDP───────────────────────────────▶  WayVR / XSOverlay-protocol overlay
                            └──D-Bus──────────────────────────────▶  the desktop's notification daemon
```

**It is a registry of *services***, each with named methods, reachable two ways:

```
WS   /v1/ws                     one persistent socket — what the plugin system uses
GET  /v1/health                 is it up, which version — no token needed
                                — everything below needs --dev —
GET  /v1/describe               every service and target, in full
POST /v1/<service>/<method>     one call — for curl and anything else that is not the page
```

**The socket is the only way the plugin system talks to the bridge.** `/v1/ws` and the
`/v1/health` probe the page opens with are all a normal install serves; a bridge started without
`--dev` answers 404 on everything else, and says so by naming the flag. The REST surface is a
second way into the same services for scripts and agents — a `curl`, an `eval` through `remote`,
a rebuild — and a second way in is a thing to ask for rather than to leave open. The one build
an installer needs before the daemon is even useful is `vrcnext-bridge --build-plugins`, which
runs it in-process and exits.

| Service | Does |
| :--- | :--- |
| `plugins` | install / list / check_updates / update / uninstall / build / keys / forget_key — clones with `gix`, validates, verifies the author's signature, compiles the bundle |
| `state` | the page's key-value store (`state.json`): enabled flags, grants, plugin settings |
| `notify` | notifications to VR overlays and the desktop, individually targetable |
| `logs` | appends the page's log lines to a file |
| `outbound` | one HTTP request, made by the bridge instead of the page, so APIs that send no CORS headers are reachable at all |

A future OSC, clipboard or presence service registers beside them without touching the
transport, the request guard, the rate limiter, or the wiring.

### `outbound`, and what it is for

A browser may only read a cross-origin response when the server says it may. Plenty of plain
HTTP APIs never say so — the Steam Web API among them — and to a plugin they are simply
unreachable: the request fails before a response is looked at, indistinguishable from the host
being down. The bridge is not a browser, so a request it makes is subject to no such rule.

That is more reach than the page has, and it is not narrowed here: `outbound` will fetch
whatever this machine can fetch, this machine's own network included. The check that matters is
in front of it, in the plugin host, which asks the user about the concrete host before a
plugin's first request to it and names the direction — *request data from* or *send data to* —
along with the method, the URL, the headers and the body. A declared host in `plugin.json` is
the plugin saying where it intends to go, not the user having agreed to it.

One request, `fetch`, text in and text out: a response that is not valid UTF-8 is refused rather
than mangled. Bounded at 1 MiB sent, 16 MiB received, 32 headers and 120 seconds; `Host`,
`Content-Length` and the other connection headers belong to the bridge and cannot be set.

It is a service like the others, reached over the same socket. The `POST /v1/...` interface is
for development and for agents driving the bridge from outside — it gains nothing here, and the
plugin system never uses it.

## The socket

The plugin system opens `/v1/ws` once and keeps it open. Every frame is JSON with a `type`. The
first frame **must** be a `hello` carrying the pairing token; until the bridge answers `welcome`
the socket carries nothing.

```jsonc
// page → bridge, first frame
{ "type": "hello", "token": "<pairing token>", "client": "vrcnext-plugin-system/0.2.0" }
// bridge → page: the socket is unlocked. `services` is the same payload as GET /v1/describe.
{ "type": "welcome", "version": "0.1.0", "services": { "state": { "summary": "…" } } }
```

Any other first frame, a wrong token, or no `hello` within 5 seconds closes the socket with code
`1008` and reason `hello_required` or `unauthorized`. A failed hello costs a rate-limit token, so
guessing is slow. After `welcome`:

```jsonc
// page → bridge: a call, answered under the same id. Several may be in flight.
{ "type": "request", "id": "17", "service": "notify", "method": "send", "params": { "title": "Hi" } }
// bridge → page
{ "type": "response", "id": "17", "ok": true, "result": { "delivered": ["wayvr"], "failed": [] } }
{ "type": "response", "id": "17", "ok": false, "error": { "code": "bad_request", "message": "…" } }

// page → bridge: a batch of plugin log lines for the log file. Never answered.
{ "type": "logs", "records": [{ "level": "info", "scope": "my-plugin", "message": "…", "ts": 0 }] }

// bridge → page: unsolicited events. `log` is a daemon log line; `error` a protocol error that
// had no id to answer under; `progress`, `plugins` and `build` come from the plugins service.
{ "type": "push", "event": "log", "data": { "level": "warn", "scope": "bridge", "message": "…", "ts": 0 } }
{ "type": "push", "event": "error", "data": { "code": "bad_request", "message": "…" } }
{ "type": "push", "event": "progress", "data": { "op": "install", "id": "friend-alerts", "step": "policy", "message": "scanning sources" } }
{ "type": "push", "event": "plugins", "data": { "plugins": [ /* list entries */ ] } }
{ "type": "push", "event": "build", "data": { "ok": true, "durationMs": 64, "plugins": ["friend-alerts"], "errors": [] } }
```

`id` is caller-chosen, up to 128 characters. Service and method names are lowercase identifiers
of up to 64 characters. A request over the socket draws from the same rate-limit bucket as an HTTP
call, so switching transports buys nothing; log frames have their own, far larger, budget.

## Plugins

`plugins/install {url}` runs one pipeline, always in this order, and pushes a `progress` frame
at each step (`awaiting_confirmation`, `clone`, `validate`, `policy`, `signature`, `move`,
`build`):

1. **Confirm natively.** A prompt outside the page — see [Security](#security). No yes, no install.
2. **Clone** with `gix`: HTTPS only, depth 1, default branch, into `plugins/.tmp-<random>`,
   120 s deadline. No shell and no system `git`, ever.
3. **Validate `plugin.json`**: id `[a-z0-9][a-z0-9-]{1,39}`, semver `version`, a semver range
   `apiVersion`, `description` ≤ 200 characters, ≤ 8 `tags`, permissions from the fixed
   vocabulary, exact `actions` / `events` / `hosts` (no wildcards), no unknown fields.
4. **Scan the source policy** — every `.ts`/`.tsx`/`.js`/`.jsx` (and `.mts`/`.cts`/`.mjs`/`.cjs`)
   file, ≤ 200 files and ≤ 2 MiB in total, no symlinks. One hit refuses the install with
   `file:line rule`. The rules, in `crates/vrcnext-bridge-plugins/src/policy.rs`, each with a
   unit test: `eval(`, `new Function`, `globalThis.`, `window.` (no exceptions, not even
   `window.location.href`), `document.cookie`, `localStorage`, `sessionStorage`, `indexedDB`,
   `XMLHttpRequest`, bare `fetch(` (`ctx.http.fetch(` is fine), `WebSocket(`, dynamic `import(`,
   `<script`, `.innerHTML =`, `insertAdjacentHTML`, `setTimeout(` with a string first argument,
   `require(`, `process.`. Plugins reach the world only through `ctx.*`. This is a text scan
   that makes honest mistakes visible; it is not a sandbox and does not claim to be.

   Before those names, the same pass applies the **shape** rules in
   `crates/vrcnext-bridge-plugins/src/obfuscation.rs`, because a table of names only works on
   code a person could have read: `minified` (a line over 1000 characters), `packed source` (a
   file of 20+ lines averaging over 250), `escape sequences` (more than eight `\xNN`/`\uNNNN` in
   a row), `mangled identifiers` (`_0x` + hex, what `javascript-obfuscator` emits), `opaque
   blob` (an unbroken 256-character run over a base64/hex alphabet at ≥ 3.5 bits of Shannon
   entropy per character) and `invisible characters` (zero-width and bidirectional overrides —
   Trojan Source). They refuse one honest thing on purpose, an inlined binary `data:` URI, which
   a text scan cannot tell from a payload.
5. **Verify the signature.** `plugin.sig` at the root must be an Ed25519 signature, version 1,
   naming this plugin's id, over a SHA-256 digest of every file in the clone except `.git/` and
   itself. Then the key has to be one the user has accepted: an unknown fingerprint is a second
   native prompt, and an update signed by a key other than the one the plugin is recorded under
   is a third, separate prompt, every time. Accepted keys live in the reserved
   `bridge.plugin-keys` namespace; `keys {}` lists them and `forget_key {keyId}` removes one
   (confirmed natively, and nothing is uninstalled). The format and the author's side of it are
   in `crates/vrcnext-bridge-plugins/src/signing.rs` and the plugin system's
   `scripts/sign-plugin.mjs`.
6. **Move** the clone to `plugins/<id>` (refused if it exists), record
   `{url, commit, keyId, installedAt, updatedAt}` in the state store's reserved `bridge.plugins`
   namespace, push `plugins` with the new list, and **build**.

Errors are `bad_request` with a stable code as the message prefix: `not_https`, `denied`,
`approval_unavailable`, `clone_failed`, `no_manifest`, `manifest_invalid: …`,
`policy: file:line rule`, `unsigned: …`, `already_installed`, `not_installed`, `not_trusted`,
`invalid_id`.

`update {id}` runs the same pipeline against the recorded URL and swaps the fresh clone in only
once it has passed, so an update that fails validation leaves the old tree exactly as it was —
and there is never a merge. `check_updates {}` fetches each clone's origin and returns
`{updates:[{id, current, latest, commitsBehind, changelog:[{commit, summary, time}]}]}` for the
ones behind (≤ 50 changelog entries; a clone is shallow, so `commitsBehind` is "at least" when
it reaches 50). `uninstall {id}` removes the clone, its record and its `plugin:<id>` state, and
rebuilds. `list {}` returns
`{plugins:[{id, name, version, description, url, commit, tags, permissions, optionalPermissions,
actions, events, hosts, author?, homepage?, apiVersion, installedAt, updatedAt, keyId}]}` read from the
clones. `build {}` forces a rebuild and returns the same report the `build` push carries.

### The build

The bridge produces the theme file VRCNext loads,
`<VRCNext config>/custom-themes/vrcnext-plugin-system/vrcnext-plugin-host.js`, which contains the
host and every installed plugin. Each build:

1. Verifies `bin/esbuild`'s SHA-256 against `bin/esbuild.sha256` and refuses to run it otherwise.
2. Writes `build/static-plugins.ts`, the import table:
   ```ts
   import p0 from '../plugins/friend-alerts/main.ts';
   import m0 from '../plugins/friend-alerts/plugin.json';
   export const COMPILED_PLUGINS = [{ manifest: m0, plugin: p0 }] as const;
   ```
3. Spawns `esbuild host/packages/host/src/index.ts --bundle --format=iife --target=es2022
   --platform=browser --minify --sourcemap=linked
   --alias:@vrcnext/plugin-api=./host/packages/api/src/index.ts
   --alias:@vrcnext/static-plugins=./build/static-plugins.ts --outfile=<staging>
   --log-level=warning --color=false` with the data directory as working directory, an empty
   environment, captured output and a 60 s deadline.
4. Writes the theme's `info.json`, then renames the staged bundle and map into place. A failed
   build leaves the previous bundle untouched.
5. Pushes `build {ok, durationMs, plugins, errors}`.

`host/` must be self-contained: the api and host sources plus any npm package they import (under
`host/node_modules`), since the bridge has no package manager.

## State

`state {get|set|delete|list}` over `~/.vrcnext-plugins/state.json`, written whole and atomically
under one lock. `ns` and `key` are `[a-zA-Z0-9_.:-]{1,64}`; a value is ≤ 64 KiB serialised; the
file ≤ 8 MiB. `get` answers `{value}` (`null` when absent), `list` answers `{entries:{key:value}}`.
Namespaces starting with `bridge.` are the bridge's own and are refused over the service. The
host uses `host` and `plugin:<id>`.

## Targeting

Within `notify`, each destination is a separately addressable **sink**. That is the point: a plugin
can put a big translucent panel in front of someone in VR and leave their monitor alone.

```bash
# VR only
TOKEN="$(vrcnext-bridge --print-token)"
curl -X POST http://127.0.0.1:42081/v1/notify/send \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Friend online","sinks":["wayvr"],"height":220,"opacity":0.85}'
```

```bash
# Both, presented differently in each
curl -X POST http://127.0.0.1:42081/v1/notify/send \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "title": "Friend online",
        "content": "on the desktop",
        "overrides": { "wayvr": { "content": "tall panel in VR", "height": 220, "opacity": 0.85 } }
      }'
```

`sinks` selects targets; `overrides` patches content and presentation per target. An override for a
target that is not being delivered to is ignored, so carrying presentation for an overlay the user
does not run costs nothing.

Ask what exists rather than hard-coding names:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:42081/v1/describe
```

Each target reports which fields it `honours` — panel height means something to `wayvr` and nothing
to `freedesktop`, and a plugin should adapt rather than guess.

## Sinks that ship

| Name | Transport | Reaches | Honours |
| :--- | :--- | :--- | :--- |
| `wayvr` | UDP `127.0.0.1:42069` | WayVR, and anything else speaking the XSOverlay protocol | everything, including `height`, `opacity`, `alwaysShow` |
| `freedesktop` | D-Bus `org.freedesktop.Notifications` | the desktop's own notification daemon | `title`, `content`, `timeoutSecs`, `icon`, `sourceApp`, `urgency`, `sound` |

A sink that fails to start is logged and skipped, never fatal — no session bus is an ordinary
state. If *nothing* starts, `notify/send` answers 503 rather than claiming success.

### What has actually been verified

Honest accounting, because this was reverse-engineered rather than read from a spec:

- The `wayvr` sink has delivered to a **running** WayVR on `127.0.0.1:42069`, which logged no parse
  error. Whether the panel *rendered* was not confirmed from inside the headset.
- WayVR's `XsoMessage` has 13 fields. Twelve names were recovered from the binary's serde metadata.
  The thirteenth is **inferred** to be `icon`. If that inference is wrong, icons are ignored and
  everything else still works.
- The `freedesktop` sink has been verified end to end on KDE.

## Endpoints

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/v1/health` | liveness, version, service names — how the plugin system tells "running" from "not installed". **No token needed**: it is the probe. |
| `GET` | `/v1/describe` | every service, method and target, with health. Bearer required. |
| `GET` | `/v1/ws` | the WebSocket upgrade; the token goes in the first frame |
| `POST` | `/v1/plugins/{install,list,check_updates,update,uninstall,build,keys,forget_key}` | see [Plugins](#plugins) |
| `POST` | `/v1/state/{get,set,delete,list}` | see [State](#state) |
| `POST` | `/v1/notify/send` | deliver a notification |
| `POST` | `/v1/notify/targets` | targets and the fields each honours |
| `POST` | `/v1/logs/write` | append a batch of plugin log lines to the log file |
| `POST` | `/v1/logs/info` | where that file is and how big it has grown |
| `POST` | `/v1/remote/eval` | run a snippet inside the paired page and return its result. Only with `--dev`; see [Remote control](docs/running.md#remote-control) |

## Security

A localhost daemon has three classes of caller, and only one of them matters.

1. **The VRCNext page.** The intended one.
2. **Other processes running as this user.** They already have the user's privileges and could call
   the notification daemon directly. The bridge grants them nothing new — *provided* no sink ever
   executes anything.
3. **Any web page in any browser on this machine.** This is the real threat. A site the user happens
   to have open can issue cross-origin requests to `127.0.0.1`. CORS stops it *reading* the
   response, but a "simple" request is still **delivered** — and delivery is the entire effect
   here. Being unable to read the reply is no comfort when the payload already appeared in
   someone's headset.

What is done about it:

- **Every request is made non-simple.** `POST` bodies must be `application/json`, which is not on
  the CORS simple-request list, so browsers must preflight — and the preflight is refused for
  origins that are not allow-listed. `Access-Control-Allow-Origin` is never `*` and never reflects
  an arbitrary origin.
- **The WebSocket checks `Origin` itself.** CORS does not protect an upgrade: a browser completes
  a `ws://127.0.0.1` handshake from any page, with no preflight. The origin allowlist therefore
  runs in front of the upgrade, and a bad origin is answered 403 before a frame is read. The
  pairing token is checked in the first frame, since a browser cannot set headers on an upgrade.
- **A pairing token, always.** Generated on first run — 32 random bytes, base64url — and stored
  `0600` at `~/.vrcnext-plugins/token`. Every `POST` carries it as `Authorization: Bearer …`, every
  socket presents it in `hello`. Only `GET /v1/health` answers without it. The banner prints it on
  every start; `--print-token` prints it and exits; `--rotate-token` replaces it. Anything that
  can read the file already runs as this user, so the token adds nothing against that caller and
  everything against a page or a process that does not.
- **Loopback only, with no override flag.** `--listen` refuses a non-loopback address. There is
  deliberately no way to force it; such a flag would exist only to be misused.
- **Privileged operations are confirmed natively, outside the page.** Installing, updating or
  uninstalling a plugin puts code into the page, and the page cannot be the thing that confirms
  that: any script already running there — a plugin included — could click its own dialog. So the
  bridge asks through something the page cannot reach: on unix a desktop notification with
  **Confirm** and **Deny** buttons (`org.freedesktop.Notifications`, critical urgency so it does
  not expire on its own), on Windows a topmost Yes/No message box. Dismissing the prompt, a
  120 s silence, a broken session bus or no prompt at all are all a refusal; the service answers
  `denied` or `approval_unavailable` and logs why. "Update all" is one prompt per plugin. `build`
  and `state` do not prompt — they put nothing new into the page.
- **Code only arrives from a key the user accepted.** A confirmation says yes to a URL, and a
  URL is not an identity — a repository changes hands and an account takeover rewrites every
  branch at once. So every tree also has to carry an Ed25519 signature over its own files, bound
  to its plugin id, and each plugin is pinned to the key it was installed under. A new key is
  confirmed once; a *changed* key is confirmed every time, separately, and being a trusted
  author of another plugin is not an excuse. Verification is offline and in-process: no key
  server, no registry, nothing fetched. What this buys is narrow and worth stating plainly — it
  says who published a tree, not that the tree is safe, and a fingerprint the user never
  compared against the author is trust on first use.
- **No service may execute a program, open a shell, or write to a caller-chosen path — with one
  exception, in one place.** The build module spawns exactly one binary, `bin/esbuild`, only
  after its SHA-256 matches the checksum the installer wrote beside it, with a fixed argument
  list and a cleared environment. The only caller-derived input is the list of plugin ids, and
  those are regex-validated and appear in a generated file, never on the command line. Nothing
  from a plugin, a manifest or a request reaches argv. Every other module keeps the rule: a
  localhost daemon that can run commands is a remote-code-execution gadget for anything that
  gets past the guard.
- **Nothing caller-supplied becomes a path without validation.** Every location comes from one
  `Paths` struct; the only thing it joins is a `PluginId`, which cannot be constructed without
  passing the id rule. Symlinks inside a clone refuse the install.
- **Everything is bounded.** Body size, string lengths (in characters, not bytes), float finiteness
  and ranges, sink-name lengths, path-segment shape. A `Notification` can only be constructed by
  validation, so sinks never handle an unchecked value.
- **Rate limited, on every endpoint.** A token bucket, 5/s with a burst of 10 by default, applied
  to health checks and preflights too — `/v1/health` is cheap, but cheap times an unbounded request
  rate is still a busy loop. A runaway `notify` loop is an accident that otherwise needs the user to
  take the headset off.
- **`unsafe_code = "forbid"`**, workspace-wide, alongside clippy `pedantic` with `unwrap_used`,
  `expect_used`, `panic` and `indexing_slicing` denied outside tests.
- **Error messages never echo caller input.** The one exception — an unknown sink's name — is both
  validated before selection and truncated at the point of formatting, because an error message is
  the last place that should reflect an unbounded caller-supplied string.

## Install

Requires a Rust toolchain. No system headers: git is `gix` over a rustls transport, and the only
C in the tree is the TLS crypto backend (`aws-lc-rs`), which builds with the platform's own
compiler. The installer in the plugin-system repository fetches the release binary, the pinned
`esbuild` and the host sources, and lays out `~/.vrcnext-plugins` (see [Layout](#layout)).

```bash
git clone https://github.com/vrcnext-plugins/vrcnext-bridge
cd vrcnext-bridge
./scripts/build.sh
```

The binary lands at `target/release/vrcnext-bridge`. Run it:

```bash
./target/release/vrcnext-bridge
```

To start it with your session, see [`docs/running.md`](docs/running.md).

## Adding a capability

Two extension points, depending on what you are adding.

**A new destination for notifications** — implement `Sink` in `vrcnext-bridge-sinks` and register
it in `crates/vrcnext-bridge/src/startup.rs`. Name it after what it talks to (`wayvr`), not the
transport (`udp`): sink names are the vocabulary plugins use to target things, so they are API.

**A whole new capability** — implement `Service` in `vrcnext-bridge-core` and register it in the
same place. The transport, guard and rate limiter already handle it; they know nothing about what
any service does. A service that has news for the page takes an `Arc<dyn Pusher>` at construction
and calls `push(event, data)`; the transport fans it out to every socket. A service that does
something privileged takes an `Arc<dyn Approver>` and asks before acting.

Either way the gate is `./scripts/build.sh`, which runs fmt, clippy, tests, docs and a release
build, in that order, with nothing filtered.

## Layout

| Crate | Contains |
| :--- | :--- |
| `vrcnext-bridge-core` | protocol, validation, the `Service`, `Sink`, `Pusher` and `Approver` traits, `Paths`, dispatch, rate limiter. **No I/O**, so it tests without a bus or a socket. |
| `vrcnext-bridge-plugins` | `state`, `plugins`, the manifest schema, the source policy, signature verification and the trust store, `gix` and the build. Git and the builder are traits, so the pipeline is tested with fakes; `tests/live_git.rs` (ignored) clones for real. |
| `vrcnext-bridge-sinks` | the `wayvr` sink; on unix also the `freedesktop` sink and the notification-based confirmation prompt. |
| `vrcnext-bridge-win` | the Windows message-box prompt: the one FFI call, in a crate that denies rather than forbids `unsafe` so the rest of the workspace can keep forbidding it. Empty elsewhere. |
| `vrcnext-bridge` | the binary: the `tokio`/`axum` transport, the WebSocket session, the request guard, configuration, wiring. |

On disk:

```
~/.vrcnext-plugins/                     (Windows: %LOCALAPPDATA%\vrcnext-plugins\)
  bin/vrcnext-bridge[.exe]              installed by the installer
  bin/esbuild[.exe]  bin/esbuild.sha256 pinned binary + the checksum verified before every spawn
  host/                                 host + api sources (packages/api/src, packages/host/src)
  plugins/<id>/                         one git clone per plugin: plugin.json + main.ts at the root
  build/static-plugins.ts               generated import table
  state.json                            the state store
  token                                 pairing token, 0600
```

The bundle goes to `~/.config/VRCNext/custom-themes/vrcnext-plugin-system/` (`%APPDATA%\VRCNext`
on Windows), beside an `info.json` and the source map.

## Licence

Released into the public domain under the Unlicense. See [LICENSE](LICENSE).
