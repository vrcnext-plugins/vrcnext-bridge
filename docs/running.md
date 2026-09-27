# Running the bridge

The bridge is a foreground process, and the plugin system needs it running: it compiles the
bundle VRCNext loads, keeps the page's state, and installs plugins. Without it the Plugins tab
shows "not detected" and nothing else.

## Manually

```bash
./target/release/vrcnext-bridge
```

The startup banner states exactly what came up: each service, each sink and its health, the data
and theme directories, the pairing token, which confirmation prompt is active, and the rate
limit. If a sink is missing, the reason is on the line above.

The first run creates `~/.vrcnext-plugins/` (`%LOCALAPPDATA%\vrcnext-plugins\` on Windows). The
installer fills `bin/esbuild`, `bin/esbuild.sha256` and `host/`; without them `plugins/build`
answers with `ok: false` and says which is missing.

## The pairing token

The first start writes `~/.vrcnext-plugins/token` (`%LOCALAPPDATA%\vrcnext-plugins\token` on
Windows), readable only by you. The page needs it once: paste it into the Plugins tab. To see it
again without the banner, or to revoke it:

```bash
vrcnext-bridge --print-token     # prints it and exits
vrcnext-bridge --rotate-token    # replaces it; every paired page must be re-paired
```

## Confirming an install

Installing, updating or uninstalling a plugin is confirmed **outside the page**, because the page
is exactly what a malicious plugin would control. What you will see:

- **Linux / unix desktops**: a notification titled "Install a plugin?" (or "Update plugin …?",
  "Uninstall plugin …?") with the URL and two buttons, **Confirm** and **Deny**. It has critical
  urgency, so it stays until you answer. Closing it is a Deny. An overlay that mirrors desktop
  notifications shows it in VR as well, but the buttons are on the desktop.
- **Windows**: a topmost Yes/No message box titled "VRCNext Bridge".

If nothing is answered within two minutes the operation is refused. If the bridge has no way to
ask — no session bus, typically because it started outside the graphical session — the banner says
`confirmation prompt: none: privileged operations will be refused`, and every install answers
`approval_unavailable` until it is restarted where a prompt can appear. There is no flag to skip
the prompt.

## As a systemd user service

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/vrcnext-bridge.service <<'UNIT'
[Unit]
Description=VRCNext plugin bridge
After=graphical-session.target
PartOf=graphical-session.target

[Service]
ExecStart=%h/.local/bin/vrcnext-bridge
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
UNIT

install -Dm755 target/release/vrcnext-bridge ~/.local/bin/vrcnext-bridge
systemctl --user daemon-reload
systemctl --user enable --now vrcnext-bridge
```

`After=graphical-session.target` matters: the `freedesktop` sink and the confirmation prompt both
need a session bus, and starting before one exists means no desktop notifications and no
installs for the lifetime of the process.

Check it:

```bash
systemctl --user status vrcnext-bridge
curl -s http://127.0.0.1:42081/v1/health
```

## Options worth knowing

| Flag | Default | Notes |
| :--- | :--- | :--- |
| `--listen` | `127.0.0.1:42081` | Must be loopback. There is no override. |
| `--sink` | all of them | Repeat to enable a subset, e.g. `--sink wayvr`. |
| `--wayvr-addr` | `127.0.0.1:42069` | Where the XSOverlay-protocol listener is. |
| `--data-dir` | `~/.vrcnext-plugins` | Plugins, host sources, esbuild, state, token. Override for a second instance. |
| `--rate` / `--burst` | `5` / `10` | Token bucket, shared by HTTP calls and socket requests. |
| `--threads` | `4` | Runtime worker threads. Services run on a separate blocking pool. |
| `--log` | `info` | `debug` logs every delivery. |
| `--remote` | off | Offer `remote/eval`: run snippets inside the page. See [Remote control](#remote-control). |

Each also reads an environment variable — see `vrcnext-bridge --help`.

## Telling the plugin system where it is

The host looks at `http://127.0.0.1:42081`, probes `/v1/health` at boot, and keeps a WebSocket to
`/v1/ws` open for as long as VRCNext runs, reconnecting in the background if the daemon goes away.
**Plugins** shows one of four states — not detected, running but not connected, unpaired (the
token was refused; paste it again), connected — and has a **Re-check** button for after you have
just started it.

## Remote control

Started with `--remote`, the bridge offers one more service: `POST /v1/remote/eval` takes
`{ "code": "…", "timeoutMs": 10000 }`, pushes the snippet to the paired page over the socket, and
answers with whatever the page returned. It exists so that a script or an agent can inspect and
drive VRCNext — open a tab, read a card, click a button, check a layout — without a synthetic
mouse and without taking the pointer from whoever is at the desk.

The snippet is the body of an `async` function. `host` (the plugin host's handle, with `manager`)
and a few helpers are in scope: `text(selector)`, `click(selector)`, `visible(selector)`,
`rects(selector)` and `sleep(ms)`. Everything else the page has — `showTab`, `document`, VRCNext's
own globals — is there as usual.

```bash
scripts/remote-eval.sh 'showTab(9); await sleep(300); return text("#tab9 .settings-nav")'
scripts/remote-eval.sh 'return rects("#vrcnextPluginsNavGroup ~ .panel-card")'
```

The reply is `{ "ok": true, "value": … }` for a value, `{ "ok": false, "error": "…" }` when the
snippet threw, and a `503 unavailable` when no page answered before the deadline (default ten
seconds, at most sixty). Values are JSON; anything that will not serialise comes back as its
string form, and anything over 512 KiB is truncated.

It is off by default on purpose. Whoever holds the pairing token can already install plugins
and read state, and the page runs the bundle this daemon compiles, so the service does not add a
new party to trust — but it turns that trust into "run anything in the app", so it has to be
asked for and the startup banner says when it is on. Keep the token file private; do not add
`--allow-origin` alongside it.

## Troubleshooting

**"no session bus"** — the process has no `DBUS_SESSION_BUS_ADDRESS`. Usually means it started
outside the graphical session; the systemd unit above fixes it. Until then there are no desktop
notifications and every install is refused with `approval_unavailable`.

**`plugins/build` answers `esbuild checksum mismatch`** — `bin/esbuild` does not match
`bin/esbuild.sha256`. The bridge will not run a binary it cannot vouch for; re-run the installer.

**A build fails with `Could not resolve "…"`** — `host/` is missing a package the host or api
sources import. The bridge has no package manager; the host release tarball must carry them.

**An install fails with `policy: file:line rule`** — the plugin's source uses something the
policy refuses (see the README's rule list). That is the plugin author's to fix.

**`wayvr` health is always `unknown`** — expected, and not a fault. UDP is fire-and-forget: an open
socket says nothing about whether an overlay is listening. Reporting `up` would be a guess dressed
as a fact.

**Notifications work from `curl` but not from a plugin** — a CORS refusal. The bridge logs
`refused request from origin …` with the origin it saw. VRCNext's page origin should be a loopback
one; if yours is not, add it with `--allow-origin`.

**401 / socket closes with `unauthorized`** — the token the page holds is not the one in the token
file, usually after `--rotate-token`. Paste the current one.

**429s** — the rate limit. The response carries `Retry-After`.
