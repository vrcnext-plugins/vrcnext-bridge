# Running the bridge

The bridge is a foreground process. It is optional — the plugin system works without it, and only
the VR and desktop notification targets become unavailable.

## Manually

```bash
./target/release/vrcnext-bridge
```

The startup banner states exactly what came up: each service, each sink and its health, the data
and theme directories, the pairing token, and the rate limit. If a sink is missing, the reason is
on the line above.

## The pairing token

The first start writes `~/.vrcnext-plugins/token` (`%LOCALAPPDATA%\vrcnext-plugins\token` on
Windows), readable only by you. The page needs it once: paste it into the Plugins tab. To see it
again without the banner, or to revoke it:

```bash
vrcnext-bridge --print-token     # prints it and exits
vrcnext-bridge --rotate-token    # replaces it; every paired page must be re-paired
```

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

`After=graphical-session.target` matters: the `freedesktop` sink needs a session bus, and starting
before one exists means that sink is skipped for the lifetime of the process.

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
| `--data-dir` | `~/.vrcnext-plugins` | Plugins, host sources, state, token. Override for a second instance. |
| `--rate` / `--burst` | `5` / `10` | Token bucket, shared by HTTP calls and socket requests. |
| `--threads` | `4` | Runtime worker threads. Services run on a separate blocking pool. |
| `--log` | `info` | `debug` logs every delivery. |

Each also reads an environment variable — see `vrcnext-bridge --help`.

## Telling the plugin system where it is

The host looks at `http://127.0.0.1:42081`, probes `/v1/health` at boot, and keeps a WebSocket to
`/v1/ws` open for as long as VRCNext runs, reconnecting in the background if the daemon goes away.
**Plugins** shows one of four states — not detected, running but not connected, unpaired (the
token was refused; paste it again), connected — and has a **Re-check** button for after you have
just started it.

## Troubleshooting

**"no session bus"** — the process has no `DBUS_SESSION_BUS_ADDRESS`. Usually means it started
outside the graphical session; the systemd unit above fixes it.

**`wayvr` health is always `unknown`** — expected, and not a fault. UDP is fire-and-forget: an open
socket says nothing about whether an overlay is listening. Reporting `up` would be a guess dressed
as a fact.

**Notifications work from `curl` but not from a plugin** — a CORS refusal. The bridge logs
`refused request from origin …` with the origin it saw. VRCNext's page origin should be a loopback
one; if yours is not, add it with `--allow-origin`.

**401 / socket closes with `unauthorized`** — the token the page holds is not the one in the token
file, usually after `--rotate-token`. Paste the current one.

**429s** — the rate limit. The response carries `Retry-After`.
