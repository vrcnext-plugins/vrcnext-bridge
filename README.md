# vrcnext-bridge

An optional, loopback-only companion daemon for
[the VRCNext plugin system](https://github.com/vrcnext-plugins/vrcnext-plugin-system).

VRCNext's page can only speak HTTP. It cannot open a UDP socket, connect to D-Bus, or reach a unix
socket — so anything a plugin wants that needs one of those has to happen in a native process.
This is that process.

```
plugin  ──fetch──▶  vrcnext-bridge  ──UDP──────▶  WayVR / XSOverlay-protocol overlay
                          │
                          └────────D-Bus──────▶  the desktop's notification daemon
```

**It is not a notification daemon.** It is a registry of *services*, each with named methods:

```
POST /v1/<service>/<method>
```

`notify` is the first service. A future OSC, clipboard or presence service registers beside it
without touching the transport, the request guard, the rate limiter, or the wiring.

## Targeting

Within `notify`, each destination is a separately addressable **sink**. That is the point: a plugin
can put a big translucent panel in front of someone in VR and leave their monitor alone.

```bash
# VR only
curl -X POST http://127.0.0.1:42081/v1/notify/send \
  -H 'Content-Type: application/json' \
  -d '{"title":"Friend online","sinks":["wayvr"],"height":220,"opacity":0.85}'
```

```bash
# Both, presented differently in each
curl -X POST http://127.0.0.1:42081/v1/notify/send \
  -H 'Content-Type: application/json' \
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
curl http://127.0.0.1:42081/v1/describe
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
| `GET` | `/v1/health` | liveness, version, service names |
| `GET` | `/v1/describe` | every service, method and target, with health |
| `POST` | `/v1/notify/send` | deliver a notification |
| `POST` | `/v1/notify/targets` | targets and the fields each honours |

## Security

A localhost HTTP daemon has three classes of caller, and only one of them matters.

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
- **Loopback only, with no override flag.** `--listen` refuses a non-loopback address. There is
  deliberately no way to force it; such a flag would exist only to be misused.
- **No sink may ever execute a program, open a shell, or write to a caller-chosen path.** This is
  the invariant that keeps class (2) harmless. A localhost daemon that can run commands is a
  remote-code-execution gadget for anything that gets past the guard.
- **Everything is bounded.** Body size, string lengths (in characters, not bytes), float finiteness
  and ranges, sink-name lengths, path-segment shape. A `Notification` can only be constructed by
  validation, so sinks never handle an unchecked value.
- **Rate limited.** A token bucket, 5/s with a burst of 10 by default. A runaway loop is an
  accident that otherwise needs the user to take the headset off.
- **`unsafe_code = "forbid"`**, workspace-wide, alongside clippy `pedantic` with `unwrap_used`,
  `expect_used`, `panic` and `indexing_slicing` denied outside tests.
- **Error messages never echo caller input**, except a sink name already bounded to 32 characters.

An optional `--token` adds a bearer check for shared or multi-user machines, where the assumption
behind class (2) stops holding.

## Install

Requires a Rust toolchain. No system headers — every dependency is pure Rust.

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
any service does.

Either way the gate is `./scripts/build.sh`, which runs fmt, clippy, tests, docs and a release
build, in that order, with nothing filtered.

## Layout

| Crate | Contains |
| :--- | :--- |
| `vrcnext-bridge-core` | protocol, validation, `Service` and `Sink` traits, dispatch, rate limiter. **No I/O**, so it tests without a bus or a socket. |
| `vrcnext-bridge-sinks` | the concrete `wayvr` and `freedesktop` sinks. |
| `vrcnext-bridge` | the binary: HTTP transport, request guard, configuration, wiring. |

## Licence

Released into the public domain under the Unlicense. See [LICENSE](LICENSE).
