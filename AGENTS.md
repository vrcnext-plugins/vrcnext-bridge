# Working on the VRCNext Bridge

The owner's working rules live in the plugin-system repo: `../vrcnext-plugin-system/AGENTS.md`.
They apply here too. Bridge-specific:

- The gate is `./scripts/build.sh` (fmt, clippy pedantic, tests, docs, release build), nothing
  filtered. Scoped `#[allow(..., reason = "...")]` over blanket suppressions.
- Deploy by copying `target/release/vrcnext-bridge` to `~/.vrcnext-plugins/bin/` and restarting
  the `vrcnext-bridge.service` user unit; the page reconnects on its own, no VRCNext restart.
- `--remote` (set in the unit) enables `remote/eval`; `scripts/remote-eval.sh` (`vrcnext-eval`
  on PATH) is how agents inspect and drive the page without the user's mouse.
- Services are synchronous and know nothing about sockets; new capabilities implement `Service`
  and register in `startup.rs`.
