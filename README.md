# vrcnext-bridge

The loopback-only native companion of the VRCNext plugin system: it installs, checks and compiles plugins, keeps their state, and delivers notifications to VR overlays and the desktop.

**Documentation:** <https://vrcnext-plugins.github.io/bridge.html> · running it: <https://vrcnext-plugins.github.io/bridge-running.html>

```bash
./scripts/build.sh            # fmt, clippy, tests, docs, release build
./target/release/vrcnext-bridge
```

Part of [VRCNext Plugins](https://vrcnext-plugins.github.io/). Released into the public domain under the [Unlicense](LICENSE).
