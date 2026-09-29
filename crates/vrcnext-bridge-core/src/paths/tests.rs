#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion is how a test reports; panicking here is the point"
)]
use std::path::{Path, PathBuf};

use super::{Paths, PluginId};

fn paths() -> Paths {
    Paths::new(PathBuf::from("/data"), Path::new("/cfg/VRCNext"))
}

#[test]
fn every_location_hangs_off_the_root_or_the_theme_dir() {
    let p = paths();
    assert_eq!(p.token_file(), Path::new("/data/token"));
    assert_eq!(p.state_file(), Path::new("/data/state.json"));
    assert_eq!(p.esbuild_checksum(), Path::new("/data/bin/esbuild.sha256"));
    assert_eq!(
        p.static_plugins(),
        Path::new("/data/build/static-plugins.ts")
    );
    assert_eq!(
        p.theme_dir(),
        Path::new("/cfg/VRCNext/custom-themes/vrcnext-plugin-system")
    );
    assert!(p.bundle().ends_with("vrcnext-plugin-host.js"));
}

#[test]
fn plugin_dirs_only_come_from_validated_ids() {
    let id = PluginId::parse("friend-alerts").expect("valid");
    assert_eq!(
        paths().plugin_dir(&id),
        Path::new("/data/plugins/friend-alerts")
    );
}

#[test]
fn ids_reject_traversal_and_odd_shapes() {
    for bad in [
        "",
        "a",
        "-abc",
        "Abc",
        "a b",
        "../x",
        "a/b",
        "a.b",
        "x_y",
        &"a".repeat(41),
    ] {
        assert!(PluginId::parse(bad).is_err(), "{bad:?} should be refused");
    }
    for good in ["ab", "friend-alerts", "a1", "x-", &"a".repeat(40)] {
        assert!(PluginId::parse(good).is_ok(), "{good:?} should be accepted");
    }
}
