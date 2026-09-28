#!/usr/bin/env bash
# The full gate. Every step must pass, in order, with no output filtered.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== fmt =="
cargo fmt --all --check

echo "== clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== test =="
cargo test --workspace

echo "== doc =="
# A broken or private intra-doc link is a warning by default, and `cargo doc` exits 0 on it —
# which is how one sat in the tree unnoticed. The gate does not filter output, so it must not
# tolerate it either.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "== release =="
cargo build --release

echo
echo "gate passed: $(ls -lh target/release/vrcnext-bridge | awk '{print $5}') binary at target/release/vrcnext-bridge"
