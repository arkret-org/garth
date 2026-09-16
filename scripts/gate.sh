#!/usr/bin/env sh

set -eu

quick=0
if [ "${1:-}" = "--quick" ]; then
    quick=1
fi

cd "$(dirname "$0")/.."

# Scoped to this package on purpose. The SDK is a sibling path dependency, and
# `cargo fmt --all` reaches into that repository and rewrites it.
echo "==> cargo fmt -- --check"
cargo fmt -- --check

echo "==> cargo check --workspace --all-features"
cargo check --workspace --all-features

echo "==> cargo clippy --workspace --all-features --all-targets -- -D warnings"
cargo clippy --workspace --all-features --all-targets -- -D warnings

echo "==> cargo test --workspace --all-features"
cargo test --workspace --all-features

if [ "$quick" -eq 0 ]; then
    echo "==> cargo check --target wasm32-unknown-unknown --no-default-features --features wasm"
    cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
fi

echo "gate: PASS"
