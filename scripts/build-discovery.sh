#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo +1.96.1 test --locked --manifest-path "$root/discovery-engine/Cargo.toml"
cargo +1.96.1 build --release --locked --target wasm32-unknown-unknown --manifest-path "$root/discovery-engine/Cargo.toml"
mkdir -p "$root/server/internal/app" "$root/console/public"
for destination in "$root/server/internal/app/discovery_engine.wasm" "$root/console/public/discovery_engine.wasm"; do
  cp "$root/discovery-engine/target/wasm32-unknown-unknown/release/milvago_discovery_engine.wasm" "$destination"
done
