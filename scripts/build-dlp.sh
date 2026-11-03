#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo +1.96.1 build --release --locked --target wasm32-unknown-unknown --manifest-path "$root/dlp-engine/Cargo.toml"
mkdir -p "$root/server/internal/app" "$root/console/public"
for destination in "$root/server/internal/app/dlp_engine.wasm" "$root/console/public/dlp_engine.wasm"; do
  cp "$root/dlp-engine/target/wasm32-unknown-unknown/release/milvago_dlp_engine.wasm" "$destination"
done
