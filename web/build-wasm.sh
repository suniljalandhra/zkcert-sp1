#!/usr/bin/env bash
# Builds the in-browser proof verifier (verifier/ crate) into web/src/wasm/.
# Needs: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli --version 0.2.130
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p zkcert-verifier --features wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir web/src/wasm \
  target/wasm32-unknown-unknown/release/zkcert_verifier.wasm
echo "wrote web/src/wasm/"
