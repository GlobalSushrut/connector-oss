#!/usr/bin/env bash
# Build the Leptos operator dashboard into platform/ui-leptos/dashboard/dist
# (required for connector-platform to serve GET / unless the Docker image UI stage ran).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/ui-leptos/dashboard"
export PATH="${HOME}/.cargo/bin:${PATH}"
command -v trunk >/dev/null 2>&1 || { echo "Install trunk: cargo install trunk"; exit 1; }
rustup target add wasm32-unknown-unknown 2>/dev/null || true
# Trunk 0.21+: use HTML entry as positional target (not --html).
env -u NO_COLOR -u FORCE_COLOR TRUNK_COLOR=auto trunk build --release --filehash false index.release.html
echo "OK: UI dist at $ROOT/ui-leptos/dashboard/dist (restart connector-platform)"
