#!/bin/bash
# Playground build + deploy — bookworm-compatible binaries for Fly (glibc 2.36).
#
# NEVER copy a host-built connector-platform into artifacts/; Ubuntu 24.04 links
# against GLIBC 2.39 and the binary will not start on debian:bookworm-slim.
#
# Usage: ./scripts/build-and-deploy.sh
set -euo pipefail

APP_NAME="connector-playground"
FLY_CONFIG="platform/deploy/fly.playground.toml"
ARTIFACTS_DIR="platform/deploy/artifacts"
TARGET_DIR="platform/deploy/playground-target"
RUST_IMAGE="rust:1.88-slim-bookworm"
JOBS="${CARGO_BUILD_JOBS:-4}"

die() { echo "build-and-deploy: ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
command -v flyctl >/dev/null || flyctl version >/dev/null 2>&1 || die "flyctl is required"

# ═════════════════════════════════════════════════════════════════════════════
# Step 1: Playground UI release (dashboard split + trial-app + manifest)
# ═════════════════════════════════════════════════════════════════════════════
echo "🎨 Building playground UI release..."
UI_DIR="platform/ui-leptos/dashboard"
(
  cd "$UI_DIR"
  python3 ./scripts/build_release.py --profile playground
  python3 ./scripts/verify_release.py
)

# ═════════════════════════════════════════════════════════════════════════════
# Step 2: Compile all binaries inside rust:1.88-slim-bookworm (matches Fly runtime)
# ═════════════════════════════════════════════════════════════════════════════
echo "🔨 Building binaries in ${RUST_IMAGE} (CARGO_TARGET_DIR=${TARGET_DIR})..."
mkdir -p "$ARTIFACTS_DIR" "$TARGET_DIR"

docker run --rm \
  -v "$(pwd):/repo" \
  -w /repo \
  "$RUST_IMAGE" \
  bash -c "
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq pkg-config libssl-dev protobuf-compiler
    export CARGO_TARGET_DIR=/repo/${TARGET_DIR}
    export CARGO_BUILD_JOBS=${JOBS}
    cargo build --manifest-path platform/server/Cargo.toml \
      --profile docker --locked --bin connector-platform
    cargo build --manifest-path plugins/tracetramp/Cargo.toml \
      --release --locked --bin tracetramp
    cargo build --manifest-path plugins/witnessctl/Cargo.toml \
      --release --locked --bin witnessctl
    ls -la \"\${CARGO_TARGET_DIR}/docker/connector-platform\"
    ls -la \"\${CARGO_TARGET_DIR}/release/tracetramp\"
    ls -la \"\${CARGO_TARGET_DIR}/release/witnessctl\"
  "

# ═════════════════════════════════════════════════════════════════════════════
# Step 3: Stage artifacts + verify glibc on bookworm runtime image
# ═════════════════════════════════════════════════════════════════════════════
echo "📦 Staging artifacts..."
cp "${TARGET_DIR}/docker/connector-platform" "${ARTIFACTS_DIR}/connector-platform"
cp "${TARGET_DIR}/release/tracetramp" "${ARTIFACTS_DIR}/tracetramp"
cp "${TARGET_DIR}/release/witnessctl" "${ARTIFACTS_DIR}/witnessctl"
chmod 755 "${ARTIFACTS_DIR}/connector-platform" "${ARTIFACTS_DIR}/tracetramp" "${ARTIFACTS_DIR}/witnessctl"

echo "🔍 Verifying GLIBC compatibility on debian:bookworm-slim..."
docker run --rm \
  -v "$(pwd)/${ARTIFACTS_DIR}:/artifacts:ro" \
  debian:bookworm-slim \
  bash -c "
    set -e
    ldd /artifacts/connector-platform >/dev/null
    ldd /artifacts/tracetramp >/dev/null
    ldd /artifacts/witnessctl >/dev/null
    /artifacts/connector-platform --version 2>/dev/null || true
  " || die "binary failed bookworm ldd check — do not deploy"

ls -la "${ARTIFACTS_DIR}/"

# ═════════════════════════════════════════════════════════════════════════════
# Step 4: Deploy unified playground image (supervisord + UI release)
# ═════════════════════════════════════════════════════════════════════════════
echo "🚀 Deploying to Fly (${APP_NAME})..."
flyctl deploy --config "$FLY_CONFIG" -a "$APP_NAME" --yes

echo "✅ Deploy complete."
echo "   Verify: curl -s https://try.cnktros.com/trial | rg '<title>|connector-trial'"
