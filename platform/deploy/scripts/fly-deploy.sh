#!/usr/bin/env bash
# Connector OS — Fly.io deploy helper
#
# Usage:
#   ./fly-deploy.sh license      # deploy license server only
#   ./fly-deploy.sh playground   # deploy playground node only
#   ./fly-deploy.sh all          # deploy both
#   ./fly-deploy.sh init         # first-time setup (create apps + volumes + PG)
#
# Prerequisites:
#   brew install flyctl  OR  curl -L https://fly.io/install.sh | sh
#   fly auth login

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DEPLOY_DIR}/../.." && pwd)"

LICENSE_APP="connector-license"
PLAYGROUND_APP="connector-playground"
REGION="iad"

info()  { echo "[fly-deploy] $*"; }
die()   { echo "[fly-deploy] ERROR: $*" >&2; exit 1; }

require_flyctl() {
    command -v fly &>/dev/null || die "flyctl not found. Install: curl -L https://fly.io/install.sh | sh"
    fly auth whoami &>/dev/null || die "Not logged in. Run: fly auth login"
}

init() {
    require_flyctl
    info "=== First-time setup ==="

    # ── License app ───────────────────────────────────────────────────────────
    info "Creating license app..."
    fly apps create "$LICENSE_APP" --org personal 2>/dev/null || info "App already exists"

    info "Creating keys volume (1GB, persistent)..."
    fly volumes create connector_keys \
        --region "$REGION" \
        --size 1 \
        -a "$LICENSE_APP" 2>/dev/null || info "Volume already exists"

    # ── Postgres: use Neon (see deploy-control-plane.sh secrets). Skip Fly PG by default.
    if [[ "${USE_FLY_POSTGRES:-0}" == "1" ]]; then
        info "Creating Fly Postgres cluster..."
        fly postgres create \
            --name connector-pg \
            --region "$REGION" \
            --vm-size shared-cpu-1x \
            --volume-size 10 \
            --initial-cluster-size 1 2>/dev/null || info "PG cluster already exists"
        fly postgres attach connector-pg -a "$LICENSE_APP" 2>/dev/null || info "Already attached"
    else
        info "Skipping Fly Postgres (set DATABASE_URL via Neon in deploy-control-plane.sh secrets)"
    fi

    # ── Playground app ────────────────────────────────────────────────────────
    info "Creating playground app..."
    fly apps create "$PLAYGROUND_APP" --org personal 2>/dev/null || info "App already exists"

    info "Creating playground data volume..."
    fly volumes create playground_data \
        --region "$REGION" \
        --size 5 \
        -a "$PLAYGROUND_APP" 2>/dev/null || info "Volume already exists"

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Init complete. Now set secrets:"
    echo ""
    echo "  fly secrets set -a $LICENSE_APP \\"
    echo "    CONNECTOR_LICENSE_ADMIN_KEY=\"\$(openssl rand -hex 32)\" \\"
    echo "    STRIPE_SECRET_KEY=\"sk_live_...\" \\"
    echo "    STRIPE_WEBHOOK_SECRET=\"whsec_...\" \\"
    echo "    SENDGRID_API_KEY=\"SG....\" \\"
    echo "    STRIPE_PRICE_COMMUNITY=\"price_...\" \\"
    echo "    STRIPE_PRICE_STARTUP=\"price_...\" \\"
    echo "    STRIPE_PRICE_PROFESSIONAL=\"price_...\" \\"
    echo "    STRIPE_PRICE_ENTERPRISE=\"price_...\""
    echo ""
    echo "  Then run: ./fly-deploy.sh all"
    echo "═══════════════════════════════════════════════════════════════"
}

deploy_license() {
    require_flyctl
    info "Deploying license server (build context: repo root)..."
    cd "$REPO_ROOT"
    fly deploy \
        --config "${DEPLOY_DIR}/fly.license.toml" \
        --remote-only \
        -a "$LICENSE_APP" \
        "$REPO_ROOT"
    info "License server deployed: https://${LICENSE_APP}.fly.dev"
}

build_playground_binary() {
    info "Building operator dashboard (embedded in connector-platform)…"
    if command -v trunk >/dev/null; then
        make -C "${REPO_ROOT}/platform/ui-leptos" build-dashboard
    else
        info "trunk not found — skipping dashboard rebuild (using existing dist if present)"
    fi

    mkdir -p "${DEPLOY_DIR}/artifacts"
    local out="${DEPLOY_DIR}/artifacts/connector-platform"
    local target_dir="${DEPLOY_DIR}/playground-target"

    # ALWAYS build inside rust:1.88-slim-bookworm to match the runtime image GLIBC (2.36).
    # Building on the host (Ubuntu 24.04 = GLIBC 2.39) produces a binary that crashes on Fly.
    info "Building connector-platform in Docker (rust:1.88-slim-bookworm — matches Fly runtime glibc 2.36)…"
    command -v docker >/dev/null || die "docker is required for the playground build"

    docker run --rm \
        -v "${REPO_ROOT}:/workspace" \
        -w /workspace \
        rust:1.88-slim-bookworm \
        bash -c "
            apt-get update -qq && \
            apt-get install -y --no-install-recommends pkg-config libssl-dev 2>/dev/null && \
            cd platform/server && \
            CARGO_TARGET_DIR=/workspace/platform/deploy/playground-target \
            CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} \
            cargo build --profile docker --locked --bin connector-platform
        "

    cp "${target_dir}/docker/connector-platform" "$out"
    chmod 755 "$out"
    [[ -f "$out" ]] || die "connector-platform artifact missing at $out"
    info "Binary ready: $out ($(du -h "$out" | cut -f1))"
}

deploy_playground() {
    require_flyctl
    cd "$REPO_ROOT"

    if [[ "${PLAYGROUND_REMOTE_BUILD:-0}" == "1" ]]; then
        info "Deploying playground (remote Rust build — may OOM on Depot)…"
        local dockerignore_backup=""
        if [[ -f .dockerignore ]]; then
            dockerignore_backup="$(mktemp)"
            cp .dockerignore "$dockerignore_backup"
        fi
        cp "${DEPLOY_DIR}/dockerignore.playground" .dockerignore
        fly deploy \
            --config "${DEPLOY_DIR}/fly.playground.toml" \
            --dockerfile "${DEPLOY_DIR}/Dockerfile.playground" \
            --ignorefile "${DEPLOY_DIR}/dockerignore.playground" \
            --remote-only \
            -a "$PLAYGROUND_APP" \
            "$REPO_ROOT"
        if [[ -n "$dockerignore_backup" ]]; then
            mv "$dockerignore_backup" .dockerignore
        else
            rm -f .dockerignore
        fi
    else
        # Unified image: manifest UI + connector-platform + tracetramp + witnessctl.
        # Binaries MUST be built in rust:1.88-slim-bookworm (see scripts/build-and-deploy.sh).
        info "Delegating to scripts/build-and-deploy.sh (UI release + bookworm binaries + unified deploy)…"
        exec "${REPO_ROOT}/scripts/build-and-deploy.sh"
    fi
    info "Playground deployed: https://${PLAYGROUND_APP}.fly.dev"
}

case "${1:-help}" in
    init)        init ;;
    license)     deploy_license ;;
    playground)  deploy_playground ;;
    all)         deploy_license; deploy_playground ;;
    *)
        echo "Usage: $0 {init|license|playground|all}"
        exit 1
        ;;
esac
