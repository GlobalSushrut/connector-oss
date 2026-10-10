#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Connector Platform — OPTIONAL license-coupled installer (not the default path)
#
# For boring self-host Linux install (no license server required):
#   1. make package   (or download connector-os-*.tar.gz + SHA256SUMS)
#   2. tar -xzf … && sudo ./install.sh   # install-from-tarball inside the archive
#   3. systemctl enable --now connector-platform
#   See: platform/deploy/PACKAGING.md and docs/SELFHOST_LINUX.md
#
# This script additionally installs connector-license-server and Requires= it.
# Only use when you intentionally run a paid/activation topology.
#
# Usage (with options):
#   CONNECTOR_VERSION=1.2.3 \
#   CONNECTOR_DATA_DIR=/opt/connector/data \
#   CONNECTOR_LICENSE_SERVER=https://license.connector.dev \
#   bash install.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

if [[ "${CONNECTOR_INSTALL_ALLOW_LICENSE_COUPLED:-}" != "1" ]]; then
  cat >&2 <<'EOF'
install.sh: refused — this path couples the node to connector-license.service.

Self-host (recommended):
  make package
  tar -xzf dist/connector-os-*-linux.tar.gz
  cd connector-os-*/
  sudo ./install.sh
  sudo systemctl enable --now connector-platform

To force this license-coupled installer:
  CONNECTOR_INSTALL_ALLOW_LICENSE_COUPLED=1 bash platform/deploy/install.sh

Docs: docs/SELFHOST_LINUX.md
EOF
  exit 2
fi

# ── Configuration ─────────────────────────────────────────────────────────────
VERSION="${CONNECTOR_VERSION:-latest}"
INSTALL_DIR="${CONNECTOR_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${CONNECTOR_DATA_DIR:-/var/lib/connector}"
LICENSE_DATA_DIR="${CONNECTOR_LICENSE_DATA_DIR:-/var/lib/connector-license}"
LICENSE_SERVER="${CONNECTOR_LICENSE_SERVER:-https://license.connector.dev}"
SERVICE_USER="${CONNECTOR_SERVICE_USER:-connector}"
RELEASE_BASE="https://releases.connector.dev"
UI_DIR="${CONNECTOR_UI_DIR:-$DATA_DIR/ui}"
VENDOR_DIR="${CONNECTOR_VENDOR_DIR:-$DATA_DIR/vendor}"
DOCKER_MODE=false

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --docker) DOCKER_MODE=true ;;
        --help)
            echo "Usage: install.sh [--docker] [--help]"
            echo "Env vars: CONNECTOR_VERSION, CONNECTOR_DATA_DIR, CONNECTOR_LICENSE_SERVER"
            exit 0 ;;
    esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}→${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC}  $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }
banner()  { echo -e "${BOLD}$*${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
banner "╔══════════════════════════════════════════════════╗"
banner "║  Connector Platform — Production Installer       ║"
banner "║  Vault-style RPC Auth · Unique Binary Identity   ║"
banner "║  Distroless Docker · Hardened systemd            ║"
banner "╚══════════════════════════════════════════════════╝"
echo ""

# ── Detect platform ───────────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64)          ARCH="x86_64-unknown-linux-musl" ;;
    aarch64|arm64)   ARCH="aarch64-unknown-linux-musl" ;;
    *) error "Unsupported architecture: $ARCH_RAW" ;;
esac

info "Platform: $OS / $ARCH_RAW"
info "Version:  $VERSION"
info "Data dir: $DATA_DIR"
info "License:  $LICENSE_DATA_DIR"
echo ""

# ── Docker mode ───────────────────────────────────────────────────────────────
if [ "$DOCKER_MODE" = true ]; then
    error "Docker Compose install path was removed with platform/deploy/docker-compose.yml (Phase 0.7). Use bare-metal install below, or connectorctl / microVM per CONNECTOR_OS_ROADMAP.md."
fi

# ── Bare-metal installation ───────────────────────────────────────────────────

# Check root/sudo
SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
        info "Will use sudo for privileged operations"
    else
        error "Run as root or install sudo"
    fi
fi

# ── Create dedicated service user ─────────────────────────────────────────────
info "Creating service user '$SERVICE_USER'..."
if ! id "$SERVICE_USER" &>/dev/null; then
    $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "Connector Platform Service" "$SERVICE_USER"
    success "User '$SERVICE_USER' created"
else
    info "User '$SERVICE_USER' already exists"
fi

# ── Create data directories ───────────────────────────────────────────────────
for DIR in "$DATA_DIR" "$UI_DIR" "$VENDOR_DIR" "$LICENSE_DATA_DIR" "$LICENSE_DATA_DIR/keys"; do
    if [ ! -d "$DIR" ]; then
        $SUDO mkdir -p "$DIR"
        success "Created $DIR"
    fi
done

# Set permissions — service user owns data, keys are 700
$SUDO chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$VENDOR_DIR" "$LICENSE_DATA_DIR"
$SUDO chmod 750 "$DATA_DIR" "$VENDOR_DIR" "$LICENSE_DATA_DIR"
$SUDO chmod 700 "$LICENSE_DATA_DIR/keys"

# ── Download binaries ─────────────────────────────────────────────────────────
download() {
    local url="$1" dest="$2" checksum_url="${1}.sha256"
    local tmp="$(mktemp)"

    info "Downloading $(basename "$dest")..."

    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$tmp"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$tmp"
    else
        error "curl or wget required"
    fi

    # Checksum verification
    if command -v curl &>/dev/null; then
        local expected
        expected="$(curl -fsSL "$checksum_url" 2>/dev/null | awk '{print $1}')" || true
        if [ -n "$expected" ]; then
            local actual
            actual="$(sha256sum "$tmp" | awk '{print $1}')"
            if [ "$actual" != "$expected" ]; then
                rm -f "$tmp"
                error "Checksum mismatch for $(basename "$dest"). Expected: $expected Got: $actual"
            fi
            success "Checksum verified: $actual"
        else
            warn "Could not fetch checksum — skipping verification"
        fi
    fi

    chmod +x "$tmp"
    $SUDO mv "$tmp" "$dest"
    $SUDO chown root:root "$dest"
    $SUDO chmod 755 "$dest"
    success "Installed $(basename "$dest") → $dest"
}

PLATFORM_URL="$RELEASE_BASE/$VERSION/connector-platform-$ARCH"
LICENSE_URL="$RELEASE_BASE/$VERSION/connector-license-server-$ARCH"
CTL_URL="$RELEASE_BASE/$VERSION/connectorctl-$ARCH"

download "$PLATFORM_URL"  "$INSTALL_DIR/connector-platform"
download "$LICENSE_URL"   "$INSTALL_DIR/connector-license-server"
download "$CTL_URL"       "$INSTALL_DIR/connectorctl"

# Optional vendored microVM assets (Phase 5.3.1/5.3.2)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_VENDOR_FIRECRACKER="$SCRIPT_DIR/../../vendor/firecracker"
REPO_VENDOR_MICROVM="$SCRIPT_DIR/../../vendor/microvm"
if [ -d "$REPO_VENDOR_FIRECRACKER" ] || [ -d "$REPO_VENDOR_MICROVM" ]; then
    info "Installing vendored microVM assets..."
    if [ -d "$REPO_VENDOR_FIRECRACKER" ]; then
        $SUDO mkdir -p "$VENDOR_DIR/firecracker"
        $SUDO cp -r "$REPO_VENDOR_FIRECRACKER/"* "$VENDOR_DIR/firecracker/" || true
    fi
    if [ -d "$REPO_VENDOR_MICROVM" ]; then
        $SUDO mkdir -p "$VENDOR_DIR/microvm"
        $SUDO cp -r "$REPO_VENDOR_MICROVM/"* "$VENDOR_DIR/microvm/" || true
    fi
    $SUDO chown -R "$SERVICE_USER:$SERVICE_USER" "$VENDOR_DIR"
    success "Vendored microVM assets staged at $VENDOR_DIR"
else
    warn "No local vendor/firecracker or vendor/microvm tree found next to installer"
fi

if [ -d "$(dirname "$0")/../ui-leptos/dashboard/dist" ]; then
    info "Installing dashboard UI..."
    $SUDO cp -r "$(dirname "$0")/../ui-leptos/dashboard/dist/"* "$UI_DIR/"
    $SUDO chown -R "$SERVICE_USER:$SERVICE_USER" "$UI_DIR"
    success "Installed dashboard UI → $UI_DIR"
else
    warn "Dashboard UI bundle not found next to installer; the node will run, but / will mount only after UI assets are installed at $UI_DIR"
fi

# ── Systemd: License Server ───────────────────────────────────────────────────
info "Installing connector-license systemd service..."
$SUDO tee /etc/systemd/system/connector-license.service > /dev/null << EOF
[Unit]
Description=Connector License Server
Documentation=https://docs.connector.dev/deployment
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER

ExecStart=$INSTALL_DIR/connector-license-server
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# ── Data directory ────────────────────────────────────────────────────────
Environment=CONNECTOR_LICENSE_DATA_DIR=$LICENSE_DATA_DIR
Environment=CONNECTOR_LICENSE_ADDR=127.0.0.1:4100
Environment=RUST_LOG=warn

# Stripe secrets — set via override or environment file
# Create: systemctl edit connector-license
# Add:
#   [Service]
#   Environment=STRIPE_SECRET_KEY=sk_live_...
#   Environment=STRIPE_WEBHOOK_SECRET=whsec_...
EnvironmentFile=-/etc/connector/license.env

# ── Security hardening ────────────────────────────────────────────────────
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LICENSE_DATA_DIR
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
success "connector-license.service installed"

# ── Systemd: Platform ─────────────────────────────────────────────────────────
info "Installing connector-platform systemd service..."
$SUDO tee /etc/systemd/system/connector-platform.service > /dev/null << EOF
[Unit]
Description=Connector Platform — Agent OS
Documentation=https://docs.connector.dev/deployment
After=network-online.target connector-license.service
Wants=network-online.target
Requires=connector-license.service

[Service]
Type=notify
NotifyAccess=main
User=$SERVICE_USER
Group=$SERVICE_USER

ExecStart=$INSTALL_DIR/connector-platform
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
WatchdogSec=60
SuccessExitStatus=143

# ── Runtime environment ───────────────────────────────────────────────────
Environment=CONNECTOR_ENV=production
Environment=CONNECTOR_DATA_DIR=$DATA_DIR
Environment=CONNECTOR_PORT=9091
Environment=CONNECTOR_HOST=0.0.0.0
Environment=CONNECTOR_UI_DIR=$UI_DIR
Environment=CONNECTOR_LICENSE_SERVER=http://127.0.0.1:4100
Environment=CONNECTOR_VENDOR_DIR=$VENDOR_DIR
Environment=CONNECTOR_OFFLINE_GRACE_SECS=259200
Environment=RUST_LOG=warn

# License identity — set after activation:
#   systemctl edit connector-platform
# Add:
#   [Service]
#   Environment=CONNECTOR_KEY_ID=key_abc123
#   Environment=CONNECTOR_INSTANCE_ID=inst_xyz789
#   Environment=CONNECTOR_TIER=Enterprise
EnvironmentFile=-/etc/connector/platform.env
EnvironmentFile=-/etc/connector/env

# ── Security hardening ────────────────────────────────────────────────────
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DATA_DIR
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
success "connector-platform.service installed"

# ── Environment files ─────────────────────────────────────────────────────────
$SUDO mkdir -p /etc/connector
$SUDO chmod 750 /etc/connector
$SUDO chown root:"$SERVICE_USER" /etc/connector

# Create placeholder env files if not present
if [ ! -f /etc/connector/license.env ]; then
    $SUDO tee /etc/connector/license.env > /dev/null << 'EOF'
# Connector License Server — Secrets
# Fill in after Stripe account setup
# STRIPE_SECRET_KEY=sk_live_...
# STRIPE_WEBHOOK_SECRET=whsec_...
EOF
    $SUDO chmod 640 /etc/connector/license.env
    $SUDO chown root:"$SERVICE_USER" /etc/connector/license.env
fi

if [ ! -f /etc/connector/platform.env ]; then
    $SUDO tee /etc/connector/platform.env > /dev/null << 'EOF'
# Connector Platform — License Identity
# Set these after running: connector-license-server issue-key
# CONNECTOR_KEY_ID=
# CONNECTOR_INSTANCE_ID=
# CONNECTOR_TIER=Community
EOF
    $SUDO chmod 640 /etc/connector/platform.env
    $SUDO chown root:"$SERVICE_USER" /etc/connector/platform.env
fi

# ── Enable and start services ─────────────────────────────────────────────────
$SUDO systemctl daemon-reload
$SUDO systemctl enable connector-license connector-platform

info "Starting connector-license..."
$SUDO systemctl start connector-license

# Wait for license server to be healthy
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    if curl -sf http://127.0.0.1:4100/health &>/dev/null; then
        success "License server healthy"
        break
    fi
    if [ "$i" -eq "$MAX_WAIT" ]; then
        warn "License server not responding after ${MAX_WAIT}s"
        warn "Check logs: journalctl -u connector-license -n 50"
    fi
    sleep 1
done

info "Starting connector-platform..."
$SUDO systemctl start connector-platform

# ── Post-install ──────────────────────────────────────────────────────────────
echo ""
banner "══════════════════════════════════════════════════"
success "Installation complete!"
banner "══════════════════════════════════════════════════"
echo ""
info "Service status:"
echo "  systemctl status connector-license connector-platform"
echo ""
info "Connector OS commands:"
echo "  connectorctl version"
echo "  connectorctl help"
echo "  connectorctl status"
echo ""
info "Health checks:"
echo "  curl http://127.0.0.1:4100/health   # License server"
echo "  curl http://127.0.0.1:9091/health   # Platform"
echo "  open http://127.0.0.1:9091/         # Dashboard"
echo ""
info "Logs:"
echo "  journalctl -fu connector-license"
echo "  journalctl -fu connector-platform"
echo ""

# ── Key backup reminder ───────────────────────────────────────────────────────
echo ""
warn "════════════════════════════════════════════════════════"
warn "  CRITICAL: Back up your Ed25519 signing key NOW"
warn "════════════════════════════════════════════════════════"
warn ""
warn "  Location: $LICENSE_DATA_DIR/keys/signing.key"
warn "  This key signs ALL issued licenses."
warn "  Losing it makes every issued license unverifiable."
warn ""
warn "  Back up to a secrets manager BEFORE going to production:"
warn ""
warn "  # AWS Secrets Manager:"
warn "  aws secretsmanager create-secret \\"
warn "    --name connector/license-signing-key \\"
warn "    --secret-binary fileb://$LICENSE_DATA_DIR/keys/signing.key"
warn ""
warn "  # Or export the public key (for embedding in binaries):"
warn "  curl -s http://127.0.0.1:4100/api/v1/public-key | jq .public_key_hex"
warn ""
warn "  Add the public key hex to server/.license-seed before each binary build."
warn "════════════════════════════════════════════════════════"
echo ""

# ── Activation guide ──────────────────────────────────────────────────────────
info "Next steps — activate your license:"
echo ""
echo "  1. Set Stripe credentials:"
echo "     sudo nano /etc/connector/license.env"
echo "     sudo systemctl restart connector-license"
echo ""
echo "  2. Issue a license key (admin):"
echo "     curl -X POST http://127.0.0.1:4100/api/v1/keys/issue \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"tier\":\"Startup\",\"customer_email\":\"you@example.com\",\"customer_name\":\"You\"}'"
echo ""
echo "  3. Create a binary issuance (per-download identity stamp):"
echo "     curl -X POST http://127.0.0.1:4100/api/v1/issuances \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"key_id\":\"<key_id_from_step2>\"}'"
echo "     # Returns: {binary_id, role_id, secret_id}"
echo ""
echo "  4. Set identity in platform env:"
echo "     sudo nano /etc/connector/platform.env"
echo "     # Set CONNECTOR_KEY_ID, CONNECTOR_TIER"
echo "     sudo systemctl restart connector-platform"
echo ""
echo "  5. Platform auto-authenticates via POST /rpc/v1/auth on startup"
echo "     RPC token issued (1h TTL), renewed automatically"
echo ""
info "Docs: https://docs.connector.dev/deployment"
echo ""
