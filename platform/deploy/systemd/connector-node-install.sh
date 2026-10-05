#!/bin/bash
# Connector Node — Installation Script
#
# This script sets up the Connector Node as a systemd service.
# Run as root or with sudo.
#
# Usage: sudo ./connector-node-install.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Connector Node — Installation${NC}"
echo "════════════════════════════════════════════════════════════════"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./connector-node-install.sh)${NC}"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────
# 1. Create connector user
# ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/6]${NC} Creating connector user..."
if id "connector" &>/dev/null; then
    echo "  User 'connector' already exists"
else
    useradd -r -s /bin/false -d /var/lib/connector connector
    echo "  Created user 'connector'"
fi

# ─────────────────────────────────────────────────────────────────
# 2. Create directories
# ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/6]${NC} Creating directories..."

mkdir -p /var/lib/connector
mkdir -p /var/lib/connector/keys
mkdir -p /var/log/connector
mkdir -p /etc/connector

chown -R connector:connector /var/lib/connector
chown -R connector:connector /var/log/connector
chmod 750 /var/lib/connector
chmod 750 /var/log/connector
chmod 700 /var/lib/connector/keys

echo "  /var/lib/connector (data)"
echo "  /var/log/connector (logs)"
echo "  /etc/connector (config)"

# ─────────────────────────────────────────────────────────────────
# 3. Install binary
# ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/6]${NC} Installing binary..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH=""

# Look for binary in common locations
if [ -f "$SCRIPT_DIR/../../target/release/connector-platform" ]; then
    BINARY_PATH="$SCRIPT_DIR/../../target/release/connector-platform"
elif [ -f "$SCRIPT_DIR/connector-node" ]; then
    BINARY_PATH="$SCRIPT_DIR/connector-node"
elif [ -f "/tmp/connector-node" ]; then
    BINARY_PATH="/tmp/connector-node"
fi

if [ -n "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" /usr/bin/connector-node
    chmod 755 /usr/bin/connector-node
    echo "  Installed /usr/bin/connector-node"
else
    echo -e "${YELLOW}  Warning: Binary not found. Install manually:${NC}"
    echo "    cp /path/to/connector-platform /usr/bin/connector-node"
fi

# Install connectorctl CLI to /usr/local/bin so it is in PATH after boot
CTL_PATH=""
if [ -f "$SCRIPT_DIR/../../target/release/connectorctl" ]; then
    CTL_PATH="$SCRIPT_DIR/../../target/release/connectorctl"
elif [ -f "$SCRIPT_DIR/connectorctl" ]; then
    CTL_PATH="$SCRIPT_DIR/connectorctl"
fi

if [ -n "$CTL_PATH" ]; then
    cp "$CTL_PATH" /usr/local/bin/connectorctl
    chmod 755 /usr/local/bin/connectorctl
    echo "  Installed /usr/local/bin/connectorctl  (now in PATH — run: connectorctl status)"
else
    echo -e "${YELLOW}  Warning: connectorctl binary not found. Install manually:${NC}"
    echo "    cp /path/to/connectorctl /usr/local/bin/connectorctl"
fi

# ─────────────────────────────────────────────────────────────────
# 4. Install systemd service
# ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/6]${NC} Installing systemd service..."

cp "$SCRIPT_DIR/connector-node.service" /etc/systemd/system/
chmod 644 /etc/systemd/system/connector-node.service
systemctl daemon-reload

echo "  Installed /etc/systemd/system/connector-node.service"

# ─────────────────────────────────────────────────────────────────
# 5. Create default config
# ─────────────────────────────────────────────────────────────────
# Install dashboard UI files to the data directory so the server finds them
# at the correct absolute path when WorkingDirectory=/var/lib/connector
UI_SOURCE="$SCRIPT_DIR/../../ui-leptos/dashboard/dist"
UI_DEST="/var/lib/connector/ui"
if [ -d "$UI_SOURCE" ]; then
    mkdir -p "$UI_DEST"
    cp -r "$UI_SOURCE/"* "$UI_DEST/"
    chown -R connector:connector "$UI_DEST"
    echo "  Installed dashboard UI → $UI_DEST"
    echo "  Dashboard will be served at http://localhost:9091/ on next start"
else
    echo -e "${YELLOW}  Warning: UI dist not found at $UI_SOURCE${NC}"
    echo "    Build the dashboard with: cd platform/ui-leptos/dashboard && trunk build --release"
    echo "    Then re-run this installer"
fi

echo -e "${YELLOW}[5/6]${NC} Creating default config..."

if [ ! -f /etc/connector/env ]; then
    cat > /etc/connector/env << 'EOF'
# Connector Node Environment Configuration
# Add your secrets and API keys here.
# This file is loaded by systemd on service start.

# LLM Provider (required for AI features)
# CONNECTOR_LLM_API_KEY=sk-...
# CONNECTOR_LLM_PROVIDER=openai
# CONNECTOR_LLM_MODEL=gpt-4o

# License Key (optional, enables enterprise features)
# CONNECTOR_LICENSE_KEY=lic_...

# Stripe (optional, for billing features)
# STRIPE_SECRET_KEY=sk_live_...

# OpenTelemetry (optional, for distributed tracing)
# OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
EOF
    chmod 600 /etc/connector/env
    chown connector:connector /etc/connector/env
    echo "  Created /etc/connector/env (edit to add API keys)"
else
    echo "  /etc/connector/env already exists (skipped)"
fi

# ─────────────────────────────────────────────────────────────────
# 6. Enable service
# ─────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[6/6]${NC} Enabling service..."

systemctl daemon-reload
systemctl enable --now connector-node
echo "  Service enabled and started (auto-starts on every boot)"
echo
# Wait up to 10s for the service to become healthy
echo "  Waiting for connector-node to become ready..."
for i in $(seq 1 10); do
    if systemctl is-active --quiet connector-node; then
        echo -e "  ${GREEN}connector-node is running${NC}"
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo -e "  ${YELLOW}connector-node did not start within 10s — check logs:${NC}"
        echo "    journalctl -u connector-node -n 30"
    fi
    sleep 1
done

# ─────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════════"
echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Usage (no path needed — connectorctl is now in PATH):"
echo "  connectorctl status           — node status"
echo "  connectorctl health           — quick health check"
echo "  connectorctl logs             — tail logs"
echo "  connectorctl agents           — list running agents"
echo
echo "Service management:"
echo "  sudo systemctl status connector-node"
echo "  sudo systemctl restart connector-node"
echo "  sudo journalctl -fu connector-node"
echo
echo "Config:"
echo "  sudo nano /etc/connector/env  (add API keys, then restart)"
echo
echo "Access:"
echo "  Dashboard: http://localhost:9091/        (UI boots with the service)"
echo "  API:       http://localhost:9091/api/v1"
echo "  Health:    http://localhost:9091/health"
echo
