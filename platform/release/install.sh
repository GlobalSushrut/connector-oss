#!/usr/bin/env bash
# Connector OS — Official Installer
# Usage:
#   curl -fsSL https://get.cnktros.com/install.sh | bash
#   curl -fsSL https://get.cnktros.com/install.sh | bash -s -- --arch arm64
#   curl -fsSL https://get.cnktros.com/install.sh | bash -s -- --os darwin --arch amd64
#
# What this does:
#   1. Detects your OS and architecture
#   2. Downloads the correct connector tarball
#   3. Installs connector-platform and connectorctl to /usr/local/bin
#   4. Creates a default config at ~/.connector/connector.toml
#   5. (Linux only) Installs a systemd user service
#
# Requirements: curl, tar, sha256sum (or shasum on macOS)
set -euo pipefail

VERSION="0.1.0"
BASE_URL="https://github.com/connector-os/connector-private/releases/download/v${VERSION}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="${HOME}/.connector"
PORTAL="https://portal.cnktros.com"

BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

log()  { echo -e "${BOLD}${GREEN}==>${RESET} $*"; }
info() { echo -e "    ${CYAN}$*${RESET}"; }
warn() { echo -e "    ${YELLOW}warning:${RESET} $*"; }
err()  { echo -e "    ${RED}error:${RESET} $*" >&2; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
OS=""
ARCH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --os)    OS="$2";   shift 2 ;;
    --arch)  ARCH="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

# ── Auto-detect OS ────────────────────────────────────────────────────────────
if [[ -z "$OS" ]]; then
  case "$(uname -s)" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="darwin" ;;
    *) err "Unsupported OS: $(uname -s). Only Linux and macOS are supported." ;;
  esac
fi

# ── Auto-detect arch ──────────────────────────────────────────────────────────
if [[ -z "$ARCH" ]]; then
  case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "Unsupported architecture: $(uname -m). Use --arch amd64 or --arch arm64." ;;
  esac
fi

TARBALL="connector-${VERSION}-${OS}-${ARCH}.tar.gz"
TARBALL_URL="${BASE_URL}/${TARBALL}"
CHECKSUM_URL="${BASE_URL}/${TARBALL}.sha256"

echo ""
echo -e "${BOLD}  Connector OS — Installer v${VERSION}${RESET}"
echo -e "  ${CYAN}https://cnktros.com${RESET}"
echo ""
log "Detected: ${OS}/${ARCH}"
log "Version:  ${VERSION}"
echo ""

# ── Check dependencies ────────────────────────────────────────────────────────
for dep in curl tar; do
  command -v "$dep" &>/dev/null || err "$dep is required but not installed."
done

# ── Download ──────────────────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log "Downloading ${TARBALL}…"
curl -fsSL --progress-bar "${TARBALL_URL}" -o "${TMP_DIR}/${TARBALL}" \
  || err "Download failed. Check your connection or visit ${PORTAL} to download manually."

# ── Verify checksum ───────────────────────────────────────────────────────────
log "Verifying checksum…"
curl -fsSL "${CHECKSUM_URL}" -o "${TMP_DIR}/${TARBALL}.sha256" 2>/dev/null || warn "Checksum file unavailable — skipping verification."
if [[ -f "${TMP_DIR}/${TARBALL}.sha256" ]]; then
  EXPECTED="$(cat "${TMP_DIR}/${TARBALL}.sha256" | awk '{print $1}')"
  if command -v sha256sum &>/dev/null; then
    ACTUAL="$(sha256sum "${TMP_DIR}/${TARBALL}" | awk '{print $1}')"
  else
    ACTUAL="$(shasum -a 256 "${TMP_DIR}/${TARBALL}" | awk '{print $1}')"
  fi
  if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    err "Checksum mismatch! Expected ${EXPECTED}, got ${ACTUAL}. The download may be corrupted."
  fi
  info "Checksum OK"
fi

# ── Extract ───────────────────────────────────────────────────────────────────
log "Extracting…"
tar -xzf "${TMP_DIR}/${TARBALL}" -C "${TMP_DIR}"
EXTRACT_DIR="${TMP_DIR}/connector-${VERSION}"

# ── Install binaries ──────────────────────────────────────────────────────────
log "Installing binaries to ${INSTALL_DIR}…"
if [[ ! -w "${INSTALL_DIR}" ]]; then
  info "Requesting sudo to install to ${INSTALL_DIR}"
  SUDO="sudo"
else
  SUDO=""
fi

$SUDO install -m 755 "${EXTRACT_DIR}/bin/connector-platform" "${INSTALL_DIR}/connector-platform"
$SUDO install -m 755 "${EXTRACT_DIR}/bin/connectorctl"       "${INSTALL_DIR}/connectorctl"
info "connector-platform → ${INSTALL_DIR}/connector-platform"
info "connectorctl       → ${INSTALL_DIR}/connectorctl"

# ── Default config ────────────────────────────────────────────────────────────
mkdir -p "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_DIR}/connector.toml" ]]; then
  cp "${EXTRACT_DIR}/connector.toml.example" "${CONFIG_DIR}/connector.toml"
  info "Config template → ${CONFIG_DIR}/connector.toml"
else
  info "Existing config preserved at ${CONFIG_DIR}/connector.toml"
fi

# ── Systemd service (Linux only) ──────────────────────────────────────────────
if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
  SERVICE_DIR="${HOME}/.config/systemd/user"
  mkdir -p "${SERVICE_DIR}"
  cat > "${SERVICE_DIR}/connector.service" <<EOF
[Unit]
Description=Connector OS Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/connector-platform --config ${CONFIG_DIR}/connector.toml
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload 2>/dev/null || true
  info "Systemd user service → ${SERVICE_DIR}/connector.service"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}  Installation complete!${RESET}"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  ${CYAN}1.${RESET} Add your pilot API key to ${CONFIG_DIR}/connector.toml"
echo -e "     Get your key at ${PORTAL}/app/api-keys"
echo ""
echo -e "  ${CYAN}2.${RESET} Start the node:"
echo -e "     ${BOLD}connector-platform --config ~/.connector/connector.toml${RESET}"
echo -e "     or (with systemd): ${BOLD}systemctl --user start connector${RESET}"
echo ""
echo -e "  ${CYAN}3.${RESET} Open the dashboard:"
echo -e "     ${BOLD}http://localhost:9090${RESET}"
echo ""
echo -e "  ${CYAN}4.${RESET} Connect Cursor / Windsurf / Claude to your node."
echo -e "     Docs: ${PORTAL}/docs/quickstart"
echo ""
