#!/usr/bin/env bash
# Install the latest prebuilt Connector node from GitHub. No compiler.
#
#   curl -fsSL https://raw.githubusercontent.com/GlobalSushrut/connector-oss/main/platform/release/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --system
#
# Default: ~/.connector and ~/.local/bin
# --system: /usr/local/bin (uses sudo when needed)
#
# Each push to main replaces the GitHub release tagged "prebuilt".
set -euo pipefail

REPO="${CONNECTOR_GITHUB_REPO:-GlobalSushrut/connector-oss}"
TAG="${CONNECTOR_RELEASE_TAG:-prebuilt}"
SYSTEM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) SYSTEM=1; shift ;;
    --repo) REPO="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    -h|--help)
      echo "usage: install.sh [--system] [--repo owner/name] [--tag prebuilt]"
      exit 0
      ;;
    *) echo "install: unknown argument: $1" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
ARCH_RAW="$(uname -m)"
if [[ "$OS" != "Linux" ]]; then
  echo "install: prebuilt tarballs are Linux only (this machine is $OS)." >&2
  exit 1
fi
case "$ARCH_RAW" in
  x86_64) ARCH=x86_64 ;;
  *)
    echo "install: prebuilt tarballs are published for Linux x86_64 only (this machine is $OS/$ARCH_RAW)." >&2
    exit 1
    ;;
esac

ASSET="connector-os-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/connector-install.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "install: downloading ${ASSET} from ${REPO} (${TAG})"
if ! curl -fL --retry 3 --retry-delay 2 "${BASE}/${ASSET}" -o "${TMP}/${ASSET}"; then
  echo "install: download failed." >&2
  echo "install: the tarball is published by GitHub Actions after each push to main." >&2
  echo "install: see https://github.com/${REPO}/releases/tag/${TAG}" >&2
  exit 1
fi
if ! curl -fL --retry 3 --retry-delay 2 "${BASE}/${ASSET}.sha256" -o "${TMP}/${ASSET}.sha256"; then
  echo "install: checksum download failed" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP" && sha256sum -c "${ASSET}.sha256")
elif command -v shasum >/dev/null 2>&1; then
  expected="$(awk '{print $1}' "${TMP}/${ASSET}.sha256")"
  actual="$(shasum -a 256 "${TMP}/${ASSET}" | awk '{print $1}')"
  if [[ "$expected" != "$actual" ]]; then
    echo "install: checksum mismatch" >&2
    exit 1
  fi
else
  echo "install: sha256sum or shasum is required" >&2
  exit 1
fi

tar -xzf "${TMP}/${ASSET}" -C "$TMP"
ROOT_DIR="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'connector-os-*' | head -1)"
if [[ -z "$ROOT_DIR" ]]; then
  echo "install: tarball has no connector-os directory" >&2
  exit 1
fi
test -x "$ROOT_DIR/bin/connector-platform"
test -x "$ROOT_DIR/bin/connectorctl"

COMMIT="unknown"
if [[ -f "$ROOT_DIR/COMMIT" ]]; then
  COMMIT="$(tr -d '[:space:]' < "$ROOT_DIR/COMMIT")"
fi

install_tree() {
  local bin_dir="$1"
  local home_dir="$2"
  local ui_dir="$3"
  local config="$4"
  local ui_export=""
  mkdir -p "$bin_dir" "$home_dir/bin" "$home_dir/data" "$(dirname "$config")"
  install -m755 "$ROOT_DIR/bin/connector-platform" "$home_dir/bin/connector-platform"
  install -m755 "$ROOT_DIR/bin/connectorctl" "$home_dir/bin/connectorctl"
  if [[ -d "$ROOT_DIR/ui" && -n "$ui_dir" ]]; then
    rm -rf "$ui_dir"
    mkdir -p "$ui_dir"
    cp -a "$ROOT_DIR/ui/." "$ui_dir/"
    ui_export="export CONNECTOR_UI_DIR=\"\${CONNECTOR_UI_DIR:-$ui_dir}\""
  fi
  if [[ ! -f "$config" ]]; then
    install -m644 "$ROOT_DIR/etc/connector.yaml.example" "$config"
  fi
  {
    echo '#!/bin/sh'
    echo "export CONNECTOR_DATA_DIR=\"\${CONNECTOR_DATA_DIR:-$home_dir/data}\""
    echo "export CONNECTOR_CONFIG_FILE=\"\${CONNECTOR_CONFIG_FILE:-$config}\""
    if [[ -n "$ui_export" ]]; then
      echo "$ui_export"
    fi
    echo "exec \"$home_dir/bin/connector-platform\" \"\$@\""
  } > "$bin_dir/connector-platform"
  {
    echo '#!/bin/sh'
    echo "export CONNECTOR_DATA_DIR=\"\${CONNECTOR_DATA_DIR:-$home_dir/data}\""
    echo "export CONNECTOR_CONFIG_FILE=\"\${CONNECTOR_CONFIG_FILE:-$config}\""
    echo "exec \"$home_dir/bin/connectorctl\" \"\$@\""
  } > "$bin_dir/connectorctl"
  chmod 755 "$bin_dir/connector-platform" "$bin_dir/connectorctl"
}

if [[ "$(id -u)" -eq 0 ]]; then
  SYSTEM=1
fi

if [[ "$SYSTEM" == "1" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "install: --system needs root. Run:" >&2
    echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/platform/release/install.sh | sudo bash -s -- --system" >&2
    exit 1
  fi
  install_tree /usr/local/bin /var/lib/connector /var/lib/connector/ui /etc/connector/connector.yaml
  echo "install: system binaries are on PATH (/usr/local/bin)"
else
  install_tree "${HOME}/.local/bin" "${HOME}/.connector" "${HOME}/.connector/ui" "${HOME}/.connector/connector.yaml"
  echo "install: user binaries are in ${HOME}/.local/bin"
  case ":$PATH:" in
    *":${HOME}/.local/bin:"*) ;;
    *)
      echo "install: add this to your shell profile if connector-platform is not found:"
      echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
      ;;
  esac
fi

echo "install: commit ${COMMIT}"
echo "install: start with:  connector-platform"
echo "install: dashboard:   http://127.0.0.1:9091/"
