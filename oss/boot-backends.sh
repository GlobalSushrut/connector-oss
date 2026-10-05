#!/usr/bin/env bash
# First boot stage: download and set up the industry tools Connector calls.
# Defaults live in boot.defaults. A later edit is picked up on the next boot.
# This stage does not start the operator UI.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$HERE/../platform/server" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
elif [[ -d "$HERE/platform/server" ]]; then
  ROOT="$HERE"
else
  echo "platform/server was not found" >&2
  exit 2
fi
WORK="${CONNECTOR_OSS_WORK:-/tmp/connector-oss}"
BIN="$WORK/bin"
# shellcheck disable=SC1091
[[ -f "$HERE/boot.defaults" ]] && . "$HERE/boot.defaults"
mkdir -p "$BIN" "$WORK/cosign" "$WORK/spire" "$WORK/agw-config"
chmod 0700 "$WORK"
chmod 0777 "$WORK/agw-config"

retry() {
  local name="$1"
  shift
  local n
  for n in 1 2 3; do
    if "$@"; then
      echo "[ok] $name"
      return 0
    fi
    echo "[retry $n] $name" >&2
    sleep 1
  done
  echo "[not ready] $name" >&2
  return 1
}

fetch() {
  local url="$1" dest="$2" sha="$3"
  if [[ ! -f "$dest" ]] || ! echo "$sha  $dest" | sha256sum -c - >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  fi
  echo "$sha  $dest" | sha256sum -c -
}

setup_cosign() {
  fetch "https://github.com/sigstore/cosign/releases/download/v2.5.3/cosign-linux-amd64" \
    "$BIN/cosign" "783b5d6c74105401c63946c68d9b2a4e1aab3c8abce043e06b8510b02b623ec9"
  chmod +x "$BIN/cosign"
  if [[ ! -f "$WORK/cosign/blob.sig" ]]; then
    printf 'connector-release\n' > "$WORK/cosign/blob"
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-connector-oss}" "$BIN/cosign" generate-key-pair \
      --output-key-prefix "$WORK/cosign/cosign" >/dev/null
    COSIGN_PASSWORD="${COSIGN_PASSWORD:-connector-oss}" "$BIN/cosign" sign-blob --yes \
      --key "$WORK/cosign/cosign.key" \
      --output-signature "$WORK/cosign/blob.sig" "$WORK/cosign/blob" >/dev/null
  fi
  "$BIN/cosign" verify-blob --key "$WORK/cosign/cosign.pub" \
    --signature "$WORK/cosign/blob.sig" "$WORK/cosign/blob" >/dev/null
}

setup_spire() {
  fetch "https://github.com/spiffe/spire/releases/download/v1.15.3/spire-1.15.3-linux-amd64-musl.tar.gz" \
    "$WORK/spire.tgz" "ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7"
  tar -xzf "$WORK/spire.tgz" -C "$WORK"
  local srv agent
  srv="$(find "$WORK" -type f -name spire-server | head -1)"
  agent="$(find "$WORK" -type f -name spire-agent | head -1)"
  ln -sfn "$agent" "$BIN/spire-agent"
  if "$agent" api fetch x509 -socketPath "$WORK/spire/agent.sock" 2>/dev/null | grep -q 'spiffe://'; then
    return 0
  fi
  rm -f "$WORK/spire/server.sock" "$WORK/spire/agent.sock"
  rm -rf "$WORK/spire/agent"
  mkdir -p "$WORK/spire/server" "$WORK/spire/agent"
  local port="${SPIRE_BIND_PORT:-18081}"
  cat > "$WORK/spire/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "$port"
    trust_domain = "connector.local"
    data_dir = "$WORK/spire/server"
    log_level = "WARN"
    socket_path = "$WORK/spire/server.sock"
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "$WORK/spire/server/datastore.sqlite3"
        }
    }
    KeyManager "memory" { plugin_data {} }
    NodeAttestor "join_token" { plugin_data {} }
}
EOF
  setsid "$srv" run -config "$WORK/spire/server.conf" >"$WORK/spire-server.log" 2>&1 < /dev/null &
  local i
  for i in $(seq 1 40); do [[ -S "$WORK/spire/server.sock" ]] && break; sleep 0.25; done
  [[ -S "$WORK/spire/server.sock" ]]
  local token
  token="$("$srv" token generate -socketPath "$WORK/spire/server.sock" -spiffeID spiffe://connector.local/host | awk '/Token:/ {print $2}')"
  cat > "$WORK/spire/agent.conf" <<EOF
agent {
    data_dir = "$WORK/spire/agent"
    log_level = "WARN"
    trust_domain = "connector.local"
    server_address = "127.0.0.1"
    server_port = "$port"
    socket_path = "$WORK/spire/agent.sock"
    insecure_bootstrap = true
    join_token = "$token"
}
plugins {
    NodeAttestor "join_token" { plugin_data {} }
    KeyManager "memory" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
}
EOF
  setsid "$agent" run -config "$WORK/spire/agent.conf" >"$WORK/spire-agent.log" 2>&1 < /dev/null &
  for i in $(seq 1 40); do [[ -S "$WORK/spire/agent.sock" ]] && break; sleep 0.25; done
  "$srv" entry create -socketPath "$WORK/spire/server.sock" \
    -spiffeID spiffe://connector.local/connector \
    -parentID spiffe://connector.local/host \
    -selector "unix:uid:$(id -u)" >"$WORK/spire/entry.log" 2>&1 \
    || grep -q AlreadyExists "$WORK/spire/entry.log"
  for i in $(seq 1 20); do
    "$agent" api fetch x509 -socketPath "$WORK/spire/agent.sock" 2>/dev/null | grep -q 'spiffe://' && return 0
    sleep 0.5
  done
  return 1
}

setup_otel() {
  curl -fsS "${OTEL_HEALTH_URL:-http://127.0.0.1:13133/}" >/dev/null
}

setup_keycloak() {
  curl -kfsS "https://127.0.0.1:${KEYCLOAK_HTTPS_PORT:-18443}/" >/dev/null
}

setup_agentgateway() {
  local pin
  pin="$(awk 'NF && $1 !~ /^#/ { print; exit }' "$ROOT/platform/deploy/seven-backends/linux/agentgateway.pin")"
  [[ -n "$pin" ]]
  cat > "$WORK/agw-config/config.yaml" <<EOF
config:
  database:
    url: sqlite:///config/data.db
gateways:
  default:
    port: ${AGENTGATEWAY_PORT:-4000}
ui:
  gateways: default
EOF
  if docker ps --format '{{.Names}}' | grep -qx connector-oss-agentgateway; then
    return 0
  fi
  docker rm -f connector-oss-agentgateway >/dev/null 2>&1 || true
  docker run -d --name connector-oss-agentgateway \
    --restart no --read-only --security-opt no-new-privileges:true \
    -p "127.0.0.1:${AGENTGATEWAY_PORT:-4000}:${AGENTGATEWAY_PORT:-4000}" \
    -v "$WORK/agw-config:/config" \
    "$pin" >/dev/null
}

echo "Boot stage 1 — industry tools"
retry cosign setup_cosign || true
retry spire setup_spire || true
retry otel setup_otel || true
retry keycloak setup_keycloak || true
retry agentgateway setup_agentgateway || true
if command -v firecracker >/dev/null 2>&1 || [[ -n "${FIRECRACKER_BIN:-}" ]]; then
  echo "[ok] firecracker binary present"
else
  echo "[default] firecracker is not bundled. Set FIRECRACKER_BIN in boot.defaults when the binary and measured kernel are on this host."
fi
if curl -fsS http://127.0.0.1:17671/healthz >/dev/null 2>&1; then
  echo "[ok] openshell"
else
  echo "[default] openshell gateway is not listening. OPA stays inside OpenShell and is not a separate download."
fi

SPIRE_AGENT="$(find "$WORK" -type f -name spire-agent | head -1)"
cat > "$WORK/backend.env" <<EOF
SPIFFE_ENDPOINT_SOCKET=unix://$WORK/spire/agent.sock
CONNECTOR_SPIRE_AGENT_BIN=${SPIRE_AGENT}
OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT:-http://127.0.0.1:4317}
CONNECTOR_COSIGN_BIN=$BIN/cosign
CONNECTOR_COSIGN_BLOB=$WORK/cosign/blob
CONNECTOR_COSIGN_SIGNATURE=$WORK/cosign/blob.sig
CONNECTOR_COSIGN_KEY=$WORK/cosign/cosign.pub
CONNECTOR_JWT_SECRET=${CONNECTOR_JWT_SECRET:-connector-oss-dev-jwt-secret-32b}
EOF
chmod 0600 "$WORK/backend.env"
echo "Boot stage 1 wrote $WORK/backend.env"
exit 0
