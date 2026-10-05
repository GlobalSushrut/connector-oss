#!/usr/bin/env bash
# Point the running Connector process at the industry tools and print deploy-verify.
# agentgateway stays off the seven-backend board. Forwarding stays denied.
set -euo pipefail

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
mkdir -p "$BIN" "$WORK/cosign" "$WORK/spire"
chmod 0700 "$WORK"

fetch() {
  local url="$1" dest="$2" sha="$3"
  if [[ ! -f "$dest" ]] || ! echo "$sha  $dest" | sha256sum -c - >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  fi
  echo "$sha  $dest" | sha256sum -c -
}

echo "[1] cosign"
fetch "https://github.com/sigstore/cosign/releases/download/v2.5.3/cosign-linux-amd64" \
  "$BIN/cosign" "783b5d6c74105401c63946c68d9b2a4e1aab3c8abce043e06b8510b02b623ec9"
chmod +x "$BIN/cosign"
if [[ ! -f "$WORK/cosign/blob.sig" ]]; then
  printf 'connector-release\n' > "$WORK/cosign/blob"
  COSIGN_PASSWORD=connector-oss "$BIN/cosign" generate-key-pair --output-key-prefix "$WORK/cosign/cosign" >/dev/null
  COSIGN_PASSWORD=connector-oss "$BIN/cosign" sign-blob --yes --key "$WORK/cosign/cosign.key" \
    --output-signature "$WORK/cosign/blob.sig" "$WORK/cosign/blob" >/dev/null
fi
"$BIN/cosign" verify-blob --key "$WORK/cosign/cosign.pub" --signature "$WORK/cosign/blob.sig" "$WORK/cosign/blob" >/dev/null
echo "    verify-blob ok"

echo "[2] SPIRE"
fetch "https://github.com/spiffe/spire/releases/download/v1.15.3/spire-1.15.3-linux-amd64-musl.tar.gz" \
  "$WORK/spire.tgz" "ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7"
tar -xzf "$WORK/spire.tgz" -C "$WORK"
SPIRE_SERVER="$(find "$WORK" -type f -name spire-server | head -1)"
SPIRE_AGENT="$(find "$WORK" -type f -name spire-agent | head -1)"
ln -sfn "$SPIRE_AGENT" "$BIN/spire-agent"
if ! "$SPIRE_AGENT" api fetch x509 -socketPath "$WORK/spire/agent.sock" >/dev/null 2>&1; then
  rm -f "$WORK/spire/server.sock" "$WORK/spire/agent.sock"
  rm -rf "$WORK/spire/agent"
  mkdir -p "$WORK/spire/server" "$WORK/spire/agent"
  cat > "$WORK/spire/server.conf" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "18081"
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
  setsid "$SPIRE_SERVER" run -config "$WORK/spire/server.conf" >"$WORK/spire-server.log" 2>&1 < /dev/null &
  for _ in $(seq 1 40); do [[ -S "$WORK/spire/server.sock" ]] && break; sleep 0.25; done
  token="$("$SPIRE_SERVER" token generate -socketPath "$WORK/spire/server.sock" -spiffeID spiffe://connector.local/host | awk '/Token:/ {print $2}')"
  cat > "$WORK/spire/agent.conf" <<EOF
agent {
    data_dir = "$WORK/spire/agent"
    log_level = "WARN"
    trust_domain = "connector.local"
    server_address = "127.0.0.1"
    server_port = "18081"
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
  setsid "$SPIRE_AGENT" run -config "$WORK/spire/agent.conf" >"$WORK/spire-agent.log" 2>&1 < /dev/null &
  for _ in $(seq 1 40); do [[ -S "$WORK/spire/agent.sock" ]] && break; sleep 0.25; done
  "$SPIRE_SERVER" entry create -socketPath "$WORK/spire/server.sock" \
    -spiffeID spiffe://connector.local/connector \
    -parentID spiffe://connector.local/host \
    -selector "unix:uid:$(id -u)" >"$WORK/spire/entry.log" 2>&1 \
    || grep -q 'AlreadyExists' "$WORK/spire/entry.log"
fi
ok=0
for _ in $(seq 1 20); do
  if "$SPIRE_AGENT" api fetch x509 -socketPath "$WORK/spire/agent.sock" | head -n 5; then
    ok=1
    break
  fi
  sleep 0.5
done
[[ "$ok" == 1 ]]
echo "    SPIRE fetch ok"

echo "[3] OpenTelemetry collector"
curl -fsS http://127.0.0.1:13133/ >/dev/null
echo "    collector health ok"

echo "[4] agentgateway pin"
PIN="$(awk 'NF && $1 !~ /^#/ { print; exit }' "$ROOT/platform/deploy/seven-backends/linux/agentgateway.pin")"
mkdir -p "$WORK/agw-config"
chmod 0777 "$WORK/agw-config"
cat > "$WORK/agw-config/config.yaml" <<'EOF'
config:
  database:
    url: sqlite:///config/data.db
gateways:
  default:
    port: 4000
ui:
  gateways: default
EOF
if ! docker ps --format '{{.Names}}' | grep -qx connector-oss-agentgateway; then
  docker rm -f connector-oss-agentgateway >/dev/null 2>&1 || true
  docker run -d --name connector-oss-agentgateway \
    --restart no --read-only --security-opt no-new-privileges:true \
    -p 127.0.0.1:4000:4000 \
    -v "$WORK/agw-config:/config" \
    "$PIN" >/dev/null
fi
echo "    container started from $PIN"

cat > "$WORK/backend.env" <<EOF
SPIFFE_ENDPOINT_SOCKET=unix://$WORK/spire/agent.sock
CONNECTOR_SPIRE_AGENT_BIN=$SPIRE_AGENT
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
CONNECTOR_COSIGN_BIN=$BIN/cosign
CONNECTOR_COSIGN_BLOB=$WORK/cosign/blob
CONNECTOR_COSIGN_SIGNATURE=$WORK/cosign/blob.sig
CONNECTOR_COSIGN_KEY=$WORK/cosign/cosign.pub
CONNECTOR_JWT_SECRET=connector-oss-dev-jwt-secret-32b
EOF
chmod 0600 "$WORK/backend.env"

if [[ -f "$WORK/platform.pid" ]]; then
  kill "$(cat "$WORK/platform.pid")" 2>/dev/null || true
fi
for _ in $(seq 1 20); do
  curl -fsS http://127.0.0.1:9091/health >/dev/null 2>&1 || break
  sleep 0.5
done

echo "[5] restart Connector so the process calls the tools"
"$HERE/up.sh"

echo "[6] give the OTLP exporter a request"
curl -fsS -H 'Authorization: Bearer dev-token' http://127.0.0.1:9091/api/v1 >/dev/null
sleep 3

echo "[7] deploy-verify"
curl -fsS -H 'Authorization: Bearer dev-token' \
  'http://127.0.0.1:9091/api/v1/runtime/deploy-verify?profile=linux-kvm' \
  | python3 -c '
import json,sys
body=json.load(sys.stdin)
print("operational_ready", body.get("operational_ready"))
for row in body.get("backends", []):
    print(f"{row.get(\"id\"):12} ready={row.get(\"ready\")}  {row.get(\"detail\")}")
'

echo "[8] agentgateway route on this process"
code="$(curl -sS -o "$WORK/agw-body.txt" -w '%{http_code}' -H 'Authorization: Bearer dev-token' http://127.0.0.1:9091/api/v1/runtime/agentgateway)"
echo "    HTTP $code"
head -c 180 "$WORK/agw-body.txt"; echo
if command -v firecracker >/dev/null 2>&1; then
  echo "[firecracker] $(firecracker --version 2>&1 | head -n 1)"
else
  echo "[firecracker] binary not installed on this host"
fi
