#!/usr/bin/env bash
# Live checks for the five backends that are not the KVM gate:
# Keycloak, SPIRE, OpenShell, the OpenTelemetry Collector, and cosign.
# Each check uses the upstream tool. A missing checksum or a failed command
# fails that row. This script does not mark deploy-verify ready.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export COMPOSE_PROJECT_NAME=connector-five
WORK="${CONNECTOR_FIVE_WORK:-/tmp/connector-five}"
BIN="$WORK/bin"
ART="$ROOT/artifacts/five-backends"
mkdir -p "$BIN" "$ART" "$WORK"
chmod 0700 "$WORK"

KEYCLOAK_IMAGE="quay.io/keycloak/keycloak@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba"
POSTGRES_IMAGE="postgres@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297"
OTEL_IMAGE="otel/opentelemetry-collector-contrib@sha256:1ab0baba0ee3695d823c46653d8a6e8894896e668ce8bd7ebe002e948d827bc7"
OPENSHELL_SHA="883b5223399dd30a2b33b7f76817fd81295d610ce6f2d04a0266fc7cfbf87575"
SPIRE_SHA="ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7"
COSIGN_SHA="783b5d6c74105401c63946c68d9b2a4e1aab3c8abce043e06b8510b02b623ec9"

pass=0
fail=0
declare -A RESULT

row() {
  local name="$1" ok="$2" detail="$3"
  RESULT["$name"]="$ok"
  if [[ "$ok" == "pass" ]]; then
    pass=$((pass + 1))
    echo "[pass] $name — $detail"
  else
    fail=$((fail + 1))
    echo "[fail] $name — $detail" >&2
  fi
}

fetch() {
  local url="$1" dest="$2" sha="$3"
  if [[ ! -f "$dest" ]] || ! echo "$sha  $dest" | sha256sum -c - >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
  fi
  echo "$sha  $dest" | sha256sum -c -
}

cleanup() {
  if [[ -n "${SPIRE_SERVER_PID:-}" ]]; then kill "$SPIRE_SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${SPIRE_AGENT_PID:-}" ]]; then kill "$SPIRE_AGENT_PID" 2>/dev/null || true; fi
  if [[ -f "$WORK/images.env" ]]; then
    docker compose --env-file "$WORK/images.env" -f "$ROOT/platform/deploy/seven-backends/linux/compose.yaml" \
      -p connector-five down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_check() {
  local name="$1" detail="$2"
  shift 2
  set +e
  ( "$@" )
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    row "$name" pass "$detail"
  else
    row "$name" fail "$detail"
  fi
}

# --- cosign ---
cosign_check() {
  set -euo pipefail
  fetch "https://github.com/sigstore/cosign/releases/download/v2.5.3/cosign-linux-amd64" \
    "$BIN/cosign" "$COSIGN_SHA"
  chmod +x "$BIN/cosign"
  local dir="$WORK/cosign"
  mkdir -p "$dir"
  rm -f "$dir/cosign.key" "$dir/cosign.pub" "$dir/blob.sig"
  printf 'connector-release\n' > "$dir/blob"
  COSIGN_PASSWORD=connector-five "$BIN/cosign" generate-key-pair --output-key-prefix "$dir/cosign" >/dev/null
  COSIGN_PASSWORD=connector-five "$BIN/cosign" sign-blob --yes --key "$dir/cosign.key" \
    --output-signature "$dir/blob.sig" "$dir/blob" >/dev/null
  "$BIN/cosign" verify-blob --key "$dir/cosign.pub" --signature "$dir/blob.sig" "$dir/blob" >/dev/null
}
run_check cosign "cosign v2.5.3 verify-blob exited 0" cosign_check

# --- SPIRE ---
spire_check() {
  set -euo pipefail
  fetch "https://github.com/spiffe/spire/releases/download/v1.15.3/spire-1.15.3-linux-amd64-musl.tar.gz" \
    "$WORK/spire.tgz" "$SPIRE_SHA"
  tar -xzf "$WORK/spire.tgz" -C "$WORK"
  local srv agent
  srv="$(find "$WORK" -type f -name spire-server | head -1)"
  agent="$(find "$WORK" -type f -name spire-agent | head -1)"
  [[ -x "$srv" && -x "$agent" ]]
  pkill -x spire-server 2>/dev/null || true
  pkill -x spire-agent 2>/dev/null || true
  rm -f "$WORK/spire/server.sock" "$WORK/spire/agent.sock"
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
  "$srv" run -config "$WORK/spire/server.conf" >"$WORK/spire/server.log" 2>&1 &
  SPIRE_SERVER_PID=$!
  for _ in $(seq 1 40); do
    [[ -S "$WORK/spire/server.sock" ]] && break
    sleep 0.25
  done
  [[ -S "$WORK/spire/server.sock" ]]
  local token
  token="$("$srv" token generate -socketPath "$WORK/spire/server.sock" -spiffeID spiffe://connector.local/host | awk '/Token:/ {print $2}')"
  [[ -n "$token" ]]
  rm -rf "$WORK/spire/agent"
  mkdir -p "$WORK/spire/agent"
  cat > "$WORK/spire/agent.conf" <<EOF
agent {
    data_dir = "$WORK/spire/agent"
    log_level = "INFO"
    trust_domain = "connector.local"
    server_address = "127.0.0.1"
    server_port = "18081"
    socket_path = "$WORK/spire/agent.sock"
    insecure_bootstrap = true
    join_token = "$token"
}
plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "memory" { plugin_data {} }
    WorkloadAttestor "unix" { plugin_data {} }
}
EOF
  "$agent" run -config "$WORK/spire/agent.conf" >"$WORK/spire/agent.log" 2>&1 &
  SPIRE_AGENT_PID=$!
  for _ in $(seq 1 40); do
    [[ -S "$WORK/spire/agent.sock" ]] && break
    sleep 0.25
  done
  [[ -S "$WORK/spire/agent.sock" ]]
  "$srv" entry create -socketPath "$WORK/spire/server.sock" \
    -spiffeID spiffe://connector.local/connector \
    -parentID spiffe://connector.local/host \
    -selector "unix:uid:$(id -u)" >"$WORK/spire/entry.log" 2>&1 \
    || grep -q 'AlreadyExists' "$WORK/spire/entry.log"
  local out="" ok=0
  for _ in $(seq 1 40); do
    out="$("$agent" api fetch x509 -socketPath "$WORK/spire/agent.sock" 2>/dev/null || true)"
    if grep -q 'spiffe://connector.local/connector' <<<"$out"; then
      ok=1
      break
    fi
    sleep 0.5
  done
  [[ "$ok" -eq 1 ]]
  grep -q 'SPIFFE ID:' <<<"$out"
}
run_check spire "Workload API returned spiffe://connector.local/connector" spire_check

# --- collector ---
otel_check() {
  set -euo pipefail
  local tls="$WORK/tls"
  mkdir -p "$tls"
  if [[ ! -f "$tls/tls.crt" ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -keyout "$tls/tls.key" -out "$tls/tls.crt" \
      -subj /CN=localhost -addext subjectAltName=DNS:localhost >/dev/null 2>&1
  fi
  local admin_pw db_pw client_secret
  admin_pw="$(openssl rand -hex 16)"
  db_pw="$(openssl rand -hex 16)"
  client_secret="$(openssl rand -hex 16)"
  cat > "$WORK/images.env" <<EOF
POSTGRES_IMAGE=$POSTGRES_IMAGE
KEYCLOAK_IMAGE=$KEYCLOAK_IMAGE
OTEL_COLLECTOR_IMAGE=$OTEL_IMAGE
KEYCLOAK_DB_PASSWORD=$db_pw
KEYCLOAK_ADMIN=connector-admin
KEYCLOAK_ADMIN_PASSWORD=$admin_pw
KEYCLOAK_HOSTNAME=localhost
KEYCLOAK_HTTPS_PORT=18443
KEYCLOAK_TLS_DIR=$tls
CONNECTOR_SSO_CLIENT_ID=connector-platform
CONNECTOR_SSO_CLIENT_SECRET=$client_secret
CONNECTOR_SSO_REDIRECT_URI=https://localhost/api/v1/auth/sso/callback
EOF
  chmod 0600 "$WORK/images.env"
  docker compose --env-file "$WORK/images.env" -f "$ROOT/platform/deploy/seven-backends/linux/compose.yaml" \
    -p connector-five down -v >/dev/null 2>&1 || true
  docker compose --env-file "$WORK/images.env" -f "$ROOT/platform/deploy/seven-backends/linux/compose.yaml" \
    -p connector-five up -d
  for _ in $(seq 1 60); do
    curl -fsS http://127.0.0.1:13133/ >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS http://127.0.0.1:13133/ >/dev/null
  local code
  code="$(curl -s -o "$WORK/otel-body.txt" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d '{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"connector-five"}}]},"scopeSpans":[{"spans":[{"traceId":"5b8aa5a2d2c872e8321cf37308d69df2","spanId":"051581bf3cb55c13","name":"connector-five-live","kind":1,"startTimeUnixNano":"1600000000000000000","endTimeUnixNano":"1600000001000000000"}]}]}]}' \
    http://127.0.0.1:4318/v1/traces)"
  [[ "$code" == "200" ]]
}
run_check otel "collector accepted an OTLP/HTTP span" otel_check

# --- Keycloak ---
iam_check() {
  set -euo pipefail
  local envf="$WORK/images.env"
  # shellcheck disable=SC1090
  set -a; . "$envf"; set +a
  local dc=(docker compose --env-file "$envf" -f "$ROOT/platform/deploy/seven-backends/linux/compose.yaml" -p connector-five)
  for _ in $(seq 1 90); do
    "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials \
      --server http://127.0.0.1:8080 --realm master \
      --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null 2>&1 && break
    sleep 2
  done
  bash "$ROOT/platform/deploy/seven-backends/linux/bootstrap-keycloak.sh" "$envf" >/dev/null
  local uuid
  uuid="$("${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh get clients -r connector \
    -q clientId=connector-platform --fields id | awk -F'"' '/"id"/ {print $4; exit}')"
  [[ -n "$uuid" ]]
  "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh update "clients/$uuid" -r connector \
    -s directAccessGrantsEnabled=true >/dev/null
  "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh create users -r connector \
    -s username=connector-operator -s enabled=true \
    -s email=operator@connector.local -s emailVerified=true \
    -s firstName=Connector -s lastName=Operator >/dev/null 2>&1 || true
  "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh set-password -r connector \
    --username connector-operator --new-password 'connector-operator-pass' >/dev/null
  local user_id
  user_id="$("${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh get users -r connector \
    -q username=connector-operator --fields id | awk -F'"' '/"id"/ {print $4; exit}')"
  [[ -n "$user_id" ]]
  "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh update "users/$user_id" -r connector \
    -s 'requiredActions=[]' -s emailVerified=true \
    -s email=operator@connector.local -s firstName=Connector -s lastName=Operator >/dev/null
  local token_json iss
  token_json="$(curl -fsS -k -d grant_type=password \
    -d client_id=connector-platform \
    -d client_secret="$CONNECTOR_SSO_CLIENT_SECRET" \
    -d username=connector-operator \
    -d password='connector-operator-pass' \
    -d scope=openid \
    https://127.0.0.1:18443/realms/connector/protocol/openid-connect/token)"
  python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id_token"])' "$token_json" > "$WORK/id_token"
  curl -fsS -k https://127.0.0.1:18443/realms/connector/protocol/openid-connect/certs > "$WORK/jwks.json"
  iss="$(python3 -c 'import json,sys,base64; t=open(sys.argv[1]).read().strip().split(".")[1]; t += "="*((4-len(t)%4)%4); print(json.loads(base64.urlsafe_b64decode(t))["iss"])' "$WORK/id_token")"
  (
    cd "$ROOT/platform/server"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/platform/server/.cargo-target-umesh}" \
    CONNECTOR_IAM_ID_TOKEN="$(cat "$WORK/id_token")" \
    CONNECTOR_IAM_JWKS="$WORK/jwks.json" \
    CONNECTOR_IAM_CLIENT_ID=connector-platform \
    CONNECTOR_IAM_ISSUER="$iss" \
      cargo test -p connector-platform --bin connector-platform live_keycloak_id_token_verifies -- --ignored --test-threads=1
  ) | tee "$WORK/iam-test.txt"
  grep -q '1 passed' "$WORK/iam-test.txt"
}
run_check iam "Keycloak JWKS id_token verified by verify_id_token_with_jwks" iam_check

# --- OpenShell ---
openshell_check() {
  set -euo pipefail
  fetch "https://github.com/NVIDIA/OpenShell/releases/download/v0.0.116/openshell_0.0.116-1_amd64.deb" \
    "$WORK/openshell.deb" "$OPENSHELL_SHA"
  dpkg-deb -x "$WORK/openshell.deb" "$WORK/openshell-root"
  pkill -x openshell-gateway 2>/dev/null || true
  local bin="$WORK/openshell-root/usr/bin"
  local tls="$WORK/openshell-tls"
  mkdir -p "$tls"
  if [[ ! -f "$tls/ca.crt" ]]; then
    "$bin/openshell-gateway" generate-certs --output-dir "$tls" --server-san host.openshell.internal
  fi
  OPENSHELL_LOCAL_TLS_DIR="$tls" OPENSHELL_HEALTH_PORT=17671 \
    "$bin/openshell-gateway" >"$WORK/openshell-gateway.log" 2>&1 &
  local gw=$!
  local up=0
  for _ in $(seq 1 240); do
    if curl -fsS http://127.0.0.1:17671/healthz >/dev/null 2>&1; then
      up=1
      break
    fi
    sleep 0.25
  done
  [[ "$up" -eq 1 ]]
  local subnet img
  subnet="$(docker network inspect openshell-docker --format '{{(index .IPAM.Config 0).Subnet}}')"
  img="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
  docker run --rm --privileged --net=host --user 0 -v /:/host \
    --entrypoint /bin/bash "$img" -c "
set -e
ld=/host/lib64/ld-linux-x86-64.so.2
libs=/host/lib/x86_64-linux-gnu:/host/lib64
if ! \$ld --library-path \$libs /host/usr/sbin/xtables-nft-multi iptables -C INPUT -s '$subnet' -p tcp --dport 17670 -j ACCEPT; then
  \$ld --library-path \$libs /host/usr/sbin/xtables-nft-multi iptables -I INPUT 1 -s '$subnet' -p tcp --dport 17670 -j ACCEPT
fi
"
  PATH="$bin:$PATH" OPENSHELL_LOCAL_TLS_DIR="$tls" \
    openshell gateway add https://127.0.0.1:17670 --local --name connector-five \
    >"$WORK/openshell-gateway-add.log" 2>&1 || true
  PATH="$bin:$PATH" OPENSHELL_LOCAL_TLS_DIR="$tls" \
    openshell gateway select connector-five
  local policy="$WORK/policy.yaml"
  cat > "$policy" <<'EOF'
version: 1
filesystem_policy:
  read_only: []
  read_write: []
network_policies: {}
EOF
  PATH="$bin:$PATH" OPENSHELL_LOCAL_TLS_DIR="$tls" \
    openshell sandbox create --no-tty --no-auto-providers --policy "$policy" -- sleep 20 \
    >"$WORK/openshell-sandbox.log" 2>&1
  kill "$gw" 2>/dev/null || true
}
run_check openshell "openshell v0.0.116 sandbox create exited 0" openshell_check

python3 - "$ART/five-backends.json" "$pass" "$fail" \
  "${RESULT[iam]:-fail}" "${RESULT[spire]:-fail}" "${RESULT[openshell]:-fail}" \
  "${RESULT[otel]:-fail}" "${RESULT[cosign]:-fail}" <<'PY'
import json, sys
path, passed, failed, iam, spire, openshell, otel, cosign = sys.argv[1:]
doc = {
  "schema": "connector.five_backends_live.v1",
  "passed": int(passed),
  "failed": int(failed),
  "iam": iam,
  "spire": spire,
  "openshell": openshell,
  "otel": otel,
  "cosign": cosign,
  "honesty": "These rows are live upstream commands. They do not by themselves set deploy-verify operational_ready.",
}
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
print(json.dumps(doc, indent=2))
PY

[[ "$fail" -eq 0 ]]
