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

# Digests already checked by the live backend scripts in this repo.
# This boot uses its own compose project and never removes connector-five.
POSTGRES_IMAGE="postgres@sha256:029660641a0cfc575b14f336ba448fb8a75fd595d42e1fa316b9fb4378742297"
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak@sha256:357829ec7c4693397533035092ad13b0644bcc95ded311f33a3738c4d9e9bdba"
OTEL_IMAGE="otel/opentelemetry-collector-contrib@sha256:1ab0baba0ee3695d823c46653d8a6e8894896e668ce8bd7ebe002e948d827bc7"
OPENSHELL_SHA="883b5223399dd30a2b33b7f76817fd81295d610ce6f2d04a0266fc7cfbf87575"
FIRECRACKER_SHA="88d89221063ee4021b539a4fea4567642f4eecfb5d52eec04cd3390833f7f3de"

setup_keycloak_otel() {
  local otel_up=0 kc_up=0
  curl -fsS "${OTEL_HEALTH_URL:-http://127.0.0.1:13133/}" >/dev/null 2>&1 && otel_up=1
  curl -kfsS "https://127.0.0.1:${KEYCLOAK_HTTPS_PORT:-18443}/" >/dev/null 2>&1 && kc_up=1
  if [[ "$otel_up" -eq 1 && "$kc_up" -eq 1 ]]; then
    return 0
  fi
  command -v docker >/dev/null 2>&1 || return 1
  if [[ "$otel_up" -eq 1 || "$kc_up" -eq 1 ]]; then
    echo "[reuse] Keycloak or OpenTelemetry is already listening. Leaving that process alone." >&2
    return 1
  fi
  local tls="$WORK/keycloak-tls"
  local envf="$WORK/keycloak.env"
  mkdir -p "$tls"
  if [[ ! -f "$tls/tls.crt" ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout "$tls/tls.key" -out "$tls/tls.crt" \
      -subj /CN=localhost -addext subjectAltName=DNS:localhost >/dev/null 2>&1
  fi
  if [[ ! -f "$envf" ]]; then
    umask 077
    cat > "$envf" <<EOF
POSTGRES_IMAGE=$POSTGRES_IMAGE
KEYCLOAK_IMAGE=$KEYCLOAK_IMAGE
OTEL_COLLECTOR_IMAGE=$OTEL_IMAGE
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 16)
KEYCLOAK_ADMIN=connector
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 16)
KEYCLOAK_HOSTNAME=localhost
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-18443}
KEYCLOAK_TLS_DIR=$tls
CONNECTOR_SSO_CLIENT_ID=connector-platform
CONNECTOR_SSO_CLIENT_SECRET=$(openssl rand -hex 16)
CONNECTOR_SSO_REDIRECT_URI=http://127.0.0.1:${CONNECTOR_PORT:-9091}/api/v1/auth/sso/callback
EOF
    chmod 0600 "$envf"
  fi
  local compose="$ROOT/platform/deploy/seven-backends/linux/compose.yaml"
  docker compose --env-file "$envf" -f "$compose" -p connector-oss-boot up -d
  local _
  for _ in $(seq 1 90); do
    curl -fsS "${OTEL_HEALTH_URL:-http://127.0.0.1:13133/}" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fsS "${OTEL_HEALTH_URL:-http://127.0.0.1:13133/}" >/dev/null
  local dc=(docker compose --env-file "$envf" -f "$compose" -p connector-oss-boot)
  # shellcheck disable=SC1090
  set -a; . "$envf"; set +a
  for _ in $(seq 1 90); do
    "${dc[@]}" exec -T keycloak /opt/keycloak/bin/kcadm.sh config credentials \
      --server http://127.0.0.1:8080 --realm master \
      --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null 2>&1 && break
    sleep 2
  done
  COMPOSE_PROJECT_NAME=connector-oss-boot \
    bash "$ROOT/platform/deploy/seven-backends/linux/bootstrap-keycloak.sh" "$envf" >/dev/null
  curl -kfsS "https://127.0.0.1:${KEYCLOAK_HTTPS_PORT:-18443}/" >/dev/null
}

# Sets KC to a logged-in kcadm for the Keycloak on KEYCLOAK_HTTPS_PORT.
# Works on a Keycloak this boot started or one it reused; admin login comes from the container.
keycloak_admin_cli() {
  local port="${KEYCLOAK_HTTPS_PORT:-18443}" c admin pass
  c="$(docker ps --filter "publish=$port" --format '{{.Names}}' | head -1)"
  [[ -n "$c" ]] || return 1
  admin="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | sed -n 's/^KC_BOOTSTRAP_ADMIN_USERNAME=//p')"
  pass="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | sed -n 's/^KC_BOOTSTRAP_ADMIN_PASSWORD=//p')"
  [[ -n "$admin" && -n "$pass" ]] || return 1
  KC=(docker exec -i "$c" /opt/keycloak/bin/kcadm.sh)
  "${KC[@]}" config credentials --server http://127.0.0.1:8080 --realm master \
    --user "$admin" --password "$pass" >/dev/null || return 1
  "${KC[@]}" get realms/connector >/dev/null 2>&1
}

# Adds an admin-only user attribute to the connector realm's user profile.
keycloak_admin_attribute() {
  local name="$1" profile
  profile="$("${KC[@]}" get users/profile -r connector)" || return 1
  grep -q "\"$name\"" <<<"$profile" && return 0
  python3 -c 'import sys,json; n=sys.argv[1]; d=json.load(sys.stdin); d["attributes"].append({"name":n,"displayName":n,"permissions":{"view":["admin"],"edit":["admin"]},"multivalued":False}); print(json.dumps(d))' "$name" <<<"$profile" \
    | "${KC[@]}" update users/profile -r connector -f - >/dev/null
}

# Maps an admin-only user attribute into a client's tokens.
keycloak_attribute_mapper() {
  local client_uuid="$1" name="$2"
  "${KC[@]}" get "clients/$client_uuid/protocol-mappers/models" -r connector | grep -q "\"$name\"" && return 0
  "${KC[@]}" create "clients/$client_uuid/protocol-mappers/models" -r connector \
    -s "name=$name" -s protocol=openid-connect \
    -s protocolMapper=oidc-usermodel-attribute-mapper \
    -s "config.\"user.attribute\"=$name" -s "config.\"claim.name\"=$name" \
    -s 'config."jsonType.label"=String' -s 'config."id.token.claim"=true' \
    -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' >/dev/null
}

keycloak_client_uuid() {
  "${KC[@]}" get clients -r connector -q "clientId=$1" --fields id \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")'
}

# Every agent gets its own Keycloak account. Connector creates them through a service account;
# agents sign in with name and password on a client that only issues tokens for Connector.
setup_keycloak_agents() {
  local port="${KEYCLOAK_HTTPS_PORT:-18443}" out="$WORK/keycloak-agents.env"
  command -v python3 >/dev/null 2>&1 || return 1
  if [[ -f "$out" ]]; then
    local id secret
    id="$(sed -n 's/^CONNECTOR_KEYCLOAK_ADMIN_CLIENT_ID=//p' "$out")"
    secret="$(sed -n 's/^CONNECTOR_KEYCLOAK_ADMIN_CLIENT_SECRET=//p' "$out")"
    curl -ksfS -d grant_type=client_credentials -d "client_id=$id" -d "client_secret=$secret" \
      "https://127.0.0.1:${port}/realms/connector/protocol/openid-connect/token" >/dev/null 2>&1 && return 0
  fi
  keycloak_admin_cli || return 1
  keycloak_admin_attribute connector_agent_pid || return 1

  local node agents platform
  node="$(keycloak_client_uuid connector-node)"
  if [[ -z "$node" ]]; then
    "${KC[@]}" create clients -r connector -s clientId=connector-node -s enabled=true \
      -s publicClient=false -s serviceAccountsEnabled=true -s standardFlowEnabled=false \
      -s directAccessGrantsEnabled=false >/dev/null || return 1
    node="$(keycloak_client_uuid connector-node)"
  fi
  [[ -n "$node" ]] || return 1
  "${KC[@]}" add-roles -r connector --uusername service-account-connector-node \
    --cclientid realm-management --rolename manage-users --rolename view-users \
    --rolename query-users >/dev/null || return 1

  agents="$(keycloak_client_uuid connector-agents)"
  if [[ -z "$agents" ]]; then
    "${KC[@]}" create clients -r connector -s clientId=connector-agents -s enabled=true \
      -s publicClient=true -s standardFlowEnabled=false -s directAccessGrantsEnabled=true \
      -s serviceAccountsEnabled=false >/dev/null || return 1
    agents="$(keycloak_client_uuid connector-agents)"
  fi
  [[ -n "$agents" ]] || return 1
  keycloak_attribute_mapper "$agents" connector_agent_pid || return 1
  if ! "${KC[@]}" get "clients/$agents/protocol-mappers/models" -r connector | grep -q '"connector-agents-audience"'; then
    "${KC[@]}" create "clients/$agents/protocol-mappers/models" -r connector \
      -s name=connector-agents-audience -s protocol=openid-connect \
      -s protocolMapper=oidc-audience-mapper \
      -s 'config."included.client.audience"=connector-agents' \
      -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' >/dev/null || return 1
  fi
  # The operator sign-in client sees the same attribute, so Connector can refuse agent accounts there.
  platform="$(keycloak_client_uuid connector-platform)"
  [[ -n "$platform" ]] && { keycloak_attribute_mapper "$platform" connector_agent_pid || return 1; }

  local node_secret
  node_secret="$("${KC[@]}" get "clients/$node/client-secret" -r connector \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("value",""))')"
  [[ -n "$node_secret" ]] || return 1
  ( umask 077; cat > "$out" <<EOF
CONNECTOR_KEYCLOAK_URL=https://localhost:${port}
CONNECTOR_KEYCLOAK_REALM=connector
CONNECTOR_KEYCLOAK_ADMIN_CLIENT_ID=connector-node
CONNECTOR_KEYCLOAK_ADMIN_CLIENT_SECRET=$node_secret
CONNECTOR_KEYCLOAK_AGENT_CLIENT_ID=connector-agents
EOF
  )
}

# Keycloak sign-in into Connector: callback, a local operator user, and the node's SSO env.
setup_keycloak_login() {
  local port="${KEYCLOAK_HTTPS_PORT:-18443}"
  command -v python3 >/dev/null 2>&1 || return 1
  if [[ -f "$WORK/sso.env" && -f "$WORK/keycloak-login.txt" ]]; then
    local saved
    saved="$(sed -n 's/^CONNECTOR_SSO_CLIENT_SECRET=//p' "$WORK/sso.env")"
    # A wrong secret answers invalid_client; this client has no service account, so a right one does not.
    if [[ -n "$saved" ]] && ! curl -ksS \
        -d grant_type=client_credentials -d client_id=connector-platform -d "client_secret=$saved" \
        "https://127.0.0.1:${port}/realms/connector/protocol/openid-connect/token" 2>/dev/null \
        | grep -q '"invalid_client"'; then
      curl -kfsS "https://127.0.0.1:${port}/realms/connector/.well-known/openid-configuration" >/dev/null && return 0
    fi
  fi
  keycloak_admin_cli || return 1
  local kc=("${KC[@]}")

  local uuid redirect uris
  uuid="$("${kc[@]}" get clients -r connector -q clientId=connector-platform --fields id \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
  [[ -n "$uuid" ]] || return 1
  redirect="http://127.0.0.1:${CONNECTOR_PORT:-9091}/api/v1/auth/sso/callback"
  uris="$("${kc[@]}" get "clients/$uuid" -r connector --fields redirectUris \
    | python3 -c 'import sys,json; u=json.load(sys.stdin).get("redirectUris",[]); r=sys.argv[1]; print(json.dumps(u if r in u else u+[r]))' "$redirect")"
  "${kc[@]}" update "clients/$uuid" -r connector -s "redirectUris=$uris" >/dev/null || return 1

  # Role comes from an admin-only attribute, so a user cannot raise their own role.
  local profile
  profile="$("${kc[@]}" get users/profile -r connector)" || return 1
  if ! grep -q '"connector_role"' <<<"$profile"; then
    python3 -c 'import sys,json; d=json.load(sys.stdin); d["attributes"].append({"name":"connector_role","displayName":"Connector role","permissions":{"view":["admin"],"edit":["admin"]},"multivalued":False}); print(json.dumps(d))' <<<"$profile" \
      | "${kc[@]}" update users/profile -r connector -f - >/dev/null || return 1
  fi
  if ! "${kc[@]}" get "clients/$uuid/protocol-mappers/models" -r connector | grep -q '"connector_role"'; then
    "${kc[@]}" create "clients/$uuid/protocol-mappers/models" -r connector \
      -s name=connector_role -s protocol=openid-connect \
      -s protocolMapper=oidc-usermodel-attribute-mapper \
      -s 'config."user.attribute"=connector_role' -s 'config."claim.name"=connector_role' \
      -s 'config."jsonType.label"=String' -s 'config."id.token.claim"=true' \
      -s 'config."access.token.claim"=true' -s 'config."userinfo.token.claim"=true' >/dev/null || return 1
  fi

  local login="$WORK/keycloak-login.txt" pw="" uid
  [[ -f "$login" ]] && pw="$(sed -n 's/^password=//p' "$login")"
  [[ -n "$pw" ]] || pw="$(openssl rand -hex 12)"
  "${kc[@]}" create users -r connector -s username=operator -s enabled=true \
    -s email=local-operator@connector.local -s emailVerified=true \
    -s firstName=Local -s lastName=Operator >/dev/null 2>&1 || true
  uid="$("${kc[@]}" get users -r connector -q username=operator -q exact=true --fields id \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
  [[ -n "$uid" ]] || return 1
  "${kc[@]}" set-password -r connector --userid "$uid" --new-password "$pw" >/dev/null || return 1
  "${kc[@]}" update "users/$uid" -r connector -s 'requiredActions=[]' \
    -s 'attributes.connector_role=["operator"]' >/dev/null || return 1
  ( umask 077; printf 'url=%s\nusername=operator\npassword=%s\n' \
      "https://localhost:${port}/realms/connector/account" "$pw" > "$login" )

  local secret disco
  secret="$("${kc[@]}" get "clients/$uuid/client-secret" -r connector \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("value",""))')"
  [[ -n "$secret" ]] || return 1
  disco="$(curl -kfsS "https://127.0.0.1:${port}/realms/connector/.well-known/openid-configuration")" || return 1
  ( umask 077
    python3 -c '
import sys, json
d = json.loads(sys.argv[1])
print("CONNECTOR_SSO_ISSUER=" + d["issuer"])
print("CONNECTOR_SSO_AUTHORIZATION_URL=" + d["authorization_endpoint"])
print("CONNECTOR_SSO_TOKEN_URL=" + d["token_endpoint"])
print("CONNECTOR_SSO_USERINFO_URL=" + d["userinfo_endpoint"])
print("CONNECTOR_SSO_JWKS_URL=" + d["jwks_uri"])
' "$disco" > "$WORK/sso.env"
    cat >> "$WORK/sso.env" <<EOF
CONNECTOR_SSO_CLIENT_ID=connector-platform
CONNECTOR_SSO_CLIENT_SECRET=$secret
CONNECTOR_SSO_REDIRECT_URI=$redirect
CONNECTOR_SSO_INSECURE_TLS=1
CONNECTOR_SSO_ROLE_CLAIM=connector_role
CONNECTOR_SSO_ROLE_MAP=operator=operator
EOF
  )
}

setup_openshell() {
  curl -fsS http://127.0.0.1:17671/healthz >/dev/null 2>&1 && return 0
  fetch "https://github.com/NVIDIA/OpenShell/releases/download/v0.0.116/openshell_0.0.116-1_amd64.deb" \
    "$WORK/openshell.deb" "$OPENSHELL_SHA"
  dpkg-deb -x "$WORK/openshell.deb" "$WORK/openshell-root"
  local bin="$WORK/openshell-root/usr/bin"
  local tls="$WORK/openshell-tls"
  mkdir -p "$tls"
  if [[ ! -f "$tls/ca.crt" ]]; then
    "$bin/openshell-gateway" generate-certs --output-dir "$tls" --server-san host.openshell.internal
  fi
  ln -sfn "$bin/openshell" "$BIN/openshell"
  ln -sfn "$bin/openshell-gateway" "$BIN/openshell-gateway"
  if ! curl -fsS http://127.0.0.1:17671/healthz >/dev/null 2>&1; then
    OPENSHELL_LOCAL_TLS_DIR="$tls" OPENSHELL_HEALTH_PORT=17671 \
      setsid "$bin/openshell-gateway" >"$WORK/openshell-gateway.log" 2>&1 < /dev/null &
    echo $! >"$WORK/openshell-gateway.pid"
  fi
  local _
  for _ in $(seq 1 60); do
    curl -fsS http://127.0.0.1:17671/healthz >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

setup_firecracker() {
  local arch
  arch="$(uname -m)"
  [[ "$arch" == "x86_64" || "$arch" == "amd64" ]] || return 1
  if [[ -x "$BIN/firecracker" ]]; then
    return 0
  fi
  fetch "https://github.com/firecracker-microvm/firecracker/releases/download/v1.9.1/firecracker-v1.9.1-x86_64.tgz" \
    "$WORK/firecracker.tgz" "$FIRECRACKER_SHA"
  local dest="$WORK/firecracker-extract"
  rm -rf "$dest"
  mkdir -p "$dest"
  tar -xzf "$WORK/firecracker.tgz" -C "$dest"
  local fc jail
  fc="$(find "$dest" -type f \( -name firecracker -o -name 'firecracker-*' \) ! -name '*.tgz' | head -1)"
  jail="$(find "$dest" -type f \( -name jailer -o -name 'jailer-*' \) | head -1 || true)"
  [[ -n "$fc" ]]
  cp "$fc" "$BIN/firecracker"
  chmod +x "$BIN/firecracker"
  if [[ -n "$jail" ]]; then
    cp "$jail" "$BIN/jailer"
    chmod +x "$BIN/jailer"
  fi
  "$BIN/firecracker" --version >/dev/null
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
retry keycloak+otel setup_keycloak_otel || true
retry keycloak-login setup_keycloak_login || true
retry keycloak-agents setup_keycloak_agents || true
retry openshell setup_openshell || true
retry firecracker setup_firecracker || true
retry agentgateway setup_agentgateway || true

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
CONNECTOR_FIRECRACKER_BIN=$BIN/firecracker
CONNECTOR_JAILER_BIN=$BIN/jailer
CONNECTOR_OPENSHELL_BIN=$BIN/openshell
OPENSHELL_LOCAL_TLS_DIR=$WORK/openshell-tls
EOF
[[ -f "$WORK/sso.env" ]] && cat "$WORK/sso.env" >> "$WORK/backend.env"
[[ -f "$WORK/keycloak-agents.env" ]] && cat "$WORK/keycloak-agents.env" >> "$WORK/backend.env"
chmod 0600 "$WORK/backend.env"
cat > "$WORK/MANAGE.txt" <<EOF
People use Connector. These tools are started for them.
Manage only if you need to:

Keycloak     https://127.0.0.1:${KEYCLOAK_HTTPS_PORT:-18443}/   project connector-oss-boot   secrets $WORK/keycloak.env
OpenTelemetry  ${OTEL_HEALTH_URL:-http://127.0.0.1:13133/}   OTLP ${OTEL_EXPORTER_OTLP_ENDPOINT:-http://127.0.0.1:4317}
SPIRE        socket $WORK/spire/agent.sock
OpenShell    http://127.0.0.1:17671/healthz   OPA is inside this gateway
Firecracker  $BIN/firecracker   binary only; a microvm is not started
cosign       $BIN/cosign
agentgateway http://127.0.0.1:${AGENTGATEWAY_PORT:-4000}/   forwarding is not proven
EOF
echo "Boot stage 1 wrote $WORK/backend.env"
echo "Manage file: $WORK/MANAGE.txt"
exit 0
