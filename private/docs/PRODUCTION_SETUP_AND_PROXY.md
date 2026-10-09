# Production setup: registration, API keys, activation, plugins, and proxy

This guide is for **operators** bringing Connector to production: from first **user registration** through **API keys**, **node activation**, choosing **workflows / plugins**, and fronting the stack with a **reverse proxy**. It complements the cage / preset doc at [`platform/docs/CONNECTOR_CAGE_NODE_AND_PLUGINS.md`](../../platform/docs/CONNECTOR_CAGE_NODE_AND_PLUGINS.md).

**Base URL:** Replace `https://api.example.com` with your public origin (`CONNECTOR_PUBLIC_URL`). All REST paths below are under **`/api/v1`** unless noted. The **LLM gateway** uses **`/v1`** on the **same host** (not under `/api/v1`).

---

## 1. Deploy the platform (production baseline)

1. Set **preset and hardening** (see cage doc for all 12 modes):

   ```bash
   export CONNECTOR_PRESET=production
   export CONNECTOR_ENV=production
   export CONNECTOR_CONFIG_STRICT=1
   export CONNECTOR_ENFORCE_PRODUCTION_PRESETS=1
   export CONNECTOR_PUBLIC_URL=https://api.example.com
   ```

2. Provide **secrets** via your secret manager (never commit):
   - **`CONNECTOR_JWT_SECRET`** (strong random)
   - **`CONNECTOR_LICENSE`** or license file, as required by your tier
   - **`CONNECTOR_LLM_API_KEY`** (or provider-specific keys) for real LLM traffic
   - Optional: **`CONNECTOR_ENGINE_STORAGE`**, **`CONNECTOR_KERNEL_STORAGE`** for durable paths

3. Start **`connector-platform`** (binary, systemd, or container). Confirm:

   ```bash
   curl -fsS https://api.example.com/health
   curl -fsS https://api.example.com/readyz
   ```

4. **Optional `connector.yaml`:** mount or place [`connector.yaml.example`](../../connector.yaml.example) as `connector.yaml` only if you need fixed ports / paths; presets are enough for many teams.

---

## 2. Registration and first operator identity

Paths depend on whether **billing / signup** is enabled in your deployment.

| Step | Endpoint | Purpose |
|------|----------|---------|
| Sign up (if enabled) | `POST /api/v1/auth/signup` | Create first org user (may tie to billing). Exact body matches your deployed OpenAPI / manifest. |
| Sign in | `POST /api/v1/auth/token` | JSON body: **`email`** + **`password`**, or exchange an existing **`api_key`** (see below). Returns **`access_token`** (JWT). |

**Example (password login):**

```bash
curl -sS -X POST https://api.example.com/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"***"}'
```

Save **`access_token`** for the next steps. Use header:

`Authorization: Bearer <access_token>`

**Dev / pilot note:** In **`CONNECTOR_PRESET=local`** (or dev bypass), you may use **`Authorization: Bearer dev-token`** for quick tests — **not** for production.

---

## 3. API keys (`cpk_*`) for automation and plugins

Long-lived keys are created **after** you have a JWT for an admin-capable user.

| Action | Endpoint | Auth |
|--------|----------|------|
| Create API key | `POST /api/v1/auth/api-keys` | `Bearer` JWT |
| List keys (if exposed) | See manifest / user profile | JWT |

**Example:**

```bash
curl -sS -X POST https://api.example.com/api/v1/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"prod-plugin-relay","expires_days":365}'
```

Response includes **`api_key`** (prefix **`cpk_`**). Store it in a secret manager. This key is what **plugins** and CI use as **`CONNECTOR_API_KEY`** / **`Authorization: Bearer cpk_...`**.

**Exchange API key for JWT (optional, for clients that want short-lived tokens):**

```bash
curl -sS -X POST https://api.example.com/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$CONNECTOR_API_KEY\"}"
```

---

## 4. Node activation (runtime mode + license / pilot key)

Activation binds the **package identity** to this machine and sets the **store-backed runtime mode** (`dev` / `pilots` / `production`). It is distinct from day-to-day **`cpk_`** API keys.

| Action | Endpoint | Notes |
|--------|----------|------|
| Status | `GET /api/v1/runtime/activation` | Current activation record and mode. |
| Activate | `POST /api/v1/runtime/activation` | Body: **`mode`**, **`access_key`** (and optional package identity fields). |

**`access_key` rules (from runtime control):**

- **`dev`:** may use empty or dev bootstrap; pilot/production require real keys.
- **`pilots`:** must match a registered **`cpk_pilot_...`** pilot key in the store.
- **`production`:** must be a **`lic_...`** style license key accepted by **`LicenseInfo::validate_key`**.

**Example (production):**

```bash
curl -sS -X POST https://api.example.com/api/v1/runtime/activation \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "production",
    "access_key": "lic_xxxxxxxx"
  }'
```

After activation, enforce **defense** and **preset** alignment (`CONNECTOR_DEFENSE_STRICT`, `CONNECTOR_ENFORCE_PRODUCTION_PRESETS`) as documented in the cage guide.

---

## 5. Choosing a workflow: platform-native vs plugins

### 5.1 Stay on the Connector kernel (no separate plugin process)

Use these when you want **agents, memory, LLM gateway, MCP, multi-agent pipelines** inside the main binary:

| Capability | Typical entry |
|------------|----------------|
| Agents | `POST /api/v1/agents`, `GET /api/v1/agents` |
| LLM (OpenAI-compatible) | `POST https://api.example.com/v1/chat/completions` |
| Anthropic-style | `POST https://api.example.com/v1/messages` |
| MCP tool registration | `POST /api/v1/tools/mcp/register` |
| Multi-agent / DAG | `POST /api/v1/multiagent/...`, orchestrator routes in manifest |
| Experiments | `POST /api/v1/experiments/...` |

Point SDKs at **`https://api.example.com/v1`** with **`Authorization: Bearer cpk_...`** (or JWT), per your auth middleware rules.

### 5.2 First-party plugins (separate processes)

Plugins in this repo (**relay**, **conductor**, **agentloop**, **ledgerlens**, etc.) run **beside** Connector and call **`CONNECTOR_URL`** (private) with **`CONNECTOR_API_KEY`**.

| After platform is up | You do |
|----------------------|--------|
| Pick plugin | e.g. **Relay** for HTTP function + governance proxy; **Conductor** for governed orchestration. |
| Configure plugin env | `CONNECTOR_URL=http://<internal>:9091`, `CONNECTOR_API_KEY=cpk_...`, plugin-specific **`PORT`**, **`DATABASE_URL`** where needed. |
| Start order | Start **Connector** first; use healthchecks + `depends_on` (see cage doc §D.4). |
| Expose plugin | Typically **`https://api.example.com/proxy/<plugin>/...`** via reverse proxy; do not expose DB ports. |

**Relay-style “user proxy”:** clients can target the **plugin** URL; the plugin forwards LLM / tool calls through Connector so **audit, budget, and admission** stay centralized.

---

## 6. Reverse proxy and TLS (production)

### 6.1 Routes to map

| Path pattern | Upstream | Notes |
|--------------|----------|--------|
| `/api/v1/*` | `connector-platform` HTTP | REST control plane, auth, agents, tools. |
| `/v1/*` | Same upstream | **OpenAI / Anthropic** gateway — same process, different path prefix. |
| `/health`, `/readyz`, `/metrics` | Same | Health and observability (restrict **`/metrics`** in prod if needed). |
| `/` | Same or static | Dashboard UI if served by Connector. |
| `/proxy/<plugin>/*` | Plugin service | Strip or forward prefix per plugin contract. |

### 6.2 Headers

- Forward **`Authorization`** and **`X-Request-Id`** (or generate request IDs).
- If TLS terminates at proxy, set **`CONNECTOR_PUBLIC_URL`** to the **https** origin.
- For multi-tenant, forward tenant headers required by your deployment (see `CONNECTOR_MULTI_TENANT` in cage doc).

### 6.3 Minimal nginx sketch

```nginx
upstream connector_upstream {
    server 127.0.0.1:9091;
}

upstream relay_upstream {
    server 127.0.0.1:9740;
}

server {
    listen 443 ssl;
    server_name api.example.com;

    location /api/v1/ {
        proxy_pass http://connector_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Authorization $http_authorization;
    }

    location /v1/ {
        proxy_pass http://connector_upstream;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
    }

    location /health {
        proxy_pass http://connector_upstream;
    }

    location /proxy/relay/ {
        proxy_pass http://relay_upstream/;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
    }
}
```

Adjust ports, TLS certificates, and **`location`** blocks for each plugin.

---

## 7. End-to-end checklist

1. [ ] Production env: **`CONNECTOR_PRESET`**, **`CONNECTOR_CONFIG_STRICT`**, **`CONNECTOR_ENFORCE_PRODUCTION_PRESETS`**, **`CONNECTOR_PUBLIC_URL`**
2. [ ] Secrets: JWT, license, LLM keys, **`CONNECTOR_API_KEY`** for automation
3. [ ] TLS + proxy: `/api/v1`, `/v1`, `/health`, optional `/proxy/...`
4. [ ] **`/health`** and **`/readyz`** green
5. [ ] Operator: signup/login → **`POST /api/v1/auth/api-keys`**
6. [ ] **`POST /api/v1/runtime/activation`** with correct **`mode`** + **`access_key`**
7. [ ] Plugin: **`CONNECTOR_URL`** internal, **`CONNECTOR_API_KEY`**, healthcheck on plugin **`/health`**
8. [ ] Document **`CONNECTOR_TRUSTED_PROXIES`** if using `X-Forwarded-For` for audit/IP features

---

## 8. Related documentation

- Cage, presets, YAML, enterprise flags: [`platform/docs/CONNECTOR_CAGE_NODE_AND_PLUGINS.md`](../../platform/docs/CONNECTOR_CAGE_NODE_AND_PLUGINS.md)
- Relay portfolio / plugin roles: [`docs/94-relay-plan.md`](../../docs/94-relay-plan.md)
