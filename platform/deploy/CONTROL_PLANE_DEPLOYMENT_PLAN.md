# Connector OS — Control Plane & Production Deployment Plan

> **Purpose:** Deploy account creation, license/key issuance, node activation (RPC), playground, and a **secure owner admin panel** so millions of vendor-hosted nodes can phone home correctly.  
> **Stack:** Vercel (marketing) · Fly.io (license + playground) · Neon (Postgres) · Cloudflare (DNS/WAF)  
> **Companion:** [`DEPLOYMENT.md`](DEPLOYMENT.md) (step-by-step ops), [`../docs/landing-page/web/LANDING_UPDATE_PLAN.md`](../docs/landing-page/web/LANDING_UPDATE_PLAN.md) (marketing UX)

---

## 1. System planes (who talks to what)

```
                         ┌─────────────────────────────────────────┐
                         │           Cloudflare (edge)              │
                         │  WAF · rate limits · TLS · bot protection │
                         └─────────────────────────────────────────┘
                │                    │                    │
    cnktros.com │         portal.cnktros.com              │ try.cnktros.com
    (Vercel)    │         api.cnktros.com                 │ (Fly playground)
    marketing   │         admin.cnktros.com               │
                │         (Fly connector-license)         │
                ▼                    ▼                    ▼
         React SPA            Axum license server      platform/server
         pilot form            ├─ Portal API (JWT)       CONNECTOR_PLAYGROUND=1
         download CTAs         ├─ Admin API (OWNER)      ephemeral sessions
                               ├─ RPC API (RpcToken)     no permanent issuance
                               ├─ Stripe webhooks
                               └─ Surveillance / kill
                                        │
                                        ▼
                               Neon Postgres (source of truth)
                                        ▲
                                        │ POST /rpc/v1/auth|heartbeat|usage
                                        │ (millions of vendor nodes)
                          ┌─────────────┴─────────────┐
                          │  Customer / vendor infra   │
                          │  connector-platform binary  │
                          │  on their VPC / bare metal  │
                          └────────────────────────────┘
```

| Plane | URL (prod) | Auth | Users |
|-------|------------|------|-------|
| **Marketing** | `https://cnktros.com` | None (public) | Prospects |
| **Customer portal** | `https://portal.cnktros.com` | Email + password + TOTP; JWT `Bearer` | Paying customers |
| **License & RPC API** | `https://api.cnktros.com` | Per-route: portal JWT, `RpcToken`, Stripe sig, **owner admin key** | Portals, nodes, Stripe |
| **Owner admin panel** | `https://admin.cnktros.com` (or `internal.admin.cnktros.com`) | **Must be hardened** (see §6) | Connector owners only |
| **Playground** | `https://try.cnktros.com` | Anonymous / email session token | Trial users |
| **Vendor nodes** | Customer network → `api.cnktros.com` | `role_id` + one-time `secret_id` → `RpcToken` | Deployed software |

---

## 2. End-to-end identity & activation flows

### 2.1 Account creation (customer)

```
cnktros.com/signup CTA
    → portal.cnktros.com/signup (Leptos www)
    → POST /api/v1/portal/register { email, password, name, license_key? }
    → Neon: portal_users (+ optional link to license_keys)
    → POST /api/v1/portal/login → JWT (portal session)
    → /app (dashboard, billing, API keys, download)
```

**Neon tables:** `portal_users`, `customers`, `license_keys` (linked after Stripe or manual pilot grant).

**Rules:**
- Passwords: bcrypt/argon2 (already in portal module).
- TOTP required for paid tiers before download/issuance (policy flag).
- Email verification before issuance (`email_verified` column exists).

### 2.2 Payment → license key → binary issuance

```
portal /app/billing
    → POST /api/v1/payment/checkout (Stripe)
    → Stripe webhook POST /webhooks/stripe
    → Neon: customers.payment_status = Active, license_keys row, stripe_sub_id
    → POST /api/v1/issuances { key_id, tier, machine_lock? }  (admin or automated post-checkout)
    → Neon: binary_issuances { role_id, secret_id (one-time), binary_id, key_id }
    → Customer downloads binary OR receives .license-seed sidecar
```

**Critical:** `secret_id` is **one-time** — consumed on first `POST /rpc/v1/auth` ([`rpc_auth.rs`](../licensing/src/rpc_auth.rs)). Each download/build gets a new issuance.

### 2.3 Node activation on vendor servers (RPC)

Implemented in [`platform/server/src/binary_id.rs`](../../server/src/binary_id.rs):

```
1. Vendor installs connector-platform (curl install.sh or tarball)
2. Binary contains (or reads from secure file):
     CONNECTOR_LICENSE_SERVER=https://api.cnktros.com
     CONNECTOR_ROLE_ID, CONNECTOR_SECRET_ID  (from issuance)
     CONNECTOR_BINARY_ID, CONNECTOR_KEY_ID
3. Startup:
     POST /rpc/v1/auth { role_id, secret_id, machine_id, binary_hash, binary_id, version }
     ← { token, expires_in, tier, permissions, instance_id }
     secret_id marked used in Neon; RPC token held in memory only
4. Steady state (every ~30–60 min):
     POST /rpc/v1/heartbeat  (Authorization: RpcToken …)
     POST /rpc/v1/usage      (aggregated metrics)
5. Before token expiry (<5 min):
     POST /rpc/v1/renew
6. Clean shutdown:
     POST /rpc/v1/revoke
7. Legacy / parallel path still supported:
     POST /rpc/v1/checkin (surveillance.rs) — payment gate, kill/degrade commands
```

**Offline grace:** `CONNECTOR_OFFLINE_GRACE_SECS` (default 72h) if license server unreachable after prior successful auth.

**Node lock:** `machine_id` SHA fingerprint; optional `locked_machine_id` on issuance prevents license migration.

### 2.4 Playground (no permanent license)

```
try.cnktros.com
    → POST /api/v1/playground/session (CONNECTOR_PLAYGROUND=1 on Fly app)
    → Returns ephemeral api_key + TTL (see fly.playground.toml caps)
    → User explores TT/WC/DevGuard stubs; no binary_issuances row
    → CTA at end: portal signup + download
```

Playground **must not** share the license DB write path for issuances; optional read-only Neon for analytics.

### 2.5 Pilot / manual grants (owner-operated)

```
Owner admin panel → POST /api/v1/admin/pilots
    → pilot_grants row (tier_override, expiry, customer_id)
Portal → GET /api/v1/portal/pilot, /entitlement
```

Bridges marketing “Request access” (Vercel `submit-pilot`) to Neon entitlement without Stripe.

---

## 3. RPC design for millions of nodes & many vendors

### 3.1 What already scales

| Mechanism | Why it scales |
|-----------|----------------|
| **HMAC RpcToken** ([`rpc_token.rs`](../licensing/src/rpc_token.rs)) | `GET /rpc/v1/verify` and most checks need **no DB read** — O(1) crypto verify |
| **Short TTL (1h) + renew** | Limits stolen-token window; renew is cheap |
| **Append-only `rpc_tokens` + in-memory revocation set** | Revocation O(1) per token_id |
| **Indexed Neon schema** | `instances`, `binary_issuances`, `usage_records` indexed ([`0001_initial.sql`](../licensing/migrations/0001_initial.sql)) |
| **Per-binary rate limit** | `CONNECTOR_RPC_RATE_LIMIT` env on token manager |

### 3.2 What must change before “millions”

| Gap | Risk | Remediation |
|-----|------|-------------|
| **Global `Mutex` on issuances/store** in single Fly VM | Auth storm serializes | Shard writes: Redis/Postgres row lock per `role_id`; horizontal Fly replicas |
| **In-memory revocation only** | Replicas disagree | Redis pub/sub revocation fanout + periodic Neon sync |
| **No `vendor_id` / `org_id` on instances** | Cannot segment OEM customers | Migration + APIs (§5) |
| **Admin APIs unauthenticated** | Anyone can call `/api/v1/admin/*` | **P0** middleware (§6) |
| **CORS permissive** on license server | CSRF / token leakage | Restrict origins per hostname |
| **Single region (iad)** | Latency for EU/APAC nodes | Multi-region Fly + Neon read replicas |

### 3.3 Target RPC topology (growth stages)

**Stage A — Launch (0–10k nodes)**  
- 1× `connector-license` Fly app, Neon primary, connection pooler (`?pgbouncer=true`).
- `api.cnktros.com` → Fly.

**Stage B — Growth (10k–500k nodes)**  
- 2–4 Fly replicas behind Fly Proxy; **sticky not required** for RpcToken verify.
- **Only** `/rpc/v1/auth` and issuance writes hit primary DB.
- Redis (Upstash) for: revocation broadcast, rate limits, idempotency keys on auth.
- Heartbeat/usage: accept async queue (SQS/NATS) → batch insert to Neon every N seconds.

**Stage C — Scale (500k–5M+ nodes)**  
- Dedicated **`rpc.cnktros.com`** edge (stateless verify workers).
- **`control.cnktros.com`** for portal/admin/Stripe (low QPS).
- Neon: read replicas per continent; partition `usage_records` by month.
- Vendor isolation: row-level `vendor_id` + API quotas.

### 3.4 Vendor / OEM model (software on customer servers)

Each vendor (MSP, ISV, enterprise) gets:

| Concept | Storage | Used by |
|---------|---------|---------|
| `vendor_id` | `customers.vendor_id` | Billing, support, admin filter |
| `org_id` | `instances.org_id` | Per-customer-of-vendor grouping |
| License key pool | `license_keys` scoped to vendor | Reseller dashboards (future) |
| Custom `license_server_url` | Baked at vendor build time | White-label phone-home |
| Blocked binary hashes | `blocked_hashes` | Anti-piracy per vendor or global |

Nodes never trust the portal JWT — only **RpcToken** or offline Ed25519 license file ([`/api/v1/keys/license-file`](../licensing/src/routes.rs)).

---

## 4. Neon database layout

**One Neon project `connector-prod`**, separate **databases or branches**:

| Database | Contents |
|----------|----------|
| `connector_license` | All tables in `0001_initial.sql` + future migrations |
| `connector_playground` | Optional: session analytics only (or ephemeral in-memory for v1) |
| `connector_marketing` | Vercel Postgres pilot submissions (already on Vercel integration) |

**Do not** mix TraceTramp/WitnessCtl plugin DBs with license DB in v1 — separate Neon branches per plugin when those run as managed services.

**Backups:** Neon PITR + nightly `platform/deploy/scripts/backup-db.sh` to R2.

---

## 5. Fly.io deployment matrix

| App | Image | Hostnames | Secrets |
|-----|-------|-----------|---------|
| `connector-license` | `Dockerfile.license` | `api.`, `portal.`, `admin.` (path `/admin` or subdomain) | `DATABASE_URL`, `CONNECTOR_RPC_SECRET`, `CONNECTOR_LICENSE_ADMIN_KEY`, `CONNECTOR_PORTAL_JWT_SECRET`, Stripe, SendGrid |
| `connector-playground` | `Dockerfile.playground` | `try.` | `CONNECTOR_LICENSE_URL`, playground caps |
| (future) `connector-rpc-edge` | slim verify-only binary | `rpc.` | `CONNECTOR_RPC_SECRET`, Redis URL |

**Build artifacts baked into license image:**
- `platform/ui-leptos/www/dist` → portal SPA (`CONNECTOR_WWW_DIR`)
- `platform/ui-leptos/admin/dist` → admin SPA (`CONNECTOR_ADMIN_UI_DIR`, served at `/admin` today)

**Persistent volume:** `/data/keys` — Ed25519 license signing keys (**never delete**).

---

## 6. Owner admin / control panel (critical — partially built, not production-safe)

### 6.1 What exists today

**UI:** [`platform/ui-leptos/admin`](../../ui-leptos/admin) — Leptos WASM, dark ops theme.

| Page | API | Function |
|------|-----|----------|
| Dashboard | `/api/v1/admin/stats` | Keys, MRR, activations |
| Customers | `/api/v1/admin/customers` | Suspend/restore/message |
| Keys | `/api/v1/keys/*` | Issue/revoke license keys |
| Instances | `/api/v1/admin/instances` | Active nodes |
| Revenue / Payments | `/api/v1/payment/*` | Stripe |
| Dunning | `/api/v1/admin/dunning` | Past-due workflow |
| **Surveillance** | `/api/v1/surveillance/*` | Kill, degrade, block binary, event log |
| Pilots | `/api/v1/admin/pilots` | Manual grants |

**Deploy target:** `admin.cnktros.com` → Vercel **or** `https://api.cnktros.com/admin` (Fly nested SPA).

### 6.2 P0 security gaps (block public launch)

1. **Admin API has no server-side auth** — UI sends `X-API-Key: sk_admin_…` but license server **does not validate** it ([`admin/src/api.rs`](../../ui-leptos/admin/src/api.rs) vs [`routes.rs`](../licensing/src/routes.rs)).
2. **Admin key in browser LocalStorage** — any XSS exfiltrates owner access.
3. **Surveillance kill/degrade** — same open API surface.
4. **CORS permissive** on license app — tighten to known origins.

### 6.3 Owner control panel — target design

```
admin.cnktros.com (or internal-only DNS)
    │
    ├─ Cloudflare Access / IP allowlist (office + VPN CIDRs only)
    ├─ Separate admin login (NOT customer portal password)
    │     Option A: Cloudflare Access SSO (Google Workspace)
    │     Option B: POST /api/v1/owner/login → short-lived HttpOnly cookie + MFA
    ├─ Axum middleware on ALL /api/v1/admin/* and /api/v1/surveillance/*
    │     Validates: CONNECTOR_LICENSE_ADMIN_KEY or owner JWT with role=owner
    ├─ Audit log table: admin_actions (who, what, instance_id, ts)
    └─ Leptos admin UI: remove LocalStorage key; use cookie session + CSRF
```

**Required owner capabilities:**

| Capability | API / UI |
|------------|----------|
| View all customers & payment state | Customers + Dunning |
| Issue/revoke license keys & issuances | Keys + Issuances |
| Force-revoke RPC tokens | Surveillance + `rpc_tokens.revoked` |
| Kill/degrade misbehaving node | Surveillance |
| Block pirated binary hash | `/surveillance/block-binary` |
| Create pilot grants | Pilots |
| Global metrics | Dashboard + Prometheus `/metrics` on Fly |
| Stripe revenue | Revenue |
| Read-only break-glass | Secondary read-only admin role |

### 6.4 Implementation order (admin hardening)

1. Add `admin_auth_middleware` in `platform/licensing` — constant-time compare `X-API-Key` / `Authorization: Bearer` against `CONNECTOR_LICENSE_ADMIN_KEY`.
2. Apply to route groups: `admin/*`, `surveillance/*`, `keys/issue`, `keys/revoke`, `issuances` POST.
3. Cloudflare WAF: block `/api/v1/admin` from non-allowlisted IPs.
4. Deploy admin SPA behind Cloudflare Access; deprecate `dev-admin-token`.
5. Add `admin_actions` migration + log every mutating call.
6. (Stage B) Owner MFA via WebAuthn or TOTP separate from customer portal.

---

## 7. Marketing site integration (cnktros.com)

See landing plan; control-plane links:

| CTA | Target |
|-----|--------|
| Sign up | `https://portal.cnktros.com/signup` |
| Log in | `https://portal.cnktros.com/login` |
| Download | `/download` → public install.sh + “Sign in for licensed binary” → portal |
| Try playground | `https://try.cnktros.com` |
| Request pilot | Existing Vercel `/api/submit-pilot` → owner reviews in **admin Pilots** → grant |

Env on Vercel (`VITE_*`): `PORTAL_BASE_URL`, `PLAYGROUND_BASE_URL`, `API_BASE_URL`, `RELEASES_BASE_URL`.

---

## 8. Phased rollout checklist

### Phase 0 — Security blockers (1 week)

- [ ] Implement admin API authentication middleware
- [ ] Rotate `CONNECTOR_LICENSE_ADMIN_KEY` / `CONNECTOR_RPC_SECRET` / JWT secret
- [ ] Restrict CORS to `portal.`, `admin.`, `cnktros.com`
- [ ] Cloudflare: IP allowlist on `/api/v1/admin`, `/api/v1/surveillance`
- [ ] Document break-glass procedure

### Phase 1 — Core deploy (2 weeks)

- [ ] Neon `connector_license` + run migrations
- [ ] Fly `connector-license` + volume + secrets
- [ ] Build & embed www + admin dist in Docker image
- [ ] DNS: `api`, `portal`, `admin`, `try`
- [ ] Stripe webhooks → active keys → auto-issuance hook
- [ ] Portal register/login/TOTP smoke test
- [ ] Single-node RPC auth smoke: install binary → `/rpc/v1/auth` → heartbeat

### Phase 2 — Playground + marketing (1 week)

- [ ] Fly `connector-playground`
- [ ] cnktros.com download + playground + auth CTAs
- [ ] Pilot grant flow: submit-pilot → admin → portal entitlement

### Phase 3 — Observability & ops (1 week)

- [ ] Fly metrics + Grafana Cloud (or Datadog)
- [ ] Alerts: auth error rate, Stripe webhook failures, kill command rate
- [ ] `backup-db.sh` cron to R2
- [ ] Runbook: revoke token, block hash, suspend customer

### Phase 4 — Scale prep (ongoing)

- [ ] Redis revocation fanout
- [ ] Async usage ingest queue
- [ ] `vendor_id` / `org_id` schema migration
- [ ] Load test: 10k auth/min, 100k heartbeat/min (k6)
- [ ] Optional `rpc.` edge split

---

## 9. Environment variable reference (production)

| Variable | App | Purpose |
|----------|-----|---------|
| `DATABASE_URL` | license | Neon Postgres |
| `CONNECTOR_RPC_SECRET` | license | HMAC sign RpcToken |
| `CONNECTOR_LICENSE_ADMIN_KEY` | license | Owner admin API |
| `CONNECTOR_PORTAL_JWT_SECRET` | license | Portal session JWT |
| `CONNECTOR_KEY_DIR` | license | Ed25519 signing keys volume |
| `STRIPE_*` | license | Payments |
| `SENDGRID_API_KEY` / `CONNECTOR_SMTP_URL` | license | Dunning email |
| `CONNECTOR_LICENSE_SERVER` | **vendor binary** | `https://api.cnktros.com` |
| `CONNECTOR_ROLE_ID` / `CONNECTOR_SECRET_ID` | **vendor binary** | From issuance |
| `CONNECTOR_PLAYGROUND` | playground | `1` |

---

## 10. Success criteria

| Test | Pass |
|------|------|
| Customer signs up on portal | `portal_users` row, can log in |
| Stripe checkout completes | `license_keys` + `customers.Active` |
| Download triggers issuance | `binary_issuances` with fresh `secret_id` |
| Node starts on vendor VPC | `/rpc/v1/auth` → token; heartbeat accepted |
| Unpaid key | Auth returns 402; checkin returns `degrade` or `shutdown` |
| Owner opens admin panel | Only from allowlisted IP; all actions audited |
| Random internet caller hits `/api/v1/admin/stats` | **401/403** |
| Playground session | TTL expires; no permanent issuance |
| 24h offline after auth | Grace then read-only/block per policy |

---

## 11. File map (implementation reference)

| Area | Path |
|------|------|
| License server routes | `platform/licensing/src/main.rs` |
| RPC auth | `platform/licensing/src/rpc_auth.rs`, `rpc_token.rs` |
| Portal auth | `platform/licensing/src/portal.rs` |
| Surveillance / kill | `platform/licensing/src/surveillance.rs` |
| Node RPC client | `platform/server/src/binary_id.rs`, `phone_home.rs` |
| Admin UI | `platform/ui-leptos/admin/` |
| Customer portal UI | `platform/ui-leptos/www/` |
| Marketing site | `platform/docs/landing-page/web/` |
| Fly configs | `platform/deploy/fly.license.toml`, `fly.playground.toml` |
| Ops guide | `platform/deploy/DEPLOYMENT.md` |

---

*This plan supersedes informal deployment notes for control-plane concerns. Update when admin middleware ships and vendor_id migration lands.*
