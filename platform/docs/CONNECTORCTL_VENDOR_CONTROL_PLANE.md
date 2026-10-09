# Vendor Control Plane — Superadmin Commands for `connectorctl`

> **Scope:** commands that only **Connector (the vendor)** can run. They
> manage customers, pilots, API keys, license keys, binary issuances,
> and cluster-wide kill / degrade / block actions.
>
> **Not runnable by:** customers, operators, or the local platform admin.
> These commands talk **directly to the WWW control plane** (`portal.connector.dev`),
> *never* to the customer's local `connector-platform` daemon.

---

## 1. Architecture

```
  ┌──────────────────────────────┐
  │  Vendor Operator             │
  │  (Connector employee)        │
  │                              │
  │  $ connectorctl vendor ...   │
  └──────────────┬───────────────┘
                 │
                 │  HTTPS + VendorToken
                 │  (separate auth realm)
                 ▼
  ┌──────────────────────────────┐
  │  portal.connector.dev        │
  │  (platform/licensing/)       │
  │                              │
  │  - /api/v1/portal/*          │   Customer self-serve (user JWT)
  │  - /api/v1/admin/*           │   Vendor admin (VendorToken)
  │  - /api/v1/surveillance/*    │   Vendor enforcement (VendorToken)
  │  - /api/v1/keys/*            │   License key issuance (VendorToken)
  │  - /api/v1/issuances         │   Binary issuance creation (VendorToken)
  │  - /rpc/v1/*                 │   Binary phone-home (RpcToken)
  │                              │
  └──────────────┬───────────────┘
                 │                        Customer's local binary
                 │  heartbeat / usage     (connector-platform)
                 ▼                             :9091
            enforces kill / degrade /
            block-binary decisions
```

**Three auth realms — strictly separated:**

| Realm | Token header | Issued by | Scopes | Where it's valid |
|---|---|---|---|---|
| **Customer platform** | `Authorization: Bearer <api_key>` | Portal (`/portal/api-keys`) | operator:read, operator:write | customer's local `:9091` |
| **Binary RPC** | `Authorization: RpcToken <token>` | Portal (`/rpc/v1/auth`) | tier-derived | portal only, 1h TTL |
| **Vendor admin** | `Authorization: VendorToken <token>` | Portal (`/api/v1/vendor/token`) ⟵ **NEW** | vendor:read, vendor:write, vendor:enforce | portal only |

No overlap. A `VendorToken` must never be accepted at a customer's `:9091`; a customer `api_key` must never be accepted at `/api/v1/admin/*`. Enforced by middleware on both sides.

---

## 2. Existing portal endpoints (mapped)

Already implemented in `platform/licensing/src/`:

### 2.1 Customer self-serve (under user JWT)
- `POST /api/v1/portal/register` / `login` / `me` / `change-password`
- `POST /api/v1/portal/totp/{setup,verify}`
- `POST /api/v1/portal/api-keys` (create) / `GET` (list) / `DELETE /{id}` (revoke)
- `PATCH /api/v1/portal/profile`
- `GET /api/v1/portal/pilot` — my pilot status
- `GET /api/v1/portal/entitlement`

### 2.2 Vendor admin (under `VendorToken`)
- `GET /api/v1/admin/stats`
- `GET /api/v1/admin/instances`
- `GET /api/v1/admin/dunning`
- `POST /api/v1/admin/customers/{id}/{suspend,restore,message}`
- `GET /api/v1/admin/customers`
- **Pilots:** `POST /api/v1/admin/pilots` / `GET` / `GET /{grant_id}` / `DELETE /{grant_id}` / `POST /{grant_id}/revoke` / `GET /customers/{cid}/pilots`
- **License keys:** `POST /api/v1/keys/issue` / `validate` / `revoke` / `license-file` / `GET /{key_id}` / `GET /`
- **Binary issuances:** `POST /api/v1/issuances` / `GET /{binary_id}`
- **Surveillance / enforcement:**
  - `GET /api/v1/surveillance/{dashboard,instances,customers,events}`
  - `POST /api/v1/surveillance/{kill,degrade,block-binary}`

### 2.3 Binary RPC (under `RpcToken`)
- `POST /rpc/v1/{auth,renew,revoke}` / `GET /rpc/v1/verify`
- `POST /rpc/v1/{checkin,heartbeat,usage}` (legacy)

---

## 3. New endpoint: `POST /api/v1/vendor/token`

Issues a `VendorToken` for a Connector employee.

**Auth:** bootstrap once via a seed `VENDOR_BOOTSTRAP_SECRET` env var on the portal, then rotated via a TOTP-backed staff account (SSO in prod).

**Request:**
```json
{
  "staff_email": "umesh@connector.ai",
  "totp_code":   "123456",
  "scopes":      ["vendor:read", "vendor:write", "vendor:enforce"],
  "ttl_hours":   8
}
```

**Response:**
```json
{
  "vendor_token": "vtk_<base64url>.<hmac>",
  "token_id":     "vtk_<uuid>",
  "scopes":       ["vendor:read", "vendor:write", "vendor:enforce"],
  "expires_at":   "2026-04-22T09:00:00Z",
  "issued_to":    "umesh@connector.ai"
}
```

Token format mirrors `RpcToken` (HMAC-signed self-contained blob — no DB lookup per request). Revocation via bloom filter + append-only log.

**Scope semantics:**
- `vendor:read` — list instances, customers, pilots, dunning dashboard, surveillance events.
- `vendor:write` — issue keys, create pilots, suspend/restore customers, create issuances.
- `vendor:enforce` — kill, degrade, block-binary (destructive / customer-visible actions).

**Middleware:** a new `require_vendor_scope(scope)` extractor on all `/api/v1/admin/*`, `/api/v1/keys/*`, `/api/v1/issuances`, and `/api/v1/surveillance/*` routes.

---

## 4. `connectorctl vendor` command surface

**Top-level entry point:**
```
connectorctl vendor <subject> <verb> [args...]
```

All commands require `CONNECTOR_VENDOR_TOKEN` env var OR a prior `connectorctl vendor login`. The client NEVER hits the local `:9091` — it hits `$CONNECTOR_PORTAL_URL` (default `https://portal.connector.dev`) directly.

If no token is present, the CLI refuses with:
```
✖ VENDOR ACCESS REQUIRED
  This command is restricted to Connector staff.
  Run `connectorctl vendor login` or export CONNECTOR_VENDOR_TOKEN.
```

### 4.1 Auth
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor login` | `POST /api/v1/vendor/token` | (bootstrap) |
| `vendor logout` | `POST /api/v1/vendor/token/revoke` | any |
| `vendor whoami` | `GET /api/v1/vendor/token/verify` | any |

### 4.2 Customers
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor customer list [--tier=X]` | `GET /api/v1/admin/customers` | vendor:read |
| `vendor customer show <cid>` | `GET /api/v1/admin/customers/{cid}` | vendor:read |
| `vendor customer suspend <cid> --reason=...` | `POST /api/v1/admin/customers/{cid}/suspend` | vendor:write |
| `vendor customer restore <cid>` | `POST /api/v1/admin/customers/{cid}/restore` | vendor:write |
| `vendor customer message <cid> --text=...` | `POST /api/v1/admin/customers/{cid}/message` | vendor:write |
| `vendor customer dunning` | `GET /api/v1/admin/dunning` | vendor:read |

### 4.3 Pilots
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor pilot list` | `GET /api/v1/admin/pilots` | vendor:read |
| `vendor pilot show <grant_id>` | `GET /api/v1/admin/pilots/{grant_id}` | vendor:read |
| `vendor pilot create <cid> --tier=X --days=N --scope=a,b` | `POST /api/v1/admin/pilots` | vendor:write |
| `vendor pilot extend <grant_id> --days=N` | — (new route) | vendor:write |
| `vendor pilot revoke <grant_id>` | `POST /api/v1/admin/pilots/{grant_id}/revoke` | vendor:enforce |
| `vendor pilot expire <grant_id>` | `DELETE /api/v1/admin/pilots/{grant_id}` | vendor:write |
| `vendor pilot customer-pilots <cid>` | `GET /api/v1/admin/customers/{cid}/pilots` | vendor:read |

### 4.4 License keys
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor key issue --tier=X --customer=email [--expires=Y]` | `POST /api/v1/keys/issue` | vendor:write |
| `vendor key list [--tier=X] [--revoked]` | `GET /api/v1/keys` | vendor:read |
| `vendor key show <key_id>` | `GET /api/v1/keys/{key_id}` | vendor:read |
| `vendor key revoke <key_id> --reason=...` | `POST /api/v1/keys/revoke` | vendor:enforce |
| `vendor key validate <key>` | `POST /api/v1/keys/validate` | vendor:read |
| `vendor key license-file <key_id> --out=path` | `POST /api/v1/keys/license-file` | vendor:write |

### 4.5 Binary issuances
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor binary issue <key_id> [--machine-id=X] [--expires=Y]` | `POST /api/v1/issuances` | vendor:write |
| `vendor binary show <binary_id>` | `GET /api/v1/issuances/{binary_id}` | vendor:read |

### 4.6 Surveillance & enforcement
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor surveil dashboard` | `GET /api/v1/surveillance/dashboard` | vendor:read |
| `vendor surveil instances [--status=X]` | `GET /api/v1/surveillance/instances` | vendor:read |
| `vendor surveil events [--since=24h] [--follow]` | `GET /api/v1/surveillance/events` | vendor:read |
| `vendor surveil kill <instance_id> --reason=...` | `POST /api/v1/surveillance/kill` | vendor:enforce |
| `vendor surveil degrade <instance_id> --tier=community` | `POST /api/v1/surveillance/degrade` | vendor:enforce |
| `vendor surveil block-binary <binary_hash> --reason=...` | `POST /api/v1/surveillance/block-binary` | vendor:enforce |

### 4.7 Portal users (staff view of end-users)
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor user list [--since=24h]` | `GET /api/v1/admin/users` ⟵ NEW | vendor:read |
| `vendor user show <user_id\|email>` | `GET /api/v1/admin/users/{id}` ⟵ NEW | vendor:read |
| `vendor user impersonate <user_id>` | `POST /api/v1/admin/users/{id}/impersonate` ⟵ NEW | vendor:enforce (audited) |
| `vendor user api-keys <user_id>` | `GET /api/v1/admin/users/{id}/api-keys` ⟵ NEW | vendor:read |
| `vendor user revoke-api-key <user_id> <key_id>` | `DELETE /api/v1/admin/users/{id}/api-keys/{key_id}` ⟵ NEW | vendor:enforce |

### 4.8 Fleet rollups (vendor's global view)
| Command | Portal endpoint | Scope |
|---|---|---|
| `vendor fleet stats` | `GET /api/v1/admin/stats` | vendor:read |
| `vendor fleet instances` | `GET /api/v1/admin/instances` | vendor:read |
| `vendor fleet revenue [--month=YYYY-MM]` | `GET /api/v1/payment/revenue` | vendor:read |

**Total: 40 vendor-only verbs**, all gated by a separate auth realm.

---

## 5. Client implementation (`connectorctl`)

### 5.1 Code layout
```
platform/server/src/bin/connectorctl.rs
├── cmd_vendor(args)               # main entry — dispatches subject
│   ├── cmd_vendor_login / logout / whoami
│   ├── cmd_vendor_customer(args)
│   ├── cmd_vendor_pilot(args)
│   ├── cmd_vendor_key(args)
│   ├── cmd_vendor_binary(args)
│   ├── cmd_vendor_surveil(args)
│   ├── cmd_vendor_user(args)
│   └── cmd_vendor_fleet(args)
└── vendor_portal_get/post()       # HTTP helpers with VendorToken header
```

### 5.2 Token storage
- **Priority:** `CONNECTOR_VENDOR_TOKEN` env var → `~/.config/connectorctl/vendor.token` (mode 0600) → prompt.
- Never written to the main `~/.connector/config.yaml`.
- `vendor login` writes the token file; `vendor logout` deletes it.

### 5.3 Safety interlocks
1. Every enforcement action (`kill`, `degrade`, `block-binary`, `customer suspend`, `key revoke`, `pilot revoke`) requires either `--confirm <id>` or an interactive `Type the <kind> to confirm:` prompt.
2. `--dry-run` is available on every `vendor:enforce` command.
3. Every invocation is logged to the vendor audit log (portal-side: `POST /api/v1/admin/vendor-audit` — implicit, server-side).

### 5.4 Refusal on customer environments
- At boot, `cmd_vendor` checks whether the CLI is talking to `portal.connector.dev` OR a vendor-signed portal URL (`CONNECTOR_PORTAL_URL` pinned at build time in production binaries).
- If the configured portal is not in the vendor allowlist, `vendor *` returns:
  ```
  ✖ Vendor commands are only available against the Connector control plane.
  ```

---

## 6. Server-side changes required

### 6.1 Licensing crate (`platform/licensing/`)

1. **New route file:** `src/vendor.rs`
   - `issue_vendor_token(staff_email, totp, scopes, ttl)` — mirrors `rpc_auth` pattern.
   - `verify_vendor_token(headers)` — extractor used by middleware.
   - `revoke_vendor_token(token_id)`.

2. **Middleware:** `require_vendor_scope(scope: &'static str)` — Axum extractor that returns 403 on missing / insufficient scope. Applied to `/api/v1/admin/*`, `/api/v1/keys/*`, `/api/v1/issuances*`, `/api/v1/surveillance/*`.

3. **Bootstrap:** `VENDOR_BOOTSTRAP_SECRET` env var (32+ random bytes). First `vendor login` exchanges `(bootstrap_secret, staff_email)` for a token. Subsequent logins require TOTP (portal already has `totp_verify` wiring).

4. **Audit log:** `src/vendor_audit.rs` — append-only SQLite table `vendor_audit(ts, staff_email, token_id, action, target, payload, result)`.

5. **New routes:** user admin (§4.7): `/api/v1/admin/users`, `/{id}`, `/{id}/api-keys`, `/{id}/api-keys/{key_id}`, `/{id}/impersonate`.

### 6.2 Binary rejection of VendorToken
- `connector-platform` middleware must **reject** `VendorToken` headers with `401 { "error": "vendor tokens not accepted here" }`. Prevents accidental leakage.

### 6.3 CORS / origin pinning
- The portal restricts `/api/v1/admin/*` to an allowlisted origin (`admin.connector.dev`) — CLI bypasses CORS via Authorization header, but browser access is locked down.

---

## 7. Threat model

| Threat | Mitigation |
|---|---|
| Customer obtains a vendor token | Bootstrap secret is never shipped in customer binaries; TOTP required for rotation. Token has 8h TTL. |
| Vendor token exfiltrated | 8h TTL + revocation bloom filter + audit log. Portal can force rotate all staff tokens. |
| Replay of enforcement action | `--confirm <id>` is hashed into the audit record; duplicate calls with the same id no-op. |
| Customer binary accepts VendorToken | Platform middleware explicitly rejects the header. |
| Vendor staff misuse | Every `vendor:enforce` action written to append-only audit with staff_email. |
| Network compromise between CLI and portal | HTTPS + certificate pinning (optional `CONNECTOR_PORTAL_CA_PIN` env). |

---

## 8. Implementation order

Milestone **V1** — auth layer (required before any command ships):
1. `platform/licensing/src/vendor.rs` — token issue/verify/revoke.
2. Middleware `require_vendor_scope` + apply to all existing admin routes.
3. `vendor login / logout / whoami` CLI commands.
4. Bootstrap flow documented in ops runbook.

Milestone **V2** — customer & pilot management (daily-ops verbs):
5. `vendor customer list / show / suspend / restore / message / dunning`.
6. `vendor pilot list / show / create / extend / revoke / expire`.
7. `vendor key list / show / issue / revoke / validate`.

Milestone **V3** — enforcement:
8. `vendor binary issue / show`.
9. `vendor surveil dashboard / instances / events / kill / degrade / block-binary`.
10. Confirmation prompts + `--dry-run` on every enforce action.

Milestone **V4** — portal user admin (new routes):
11. `GET /api/v1/admin/users`, `/{id}`, `/{id}/api-keys`, impersonate endpoint.
12. `vendor user list / show / api-keys / revoke-api-key / impersonate`.

Milestone **V5** — polish:
13. Audit log UI (`vendor audit list [--staff=X] [--action=Y]`).
14. Stable JSON schemas documented per command.
15. Shell completion (`connectorctl vendor <TAB>`).

---

## 9. Summary tables

**Who can run what:**

| Caller | Realm | Can call |
|---|---|---|
| Customer operator | platform `:9091` | all 52 local verbs in `CONNECTORCTL_COMMAND_SPEC.md` |
| Customer's binary (auto) | `portal.connector.dev /rpc/v1/*` | token lifecycle, heartbeats |
| Connector staff | `portal.connector.dev /api/v1/admin/*` | all 40 vendor verbs in §4 |

**What the vendor cannot do from CLI:**
- Directly edit a customer's local kernel state (they must go through the customer's consent or use `surveil kill` which the binary enforces itself).
- Read customer data in plaintext (redaction policy on the portal's surveillance logs hides prompts/completions by default — separate "raw payload" scope not exposed to `connectorctl`).

---

**Status:** design approved, implementation starts at Milestone V1.
