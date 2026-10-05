# Connector — Role Distribution & Authority Model

> Who can do what, and where the authority is enforced.
> Supersedes any ambiguity in the older RBAC notes.

---

## 1. Three worlds, three authorities

Connector runs as three cleanly separated planes. Each has its **own auth realm, its own code path, and its own audit log**.

```
┌───────────────────────────────┐    ┌───────────────────────────────┐    ┌───────────────────────────────┐
│  VENDOR PLANE                 │    │  CUSTOMER PLATFORM PLANE      │    │  AGENT PLANE                  │
│  (Connector — us)             │    │  (customer's own servers)     │    │  (agents running workloads)   │
│                               │    │                               │    │                               │
│  portal.connector.dev         │    │  connector-platform :9091     │    │  spawned by the platform       │
│  platform/licensing/          │    │  platform/server/             │    │  vac-core kernel              │
│                               │    │                               │    │                               │
│  Authority:                   │    │  Authority:                   │    │  Authority:                   │
│  - license lifecycle          │    │  - agent CRUD                 │    │  - act within assigned scope  │
│  - billing + subscriptions    │    │  - policy / runtime config    │    │  - heartbeat + emit receipts  │
│  - customer provisioning      │    │  - KECS / books / audit       │    │  - cannot escalate privilege  │
│  - kill / degrade / block     │    │  - all 52 local verbs         │    │                               │
│  - pilot grants               │    │                               │    │                               │
└───────────────────────────────┘    └───────────────────────────────┘    └───────────────────────────────┘
         │                                         │                                         │
         │ RPC HTTPS (token)                       │ kernel syscalls                         │
         ├─ /rpc/v1/{auth,renew,...}  ◄────────────┤                                         │
         ├─ /api/v1/admin/* (VendorToken)          │                                         │
         └─ /api/v1/portal/*  (UserJwt)            │                                         │
                                                   │ audit receipts, cost ledger    ◄────────┤
                                                   │ heartbeats                              │
                                                   │                                         │
                                                   └─── heartbeat / usage ───► portal        │
```

**Key invariant:** no plane can unilaterally mutate another. The vendor plane can *kill* a customer's platform (via signal to the binary), but cannot read or write its internal kernel state. The customer plane can *register* agents but cannot mint vendor tokens. Agents can *emit work* but cannot alter policy.

---

## 2. Roles

### 2.1 Vendor-side roles (Connector staff — **you and your team**)

Hosted on the WWW control plane (`platform/licensing/`). Governed by `VendorToken`.

| Role | Scopes | Can do | Cannot do |
|---|---|---|---|
| **`vendor:owner`** | read, write, enforce, billing, staff-admin | everything including rotating the `VENDOR_BOOTSTRAP_SECRET`, creating other vendor staff | nothing restricted |
| **`vendor:admin`** | read, write, enforce | all customer / pilot / key / enforcement operations | create/revoke vendor staff; rotate bootstrap secret |
| **`vendor:ops`** | read, write | customer mgmt, pilot issuance, license key issuance, view surveillance | enforcement (`kill`, `degrade`, `block-binary`, suspend) |
| **`vendor:support`** | read | read-only dashboards, customer lookup, impersonate with audit | any mutation |
| **`vendor:billing`** | read, billing | revenue dashboards, Stripe reconciliation, dunning mgmt | technical enforcement |
| **`vendor:auditor`** | read-audit-only | vendor_audit log, signed staff activity exports | nothing else |

All vendor actions are written to the **vendor audit log** (append-only, signed). The `vendor:auditor` role is the only role that can *read* this log — even owners can't silently delete entries.

### 2.2 Customer-side roles (inside a customer tenant)

Governed by portal-issued API keys (`cpk_...`) mapped to operator ranks on the customer's platform.

| Role | Rank | Scopes | Can do |
|---|---|---|---|
| **`tenant:owner`** | 6 | operator:*, admin:* | everything in their tenant: register agents, change policy, delete, invite other tenant users |
| **`tenant:admin`** | 5 | operator:*, admin:agent, admin:policy | operator work + policy changes; cannot delete tenant |
| **`tenant:operator`** | 4 | operator:read, operator:write | spawn/pause/resume/kill agents, view audit, run `connectorctl` day-to-day |
| **`tenant:developer`** | 3 | operator:read, dev:deploy | deploy manifests, run experiments; cannot kill production agents |
| **`tenant:viewer`** | 2 | operator:read | read-only dashboards |
| **`tenant:service`** | 1 | narrow scope (configurable) | headless service accounts for CI, gateways |

Mapped to the existing `caller(headers) -> (user_id, Role)` extractor in `platform/server/src/services/agents.rs`. Rank numbers match the existing `role.rank()` comparisons (`role.rank() < 4` = not-operator).

### 2.3 Agent-side roles (executing inside the kernel)

Attached to each `AgentControlBlock`. Enforced by the vac-core kernel during `dispatch(SyscallRequest)`.

| Role | Can syscall | Cannot |
|---|---|---|
| **`agent:worker`** (default) | memory read/write within own namespace, cost tracking, heartbeat, receipt emit | spawn agents, modify policy, access cross-tenant memory |
| **`agent:supervisor`** | worker + spawn child agents in same namespace | modify policy, cross-tenant |
| **`agent:reflector`** | worker + trigger reflection / retraining in own namespace | cross-namespace, policy changes |
| **`agent:system`** (reserved) | internal kernel-only; background tasks only | never exposed over HTTP |

---

## 3. Authority matrix — who can call what

Compressed view. Format: `✅` = allowed, `—` = denied, `📝` = allowed with audit trail.

| Action | Vendor Owner | Vendor Ops | Tenant Owner | Tenant Operator | Agent Worker |
|---|:---:|:---:|:---:|:---:|:---:|
| **Vendor plane** | | | | | |
| Issue license key | ✅ | ✅ | — | — | — |
| Revoke license key | 📝 | — | — | — | — |
| Create pilot grant | ✅ | ✅ | — | — | — |
| Kill customer binary (`surveil kill`) | 📝 | — | — | — | — |
| Block a binary hash | 📝 | — | — | — | — |
| Suspend a customer | 📝 | 📝 | — | — | — |
| Read vendor audit log | ✅ (read) | — | — | — | — |
| Create vendor staff account | 📝 owner-only | — | — | — | — |
| **Customer platform plane** | | | | | |
| List own agents | — | — | ✅ | ✅ | — |
| Register agent | — | — | ✅ | ✅ | — |
| Pause/resume agent | — | — | ✅ | ✅ | — |
| Terminate agent | — | — | ✅ | 📝 admin-rank | — |
| Clean all agents (`clean --force`) | — | — | 📝 owner-only | — | — |
| Change runtime policy | — | — | ✅ | — | — |
| View cost ledger | — | — | ✅ | ✅ | ✅ (own) |
| Verify audit chain | — | — | ✅ | ✅ | — |
| **Agent plane** | | | | | |
| Write memory in own ns | — | — | — | — | ✅ |
| Read memory in other ns | — | — | — | — | — |
| Spawn child agent | — | — | — | — | ✅ supervisor only |
| Emit audit receipt | — | — | — | — | ✅ |
| Modify own ACB | — | — | — | — | — |

---

## 4. Token types — final catalogue

| Type | Prefix | Signer | TTL | Where valid | Carries |
|---|---|---|---|---|---|
| **VendorToken** | `vtk_` | portal HMAC | 8h (rotate) | portal only | vendor scopes |
| **RpcToken** (binary) | (b64 blob) | portal HMAC | 1h | portal only | tier, machine_id |
| **PortalUserJwt** | JWT | portal JWT secret | 1h | portal only (customer self-serve) | user_id, email |
| **CustomerApiKey** | `cpk_` | portal (hashed on server) | no-expire unless set | customer platform `:9091` | tenant_role scopes |
| **AgentKernelToken** | (in-ACB) | kernel | lifetime of agent | kernel only | agent_pid, ns, role |

No token crosses realms. The CLI enforces this client-side; the servers enforce it on the boundary.

---

## 5. Bootstrapping a new vendor staff member

1. Existing `vendor:owner` runs:
   ```
   connectorctl vendor staff create --email alice@connector.ai --role vendor:ops
   ```
2. Portal sends `alice@connector.ai` a one-time activation link.
3. Alice clicks link → TOTP setup via `/portal/totp/setup` → saves recovery codes.
4. Alice runs `connectorctl vendor login` — enters email + TOTP → receives `VendorToken` (8h TTL).
5. Token stored in `~/.config/connectorctl/vendor.token` (mode 0600).
6. Every action Alice takes writes to `vendor_audit` with her email + token_id.

Rotation: tokens auto-expire after 8h. Alice must re-TOTP daily. `vendor:owner` can force-rotate all tokens (`connectorctl vendor staff rotate-all`).

---

## 6. Bootstrapping a customer tenant

1. Customer signs up at `portal.connector.dev` → gets `PortalUserJwt`.
2. Customer creates a `CustomerApiKey` via `POST /portal/api-keys` → returns `cpk_...`.
3. Customer installs `connector-platform` binary (has its own `role_id` + `secret_id` from the issuance).
4. On first start, binary calls `/rpc/v1/auth` with `role_id + secret_id` → gets `RpcToken` for phone-home.
5. Customer runs `connectorctl config set api_key cpk_...` → local CLI now talks to `:9091` using that key.
6. All local work is governed by the key's scopes (`tenant:owner` by default for the first key).
7. Customer can create more keys with narrower scopes for teammates.

---

## 7. Enforcement path for "kill a customer"

This is the most sensitive vendor action. Full chain:

```
 vendor:owner runs
 └── connectorctl vendor surveil kill inst_abc123 --reason "non-payment" --confirm inst_abc123
      └── POST portal/api/v1/surveillance/kill  (VendorToken, vendor:enforce)
           └── portal writes kill directive to instance_records
                └── binary's next heartbeat (/rpc/v1/heartbeat) receives "kill":true
                     └── connector-platform enters kill mode:
                          • graceful shutdown of agents
                          • flush audit chain to disk
                          • final /rpc/v1/usage report
                          • process exits with code 86
                               └── vendor_audit logs: staff_email, token_id, instance_id, reason
```

The customer's binary **enforces the kill on itself** — the vendor never directly touches the customer's kernel. This preserves the air-gap semantic: even a compromised portal cannot exfiltrate customer data; at worst it can force a shutdown.

---

## 8. Implementation status

| Component | Status | Location |
|---|---|---|
| Portal endpoints (`/api/v1/admin/*`, `/api/v1/surveillance/*`, `/api/v1/keys/*`) | ✅ exist | `platform/licensing/src/{portal,surveillance,routes,pilot_api}.rs` |
| `RpcToken` issuance + validation | ✅ exist | `platform/licensing/src/rpc_{auth,token}.rs` |
| Customer platform auth (`Bearer cpk_*`) | ✅ exist | `platform/server/src/services/agents.rs :: caller()` |
| Customer roles (rank 1–5) | ✅ exist | same file |
| **`VendorToken` issuance / verify / revoke** | ❌ **missing** | new: `platform/licensing/src/vendor.rs` |
| **`require_vendor_scope` middleware** | ❌ **missing** | new; applied to existing admin routes |
| **Vendor audit log** | ❌ **missing** | new: `platform/licensing/src/vendor_audit.rs` |
| **`connectorctl vendor *` subcommand** | ❌ **missing** | new: `platform/server/src/bin/connectorctl.rs` |
| **Customer platform rejects `VendorToken`** | ❌ **missing** | new middleware check |

Five gaps; all designed in `CONNECTORCTL_VENDOR_CONTROL_PLANE.md`.

---

## 9. What changes for existing code

1. Existing `/api/v1/admin/*` routes must gain a `require_vendor_scope("vendor:write")` extractor. Without it they're currently open (or guarded only by a weak admin header).
2. `PortalUserJwt` users who hit `/api/v1/admin/*` should get `403` with code `VENDOR_ONLY`.
3. `connectorctl` main dispatch adds one new verb: `vendor`. All other 52 verbs stay exactly the same.
4. The customer's platform adds one middleware line: reject `Authorization: VendorToken *` with 401 `vendor_token_not_accepted_here`.

No migration required. Existing customers keep working; the new vendor surface layers on top.

---

**One-sentence summary:** the **person who hosts `portal.connector.dev` controls the vendor realm via `VendorToken`**; the **customer controls their local platform via `CustomerApiKey`**; the **agents only ever see kernel tokens**. No token crosses a realm boundary, and every destructive action is audited.
