# Connector OS — Profile, payments, UI-RPC, and RBAC (server assessment)

**Scope:** Server-side individual “operator” identity, billing/payments, workflow objects, the **UI-RPC** WebSocket gateway, and how they relate to **Connector OS** presets / deployment modes.  
**Audience:** Platform engineers extending “user profile + payments + RPC” surfaces.

**Where this doc applies:** The REST/UI-RPC assessment below targets **`connector-platform`** (`platform/server/`) — the binary customers run for the full kernel and **embedded operator dashboard** (`connector-ui`, `/api/v1`). The **vendor-hosted** account portal (`connector-www`, `/api/v1/portal/*`) and its API live on **`connector-license-server`** (`platform/licensing/`). See **`ARCHITECTURE.md`** § “Customer node vs vendor control plane”.

---

## 1. Executive summary

| Area | What exists | Main gap |
|------|-------------|----------|
| **Human profile** | `User` in `UserStore` (Argon2, TOTP, API keys, **tier**, **billing_state**, Stripe id, token counters) persisted under `_auth_users` | **`GET /api/v1/auth/me`** does not expose billing/tier fields; UI must stitch REST calls |
| **Payments** | Stripe-oriented routes (`/billing/*`), usage tied to **JWT `sub`** in billing handlers | **Single-tenant** store: no `org_id` / workspace; workflows and kernel state are global |
| **REST `/api/v1` auth** | Router middleware: public allowlist, API keys (`cpk_*`, pilot scopes), JWT verify, dev/lab gate | **No global RBAC enforcement** from JWT `permissions` on the main API router (see §4) |
| **UI-RPC** | Separate listener (`CONNECTOR_UI_RPC_PORT`, default **9093**), JSON-RPC 2.0 over WebSocket, Bearer in `Sec-WebSocket-Protocol` | **No per-method RBAC**; session carries **`subject` + `is_dev` only**; powerful methods (e.g. **`system.dns`**) with no role check |
| **Dashboard UI** | Leptos CSR app talks **`/api/v1/*`** via fetch | **No in-tree consumer** of `/ui-rpc` in `platform/ui-leptos` — RPC path is optional / future |
| **Workflows** | `WorkflowRecord` in `engine_store` (`workflow_runtime`) | **No owner** field — all workflows are **node-global**, not per-user |
| **“Kernel profile”** | `KernelProfileRecord` / `POST /api/v1/kernel/profiles` | **Host egress policy**, not a user avatar/settings profile — naming collision for product docs |

---

## 2. Component map

### 2.1 Identity & profile (REST)

- **Model:** `auth::core::User` — `user_id`, `email`, `name`, `role: PlatformRole`, billing fields, `api_keys`, etc. (`platform/server/src/auth/core.rs`).
- **Persistence:** `UserStore::persist_user` → `engine_store.folder_put("_auth_users", …)`.
- **`/auth/me`:** Returns id, email, name, role, **static** `permissions` from `PlatformRole::permissions()`, TOTP flag, api key **count**, `instance_id` — **not** `tier`, `billing_state`, `stripe_customer_id`, usage counters (`auth::me` in same file).

**Implication:** A “profile management” page that only calls `/auth/me` cannot show plan or payment state without also calling `/billing/usage`, `/billing/entitlements`, `/billing/portal`, etc.

### 2.2 Billing & payments (REST)

- **Module:** `platform/server/src/services/billing.rs`.
- **User binding:** Handlers such as `billing_usage` use `extract_claims` → `claims.sub` → `user_store.get_user` — **correct per-user metering** for the single shared node.
- **Tiers:** `EntitlementSet::for_tier` encodes community/pro/team/enterprise limits.

**Implication:** Payments are **account-scoped** (JWT user), but **data plane** (agents, workflows, memory) is not namespaced by that user in the store layout described below.

### 2.3 RBAC (roles vs enforcement)

- **Roles:** `PlatformRole` — SuperAdmin → Service, with `rank()` and `permissions()` returning strings like `memory:read`, `users:write` (`auth/core.rs`).
- **JWT:** `Claims` includes `role` and `permissions: Vec<String>`.
- **Unused gateway path:** `auth::auth_middleware` implements `path_to_permission` (first URL segment under `/api/v1/` + GET→`read` else `write`) and checks `claims.permissions`. **This middleware is not wired on the main `router` API stack** — a repo-wide grep shows only `router.rs`’s **local** `auth_middleware` (JWT/API key **presence** and pilot scope), not `auth::auth_middleware`.

**Implication:** **Authorization is inconsistent:** some modules call `require_admin_or_dev` / `extract_claims` + role checks (e.g. `workflow_runtime` hydrate, `settings_secrets`, `plugin_hub`, `plugin_configure`, `author_portal`); many routes likely assume “any authenticated operator.”

### 2.4 UI-RPC (WebSocket JSON-RPC)

- **File:** `platform/server/src/ui_rpc/mod.rs`.
- **Auth:** On upgrade, `verify_token` → `UiSession { subject: claims.sub, … }` (or `dev` in dev bypass). **Role and permissions are not stored on `UiSession`.**
- **Dispatch:** `dispatch()` matches a small fixed set: `system.ping`, `system.boot_progress`, **`system.dns`** (full internal DNS dump), `agents.list`, `agents.get`, `health.status`, `audit.recent`, `metrics.summary`.
- **RBAC:** **None** inside `dispatch` — any user who passed WS auth can call any registered method.

**Risks:**

1. **`system.dns`** exposes internal service registry — high sensitivity on shared or pilot hosts.
2. **Parity:** REST may later gain per-route checks; UI-RPC will remain **superuser-shaped** unless mirrored.
3. **Observability:** RPC is logged with `source = "dashboard-ui"` but is **not** the same code path as REST audit middleware.

### 2.5 Dashboard UI (Leptos)

- **Search:** No `ui-rpc` / `WebSocket` references under `platform/ui-leptos/dashboard` in this repo snapshot.
- **Pattern:** Pages use `api::get_value("/…")` against **`/api/v1`** (same auth model as router).

**Implication:** “Enhance the serverside RPC server where people manage profile/payments” is **not** satisfied by current UI — those flows are **REST-first**. UI-RPC is a **parallel** channel suitable for push (`push.boot_progress`) and low-latency multiplexing, not yet the profile/billing control plane.

### 2.6 Workflows vs “profiles”

- **Record:** `WorkflowRecord { workflow_id, package_id, version, state, cls_source, updated_at }` — **no `owner_user_id` or `org_id`** (`workflow_runtime.rs`).
- **Auth:** Expensive `hydrate_dry_run_index` requires admin or dev; generic list/get may still expose **global** workflow IDs to any authenticated caller (handler-level review recommended).

**Implication:** **Connector OS “different workflows per profile”** (per-tenant or per-seat) needs a **data model change**: partition key on user/org, plus list filters and RBAC on transition/publish.

### 2.7 Connector OS presets vs RBAC

- **Presets / env:** `connector_profile`, `runtime_control`, `CONNECTOR_PRESET`, production hygiene — **node-level** behavior, not per-user.
- **Pilot keys:** Router enforces `pilot_scope_allows` for `cpk_pilot_*` in Pilots mode — **good** scoped exception model to copy for future “profile-scoped RPC tokens.”

---

## 3. Problem list (prioritized)

### P0 — Security / compliance

1. **UI-RPC authorization gap** — Authenticated viewer can invoke **`system.dns`** and **`audit.recent`** same as admin (`ui_rpc/mod.rs`).
2. **REST permission matrix dormant** — `auth::auth_middleware` + `path_to_permission` not applied on primary API router; JWT `permissions` are largely **informational** unless handlers enforce roles.
3. **Dev / lab auth gate** — `operator_lab_auth_gate` can allow unauthenticated `/api/v1/*` in some modes; intentional for DX but must stay **strictly off** in production (already aligned with other hygiene work in-repo).

### P1 — Product / architecture

4. **Profile API incomplete for “account center”** — `/auth/me` omits billing fields that already exist on `User`.
5. **No multi-tenant partition** — Single `UserStore` + global workflows + shared kernel — “individual profile” is **account** only, not **data isolation**.
6. **Naming collision** — “Kernel profile” (host policy) vs “user profile” (identity) confuses roadmaps and UI copy.

### P2 — Operations / DX

7. **UI-RPC unused by shipped dashboard** — Risk of **bit-rot** and security drift vs REST.
8. **No RPC methods** for `billing.*`, `users.*`, `workflows.*` — if UI moves to WS, everything must be re-spec’d and RBAC’d.

---

## 4. Recommendations

### Short term (1–2 milestones)

1. **UI-RPC hardening (minimal)**  
   - Attach **role + permission snapshot** to `UiSession` from JWT at handshake.  
   - Gate **`system.dns`**, **`audit.recent`**, and **`agents.*`** with `PlatformRole::rank()` or explicit permission strings.  
   - Document allowed methods in `platform/docs/` and OpenAPI-style RPC catalog.

2. **Profile surface (REST)**  
   - Extend **`/auth/me`** with **non-secret** billing summary: `tier`, `billing_state`, `agents_count`, token rollups, `stripe_customer_id` presence (boolean), link hints to `/billing/portal`.  
   - Or add **`GET /auth/profile`** returning a superset for the dashboard only.

3. **RBAC decision**  
   - Either **wire `auth::auth_middleware` after JWT validation** (merge with router middleware carefully), or **delete / quarantine** dead `path_to_permission` to avoid false confidence.  
   - Prefer **one** enforcement point: gateway or handlers, not neither.

### Medium term

4. **Tenant / org model** (if multi-seat product)  
   - Add `org_id` to `User`, scope workflows (`owner_org_id`), and optionally shard `engine_store` keys.

5. **UI-RPC product plan**  
   - If dashboard adopts WS: define **`profile.get`**, **`billing.summary`**, **`push.billing_state`**, with same authz as REST; keep mutations on REST until idempotency story is clear.

### Long term

6. **Separate “control plane RPC”** from **“data plane”** — gRPC or Connect for billing webhooks / internal services; keep UI-RPC for browser push only.

---

## 5. Key file index

| Concern | Location |
|---------|----------|
| User + billing fields | `platform/server/src/auth/core.rs` (`User`, `Claims`, `me`) |
| REST auth gate (not RBAC matrix) | `platform/server/src/router.rs` (`auth_middleware`) |
| RBAC middleware (currently unused on main API) | `platform/server/src/auth/core.rs` (`auth_middleware`, `path_to_permission`) |
| UI-RPC protocol + dispatch | `platform/server/src/ui_rpc/mod.rs` |
| Billing | `platform/server/src/services/billing.rs` |
| Workflows (no owner) | `platform/server/src/services/workflow_runtime.rs` (`WorkflowRecord`) |
| Kernel host “profile” | `platform/server/src/services/kernel_host.rs` |
| UI-RPC port config | `platform/server/src/config.rs` (`ui_rpc_port`, `ui_rpc_addr`) |

---

## 6. Conclusion

The server already has a **solid single-user auth + billing** story on **REST**, with **Stripe** and entitlements tied to JWT identity. The **UI-RPC** layer is a **thin, powerful** JSON-RPC channel that today **does not** implement profile/billing methods and **does not** replicate RBAC — it is **not** safe to expose as a “full operator control plane” without method-level authorization and UI adoption planning.

**Next engineering step:** decide whether **UI-RPC becomes first-class** (then add profile/billing RPC + session RBAC), or **stay a boot/push helper** while **REST + `/auth/me` enrichment** carries account management — and align **workflow** persistence with that decision via **ownership metadata**.
