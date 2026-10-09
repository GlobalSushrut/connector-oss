# Dashboard Loading — Implementation Checklist

Track progress against [DASHBOARD_LOADING_ARCHITECTURE_PLAN.md](./DASHBOARD_LOADING_ARCHITECTURE_PLAN.md).

---

## Phase 0 — Baseline & budgets

- [ ] Record WASM sizes in CI artifact summary (raw + gzip)
- [ ] Lighthouse script: `/`, `/agents`, `/plugins/witnessctl` on Fast 3G + 4× CPU
- [ ] Set fail thresholds: shell ≤ 1.5 MB gzip, page chunk ≤ 300 KB gzip, TTI ≤ 3 s

---

## Phase 1 — Stop boot-time waste (no Leptos upgrade) ✅

### 1.1 Deployment polling

- [x] Fetch `/deployment/info` once on boot
- [x] Refetch on `visibilitychange` → visible (tab focus)
- [x] Playground: poll every 60 s (session countdown / caps)
- [x] Self-hosted: poll every 5 min (not 60 s always)

### 1.2 Defer authenticated-only fetches

- [x] Sidebar `/plugins/status` — only when `auth.is_authenticated`
- [x] Header health + notifications — use `request_store` (no duplicate + no refetch every route change)

### 1.3 Adopt `request_store`

- [x] Monitor `/monitor/health` → shared `health`
- [x] Overview `/agents` → shared `agents`
- [x] Monitor tab panels — mount per-tab component (fetch only when tab opened)
- [x] Memory page `/agents` → shared `agents`
- [x] Agents page → shared `agents`
- [x] Notifications page → shared `notifications`
- [x] Header notification preview → shared `notifications`
- [x] Search palette agents → shared `agents`

### 1.4 Route registry

- [x] `routes.rs` path table + `title_for_path()` (single source for sidebar/search/titles)
- [x] CI test: every `RouteDescriptor.path` has a matching route
- [ ] Leptos 0.8: move route views out of `main.rs` (0.7 tuple limit blocks macro/component grouping)

---

## Phase 2 — Leptos 0.7 → 0.8 ✅

- [x] Bump `leptos`, `leptos_router` to 0.8 in all four UI crates (+ `Cargo.minimal.toml`)
- [x] Fix `LocalResource` `.as_deref()` call sites (none in codebase — dashboard already used direct `.get()`)
- [x] Verify trial / www / admin still build (`cargo check` on all four)
- [x] Dashboard WASM release target builds (`cargo check --target wasm32-unknown-unknown --release`)
- [ ] Full click-through smoke test (manual, post-deploy)

---

## Phase 3 — Route-level WASM code splitting

- [x] Move dashboard build: Trunk → `cargo leptos build --split` (`make build-playground`; Trunk kept as `build-playground-trunk`)
- [x] Port Tailwind pre-build + `patch_wasm_init.py` into cargo-leptos pipeline (`scripts/build-leptos.sh`)
- [x] Workspace + `dashboard-server` + lib/cdylib entry (`dashboard/src/lib.rs`, `platform/ui-leptos/Cargo.toml`)
- [ ] Define shell binary budget — **Wave 1: 4.2 MB shell + ~720 KB lazy chunks (6 routes) + 34 shared `chunk_*.wasm`**
- [x] Wave 1 lazy routes: compliance, workflows, cls_builder, devguard/tracetramp/witnessctl plugin dashboards
- [x] Sidebar link prefetch on hover (`routing/lazy_preload.rs` + sidebar `mouseenter`)
- [x] SW cache update for split chunks (`public/sw.js` → `connector-v3-split`)
- [x] Playground auth gate — redirect unauthenticated users to `/login` before loading dashboard WASM
- [x] Server: `/` serves trial-app when `trial-app/` exists; trial pages unregister stale SW
- [x] Deploy split build + auth gate to `try.cnktros.com`
- [ ] Wave 2: remaining top-level pages
- [ ] Wave 3: wizards + dev pages

---

## Phase 4 — Data layer

- [ ] Page data declared in route `data()` (post lazy_route migration)
- [ ] SWR cache: key → (value, fetched_at), refetch on focus
- [ ] Server pagination on heavy list endpoints
- [ ] Evaluate `ui_rpc` WebSocket for Monitor / Activity live views

---

## Phase 5 — Production hardening

- [ ] CI size budgets enforced
- [ ] Chunk 404 → “new version deployed, reload” toast
- [ ] Per-route Suspense skeletons (no blank on lazy nav)
- [ ] Lighthouse in CI on throttled profile

---

## Phase 6 — SSR / islands (deferred)

- [ ] Decision doc: needed after Phase 3 metrics?
- [ ] `www` marketing SSR
- [ ] Dashboard islands-router evaluation

---

## Quick verify (after each deploy)

```bash
# Trial = lightweight bundle
curl -s https://try.cnktros.com/trial | grep -oP 'connector-(trial|ui)-[a-f0-9]+' | head -1

# Dashboard route = full bundle
curl -s https://try.cnktros.com/plugins/witnessctl | grep -oP 'connector-(trial|ui)-[a-f0-9]+' | head -1

# Session API works
curl -s -X POST https://try.cnktros.com/api/v1/playground/session \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@example.com"}' | jq '.ok, .api_key != null'
```
