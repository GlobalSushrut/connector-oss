# Dashboard Loading Architecture Plan

**Goal:** stop shipping the entire 50-page dashboard as one 8.9 MB WASM binary. Load only what
the current page needs — the way Next.js loads only the current route's JS — while keeping the
Rust/Leptos stack.

**Status:** PLAN (written 2026-06-12)
**Scope:** `platform/ui-leptos/dashboard` (and build/serve pipeline in `platform/server`)

---

## 1. The Problem

### 1.1 What happens today when a user opens any dashboard page

1. Browser requests `/agents` (or any route) → server returns the **same** `index.html`.
2. Browser downloads **one WASM binary containing all ~81 page modules** —
   8.9 MB raw / 2.4 MB gzip — even if the user only ever looks at one page.
3. The browser JIT-compiles all 8.9 MB before anything renders. WASM compile time is
   proportional to binary size; on a mid-range laptop this blocks for seconds, on weak
   hardware it triggers the browser's "this page is slowing down your browser" warning.
4. `main()` runs, the reactive graph for the whole app initializes, and only then does the
   route's page render and start fetching its data.

### 1.2 Root causes (architecture, not tuning)

| # | Cause | Evidence |
|---|-------|----------|
| 1 | **Monolithic compilation unit.** Leptos 0.7 CSR + Trunk produces exactly one `.wasm`. Every route registered in `main.rs` is compiled in, reachable or not. | 171 `.rs` files / 36k LOC → one 8.9 MB binary |
| 2 | **No lazy loading primitive.** Leptos 0.7 has no `#[lazy_route]`; the router resolves every view eagerly at compile time. | `main.rs` imports all 50+ page components directly |
| 3 | **Boot-time global fetches.** `deployment/info` (every 60 s, even unauthenticated), `auth/me`, shared requests, sidebar `/plugins/status` all fire at startup regardless of route. | `App()` root providers |
| 4 | **Per-page fetch storms.** Pages create up to 10 parallel `LocalResource`s on mount (Monitor). `request_store` exists but no page has adopted it. | `monitor.rs`, `request_store.rs` |
| 5 | **All rendering is client-side.** No SSR, no hydration, no islands — the browser does 100% of the work, the server only serves static files. | All 4 crates are `csr`-only |

The trial-app split (separate `connector-trial` crate, ~205 KB gzip, served for `/trial` +
`/login`) already proved the value of splitting: **12× smaller payload for anonymous users**.
This plan generalizes that win to the whole dashboard.

---

## 2. Where We Are (current inventory)

| Asset | Size (raw / gzip) |
|---|---|
| `connector-ui-*_bg.wasm` (full dashboard) | 8.9 MB / 2.4 MB |
| `connector-trial-*_bg.wasm` (trial + login) | 556 KB / 205 KB |
| Dashboard JS glue | 67 KB / 10 KB |
| Tailwind CSS (dashboard) | 100 KB / 17 KB |

- **Crates:** `dashboard` (81 page files, ~72 routes), `trial`, `www`, `admin` — all Leptos
  **0.7**, CSR-only, built with **Trunk** (not cargo-leptos).
- **Feature flags already present:** `full-pages`, `minimal`, `playground` / `self-deploy` —
  compile-time size levers, but still one binary per build.
- **Data layer:** REST via `gloo-net` (`api.rs`), per-page `LocalResource`; `request_store.rs`
  (shared health/notifications/agents resources) is wired but unused by pages; `ui_rpc`
  WebSocket exists server-side but no client uses it.
- **Serving:** `mount_dashboard_ui` in `platform/server/src/router.rs` does route-aware static
  serving (trial-app vs full bundle), pre-compressed `.gz`, immutable cache headers, SW.
- **Two route registries** that can drift: `main.rs` (real routes) and `routes.rs` (sidebar/⌘K).

---

## 3. How This Problem Was Solved Elsewhere

### 3.1 The JS world (what Next.js & friends actually do)

The JS ecosystem hit this exact wall in 2015–2017 era SPAs ("the 5 MB `bundle.js`"). The fixes,
in order of invention:

1. **Dynamic `import()` + route-based code splitting** (Webpack 2, 2017). The bundler cuts the
   app at `import()` boundaries into chunks. The router loads a route's chunk on navigation.
   Next.js made this automatic: **every page is its own chunk by construction**, plus a small
   shared "framework" chunk (React + router + layout).
2. **Prefetching.** Next.js `<Link>` prefetches a route's chunk when the link scrolls into the
   viewport or on hover — so navigation feels instant even though code loads lazily.
3. **Shared-chunk extraction.** Code used by ≥2 pages goes into a commons chunk, downloaded
   once, cached forever (content-hashed filenames + immutable cache headers).
4. **SSR / RSC (server does the rendering).** Next.js renders HTML on the server; the client
   downloads only the JS needed to hydrate interactive parts. React Server Components go
   further: server-only components ship **zero** JS to the browser.
5. **Per-page data fetching with cache** (SWR/React-Query): fetch on mount, cache by key,
   stale-while-revalidate, no global polling.

Key insight: **the unit of delivery became the route, not the app.**

### 3.2 The WASM world today (2025–2026)

WASM had the same problem worse (one linker output, no `import()` equivalent), and now has
real answers:

| Tool | What it does | Maturity |
|---|---|---|
| **Binaryen `wasm-split`** | Splits one `.wasm` into a primary module + lazily-loaded secondary modules; placeholder functions trigger the load. The foundation everything else builds on. | Stable tool; raw usage is manual (profile-guided) |
| **Leptos 0.8.5+ `#[lazy]` / `#[lazy_route]`** (July 2025) | Framework-integrated code splitting. `#[lazy]` makes any function load from a separate WASM chunk on first call. `#[lazy_route]` splits a route into a `data()` half (kept in the main binary, starts fetching immediately) and a `view()` half (lazy chunk, loaded **concurrently** with the data — no waterfall). Nested routes load all their chunks in parallel. Shared code between two lazy functions is automatically extracted into a common chunk (exactly like Webpack commons). Built with `cargo leptos build --split`. | Released; ecosystem stabilizing through 0.8.x → 0.9 (0.9 gates it behind a `lazy` feature flag). Known early bugs are being fixed (e.g. `__wasm_split.js` 404 with file hashing — fixed). |
| **Multi-app federation** | Several small WASM apps behind one origin; server routes paths to bundles; full page navigation between zones. | Proven **in this repo** (trial-app) |
| **SSR + islands (Leptos `ssr`/`hydrate`, islands router)** | Server renders HTML; client hydrates. Islands ship WASM only for interactive bits. | Mature in Leptos, but a different app architecture (server functions, hydration) — large migration from a CSR codebase |

**The Leptos `#[lazy_route]` model is the direct WASM equivalent of Next.js page chunks**, and
it's the path the framework itself recommends for exactly our situation.

### 3.3 What "load should be server-based" means for us

Two separable ideas, often conflated:

- **Code delivery** — don't ship code for pages the user isn't on. Solved by code splitting
  (§3.2). This is 90% of our pain and does **not** require SSR.
- **Rendering location** — server renders HTML, client hydrates. Solves first-paint latency
  and SEO. Bigger migration (CSR → SSR changes how every page is written and how the binary
  is built/served). Worth doing eventually for public-facing surfaces; **not** required to fix
  the loading problem.

This plan does code splitting first, and leaves SSR/islands as an explicitly-scoped later phase.

---

## 4. Options Considered

| Option | Initial payload | Effort | Risk | Verdict |
|---|---|---|---|---|
| **A. Keep monolith, optimize harder** (wasm-opt -Ozz, strip more, smaller deps) | ~7 MB (-20%) | S | Low | Insufficient. Already doing most of it. |
| **B. Multi-app federation** — split dashboard into N crates by zone (core / plugins / settings / wizards), server routes paths → bundles (extend the trial-app pattern) | ~1.5–2.5 MB per zone | M | Low (proven here) | Good fallback; duplicates shared code in every bundle (each zone re-ships leptos + components, ~1 MB+ each); hard navigation between zones loses SPA feel. |
| **C. Leptos 0.8 `#[lazy_route]` code splitting** — one app, shell in main binary, every page a lazy chunk | **~1–1.5 MB shell** + 50–300 KB per page chunk, loaded on demand, shared chunks extracted automatically | M–L | Medium (requires 0.7→0.8 upgrade + build pipeline change from Trunk to cargo-leptos or standalone wasm-split) | **Chosen.** The architecturally-correct fix; framework-supported; keeps SPA navigation; matches Next.js model exactly. |
| **D. Full SSR + islands rewrite** | KBs of HTML first paint | XL | High | Right long-term direction for public pages, wrong first move for a 36k-LOC CSR app. Deferred (Phase 6). |

Strategy: **C as the destination, B as the already-proven safety net** (if `--split` tooling
fights us on some milestone, the same page-boundary refactor lets us fall back to zone bundles
without wasted work — the code organization required is identical).

---

## 5. The Plan

### Phase 0 — Baseline & budgets (½ day)

- Record current metrics in CI: WASM size (raw/gzip), time-to-interactive on `/`, `/agents`,
  `/plugins/witnessctl` (throttled "Fast 3G + 4× CPU" Lighthouse run).
- Set budgets the build fails on later: **main shell ≤ 1.5 MB gzip; any page chunk ≤ 300 KB
  gzip; TTI on cold load ≤ 3 s on throttled profile.**

### Phase 1 — Stop the boot-time waste (1–2 days, ships value immediately, no upgrade needed)

1. **Gate `deployment/info`**: fetch once on boot, refresh only on auth change / window focus —
   not a 60 s unauthenticated poll.
2. **Defer sidebar `/plugins/status`** until sidebar is actually rendered (post-auth).
3. **Adopt `request_store` in the worst offenders** (Monitor's 10 parallel resources first),
   adding a simple cache-by-key + `ReloadPulse` stale-while-revalidate so navigating back to a
   page doesn't refetch everything.
4. **Unify the two route registries**: generate `main.rs` routes and the sidebar from one table
   (`routes.rs` becomes the single source of truth). Required prep for Phase 4 anyway.

### Phase 2 — Upgrade Leptos 0.7 → 0.8 (2–4 days)

- Per release notes, 0.8 is intentionally low-breakage from 0.7: main changes are
  `LocalResource` no longer wrapping values in `SendWrapper` (remove some `.as_deref()`),
  server-fn error types (we don't use server fns), Axum 0.8 re-exports (server crate is
  separate). Mechanical sweep over ~50 `LocalResource` call sites.
- Upgrade all four UI crates together (`dashboard`, `trial`, `www`, `admin`) to stay on one
  version.
- Ship behind the existing build pipeline (Trunk still works for non-split 0.8 builds) — this
  phase changes no architecture, just unblocks Phase 3.

### Phase 3 — Route-level code splitting (the core; 1–2 weeks)

1. **Build tool:** move the dashboard build from Trunk to **`cargo leptos build --split`**
   (cargo-leptos ≥ 0.3.x with out-of-repo `wasm-split`). Keep Trunk for the small crates
   (`trial`, `www`, `admin`) — they don't need splitting.
   - Port the Tailwind pre-build hook and `patch_wasm_init.py` post-processing (wasm-opt per
     chunk — cargo-leptos already runs wasm-opt separately on each split file; SRI hashes;
     gzip; SW) into the cargo-leptos pipeline / a thin wrapper script.
   - *Fallback if `--split` + CSR fights us:* run `wasm-split` CLI directly on the Trunk
     output, or fall back to Option B zone bundles. The page-boundary work below is identical
     either way.
2. **Define the main-binary "shell"** (what every page needs, loads once):
   auth, router, `AppShell` + `Sidebar` + header, toaster, error boundary, theme/CSS, `api.rs`,
   `request_store`. Target ≤ 1.5 MB gzip.
3. **Convert pages to `#[lazy_route]`**, in traffic order:
   - Wave 1: the 5 heaviest pages (`compliance` 1.5k LOC, `workflows`, `cls_builder`,
     plugin dashboards ×3) — biggest size wins.
   - Wave 2: all remaining top-level pages.
   - Wave 3: setup wizards + `/dev` pages (rarely visited — pure win).
   - Pattern per page: `data()` stays in main binary (creates the page's `Resource`s so
     fetching starts at navigation time), `view()` becomes the lazy chunk —
     **code and data load concurrently, no waterfall.**
4. **Prefetching (the Next.js trick):** on sidebar-link hover/focus and for the 3 most-likely
   next routes after login, call the lazy view's loader ahead of navigation. Chunks are
   content-hashed + `immutable`-cached, so prefetch is free on repeat visits.
5. **Serving:** extend `mount_dashboard_ui` to serve the split chunk files
   (`__wasm_split*.js`, chunk `.wasm` files) with the same gzip + immutable-cache treatment;
   update the service worker to cache chunks cache-first.

### Phase 4 — Data layer: page-scoped, cached, bounded (3–5 days, parallel with Phase 3 waves)

1. Every page declares its data in `LazyRoute::data()` — one place, started at nav time.
2. `request_store` grows into a small SWR-style cache: key → (value, fetched_at); pages read
   through it; background revalidate on focus/`ReloadPulse`; in-flight dedup.
3. Server-side pagination/limits for the heavy list endpoints (activity log, receipts,
   sessions) so a page never pulls unbounded data into browser memory.
4. Drop remaining polling in favor of refetch-on-focus (later: `ui_rpc` WebSocket push for the
   few live views — Monitor, activity — which is already built server-side).

### Phase 5 — Production hardening (2–3 days)

- CI budgets from Phase 0 enforced (`fail` if shell or any chunk exceeds budget).
- Chunk-load failure UX: retry + "new version deployed, reload" toast (chunk 404 after deploy
  = stale index; SW + content hashes make this deterministic).
- Loading skeletons per route (`Suspense` fallbacks) so lazy navigation never shows a blank.
- Lighthouse run on throttled profile in CI for `/`, `/agents`, one plugin dashboard.

### Phase 6 (deferred, separate decision) — SSR / islands for first-paint & public surfaces

- Candidates: `www` (marketing) and the logged-out surfaces — true server-rendered HTML.
- For the authenticated dashboard, evaluate Leptos islands-router once 0.9 stabilizes;
  re-assess after Phase 3 metrics — code splitting may already make this unnecessary.

---

## 6. Expected Outcome

| Metric | Today | After Phase 3 |
|---|---|---|
| First load (any page, cold) | 2.4 MB gzip WASM, compile-everything | ~1–1.5 MB shell + 1 page chunk (50–300 KB) |
| Navigate to a new page | 0 bytes but **all code already paid for up front** | 1 chunk (often prefetched), data loads concurrently |
| `/trial`, `/login` | 205 KB (already split) | unchanged |
| Rarely-visited pages (wizards, dev) | always shipped | never shipped unless visited |
| Browser memory | whole app's reactive graph | shell + visited pages only |

## 7. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| `--split` tooling is young (released mid-2025) | Pin cargo-leptos + leptos versions; e2e smoke test per chunk in CI; fallback = Option B zone bundles (same refactor, different cut points) |
| 0.7→0.8 regressions across 36k LOC | Mechanical change list is small (LocalResource API); full-page click-through test before Phase 3 starts |
| Trunk → cargo-leptos pipeline churn (Tailwind hook, SRI, SW, deploy scripts) | Phase 3.1 is exactly this port, done before any page conversion; keep Trunk path working until parity proven |
| Shared-chunk explosion (too many tiny files) | Start with route-level splits only; let the splitter extract commons; review chunk map per wave |
| Stale chunks after deploy | Content-hashed names + immutable cache + reload toast on chunk 404 |

## 8. Decision Log

- **2026-06-12** — Plan written. Chosen path: Leptos 0.8 `#[lazy_route]` route-level code
  splitting (Option C) with zone-bundle federation (Option B) as fallback; SSR/islands
  explicitly deferred to Phase 6. Trial-app split (done earlier) stays as-is and validated
  the splitting approach: 12× payload reduction for anonymous users.
