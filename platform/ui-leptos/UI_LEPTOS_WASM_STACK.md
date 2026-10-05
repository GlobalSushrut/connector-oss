# Leptos / WASM Operator UI Stack

**Status:** Canonical — do not regress.  
**Applies to:** `platform/ui-leptos/dashboard` (`connector-ui`) — the operator dashboard embedded in `connector-platform`.  
**Related:** [UI_MAKEOVER_PLAN.md](../../UI_MAKEOVER_PLAN.md) · [UI_PAGE_DESIGN.md](../../UI_PAGE_DESIGN.md) · `Makefile` · `.github/workflows/ui-leptos.yml`

**One sentence:** The operator UI is **Leptos 0.8 CSR compiled to WebAssembly** — not a JavaScript/React SPA. WASM loading, code splitting, and cache busting were solved the hard way; **keep this pipeline intact** when adding shell components.

---

## 1. Stack (non-negotiable)

| Layer | Choice | Not this |
|-------|--------|----------|
| UI framework | **Leptos 0.8** (`features = ["csr"]`) | React, Vue, Svelte, plain JS SPA |
| Language | **Rust → `wasm32-unknown-unknown`** | TypeScript app bundle for dashboard |
| Router | `leptos_router` | React Router, client-side history in JS |
| HTTP | `gloo-net` | `fetch` wrappers in JS |
| Styling | **Tailwind** (`input.css` → `tailwind.out.css`) | CSS-in-JS, separate design-system npm package |
| Dev server | **Trunk** (self-deploy) or **`cargo leptos watch --split`** (playground) | Vite, webpack, Next.js |
| Production playground | **`cargo leptos build --split`** + `patch_wasm_init.py` | Trunk-only for try.cnktros.com |
| Server embed | `include_dir!` via `platform/server/build.rs` | Serving raw `src/` or bundling JS from npm |

New operator shell work (`OpPulseBar`, drawer topics, workflow cards) **extends the existing Leptos crate** — no parallel frontend.

---

## 2. Why WASM loading was painful (and what we fixed)

Browsers kill long-running synchronous WASM init (“script timeout”, “terminated”). Split modules + CDN caching added **stale chunk** bugs (main module from release N, `chunk_*.wasm` from N−1 → opaque instantiate failures).

**Do not undo these fixes.**

### 2.1 Rust entry — return from `hydrate()` immediately

`dashboard/src/lib.rs`:

- `#[wasm_bindgen(start)]` → `hydrate()`
- `hydrate()` uses `spawn_local` + `TimeoutFuture(0)` before `mount_to(#root)`
- **Reason:** wasm-bindgen’s browser watchdog only measures **synchronous** work in the init closure. Scheduling mount as a microtask lets init return fast even when the reactive graph takes hundreds of ms.

**Do not** move heavy sync work into `hydrate()` without measuring watchdog behavior.

### 2.2 HTML boot splash — honest loading UX

`dashboard/index.html`:

- `#root` contains `.boot-splash` (spinner + `#boot-msg` + `#boot-err`)
- `hydrate()` clears `#root` inner HTML before mount
- CSS `#root:has(> :not(.boot-splash)) .boot-splash { display: none }` hides splash when real UI mounts
- `data-trunk rel="rust" data-no-wasm-opt"` — Trunk must **not** run extra wasm-opt (breaks wasm-bindgen closures on trial; redundant with cargo-leptos on split builds)

### 2.3 `patch_wasm_init.py` — production loader (playground + patched trunk)

Run automatically by `build-leptos-core.sh` after every `cargo leptos build --split`.

| Fix | What it does |
|-----|----------------|
| **Async IIFE** | Module script returns immediately; no browser script-timeout |
| **Streaming fetch** | `init({ module_or_path: fetch(wasm) })` — compile while downloading |
| **Boot progress** | Updates `#boot-msg`: “Downloading…”, “Compiling…” (1–2 min first visit is normal) |
| **3-minute race** | User-visible error + hard-refresh hint instead of silent hang |
| **No double hydrate** | Does **not** call `bindings.hydrate()` — `#[wasm_bindgen(start)]` already runs it |
| **SW unregister** | Clears stale service-worker caches before load |
| **wasm-opt OFF** | Split modules share one indirect function table; per-file wasm-opt **renumbers table indices** and breaks cross-module calls |
| **pkg/ mirror** | Copies `connector-ui.js|wasm` into `pkg/`; rewrites `__wasm_split*.js` imports |
| **Cache-bust `?v=`** | Single `build_v` from wasm hash on JS, wasm, split chunks, CSS — prevents CDN pairing main@N with chunk@N−1 |
| **Import key rule** | Query strings on import **specifiers** OK; import **object keys** must stay exact module names (no `?v=` on keys) |
| **gzip -9** | All `.js`, `.css`, `.wasm`, `sw.js` — server can serve precompressed |
| **Playground auth gate** | Inline script before WASM — unauthenticated users → `/login` (trial app) without compiling full dashboard |
| **Trial SW cleanup** | Trial bundle unregisters dashboard service workers |

**Never re-enable standalone `wasm-opt` in `patch_wasm_init.py` without validating the full split module graph.**

### 2.4 Code splitting — keep bundles loadable

Playground / large dashboard builds use:

```bash
cargo leptos build --split --release --frontend-only --lib-features playground|self-deploy
```

- Workspace config: `platform/ui-leptos/Cargo.toml` → `[[workspace.metadata.leptos]]`
- Profile: `wasm-release` (LTO, `opt-level = "z"`)
- Lazy routes: `dashboard/src/routing/lazy_routes.rs` — `#[lazy_route]` for heavy pages (workflows, CLS, plugin consoles)

**Shell components:** prefer lazy routes for new heavy drawers; keep initial chunk small enough for first compile.

---

## 3. Build profiles & commands

Two **mutually exclusive** Cargo features (`compile_error!` if both):

| Profile | Feature | Output | Build command |
|---------|---------|--------|---------------|
| **Self-deploy** | `self-deploy` (default) | `dashboard/dist/` | `make -C platform/ui-leptos build-self-deploy` (Trunk) |
| **Playground** | `playground` | `dashboard/dist/playground/` (+ releases manifest) | `make -C platform/ui-leptos build-playground` (cargo-leptos + patch) |

**Dev only:** `dev-bypass` — login “Skip Auth”. **Never** in release (`ui-leptos.yml` greps wasm for `dev_bypass` symbol).

```bash
# Local dev — self-deploy + skip auth
make -C platform/ui-leptos dev-dashboard

# Local dev — playground profile
make -C platform/ui-leptos dev-dashboard-playground

# Local dev — cargo leptos hot reload (playground)
make -C platform/ui-leptos dev-dashboard-playground-leptos

# Check all feature combos
make -C platform/ui-leptos check-all
```

### Embed into `connector-platform`

1. Build dashboard → `platform/ui-leptos/dashboard/dist/` (must contain `index.html` + wasm chunks)
2. `platform/server/build.rs` copies dist → `OUT_DIR/dashboard_embed` for `include_dir!`
3. If dist missing → **stub** UI (CI clean checkout still compiles)
4. Runtime override: **`CONNECTOR_UI_DIR`** → serve from disk instead of embed

**After UI changes:** rebuild dashboard **before** `cargo build -p connector-platform`, or set `CONNECTOR_UI_DIR` to fresh dist. `scripts/doctor.sh` warns when `src/` is newer than `dist/`.

---

## 4. File map (touch these, not random JS)

| Path | Role |
|------|------|
| `dashboard/src/lib.rs` | WASM entry, `hydrate()`, app router |
| `dashboard/src/api.rs` | `/api/v1` client (gloo-net) |
| `dashboard/index.html` | Trunk template, boot splash, `data-no-wasm-opt` |
| `dashboard/scripts/build-leptos-core.sh` | Tailwind + cargo-leptos + patch + gzip |
| `dashboard/scripts/patch_wasm_init.py` | **WASM loader patches — sacred** |
| `dashboard/scripts/leptos_index.py` | CSR `index.html` for cargo-leptos output |
| `dashboard/scripts/build_release.py` | Playground manifest + trial-app bundle |
| `dashboard/scripts/playground_auth_gate.py` | Pre-WASM auth redirect |
| `dashboard/public/sw.js` | Service worker (copied to dist; unregister on boot) |
| `platform/ui-leptos/Makefile` | Dev + release entrypoints |
| `platform/ui-leptos/Cargo.toml` | `workspace.metadata.leptos` split config |
| `platform/server/build.rs` | Stage dist for embed |
| `platform/server/src/dashboard_embed.rs` | Serve embedded or `CONNECTOR_UI_DIR` |

---

## 5. Rules for v3 shell work (UI_MAKEOVER_PLAN)

When implementing RUN · WATCH · FIX · SETUP:

1. **New components = `.rs` files** under `dashboard/src/components/operator/` (or `components/ui/`).
2. **No new npm app** — Tailwind classes + existing `Op*` tokens ([UI_OPERATOR_COMPONENT_SYSTEM.md](../../UI_OPERATOR_COMPONENT_SYSTEM.md)).
3. **Data fetching = `api.rs` / `request_store.rs`** — same patterns as existing pages.
4. **Do not add synchronous WASM work** on first paint path.
5. **Do not add pages without considering lazy split** — large new routes should use `#[lazy_route]` where applicable.
6. **Do not change `patch_wasm_init.py` or loader script** unless you understand split-module cache busting; run full playground build + hard-refresh test.
7. **Honesty components** (`fmt_unknown`, `VerifiedBadge`) are Rust — keep them shared, not duplicated in JS.

---

## 6. Debugging WASM load failures

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Blank page, no error | Stale embed — server built without fresh dist | Rebuild UI, rebuild platform, or `CONNECTOR_UI_DIR` |
| “import object field … is not an Object” | Stale split chunk or bad `?v=` on import **key** | Full playground rebuild; hard refresh; check `patch_wasm_init` chunk URLs |
| “timeout” / “terminated” | Sync work in init or missing async IIFE | Check `hydrate()` still uses `spawn_local`; check index script patched |
| Double mount / weird router | `hydrate()` called twice | Remove manual `bindings.hydrate()` from HTML |
| 8MB cached old dashboard | Service worker | Boot script unregisters SW; clear site data |
| `dev_bypass` in production | Wrong features on release build | Never pass `dev-bypass` to trunk/leptos release |

**Verify release:**

```bash
cd platform/ui-leptos/dashboard
python3 scripts/build_release.py --profile playground
python3 scripts/verify_release.py dist/playground/current
```

---

## 7. CI

`.github/workflows/ui-leptos.yml`:

- Feature matrix: `self-deploy`, `playground`, ± `dev-bypass`
- Trunk release build per profile
- Guards: no `dev_bypass` in shipping wasm, no playground/self-deploy leakage, no raw `/api/v1/` in body copy

Path-scoped — only runs when `platform/ui-leptos/**` changes.

---

## 8. What we are NOT doing

- Rewriting the dashboard in JavaScript/TypeScript “for faster iteration”
- Adding Vite/webpack alongside Trunk/cargo-leptos for the operator app
- Re-enabling per-file wasm-opt on split builds
- Calling `hydrate()` from both `#[wasm_bindgen(start)]` and inline HTML
- Shipping `dev-bypass` in playground or self-deploy release artifacts
- Assuming `cargo build -p connector-platform` picks up UI source changes without a dist rebuild

---

*If WASM loading regresses, compare against this doc and git history for `patch_wasm_init.py` + `lib.rs::hydrate()` before trying new loader hacks.*
