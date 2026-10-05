# WASM Loading — Root Cause Analysis & Fix

## Problem

`https://try.cnktros.com/trial` was stuck showing a static loading spinner.
The browser console reported:

```
Script terminated by timeout at:
real@connector-ui-d2742c207d123924.js:1317:18
```

The WASM module was timing out before initialising — the browser killed the
async JS module script because `init()` (fetching + compiling 13 MB of WASM)
took longer than the browser's script-execution budget.

---

## Root Causes (in order of impact)

### 1. Wrong WASM build — `self-deploy` feature instead of `playground`

| | Value |
|---|---|
| **File** | `dist/` |
| **Feature compiled** | `self-deploy` (default) |
| **Required feature** | `playground` |

`Trunk.toml` (default config, `self-deploy` feature) and
`Trunk.playground.toml` (`playground` feature) write to `dist/` and
`dist/playground/` respectively. The Docker image was copying from `dist/`
which held the **wrong feature build**.

The `playground` feature changes:
- Trial page email → session → plugin navigation flow
- Deployment mode detection (hardcodes `Playground` at compile time)
- Removes `dev_bypass` path entirely

**Fix:** Always build with `Trunk.playground.toml` for playground deployments:
```sh
TRUNK_CONFIG=Trunk.playground.toml \
  trunk build --release --no-default-features --features=playground
```

---

### 2. `data-dev="1"` injection breaking the WASM at runtime

`dashboard_static.rs:dashboard_dev_html_enabled()` was returning `true`
because `CONNECTOR_PRESET=playground` triggers
`free_tier_open_auth_enabled()` → `operator_lab_auth_gate()` → `true`.

This injected `data-dev="1"` onto the `<html>` tag. The playground WASM reads
this on boot and enters dev-bypass mode — a code path that bails early on
playground servers, leaving `AuthState` unauthenticated and the reactive
system stalled.

**Fix:** `dashboard_static.rs` now short-circuits to `false` when
`CONNECTOR_PRESET=playground`:
```rust
if std::env::var("CONNECTOR_PRESET")
    .map(|v| v.eq_ignore_ascii_case("playground"))
    .unwrap_or(false)
{
    return false;
}
```

---

### 3. 13 MB uncompressed WASM — no `Content-Encoding: gzip`

The server was serving the raw 13 MB WASM with no compression. On a typical
connection (5–20 Mbps) this takes 5–20 seconds. Firefox/Chrome have a
~10 second soft timeout for module scripts, causing `Script terminated by
timeout`.

**Fix:** Pre-compress assets at build time and serve `.gz` siblings:

| Asset | Uncompressed | Gzipped | Reduction |
|---|---|---|---|
| `connector-ui-*.wasm` | 13.0 MB | 2.1 MB | **84%** |
| `connector-ui-*.js` | 62 KB | 9.8 KB | 84% |
| `tailwind.out-*.css` | 100 KB | 17 KB | 83% |

**Build step** (in `Trunk.playground.toml` post_build hook):
```sh
for f in dist/playground/*.wasm dist/playground/*.js dist/playground/*.css; do
  gzip -9 -f -k "$f"
done
```

**Server** (`router.rs:serve_with_compression`): when request has
`Accept-Encoding: gzip`, serve `filename.ext.gz` with:
```
Content-Encoding: gzip
Content-Type: application/wasm   # original mime, not gzip
Vary: Accept-Encoding
Cache-Control: public, max-age=31536000, immutable
```

---

## Architecture: Custom Static File Server

Replaced `tower_http::ServeDir` fallback with a purpose-built handler
`serve_with_compression` in `platform/server/src/router.rs`:

```
Request for /connector-ui-HASH_bg.wasm
         │
         ▼
  Accept-Encoding: gzip?
         │
    yes ─┤─────────────────────► /var/lib/connector/ui/connector-ui-HASH_bg.wasm.gz
         │                            │ exists?
         │                       yes ─┘ → serve with Content-Encoding: gzip
         │                       no  ─┐
    no ──┘                            │
         ◄────────────────────────────┘
         │
         ▼
  /var/lib/connector/ui/connector-ui-HASH_bg.wasm
         │ exists?
    yes ─┘ → serve plain
    no  ──► is_asset? → 404
            else     → serve index.html (SPA fallback)
```

**Cache headers:**
- Hashed assets (`*-HASH.wasm/.js/.css`): `public, max-age=31536000, immutable`
- HTML / SPA routes: `no-cache, no-store, must-revalidate`
- Other assets: `public, max-age=3600`

---

## Build Procedure (playground)

```sh
# 1. Build UI (playground feature, with gzip post-step)
cd platform/ui-leptos/dashboard
TRUNK_CONFIG=Trunk.playground.toml \
  trunk build --release --no-default-features --features=playground
# → dist/playground/*.{wasm,js,css,html} + .gz siblings

# 2. Copy to dist/ for Dockerfile
cp dist/playground/* dist/

# 3. Build server binary
docker run --rm \
  -v $(pwd)/../..:/repo -w /repo/platform/server \
  -e CARGO_TARGET_DIR=/repo/platform/deploy/playground-target-platform \
  rust:1.88-slim-bookworm \
  sh -c "apt-get install -y protobuf-compiler pkg-config libssl-dev && \
         cargo build --release --bin connector-platform"
cp platform/deploy/playground-target-platform/release/connector-platform \
   platform/deploy/artifacts/connector-platform

# 4. Docker build + deploy
docker build -f platform/deploy/Dockerfile.playground.unified \
  -t registry.fly.io/connector-playground:latest .
flyctl deploy -a connector-playground \
  --image registry.fly.io/connector-playground:latest --yes
```

---

## Verification

After deploy, confirm gzip serving:
```sh
curl -sI -H "Accept-Encoding: gzip" \
  https://try.cnktros.com/connector-ui-HASH_bg.wasm \
  | grep -E "content-encoding|content-length|cache-control"
# Expected:
#   content-encoding: gzip
#   content-length: 2185898   ← 2.1 MB not 13 MB
#   cache-control: public, max-age=31536000, immutable
```

Confirm no `data-dev` injection:
```sh
curl -s https://try.cnktros.com/trial | grep data-dev
# Expected: no output
```
