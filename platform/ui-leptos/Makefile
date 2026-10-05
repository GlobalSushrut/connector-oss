# Connector Leptos UI — DevOps Makefile

**WASM stack reference:** [UI_LEPTOS_WASM_STACK.md](./UI_LEPTOS_WASM_STACK.md) — loader patches, profiles, do-not-break rules.

# ──────────────────────────────────────
# Usage:
#   make dev-dashboard           # trunk serve dashboard, self-deploy profile + dev-bypass
#   make dev-dashboard-playground# trunk serve dashboard, playground profile + dev-bypass
#   make dev-www                 # trunk serve www (port 1421)
#   make dev-admin               # trunk serve admin (port 1422)
#   make build-self-deploy       # release build dashboard → dist/ (self-deploy)
#   make build-playground        # release build dashboard → dist/playground/
#   make build-dashboard         # alias of build-self-deploy (back-compat)
#   make build-www               # release build www
#   make build-admin             # release build admin
#   make build-all               # build all dashboards + www + admin
#   make check-all               # cargo check across all feature combos

.PHONY: dev-dashboard dev-dashboard-prodlike dev-dashboard-playground \
        dev-www dev-admin \
        build-dashboard build-self-deploy build-playground build-playground-trunk \
        build-www build-admin build-all \
        check-all clean-all

# ── Dev servers ───────────────────────────────────────────────────────────────
# `dev-dashboard` opts into the `dev-bypass` Cargo feature so the login page
# offers the one-click "Skip Auth" affordance for local operator workflows.
# Use `dev-dashboard-prodlike` to reproduce the production login experience.
# Use `dev-dashboard-playground` to develop the playground bundle on port 1430.

dev-dashboard:
	cd dashboard && trunk serve --features dev-bypass

dev-dashboard-prodlike:
	cd dashboard && trunk serve

dev-dashboard-playground:
	cd dashboard && TRUNK_CONFIG=Trunk.playground.toml \
	    trunk serve --no-default-features --features playground,dev-bypass

dev-dashboard-playground-leptos:
	cd .. && cargo leptos watch --split --lib-features playground,dev-bypass

dev-www:
	cd www && trunk serve --port 1421

dev-admin:
	cd admin && trunk serve --port 1422

# ── Production builds ─────────────────────────────────────────────────────────
# Release builds NEVER include the `dev-bypass` feature; the `auth::dev_bypass`
# symbol and login UI affordances are compiled out. The two distribution
# bundles target disjoint output dirs so both can ship side-by-side.

build-self-deploy:
	cd dashboard && env -u NO_COLOR -u FORCE_COLOR TRUNK_COLOR=auto \
	    trunk build --release --filehash false index.release.html

build-playground:
	cd dashboard && ./scripts/build-leptos.sh playground

build-playground-trunk:
	cd dashboard && env -u NO_COLOR -u FORCE_COLOR TRUNK_COLOR=auto \
	    TRUNK_CONFIG=Trunk.playground.toml \
	    trunk build --release --filehash false \
	    --no-default-features --features playground \
	    index.release.html

# Back-compat alias — the install pipeline still references `build-dashboard`.
build-dashboard: build-self-deploy

build-www:
	cd www && env -u NO_COLOR -u FORCE_COLOR TRUNK_COLOR=auto trunk build --release --filehash false index.release.html

build-admin:
	cd admin && env -u NO_COLOR -u FORCE_COLOR TRUNK_COLOR=auto trunk build --release --filehash false index.release.html

build-all: build-self-deploy build-playground build-www build-admin
	@echo "All UI bundles built (self-deploy + playground + www + admin)."

# ── Cargo check ───────────────────────────────────────────────────────────────

check-all:
	cd dashboard && cargo check --target wasm32-unknown-unknown
	cd dashboard && cargo check --target wasm32-unknown-unknown --features dev-bypass
	cd dashboard && cargo check --target wasm32-unknown-unknown --no-default-features --features playground
	cd dashboard && cargo check --target wasm32-unknown-unknown --no-default-features --features playground,dev-bypass
	cd www        && cargo check --target wasm32-unknown-unknown
	cd admin      && cargo check --target wasm32-unknown-unknown

# ── Clean ─────────────────────────────────────────────────────────────────────

clean-all:
	rm -rf dashboard/dist www/dist admin/dist
	@echo "All dist/ dirs removed."
