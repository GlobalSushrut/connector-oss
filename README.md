# Connector OS (private)

Commercial governance kernel and plugins. The public launch tree is produced by `scripts/export-oss-launch.sh`. Do not publish this private repository. The export keeps `oss/` (Apache-2.0), the node under `platform/` (BSL 1.1), and the `agos` crates the node builds against. It leaves out the license server, billing portal, vendor admin UI, and `platform/docs/arch/`. From the published root, `./up.sh` is the start command.

**Product framing:** Ship and install **one Connector OS node** — **`connector-platform`** is the governed **runtime** (policy, agents, gateway, workflows, plugins); workflows and `.cpkg` plugins are **workloads on top** of that substrate, much like apps on an OS. **`connectorctl`** is the bundled **operator CLI** for the same node. Official packs put both in a **single tarball** (`make package` → `dist/connector-os-*-linux.tar.gz`). Narrative and topology (including the vendor-hosted license/portal plane) are summarized in **`ARCHITECTURE.md`**.

## Canonical binaries (release)

After a release build, installable artifacts are:

- `platform/server/target/release/connector-platform`
- `platform/server/target/release/connectorctl`

Build from the repo root:

```bash
cargo build --release --manifest-path platform/server/Cargo.toml --bin connector-platform --bin connectorctl
```

**Packaged release (Phase 1.7):** from the repo root, `make package` runs `scripts/package-connector-os.sh`, performs the same release build, and writes a single **`dist/connector-os-<version>-<arch>-linux.tar.gz`** containing `connector-platform`, `connectorctl`, `connector.yaml.example`, `VERSION`, and `README-OSS.txt`. Override the output directory with **`CONNECTOR_PACKAGE_DIR`**. To repack existing release binaries without rebuilding: **`CONNECTOR_PACKAGE_NO_BUILD=1 make package`**. CI runs the full pack on **`connector-platform-kernel`** (path-filtered); **`repo-hygiene`** only sanity-checks the script.

Debug equivalents live under `platform/server/target/debug/`.

## Local hygiene

- Never run `cargo` as **root** in this tree — it leaves `platform/server/target/` owned by root and breaks later builds. If that happened: `chown -R "${USER:-$LOGNAME}:${USER:-$LOGNAME}" platform/server/target`.
- Before a push, run `make doctor` (target ownership, default `CONNECTOR_PORT`, `cargo check`, dashboard `dist/` freshness).

## One-time secret migration (vault)

With the node running and `CONNECTOR_API_URL` / `CONNECTOR_API_KEY` set as for other `connectorctl` HTTP commands:

```bash
connectorctl bootstrap              # dry-run: list env vars that would be stored
connectorctl bootstrap --apply      # POST each to /api/v1/infra/vault/secrets
```

Then remove the migrated variables from your shell profile or service unit (`unset` lines are printed at the end). `CONNECTOR_API_KEY` is **not** migrated (it is the CLI→API credential).

Lab and compose helpers: `lab/README.md`, `scripts/lab_up.sh`.

## Supervisor library (Phase 1.1–1.2)

`platform/supervisor/` — `connector-supervisor` (`ProcessGroup`, `TcpHealthProbe` / `HttpHealthProbe`, `Backoff`, `ShutdownCoordinator`, optional prefixed log fan-in).

- **CI:** `repo-hygiene` runs `cargo test` for this crate.
- **`connectorctl start`** (non-systemd background): spawns `connector-platform` (or `cargo run …`) in a **Unix process group** via `connector-supervisor`; **`connectorctl stop`** uses `kill(-pgid, …)` with fallbacks.
- **Logs:** default child stdout/stderr are discarded (same as before). Set **`CONNECTOR_SUPERVISOR_LOGS=1`** to prefix-stream child logs to the supervisor thread’s stderr.

## Plugin manifest (Phase 1.3)

`platform/plugin-manifest/` — `connector-plugin-manifest`: parse and validate AGOS `plugin.toml` (see `examples/sample.plugin.toml`). **CI:** `repo-hygiene` runs `cargo test --manifest-path platform/plugin-manifest/Cargo.toml`.

## Plugin handshake (Phase 1.4)

`platform/plugin-handshake/` — `connector-plugin-handshake`: JSON bootstrap via `CONNECTOR_AGOS_HANDSHAKE` (file path) or `CONNECTOR_AGOS_HANDSHAKE_FD` (Unix, read-once fd). TraceTramp, WitnessCtl, and DevGuard apply it at startup before config/CLI. **Contract:** `PLUGIN_CONTRACT.md`. **CI:** `repo-hygiene` runs `cargo test --manifest-path platform/plugin-handshake/Cargo.toml`.

## Cage-internal DNS (Phase 1.4a)

`platform/server/src/internal_dns/mod.rs` registers `<slug>.<CONNECTOR_CAGE_TLD>` (default `cnktros`) for enabled first-party plugins and exposes **`/plugin/<slug>/*`** (same auth stack as `/api/v1`) to reverse-proxy to plugin management planes with a rewritten `Host` header. TLD: `connector.yaml` → `connector.cage_tld` or env. Details: `PLUGIN_CONTRACT.md` § Cage-internal DNS; `GET /api/v1/plugins/status` includes `cage_host` and `public_plugin_proxy_prefix`.

## `.cpkg` + Hub (Phase 4.2–4.4)

- **`platform/cpkg/`** — `connector-cpkg`: ZIP layout, `read_cpkg` / `write_cpkg`, **Ed25519** sign/verify (`sign_envelope`, `read_cpkg_verify_optional`). **CI:** `repo-hygiene` runs `cargo test --manifest-path platform/cpkg/Cargo.toml`.
- **`platform/hub/`** — `connector-hub` binary: `GET /v1/search`, `GET /v1/latest`, `GET /v1/cpkg`, `POST /v1/publish`, `POST /v1/yank`. Env: **`CONNECTOR_HUB_DATA_DIR`**, **`CONNECTOR_HUB_BIND`** (default `127.0.0.1:19100`), **`CONNECTOR_HUB_PUBLISH_TOKEN`** (optional Bearer gate).
- **Kernel install:** `POST /api/v1/plugins/cpkg/install` (JSON: `cpkg_base64` or `url`, optional `trust_keys`, `require_signature`, `verify_health_sec`), bundle **`/plugins/cpkg/bundle/export|import`**. **`CONNECTOR_CPKG_REQUIRE_SIGNATURE=1`** forces signed packages + `trust_keys` on install.
- **`connectorctl hub`** — `search | install | update | publish | yank` against **`CONNECTOR_HUB_URL`**; install pushes bytes to the kernel API.

## Embedded dashboard (Phase 1.5)

The Leptos dashboard `dist/` is compiled into **`connector-platform`** via `include_dir!` (`platform/server/src/dashboard_embed.rs`). `build.rs` copies `platform/ui-leptos/dashboard/dist` into `OUT_DIR` before compile, or falls back to a small **`platform/server/dashboard-embed-stub/`** if dist is missing. Override at runtime with **`CONNECTOR_UI_DIR`** (directory containing `index.html` / `index.release.html`) to serve from disk instead.
