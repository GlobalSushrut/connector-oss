# AGOS plugin authoring

> **AGOS** (Agent Governance OS) community plugins ship as a **`plugin.toml`** manifest plus a **`subprocess`** or **`wasm`** entrypoint. This page is the shortest path from zero to a verifiable “hello world” on **Connector OS** (`agos.v1`).

For the wire-level bootstrap JSON, see **[`PLUGIN_CONTRACT.md`](../../PLUGIN_CONTRACT.md)** in the repository root. For roadmap depth (SDK phases, certification), see **`CONNECTOR_OS_ROADMAP.md`** (Phase 6 and §2A.9).

---

## What you install

| Piece | Role |
|--------|------|
| **`agos-abi`** | Stable contract id (`agos.v1`); the kernel re-exports it on **`GET /api/v1`**. |
| **`agos-sdk`** | Public Rust SDK: manifest types, `load_manifest_path`, `assert_manifest_matches_abi`, handshake helpers. |
| **`cargo-connector`** | Cargo subcommand: **`cargo connector new …`** scaffolds Rust + `plugin.toml`. |
| **`connectorctl`** | **`plugin verify`**, **`plugin run --dev`**, Hub flows. |

From the **repository root**:

```bash
cargo install --path cargo-connector
```

---

## Hello world in under 30 lines (Rust + manifest)

The following two files are a complete minimal plugin: **25 lines** of `plugin.toml` and **3 lines** of Rust (**28 lines total** for manifest + entrypoint, under the “30-line hello world” bar). Adjust **`id`**, **`entrypoint`**, and **`routes`** to match your slug.

**`plugin.toml`**

```toml
[plugin]
id = "local/hello"
name = "Hello"
version = "0.1.0"
author = "local"
license = "MIT"
min_kernel = "0.1.0"
agos_abi = "agos.v1"

[runtime]
type = "subprocess"
entrypoint = "target/release/hello"
memory_mb = 32
vcpus = 1
shared = false
max_concurrency = 4
idle_window = "30s"
cold_start_budget_ms = 500

[routes]
prefix = "/plugins/hello"
admin = "/plugins/hello/admin/*"

[capabilities]
required = ["audit.write"]
```

**`src/main.rs`** (binary package name `hello`, same as release artifact)

```rust
fn main() {
    println!("hello from AGOS (local/hello)");
}
```

**`Cargo.toml`** (minimal binary crate)

```toml
[package]
name = "hello"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "hello"
path = "src/main.rs"
```

Build and certify locally:

```bash
cargo build --release
connectorctl plugin verify . --json
```

`verify` prints **`warnings`** (e.g. weak **`plugin.license`** vs SPDX) without failing; failures are **`fail`** checks only.

When a kernel is reachable, add **`--require-kernel`** to require **`GET /api/v1`** and a matching **`agos_abi.contract_id`**. Optional **`--probe-health`** calls **`GET /api/v1/health`** and checks the unified rollup for built-in slugs **`tracetramp`**, **`witnessctl`**, **`devguard`** (matched from the last segment of **`plugin.id`**). If you add **`[health]`**, **`path`** must be an absolute path such as **`/healthz`** (validated in **`verify`**).

---

## Preferred path: scaffold + verify

Let **`cargo connector`** create the same shape (project folder `vendor-slug`, `plugin.toml`, `Cargo.toml`, `.gitignore`):

```bash
cargo connector new local/hello
cd local-hello
cargo build --release
connectorctl plugin verify .
```

Then install a **`.cpkg`** rollout under **`CONNECTOR_DATA_DIR`** and use **`connectorctl plugin run --dev local/hello`** (tier admit, quarantine gate, tier touch) as described in **`connectorctl plugin help`**.

---

## Identity and policy rules (short)

- **`plugin.id`** must be **`vendor/slug`** where each segment uses only **`a-z`**, **`0-9`**, and **`-`**. Bare **`cargo connector new greeter`** becomes **`local/greeter`**.
- **`agos_abi`** must match the kernel contract (today **`agos.v1`**). Use **`agos_sdk::assert_manifest_matches_abi`** before registering routes or opening network in real code.
- **`connector/`** vendor ids are reserved for first-party plugins unless **`author`** is exactly **`Connector`** (see manifest validation).
- **`routes.prefix`** and **`routes.admin`** must **not** start with **`/api/v1`** (kernel namespace).
- Declare **`[capabilities].required`** honestly; certification (roadmap 2A.9) will tighten over time.

---

## Reference plugins (Acme)

Three in-repo stubs that use **only** **`agos-sdk`**: **`examples/agos-reference-plugins/`** (`acme/slack-notifier`, `acme/jira-bridge`, `acme/datadog-forwarder`). Run **`cargo check --manifest-path …/Cargo.toml`** in each directory.

## Next steps

- Add **`agos-sdk`** as a dependency when you read the handshake from the environment and register CNP surfaces.
- Package with **`.cpkg`** (`connector-cpkg` / Hub) before publishing; **`connectorctl plugin verify`** on the archive checks signature envelope presence (MVP).

---

## See also

- **[32 — connectorctl CLI](../32-connectorctl.md)** — AGOS **`plugin`** verbs.
- **[ABI versioning](abi-versioning.md)** — **`supported_contract_ids`**, deprecation, **`agos.v2`** staging.
- **`agos-sdk`** crate (`load_manifest_path`, `assert_manifest_matches_abi`).
- **`CONNECTOR_OS_ROADMAP.md`** §2A.9 — certification checklist before Hub publish.
