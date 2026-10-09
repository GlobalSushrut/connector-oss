# AGOS plugin contract (bootstrap)

This document is the normative reference for **Phase 1.4** kernel → plugin bootstrap. Runtime behaviour (routes, capabilities, migrations) lives in `CONNECTOR_OS_ROADMAP.md` §6 (`plugin.toml`).

## Handshake v1 (JSON)

When the kernel (or a lab launcher) starts a plugin process, it SHOULD pass configuration **once** using the **handshake** instead of scattering ad hoc env vars. Plugins call `connector_plugin_handshake::apply_from_env()` at the very beginning of `main`; that maps the document into the legacy env names they already read.

### `schema_version`

Must be `1`.

### `connector` (required when handshake is used)

| Field       | Type   | Meaning |
|------------|--------|---------|
| `base_url` | string | Connector HTTP API base (no trailing slash required; plugins trim). |
| `api_key`  | string? | API key / access key. Omitted means URLs only. |

### Mapped environment variables

After a successful apply:

- **TraceTramp:** `TRACETRAMP_CONNECTOR_BASE_URL`, and `TRACETRAMP_CONNECTOR_API_KEY` if `api_key` is set.
- **WitnessCtl:** `CONNECTOR_BASE_URL`, `CONNECTOR_API_KEY`, `CONNECTOR_KEY` (same value as `CONNECTOR_API_KEY` for alias compatibility).
- **DevGuard:** `CONNECTOR_URL`, `CONNECTOR_ACCESS_KEY` (when `api_key` is set).

### Delivery

1. **`CONNECTOR_AGOS_HANDSHAKE_FD`** (Unix): decimal file descriptor inherited by the child; the entire JSON document is read from that fd until EOF, then the fd is closed by the library.
2. **`CONNECTOR_AGOS_HANDSHAKE`**: absolute or relative path to a UTF-8 file containing the JSON document.

If `CONNECTOR_AGOS_HANDSHAKE_FD` is set to a non-empty value, it takes precedence over the path. If neither variable is set, apply is a no-op and plugins keep using `.env` / shell env as today.

### Example file

See `platform/plugin-handshake/examples/handshake.v1.json`.

## Cage-internal DNS (Phase 1.4a)

- **Cage host:** `<slug>.<cage_tld>` (default TLD label `cnktros` → e.g. `tracetramp.cnktros`). Configure via `connector.yaml` → `connector.cage_tld` or **`CONNECTOR_CAGE_TLD`** (single DNS label, no leading dot).
- **Registry:** The kernel keeps an in-process table (`internal_dns`) mapping each cage host to the current upstream **SocketAddr** (lab: parsed from `CONNECTOR_*_MANAGEMENT_URL`; otherwise the main API listener). **Do not** resolve `*.<cage_tld>` via the OS resolver or external DNS.
- **CLS / CNP:** Use `internal_dns::cage_routing_key` / `internal_dns::plugin_cage_hostname(slug)` in workflows and routing keys — not `127.0.0.1:port`.
- **Public proxy:** Authenticated **`/plugin/<slug>/*`** on the platform origin rewrites the upstream `Host` header to the cage hostname and injects the same admin bearer env vars as `/api/v1/plugins/...` proxies (TraceTramp / WitnessCtl). DevGuard upstream calls may be unauthenticated.

## ABI contract ids (Phase 6.9)

Kernel **`GET /api/v1`** and **`GET /health`** expose **`agos_abi.supported_contract_ids`** (install + tier admit) and optional **`staged_contract_ids`**. Policy for **`agos.v1` → `agos.v2`**: see **`docs/agos/abi-versioning.md`**.

## Workflow builder contract (U6.4)

CLS workflows must compose substrate APIs (memory, moment, usage, artifact log, CFNI)
and treat TraceTramp / WitnessCtl / DevGuard as optional projections.

- Normative builder guide: **`docs/agos/workflow-builder-contract.md`**
- Shipped sample (no institutions): **`substrate_memory_moment`** in
  `GET /api/v1/workflows/reference-templates`

## `.cpkg` signing (Phase 4.2)

- **Canonical digest:** `connector_cpkg::canonical_payload_digest(manifest_src, files)` — SHA-256 over sorted JSON describing `manifest_sha256` and per-file `path` + `sha256` (excludes `META/signature.json`).
- **Signed message:** `CONNECTOR_CPKG_SIGN_V1\0` || `digest` (32 bytes); **Ed25519** signature over that byte string.
- **Envelope:** `META/signature.json` — `{ "algorithm": "ed25519", "key_id", "payload_sha256"?, "signature_b64", "parent_key_id"? }`.
- **Verify:** `read_cpkg_verify_optional(bytes, Some(trust_map))` where `trust_map` is `key_id` → raw 32-byte verifying key (base64).
- **CLI/crate helpers:** `sign_envelope`, `verify_envelope`, `parse_verifying_key_b64` in `connector-cpkg`.
