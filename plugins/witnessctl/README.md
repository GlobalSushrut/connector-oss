# WitnessCtl

API witness layer: capture, receipts, seal, export. Uses Connector for policy, firewall inspect, and kernel host snapshot.

## Session export formats

`GET /api/v1/export/:session_id?format=...` (see `src/routes.rs`).

| Format | Use case |
|--------|----------|
| `json` | Machine processing |
| `csv` | Spreadsheets |
| `markdown` / `md` | Human-readable |
| **`html`** | **Open in any browser → Print → Save as PDF** (no server Chrome required) |
| **`pdf`** | Server-side PDF (requires **Chromium/Chrome** or **wkhtmltopdf** on the host) |

HTML/PDF shells are built with the shared **`connector-report-pdf`** crate (`oss/connector/crates/connector-report-pdf`).

## `decision_digest`

Each capture row stores **`decision_digest`** JSONB: admission verdict, firewall outcome, optional `kernel_host` snapshot from Connector, and **`tracetramp`** hints (`risk_level`, `policy_verdict` from proxy headers when present) for audit alignment with TraceTramp.

## TraceTramp integration handoff

`POST /api/v1/integrations/tracetramp/handoff` (shared secret) stores payloads for SIEM correlation. TraceTramp sends enforcement events; when an **operation block is released** on the TraceTramp management plane, a handoff with `event: "operation_block_released"` may be posted (same endpoint, synthetic `trace_id` / `request_id`) so Witness retains an audit line for revoke actions.
