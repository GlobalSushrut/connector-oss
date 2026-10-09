# WitnessCtl — Current Status

## Build
- **Status:** ✅ Compiles cleanly (0 errors, 24 warnings — all dead-code)
- **LOC:** 3,014 lines of Rust across 14 source files
- **Stubs:** Zero `NOT_IMPLEMENTED`, `todo!()`, `unimplemented!()`, or `FIXME` in codebase

## Modules

| File | Lines | Purpose |
|------|-------|---------|
| `compliance.rs` | 490 | HIPAA/SOC2/GDPR/EU-AI-Act evaluation engine with per-control results |
| `routes.rs` | 407 | 15 HTTP endpoints (sessions, ingest, compliance, proof, verify, schemas, PII, export, proxy) |
| `connector.rs` | 380 | ConnectorClient — agent registration, firewall, policy, memory, audit, proof, receipts, health |
| `types.rs` | 361 | Session, Capture, Receipt, PII, Schema, Compliance types |
| `schema.rs` | 253 | Structural schema inference + drift detection |
| `pii.rs` | 200 | PII/PHI scanner (email, phone, SSN, CC, IP, API keys, PHI fields) |
| `export.rs` | 186 | JSON/CSV compliance export with raw content toggle |
| `session.rs` | 169 | Session CRUD, open/seal lifecycle, proof bundle generation |
| `receipt.rs` | 147 | HMAC-SHA256 chained receipt generation + verification |
| `proxy.rs` | 147 | HTTP reverse proxy — real forwarding to upstream with capture |
| `capture.rs` | 94 | Core hot-path: admit → firewall → PII scan → schema drift → receipt → store |
| `main.rs` | 80 | Server bootstrap with all engines wired |
| `error.rs` | 64 | AppError with proper HTTP status mapping |
| `config.rs` | 36 | Environment-based configuration |

## API Endpoints (all implemented, zero stubs)

### Sessions
- ✅ `POST /api/v1/sessions` — Open session (registers agent with Connector)
- ✅ `GET /api/v1/sessions` — List sessions
- ✅ `GET /api/v1/sessions/:id` — Get session details
- ✅ `POST /api/v1/sessions/:id/seal` — Seal session (immutable, generate proof)

### Capture
- ✅ `POST /api/v1/ingest` — Ingest request+response pair (SDK shim mode)
- ✅ `POST /witness/*path` — Proxy forward (auto-captures, real upstream forwarding)

### Compliance
- ✅ `GET /api/v1/compliance/:session_id` — Get existing compliance verdicts
- ✅ `POST /api/v1/compliance/:session_id/evaluate` — Re-evaluate against all frameworks

### Proof & Verification
- ✅ `GET /api/v1/proof/:session_id` — Proof bundle (local receipts + Connector proof)
- ✅ `GET /api/v1/verify/:session_id` — Verify HMAC chain integrity + tamper detection

### Schema & PII
- ✅ `GET /api/v1/schemas/:session_id` — API schema history + drift events
- ✅ `GET /api/v1/pii/:session_id` — PII detection report

### Export
- ✅ `GET /api/v1/export/:session_id?format=json|csv&include_raw=true` — Regulator-ready export

### Health
- ✅ `GET /health` — Real DB + Connector health check

## Connector Integration (all real HTTP calls)

| Connector API | Used By | Purpose |
|---------------|---------|---------|
| `POST /api/v1/agents/register` | session.rs | Register witness agent per session |
| `POST /api/v1/guard/firewall` | capture.rs | Scan request content for PII/injection |
| `POST /api/v1/governance/policy-check` | capture.rs | Admission gate (allow/deny/hold) |
| `POST /api/v1/audit/decision` | capture.rs | Record every API call decision |
| `POST /api/v1/proof/generate` | session.rs | Generate proof bundle on seal |
| `POST /api/v1/audit/receipt` | connector.rs | Issue Connector-level receipt |
| `GET /api/v1/compliance/report` | compliance.rs | Get Connector's compliance view |
| `GET /health` | routes.rs | Health check |

## Database Schema

Migration `20240101000001_witnessctl_core.sql`:
- `witness_sessions` — Session lifecycle, totals, chain head
- `witness_captures` — Per-API-call record with hashes, verdicts, PII flags, drift
- `witness_receipts` — HMAC-chained receipt chain
- `witness_schemas` — Per-endpoint schema snapshots with drift log
- `witness_pii_hits` — Individual PII detections
- `witness_compliance` — Per-framework compliance verdicts

## What's Not Done (Phase 2 scaling)

- [ ] Tiered storage rollups (hot PG → warm compressed → cold S3) — architecture designed, not yet implemented
- [ ] PDF compliance export (requires wkhtmltopdf or similar)
- [ ] Redis caching for session lookups
- [ ] WebSocket streaming for live capture events
- [ ] SSO/SAML authentication
- [ ] Kubernetes Helm chart
- [ ] Docker Compose deployment

## How It Differs From TraceTramp

| | TraceTramp | WitnessCtl |
|---|-----------|------------|
| Direction | Inbound (LLM calls) | Outbound (API calls) |
| Captures | Prompts, responses, decisions | HTTP requests, responses, headers |
| Governance | LLM provider routing, RBAC | API admission, firewall, PII redaction |
| Evidence | Decision trees | HMAC receipt chains |
| Compliance | Token/cost attribution | HIPAA/SOC2/GDPR/EU-AI-Act per-control |
| Unique | Decision tree recording | Schema drift detection |

Together: unbroken chain from user input → AI reasoning → external system effect.
