# WitnessCtl — API Witness Layer

## What It Does

WitnessCtl captures, governs, and proves every outbound API call your AI agents make. It sits between your AI system and external APIs (Stripe, Salesforce, internal microservices, third-party REST APIs), recording the full request/response cycle with tamper-evident receipts.

```
AI Agent → [WitnessCtl] → External API
                │
                ├── Admission gate (allow/deny/hold)
                ├── Firewall scan (PII, injection, exfiltration)
                ├── Schema drift detection
                ├── HMAC receipt chain
                └── Compliance evaluation
```

## Two Modes

### 1. Proxy Mode (zero code change)
Point your agents at WitnessCtl instead of the upstream. It forwards the request, captures everything, and returns the response.

```bash
# Open a session
curl -X POST http://localhost:7443/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "upstream": "https://api.stripe.com",
    "role": "billing-agent",
    "mode": "proxy",
    "frameworks": ["hipaa", "soc2"]
  }'

# Response:
# {
#   "session_id": "uuid",
#   "session_token": "wst_abc123",
#   "proxy_url": "http://localhost:7443/witness/uuid",
#   "proxy_header": "X-Witness-Session: wst_abc123"
# }

# Route agent traffic through the proxy
curl -X POST http://localhost:7443/witness/v1/charges \
  -H "X-Witness-Session: wst_abc123" \
  -H "X-Original-Method: POST" \
  -d '{"amount": 2000, "currency": "usd"}'
```

### 2. SDK Shim Mode (programmatic)
Send request+response pairs directly from your code.

```bash
curl -X POST http://localhost:7443/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "uuid",
    "request": {
      "method": "POST",
      "url": "https://api.stripe.com/v1/charges",
      "headers": {},
      "body": "{\"amount\": 2000}"
    },
    "response": {
      "status": 200,
      "headers": {},
      "body": "{\"id\": \"ch_123\"}",
      "latency_ms": 145
    }
  }'
```

## API Reference

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sessions` | Open a new capture session |
| GET | `/api/v1/sessions` | List sessions |
| GET | `/api/v1/sessions/:id` | Get session details |
| POST | `/api/v1/sessions/:id/seal` | Seal session (immutable, generate proof) |

### Capture

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/ingest` | Ingest a request+response pair (SDK shim) |
| POST | `/witness/*path` | Proxy forward (auto-captures) |

### Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/compliance/:session_id` | Get existing compliance verdicts |
| POST | `/api/v1/compliance/:session_id/evaluate` | Re-evaluate against all frameworks |

### Proof & Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/proof/:session_id` | Get proof bundle (receipts + Connector proof) |
| GET | `/api/v1/verify/:session_id` | Verify HMAC chain integrity |

### Schema & PII

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/schemas/:session_id` | Get API schema history + drift events |
| GET | `/api/v1/pii/:session_id` | Get PII detection report |

### Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/export/:session_id?format=json\|csv&include_raw=true` | Export session data |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health (DB + Connector check) |

## Compliance Frameworks

WitnessCtl evaluates each session against these frameworks:

### HIPAA
- §164.312(a)(1) Access Control — admission gate enforcement
- §164.312(b) Audit Controls — full receipt chain
- §164.312(c)(1) Integrity — HMAC tamper evidence
- §164.312(d) Authentication — firewall blocks
- §164.312(e)(1) Transmission Security — PII in responses
- §164.530(c) PHI Safeguards — PII detection + blocking

### SOC2
- CC6.1 Access Controls — denied calls
- CC6.2 Authentication — firewall blocks
- CC7.1 Change Management — schema drift detection
- CC7.2 Data Integrity — HMAC receipt chain
- CC8.1 Incident Response — firewall block tracking

### GDPR
- Art. 5(1)(c) Data Minimisation — PII in requests
- Art. 5(1)(f) Integrity/Confidentiality — HMAC chain
- Art. 13 Transparency — full audit trail
- Art. 17 Erasure — session sealing
- Art. 25 Protection by Design — admission gate
- Art. 35 DPIA — full call documentation

### EU AI Act
- Art. 9 Risk Management — denied/blocked calls
- Art. 10 Data Governance — PII detection
- Art. 11 Technical Documentation — receipt chain
- Art. 12 Record-Keeping — automated logging
- Art. 13 Transparency — decision trail
- Art. 14 Human Oversight — firewall + admission

## Environment Variables

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/witnessctl
CONNECTOR_BASE_URL=http://localhost:8080
CONNECTOR_API_KEY=conn_key_xxx
HMAC_SECRET=your-hmac-secret-key
PORT=7443
LOG_LEVEL=info
```

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│  AI Agent    │────▶│  WitnessCtl                          │────▶│  Upstream   │
│             │     │                                      │     │  API        │
└─────────────┘     │  ┌─────────┐  ┌──────────┐  ┌─────┐ │     └─────────────┘
                    │  │Admission │  │ Firewall  │  │ PII │ │
                    │  │  Gate    │  │  Scan     │  │Scan │ │
                    │  └────┬────┘  └────┬─────┘  └──┬──┘ │
                    │       │            │           │     │
                    │  ┌────▼────────────▼───────────▼──┐ │
                    │  │       Capture Engine             │ │
                    │  │  (SHA-256 hash, schema drift)    │ │
                    │  └────────────┬────────────────────┘ │
                    │               │                        │
                    │  ┌────────────▼────────────────────┐   │
                    │  │     HMAC Receipt Chain          │   │
                    │  │  (tamper-evident, chained)      │   │
                    │  └────────────┬────────────────────┘   │
                    │               │                        │
                    │  ┌────────────▼────────────────────┐   │
                    │  │     Compliance Engine           │   │
                    │  │  (HIPAA/SOC2/GDPR/EU-AI-Act)   │   │
                    │  └─────────────────────────────────┘   │
                    └──────────────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────────┐
                    │  Connector OS                      │
                    │  (agent registration, policy,       │
                    │   firewall, audit, proof, memory)  │
                    └───────────────────────────────────┘
```

## With TraceTramp

TraceTramp handles **inbound** LLM calls (what the AI decided). WitnessCtl handles **outbound** API calls (what the AI actually did). Together they form an unbroken audit chain:

```
User Request
    │
    ▼
TraceTramp ──── "AI decided to issue a refund"
    │
    ▼
AI Agent calls Stripe /refunds
    │
    ▼
WitnessCtl ──── "POST stripe.com/refunds → 200 OK, $50 refunded"
    │
    ▼
Full audit chain: decision + action + external effect
```
