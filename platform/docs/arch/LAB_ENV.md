# TraceTramp + WitnessCtl — Production-Standard Lab Environment

> This is not a demo. This is a real simulative lab that exercises both plugins at
> production standard — sustained traffic, PII injection, chaos, budget exhaustion,
> schema drift, multi-tenant load, seal → verify cycles.

---

## Tools Used

### Core Mock LLM Server — `aimock` (CopilotKit)
**Repo:** https://github.com/CopilotKit/aimock
**Docker image:** `ghcr.io/copilotkit/aimock:latest`

Why aimock and not alternatives:
- Full OpenAI + Anthropic + Ollama + Gemini + Azure + Cohere compatible (11 providers)
- Real SSE streaming with configurable `ttft` (time to first token), `tps` (tokens/sec), jitter
- **Chaos injection**: 500 errors, malformed JSON, mid-stream disconnects at configurable probability
- Fixture-driven deterministic responses — same input always returns same output
- Record & replay — proxy real API once, replay forever with no API key cost
- Prometheus metrics at `/metrics` — request counts, latency, fixture match rates
- Docker image + zero Node dependencies
- Multi-turn conversations and tool call support

### Other Components
| Component         | Image / Tool                     | Purpose                                      |
|-------------------|----------------------------------|----------------------------------------------|
| PostgreSQL 16     | `postgres:16-alpine`             | TraceTramp + WitnessCtl persistent storage   |
| Redis 7           | `redis:7-alpine`                 | TraceTramp session/budget cache              |
| Prometheus        | `prom/prometheus:latest`         | Scrapes TraceTramp, WitnessCtl, aimock       |
| Grafana           | `grafana/grafana:latest`         | Dashboards for live lab observation          |
| Traffic generator | Python 3.12 + httpx              | Sends realistic multi-turn PII-laden traffic |
| Connector OS      | local build                      | Kernel for agent/session/audit primitives    |

---

## Lab Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             LAB NETWORK                  │
                    │                                          │
  traffic-gen  ───► │  TraceTramp :9741  ──────────────────►  │  aimock :9999
  (Python)          │  (data plane)       (LLM calls proxied) │  (mock LLM server)
                    │       │                                  │
                    │       │ async ingest                     │
                    │       ▼                                  │
                    │  WitnessCtl :7443                        │
                    │  (capture + receipt chain)               │
                    │       │                                  │
                    │       ▼                                  │
                    │  Connector OS :9735                      │
                    │  (agents, audit, policy, memory)         │
                    │       │                                  │
                    │       ▼                                  │
                    │  PostgreSQL :5432     Redis :6379        │
                    │                                          │
                    │  Prometheus :9090     Grafana :3000      │
                    └─────────────────────────────────────────┘
```

TraceTramp's `OPENAI_BASE_URL` points to `aimock` — so every LLM call goes through
TraceTramp (policy check, budget check, PII scan) → aimock (returns fixture response).
WitnessCtl receives every call via async ingest from TraceTramp.

---

## File Layout

```
lab/
  docker-compose.yml          # spins up everything
  aimock/
    fixtures/
      normal_chat.json        # clean multi-turn conversations
      pii_ssn.json            # SSN embedded in user message
      pii_email.json          # email embedded in user message
      pii_phi.json            # HIPAA PHI fields (patient_id, mrn, dob)
      tool_call.json          # agent tool_use call + result
      streaming_slow.json     # slow stream (tests SSE handling)
      schema_drift_v1.json    # initial response schema
      schema_drift_v2.json    # same endpoint, new field added
      chaos_500.json          # aimock returns 500 (tests fallback)
      chaos_malformed.json    # aimock returns malformed JSON
    aimock.json               # aimock config pointing at fixtures
  prometheus/
    prometheus.yml            # scrape config
  grafana/
    dashboards/
      tracetramp.json         # TraceTramp dashboard
      witnessctl.json         # WitnessCtl dashboard
  traffic/
    gen.py                    # main traffic generator
    scenarios/
      clean_traffic.py        # normal multi-turn, no PII
      pii_injection.py        # embeds SSN/email/PHI mid-session
      budget_exhaust.py       # hammers until budget is exhausted
      provider_chaos.py       # triggers chaos (500s, timeouts)
      schema_drift.py         # switches fixture mid-session
      multi_tenant.py         # concurrent traffic across 3 tenants
  scripts/
    setup.sh                  # first-time setup: DB, migrations, tenants, API keys
    teardown.sh               # clean stop + volume wipe
    run_scenario.sh           # run a named scenario end-to-end
    seal_and_verify.sh        # seal WitnessCtl session + verify chain + download PDF
```

---

## docker-compose.yml

**Phase 1.6 alignment:** checked-in lab builds use `lab/docker-compose.premium-lab.yml` with `dockerfile` paths under `lab/` (see `lab/README.md`). The fragment below uses the same **context** / **dockerfile** pairing as that compose file (paths relative to each build context).

```yaml
version: "3.9"

services:

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: lab
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lab"]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10

  aimock:
    image: ghcr.io/copilotkit/aimock:latest
    ports:
      - "9999:9999"
    volumes:
      - ./aimock:/fixtures
    environment:
      AIMOCK_PORT: "9999"
      AIMOCK_CONFIG: /fixtures/aimock.json
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9999/health || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 10

  connector:
    build:
      context: ../../oss
      dockerfile: ../lab/Dockerfile.connector
    ports:
      - "9735:9735"
    environment:
      DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      REDIS_URL: redis://redis:6379
      CONNECTOR_LLM_STUB: "1"
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  tracetramp:
    build:
      context: .
      dockerfile: ../../lab/Dockerfile.tracetramp
    ports:
      - "9741:9741"   # data plane
      - "9742:9742"   # management plane
    environment:
      DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      REDIS_URL: redis://redis:6379
      TRACETRAMP_PORT: "9741"
      TRACETRAMP_ADMIN_PORT: "9742"
      CONNECTOR_BASE_URL: http://connector:9735
      CONNECTOR_API_KEY: lab-connector-key
      OPENAI_BASE_URL: http://aimock:9999/v1
      OPENAI_API_KEY: lab-fake-key
      JWT_SECRET: lab-jwt-secret-change-in-prod
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      aimock:
        condition: service_healthy
      connector:
        condition: service_started

  witnessctl:
    build:
      context: ../witnessctl
      dockerfile: ../../lab/Dockerfile.witnessctl
    ports:
      - "7443:7443"
    environment:
      WITNESSCTL_DATABASE_URL: postgres://lab:lab@postgres:5432/lab
      WITNESSCTL_PORT: "7443"
      CONNECTOR_BASE_URL: http://connector:9735
      CONNECTOR_API_KEY: lab-connector-key
      WITNESSCTL_HMAC_SECRET: lab-hmac-secret-change-in-prod
      WITNESSCTL_NOTIFY_TERMINAL: "true"
      WITNESSCTL_HOLD_ON_BLOCK: "true"
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      connector:
        condition: service_started

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: lab
    volumes:
      - ./grafana/dashboards:/var/lib/grafana/dashboards
      - grafana_data:/var/lib/grafana
    depends_on:
      - prometheus

volumes:
  pg_data:
  grafana_data:
```

---

## aimock/aimock.json

```json
{
  "port": 9999,
  "providers": {
    "openai": {
      "chatCompletions": {
        "fixtures": "./fixtures"
      }
    }
  },
  "metrics": true,
  "chaosDefaults": {
    "errorRate": 0.0,
    "malformedRate": 0.0,
    "disconnectRate": 0.0
  }
}
```

---

## aimock fixture examples

### aimock/fixtures/normal_chat.json
```json
{
  "match": { "messages": [{ "role": "user", "content": "explain unit testing" }] },
  "response": {
    "model": "gpt-4o",
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "Unit testing is the practice of testing individual components of code in isolation. Each test verifies that a single function or method behaves correctly given specific inputs."
      },
      "finish_reason": "stop"
    }],
    "usage": { "prompt_tokens": 18, "completion_tokens": 42, "total_tokens": 60 }
  },
  "stream": true,
  "streamingPhysics": { "ttft": 80, "tps": 40, "jitter": 10 }
}
```

### aimock/fixtures/pii_ssn.json
```json
{
  "match": { "messages": [{ "role": "user", "content_contains": "123-45-6789" }] },
  "response": {
    "model": "gpt-4o",
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "I can help with that healthcare form. Please provide the required fields."
      },
      "finish_reason": "stop"
    }],
    "usage": { "prompt_tokens": 24, "completion_tokens": 18, "total_tokens": 42 }
  }
}
```

### aimock/fixtures/schema_drift_v2.json
```json
{
  "match": { "messages": [{ "role": "user", "content_contains": "drift_trigger" }] },
  "response": {
    "model": "gpt-4o",
    "choices": [{
      "message": {
        "role": "assistant",
        "content": "Here is the analysis.",
        "reasoning": "The user asked for analysis. I should provide a structured response."
      },
      "finish_reason": "stop"
    }],
    "usage": { "prompt_tokens": 12, "completion_tokens": 22, "total_tokens": 34 }
  }
}
```
> The `reasoning` field is new — WitnessCtl must detect schema drift on this response.

### aimock/fixtures/chaos_500.json
```json
{
  "match": { "messages": [{ "role": "user", "content_contains": "chaos_trigger" }] },
  "response": {
    "error": {
      "message": "The server had an error processing your request.",
      "type": "server_error",
      "code": 500
    }
  },
  "statusCode": 500
}
```
> TraceTramp must catch this, trigger provider fallback, NOT return a 500 to the caller.

---

## traffic/gen.py — Main traffic generator

```python
#!/usr/bin/env python3
"""
Lab traffic generator for TraceTramp + WitnessCtl.
Runs all scenarios sequentially or a named one.
"""
import asyncio
import sys
from scenarios import (
    clean_traffic,
    pii_injection,
    budget_exhaust,
    provider_chaos,
    schema_drift,
    multi_tenant,
)

SCENARIOS = {
    "clean":    clean_traffic.run,
    "pii":      pii_injection.run,
    "budget":   budget_exhaust.run,
    "chaos":    provider_chaos.run,
    "drift":    schema_drift.run,
    "tenant":   multi_tenant.run,
    "all":      None,
}

async def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "all"
    if name == "all":
        for scenario_name, fn in SCENARIOS.items():
            if fn:
                print(f"\n{'='*60}")
                print(f"  SCENARIO: {scenario_name}")
                print(f"{'='*60}")
                await fn()
    elif name in SCENARIOS:
        await SCENARIOS[name]()
    else:
        print(f"Unknown scenario: {name}")
        print(f"Available: {list(SCENARIOS.keys())}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

---

## traffic/scenarios/pii_injection.py

```python
"""
Scenario: PII Injection
Sends a mix of clean messages and messages with embedded PII.
Verifies TraceTramp blocks/redacts PII.
Verifies WitnessCtl receipt chain records the blocks.
"""
import httpx
import asyncio

TRACETRAMP_URL = "http://localhost:9741"
WITNESSCTL_URL = "http://localhost:7443"
API_KEY        = "cpk_lab_tenant_acme"

MESSAGES = [
    ("clean",   "explain how JWT tokens work"),
    ("clean",   "what is the difference between REST and GraphQL"),
    ("pii_ssn", "my SSN is 123-45-6789, help me fill out this healthcare form"),
    ("clean",   "how do I write a unit test in Rust"),
    ("pii_email","contact john.doe@acme.com about the contract renewal"),
    ("pii_phi",  "patient_id: P10293, dob: 1981-04-12, mrn: MRN8847, explain this lab result"),
    ("clean",   "what is dependency injection"),
    ("pii_cc",  "my card number is 4111 1111 1111 1111 expires 12/28"),
    ("clean",   "explain async/await in Python"),
]

async def run():
    print("[pii_injection] Opening WitnessCtl session...")
    async with httpx.AsyncClient() as client:
        # Open witness session
        sess = await client.post(
            f"{WITNESSCTL_URL}/api/v1/sessions",
            json={"upstream": TRACETRAMP_URL, "role": "lab-analyst"},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        session_id = sess.json()["session_id"]
        print(f"[pii_injection] Session: {session_id}")

        blocked = 0
        allowed = 0

        for label, content in MESSAGES:
            resp = await client.post(
                f"{TRACETRAMP_URL}/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": content}],
                    "stream": False,
                },
                headers={"Authorization": f"Bearer {API_KEY}"},
            )
            decision = resp.headers.get("x-tracetramp-decision", "unknown")
            status   = resp.status_code

            if status == 403 or decision == "block":
                blocked += 1
                print(f"  [BLOCK]  {label:10}  status={status}  reason={resp.json().get('reason','?')}")
            else:
                allowed += 1
                print(f"  [ALLOW]  {label:10}  status={status}  decision={decision}")

            await asyncio.sleep(0.3)

        print(f"\n[pii_injection] Done. Allowed: {allowed}  Blocked: {blocked}")
        print(f"[pii_injection] Expected blocks: 4 (ssn, email, phi, cc)")

        if blocked < 4:
            print(f"  FAIL: only {blocked}/4 PII calls were blocked")
        else:
            print(f"  PASS: all PII blocked correctly")

        # Seal session and check PII report
        seal = await client.post(
            f"{WITNESSCTL_URL}/api/v1/sessions/{session_id}/seal",
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        proof = seal.json()
        print(f"\n[pii_injection] Sealed: {proof.get('proof_id')}")
        print(f"  HIPAA: {proof.get('hipaa_score')}  GDPR: {proof.get('gdpr_score')}")
```

---

## traffic/scenarios/budget_exhaust.py

```python
"""
Scenario: Budget Exhaustion
Creates a tenant with a very low budget, sends calls until it is exhausted.
Verifies TraceTramp returns 402 on exhaustion, not 500.
"""
import httpx
import asyncio

TRACETRAMP_MGMT = "http://localhost:9742"
TRACETRAMP_DATA = "http://localhost:9741"
ADMIN_JWT       = "LAB_ADMIN_JWT"  # set from scripts/setup.sh output

async def run():
    print("[budget_exhaust] Creating tight-budget tenant...")
    async with httpx.AsyncClient() as client:
        # Create tenant with $0.01 budget (will exhaust quickly)
        t = await client.post(
            f"{TRACETRAMP_MGMT}/admin/tenants",
            json={"name": "budget-lab-tenant", "daily_budget_usd": 0.01},
            headers={"Authorization": f"Bearer {ADMIN_JWT}"},
        )
        tenant = t.json()
        api_key = tenant["api_key"]
        print(f"  Tenant: {tenant['id']}  budget: $0.01  key: {api_key[:12]}...")

        call_num  = 0
        exhausted = False

        while not exhausted and call_num < 100:
            call_num += 1
            resp = await client.post(
                f"{TRACETRAMP_DATA}/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "explain unit testing"}],
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            if resp.status_code == 402:
                exhausted = True
                print(f"\n  PASS: 402 Budget Exhausted on call #{call_num}")
                print(f"  Body: {resp.json()}")
            else:
                cost = resp.headers.get("x-tracetramp-cost", "?")
                print(f"  call {call_num:3}  status={resp.status_code}  cost={cost}")
            await asyncio.sleep(0.1)

        if not exhausted:
            print("  FAIL: budget was never exhausted after 100 calls")
```

---

## traffic/scenarios/provider_chaos.py

```python
"""
Scenario: Provider Chaos
Sends messages with 'chaos_trigger' — aimock returns 500.
Verifies TraceTramp does NOT return 500 to the caller (graceful error or fallback).
"""
import httpx
import asyncio

TRACETRAMP_URL = "http://localhost:9741"
API_KEY        = "cpk_lab_tenant_acme"

async def run():
    print("[provider_chaos] Sending chaos_trigger messages...")
    async with httpx.AsyncClient() as client:
        passed = 0
        failed = 0
        for i in range(5):
            resp = await client.post(
                f"{TRACETRAMP_URL}/v1/chat/completions",
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": f"chaos_trigger run {i}"}],
                },
                headers={"Authorization": f"Bearer {API_KEY}"},
            )
            if resp.status_code == 500:
                failed += 1
                print(f"  FAIL call {i}: raw 500 leaked to caller — fallback not working")
            else:
                passed += 1
                print(f"  PASS call {i}: status={resp.status_code}  body={resp.text[:80]}")
            await asyncio.sleep(0.2)

        print(f"\n[provider_chaos] Passed: {passed}/5  Failed: {failed}/5")
```

---

## traffic/scenarios/schema_drift.py

```python
"""
Scenario: Schema Drift
Sends normal traffic first to establish baseline schema,
then sends 'drift_trigger' message — aimock v2 fixture adds 'reasoning' field.
Verifies WitnessCtl detects the drift and marks CC7.1 / CM-3 as WARN.
"""
import httpx
import asyncio

TRACETRAMP_URL = "http://localhost:9741"
WITNESSCTL_URL = "http://localhost:7443"
API_KEY        = "cpk_lab_tenant_acme"

async def run():
    print("[schema_drift] Opening WitnessCtl session...")
    async with httpx.AsyncClient() as client:
        sess = await client.post(
            f"{WITNESSCTL_URL}/api/v1/sessions",
            json={"upstream": TRACETRAMP_URL, "role": "lab-analyst"},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        session_id = sess.json()["session_id"]
        print(f"  Session: {session_id}")

        # 5 normal calls to establish schema baseline
        for i in range(5):
            await client.post(
                f"{TRACETRAMP_URL}/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "explain unit testing"}]},
                headers={"Authorization": f"Bearer {API_KEY}"},
            )
            await asyncio.sleep(0.2)
        print("  Baseline established (5 normal calls)")

        # 1 drift call — aimock returns extra 'reasoning' field
        await client.post(
            f"{TRACETRAMP_URL}/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "drift_trigger analysis"}]},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        print("  Drift call sent")

        # Check schema history
        await asyncio.sleep(1)
        drift = await client.get(
            f"{WITNESSCTL_URL}/api/v1/schema/{session_id}",
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        drifts = drift.json().get("drifts", [])
        if drifts:
            print(f"  PASS: {len(drifts)} drift event(s) detected:")
            for d in drifts:
                print(f"    field={d.get('field')}  change={d.get('change_type')}  at={d.get('detected_at')}")
        else:
            print("  FAIL: no drift detected — WitnessCtl schema tracking not working")

        # Seal and check SOC2 / FedRAMP scores
        seal = await client.post(
            f"{WITNESSCTL_URL}/api/v1/sessions/{session_id}/seal",
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        proof = seal.json()
        print(f"\n  SOC2:    {proof.get('soc2_score')}  (expect WARN on CC7.1)")
        print(f"  FedRAMP: {proof.get('fedramp_score')}  (expect WARN on CM-3)")
```

---

## scripts/setup.sh

```bash
#!/usr/bin/env bash
set -e

echo "=== Lab Setup ==="

echo "[1] Starting infrastructure..."
docker compose up -d postgres redis aimock
sleep 5

echo "[2] Running TraceTramp migrations..."
docker compose run --rm tracetramp ./tracetramp migrate

echo "[3] Running WitnessCtl migrations..."
docker compose run --rm witnessctl ./witnessctl migrate

echo "[4] Starting Connector OS..."
docker compose up -d connector
sleep 5

echo "[5] Starting TraceTramp + WitnessCtl..."
docker compose up -d tracetramp witnessctl
sleep 5

echo "[6] Creating lab tenant in TraceTramp..."
ADMIN_JWT=$(docker compose exec tracetramp ./tracetramp gen-jwt --role admin)
echo "Admin JWT: $ADMIN_JWT"

TENANT=$(curl -sf -X POST http://localhost:9742/admin/tenants \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"lab-acme","daily_budget_usd":10.0}')
API_KEY=$(echo "$TENANT" | jq -r '.api_key')
echo "Lab API Key: $API_KEY"

echo "[7] Registering aimock as OpenAI provider in TraceTramp..."
curl -sf -X POST http://localhost:9742/admin/providers \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"aimock\",\"provider\":\"openai\",\"base_url\":\"http://aimock:9999/v1\",\"api_key\":\"lab-fake\"}"

echo "[8] Starting Prometheus + Grafana..."
docker compose up -d prometheus grafana

echo ""
echo "=== Lab Ready ==="
echo "  TraceTramp data plane:  http://localhost:9741"
echo "  TraceTramp mgmt plane:  http://localhost:9742"
echo "  WitnessCtl:             http://localhost:7443"
echo "  aimock (mock LLM):      http://localhost:9999"
echo "  Prometheus:             http://localhost:9090"
echo "  Grafana:                http://localhost:3000  (admin/lab)"
echo ""
echo "  API Key for lab:  $API_KEY"
echo "  Admin JWT:        $ADMIN_JWT"
echo ""
echo "  Run a scenario:   python traffic/gen.py pii"
echo "  Run all:          python traffic/gen.py all"
echo "  Seal + verify:    ./scripts/seal_and_verify.sh <session_id>"
```

---

## scripts/seal_and_verify.sh

```bash
#!/usr/bin/env bash
set -e

SESSION_ID=$1
API_KEY=${LAB_API_KEY:-"cpk_lab_tenant_acme"}
WITNESSCTL="http://localhost:7443"

if [ -z "$SESSION_ID" ]; then
  echo "Usage: seal_and_verify.sh <session_id>"
  exit 1
fi

echo "=== Sealing session $SESSION_ID ==="
SEAL=$(curl -sf -X POST "$WITNESSCTL/api/v1/sessions/$SESSION_ID/seal" \
  -H "Authorization: Bearer $API_KEY")

echo "$SEAL" | jq '{
  proof_id,
  receipts,
  hipaa_score,
  soc2_score,
  gdpr_score,
  euaiact_score,
  fedramp_score
}'

PROOF_ID=$(echo "$SEAL" | jq -r '.proof_id')

echo ""
echo "=== Verifying chain ==="
witnessctl verify "$PROOF_ID"

echo ""
echo "=== Downloading PDFs ==="
mkdir -p ./lab-reports
for FRAMEWORK in hipaa soc2 gdpr euaiact fedramp; do
  curl -sf "$WITNESSCTL/api/v1/sessions/$SESSION_ID/export?format=pdf&framework=$FRAMEWORK" \
    -H "Authorization: Bearer $API_KEY" \
    -o "./lab-reports/report-${SESSION_ID}-${FRAMEWORK}.pdf"
  echo "  Saved: lab-reports/report-${SESSION_ID}-${FRAMEWORK}.pdf"
done

echo ""
echo "=== Checking notifications ==="
curl -sf "$WITNESSCTL/api/v1/notifications?session_id=$SESSION_ID" \
  -H "Authorization: Bearer $API_KEY" | jq '.[] | {id, type, message, acked}'
```

---

## prometheus/prometheus.yml

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: tracetramp
    static_configs:
      - targets: ["tracetramp:9741"]

  - job_name: witnessctl
    static_configs:
      - targets: ["witnessctl:7443"]

  - job_name: aimock
    static_configs:
      - targets: ["aimock:9999"]
```

---

## Lab Test Scenarios — What Each One Proves

| Scenario       | Command                      | What it verifies                                                              |
|----------------|------------------------------|-------------------------------------------------------------------------------|
| `clean`        | `python gen.py clean`        | Normal traffic flows through TraceTramp, receipts written, no false blocks    |
| `pii`          | `python gen.py pii`          | SSN/email/PHI blocked or redacted, WitnessCtl chain records blocks, HIPAA+GDPR PDF reflects detections |
| `budget`       | `python gen.py budget`       | 402 returned on budget exhaustion (not 500), hard budget enforcement works    |
| `chaos`        | `python gen.py chaos`        | aimock 500 → TraceTramp fallback fires → caller gets graceful error not 500   |
| `drift`        | `python gen.py drift`        | WitnessCtl detects new field in response schema → SOC2 CC7.1 + FedRAMP CM-3 WARN in PDF |
| `tenant`       | `python gen.py tenant`       | 3 tenants in parallel → no cross-contamination, budgets isolated, policies isolated |
| `all`          | `python gen.py all`          | Full end-to-end lab run                                                       |
| seal+verify    | `./scripts/seal_and_verify.sh <id>` | Seals WitnessCtl session → downloads 5 PDFs → verifies HMAC chain integrity |

---

## Quick Start

```bash
# 1. Clone and enter the repo
cd ~/Projects/connector-private

# 2. Run setup (first time only)
./lab/scripts/setup.sh

# 3. Run all scenarios
cd lab
python traffic/gen.py all

# 4. Seal and verify the WitnessCtl session
./scripts/seal_and_verify.sh <session_id_from_output>

# 5. View live dashboards
open http://localhost:3000  # Grafana (admin/lab)
open http://localhost:9090  # Prometheus

# 6. Tear down
./scripts/teardown.sh
```

---

## Connector OS — plugin dev & Docker lab (Phase 5)

When developing AGOS plugins against a local kernel, **`connectorctl plugin run --dev`** can use the host subprocess backend or **`CONNECTOR_PLUGIN_RUN_BACKEND=docker_lab`** (see repository root **`connector.yaml.example`**). Relevant environment variables (not required for TraceTramp/WitnessCtl compose above):

| Variable | Role |
|----------|------|
| `CONNECTOR_PLUGIN_RUN_BACKEND` | `docker_lab` → `connector-plugin-runtime` **`docker run`** (foreground) with rollout bind-mount |
| `CONNECTOR_DOCKER_LAB_IMAGE` | Optional image (default `alpine`-style in runtime crate) |
| `CONNECTOR_DOCKER_LAB_EGRESS` | `unrestricted` / `deny_all` / `allowlist_strict` |
| `CONNECTOR_DOCKER_LAB_EGRESS_ENFORCE` | `iptables` on **Linux** + root/`CAP_NET_ADMIN`: restrict egress to resolved manifest **`network.outbound:*`** caps; detached runs flush rules after **`docker wait`** (see **`platform/plugin-runtime`**) |
| `CONNECTOR_DOCKER_LAB_ALLOW_RESOLVER_DNS` | With iptables enforce: allow DNS to **`/etc/resolv.conf`** nameservers (default on) |

Manifest egress caps use **`network.outbound:host:port`**; IPv6 literals in the manifest should be bracketed: **`network.outbound:[2001:db8::1]:443`**. The same information is at **`GET /api/v1/kernel/plugin-egress-allowlist?plugin_id=vendor/slug`** (includes **`phase_5_operator_env`** host snapshot).

---

## What This Lab Does NOT Use

- No real API keys — aimock handles all LLM responses from fixtures
- No GPU — aimock simulates token streaming without inference
- No cloud — runs entirely local on a laptop or CI runner
- No demo shortcuts — every scenario exercises a real code path end-to-end
