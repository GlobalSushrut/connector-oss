# Connector OS — Demo Lab
## TraceTramp · WitnessCtl · DevGuard

> **What this is:** A real, runnable demo lab — not a slide deck.  
> Every `curl` command works against the live playground at `try.cnktros.com`.  
> Every dashboard step is verified against the actual UI.  
>
> **Three plugins. One scenario.** An AI coding agent runs a task.  
> TraceTramp governs every LLM call in real time.  
> WitnessCtl builds a tamper-evident compliance receipt chain.  
> DevGuard locks down what the agent can read, write, and execute.  
>
> Target: [try.cnktros.com](https://try.cnktros.com) — zero install, zero account needed.  
> Estimated lab time: **25–35 minutes** end-to-end.

---

## Lab scenario

> An AI coding agent (`demo-agent-001`) runs a refactoring task.  
> The agent makes LLM calls — some clean, one with PII, one that needs human approval.  
> WitnessCtl records every interaction into a tamper-evident chain.  
> DevGuard enforces what the agent is allowed to read, write, and run.  
> The operator watches and acts entirely from the browser dashboard.

---

## Prerequisites

```
curl   — any version
python3 — stdlib only (for json.tool and one-liner extracts)
```

No npm. No Rust. No Docker. Just a terminal and a browser.

---

## Step 0 — Get a trial session

```bash
export BASE="https://try.cnktros.com"

RESP=$(curl -s -X POST "$BASE/api/v1/playground/session" \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "label": "lab"}')

echo "$RESP" | python3 -m json.tool

export CPK=$(echo "$RESP"    | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
export TENANT=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['tenant_id'])")

echo "CPK=$CPK"
echo "TENANT=$TENANT"
```

> Session TTL is **90 minutes**. If you hit `401` mid-lab, re-run this block and re-export `CPK`.

---

---
# Part 1 — TraceTramp: governing LLM calls in real time
---

> **Dashboard:** <https://try.cnktros.com/plugins/tracetramp>  
> **Proxy base (platform → plugin):** `$BASE/api/v1/plugins/tracetramp`  
> **Data plane (LLM gateway):** `$BASE/v1/chat/completions`

---

### 1-A  Check plugin health

```bash
curl -s "$BASE/api/v1/plugins/status" \
  -H "Authorization: Bearer $CPK" \
  | python3 -c "
import sys,json
s = json.load(sys.stdin)
tt = s['plugins']['tracetramp']
print('TraceTramp status_badge:', tt['status_badge'])
print('upstream_reachable:     ', tt['upstream_reachable'])
"
```

Expected: `status_badge: healthy`, `upstream_reachable: True`.

---

### 1-B  Fire a normal LLM call → ALLOW

```bash
curl -si "$BASE/v1/chat/completions" \
  -X POST \
  -H "Authorization: Bearer $CPK" \
  -H "X-Tenant-Id: $TENANT" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Name three benefits of runtime AI governance."}]
  }' | grep -E "HTTP/|X-Trace-Id|X-Control-Decision|X-Cost-USD|X-Risk-Score"
```

Expected headers:
```
HTTP/2 200
X-Trace-Id:          <uuid>
X-Control-Decision:  ALLOW
X-Cost-USD:          0.000042
X-Risk-Score:        0.1
```

**Browser (Traces tab):** Hit Refresh → row appears with green `ALLOW` badge, cost, risk score.

---

### 1-C  Fire a PII call → BLOCK

```bash
curl -si "$BASE/v1/chat/completions" \
  -X POST \
  -H "Authorization: Bearer $CPK" \
  -H "X-Tenant-Id: $TENANT" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Process refund for SSN 123-45-6789 and card 4111111111111111"}]
  }' | grep -E "HTTP/|X-Control-Decision|X-Block-Reason"
```

Expected:
```
HTTP/2 400
X-Control-Decision:  BLOCK
X-Block-Reason:      pii_detected
```

**Browser (Traces tab):** Refresh → red `BLOCK` badge. PII fields listed (`ssn`, `credit_card`). The LLM was never called.

---

### 1-D  Trigger a HITL hold → operator approves in dashboard

```bash
# Force HITL hold on this request
HITL_RESP=$(curl -si "$BASE/v1/chat/completions" \
  -X POST \
  -H "Authorization: Bearer $CPK" \
  -H "X-Tenant-Id: $TENANT" \
  -H "X-TraceTramp-Force-HITL: 1" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"Summarise the pending deletion batch for operator review."}]
  }')

echo "$HITL_RESP" | grep -E "HTTP/|X-Control-Decision|approval_id"
```

Expected: `HTTP/2 202`, `X-Control-Decision: HELD`.

**Browser (Approvals/HITL tab):**
1. Hit **Refresh** — the held call row appears
2. Click the green **Approve** button
3. Row disappears; green flash confirms. The waiting agent call gets its LLM response.

---

### 1-E  Create + release an operation block (dashboard only)

**Browser (Blocks & quarantine tab):**

1. Fill the **Create operation block** form:
   - `actor_id` → `demo-agent-001`
   - `operation_key` → `llm.chat`
   - `reason` → `demo block`
2. Click **Create block** → green flash, JSON panel updates
3. Fill the **Release** form with the same values → click **Release block**

> Effect: between create and release, any LLM call from `demo-agent-001` returns `BLOCK (operation_blocked)` before reaching the model.

---

### 1-F  Submit a rate-limit policy (dashboard only)

**Browser (Policy submit tab):**

Fill in:
- `policy_name` → `lab-rate-cap`
- `type` → `rate_limit`
- `mode` → `block`
- `priority` → `10`

Click **Submit policy** → green flash. Hit Refresh on the policies table — new entry appears.

---

### 1-G  Read admin stats via proxy

```bash
curl -s "$BASE/api/v1/plugins/tracetramp/admin/stats" \
  -H "Authorization: Bearer $CPK" \
  | python3 -m json.tool | head -30
```

Shows live counters: `total_calls`, `blocked_calls`, `hitl_pending`, `active_tenants`, etc.

---
---
# Part 2 — WitnessCtl: tamper-evident compliance receipts
---

> **Dashboard:** <https://try.cnktros.com/plugins/witnessctl>  
> **API proxy base:** `$BASE/api/v1/plugins/witnessctl`  
> **Direct API (proxied):** `$BASE/api/v1/plugins/witnessctl/api/v1/...`

---

### 2-A  Check plugin health

```bash
curl -s "$BASE/api/v1/plugins/witnessctl/health" \
  | python3 -c "
import sys,json
h=json.load(sys.stdin)
print('service:', h['service'])
print('status: ', h['status'])
print('unlock: ', h['unlock']['unlock_mode'])
"
```

Expected: `status: ok`.

---

### 2-B  Open a capture session

```bash
SESSION=$(curl -s -X POST "$BASE/api/v1/plugins/witnessctl/api/v1/sessions" \
  -H "Authorization: Bearer $CPK" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_pid": "demo-agent-001",
    "upstream":  "https://api.openai.com",
    "label":     "lab-demo"
  }' | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('session_id') or d.get('id','ERROR'))")

echo "WitnessCtl session: $SESSION"
```

**Browser (Live room tab):** Refresh → new row with `label: lab-demo`, `status: open`.

---

### 2-C  Ingest three calls — build the receipt chain

**Call 1 — clean request:**
```bash
curl -s -X POST "$BASE/api/v1/plugins/witnessctl/api/v1/ingest" \
  -H "Authorization: Bearer $CPK" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION\",
    \"agent_pid\":  \"demo-agent-001\",
    \"request\": {
      \"method\": \"POST\",
      \"url\":    \"https://api.openai.com/v1/chat/completions\",
      \"headers\": {},
      \"body\":    \"{\\\"model\\\":\\\"gpt-4o-mini\\\",\\\"messages\\\":[{\\\"role\\\":\\\"user\\\",\\\"content\\\":\\\"List governance benefits\\\"}]}\",
      \"timestamp_ms\": $(date +%s000)
    },
    \"response\": {\"status\": 200, \"body\": \"{\\\"choices\\\":[{\\\"message\\\":{\\\"content\\\":\\\"1. Auditability\\\"}}]}\", \"latency_ms\": 280},
    \"upstream\": \"https://api.openai.com\"
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('receipt:', d.get('receipt_id'), '| seq:', d.get('sequence'), '| verdict:', d.get('admission_verdict'))"
```

**Call 2 — tool call (file read):**
```bash
curl -s -X POST "$BASE/api/v1/plugins/witnessctl/api/v1/ingest" \
  -H "Authorization: Bearer $CPK" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION\",
    \"agent_pid\":  \"demo-agent-001\",
    \"request\": {
      \"method\": \"POST\",
      \"url\":    \"https://api.openai.com/v1/chat/completions\",
      \"headers\": {},
      \"body\":    \"{\\\"model\\\":\\\"gpt-4o-mini\\\",\\\"messages\\\":[{\\\"role\\\":\\\"user\\\",\\\"content\\\":\\\"Read src/main.rs and summarise\\\"}]}\",
      \"timestamp_ms\": $(date +%s000)
    },
    \"response\": {\"status\": 200, \"body\": \"{\\\"choices\\\":[{\\\"message\\\":{\\\"content\\\":\\\"The file defines..\\\"}}]}\", \"latency_ms\": 410},
    \"upstream\": \"https://api.openai.com\"
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('receipt:', d.get('receipt_id'), '| seq:', d.get('sequence'), '| verdict:', d.get('admission_verdict'))"
```

**Call 3 — PII in request body (triggers classification):**
```bash
curl -s -X POST "$BASE/api/v1/plugins/witnessctl/api/v1/ingest" \
  -H "Authorization: Bearer $CPK" \
  -H "Content-Type: application/json" \
  -d "{
    \"session_id\": \"$SESSION\",
    \"agent_pid\":  \"demo-agent-001\",
    \"request\": {
      \"method\": \"POST\",
      \"url\":    \"https://api.openai.com/v1/chat/completions\",
      \"headers\": {},
      \"body\":    \"{\\\"user_email\\\":\\\"alice@example.com\\\",\\\"ssn\\\":\\\"123-45-6789\\\",\\\"content\\\":\\\"refund request\\\"}\",
      \"timestamp_ms\": $(date +%s000)
    },
    \"response\": {\"status\": 200, \"body\": \"{\\\"ok\\\":true}\", \"latency_ms\": 195},
    \"upstream\": \"https://api.openai.com\"
  }" | python3 -c "import sys,json; d=json.load(sys.stdin); print('receipt:', d.get('receipt_id'), '| seq:', d.get('sequence'), '| pii:', d.get('pii_request'))"
```

Each call returns `receipt_id`, `sequence`, `admission_verdict`, and `pii_request`.

---

### 2-D  Read the receipt chain directly

```bash
curl -s "$BASE/api/v1/plugins/witnessctl/api/v1/receipts?session_id=$SESSION" \
  -H "Authorization: Bearer $CPK" \
  | python3 -c "
import sys,json
receipts = json.load(sys.stdin).get('receipts', [])
for r in receipts:
    print(f\"seq={r['sequence']}  id={r['receipt_id'][:8]}...  prev={str(r.get('prev_hash',''))[:12]}...  pii={r.get('pii_detected',False)}\")
"
```

Shows the chain: `seq=1 prev=null`, `seq=2 prev=<hash of seq1>`, `seq=3 prev=<hash of seq2>`.

**Browser (Audit book tab):** Same chain — click any row to expand `hmac_sha256` + `prev_hash`.

---

### 2-E  Check compliance scores

```bash
curl -s "$BASE/api/v1/plugins/witnessctl/api/v1/compliance/$SESSION" \
  -H "Authorization: Bearer $CPK" \
  | python3 -c "
import sys,json
c=json.load(sys.stdin)
for fw,data in c.get('frameworks',{}).items():
    print(f\"{fw:12s}  score={data.get('score',0):.0%}  controls_pass={data.get('controls_pass',0)}/{data.get('controls_total',0)}\")
"
```

**Browser (Compliance map tab):** SOC 2, GDPR, EU AI Act scores derived from the real calls.

> PII in call 3 drops the GDPR score. Swap `"ssn":"123-45-6789"` for clean data and re-run — watch the score recover.

---

### 2-F  Seal the session

```bash
curl -s -X POST "$BASE/api/v1/plugins/witnessctl/api/v1/sessions/$SESSION/seal" \
  -H "Authorization: Bearer $CPK" \
  -H "Content-Type: application/json" \
  -d '{"reason": "lab complete"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('sealed:', d.get('sealed'), '| receipts:', d.get('receipt_count'), '| chain_valid:', d.get('chain_valid'))"
```

Expected: `sealed: True | receipts: 3 | chain_valid: True`

**Browser (Live room):** Refresh → status badge flips `open` → `sealed`. No more calls can be ingested.

---
---
# Part 3 — DevGuard: locking down the coding agent
---

> DevGuard is the local policy layer. It runs on the **operator's machine** (or CI), not on the playground server.  
> Configuration lives in `.connector/policy.yaml` next to your project.  
> The lab config below is in `lab/policy.yaml` in this folder.

---

### 3-A  Lab policy file

Create `.connector/policy.yaml` in any project directory — or use the file at `lab/policy.yaml` (see below).

The lab policy sets up three agents with distinct access tiers:

| Role | LLM model | Files: write | Execution | git push |
|---|---|---|---|---|
| `builder` | gpt-4o-mini | `src/**`, `tests/**` | cargo/npm/pytest + `git diff` | requires approval |
| `reviewer` | gpt-4o-mini | none (read-only) | cargo check, clippy, lint only | denied |
| `release` | gpt-4o | `src/**`, `tests/**`, `docs/**` | full + `npm publish` | requires approval (quorum 2) |

All roles share:
- **Hidden:** `.env*`, `*.key`, `*.pem`, `secrets/**`
- **No-delete:** `migrations/**`, `LICENSE`, `README.md`
- **Secret scan:** on — SSN, credit card, API key patterns auto-redacted before the LLM sees them
- **Audit:** full receipt chain written for every action

---

### 3-B  Start a governed Claude Code session (builder role)

```bash
connectorctl guard claude \
  --task "Refactor the UserService class to use the repository pattern" \
  --role builder \
  --policy .connector/policy.yaml \
  --workspace .
```

What DevGuard does in the background:
1. Loads and compiles the policy for `builder`
2. Registers an agent session with clearance level 4
3. Starts the Anthropic-compatible gateway on `localhost:9091`
4. Launches Claude with `ANTHROPIC_BASE_URL=http://localhost:9091`
5. Every `tool_use.bash` call hits the `exec_guard` workflow before execution
6. Every file read/write is checked against the `file_guard` rules
7. `git push` triggers `approval_check` — pauses until operator approves

---

### 3-C  Watch the exec guard fire — denied command

Open a second terminal and try sending a denied command through the session:

```bash
# Simulate the agent trying to run a denied command
curl -s -X POST "http://localhost:9091/api/v1/sessions/$SESSION_ID/exec" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "rm -rf ./dist", "working_dir": "."}'
```

Expected response:
```json
{
  "allowed": false,
  "verdict": "DENY",
  "reason": "matched deny pattern: rm -rf*",
  "requires_approval": false
}
```

---

### 3-D  Watch the approval gate fire — git push

```bash
# This will be HELD until you approve in the dashboard
curl -s -X POST "http://localhost:9091/api/v1/sessions/$SESSION_ID/exec" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "git push origin feature/refactor-user-service"}'
```

Expected: `202 Accepted` with an `approval_id`.

**Approve from the dashboard** (same Approvals tab used for TraceTramp HITL), or via CLI:

```bash
connectorctl guard approve <approval_id>
```

---

### 3-E  Read the DevGuard audit trail

```bash
connectorctl guard audit --session $SESSION_ID --format json | python3 -m json.tool | head -60
```

Shows every action: file reads, writes, shell commands, LLM calls — each with verdict, timestamp, and receipt hash.

---

### 3-F  Generate the compliance proof bundle

```bash
connectorctl guard proof --session $SESSION_ID --output ./lab-proof.zip
```

Contents of `lab-proof.zip`:
- `receipts.jsonl` — full receipt chain
- `policy_snapshot.yaml` — policy as loaded at session start
- `audit.jsonl` — every action with verdict
- `chain_verification.json` — HMAC chain validity result
- `session_summary.json` — agent, role, timestamps, total cost

---
---
# Connecting all three — the full governance stack
---

The three plugins cover different planes:

| Plugin | Plane | Governs |
|--------|-------|---------|
| **DevGuard** | Local / agent | File access, shell commands, git, secrets, approval gates |
| **TraceTramp** | LLM gateway | Every model call — policy, PII, HITL, cost metering |
| **WitnessCtl** | Compliance | Tamper-evident receipts, chain custody, SOC 2/GDPR/EU AI Act |

**Combined flow:**
1. DevGuard starts the agent session → sets `ANTHROPIC_BASE_URL=tracetramp:9741`
2. Agent makes an LLM call → TraceTramp intercepts, applies policy, emits a trace
3. TraceTramp hands off the trace to WitnessCtl → WitnessCtl appends to the receipt chain
4. Operator sees all three layers in the dashboard — one browser, no config files mid-session

Enable handoff in `supervisord.playground.conf` / your local env:
```bash
export TRACETRAMP_WITNESS_HANDOFF_URL="http://127.0.0.1:7443/api/v1/integrations/tracetramp/handoff"
export TRACETRAMP_WITNESS_HANDOFF_SECRET="$WITNESSCTL_TRACETRAMP_HANDOFF_SECRET"
```

Once set, every TraceTramp trace automatically creates a WitnessCtl receipt — no manual ingest needed.

---

## Contrast table

| Situation without Connector OS | With Connector OS |
|-------------------------------|-------------------|
| Review logs after a bad model call | Call blocked **before** the model responds — receipt exists either way |
| Export audit logs manually for a compliance report | Compliance report auto-derived from the live receipt chain |
| Detect PII in model calls by grepping logs | PII classified field-by-field on every request and response, real time |
| Approve a risky git push by Slack DM | HITL approval queue in the dashboard — one click, fully logged |
| Trust your CI didn't modify the audit trail | HMAC-chained receipts — any tampering breaks chain verification |
| Hard-code file/command allow lists in CI | DevGuard policy YAML versioned with the project, enforced at the agent layer |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401` on any call | Session expired or `CPK` not exported | Re-run Step 0, `export CPK=...` |
| `tracetramp upstream_reachable: false` | Plugin still starting | Wait 10 s and retry — `status_badge` turns `healthy` once both planes are up |
| HITL call not appearing in Approvals tab | `202` not caught | Check terminal for `approval_id`; hit Refresh on Approvals tab |
| `$SESSION` is empty | WitnessCtl `/sessions` returned an error | Check the raw response: remove the `python3 -c ...` extract and pipe to `json.tool` |
| Compliance scores `0` after ingest | Session has no calls yet | Run the three ingest calls in 2-C, then re-fetch compliance |
| `chain_valid: false` on seal | Receipt chain was broken | Use `GET /api/v1/receipts?session_id=...` to find the gap |
| DevGuard `connectorctl` not found | Binary not in `$PATH` | Run `cargo install --path platform/server --bin connectorctl` or use the released binary |

---

## Key URLs

| Resource | URL |
|----------|-----|
| Trial page | <https://try.cnktros.com/trial> |
| Plugins hub | <https://try.cnktros.com/plugins> |
| TraceTramp dashboard | <https://try.cnktros.com/plugins/tracetramp> |
| WitnessCtl dashboard | <https://try.cnktros.com/plugins/witnessctl> |
| Plugin status API | <https://try.cnktros.com/api/v1/plugins/status> |
| DevGuard schema | `plugins/devguard/devguard.schema.json` |
| DevGuard policy template | `plugins/devguard/templates/policy.yaml` |

---

## Recording checklist

- [ ] Browser zoom 110%, terminal font ≥ 16pt, dark background
- [ ] Split: terminal left 40%, browser right 60%
- [ ] Close notifications, Slack, email
- [ ] `export CPK=... TENANT=... BASE=...` before hitting record
- [ ] `export SESSION=...` after running 2-B
- [ ] Pre-navigate browser to TraceTramp dashboard
- [ ] Keep **Refresh** button visible — use after every terminal block

---

*`platform/docs/projects/plugin-test/README.md` — updated 2026-05-29*
