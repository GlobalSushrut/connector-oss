# 41 — Builder: witnessctl Plugin

> How witnessctl works, how to configure it, and how to build on top of it.

---

## What witnessctl Does

witnessctl is the API capture and attestation plugin for Connector. It wraps outbound API calls — to external services, internal microservices, or third-party APIs — and:

1. **Captures** the full request and response
2. **Extracts** the API schema from the observed traffic
3. **Detects** PII in both request and response
4. **Inspects** through the admission gate and firewall
5. **Emits** a HMAC-chained receipt for every call
6. **Stores** tamper-evident evidence in the memory kernel
7. **Maps** each captured call to compliance controls
8. **Generates** a proof bundle for the session

---

## Plugin Structure

```
plugins/witnessctl/
├── plugin.yaml                # Plugin manifest
├── workflows/
│   ├── session_open.yaml      # Start a capture session
│   ├── capture.yaml           # Per-call capture pipeline
│   ├── inspect.yaml           # Inspect a session
│   ├── seal.yaml              # Close and seal a session
│   ├── report.yaml            # Generate compliance report
│   ├── replay.yaml            # Replay a captured session
│   └── verify.yaml            # Verify a sealed session
├── internal/
│   ├── chain_emit.yaml        # HMAC receipt chaining
│   ├── schema_extract.yaml    # Schema inference and drift detection
│   ├── policy_eval.yaml       # Per-call policy evaluation
│   └── compliance_map.yaml    # Framework control mapping
└── templates/
    ├── compliance_report.md   # Report template
    ├── receipt.json           # Receipt structure
    └── policy_schema.yaml     # Policy schema
```

---

## `plugin.yaml`

```yaml
name:        witnessctl
version:     "1.0.0"
description: "API capture and compliance attestation plugin"

workflows:
  count: 7
  public: [session_open, capture, inspect, seal, report, replay, verify]

internal_workflows:
  count: 4
  list:  [chain_emit, schema_extract, policy_eval, compliance_map]

templates:
  count: 3
  list:  [compliance_report.md, receipt.json, policy_schema.yaml]
```

---

## Session Lifecycle

```
session_open()          ← Register agent + initialize receipt chain
    │
    ▼
capture(request, response)  ← One call per API interaction
    │   (repeated N times)
    ▼
inspect(session_id)         ← Optional: check session mid-flight
    │
    ▼
seal(session_id)            ← Close chain, collect all evidence
    │
    ▼
report(session_id)          ← Generate compliance report
    │
    ▼
verify(bundle_id)           ← Verify the sealed bundle
```

---

## Using witnessctl from Python

```python
import sys, json, requests, hashlib
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

# 1. Open session
agent = p.register_agent("witness-session", "witnessctl capture session", 3)
pid   = agent["pid"]
ns    = agent["namespace"]

# 2. Capture an API call
def witness_capture(pid, ns, method, url, payload, headers=None):
    """Capture and attest a single API call."""
    import time
    t0 = time.time()

    # Firewall inspect before making the call
    fw_req = p.firewall_inspect(pid, json.dumps(payload or {}), ns)
    if fw_req["blocked"]:
        p.record_decision(pid, f"api.blocked:{method.upper()}:{url[:60]}",
                          url, "blocked_by_firewall",
                          rationale=fw_req["final_decision"],
                          regulations=["soc2"])
        return None

    # Make the actual API call
    resp = requests.request(method, url, json=payload, headers=headers or {}, timeout=10)

    latency_ms = round((time.time() - t0) * 1000)

    # Firewall inspect response
    fw_resp = p.firewall_inspect(pid, resp.text[:2000], ns)
    pii_in_resp = fw_resp.get("pii_detected", False)

    # Hash request and response
    req_hash  = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
    resp_hash = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

    # Record decision
    outcome = "allow" if resp.ok else f"http_{resp.status_code}"
    p.record_decision(pid,
        f"api.call:{method.upper()}:{url[:60]}",
        url, outcome,
        rationale=(
            f"status={resp.status_code}; latency={latency_ms}ms; "
            f"pii_req={fw_req.get('pii_detected')}; pii_resp={pii_in_resp}; "
            f"req_hash={req_hash}"
        ),
        confidence=0.99,
        regulations=["soc2"])

    # Store evidence
    evidence = {
        "url":        url,
        "method":     method.upper(),
        "status":     resp.status_code,
        "latency_ms": latency_ms,
        "req_hash":   req_hash,
        "resp_hash":  resp_hash,
        "pii_in_req": fw_req.get("pii_detected"),
        "pii_in_resp": pii_in_resp,
        "fw_blocked": fw_req.get("blocked")
    }

    cid = p.write_memory(pid, json.dumps(evidence),
                          ptype="witnessctl_capture",
                          memory_type="evidence",
                          tags=["witnessctl", f"url:{url[:40]}"],
                          entity_kind="witnessctl_capture")["cid"]

    return {**evidence, "cid": cid}

# 3. Capture a real API call
result = witness_capture(pid, ns, "GET",
    "https://suggestqueries.google.com/complete/search",
    {"q": "machine learning", "client": "firefox"})

if result:
    print(f"Captured: {result['url']}")
    print(f"Status: {result['status']}")
    print(f"PII in response: {result['pii_in_resp']}")
    print(f"Evidence CID: {result['cid']}")
```

---

## Recall All Session Evidence

```python
evidence = p.recall_memory(ns, limit=100, memory_type="evidence")
captures  = evidence.get("packets", [])

print(f"\nTotal captures: {len(captures)}")
for pkt in captures:
    data = json.loads(pkt["content"])
    print(f"  {data['method']} {data['url'][:60]} → {data['status']}")
```

---

## Seal and Generate Report

```python
# Seal the session
proof = p.generate_proof(pid, title="witnessctl_session")
print(f"\nSession sealed: {proof['proof_id']}")
print(f"Chain verified: {proof['chain_verified']}")
print(f"Journal entries: {proof['journal_entries']}")

# Generate compliance report
report = p.get_regulation_report("soc2")
print(f"SOC2 report: ok={report.get('ok')}")
```

---

## witnessctl Policy Schema

Configure per-domain policies in `templates/policy_schema.yaml`:

```yaml
# Which domains to capture
domains:
  - host: "*.googleapis.com"
    capture: true
    pii_check: true
    schema_extract: true

  - host: "internal.company.com"
    capture: true
    pii_check: true
    admission_gate: strict

# PII in requests — what to do
pii_in_request:
  ssn:         block
  credit_card: block
  email:       log_and_allow

# PII in responses — what to do
pii_in_response:
  phi: block_and_alert
  email: log_and_allow
```

---

## Next Steps

- **[42 — Builder: Tool Bridge](42-builder-tool-bridge.md)**
- **[plugins/witnessctl/](../plugins/witnessctl/plugin.yaml)**
- **[40 — Tutorial: HIPAA System](40-tutorial-compliance.md)**
