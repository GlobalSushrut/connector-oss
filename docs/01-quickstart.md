# 01 — Quickstart

> Boot a governed node. Prefer the boring Linux path when you want production-shaped install.

---

## Self-host Linux (recommended for real hosts)

```bash
make package
tar -xzf dist/connector-os-*-linux.tar.gz
cd connector-os-*/
sudo ./install.sh
sudo systemctl enable --now connector-platform
curl -fsS http://127.0.0.1:9091/healthz
connectorctl doctor
```

Full operator path: [SELFHOST_LINUX.md](SELFHOST_LINUX.md) · packaging truths: [PACKAGING.md](../platform/deploy/PACKAGING.md).

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Linux (Ubuntu 22.04+) / macOS 13+ | Ubuntu 22.04 LTS |
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 8 GB |
| Disk | 4 GB | 20 GB |
| Python | 3.10+ | 3.11+ |
| Docker | 24+ (optional) | 24+ |

---

## Dev: Clone + Run

```bash
git clone https://github.com/connectorai/connector-private
cd connector-private
make run-local
```

Single onboarding URL:

```text
http://localhost:9091/v1
```

## Step 2 — Point SDKs

Set:

```bash
export OPENAI_BASE_URL=http://localhost:9091/v1
export OPENAI_API_KEY=dev-token
# Anthropic-compatible clients:
export ANTHROPIC_BASE_URL=http://localhost:9091/v1
export ANTHROPIC_API_KEY=dev-token
```

Leaving these unset lets the client talk to the vendor directly. On a hardened node, connecting a session can DROP that path — see [WORLD_CAGE_AND_BROWSER.md](WORLD_CAGE_AND_BROWSER.md).

## Step 3 — Bootstrap with connectorctl

```bash
connectorctl quickstart
```

This checks connectivity, creates your first agent, runs a first governance event, and prints trace follow-ups.

---

## Step 1 (Detailed) — Install

### Docker (fastest)

```bash
docker pull connectorai/connector:latest
docker run -d \
  --name connector \
  -p 9091:9091 \
  -e CONNECTOR_API_KEY=dev-local-key \
  -e CONNECTOR_DEV_MODE=1 \
  connectorai/connector:latest
```

### Bare Metal

```bash
# Download the binary
curl -fsSL https://install.connector.ai | bash

# Or build from source
git clone https://github.com/connectorai/connector-private
cargo build --release -p connector-server
./target/release/connector-server --config connector.yaml
```

### Environment Variables

```bash
export CONNECTOR_URL=http://localhost:9091
export CONNECTOR_API_KEY=dev-local-key
export CONNECTOR_DEV_MODE=1          # enables dev token, relaxes auth
```

---

## Step 2 — Verify Health

```bash
connectorctl health
```

Expected output:
```
● Connector  v1.x.x  READY
  node_id:   node_abc123
  uptime:    0h 0m 12s
  rings:     9/9 active
  journal:   seq=1  chain_ok=true
  memory:    0 packets
  agents:    0 active
```

Or via HTTP:
```bash
curl http://localhost:9091/health
```

```json
{
  "status": "ready",
  "version": "1.x.x",
  "rings_active": 9,
  "chain_verified": true,
  "uptime_seconds": 12
}
```

---

## Step 3 — Create Your First Agent

```bash
connectorctl agents create \
  --name my-first-agent \
  --role assistant \
  --clearance 3
```

Or via Python:
```python
import sys
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()
agent = p.register_agent("my-first-agent", "My first governed agent", clearance=3)
pid = agent["pid"]
print(f"Agent created: {pid}")
```

---

## Step 4 — Run the 5 Essential Commands

```bash
# 1. List all agents
connectorctl agents

# 2. Inspect your agent
connectorctl inspect <pid>

# 3. Show formatted summary
connectorctl show agent <pid>

# 4. View the audit journal
connectorctl trace agent <pid>

# 5. Generate a proof bundle
connectorctl prove agent <pid>
```

---

## Step 5 — Make a Governed Chat Call

```python
from system_data import ConnectorPlatform

p = ConnectorPlatform()
agent = p.register_agent("quickstart-agent", "Quickstart demo", 3)
pid = agent["pid"]

# Governed chat — passes through all 9 rings
response = p.invoke_chat(
    agent_pid=pid,
    namespace=f"m/{pid}",
    prompt="What is the capital of France?",
    system="You are a helpful assistant."
)
print(response)
```

Every call through `/v1/chat/completions` produces:
- A `decision_id` — governance decision record
- An `audit_cid` — content-addressed journal entry
- A journal entry in the integrity chain

---

## Step 6 — See the Governance Decision

```bash
connectorctl explain <decision_id>
```

```
Decision: allow_forwarded
Action:   chat.invoke
Target:   /v1/chat/completions
Outcome:  ALLOW
Confidence: 0.99
Regulations: []
Audit CID: mem1-sha256-abc...
Chain verified: true
```

---

## Step 7 — Inspect the Firewall

```python
result = p.firewall_inspect(pid, "What is the capital of France?")
print(result)
# {
#   "blocked": false,
#   "final_decision": "Allow",
#   "layers_evaluated": 5,
#   "injection_score": 0.01,
#   "pii_detected": false
# }
```

---

## What You Just Proved

| Claim | Evidence |
|---|---|
| Every LLM call is governed | `decision_id` on every response |
| Every action is audited | `audit_cid` in audit journal |
| PII is scanned | `firewall_inspect` result |
| Chain is tamper-evident | `chain_verified: true` |

---

## Common Errors

| Error | Cause | Fix |
|---|---|---|
| `CONNECTOR_API_KEY must be set` | No auth configured | Set `CONNECTOR_DEV_MODE=1` |
| `Connection refused` | Node not running | Check `docker ps` or `systemctl status connector` |
| `401 Unauthorized` | Wrong API key | Verify `CONNECTOR_API_KEY` matches node config |
| `Agent not found` | Wrong PID | Run `connectorctl agents` to list |

---

## Next Steps

- **[02 — Product Overview](02-product-overview.md)** — understand the architecture
- **[04 — Python SDK](04-python-sdk.md)** — full method reference
- **[33 — Tutorial: First Agent](33-tutorial-first-agent.md)** — deep walkthrough
