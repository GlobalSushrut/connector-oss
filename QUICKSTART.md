# Quickstart — 5 Minutes to Trusted AI Agents

Pick your path: **Python**, **TypeScript**, **Docker**, or **curl**.

---

## Option A: Python SDK

```bash
pip install connector-oss
```

```python
import os
from connector_oss import Connector

c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])

# Run an agent with trusted memory
result = c.agent("bot", "You are a helpful assistant").run("Hello!", "user:alice")

print(result.text)         # LLM response
print(result.trust)        # 0-100 kernel-verified trust score
print(result.trust_grade)  # "A+" | "A" | "B" | "C" | "D" | "F"

# Write memory (tamper-proof, CID-addressed)
c.memory_write("pid:bot", "text", "Patient has fever", "user:nurse", "ns:er")

# Search memory
packets = c.search_namespace("ns:er", limit=10)

# Knowledge graph
c.knowledge_ingest("ns:er")
ctx = c.rag_retrieve("pid:bot", "ns:er", entities=["fever"], max_facts=10)

# Multi-agent pipeline with HIPAA compliance
pipe = c.pipeline("support")
pipe.agent("triage", "Classify tickets")
pipe.agent("resolver", "Find answers")
pipe.route("triage -> resolver")
pipe.hipaa()
result = pipe.run("My account is locked", user="user:bob")
```

### From YAML config

```bash
export DEEPSEEK_API_KEY=sk-...
python -c "
from connector_oss import Connector
c = Connector.from_config('examples/yaml/level0_hello.yaml')
r = c.agent('bot', 'You are helpful').run('Hello!', 'user:alice')
print(r.text)
"
```

---

## Option B: TypeScript / Node.js SDK

```bash
npm install @connector-oss/connector
```

```typescript
import { Connector, isNativeAvailable } from '@connector-oss/connector'

console.log('Native Rust:', isNativeAvailable()) // true if prebuilt binary available

const c = new Connector({
  llm: 'deepseek:deepseek-chat',
  apiKey: process.env.DEEPSEEK_API_KEY
})

// Memory (tamper-proof, kernel-verified)
await c.remember('pid:bot', 'Patient has fever', 'nurse')
const mems = await c.memories('ns:er')

// Sessions
const sess = await c.sessionCreate('pid:bot', 'ns:er', 'ER Visit')
await c.sessionClose('pid:bot', sess.session_id)

// Search
const results = await c.search({ namespace: 'ns:er', limit: 10 })

// Custom folders (OS mkdir model)
await c.folderCreate('agent:nurse/notes', 'agent', 'nurse', 'Patient notes')
await c.folderPut('agent:nurse/notes', 'p123', { bp: '140/90' })

// Trust & stats
const trust = await c.trust()
const stats = await c.dbStats()
```

---

## Option C: Docker (REST API — 38 routes)

```bash
# One command to run the server
docker run -p 8080:8080 \
  -e DEEPSEEK_API_KEY=sk-... \
  globalsushrut/connector-oss

# Or with docker compose (includes SQLite persistence)
export DEEPSEEK_API_KEY=sk-...
docker compose up
```

Then use curl:

```bash
# Health check
curl http://localhost:8080/health

# Run an agent
curl -X POST http://localhost:8080/run \
  -H 'Content-Type: application/json' \
  -d '{"agent": "bot", "instructions": "You are helpful", "input": "Hello!", "user": "alice"}'

# Write memory
curl -X POST http://localhost:8080/remember \
  -H 'Content-Type: application/json' \
  -d '{"pid": "pid:bot", "content": "Patient has fever", "user": "nurse", "namespace": "ns:er"}'

# Search memory
curl http://localhost:8080/memories/ns:er

# Knowledge graph
curl -X POST http://localhost:8080/knowledge/ingest \
  -H 'Content-Type: application/json' \
  -d '{"namespace": "ns:er"}'

# DB stats
curl http://localhost:8080/db/stats

# Prometheus metrics
curl http://localhost:8080/metrics
```

---

## Option D: Build from Source

```bash
git clone https://github.com/GlobalSushrut/connector-oss.git
cd connector-oss

# Test everything (1,857 tests)
cd connector && cargo test    # 1,194 tests
cd ../vac && cargo test       # 492 tests
cd ../aapi && cargo test      # 171 tests

# Run the server
cd ../connector
DEEPSEEK_API_KEY=sk-... cargo run -p connector-server

# Build Python FFI
cd ../sdks/python
pip install maturin
maturin develop --release

# Build TypeScript SDK (requires Rust)
cd ../typescript
npm install
npm run build
```

---

## YAML Config Levels (Progressive Complexity)

| Level | File | What it adds |
|-------|------|-------------|
| 0 | `level0_hello.yaml` | 1 line: just `agent: "..."` |
| 1 | `level1_memory.yaml` | Memory + namespaces |
| 2 | `level2_pipeline.yaml` | Multi-agent pipelines |
| 3 | `level3_security.yaml` | Firewall + HIPAA + policies |
| 4 | `level4_economy.yaml` | Budgets + escrow + pricing |
| 5 | `level5_database.yaml` | SQLite + custom folders |
| 6 | `level6_distributed.yaml` | Cluster + replication + BFT consensus |
| 7 | `level7_full_stack.yaml` | Everything (kitchen sink reference) |

Start at Level 0. Add features by adding YAML sections. **Absent = OFF.**

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|---------|---------|-------------|
| `DEEPSEEK_API_KEY` | Yes (or any LLM key) | — | LLM provider API key |
| `CONNECTOR_ENGINE_STORAGE` | No | `memory` | `memory`, `sqlite:path`, `redb:path` |
| `CONNECTOR_CELL_ID` | No | `cell_default` | Cell identity for distributed mode |
| `CONNECTOR_ADDR` | No | `0.0.0.0:8080` | Server bind address |
| `RUST_LOG` | No | `info` | Log level |

---

## What Makes This Different

| | LangChain | CrewAI | OpenAI SDK | **Connector-OSS** |
|-|-----------|--------|-----------|-------------------|
| Tamper-proof memory | ❌ | ❌ | ❌ | ✅ CID-addressed, kernel-verified |
| Audit trail | ❌ | ❌ | ❌ | ✅ Ed25519-signed, append-only |
| HIPAA/SOC2/GDPR | ❌ | ❌ | ❌ | ✅ Built-in compliance policies |
| Policy enforcement | ❌ | ❌ | ❌ | ✅ Non-bypassable 5-layer guard |
| Trust scoring | ❌ | ❌ | ❌ | ✅ Per-response kernel-verified score |
| Multi-cell federation | ❌ | ❌ | ❌ | ✅ BFT consensus + SCITT attestation |
| Protocol (A2A/MCP/ACP) | Partial | ❌ | ❌ | ✅ All three + CP/1.0 native |

---

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for the full system overview
- Browse `examples/yaml/` for progressive config examples
- See 38 REST routes in the architecture doc
- Join discussions at [GitHub Issues](https://github.com/GlobalSushrut/connector-oss/issues)
