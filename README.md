<div align="center">

<img src="https://img.shields.io/badge/Connector_OSS-Tamper--Proof_AI_Memory-6C3483?style=for-the-badge" alt="Connector OSS"/>

# Connector OSS

### *Kernel + Control-Plane + SDK for trusted AI agents.*

> Tamper-proof memory · Ed25519 audit trail · Non-bypassable policy enforcement
> 28 crates · 61 engine modules · 11 protocol layers · 1,857 tests · 0 failures

<br/>

[![License](https://img.shields.io/badge/license-Apache%202.0-22c55e?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/badge/pip_install-connector--agent--oss-3b82f6?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/connector-agent-oss/)
[![npm](https://img.shields.io/badge/npm-@connector__oss/connector-ef4444?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@connector_oss/connector)
[![Docker](https://img.shields.io/badge/docker-connector--oss-2496ED?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/adminumesh3011/connector-oss)
[![Tests](https://img.shields.io/badge/tests-1%2C857_passed-22c55e?style=flat-square)](https://github.com/GlobalSushrut/connector-oss)

<br/>

**Built by [Umesh Adhikari](mailto:umeshlamton@gmail.com)** · 📧 [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com) · 🐙 [GitHub](https://github.com/GlobalSushrut/connector-oss)

</div>

---

## Install — Pick Your Language

```bash
pip install connector-agent-oss                        # Python (native Rust via PyO3)
npm install @connector_oss/connector                   # TypeScript (native Rust via NAPI-RS)
docker run -p 8080:8080 adminumesh3011/connector-oss   # Server (38 REST + 10 protocol routes)
```

> No Rust toolchain needed. Prebuilt binaries for Linux, macOS, Windows.

---

## 60-Second Hello World

### Python

```python
import os
from connector_agent_oss import Connector

c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
result = c.agent("bot", "You are helpful").run("Hello!", "user:alice")

print(result.text)         # LLM response
print(result.trust)        # 0-100 kernel-verified trust score
print(result.trust_grade)  # "A+"
print(result.cid)          # tamper-proof content hash
```

### TypeScript

```typescript
import { Connector, isNativeAvailable } from '@connector_oss/connector'
const c = new Connector({ llm: 'deepseek:deepseek-chat', apiKey: process.env.DEEPSEEK_API_KEY })
await c.remember('pid:bot', 'Patient has fever', 'nurse')
const mems = await c.memories('ns:er')
```

### Docker

```bash
docker run -p 8080:8080 -e DEEPSEEK_API_KEY=sk-... adminumesh3011/connector-oss
curl http://localhost:8080/health
```

**[→ Full 5-minute guide: QUICKSTART.md](QUICKSTART.md)**

---

## Why Connector — vs Everything Else

| | LangChain | CrewAI | OpenAI SDK | **Connector-OSS** |
|-|-----------|--------|-----------|-------------------|
| Tamper-proof memory | ❌ | ❌ | ❌ | ✅ CID-addressed, kernel-verified |
| Audit trail | ❌ | ❌ | ❌ | ✅ Ed25519-signed, HMAC-chained |
| HIPAA/SOC2/GDPR | ❌ | ❌ | ❌ | ✅ Built-in from real evidence |
| Policy enforcement | ❌ | ❌ | ❌ | ✅ Non-bypassable 5-layer guard |
| Trust scoring | ❌ | ❌ | ❌ | ✅ Per-response, 0-100 |
| Multi-cell federation | ❌ | ❌ | ❌ | ✅ BFT consensus + SCITT |
| Agent protocol | Partial | ❌ | ❌ | ✅ CP/1.0 + A2A + MCP + ACP |

---

## Who This Is For

| Industry | What Connector Solves |
|----------|----------------------|
| **Healthcare** | Tamper-evident memory + HIPAA audit trail from real kernel evidence |
| **Finance** | HMAC-chained audit + SOC2/GDPR reports from kernel data |
| **Legal** | CIDv1 + Ed25519 = cryptographic chain of custody |
| **Government** | EU AI Act decision traceability, exportable for regulators |
| **Defense** | Air-gapped, TOP_SECRET classification, MFA, zero delegation |

---

## What You Get — Zero Config

| Feature | How | API |
|---------|-----|-----|
| **Tamper-proof memory** | CIDv1 = SHA2-256(DAG-CBOR) | `result.cid` |
| **Trust score 0–100** | Kernel-computed from real audit data | `result.trust` |
| **Full audit trail** | HMAC-chained, Ed25519-signed | `c.audit_count()` |
| **Namespace isolation** | Kernel-enforced, non-bypassable | Automatic |
| **Knowledge graph + RAG** | KnotEngine, entity extraction | `c.rag_retrieve(...)` |
| **Multi-agent pipelines** | DAG orchestration, saga rollback | `c.pipeline(...)` |
| **Custom folders** | OS-like mkdir/put/get model | `c.folder_create(...)` |
| **Compliance reports** | From real kernel evidence | `result.comply("hipaa")` |

---

## Build Anything — Same Install, Add YAML

```
Simple chatbot           →  3 lines of Python
Persistent memory        →  add  storage: sqlite:./data.db
Multi-agent pipeline     →  add  flow: [triage, doctor, pharmacist]
HIPAA-compliant system   →  add  comply: [hipaa]  +  secure: hipaa
SOC2 + GDPR finance      →  add  comply: [soc2, gdpr]  +  jurisdiction: EU
Distributed cluster      →  add  cluster: { peers: [...], consensus: bft }
```

### YAML Config Levels (progressive complexity)

| Level | File | What it adds |
|-------|------|-------------|
| 0 | `level0_hello.yaml` | 1 line: `agent: "..."` — auto-detects everything |
| 1 | `level1_memory.yaml` | Memory + namespaces |
| 2 | `level2_pipeline.yaml` | Multi-agent pipelines |
| 3 | `level3_security.yaml` | Firewall + HIPAA + policies |
| 4 | `level4_economy.yaml` | Budgets + escrow + pricing |
| 5 | `level5_database.yaml` | SQLite/ReDB + custom folders |
| 6 | `level6_distributed.yaml` | Cluster + replication + BFT consensus |
| 7 | `level7_full_stack.yaml` | Everything (kitchen sink reference) |

```yaml
# connector.yaml — HIPAA-compliant ER triage in 15 lines
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: sqlite:./data.db
  comply: [hipaa, soc2]
  security:
    signing: true
    data_classification: PHI
  firewall:
    preset: hipaa
agents:
  triage: { instructions: "Classify patients by urgency 1-5." }
  doctor: { instructions: "Diagnose based on triage.", memory_from: [triage] }
```

→ [Full YAML Dictionary](docs/31_YAML_DICTIONARY.md)

---

## Examples

### Healthcare — HIPAA ER Triage

```python
c = Connector.from_config("hospital.yaml")
triage = c.agent("triage", "Classify patients by urgency 1-5.")
doctor = c.agent("doctor", "Diagnose based on triage data.")

t = triage.run("45M, chest pain 2h, BP 158/95", "patient:P-001")
d = doctor.run(f"Patient: {t.text}", "patient:P-001")
print(f"Trust: {d.trust}/100 ({d.trust_grade})")  # A+
```

### Finance — Fraud Detection

```python
c = Connector.from_config("finance.yaml")  # comply=[soc2, gdpr]
result = c.agent("fraud_analyzer", "Analyze transactions.").run(
    "Transaction: $4,200 at 3:47 AM, Lagos. Cardholder in New York.",
    "user:card-8821"
)
print(f"CID: {result.cid}")  # immutable audit evidence
```

### Multi-Agent Pipeline

```python
pipe = c.pipeline("support")
pipe.agent("triage", "Classify tickets")
pipe.agent("resolver", "Find answers")
pipe.route("triage -> resolver")
pipe.hipaa()
result = pipe.run("My account is locked", user="user:bob")
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  pip install connector-agent-oss  /  npm i @connector_oss/connector               │
│  Python (PyO3 ~140 fn)     TypeScript (NAPI-RS ~35 methods + HTTP fallback)│
├─────────────────────────────────────────────────────────────────────────────┤
│  connector-server  (38 REST + 10 protocol routes)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 4 — connector-api  (developer surface)                                │
│  Connector · AgentBuilder · PipelineBuilder · YAML config · auto-detect     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 3 — connector-engine  (61 modules)                                    │
│  GuardPipeline (5-layer) · PolicyEngine · Firewall · TrustComputer         │
│  AdaptiveRouter · BftConsensus · Orchestrator · CircuitBreaker · Watchdog  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 1 — VAC Memory Kernel     │  Ring 2 — AAPI Action Kernel              │
│  MemoryKernel · 29 syscalls     │  VAKYA grammar (8 slots, 15 verbs)        │
│  MemPacket (CID-addressed)      │  Ed25519 signing · capability tokens      │
│  KnotEngine · Prolly tree       │  SagaCoordinator · FederatedPolicy        │
│  vac-cluster · vac-replicate    │  Marketplace · Payment escrow             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 0 — Cryptographic Foundation                                           │
│  CIDv1 · Ed25519 · HMAC-SHA256 · Noise_IK · ML-DSA-65 · Prolly Merkle    │
├─────────────────────────────────────────────────────────────────────────────┤
│  Connector Protocol — CP/1.0  (7 layers, 120 capabilities)                  │
│  Identity · Channel · Capability · Safety · Consensus · Routing · Envelope │
│  Bridges: ANP · A2A · ACP · MCP · SCITT                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

**28 crates · 3 workspaces · 1,857 tests · 0 failures** → [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Compliance & Trust

Reports from **actual kernel audit evidence** — not self-assessment:

| Framework | What it checks |
|-----------|---------------|
| **HIPAA** | PHI access controls, audit trail, integrity, encryption |
| **SOC2** | Availability, access controls, change management |
| **GDPR** | Right to erasure, data minimization, retention |
| **EU AI Act** | Human oversight, risk management, transparency |
| **NIST AI RMF** | GOVERN / MAP / MEASURE / MANAGE |
| **DoD** | TOP_SECRET classification, MFA, no delegation |

**Trust score (0–100)** — kernel-derived, not self-reported:

| Dimension | Max | Measures |
|-----------|-----|----------|
| Memory Integrity | 20 | % of packets with valid CIDs |
| Audit Completeness | 20 | HMAC chain intact |
| Authorization | 20 | % of writes with VAKYA token |
| Provenance | 20 | % of decisions with evidence CIDs |
| Operational Health | 20 | No denied/failed ops |

---

## Install & Publish

### From Source

```bash
git clone https://github.com/GlobalSushrut/connector-oss.git && cd connector-oss

# Test (1,857 tests)
cd connector && cargo test && cd ..   # 1,194 tests
cd vac && cargo test && cd ..         # 492 tests
cd aapi && cargo test && cd ..        # 171 tests

# Python FFI
cd sdks/python && pip install maturin && maturin develop --release && cd ../..

# TypeScript SDK (native Rust via NAPI-RS)
cd sdks/typescript && npm install && npm run build && cd ../..

# Docker
docker build -t connector-oss .
```

### CI / Publishing

Automated via GitHub Actions on `git tag v*`:

| Package | Registry | Workflow |
|---------|----------|---------|
| `connector-agent-oss` | PyPI | `publish-pypi.yml` |
| `@connector_oss/connector` | npm | `publish-npm.yml` |
| `adminumesh3011/connector-oss` | Docker Hub + GHCR | `publish-docker.yml` |

---

## Repository Structure

```
connector-oss/
├── connector/crates/
│   ├── connector-api/       # Connector, AgentBuilder, PipelineBuilder, YAML
│   ├── connector-engine/    # 61 modules: firewall, policy, trust, routing...
│   ├── connector-server/    # axum HTTP (38 + 10 protocol routes)
│   ├── connector-protocol/  # CP/1.0 (7 layers, 120 capabilities)
│   └── connector-protocols/ # Bridges: ANP, A2A, ACP, MCP, SCITT
├── vac/crates/
│   ├── vac-core/            # MemoryKernel, MemPacket, CID, audit
│   ├── vac-store/           # SQLite, ReDB, Prolly, InMemory
│   ├── vac-ffi/             # PyO3 → Python (~140 methods)
│   └── vac-cluster/         # Cell cluster, replication, BFT
├── aapi/crates/
│   ├── aapi-core/           # VAKYA grammar (8 slots, 15 verbs)
│   ├── aapi-federation/     # Cross-org governance, marketplace
│   └── aapi-pipeline/       # Saga coordinator
├── sdks/
│   ├── python/              # pip install connector-agent-oss
│   └── typescript/          # npm install @connector_oss/connector
├── examples/yaml/           # 8 progressive YAML configs
├── docs/                    # 35+ reference documents
├── .github/workflows/       # CI + publish (PyPI, npm, Docker)
├── QUICKSTART.md            # 5-minute guide
├── ARCHITECTURE.md          # Full system architecture
├── CHANGELOG.md
├── Dockerfile               # Scratch image (~8MB, 0 CVEs)
└── docker-compose.yml       # Server + SQLite + Prometheus + Grafana
```

---

## Tests

| Workspace | Tests | Failures |
|-----------|-------|----------|
| connector | 1,194 | 0 |
| vac | 492 | 0 |
| aapi | 171 | 0 |
| **Total** | **1,857** | **0** |

---

## Documentation

**[→ docs/01_INDEX.md](docs/01_INDEX.md)** — 35 documents from crypto foundations to deployment.

| Layer | Documents |
|-------|-----------|
| **Crypto** | CID & DAG-CBOR · Merkle & Prolly · Ed25519 & HMAC |
| **Kernel** | Memory Kernel · MemPacket · Syscalls · Namespaces · Audit · Sessions · Storage · KnotEngine |
| **Policy** | VAKYA Grammar · AAPI Policy · AAPI Pipeline |
| **Engine** | Dispatcher · Cognitive Loop · Knowledge · Trust · Compliance · LLM Router |
| **SDK** | Connector API · YAML Config · Pipeline Output · Python SDK · TypeScript SDK |
| **Ops** | Security Model · Deployment · YAML Dictionary · Code Dictionaries |

Also see: [ARCHITECTURE.md](ARCHITECTURE.md) · [QUICKSTART.md](QUICKSTART.md) · [CHANGELOG.md](CHANGELOG.md)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

📧 [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com)

## License

Apache-2.0 — See [LICENSE](LICENSE)

---

<div align="center">

`pip install connector-agent-oss` &nbsp;·&nbsp; `npm i @connector_oss/connector` &nbsp;·&nbsp; `docker run adminumesh3011/connector-oss`

[GitHub](https://github.com/GlobalSushrut/connector-oss) &nbsp;·&nbsp; [PyPI](https://pypi.org/project/connector-agent-oss/) &nbsp;·&nbsp; [npm](https://www.npmjs.com/package/@connector_oss/connector) &nbsp;·&nbsp; [Docker](https://hub.docker.com/r/adminumesh3011/connector-oss) &nbsp;·&nbsp; [Docs](docs/01_INDEX.md)

Built by **[Umesh Adhikari](mailto:umeshlamton@gmail.com)**

</div>
