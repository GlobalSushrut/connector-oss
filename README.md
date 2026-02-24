<div align="center">

<img src="https://img.shields.io/badge/Connector_OSS-Tamper--Proof_AI_Memory-6C3483?style=for-the-badge" alt="Connector OSS"/>

# Connector OSS

### *The missing trust layer for AI agents.*

> Every memory content-addressed. Every read audited. Every decision provable.
> From a 3-line chatbot to a military-grade multi-agent system — **one install**.

<br/>

[![License](https://img.shields.io/badge/license-Apache%202.0-22c55e?style=flat-square)](LICENSE)
[![PyPI](https://img.shields.io/badge/pip_install-connector__oss-3b82f6?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/connector-oss/)
[![npm](https://img.shields.io/badge/npm_install-connector__oss-ef4444?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/connector-oss)
[![Rust](https://img.shields.io/badge/Rust_kernel-45%2C800+_LOC-f97316?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-503_passed-22c55e?style=flat-square)](https://github.com/GlobalSushrut/connector-oss)
[![GitHub](https://img.shields.io/badge/GitHub-GlobalSushrut-181717?style=flat-square&logo=github)](https://github.com/GlobalSushrut/connector-oss)

<br/>

**Built by [Umesh Adhikari](mailto:umeshlamton@gmail.com)**
*Independent researcher & systems engineer*
📧 [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com) · 🐙 [github.com/GlobalSushrut](https://github.com/GlobalSushrut/connector-oss)

</div>

---

## See It Running

<div align="center">

**Install and Hello World — 60 seconds**

![Connector Hello World Demo](demos/assets/demo.gif)

**Internal Architecture — How the 4-ring kernel works**

![Connector Architecture](demos/assets/arch.gif)

</div>

---

## 🚪 The Niche Door — Why This Exists and Why It Matters Now

> **The AI agent market is exploding. The trust infrastructure doesn't exist yet. Connector OSS is that infrastructure.**

Every major AI framework — LangChain, CrewAI, AutoGen, OpenAI Agents — gives you a way to build agents. None of them answer the question that regulators, enterprise buyers, and auditors are now asking:

**"How do you prove your AI agent didn't silently modify its own memory?"**

This is not a hypothetical. It is the exact question that blocks AI adoption in:

| Industry | The Blocker | What Connector Solves |
|----------|-------------|----------------------|
| 🏥 **Healthcare** | HIPAA requires audit trails for every PHI access. No framework provides one. | Tamper-evident memory + HIPAA compliance report from real evidence |
| 🏦 **Finance** | SOC2 auditors want proof of access controls. Self-reported logs don't count. | HMAC-chained audit trail + SOC2 report generated from kernel data |
| ⚖️ **Legal** | AI-generated documents need chain-of-custody to be admissible. | CIDv1 hash + Ed25519 signature = cryptographic chain of custody |
| 🏛️ **Government** | EU AI Act (Aug 2025, €35M penalties) mandates decision traceability. | Every decision linked to evidence CIDs, exportable for regulators |
| 🎖️ **Defense** | Military AI needs air-gapped, tamper-proof, zero-delegation operation. | DoD preset: local LLM + TOP_SECRET classification + MFA + no delegation |

### 💡 The Business Potential — If This Stabilises

The gap Connector fills is **not a feature gap — it is a market gap**. No open-source project currently provides:

1. **Content-addressed agent memory** (CIDv1 — same content, same hash, always)
2. **Kernel-enforced audit trail** (HMAC-chained — deletion is mathematically detectable)
3. **Evidence-based compliance** (reports from real kernel data, not self-assessment)
4. **Trust score with a CID** (the score itself is verifiable — it has a hash)
5. **One install, all levels** (chatbot → enterprise → military, same package)

**Market context:**
- AI Agent market: **$5.1B (2024) → $47.1B (2030)**, 44.8% CAGR *(Grand View Research)*
- Mem0 (closest comparable): **$24M Series A**, 41K GitHub stars, 186M API calls/quarter — *with no cryptographic trust layer*
- EU AI Act penalties: up to **€35M or 7% of global revenue** — creating immediate enterprise demand for audit infrastructure
- 63% of enterprises cite **observability and governance** as their top AI deployment blocker *(Gartner 2024)*

**If Connector stabilises**, it becomes the `openssl` of AI agent memory — the foundational trust layer that every regulated AI system depends on. The OSS core drives adoption; the enterprise layer (hosted audit service, compliance SaaS, SDK support contracts) drives revenue.

> *This is one person's work so far. Imagine what a team could do.*
> *— Umesh Adhikari, [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com)*

---

## 🤝 Industry Pilots & Collaboration

> **If you are building AI systems in a regulated industry and want a trust layer that actually works — let's talk.**

Connector OSS is production-ready at the kernel level (45,800 lines of Rust, 503 tests, 0 failures). What it needs now is real-world pilots with teams who understand the compliance problem firsthand.

### Who This Is For

| You are... | What we can do together |
|------------|------------------------|
| 🏥 **A healthtech team** shipping AI agents that touch PHI | Pilot HIPAA-compliant memory with a real audit trail — not a checkbox |
| 🏦 **A fintech or trading firm** needing SOC2/GDPR evidence | Integrate Connector as the trust layer under your existing LLM stack |
| ⚖️ **A legaltech company** building AI document workflows | Add cryptographic chain-of-custody to every AI-generated output |
| 🏛️ **A govtech or defense contractor** with compliance mandates | Deploy air-gapped with local LLM + DoD preset + MFA + zero delegation |
| 🔬 **A research lab or AI safety team** | Collaborate on the trust model, contribute to the kernel, co-author work |
| 🏗️ **An infrastructure or platform company** | Embed Connector as the memory/audit layer in your AI platform |

### What a Pilot Looks Like

- **Duration**: 2–4 weeks, your stack, your data, your compliance requirements
- **What you get**: Working integration, compliance report from real kernel evidence, trust score on every agent decision
- **What I need**: Your use case, your compliance framework, and a willingness to give honest feedback
- **Cost**: Free during pilot — this is open source and the goal is real-world validation

### How to Start

The preferred path is a **direct conversation** — no forms, no sales process:

📧 **[umeshlamton@gmail.com](mailto:umeshlamton@gmail.com)**
🐙 **[github.com/GlobalSushrut/connector-oss](https://github.com/GlobalSushrut/connector-oss)** — open an issue tagged `pilot`

Tell me:
1. What industry you're in and what compliance framework you need
2. What your current agent stack looks like (LangChain, CrewAI, custom, etc.)
3. What the specific trust/audit problem is that you haven't been able to solve

I will respond personally. No automated replies.

---

## ⚡ Install in 30 Seconds

### Python

```bash
pip install connector_oss
```

```python
import os
from connector_oss import Connector

c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
result = c.agent("bot", "You are a helpful assistant.").run("Hello!", "user:alice")

print(result.text)         # LLM response
print(result.trust)        # 100  ← kernel-verified trust score
print(result.trust_grade)  # "A+"
print(result.cid)          # "bafyreigima..."  ← tamper-proof hash of this response
print(result.verified)     # True
```

### TypeScript / Node.js

```bash
npm install connector_oss
```

```typescript
import { Connector } from 'connector_oss';

const c = new Connector({ provider: 'deepseek', model: 'deepseek-chat', apiKey: process.env.DEEPSEEK_API_KEY! });
const result = await c.agent('bot', 'You are helpful.').run('Hello!', 'user:alice');

console.log(result.text);        // LLM response
console.log(result.trust);       // 100
console.log(result.trustGrade);  // "A+"
console.log(result.cid);         // tamper-proof CID
```

> **That's it.** No Rust toolchain. No config files. No infrastructure. The pre-built native binary ships inside the package.

---

## 🔍 Why Connector Exists

Every agent framework gives you memory. **None of them give you proof.**

When your AI agent writes a diagnosis, makes a financial decision, or files a legal document — can you prove the memory wasn't silently modified? Can you prove the agent actually saw the data it claims? Can you generate a HIPAA audit trail that holds up in court?

**Connector is the answer.** A 45,800-line Rust kernel wraps every agent operation:

- 🔐 Every memory packet gets a **CIDv1** — a cryptographic hash. Same content → same CID, always. Change one byte → different CID → tamper detected.
- 📋 Every operation is logged in an **HMAC-chained audit trail**. Deletion or reordering is mathematically detectable.
- ✅ Every compliance report (HIPAA, SOC2, GDPR, EU AI Act) is generated from **actual kernel audit evidence** — not self-assessment checkboxes.
- 🎯 Every trust score is **kernel-derived** — computed from real CID integrity checks, not a number you set yourself.

---

## 🎁 What You Get Automatically — Zero Config

| Feature | How | Where to see it |
|---------|-----|-----------------|
| **Tamper-proof memory** | CIDv1 = SHA2-256(DAG-CBOR(content)) | `result.cid` |
| **Trust score 0–100** | Computed from real kernel audit data | `result.trust`, `result.trust_grade` |
| **Full audit trail** | Every syscall logged + HMAC-chained | `c.audit_count()` |
| **Namespace isolation** | Kernel-enforced, no bypass possible | Automatic |
| **Integrity check** | CID re-hash verification | `c.integrity_check()` |
| **Provenance tracking** | Every output tagged with its source | `result.verified` |
| **VAKYA authorization** | Every action has a signed token | Automatic |

---

## 🏗️ Build Anything — One Framework

```
Simple chatbot           →  3 lines of Python
Persistent memory agent  →  add  storage: redb:./data.redb
Multi-agent pipeline     →  add  .route("triage -> doctor -> pharmacist")
HIPAA-compliant system   →  add  comply: [hipaa]  +  data_classification: PHI
SOC2 + GDPR finance      →  add  comply: [soc2, gdpr]  +  jurisdiction: EU
Military-grade secure    →  add  comply: [dod]  +  signing: true  +  require_mfa: true
```

All from the same `pip install connector_oss`. No new framework to learn at each level — just add YAML keys.

---

## 🚀 5-Minute Examples

### 🏥 Healthcare — HIPAA ER Triage

```python
import os
from connector_oss import Connector

c = Connector.from_config("hospital.yaml")
# hospital.yaml: comply=[hipaa], signing=true, data_classification=PHI

triage = c.agent("triage", "Classify patients by urgency 1-5.")
doctor = c.agent("doctor", "Diagnose based on triage data.")

t = triage.run("45M, chest pain 2h, BP 158/95, diaphoresis", "patient:P-001")
d = doctor.run(f"Patient: {t.text}", "patient:P-001")

print(f"Diagnosis: {d.text}")
print(f"Trust:     {d.trust}/100 ({d.trust_grade})")   # A+
print(f"Audit:     {c.audit_count()} entries")
ok, _ = c.integrity_check()
print(f"Integrity: {'PASS ✅' if ok else 'FAIL ❌'}")
```

### 🏦 Finance — Fraud Detection with SOC2

```python
c = Connector.from_config("finance.yaml")
# finance.yaml: comply=[soc2, gdpr], pii_types=[credit_card, ssn]

analyzer = c.agent("fraud_analyzer",
    "Analyze transactions. Output: risk_score (0-100), recommendation (approve/review/block).")

result = analyzer.run(
    "Transaction: $4,200 at 3:47 AM, Lagos Nigeria. Cardholder in New York.",
    "user:card-8821"
)
print(result.text)           # {"risk_score": 94, "recommendation": "block"}
print(f"CID: {result.cid}")  # immutable audit evidence
```

### 🔬 Multi-Agent Pipeline — Research → Analyze → Write

```python
c = Connector.from_config("research.yaml")

r = c.agent("researcher", "Research the topic thoroughly.").run("Impact of LLMs on software", "user:alice")
a = c.agent("analyst",    "Analyze findings.").run(r.text, "user:alice")
w = c.agent("writer",     "Write a clear summary.").run(a.text, "user:alice")

print(w.text)
print(f"Trust: {w.trust}/100 — {w.trust_grade}")
```

---

## 📄 YAML Config — Plain English

The entire system is configured in one YAML file. No code changes to go from dev to HIPAA-compliant production:

```yaml
# connector.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}   # env-var interpolated — never hardcode
  storage: redb:./data.redb      # persistent (omit = in-memory)
  comply: [hipaa, soc2]          # compliance frameworks to enforce

  security:
    signing: true                # Ed25519-sign every memory packet
    data_classification: PHI     # activates HIPAA PII detection
    jurisdiction: US
    retention_days: 2555         # 7 years — HIPAA requirement

  firewall:
    preset: hipaa                # blocks injection, PHI leakage, anomalies

agents:
  triage:
    instructions: "Classify patients by urgency 1-5."
    role: writer
  doctor:
    instructions: "Diagnose based on triage data."
    memory_from: [triage]        # doctor reads triage's memory
    require_approval: [prescribe_medication]   # human-in-the-loop
```

→ [Full YAML Dictionary](docs/31_YAML_DICTIONARY.md) — every key explained in plain English.

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  pip install connector_oss  /  npm install connector_oss                    │
│  Python (vac-ffi / PyO3)          TypeScript (REST → connector-server)      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 4 — connector-api  (developer surface)                                │
│  Connector · AgentBuilder · PipelineBuilder · YAML config loader            │
│  PipelineOutputExt: trust() · comply() · replay() · xray() · audit()       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 3 — connector-engine  (orchestration)                                 │
│  DualDispatcher · BindingEngine · TrustComputer · ComplianceVerifier        │
│  AgentFirewall · BehaviorAnalyzer · LlmRouter · KernelOps                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 1 — VAC Memory Kernel     │  Ring 2 — AAPI Action Kernel              │
│  MemoryKernel · 29 syscalls     │  VAKYA grammar (8 slots, 15 verbs)        │
│  MemPacket (3-plane model)      │  Ed25519 signing · capability tokens      │
│  KernelAuditEntry (HMAC-chain)  │  PolicyRule · BudgetTracker               │
│  KnotEngine · Prolly tree       │  SagaCoordinator · FederatedPolicy        │
├─────────────────────────────────────────────────────────────────────────────┤
│  Ring 0 — Cryptographic Foundation                                           │
│  CIDv1 (DAG-CBOR + SHA2-256) · Ed25519 · HMAC-SHA256 · Prolly Merkle tree  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**45,800+ lines of Rust · 503 tests · 0 failures**

---

## 🛡️ Compliance Built In

Compliance reports are generated from **actual kernel audit evidence** — not self-assessment:

| Framework | What it checks | One line |
|-----------|---------------|----------|
| **HIPAA** | PHI access controls, audit trail, integrity, encryption | `result.comply("hipaa")` |
| **SOC2** | Availability, access controls, change management | `result.comply("soc2")` |
| **GDPR** | Right to erasure, data minimization, retention | `result.comply("gdpr")` |
| **EU AI Act** | Human oversight, risk management, transparency | `result.comply("eu_ai_act")` |
| **NIST AI RMF** | GOVERN/MAP/MEASURE/MANAGE | `result.comply("nist_ai_rmf")` |
| **OWASP LLM Top 10** | Injection, PII, excessive agency, overreliance | `result.comply("owasp_llm")` |
| **DoD / Military** | TOP_SECRET classification, MFA, no delegation | `comply: [dod]` in YAML |

---

## 📊 Trust Score — Verifiable, Not Self-Reported

The trust score (0–100) is computed from real kernel data — not configuration flags:

| Dimension | Max | What it measures |
|-----------|-----|------------------|
| Memory Integrity | 20 | % of packets with valid CIDs (tamper detection) |
| Audit Completeness | 20 | HMAC chain intact + all ops succeeded |
| Authorization Coverage | 20 | % of writes with VAKYA token |
| Decision Provenance | 20 | % of decisions with evidence CIDs |
| Operational Health | 20 | No denied/failed ops, sessions properly closed |

```python
result = agent.run("Diagnose patient", "patient:P-001")
print(result.trust)        # 87
print(result.trust_grade)  # "A"
# The score itself has a CID — you can verify it wasn't fabricated
```

---

## 🔧 Install from Source (Development)

```bash
git clone https://github.com/GlobalSushrut/connector-oss.git
cd connector-oss

# Build the Rust FFI bridge
cd vac/crates/vac-ffi && maturin develop --release && cd ../../..

# Install Python SDK (editable)
cd sdks/python && pip install -e . && cd ../..

# Build connector-server (for TypeScript)
cd connector && cargo build --release -p connector-server && cd ..

# Build TypeScript SDK
cd sdks/typescript && npm install && npm run build && cd ../..
```

### Run the Demos

```bash
export DEEPSEEK_API_KEY=sk-...

# Python demos
python demos/python/01_hello_world.py
python demos/python/02_hospital_er.py

# TypeScript demos (connector-server must be running)
npx ts-node demos/typescript/01_hello_world.ts
```

---

## 📦 Publishing to PyPI and npm

### PyPI (`pip install connector_oss`)

```bash
# 1. Build wheels for all platforms (maturin handles cross-compilation)
cd vac/crates/vac-ffi
maturin build --release --strip
# → target/wheels/connector_oss-*.whl

# 2. Build sdks/python source distribution
cd ../../..
cd sdks/python
python -m build

# 3. Upload to PyPI
pip install twine
twine upload dist/*
# → pip install connector_oss now works globally
```

**`pyproject.toml`** (in `sdks/python/`):
```toml
[project]
name = "connector_oss"
version = "0.1.0"
description = "Tamper-proof memory and chain-of-custody for AI agents"
requires-python = ">=3.10"
dependencies = []

[project.urls]
Homepage = "https://github.com/GlobalSushrut/connector-oss"
Documentation = "https://github.com/GlobalSushrut/connector-oss/blob/main/docs/01_INDEX.md"
```

### npm (`npm install connector_oss`)

```bash
# 1. Build TypeScript SDK
cd sdks/typescript
npm install && npm run build

# 2. Publish to npm
npm login
npm publish --access public
# → npm install connector_oss now works globally
```

**`package.json`** (in `sdks/typescript/`):
```json
{
  "name": "connector_oss",
  "version": "0.1.0",
  "description": "Tamper-proof memory and chain-of-custody for AI agents",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "repository": "https://github.com/GlobalSushrut/connector-oss"
}
```

> **Note:** The TypeScript SDK calls `connector-server` (the Rust HTTP server) via REST. For production npm packages, bundle a pre-built `connector-server` binary for each platform using `pkg` or `@vercel/ncc`, or document that users run the server separately.

---

## 🗂️ Repository Structure

```
connector-oss/
├── vac/crates/
│   ├── vac-core/        # MemoryKernel, MemPacket, CID, audit, sessions
│   ├── vac-store/       # Storage backends (InMemory, Prolly, IndexDB)
│   ├── vac-ffi/         # PyO3 bridge → Python native extension
│   ├── vac-prolly/      # Prolly tree with Merkle proofs
│   └── vac-crypto/      # Ed25519, SHA-256
│
├── aapi/crates/
│   ├── aapi-core/       # VAKYA grammar, 8 slots, 15 verbs
│   ├── aapi-metarules/  # Policy engine (Allow/Deny/RequireApproval)
│   └── aapi-pipeline/   # Saga coordinator, distributed transactions
│
├── connector/crates/
│   ├── connector-api/   # Connector, AgentBuilder, PipelineBuilder
│   ├── connector-engine/# DualDispatcher, TrustComputer, ComplianceVerifier
│   └── connector-server/# axum HTTP server (port 8080) for TypeScript SDK
│
├── sdks/
│   ├── python/          # pip install connector_oss
│   └── typescript/      # npm install connector_oss
│
├── demos/
│   ├── python/          # 5 Python demo scripts
│   ├── typescript/      # 2 TypeScript demo scripts
│   └── assets/          # demo.gif, arch.gif
│
├── docs/                # 35 documentation files
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

---

## ✅ Test Status

| Workspace | Tests | Failures |
|-----------|-------|----------|
| VAC (Rust) | 353 | 0 |
| AAPI (Rust) | 150 | 0 |
| **Total** | **503** | **0** |

```bash
cd vac && cargo test --workspace && cd ..
cd aapi && cargo test --workspace && cd ..
cd connector && cargo test --workspace && cd ..
```

---

## 📚 Documentation

35 documents covering every layer of the system — from cryptographic foundations to military-grade deployment. Start with the index:

**[→ docs/01_INDEX.md](docs/01_INDEX.md)**

| Group | Documents |
|-------|-----------|
| **System Overview** | [02 System Overview](docs/02_SYSTEM_OVERVIEW.md) |
| **Ring 0 — Crypto** | [03 CID & DAG-CBOR](docs/03_CID_AND_DAG_CBOR.md) · [04 Merkle & Prolly](docs/04_MERKLE_AND_PROLLY.md) · [05 Ed25519 & HMAC](docs/05_ED25519_AND_HMAC.md) |
| **Ring 1 — VAC Kernel** | [06 Memory Kernel](docs/06_MEMORY_KERNEL.md) · [07 MemPacket](docs/07_MEMPACKET.md) · [08 Syscalls](docs/08_SYSCALLS.md) · [09 Namespace Isolation](docs/09_NAMESPACE_ISOLATION.md) · [10 Audit Chain](docs/10_AUDIT_CHAIN.md) · [11 Sessions](docs/11_SESSIONS_AND_CONTEXTS.md) · [12 Storage Backends](docs/12_STORAGE_BACKENDS.md) · [13 Knot Engine](docs/13_KNOT_ENGINE.md) · [14 Interference Engine](docs/14_INTERFERENCE_ENGINE.md) |
| **Ring 2 — AAPI** | [15 VAKYA Grammar](docs/15_VAKYA_GRAMMAR.md) · [16 AAPI Policy](docs/16_AAPI_POLICY.md) · [17 AAPI Pipeline](docs/17_AAPI_PIPELINE.md) |
| **Ring 3 — Engine** | [18 Dual Dispatcher](docs/18_DUAL_DISPATCHER.md) · [19 Cognitive Loop](docs/19_COGNITIVE_LOOP.md) · [20 Knowledge Engine](docs/20_KNOWLEDGE_ENGINE.md) · [21 Trust Computer](docs/21_TRUST_COMPUTER.md) · [22 Compliance Engine](docs/22_COMPLIANCE_ENGINE.md) · [23 LLM Router](docs/23_LLM_ROUTER.md) |
| **Ring 4 — API & SDK** | [24 Connector API](docs/24_CONNECTOR_API.md) · [25 YAML Config](docs/25_YAML_CONFIG.md) · [26 Pipeline Output](docs/26_PIPELINE_OUTPUT.md) · [27 Python SDK](docs/27_PYTHON_SDK.md) · [28 TypeScript SDK](docs/28_TYPESCRIPT_SDK.md) |
| **Operations** | [29 Security Model](docs/29_SECURITY_MODEL.md) · [30 Deployment](docs/30_DEPLOYMENT.md) |
| **Dictionaries & Quickstart** | [31 YAML Dictionary](docs/31_YAML_DICTIONARY.md) · [32 Python Code Dictionary](docs/32_CODE_DICTIONARY_PYTHON.md) · [33 Rust Code Dictionary](docs/33_CODE_DICTIONARY_RUST.md) · [34 TypeScript Code Dictionary](docs/34_CODE_DICTIONARY_TYPESCRIPT.md) · [35 Quickstart](docs/35_QUICKSTART.md) |

---

## 🤝 Contributing

Contributions, issues, and ideas are very welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Want to collaborate or discuss the project?**
Reach out directly: [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com)

## 📜 License

Apache License 2.0 — See [LICENSE](LICENSE)

Free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

---

### Connector OSS

*The missing trust layer for AI agents.*

`pip install connector_oss` &nbsp;·&nbsp; `npm install connector_oss`

[GitHub](https://github.com/GlobalSushrut/connector-oss) &nbsp;·&nbsp; [PyPI](https://pypi.org/project/connector-oss/) &nbsp;·&nbsp; [npm](https://www.npmjs.com/package/connector-oss) &nbsp;·&nbsp; [Docs](docs/01_INDEX.md)

<br/>

Built with ❤️ by **Umesh Adhikari**

📧 [umeshlamton@gmail.com](mailto:umeshlamton@gmail.com) &nbsp;·&nbsp; 🐙 [github.com/GlobalSushrut](https://github.com/GlobalSushrut/connector-oss)

*Apache 2.0 — Free to use, fork, and build upon.*

</div>
