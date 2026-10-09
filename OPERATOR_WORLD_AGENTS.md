# Operator guide — any agent → world (CNP) + custom .cpkg + audit

**Architecture:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0 (kernel → ACS / layers / world / share).  
**Now possible:** [AGENTIC_INFRA_NOW_POSSIBLE.md](AGENTIC_INFRA_NOW_POSSIBLE.md).  
**One sentence:** You can build **any kind of agent**, connect it to **APIs, networks, robots, IoT, and services** through Connector’s **secure CNP/CONP stack**, ship **your own logic as `.cpkg`**, and keep **governed actions audited**.

---

## What you get

| Need | What Connector does |
|------|---------------------|
| Any agent kind | Register → charter → activate. Purpose + capabilities = the cage. |
| Connect to the world | **CNP** = secure spine. **CONP (CP/1.0)** = 30 message types + **120** capabilities for machines/robots/devices/APIs. |
| 20+ world types | Entity classes (agent/machine/device/service/sensor/actuator/composite) **plus** HTTP APIs, MCP, A2A, MQTT/Modbus caps, mesh cells, IoT, partner robot HALs, `.cpkg` plugins, knowledge plane — see `GET /api/v1/protocol/world`. |
| Identity in the world | EntityId + proofs: **DICE / SPIFFE / self-signed** (+ Connector principal). |
| Your own agent logic | Package as **`.cpkg`**, install via Hub, run in DockLock cage; call memory, tools, Talk, cluster, security APIs **as that agent**. |
| Audit | Talk, tools, CONP commands, fabric, share/signal leave **DecisionTraces** + activity + forensic package. |
| 3 admission layers | **Root HITL** · **Cone** (AI suggests, you approve — default) · **App** (automation only if you, human+root, justify that pid × address × cap). |
| Isolation | Each agent has its own **ACS + NS FS + memory**. A cannot see B. Share needs a **contract** (what/where/how much/why) then a **portal**. |
| Density | **light_ns** — Docker-grade Linux materials, shared kernel, max agents. MicroVM is high-risk only. |

---

## How people use it

1. **Create an agent** and set its charter (what it may touch).  
2. **Link an LLM** and **Start** from Control.  
3. **Talk** or run **tools**; risky work can pause for human Approve.  
4. **Reach machines / APIs / IoT** — each target is an **address** (type + address + params + CNP). **Agent A at P** is a different grant from **A at Q** and from **B at P**. Owner fills the **gateway form** + **kernel root passcode** (Setup or Charter → Power · world). Pick layer: Cone (Ask) or App Allow (justify). Once an agent has any grant, CONP `entity_id` must match.  
5. **Share between agents** only via Manage → sharing contract (human+root). No contract → no portal → isolated.  
6. **Optional:** write a `.cpkg` that uses Connector memory/knowledge/tools; install and run under the agent’s cage.  
7. **Need proof?** Download the forensic package / check traces.

---

## Honest limits (keep these)

- **CONP taxonomy ≠ SIL-certified robot safety.** Partner HALs speak CONP; certified e-stop loops stay partner-side.  
- **Court-green** only with live WC+CFNI soak. **light_ns ≠ MicroVM.** Host Active ≠ eBPF unless applied.  
- **Cross-cell mTLS** is productizing; posture tells you lab stub vs fail-closed.  
- **“100% audited”** means: **every charter-gated effect** that crosses the membrane is traced. Code that bypasses platform APIs is blocked under harden (no ambient shell / unrestricted net).

---

## Quick APIs

```text
GET  /api/v1/protocol/world              ← full operator map
GET  /api/v1/protocol/conp/info          ← 30 types + entity classes
GET  /api/v1/protocol/conp/capabilities  ← 120 caps (filter by category)
POST /api/v1/protocol/conp/command       ← gated machine command
GET  /api/v1/intelligence/gateway/status ← types + layers + root set?
POST /api/v1/intelligence/gateway/grant  ← this agent × this address (root pass)
POST /api/v1/intelligence/share-contract ← human+root → shared portal
GET  /api/v1/runtime/acs/:pid            ← character + isolation + NS FS
GET  /api/v1/cnp/overview                ← CNP spine
GET  /api/v1/runtime/intelligence-posture
```

Hub / plugins: `connectorctl hub install …` · `connectorctl plugin run --dev vendor/slug`
