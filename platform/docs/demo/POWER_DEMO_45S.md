# Connector power demo — 45 seconds · 5 slides

**Open deck:** open [`power-demo-45s.html`](./power-demo-45s.html) in a browser (auto-advances ~45s).  
**Live product:** https://try.cnktros.com · full surface [CONNECTOR_PLAYGROUND_REACHED.md](./CONNECTOR_PLAYGROUND_REACHED.md)

| Slide | Sec | Beat | Spoken line (≈) |
|------:|----:|------|-----------------|
| 1 | 8 | **Whoami** | “Connector is the OS for agent *effects*. Models propose. We admit.” |
| 2 | 8 | **Capabilities** | “Who it is, which tools, which world grants, stub or linked LLM — before any effect.” |
| 3 | 9 | **Tool exec** | “Cayman wire: Score → Admit → PATE → ToolDispatch. Ledger moves only after Admit.” |
| 4 | 10 | **Control** | “SpendCease. Generation fenced. Continue refuses. Expometer shows CEASED.” |
| 5 | 10 | **Report** | “Action Trail — Orders, Evidence, Standing. Reconstructible. Honest: playground ≠ FedWire.” |

**Total:** 45s · Space pause · ←/→ step.

---

## Live click path (same story, ~50s on try.cnktros.com)

1. **Whoami (8s)** — Workbench → BankOps → “Who are you?” / Expometer `active`.  
2. **Capabilities (8s)** — Expometer world + LLM mode; chips Score/Hold/Decide/Ledger.  
3. **Tool exec (12s)** — Score wire → **Admit** → receipt; optional Hold.  
4. **Control (12s)** — **Cease** → continue → refuse popup / `REFUSED_GENERATION_FENCED`.  
5. **Report (10s)** — **Open Evidence trail →** → `/run/trail/…?focus=evidence`.

---

## Slide copy (for recording / Figma)

### 01 · Whoami
**Title:** Connector is the OS for agent effects.  
**Sub:** Not a chatbot. Intelligence proposes. Connector admits. World changes only after PATE → ToolDispatch.

### 02 · Capabilities
**Title:** What this agent may do.  
Cards: Who (BankOps) · Tools (score/hold/decide/ledger) · World (Expometer grants) · LLM (stub or linked).

### 03 · Tool execution
**Title:** Propose → Admit → receipt.  
Flow: `order` → pending → Admit → PATE · ToolDispatch → ledger mutates.

### 04 · Control
**Title:** SpendCease. Admit dies.  
Expometer: `CEASED` · `admit · REFUSED_GENERATION_FENCED` · continue → refuse + reason.

### 05 · Report
**Title:** Action Trail proves the loop.  
Orders · Evidence · Trail live · Honesty: playground_demo, not court / not FedWire.

---

## What this demo proves (software power)

| Claim | Mechanism shown |
|-------|-----------------|
| Capability ≠ authority | Tools proposed; Admit required |
| Operator visibility | Expometer + Action Trail |
| Hard stop | SpendCease fences generation |
| Reconstructibility | Evidence trail / receipts |
| Honesty | Explicit playground bounds |
