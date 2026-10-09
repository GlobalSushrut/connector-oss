# Create an intelligence in ~5 minutes (OS-level security)

**Architecture (kernel → ACS):** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0.  
**What this unlocks:** [AGENTIC_INFRA_NOW_POSSIBLE.md](AGENTIC_INFRA_NOW_POSSIBLE.md).  
**Enhance what we already have** — not a new spine.  
Uses: `register` → `setup` → `contract` → knowledge ingest → `activate` + DockLock / AutonomyGateway.

---

## Flow (like k8s, for intelligence)

```text
parameters → skills → knowledge → limitations → portals → rules
     └─────────── POST /api/v1/intelligence/apply ───────────┘
```

| Step | What you give | What it is |
|------|----------------|------------|
| **Parameters** | name, purpose, class (`app` / `robotics` / `iot` / `cybernetic` / `service`), model, namespace | Like k8s metadata + basic spec |
| **Skills** | Typed capabilities (`conp` / `tool` / `mcp`…) | **Bounded** — not markdown files |
| **Knowledge** | 1 line **or** long docs | Primary `/k` dataset for the agent |
| **Limitations** | caps, deny list, network, HITL, forensic | Charter / cage boundaries |
| **Portals** | machines, APIs, IoT, cluster | Real-world access potential |
| **Rules** | ask / block / note | Extra boundaries |

`harden: true` (default) → HITL≥tool, forensic≥standard, `network_default=deny`, no `ambient_shell` — **military-grade membrane ready** when you activate.

---

## Operator UI

**Easy path (Setup):** connect LLM (paste key) → **Create an agent** (name + type) → Talk.

Optional: world/edge, TraceTramp, compliance PDF, or the full `/agents/create` wizard.

## Per-agent security (not shared)

Each `agent_pid` has its own stack. Another agent cannot inherit this pack.

| Layer | What it is | Where |
|-------|------------|--------|
| **Charter cage** | Capabilities, deny list, network default, HITL, forensic | Charter → cage |
| **Bound skills** | Typed tools/CONP this pid may invoke (empty = charter-only) | Charter → Power · world |
| **Portals** | CNP/CONP outer-world targets (machine, http_api, mcp…) | same |
| **Rules** | Extra ask/block/note for this pid | same |
| **AAPI** | UCAN cap issued to this subject + optional require_approval policy | same |
| **ACS** | Agentic Character Surface: who this pid is + isolation + NS FS + grants | Agent workbench (top) |
| **Isolation (`light_ns`)** | Docker-grade Linux materials, **shared kernel** (max agents). Not a VM. | `GET /runtime/isolation/:pid` |
| **NS FS** | Per-pid trees: `/workspace` `/m` `/k` `/p` `/v` `/out` `/share` | `{DATA}/nsfs/{pid}/` |
| **World grant** | **This pid × this CNP address** (type + params + caps). A→P ≠ A→Q ≠ B→P | Setup / Power · world gateway |
| **Kernel root** | Owner sudo to authorize grants — **node-wide**, not an agent secret | `{DATA}/keys/kernel_root.pass` |
| **Node env** | Lab vs harden is **node-wide**, not per agent | shell banner |

Membrane: AutonomyGateway Allow/Ask/Block on Talk, tools, CONP. E-stop is ambient Allow.

## Isolation density (`light_ns`)

Complex security **without** a Docker daemon or Firecracker per agent — so the node can run **max agents**.

| | Docker daemon / MicroVM | **light_ns (default)** |
|--|-------------------------|------------------------|
| Security materials | namespaces, cgroups, seccomp, FS | **same** (Landlock + NS FS + seccomp + cgroup v2 + DockLock + matrix) |
| Compute | guest kernel or docker dind | **shared host kernel** |
| When | lab convenience / high-risk untrusted `.cpkg` | **every intelligence** |

ACS (`GET /runtime/acs/:pid`) is the top-level document: character + isolation + NS FS + world grants.

## World gateway — one grant per (agent × address)

The outer world is not “this agent can use CONP.” It is a **matrix**.

Every external target is an **address**:

| Field | Meaning |
|-------|---------|
| **type** | One of ~20: `http_api`, `machine` (robot/CNC), `device`, `mqtt`, `mcp_tool`, `agent`, … |
| **address** | The thing being accessed: URL, `machine:arm-1`, MQTT topic, other pid, … |
| **params** | Owner root parameters for that address (`max_speed`, auth, namespace, …) |
| **CNP access** | Which capabilities this grant may speak at that address (`machine.move_axis`, `*` , …) |

**Agent A → address P** is a different setup from **A → Q** and from **B → P**. Same agent, new address → fill the form again. Same address, new agent → fill the form again.

Owner (you) fills the **gateway form** and authorizes with a **kernel root passcode** (Linux sudo analogue — node-wide, not the agent). Stored as a salted hash under `{CONNECTOR_DATA_DIR}/keys/kernel_root.pass` (or `CONNECTOR_KERNEL_ROOT_PASS`).

```text
                    address P          address Q          address R
agent A             form + root        form + root        —
agent B             form + root        —                  form + root
```

Once an agent has **any** grant, every CONP `entity_id` must match a grant (`world_grant_denied` otherwise). Under harden, no grants still means **Cone Ask** for CONP (not silent Allow).

## Three layers (no bypass)

Human is root. AI never skips admission.

| Layer | Who executes | AI role | When this (agent × address × cap) runs |
|-------|----------------|---------|----------------------------------------|
| **1 Root HITL** | Human | May draft only | Only after digest-bound HITL approve + consume |
| **2 Cone (augmented)** | Human + AI | **Suggests** | Same — Ask until you approve. **Default.** |
| **3 App** | Automation | May act | Only caps you **justified** on this grant (kernel root). Charter Block still Block. |

Fold (supreme): **Block > Cone/Root Ask > App Allow**. App Allow **cannot** turn Ask or Block into Allow.

On one grant for agent A at address P: list **App Allow** caps (no HITL) and **Cone Ask** caps (always HITL). Unlisted access stays Cone. Missing justification → Cone, never silent App.

**App Allow is human+root only.** An agent cannot grant itself skip-HITL. Kernel root passcode is entered by a human operator.

## Isolation + sharing contracts

Each intelligence owns its own **NS FS**, **ACS**, and storage (`/m` memory, `/k` knowledge, `/p` private, `/share` empty). **Agent A cannot see Agent B** (and vice versa).

To share: a **human** files a contract — **what**, **where**, **how much**, **why** — with kernel root. Only then is a **shared portal** minted (`/share/{portal_id}`). No contract → no portal → isolated.

UI: Agent → Manage → Sharing contract.  
API: `POST /intelligence/share-contract`, `GET /intelligence/share-portals?agent_pid=`

UI: Setup → World gateway (layer + justification). Ask without approve → `hitl_required`; agent cannot perform the action.

## One-shot apply

```bash
# See template
curl -s "$CONNECTOR_API_URL/api/v1/intelligence/spec-schema" | jq .

# Apply
connectorctl iia apply --file examples/intelligence-robotics.json
# or: POST /api/v1/intelligence/apply
```

## Or enhance existing setup (same core)

```http
POST /api/v1/agents/:pid/setup
{
  "acume": "pick and place",
  "hitl_policy": "tool",
  "forensic_profile": "standard",
  "skills": [{ "id": "grasp", "kind": "conp", "capability": "actuator.gripper", "risk": "high", "requires_hitl": true }],
  "knowledge": [{ "title": "ops", "content": "Never exceed 2m/s." }],
  "portals": [{ "id": "arm", "type": "machine", "entity_id": "machine:arm-1" }],
  "rules": [{ "id": "bay", "effect": "ask", "text": "Bay doors need HITL" }],
  "setup_complete": true
}
```

Then `PATCH` contract + `POST …/activate` as today.

---

## .cpkg (optional after 5 min)

Ship **custom runtime logic** later as `.cpkg`. It calls Connector memory/tools/Talk **as that agent** — still audited. Not required to create the intelligence.

---

## APIs

| Route | Job |
|-------|-----|
| `GET /intelligence/spec-schema` | Template |
| `POST /intelligence/apply` | 5-minute create |
| `GET /intelligence/:pid/pack` | skills + portals + rules |
| `GET /runtime/acs/:pid` | **ACS** — character + isolation + NS FS + grants |
| `GET /runtime/nsfs/:pid` | Namespace filesystem snapshot |
| `POST /runtime/nsfs/:pid/ensure` | Create light NS FS tree |
| `GET /runtime/isolation/:pid` | Isolation tier + `light_ns` density |
| `GET /intelligence/gateway/status` | Types catalog + whether kernel root is set |
| `POST /intelligence/gateway/root` | Init / rotate kernel root (admin, rank≥5) |
| `POST /intelligence/gateway/address` | Register world address (root pass) |
| `POST /intelligence/gateway/grant` | Grant **this agent × this address** (developer+, root pass) |
| `POST /intelligence/share-contract` | Human+root sharing contract → portal |
| `GET /intelligence/share-portals?agent_pid=` | Portals this pid may use |
| `GET /agents/:pid/skills` | learned cache **+** `bound_skills` |
| `POST /agents/:pid/setup` | **Enhanced** — accepts skills/knowledge/portals/rules |

---

## Honesty

- Skills are **typed bounds**, not prompt MD packs.  
- If `bound_skills` are set, tools/CONP must match them (plus charter).  
- World access is **(agent × address)** grants, not a shared allow-list. Kernel root is owner sudo, not an agent secret.  
- Three layers: Root HITL · Cone (AI suggests, human approves) · App (justified automation, **human+root only**). **No bypass** of `admit_*`. App cannot downgrade Ask/Block.  
- Agents are **isolated by default** (own NS FS / ACS / memory). Share only via a human+root **sharing contract** that mints a portal.  
- Isolation default is **light_ns** (docker-grade materials, shared kernel). MicroVM is high-risk only.  
- “5 minutes” = declare + apply; security is the **existing** DockLock / gateway / traces path.
