# VAKYA Grammar

> 8 slots, 15 verbs, VAKYA structure, CID-linked tokens
> Source: `aapi/crates/aapi-core/`, `connector/crates/connector-engine/src/aapi.rs`

---

## What is VAKYA?

VAKYA (Sanskrit: "sentence") is the authorization grammar for every agent action. No action executes without a VAKYA token — a signed, CID-linked, 8-slot authorization record. `AutoVakya` in `connector-engine` builds tokens automatically for every pipeline operation.

---

## 8 Slots

| Slot | Sanskrit Name | Role | Example |
|------|--------------|------|---------|
| V1 | **Karta** | Agent identity — who acts | `pid:000001` |
| V2 | **Karma** | Target resource — what is acted upon | `ns:triage`, `ehr:patient-001` |
| V3 | **Kriya** | Action verb — what is done | `memory.write`, `tool.call` |
| V4 | **Karana** | Instrument/tool used | `deepseek-chat`, `read_ehr` |
| V5 | **Sampradana** | Recipient — who benefits | `user:alice`, `ns:diagnosis` |
| V6 | **Apadana** | Source/origin — where data comes from | `ns:triage`, `web:pubmed` |
| V7 | **Adhikarana** | Context + execution constraints | `{ pipeline: "er", jurisdiction: "US" }` |
| V8 | **Pratyaya** | Expected effect + postconditions | `{ effect: "memory_written", verify: true }` |

---

## 15 Verbs (Kriya)

**Memory verbs**:
- `memory.write` — write a packet to kernel
- `memory.read` — read a packet from kernel
- `memory.seal` — make packets immutable
- `memory.evict` — remove packets from active memory
- `memory.share` — grant cross-namespace read access

**Knowledge verbs**:
- `knowledge.query` — retrieve from knowledge graph
- `knowledge.ingest` — add observation to knowledge base
- `knowledge.seed` — initialize knowledge from external source

**Tool verbs**:
- `tool.call` — invoke a registered tool
- `tool.register` — register a new tool

**Chat verbs**:
- `chat.send` — send message to LLM
- `chat.receive` — receive LLM response

**Action verbs**:
- `action.execute` — execute an authorized action
- `action.approve` — human approval of a pending action
- `action.rollback` — undo a previously executed action

---

## VAKYA Token Structure

```rust
// aapi-core
pub struct Vakya {
    pub vakya_id:    String,          // "vk_8f7a2d..." (UUID)
    pub karta:       String,          // V1: agent PID
    pub karma:       String,          // V2: target resource
    pub kriya:       String,          // V3: verb
    pub karana:      Option<String>,  // V4: instrument
    pub sampradana:  Option<String>,  // V5: recipient
    pub apadana:     Option<String>,  // V6: source
    pub adhikarana:  VakyaContext,    // V7: context + constraints
    pub pratyaya:    VakyaEffect,     // V8: expected effect
    pub issued_at:   i64,
    pub expires_at:  Option<i64>,
    pub signature:   Vec<u8>,         // Ed25519 signature
    pub cid:         Cid,             // CID of this token
}

pub struct VakyaContext {
    pub pipeline_id:   String,
    pub jurisdiction:  Option<String>,
    pub constraints:   BTreeMap<String, serde_json::Value>,
}

pub struct VakyaEffect {
    pub effect_type:    EffectType,
    pub postconditions: Vec<Postcondition>,
    pub verify:         bool,
}
```

---

## EffectType

```rust
pub enum EffectType {
    MemoryWritten,
    MemoryRead,
    MemorySealed,
    ToolCalled,
    ActionExecuted,
    PolicyDecision,
    AuditLogged,
    NoEffect,
}
```

---

## IssuedCapability

When AAPI authorizes an action, it issues a capability token:

```rust
// connector-engine/src/aapi.rs
pub struct IssuedCapability {
    pub token_id:    String,
    pub agent_pid:   String,
    pub action:      String,
    pub resource:    String,
    pub issued_at:   i64,
    pub expires_at:  Option<i64>,
    pub constraints: BTreeMap<String, serde_json::Value>,
}
```

---

## AutoVakya

`connector-engine` builds VAKYA tokens automatically — developers never construct them manually:

```rust
// connector-engine/src/aapi.rs — AutoVakya
pub fn build(
    agent_pid:   &str,
    operation:   &str,
    pipeline_id: &str,
) -> Vakya
// Fills all 8 slots from context, signs with kernel keypair
// Returns Vakya with vakya_id and cid
```

The `vakya_id` is stored in:
- `SyscallRequest.vakya_id` — passed to every kernel syscall
- `MemPacket.authority.vakya_id` — stored in every packet
- `KernelAuditEntry.vakya_id` — logged in every audit entry

This creates a complete authorization chain: every packet can be traced back to the VAKYA that authorized it.

---

## VAKYA Validation

```rust
// aapi-core
pub fn validate_vakya(vakya: &Vakya, public_key: &[u8]) -> Result<(), VakyaError>
// Checks:
//   1. Signature valid (Ed25519)
//   2. Not expired (expires_at > now)
//   3. All mandatory slots present (V1, V2, V3)
//   4. Kriya is a known verb
//   5. CID matches content
```

---

## Cross-Reference with VAC Kernel

```
MemPacket.authority.vakya_id  ←→  ActionRecord.vakya_id
AgentControlBlock.pid         ←→  Vakya.karta (V1)
ToolBinding                   ←→  Vakya.karana (V4) + Vakya.kriya (V3)
DelegationChain (VAC)         ←→  DelegationHop (AAPI)
KernelAuditEntry.vakya_id     ←→  Vakya.vakya_id
```
