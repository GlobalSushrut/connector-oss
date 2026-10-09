# Admission matrix — external effects → gates

> **Not N4:** This document is the **Effect Admission Inventory** (HTTP route → `admission_gate` map, Gate-2 *paths*). **N4 Intelligence Admission** (model handshake → CPO) lives in `intelligence_admission/` — see [intelligence-identity-architecture-v2.md](./intelligence-identity-architecture-v2.md) and [IIA_CORE_UPGRADE_CHECKLIST.md](../../IIA_CORE_UPGRADE_CHECKLIST.md).

Operator honesty surface for **P2.1**: every mutating external-effect path must call `admission::check` (or `admission_gate::*`) before dispatch.

Live JSON: `GET /api/v1/substrate/admission/matrix`  
Code anchors: `platform/server/src/substrate/admission_matrix.rs`, `admission_gate.rs`, `services/admission.rs`  
Route inventory: [route-security-inventory.json](./route-security-inventory.json)

## Major effect routes

| Effect class | Route(s) | Gate | Handler path |
|--------------|----------|------|----------------|
| Gateway LLM (OpenAI-compat) | `POST /v1/chat/completions` | `admission::check(LlmChat)` | `services/gateway.rs` |
| Gateway LLM (Anthropic) | Anthropic messages path | `admission::check(LlmChat)` | `services/anthropic_gateway.rs` |
| Tools / MCP register | `POST /tools/mcp/register` | `admission::check(ToolDispatch)` | `services/tools.rs` |
| Tools / MCP invoke | `POST /tools/mcp/invoke` | `admission::check(ToolDispatch)` | `services/tools.rs` |
| Protocols MCP | `POST /protocols/mcp/{discover,call,handle}` | `admission_gate::require_mcp_call` / `require_tool_dispatch` | `services/protocols.rs` |
| Knowledge ingest | `POST /memory/knowledge/ingest` | `admission::check(MemoryWrite)` | `services/memory.rs` (`knowledge_ingest`) |
| Memory write / graph / sessions | `/memory/write`, `/memory/graph/*`, sessions, compact/purge/import | `admission::check` / `admission_gate::require_memory_write` | `services/memory.rs`, `memory2.rs` |
| Object Fabric | `PUT/POST /memory/objects` | `admission::check(MemoryWrite)` | `services/object_fabric.rs` |
| Multi-agent pipeline | `POST /multiagent/{pipeline,grant,revoke,…}` | `admission_gate::require_*` | `services/multiagent.rs` |
| Experiments | `POST /experiments/:id/run` | `admission_gate::require_llm_chat` | `services/experiments.rs` |
| Assets ingest | `POST /assets/ingest`, container upload | `admission_gate::require_memory_write` | `services/assets.rs` |
| Debug restore (mutating) | `POST /debug/agents/:agent_pid/restore` | `admission_gate::require_memory_write` (+ admin) | `services/debug.rs` |
| Debug snapshot persist | `GET /debug/agents/:agent_pid/snapshot` (writes snapshot folder) | `admission_gate::require_memory_write` (+ admin) | `services/debug.rs` |

## Gate helpers

| Helper | Op | Use |
|--------|-----|-----|
| `admission::check` | any `AdmissionOp` | Direct call sites |
| `admission_gate::require_memory_write` | `MemoryWrite` | Memory / fabric / debug restore |
| `admission_gate::require_tool_dispatch` | `ToolDispatch` | Tool bridges |
| `admission_gate::require_mcp_call` | `McpCall` | Protocol MCP |
| `admission_gate::require_llm_chat` | `LlmChat` | Orchestration / experiments |
| `admission_gate::require_pipeline_step` | `PipelineStep` | Multi-agent steps |

## Deny response shape

Preferred JSON (UI should surface `message` / `denial_reason`, not silent fail):

```json
{
  "ok": false,
  "error": "admission_denied",
  "message": "<human_readable>",
  "denial_reason": "<slug>",
  "code": "admission_denied"
}
```

## Verify

- Unit: `admission_matrix` tests (handler source contains gate needles; wired routes ⊆ inventory).
- Adversarial HTTP: `platform/server/tests/trust_adversarial_http.rs` (`admission_matrix_lists_wired_effect_routes`).
- Do **not** run full `cargo test -p connector-platform --bin connector-platform` on ≤16 GiB laptops — see [LOW_MEMORY_DEV.md](../LOW_MEMORY_DEV.md).
