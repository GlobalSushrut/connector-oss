# Agent Packet DNA — network genome Connector understands

## Problem

Today's networks carry IP / TCP / TLS / HTTP metadata. Connector needs every
packet to carry **agent DNA**: seven fixed parameters that an LLM or tool
cannot invent, strip, or forge.

## Genome (exactly 7)

| # | Slot | Source of truth |
|---|------|-----------------|
| 1 | `principal_id` | Kernel principal (not prompt text) |
| 2 | `agent_pid` | Agent instance id |
| 3 | `character_hash` | IntelligenceSpec name+purpose (or who_am_i) |
| 4 | `contract_hash` | AgentContract digest |
| 5 | `quantum_id` | DockLock execution quantum |
| 6 | `flow_lease_id` | Flow lease map |
| 7 | `effect_digest` | `SHA256(op\|address\|param_digest)` |

Bound fields: `payload_digest`, `nonce`, `issued_at_ms`, `expires_at_ms`, `hop`,
`signer_key_id`, `digest_hex`, `signature`.

## Wire

- Schema: `connector.agent_packet_dna.v1`
- HTTP header: `x-connector-dna` (base64url JSON)
- CNP: `WireEnvelope.dna` — digest included in CNP HMAC preimage
- Mint: `substrate::packet_dna::mint_for_agent` (kernel only)
- Verify: `assert_dna_or_refuse` — fail-closed when `CONNECTOR_PACKET_DNA_REQUIRE=1` or productionish

## Env

| Var | Role |
|-----|------|
| `CONNECTOR_PACKET_DNA_HMAC` | Signing secret (falls back to audit HMAC) |
| `CONNECTOR_PACKET_DNA_REQUIRE` | Force DNA on every CNP/network hop |

## Honesty

DNA is **not** a substitute for eBPF mark-deny or microVM isolation. It is the
L7 genome so every governed hop carries the same agent identity that admission
already decided — models cannot rewrite it mid-flight.

## LLM miss → HTTP 499

If the LLM does not follow Connector's **13 parameters** (7 DNA genome + 6
agentic pillars: who_am_i, principal, character, last_memory, knowledge_contract,
rules_hitl), the gateway returns **HTTP 499** with:

```json
{ "ok": false, "status": 499, "message": "sorry, you are not allowed — need human approval", "human_approval": true, ... }
```

Denial reason: `llm_not_allowed` / quarantine. HITL required for recovery.

## Related: LLM Context Broker

Same model brain may serve 100+ agents. Under distrust / exclusivity /
`CONNECTOR_LLM_CONTEXT_BROKER`, talk injects only opaque `ctx_tok_…` refs
(see [`LLM_CONTEXT_BROKER.md`](LLM_CONTEXT_BROKER.md)). Quarantine voids tokens
so leftover LLM context cannot authorize effects.

## Related: Data tokenization plane

Chat/tool/address payloads are tokenized for the model (Presidio sandwich +
vault-proxy). See [`LLM_TOKENIZATION_PLANE.md`](LLM_TOKENIZATION_PLANE.md).

## Related: AiPassport + SpendCease

Egress artifact provenance (leave-behind `.aipsprt.sig` / `connector_aipsprt`) and
hard cost/stop (kernel Cease so the LLM cannot keep spending after Stop) are
sibling planes — see [`AIPSPRT_SIG.md`](AIPSPRT_SIG.md) and [`SPEND_CEASE.md`](SPEND_CEASE.md).
