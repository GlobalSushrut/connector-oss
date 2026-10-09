# Zero-Trust Handshake (blockchain-grade tool binding)

Once a tool is connected through Connector, an LLM or external agent **cannot**
produce that tool's effect except by a Connector-minted, hash-chained ticket.

## Why this exists

Policy admission is not enough if the model can call the same MCP/HTTP endpoint
directly. The handshake makes Connector the **only signer** of tool authority.

```text
LLM / external agent
        │
        │  (no session key, cannot forge Ed25519)
        ▼
   Connector node
        │  genesis (Ed25519) → hash chain → single-use ticket
        ▼
      TOOL EFFECT
```

## Cryptographic properties

| Property | How |
|----------|-----|
| Genesis immutability | SHA-256 genesis hash + node Ed25519 signature |
| Session secrecy | Session key rederived from node signature of `zt-session\|handshake_id` — **never given to the LLM** |
| Chain continuity | Each ticket's `prev_hash` is the previous `block_hash` |
| Single-use | Nonce spent in `zt_handshake_spent_v1`; replay denied |
| Forgery resistance | Ticket MAC (HMAC-SHA256) + node signature; forged tickets fail verify |
| Manifest binding | Optional `CONNECTOR_ZT_HANDSHAKE_BIND_MANIFEST=1` invalidates handshake if tool identity changes |

## Enforcement

Set `CONNECTOR_ZT_HANDSHAKE=1` (production default).

Every `ToolDispatch` / MCP invoke goes through `zt_handshake::admit_tool_effect`:

1. Node establishes handshake if missing (LLM cannot do this without node key).
2. Node mints a 30s single-use ticket.
3. Ticket is verified and spent before the tool runs.
4. Remote bridges receive `x-connector-zt-*` headers — they must refuse unsigned calls.

## APIs

- `POST /api/v1/runtime/zt-handshake/establish`
- `GET /api/v1/runtime/zt-handshake/status`
- `POST /api/v1/runtime/zt-handshake/probe` — `llm_direct_tool`, `external_agent`, `forged_ticket`, `replay_ticket`, `mutated_manifest`
- `POST /api/v1/runtime/zt-handshake/revoke`

## Probe script

```bash
platform/scripts/zt-handshake-adversarial.sh
```

## Honest remainder

This closes **logical** and **in-process MCP** bypass. A remote tool that ignores
`x-connector-zt-*` headers can still be abused if it is reachable on the open
network. Pair this with effect exclusivity (no raw sockets) and isolation runtime
(`docker_lab` / `microvm`) so the agent physically cannot reach the tool except
through Connector.
