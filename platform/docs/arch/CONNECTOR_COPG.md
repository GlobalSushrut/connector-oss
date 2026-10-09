# COPG — Connector Operation Persistence Graph

**Status:** Connector standard for ARC / agency durable state (Soft default: JSONL; production: COPG).  
**Replaces:** SQLite as the planned ARC store — lighter, graph-native, integrity-chained.

## Why not SQLite?

| | SQLite | COPG (redb + graph) |
|---|--------|---------------------|
| Weight | SQL parser, VFS, generic planner | Pure Rust mmap B-tree (~kernel.redb pattern) |
| Agency fit | Relational tables; graph = JOIN pain | **Operation graph** is first-class |
| Security | File encryption = OS layer only | **Digest chain** per append + optional HMAC |
| Connector stack | Second engine beside kernel redb | **Same redb family** as Ring 0 |

COPG is **lighter than SQLite** and **more advanced for agency law** (worldline, FSM edges, lease links). It is not a general OLAP database.

## Dual operation model

```text
                    ┌─────────────────────────────────┐
  writes ──────────►│  append-only integrity chain    │
  (tx, commit,      │  (forensic replay / proof)      │
   lease, edge)     └──────────────┬──────────────────┘
                                   │ project
                    ┌──────────────▼──────────────────┐
                    │  redb: arc.redb                   │
                    │  • graph_edges (native traverse)  │
                    │  • records (typed blobs)          │
                    │  • agent_index (SQL-ish lookup)   │
                    └──────────────┬──────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
     Graph API                                  SQL-ish API
     traverse / export_graph                    select(table, filter, limit)
     worldline head / progeny                   operator + proof export
```

- **Graph:** worldline chain, AgencyTransaction FSM edges, lease→tx links.
- **SQL-ish:** structured `select` over typed tables — not full SQL (no JOIN parser overhead).

## On-disk layout

```text
$CONNECTOR_ARC_DURABLE_DIR/
  arc.redb          # redb — graph + record tables
  worldline.jsonl   # legacy Soft fallback when STORE=jsonl
```

## Configuration

| Env | Default | Role |
|-----|---------|------|
| `CONNECTOR_ARC_DURABLE` | `0` | Enable durable ARC |
| `CONNECTOR_ARC_DURABLE_DIR` | `.connector-arc-data` | Data directory |
| `CONNECTOR_ARC_STORE` | `jsonl` | `jsonl` (Soft) \| `copg` (redb graph+SQL) |
| `CONNECTOR_ARC_STORE_MAC_KEY` | (none) | Optional HMAC on chain links (lab: off) |

`CONNECTOR_ARC_HARDEN=1` implies durable + prefers `copg` when unset.

## Security properties

1. **Append integrity chain** — each record carries `prev_digest` + `digest` (sha256).
2. **Optional HMAC** — `CONNECTOR_ARC_STORE_MAC_KEY` seals chain links (tamper-evident).
3. **CoW crash safety** — redb copy-on-write; no blind COMMITTED after EFFECT_UNKNOWN.
4. **Worldline authoritative** — graph head monotonic; AACR single-writer fence unchanged.

## Schema (redb tables)

| Table | Key | Value |
|-------|-----|-------|
| `copg_records` | `{kind}:{id}` | JSON `CopgRecord` |
| `copg_chain_tip` | `"tip"` | last digest hex |
| `copg_graph_edges` | `{agent}:{seq:08}:{edge_id}` | JSON edge |
| `copg_agent_head` | `agent_id` | commit digest |
| `copg_agent_seq` | `agent_id` | u64 seq counter |

Record kinds: `worldline_commit`, `agency_tx`, `lease`, `graph_edge`.

## API (Rust)

```rust
copg::open(dir) -> CopgStore
copg::persist_worldline_commit(&commit)
copg::persist_agency_tx(&tx)
copg::graph_export(agent_id) -> Value
copg::select(CopgTable::WorldlineCommits, filter, limit) -> Vec<Value>
copg::load_worldline_into(store)
```

## Honesty

- **Soft:** `STORE=jsonl` — survives restart; no graph index.
- **Harden:** `STORE=copg` — graph + SQL-ish + chain; operator verify on node.
- **Not claimed:** distributed COPG, encrypted-at-rest beyond OS, full SQL-92.

## API (HTTP)

| Route | Role |
|-------|------|
| `GET /api/v1/arc/posture` | ARC + COPG honesty |
| `GET /api/v1/arc/:agent_pid/graph` | Operation graph + reconstruct |
| `GET /api/v1/arc/:agent_pid/query?table=&limit=` | SQL-ish COPG select |

## CLI

```bash
connectorctl arc posture
connectorctl arc graph --agent AGENT_PID [--out graph.json]
connectorctl arc query --agent AGENT_PID --table agency_transactions --limit 100
```

Tables: `worldline_commits` | `agency_transactions` | `graph_edges`

## References

- [CONNECTOR_ARC.md](CONNECTOR_ARC.md) — four primitives + worldline authority
- [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md) — Phase B0/E durable
- Ring 0 `kernel.redb` — same redb pattern in `connector-engine/redb_store.rs`
