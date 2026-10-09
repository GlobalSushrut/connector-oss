# Doctrine for coders (U0.3 / I-01)

Single story — do not invent a second source of truth.

| Concern | Source of truth | Projection / not SoT |
|---------|-----------------|----------------------|
| Agent memory bytes | VAC **MemPackets** (redb) | TT/WC Postgres, UI caches |
| Large multimodal bytes | **Object Fabric** (content-hash) | Inline base64 in packets |
| Usage / meters | **UsageEventV2** append log | Books UI, billing estimates |
| Custody / artifacts | **ArtifactLogRecordV2** | TraceTramp / WitnessCtl DBs |
| Graph | **Knot** rebuilt from MemPackets at boot | In-RAM HNSW index |
| Forensics join | **CFNI** `flow_id` + causal envelopes | Soft header correlation |
| HA | **Single-node** product SoT | Cluster crates experimental; `automatic_failover: false` |

**Rules**

1. No new Postgres-as-SoT for memory/usage without an ADR + projection adapter.
2. Never return decorative `"verified": true` or fake `$0` when unobserved.
3. Production / defense-strict: require `CONNECTOR_AUDIT_HMAC_KEY`, `CONNECTOR_CFNI_SECRET`, `CONNECTOR_CAGE_CAP_SECRET`; reject mock caps / glue stubs.
4. Deferred plugins (conductor, agentloop, ledgerlens, relay, engram, agentpassport) are not default install.

See also: [substrate-map.md](./substrate-map.md) · [MATURITY_21_UPGRADE_PLAN.md](../../MATURITY_21_UPGRADE_PLAN.md).
