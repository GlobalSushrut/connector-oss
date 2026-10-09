# Workflow institutions as projections (U6.2 / I-14)

TraceTramp and WitnessCtl are **institutions above** the substrate. Their Postgres
(and admin UIs) are **projections**, not a second source of truth.

| Substrate SoT | Projection |
|---------------|------------|
| MemPackets / Object Fabric / Moment | TT memory scope writes, decision trees |
| UsageEventV2 | TT cost.recorded / stream finalize (catalogue estimate only) |
| ArtifactLogRecordV2 + CFNI `flow_id` | TT trace_id, WC custody_id soft joins |
| CausalEnvelopeV2 | Admission lineage |

**Join rule:** prefer `x-connector-flow-id` (CFNI) over soft headers. Soft
correlation remains for legacy traffic until enforce is universal.

**Operator UI:** Forensics panel shows flow_id + moment + ArtifactLog alongside
TT/WC ids (`OpForensicsPanel`).
