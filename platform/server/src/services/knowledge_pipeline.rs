//! **Knowledge & instruction pipeline** — operator contract for large-scale ingest.
//!
//! Stabilises the S3-analog (`StorageZone` + `/k/`) and Kafka-analog (topics, partitions,
//! idempotent runs, actionlog fan-out) without embedding a broker or object store in-process.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::SharedState;

#[derive(Clone, Serialize)]
struct PipelineSpecV1 {
    spec_version: &'static str,
    pipeline_implementation_version: &'static str,
    object_model: serde_json::Value,
    kafka_standard_analog: serde_json::Value,
    s3_standard_analog: serde_json::Value,
    endpoints: serde_json::Value,
    instruction_injection: serde_json::Value,
    observability: serde_json::Value,
    cell_id: String,
}

/// GET /memory/knowledge/pipeline/spec — canonical contract for knowledge containers + ingest.
pub async fn get_pipeline_spec(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let cell_id = state.storage_layout.cell_id.clone();
    let zone_paths: Vec<String> = state
        .storage_layout
        .zones
        .keys()
        .map(|z| format!("{:?}", z))
        .collect();

    let spec = PipelineSpecV1 {
        spec_version: "1.0",
        pipeline_implementation_version: "2026.04-connector-platform",
        object_model: serde_json::json!({
            "storage_zones": {
                "summary": "Durable paths + replication intent (S3-analog at the Connector OS layer — not AWS S3 API).",
                "layout_route": "GET /api/v1/monitor/storage/layout",
                "zone_names": zone_paths,
            },
            "asset_containers": {
                "staging_namespace_pattern": "v/{container_id}",
                "create": "POST /api/v1/assets/containers",
                "upload": "POST /api/v1/assets/containers/:id/upload",
                "promote_to_knowledge": "POST /api/v1/assets/ingest → MemWrite under k/* + Knot ingest",
            },
            "knowledge_namespaces": {
                "pattern": "k/{tenant_or_corpus}",
                "canonical_for_knot": "Packets in k/* are merged into KnotEngine on ingest.",
            },
            "agent_private_memory": {
                "pattern": "Per-agent namespace from AgentControlBlock — not shared until written to k/ or granted.",
            },
        }),
        kafka_standard_analog: serde_json::json!({
            "topic": "Logical stream — set `source.topic` on POST /memory/knowledge/ingest (optional metadata).",
            "partition_key": "Optional `partition_key` for tenant-ordered processing analog.",
            "offsets_analog": "`ingest_run_id` scopes a batch; per-record `dedupe_key` provides idempotent commits.",
            "fan_out_consumers": [
                "GET /api/v1/actionlog/export/jsonl",
                "GET /api/v1/actionlog/export/cloudevents",
            ],
            "honesty": "No Apache Kafka broker ships inside connector-platform — integrate your cluster using these exports or webhooks.",
        }),
        s3_standard_analog: serde_json::json!({
            "buckets_analog": "StorageZone + engine_store folders (`asset_containers`, `asset_records`).",
            "object_versioning_analog": "Content-addressed payload CIDs + audit log append-only ordering.",
            "put_route": "POST /assets/containers/:id/upload stores raw content; POST /assets/ingest materialises knowledge packets.",
        }),
        endpoints: serde_json::json!({
            "pipeline_spec": "GET /api/v1/memory/knowledge/pipeline/spec",
            "ingest_batch": "POST /api/v1/memory/knowledge/ingest with body `records: [...]`",
            "ingest_rescan_namespace": "POST /api/v1/memory/knowledge/ingest with body `{ \"namespace\": \"...\" }` only (re-index existing packets)",
            "knowledge_query": "POST /api/v1/memory/knowledge/query",
            "memory_plane": "GET /api/v1/memory/plane/overview",
            "context_efficiency_seven": "GET /api/v1/memory/plane/context-efficiency — CoT persistence, memory stability, grounding, learning, mesh, tools, Knot RAG (token-cost architecture)",
            "mesh_multiagent": "GET /api/v1/multiagent/mesh/knowledge-plane — grants, shared writes, agents on one collaborative surface",
        }),
        instruction_injection: serde_json::json!({
            "role_instruction": "Use record field `role: \"instruction\"` → PacketType::input with tag `instruction_injection` (system prompt / policy text).",
            "role_fact": "Default / `role: \"fact\"` → PacketType::extraction for RAG / Knot facts.",
            "governance": "Large corpora should use asset containers + ingest, or batch ingest with dedupe — avoids duplicate instruction drift.",
        }),
        observability: serde_json::json!({
            "mesh_with_knot": "Knot `last_ingest_sn` + entity count visible via GET /api/v1/cnp/overview mesh_snapshot or topology center.",
            "audit": "MemWrite operations appear in kernel audit + actionlog exports.",
        }),
        cell_id,
    };

    Json(serde_json::json!({
        "ok": true,
        "data": serde_json::to_value(&spec).unwrap_or_else(|_| serde_json::json!({}))
    }))
}
