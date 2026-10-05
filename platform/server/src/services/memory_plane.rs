//! Unified **Agent OS** view: durable storage zones, knowledge pipeline, memory stability,
//! anti-hallucination chain, cognitive/context-efficiency pillars, and tool/contract execution —
//! honest about what is kernel-backed vs roadmap (Kafka broker, full VM sandboxes).

use axum::{extract::State, Json};

use crate::state::SharedState;

/// GET /memory/plane/overview — read-only catalog of how memory, knowledge, storage, tools,
/// and isolation fit together on this node (for operator dashboards and onboarding).
/// GET /memory/plane/context-efficiency — seven production pillars for LLM context/token efficiency (subset of overview).
pub async fn context_efficiency(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "data": context_efficiency_seven_block(),
    }))
}

pub async fn overview(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let layout = &state.storage_layout;
    let (packet_count, agent_count) = {
        let k = state.kernel.lock().unwrap();
        (k.packet_count(), k.agents().len())
    };
    let knot_entities = {
        let knot = state.knot.lock().unwrap();
        knot.node_count()
    };

    let zones: Vec<serde_json::Value> = layout
        .zones
        .iter()
        .map(|(zone, cfg)| {
            serde_json::json!({
                "zone": format!("{:?}", zone),
                "path": zone.path(),
                "durability": format!("{:?}", cfg.durability),
                "replication": format!("{:?}", cfg.replication),
                "encrypted": cfg.encrypted,
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "data": {
            "agent_operating_model": {
                "summary": "A Connector agent is a first-class subject: isolated memory namespace, auditable syscalls (memory/tool), contract/CLS bindings, and optional runtime sandbox policy rows — not merely a chat session.",
                "namespace_isolation": "Per-agent packets live in dedicated namespaces; cross-agent share via grants, /memory/share, or promotion to shared k/* (+ Knot) for fleet-wide knowledge and instruction.",
            },
            "distributed_mesh_collaboration": {
                "summary": "Shared knowledge, instruction, and memory are first-class together: batch ingest to k/* with role=fact|instruction; AccessGrant opens namespaces for peer read/write; /memory/share copies packets; multi-agent pipelines coordinate iterative work; mesh endpoint surfaces live edges.",
                "routes": {
                    "mesh_knowledge_plane": "GET /api/v1/multiagent/mesh/knowledge-plane",
                    "grant": "POST /api/v1/multiagent/grant",
                    "revoke": "POST /api/v1/multiagent/revoke",
                    "share_memory": "POST /api/v1/memory/share",
                    "knowledge_ingest": "POST /api/v1/memory/knowledge/ingest",
                    "knowledge_query": "POST /api/v1/memory/knowledge/query",
                    "multiagent_pipeline": "POST /api/v1/multiagent/pipeline",
                    "topology": "GET /api/v1/topology/center",
                },
            },
            "durable_storage_s3_analogy": {
                "what_it_is": "StorageZones + EngineStore (redb) + kernel packet store — zone-level durability, replication intent, and encrypted pockets (see connector-engine storage_zone).",
                "what_it_is_not": "Not Amazon S3 or MinIO APIs on this endpoint; use layout for OS-style paths and compliance posture.",
                "routes": {
                    "layout": "GET /api/v1/monitor/storage/layout",
                    "zone_health": "GET /api/v1/monitor/storage/zones/:zone_name",
                },
                "zones": zones,
                "zone_count": layout.zones.len(),
                "cell_id": layout.cell_id,
            },
            "knowledge_kafka_analogy": {
                "what_it_is": "Append-only audit + actionlog exports are the supported event fabric; standardized batch ingest (`records` + `dedupe_key` + `ingest_run_id`) pushes typed packets into the shared Knot graph.",
                "what_it_is_not": "No embedded Apache Kafka broker; use exports with your cluster or POST batch ingest from connectors.",
                "routes": {
                    "pipeline_spec": "GET /api/v1/memory/knowledge/pipeline/spec",
                    "ingest_batch_or_rescan": "POST /api/v1/memory/knowledge/ingest",
                    "ingest_to_graph": "POST /api/v1/memory/knowledge/ingest",
                    "query_graph": "POST /api/v1/memory/knowledge/query",
                    "semantic_search": "GET /api/v1/memory/semantic-search?q=…",
                    "audit_feed_jsonl": "GET /api/v1/actionlog/export/jsonl",
                    "audit_feed_cloudevents": "GET /api/v1/actionlog/export/cloudevents",
                    "asset_promotion": "POST /api/v1/assets/ingest (staging → k/)",
                },
            },
            "memory_stability_long_context": {
                "tiering": {
                    "distribution": "GET /api/v1/memory/tier/distribution/:agent_pid",
                    "change": "POST /api/v1/memory/tier/change",
                },
                "pressure_and_compaction": [
                    "GET /api/v1/memory/context-pressure/:agent_pid",
                    "POST /api/v1/memory/optimize-context/:agent_pid",
                    "POST /api/v1/memory/consolidate/:agent_pid",
                    "GET /api/v1/memory/stale-analysis",
                    "POST /api/v1/memory/eviction-policy",
                ],
                "per_agent_tree": "GET /api/v1/agents/:pid/memory/tree",
            },
            "de_hallucination_and_integrity_chain": {
                "order": [
                    "GuardPipeline (MAC → policy → content → circuit breaker → HITL) on ingress",
                    "Semantic injection detector on MCP tool inputs (default block > 0.75)",
                    "Grounding tables + claims / safety formal routes for post-hoc verification",
                ],
                "routes": {
                    "grounding_stats": "GET /api/v1/grounding/stats",
                    "safety_verify": "GET /api/v1/safety/formal/verify",
                    "tool_invoke": "POST /api/v1/tools/mcp/invoke",
                    "tool_invoke_scoped": "POST /api/v1/tools/mcp/invoke-scoped",
                },
            },
            "tool_execution_and_contract_virtualization": {
                "summary": "Tools execute as kernel ToolDispatch syscalls with bridge binding, optional scoped/circuit-aware invoke, and CLS/contract packages binding budgets and allowed capabilities.",
                "invoke": "POST /api/v1/tools/mcp/invoke",
                "invoke_scoped": "POST /api/v1/tools/mcp/invoke-scoped",
                "pending_hitl": "GET /api/v1/tools/approvals/pending",
                "cls_surface": [
                    "POST /api/v1/cls/compile",
                    "GET /api/v1/cls/packages",
                    "POST /api/v1/agents/:id/contract/from-template",
                ],
                "logic_stability": "Contracts + approvals reduce tool drift; injection gate reduces prompt-tool exfil patterns.",
            },
            "cnp_native_protocol": {
                "summary": "Connector Native Protocol (CNP) — 7-layer stack in connector-engine; superset of MCP/A2A with cross-cell L5 routing.",
                "overview": "GET /api/v1/cnp/overview",
                "mesh_with_topology": "GET /api/v1/topology/center (field data.cnp_mesh_control)",
            },
            "virtualization_and_sandbox_isolation": {
                "summary": "Kernel-backed agent lifecycle + logical namespaces are real; GET /runtime/enforcement exposes live OS telemetry (PID, kernel_release, cgroup excerpt) and registered agents. MCP bridges are separate OS services — ToolDispatch is recorded in-kernel from the control plane.",
                "routes": {
                    "runtime_enforcement": "GET /api/v1/runtime/enforcement",
                    "budget_groups": "GET /api/v1/monitor/cgroups",
                },
                "honesty": "Per-agent hardware VMs are optional via deployment; never fabricate per-agent cgroup paths in API JSON.",
            },
            "live_counters": {
                "kernel_packets": packet_count,
                "registered_agents": agent_count,
                "knowledge_graph_entities": knot_entities,
            },
            "context_efficiency_seven": context_efficiency_seven_block(),
        }
    }))
}

/// Seven **distinct, production** mechanisms that reduce repeated LLM context regeneration:
/// persisted reasoning, compaction, grounding, durable learning, shared mesh, tool stability,
/// and subgraph RAG — each mapped to live routes (not a lab-only demo).
fn context_efficiency_seven_block() -> serde_json::Value {
    serde_json::json!({
        "title": "Context efficiency — seven production pillars",
        "summary": "Instead of re-sending full chat history and re-deriving plans on every hop, agents persist reasoning, compact memory, retrieve grounded slices, learn into k/ + Knot, share via mesh, scope tools, and query the graph. Integrate these routes in your loop to cut input tokens and retry churn.",
        "honesty": {
            "measurement": "Exact multipliers are workload-specific (baseline prompts, model, tokenizer, tool fan-out). The stack implements real persistence, retrieval, and enforcement — benchmark on your traces.",
            "design_targets": {
                "general_workloads": "~5× lower regenerative context pressure vs naive full-thread replay when compaction + retrieval + persisted steps are used consistently.",
                "coding_and_tool_heavy": "~7× potential in tight tool loops when scoped invocation, grounded facts, and cached reasoning reduce speculative retries and wide prompts."
            }
        },
        "external_research": [
            {
                "label": "RAG vs long-context LLMs (hybrid routing)",
                "url": "https://arxiv.org/abs/2407.16833",
                "takeaway": "Retrieval-first and hybrid designs trim input length while staying competitive on quality — the cost axis favors selective context over stuffing full windows."
            },
            {
                "label": "Industry pattern: RAG and token budgeting",
                "url": "https://myengineeringpath.dev/genai-engineer/context-windows/",
                "takeaway": "Long windows are priced linearly in tokens; substituting retrieval + smaller working sets is the standard ops lever for spend control."
            }
        ],
        "pillars": [
            {
                "id": "persisted_chain_of_thought",
                "name": "Persisted chain-of-thought",
                "problem": "Models re-reason from scratch each turn when intermediate steps live only in ephemeral chat.",
                "what_we_do": "Record reasoning steps and conclusions as kernel packets; run full cognitive cycles; export chains for audit.",
                "routes": {
                    "reasoning_step": "POST /api/v1/cognitive/reasoning/step",
                    "reasoning_conclude": "POST /api/v1/cognitive/reasoning/conclude",
                    "cognitive_cycle": "POST /api/v1/cognitive/cycle",
                    "cognitive_report": "GET /api/v1/cognitive/report/:agent_pid",
                    "perceived_context": "GET /api/v1/cognitive/context/:agent_pid",
                    "observe": "POST /api/v1/cognitive/observe",
                    "debug_reasoning_chain": "GET /api/v1/debug/agents/:agent_pid/reasoning-chain (admin)"
                }
            },
            {
                "id": "memory_stability_long_context",
                "name": "Memory stability & long-context hygiene",
                "problem": "Stale, duplicate, and over-wide contexts inflate tokens and contradict newer facts.",
                "what_we_do": "Tier visibility, measure pressure, optimize/evict, and consolidate buckets into summaries — shrink what you send to the model.",
                "routes": {
                    "tier_distribution": "GET /api/v1/memory/tier/distribution/:agent_pid",
                    "tier_change": "POST /api/v1/memory/tier/change",
                    "context_pressure": "GET /api/v1/memory/context-pressure/:agent_pid",
                    "optimize_context": "POST /api/v1/memory/optimize-context/:agent_pid",
                    "consolidate": "POST /api/v1/memory/consolidate/:agent_pid",
                    "stale_analysis": "GET /api/v1/memory/stale-analysis",
                    "eviction_policy": "POST /api/v1/memory/eviction-policy",
                    "agent_memory_tree": "GET /api/v1/agents/:pid/memory/tree"
                }
            },
            {
                "id": "dehallucination_grounding_chain",
                "name": "De-hallucination & grounding chain",
                "problem": "Hallucinations force human rework, longer dialogs, and repeated verification prompts.",
                "what_we_do": "Guard + injection checks on ingress; grounding tables; claims verify; formal safety checks — cite and gate before paying for another full generation.",
                "routes": {
                    "grounding_stats": "GET /api/v1/grounding/stats",
                    "ground_output": "POST /api/v1/grounding/ground-output",
                    "verify_claim": "POST /api/v1/grounding/claims/verify",
                    "verify_batch": "POST /api/v1/grounding/claims/verify-batch",
                    "ground_and_verify": "POST /api/v1/grounding/claims/ground-and-verify",
                    "safety_formal_verify": "GET /api/v1/safety/formal/verify",
                    "tool_invoke_scoped": "POST /api/v1/tools/mcp/invoke-scoped"
                }
            },
            {
                "id": "chain_learning_durable_recall",
                "name": "Chain learning & durable recall",
                "problem": "Lessons from one session are lost; the LLM is asked to relearn policies from prose each time.",
                "what_we_do": "Reflection runs, compile reasoning into reusable knowledge packets, and promote facts/instructions into shared k/ + Knot.",
                "routes": {
                    "agent_reflect": "POST /api/v1/agents/:pid/reflect",
                    "knowledge_compile": "POST /api/v1/memory/knowledge/compile",
                    "knowledge_ingest": "POST /api/v1/memory/knowledge/ingest",
                    "knowledge_query": "POST /api/v1/memory/knowledge/query",
                    "memory_write": "POST /api/v1/memory/write"
                }
            },
            {
                "id": "shared_mesh_knowledge_instruction",
                "name": "Shared knowledge + instruction mesh",
                "problem": "Every agent duplicates the same instructions and facts in private context.",
                "what_we_do": "Grants, memory share, batch ingest with role=fact|instruction, and mesh telemetry — one fleet pub/sub surface for static+policy text.",
                "routes": {
                    "mesh_knowledge_plane": "GET /api/v1/multiagent/mesh/knowledge-plane",
                    "grant": "POST /api/v1/multiagent/grant",
                    "share_memory": "POST /api/v1/memory/share",
                    "multiagent_pipeline": "POST /api/v1/multiagent/pipeline",
                    "topology": "GET /api/v1/topology/center"
                }
            },
            {
                "id": "tool_execution_contract_stability",
                "name": "Tool & contract stability",
                "problem": "Unscoped tool calls and drift burn tokens on retries, arguments repair, and escalation.",
                "what_we_do": "Scoped invoke, approvals queue, CLS packages — fewer invalid calls and less re-planning.",
                "routes": {
                    "mcp_invoke": "POST /api/v1/tools/mcp/invoke",
                    "mcp_invoke_scoped": "POST /api/v1/tools/mcp/invoke-scoped",
                    "pending_hitl": "GET /api/v1/tools/approvals/pending",
                    "cls_compile": "POST /api/v1/cls/compile",
                    "cls_packages": "GET /api/v1/cls/packages"
                }
            },
            {
                "id": "knot_rag_substrate",
                "name": "Knot + k/ RAG substrate",
                "problem": "Dumping entire corpora into the prompt every turn scales cost linearly with corpus size.",
                "what_we_do": "Entity graph ingestion (Knot) plus scoped semantic search — retrieve a small evidence bundle instead of regenerating from whole-repo context.",
                "routes": {
                    "pipeline_spec": "GET /api/v1/memory/knowledge/pipeline/spec",
                    "semantic_search": "GET /api/v1/memory/semantic-search?q=…",
                    "graph_entities": "GET /api/v1/memory/graph/entities",
                    "cnp_overview": "GET /api/v1/cnp/overview",
                    "assets_ingest": "POST /api/v1/assets/ingest"
                }
            }
        ]
    })
}
