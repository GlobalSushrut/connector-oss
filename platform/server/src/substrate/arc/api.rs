//! ARC / COPG operator HTTP API.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct ArcQueryParams {
    /// `worldline_commits` | `agency_transactions` | `graph_edges`
    #[serde(default = "default_table")]
    pub table: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_table() -> String {
    "worldline_commits".into()
}

fn default_limit() -> usize {
    50
}

fn parse_table(raw: &str) -> Result<crate::substrate::arc::copg::CopgTable, Value> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "worldline_commits" | "worldline" | "commits" => {
            Ok(crate::substrate::arc::copg::CopgTable::WorldlineCommits)
        }
        "agency_transactions" | "agency_tx" | "transactions" | "tx" => {
            Ok(crate::substrate::arc::copg::CopgTable::AgencyTransactions)
        }
        "graph_edges" | "edges" | "graph" => {
            Ok(crate::substrate::arc::copg::CopgTable::GraphEdges)
        }
        other => Err(json!({
            "ok": false,
            "error": "unknown_table",
            "table": other,
            "allowed": ["worldline_commits", "agency_transactions", "graph_edges"],
        })),
    }
}

/// GET /api/v1/arc/posture — ARC + COPG store posture.
pub async fn get_arc_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.arc.api.posture.v1",
        "arc": crate::substrate::arc::posture_json(),
        "copg": crate::substrate::arc::copg::posture_json(),
        "durable": crate::substrate::arc::durable::posture_json(),
        "docs": [
            "platform/docs/arch/CONNECTOR_ARC.md",
            "platform/docs/arch/CONNECTOR_COPG.md",
        ],
    })))
}

/// GET /api/v1/arc/:agent_pid/graph — COPG operation graph (+ in-memory worldline export).
pub async fn get_arc_graph(
    State(_state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let memory = crate::substrate::arc::worldline::export_graph(&agent_pid);
    let copg = crate::substrate::arc::copg::graph_export(&agent_pid);
    Json(operator_envelope(json!({
        "schema": "connector.arc.api.graph.v1",
        "agent_pid": agent_pid,
        "worldline_export": memory,
        "copg_graph": copg,
        "reconstruct": crate::substrate::arc::worldline::reconstruct_agency_state(&agent_pid, None).to_json(),
    })))
}

/// GET /api/v1/arc/:agent_pid/query — SQL-ish COPG select (+ memory tx list when COPG off).
pub async fn get_arc_query(
    State(_state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<ArcQueryParams>,
) -> Json<Value> {
    let limit = q.limit.clamp(1, 500);
    let table = match parse_table(&q.table) {
        Ok(t) => t,
        Err(e) => return Json(operator_envelope(e)),
    };

    let copg_rows = crate::substrate::arc::copg::sql_select(table, Some(&agent_pid), limit);
    let open_tx: Vec<Value> = crate::substrate::arc::runtime::transactions()
        .list_for_agent(&agent_pid)
        .into_iter()
        .take(limit)
        .map(|t| t.to_json())
        .collect();

    Json(operator_envelope(json!({
        "schema": "connector.arc.api.query.v1",
        "agent_pid": agent_pid,
        "table": q.table,
        "limit": limit,
        "copg": copg_rows,
        "open_transactions_memory": open_tx,
        "honesty": "copg rows empty when STORE=jsonl — set CONNECTOR_ARC_STORE=copg on node",
    })))
}
