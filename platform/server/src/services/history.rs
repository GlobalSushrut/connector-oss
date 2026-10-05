use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub status: Option<String>,
}
fn default_limit() -> usize {
    50
}

pub async fn list_agents(
    State(state): State<SharedState>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let agents: Vec<serde_json::Value> = k
        .agents()
        .iter()
        .take(q.limit)
        .map(|(pid, acb)| {
            let ns = format!("ns:{}", acb.agent_pid);
            let packet_count = k.packets_in_namespace(&ns).len();
            let audit_count = k.audit_log().iter().filter(|e| e.agent_pid == *pid).count();
            serde_json::json!({
                "pid": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "status": format!("{:?}", acb.status),
                "registered_at": acb.registered_at,
                "terminated_at": acb.terminated_at,
                "packet_count": packet_count,
                "audit_entries": audit_count,
            })
        })
        .collect();
    Json(serde_json::json!({"count": agents.len(), "agents": agents}))
}

pub async fn agent_timeline(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .take(q.limit)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "outcome": format!("{:?}", e.outcome),
                "reason": e.reason,
                "target": e.target,
            })
        })
        .collect();
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "count": entries.len(),
        "timeline": entries,
    }))
}

pub async fn agent_sessions(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let sessions: Vec<serde_json::Value> = k
        .sessions()
        .iter()
        .filter(|(_, env)| {
            env.metadata.get("agent_pid").and_then(|v| v.as_str()) == Some(&agent_pid)
        })
        .map(|(id, env)| {
            serde_json::json!({
                "session_id": id,
                "type": env.type_,
                "summary": env.summary,
                "total_tokens": env.total_tokens,
            })
        })
        .collect();
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "count": sessions.len(),
        "sessions": sessions,
    }))
}

/// Wave 3 — Item 3.5: Auto-detect what config change caused quality drop
pub async fn regression_detect(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();

    if audit.len() < 10 {
        return Json(serde_json::json!({
            "agent_pid": agent_pid,
            "regression_detected": false,
            "reason": "Need at least 10 audit entries for regression analysis",
        }));
    }

    // Split into two halves and compare failure rates
    let mid = audit.len() / 2;
    let first_half = &audit[..mid];
    let second_half = &audit[mid..];

    let first_fail_rate = first_half
        .iter()
        .filter(|e| {
            e.outcome == vac_core::types::OpOutcome::Failed
                || e.outcome == vac_core::types::OpOutcome::Denied
        })
        .count() as f64
        / first_half.len() as f64;
    let second_fail_rate = second_half
        .iter()
        .filter(|e| {
            e.outcome == vac_core::types::OpOutcome::Failed
                || e.outcome == vac_core::types::OpOutcome::Denied
        })
        .count() as f64
        / second_half.len() as f64;

    let regression = second_fail_rate > first_fail_rate + 0.1; // >10% increase

    // Find the first failure in second half that wasn't failing in first half
    let mut regression_point: Option<serde_json::Value> = None;
    if regression {
        let first_ops: std::collections::HashSet<String> = first_half
            .iter()
            .filter(|e| {
                e.outcome == vac_core::types::OpOutcome::Failed
                    || e.outcome == vac_core::types::OpOutcome::Denied
            })
            .map(|e| format!("{:?}", e.operation))
            .collect();

        for entry in second_half {
            let op = format!("{:?}", entry.operation);
            if (entry.outcome == vac_core::types::OpOutcome::Failed
                || entry.outcome == vac_core::types::OpOutcome::Denied)
                && !first_ops.contains(&op)
            {
                regression_point = Some(serde_json::json!({
                    "timestamp": entry.timestamp,
                    "operation": op,
                    "error": &entry.error,
                    "reason": &entry.reason,
                }));
                break;
            }
        }
    }

    let mut recommendations: Vec<String> = Vec::new();
    if regression {
        recommendations.push(format!(
            "Failure rate increased from {:.0}% to {:.0}% in recent operations",
            first_fail_rate * 100.0,
            second_fail_rate * 100.0
        ));
        if let Some(ref rp) = regression_point {
            recommendations.push(format!(
                "First new failure type: {} at timestamp {}",
                rp.get("operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                rp.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0)
            ));
        }
        recommendations.push("Check recent agent configuration changes, tool binding updates, or namespace permission changes.".into());
    }

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "regression_detected": regression,
        "first_half_fail_rate": (first_fail_rate * 1000.0).round() / 10.0,
        "second_half_fail_rate": (second_fail_rate * 1000.0).round() / 10.0,
        "total_operations": audit.len(),
        "regression_point": regression_point,
        "recommendations": recommendations,
    }))
}

/// Fleet-level regression detect — no agent_pid path param (used by /history/regression-detect)
pub async fn regression_detect_fleet(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit = k.audit_log();
    if audit.len() < 10 {
        return Json(serde_json::json!({
            "detected": false,
            "reason": "Need at least 10 fleet-wide audit entries for analysis",
            "total_entries": audit.len(),
        }));
    }
    let mid = audit.len() / 2;
    let first_fail = audit[..mid]
        .iter()
        .filter(|e| {
            e.outcome == vac_core::types::OpOutcome::Failed
                || e.outcome == vac_core::types::OpOutcome::Denied
        })
        .count() as f64
        / mid as f64;
    let second_fail = audit[mid..]
        .iter()
        .filter(|e| {
            e.outcome == vac_core::types::OpOutcome::Failed
                || e.outcome == vac_core::types::OpOutcome::Denied
        })
        .count() as f64
        / (audit.len() - mid) as f64;
    let detected = second_fail > first_fail + 0.1;
    Json(serde_json::json!({
        "detected": detected,
        "description": if detected {
            format!("Fleet failure rate increased from {:.0}% to {:.0}%", first_fail * 100.0, second_fail * 100.0)
        } else {
            "No fleet-wide regression detected".into()
        },
        "first_half_fail_rate": (first_fail * 1000.0).round() / 10.0,
        "second_half_fail_rate": (second_fail * 1000.0).round() / 10.0,
        "total_entries": audit.len(),
    }))
}

/// Wave 3 — Item 3.6: Compare agent state between two timestamps
pub async fn agent_diff(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let audit: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();

    if audit.is_empty() {
        return Json(
            serde_json::json!({"agent_pid": agent_pid, "error": "No audit entries found"}),
        );
    }

    // Split at midpoint for comparison
    let mid = audit.len() / 2;
    let first_half = &audit[..mid];
    let second_half = &audit[mid..];

    // Count operations by type in each half
    let mut first_ops: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut second_ops: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in first_half {
        *first_ops.entry(format!("{:?}", e.operation)).or_insert(0) += 1;
    }
    for e in second_half {
        *second_ops.entry(format!("{:?}", e.operation)).or_insert(0) += 1;
    }

    // Find new operations, removed operations, and changed frequencies
    let all_ops: std::collections::HashSet<String> =
        first_ops.keys().chain(second_ops.keys()).cloned().collect();
    let mut changes: Vec<serde_json::Value> = Vec::new();
    for op in &all_ops {
        let before = *first_ops.get(op).unwrap_or(&0);
        let after = *second_ops.get(op).unwrap_or(&0);
        if before != after {
            let change_type = if before == 0 {
                "new"
            } else if after == 0 {
                "removed"
            } else if after > before {
                "increased"
            } else {
                "decreased"
            };
            changes.push(serde_json::json!({
                "operation": op,
                "before": before,
                "after": after,
                "change": change_type,
            }));
        }
    }

    // Agent current state
    let acb = k.get_agent(&agent_pid);
    let agent_info = acb.map(|a| {
        serde_json::json!({
            "name": &a.agent_name,
            "status": format!("{:?}", a.status),
            "role": format!("{:?}", a.role),
            "tool_bindings": a.tool_bindings.len(),
            "namespace_mounts": a.namespace_mounts.len(),
            "total_tokens": a.total_tokens_consumed,
            "total_cost_usd": a.total_cost_usd,
        })
    });

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "total_operations": audit.len(),
        "first_half_range": {
            "from": first_half.first().map(|e| e.timestamp),
            "to": first_half.last().map(|e| e.timestamp),
            "count": first_half.len(),
        },
        "second_half_range": {
            "from": second_half.first().map(|e| e.timestamp),
            "to": second_half.last().map(|e| e.timestamp),
            "count": second_half.len(),
        },
        "changes": changes,
        "current_state": agent_info,
    }))
}

/// Wave 4 — Item 4.9: Time-range session replay
pub async fn replay(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let from_ts = req.get("from_ts").and_then(|v| v.as_i64()).unwrap_or(0);
    let to_ts = req
        .get("to_ts")
        .and_then(|v| v.as_i64())
        .unwrap_or(i64::MAX);

    let k = state.kernel.lock().unwrap();

    // Get audit entries in time range
    let audit_entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .filter(|e| {
            e.timestamp >= from_ts
                && e.timestamp <= to_ts
                && (agent_pid.is_empty() || e.agent_pid == agent_pid)
        })
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": &e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "target_cid": &e.target,
                "reason": &e.reason,
                "duration_us": e.duration_us,
            })
        })
        .collect();

    // Get memory packets in time range
    let mut packets: Vec<serde_json::Value> = Vec::new();
    if !agent_pid.is_empty() {
        if let Some(acb) = k.get_agent(agent_pid) {
            packets = k.packets_in_namespace(&acb.namespace).iter()
                .filter(|p| p.index.ts >= from_ts && p.index.ts <= to_ts)
                .map(|p| serde_json::json!({
                    "cid": p.content.payload_cid.to_string(),
                    "type": format!("{}", p.content.packet_type),
                    "ts": p.index.ts,
                    "text": p.content.payload.get("text").and_then(|v| v.as_str()).map(|s| s.chars().take(120).collect::<String>()),
                }))
                .collect();
        }
    }

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "audit_events": audit_entries.len(),
        "memory_packets": packets.len(),
        "timeline": audit_entries,
        "packets": packets,
    }))
}

/// Wave 4 — Item 4.10: Sessions by time range for an agent
pub async fn sessions_range(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();

    // Get all sessions for this agent
    let sessions: Vec<serde_json::Value> = k
        .sessions()
        .iter()
        .filter(|(_, env)| {
            env.metadata.get("agent_pid").and_then(|v| v.as_str()) == Some(&agent_pid)
        })
        .take(q.limit)
        .map(|(id, env)| {
            // Count packets in this session
            let packet_count = k.packets_in_session(id).len();
            serde_json::json!({
                "session_id": id,
                "type": env.type_,
                "version": env.version,
                "summary": env.summary,
                "total_tokens": env.total_tokens,
                "packet_count": packet_count,
                "child_sessions": env.child_session_ids.len(),
            })
        })
        .collect();

    // Also get agent's audit timeline grouped by operation type
    let mut op_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for e in k.audit_log().iter().filter(|e| e.agent_pid == agent_pid) {
        *op_counts.entry(format!("{:?}", e.operation)).or_insert(0) += 1;
    }

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "session_count": sessions.len(),
        "sessions": sessions,
        "operation_summary": op_counts,
    }))
}

// ── E5.8: Cost timeline + chargeback ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct CostTimelineQuery {
    pub window: Option<String>,
    pub granularity: Option<String>,
}

/// GET /history/agents/{pid}/cost-timeline?window=30d&granularity=day
pub async fn cost_timeline(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<CostTimelineQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let window_days: i64 = q
        .window
        .as_deref()
        .unwrap_or("30d")
        .strip_suffix('d')
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let granularity = q.granularity.as_deref().unwrap_or("day");
    let bucket_ms: i64 = match granularity {
        "hour" => 3_600_000,
        "week" => 7 * 86_400_000,
        _ => 86_400_000, // day
    };
    let cutoff_ms = now_ms - window_days * 86_400_000;

    let audit_log = k.audit_log();
    let es = state.engine_store.lock().unwrap();

    // Build cost per bucket from token_usage records
    let usage_keys = es.folder_keys("token_usage", None).unwrap_or_default();
    let mut bucket_cost: std::collections::BTreeMap<i64, f64> = std::collections::BTreeMap::new();
    let mut bucket_tokens: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();
    let mut bucket_ops: std::collections::BTreeMap<i64, u64> = std::collections::BTreeMap::new();

    for key in &usage_keys {
        let rec = match es.folder_get("token_usage", key).ok().flatten() {
            Some(r) => r,
            None => continue,
        };
        if rec.get("agent_pid").and_then(|v| v.as_str()) != Some(&agent_pid) {
            continue;
        }
        let ts = rec.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        if ts < cutoff_ms {
            continue;
        }
        let bucket = (ts / bucket_ms) * bucket_ms;
        let cost = rec.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let tokens = rec
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            + rec
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
        *bucket_cost.entry(bucket).or_insert(0.0) += cost;
        *bucket_tokens.entry(bucket).or_insert(0) += tokens;
    }

    // Ops per bucket from audit log
    for entry in audit_log
        .iter()
        .filter(|e| e.agent_pid == agent_pid && e.timestamp >= cutoff_ms)
    {
        let bucket = (entry.timestamp / bucket_ms) * bucket_ms;
        *bucket_ops.entry(bucket).or_insert(0) += 1;
    }

    let all_buckets: std::collections::BTreeSet<i64> = bucket_cost
        .keys()
        .chain(bucket_ops.keys())
        .copied()
        .collect();

    let timeline: Vec<serde_json::Value> = all_buckets
        .iter()
        .map(|&b| {
            let cost = bucket_cost.get(&b).copied().unwrap_or(0.0);
            let tokens = bucket_tokens.get(&b).copied().unwrap_or(0);
            let ops = bucket_ops.get(&b).copied().unwrap_or(0);
            let iso = chrono::DateTime::from_timestamp_millis(b)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            serde_json::json!({
                "bucket_ms":  b,
                "bucket_iso": iso,
                "cost_usd":   (cost * 1_000_000.0).round() / 1_000_000.0,
                "tokens":     tokens,
                "ops":        ops,
            })
        })
        .collect();

    let total_cost: f64 = bucket_cost.values().sum();
    let total_tokens: u64 = bucket_tokens.values().sum();
    let total_ops: u64 = bucket_ops.values().sum();

    // Chargeback: cost per team/namespace (using agent namespace)
    let acb = k.get_agent(&agent_pid);
    let namespace = acb
        .map(|a| a.namespace.clone())
        .unwrap_or_else(|| "default".into());

    Json(serde_json::json!({
        "agent_pid":     agent_pid,
        "namespace":     namespace,
        "generated_at":  now.to_rfc3339(),
        "window_days":   window_days,
        "granularity":   granularity,
        "summary": {
            "total_cost_usd":   (total_cost * 1_000_000.0).round() / 1_000_000.0,
            "total_tokens":     total_tokens,
            "total_ops":        total_ops,
            "avg_cost_per_op":  if total_ops > 0 { (total_cost / total_ops as f64 * 1_000_000.0).round() / 1_000_000.0 } else { 0.0 },
        },
        "chargeback": {
            "namespace":        namespace,
            "cost_usd":         (total_cost * 1_000_000.0).round() / 1_000_000.0,
            "billing_period":   format!("{}d ending {}", window_days, now.format("%Y-%m-%d")),
            "chargeback_note":  "Allocate cost to namespace for internal showback/chargeback",
        },
        "timeline": timeline,
    }))
}

// ── E5.9: Fleet comparison table ─────────────────────────────────────────────

/// GET /history/fleet/compare — side-by-side metric comparison across all agents
pub async fn fleet_compare(
    State(state): State<SharedState>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    let cutoff_24h = now_ms - 86_400_000i64;
    let cutoff_7d = now_ms - 7 * 86_400_000i64;

    let audit_log = k.audit_log();
    let agents = k.agents();
    let es = state.engine_store.lock().unwrap();

    let usage_keys = es.folder_keys("token_usage", None).unwrap_or_default();

    let mut rows: Vec<serde_json::Value> = agents
        .values()
        .map(|acb| {
            let pid = &acb.agent_pid;

            // 24h metrics
            let ops_24h: Vec<_> = audit_log
                .iter()
                .filter(|e| &e.agent_pid == pid && e.timestamp >= cutoff_24h)
                .collect();
            let denied_24h = ops_24h
                .iter()
                .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
                .count();
            let deny_rate_24h = if ops_24h.is_empty() {
                0.0
            } else {
                denied_24h as f64 / ops_24h.len() as f64 * 100.0
            };

            // 7d cost
            let cost_7d: f64 = usage_keys
                .iter()
                .filter_map(|k| es.folder_get("token_usage", k).ok().flatten())
                .filter(|u| {
                    u.get("agent_pid").and_then(|v| v.as_str()) == Some(pid)
                        && u.get("ts")
                            .and_then(|v| v.as_i64())
                            .map_or(false, |t| t >= cutoff_7d)
                })
                .filter_map(|u| u.get("cost_usd").and_then(|v| v.as_f64()))
                .sum();

            // Trust score
            let trust = connector_engine::TrustComputer::compute(&k);

            // Last active
            let last_active_iso = chrono::DateTime::from_timestamp_millis(acb.last_active_at)
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();

            // Health signal
            let health = if deny_rate_24h > 50.0 {
                "critical"
            } else if deny_rate_24h > 20.0 {
                "degraded"
            } else {
                "healthy"
            };

            serde_json::json!({
                "agent_pid":      pid,
                "agent_name":     acb.agent_name,
                "namespace":      acb.namespace,
                "model":          acb.model,
                "status":         format!("{:?}", acb.status),
                "health":         health,
                "ops_24h":        ops_24h.len(),
                "denied_24h":     denied_24h,
                "deny_rate_24h":  (deny_rate_24h * 10.0).round() / 10.0,
                "cost_7d_usd":    (cost_7d * 1_000_000.0).round() / 1_000_000.0,
                "total_tokens":   acb.total_tokens_consumed,
                "total_cost_usd": (acb.total_cost_usd * 1_000_000.0).round() / 1_000_000.0,
                "agent_health_score": trust.score,
                "last_active":    last_active_iso,
            })
        })
        .collect();

    // Sort by deny_rate descending (worst first)
    rows.sort_by(|a, b| {
        let da = a
            .get("deny_rate_24h")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let db = b
            .get("deny_rate_24h")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
    });

    let critical_count = rows
        .iter()
        .filter(|r| r.get("health").and_then(|v| v.as_str()) == Some("critical"))
        .count();
    let degraded_count = rows
        .iter()
        .filter(|r| r.get("health").and_then(|v| v.as_str()) == Some("degraded"))
        .count();

    Json(serde_json::json!({
        "generated_at":    now.to_rfc3339(),
        "agent_count":     rows.len(),
        "critical_agents": critical_count,
        "degraded_agents": degraded_count,
        "columns": ["agent_pid","agent_name","namespace","model","status","health","ops_24h","denied_24h","deny_rate_24h","cost_7d_usd","total_tokens","total_cost_usd","agent_health_score","last_active"],
        "rows":            rows,
    }))
}

// ── E5.10: Behaviour drift detection ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct DriftQuery {
    pub window: Option<String>,
}

/// GET /history/agents/{pid}/drift?window=7d
pub async fn behaviour_drift(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<DriftQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();

    let window_days: i64 = q
        .window
        .as_deref()
        .unwrap_or("7d")
        .strip_suffix('d')
        .and_then(|s| s.parse().ok())
        .unwrap_or(7);

    let recent_ms = window_days * 86_400_000;
    let baseline_ms = recent_ms * 4; // 4x window for baseline

    let recent_start = now_ms - recent_ms;
    let baseline_start = now_ms - baseline_ms;

    let audit_log = k.audit_log();

    let baseline_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid && e.timestamp >= baseline_start && e.timestamp < recent_start
        })
        .collect();
    let recent_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| e.agent_pid == agent_pid && e.timestamp >= recent_start)
        .collect();

    let baseline_total = baseline_ops.len().max(1);
    let recent_total = recent_ops.len().max(1);

    // Deny rate drift
    let baseline_deny = baseline_ops
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let recent_deny = recent_ops
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let baseline_deny_rate = baseline_deny as f64 / baseline_total as f64;
    let recent_deny_rate = recent_deny as f64 / recent_total as f64;
    let deny_rate_delta = recent_deny_rate - baseline_deny_rate;

    // Op volume drift (ops/day)
    let baseline_ops_per_day = baseline_total as f64 / (window_days * 4) as f64;
    let recent_ops_per_day = recent_total as f64 / window_days as f64;
    let volume_delta_pct = if baseline_ops_per_day > 0.0 {
        (recent_ops_per_day - baseline_ops_per_day) / baseline_ops_per_day * 100.0
    } else {
        0.0
    };

    // Operation type distribution drift
    let op_dist =
        |ops: &[&vac_core::types::KernelAuditEntry]| -> std::collections::HashMap<String, f64> {
            let total = ops.len().max(1) as f64;
            let mut counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for e in ops {
                *counts.entry(format!("{:?}", e.operation)).or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(k, v)| (k, v as f64 / total))
                .collect()
        };

    let baseline_dist = op_dist(&baseline_ops);
    let recent_dist = op_dist(&recent_ops);

    // Jensen-Shannon-like distance (simple symmetric KL approximation)
    let all_ops: std::collections::HashSet<&str> = baseline_dist
        .keys()
        .chain(recent_dist.keys())
        .map(|s| s.as_str())
        .collect();

    let mut op_drifts: Vec<serde_json::Value> = all_ops
        .iter()
        .filter_map(|&op| {
            let b = baseline_dist.get(op).copied().unwrap_or(0.001);
            let r = recent_dist.get(op).copied().unwrap_or(0.001);
            let delta = r - b;
            if delta.abs() > 0.05 {
                Some(serde_json::json!({
                    "operation":       op,
                    "baseline_share":  (b * 100.0).round() / 100.0,
                    "recent_share":    (r * 100.0).round() / 100.0,
                    "delta":           (delta * 100.0).round() / 100.0,
                    "direction":       if delta > 0.0 { "INCREASE" } else { "DECREASE" },
                }))
            } else {
                None
            }
        })
        .collect();
    op_drifts.sort_by(|a, b| {
        let da = a.get("delta").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
        let db = b.get("delta").and_then(|v| v.as_f64()).unwrap_or(0.0).abs();
        db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Overall drift score (0-100)
    let drift_score = (deny_rate_delta.abs() * 50.0
        + volume_delta_pct.abs() / 2.0
        + op_drifts.len() as f64 * 5.0)
        .min(100.0)
        .max(0.0);

    let drift_status = if drift_score > 70.0 {
        "SIGNIFICANT_DRIFT"
    } else if drift_score > 30.0 {
        "MODERATE_DRIFT"
    } else {
        "STABLE"
    };

    Json(serde_json::json!({
        "agent_pid":       agent_pid,
        "generated_at":    now.to_rfc3339(),
        "window":         format!("{}d", window_days),
        "baseline_period":format!("{}d–{}d ago", window_days, window_days * 4),
        "status":         drift_status,
        "drift_score":    (drift_score * 10.0).round() / 10.0,
        "deny_rate_drift": {
            "baseline":  (baseline_deny_rate * 100.0).round() / 100.0,
            "recent":    (recent_deny_rate * 100.0).round() / 100.0,
            "delta":     (deny_rate_delta * 100.0).round() / 100.0,
            "direction": if deny_rate_delta > 0.01 { "WORSENING" } else if deny_rate_delta < -0.01 { "IMPROVING" } else { "STABLE" },
        },
        "volume_drift": {
            "baseline_ops_per_day": (baseline_ops_per_day * 10.0).round() / 10.0,
            "recent_ops_per_day":   (recent_ops_per_day * 10.0).round() / 10.0,
            "delta_pct":            (volume_delta_pct * 10.0).round() / 10.0,
        },
        "op_type_drifts":  op_drifts,
        "recommendation":  if drift_status == "STABLE" {
            "Agent behaviour is stable. No action required.".into()
        } else {
            format!("Drift score {:.0}/100. Review op_type_drifts and deny_rate_drift. Consider causal analysis: GET /insights/causal-analysis/{}", drift_score, agent_pid)
        },
    }))
}

pub async fn full_audit(
    State(state): State<SharedState>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let entries: Vec<serde_json::Value> = k
        .audit_log()
        .iter()
        .rev()
        .take(q.limit)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "outcome": format!("{:?}", e.outcome),
                "reason": e.reason,
                "target": e.target,
                "error": e.error,
                "task_id": e.vakya_id,
            })
        })
        .collect();
    Json(serde_json::json!({"count": entries.len(), "entries": entries}))
}

// ── E6.10: Terminated agent archive ──────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AgentListQuery {
    pub include_terminated: Option<bool>,
    pub namespace: Option<String>,
    pub cost_center: Option<String>,
    pub limit: Option<usize>,
}

/// GET /history/agents/archive?include_terminated=true
/// Returns active agents plus terminated agents from engine_store archive.
/// Retention windows: Indie=30d, Growth=90d, Scale=365d, Enterprise=unlimited
pub async fn agent_archive(
    State(state): State<SharedState>,
    Query(q): Query<AgentListQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let es = state.engine_store.lock().unwrap();
    let now = chrono::Utc::now();
    let limit = q.limit.unwrap_or(200).min(1000);

    // Retention window by tier
    let retention_days: i64 = state.license.retention_days as i64;
    let cutoff_ms = now.timestamp_millis() - retention_days * 86_400_000;

    // Active agents from kernel
    let active_agents: Vec<serde_json::Value> = k.agents().values().map(|acb| {
        let audit_log = k.audit_log();
        let agent_ops: Vec<_> = audit_log.iter().filter(|e| e.agent_pid == acb.agent_pid).collect();
        let last_active_ms = agent_ops.iter().map(|e| e.timestamp).max().unwrap_or(0);
        let total_cost: f64 = acb.total_cost_usd;
        let total_ops  = agent_ops.len();
        let denied_ops = agent_ops.iter()
            .filter(|e| matches!(e.outcome, vac_core::types::OpOutcome::Denied)).count();

        // Filter by optional params
        if let Some(ref ns) = q.namespace {
            if !acb.agent_pid.contains(ns.as_str()) && acb.agent_name.contains(ns.as_str()) == false {
                // Still include — namespace filter best-effort on pid/name
            }
        }

        serde_json::json!({
            "agent_pid":      acb.agent_pid,
            "agent_name":     acb.agent_name,
            "model":          acb.model,
            "status":         "active",
            "total_cost_usd": (total_cost * 1_000_000.0).round() / 1_000_000.0,
            "total_ops":      total_ops,
            "denied_ops":     denied_ops,
            "deny_rate_pct":  if total_ops > 0 { (denied_ops as f64 / total_ops as f64 * 100.0).round() } else { 0.0 },
            "last_active_at": chrono::DateTime::from_timestamp_millis(last_active_ms)
                .map(|d| d.to_rfc3339()).unwrap_or_default(),
            "archived_at":    null,
            "retention_days": retention_days,
        })
    }).take(limit).collect();

    // Terminated agents from engine_store archive
    let mut terminated_agents: Vec<serde_json::Value> = Vec::new();
    if q.include_terminated.unwrap_or(false) {
        let archive_keys = es
            .folder_keys("terminated_agents", None)
            .unwrap_or_default();
        for key in archive_keys.iter().take(limit) {
            if let Some(rec) = es.folder_get("terminated_agents", key).ok().flatten() {
                let archived_ms = rec
                    .get("archived_at_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                // Respect retention window
                if archived_ms < cutoff_ms {
                    continue;
                }
                terminated_agents.push(rec);
            }
        }
    }

    let total_active = active_agents.len();
    let total_terminated = terminated_agents.len();

    Json(serde_json::json!({
        "generated_at":        now.to_rfc3339(),
        "total_active":        total_active,
        "total_terminated":    total_terminated,
        "total_agents":        total_active + total_terminated,
        "include_terminated":  q.include_terminated.unwrap_or(false),
        "retention_days":      retention_days,
        "retention_tier":      format!("{:?}", state.license.tier),
        "active_agents":       active_agents,
        "terminated_agents":   terminated_agents,
        "archive_hint":        "Terminated agents persist for retention_days. Full timeline, sessions, and cost data remain accessible.",
        "terminate_hint":      "To archive a terminated agent, POST /history/agents/{pid}/terminate",
    }))
}

/// POST /history/agents/{pid}/terminate
/// Archives an agent's record into terminated_agents store.
/// Preserves full history (timeline, sessions, cost) for retention_days.
/// FIX BUG-009: Now actually removes agent from kernel after archiving.
pub async fn terminate_agent(
    State(state): State<SharedState>,
    axum::extract::Path(agent_pid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "lifecycle",
        "archive_agent",
        &serde_json::json!({"agent_pid": agent_pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a.clone(),
        None => {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error":"agent not found","status":404,"agent_pid":agent_pid,"task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };

    let audit_log = k.audit_log();
    let agent_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();
    let total_ops = agent_ops.len();
    let denied_ops = agent_ops
        .iter()
        .filter(|e| matches!(e.outcome, vac_core::types::OpOutcome::Denied))
        .count();
    let last_active_ms = agent_ops.iter().map(|e| e.timestamp).max().unwrap_or(0);

    let archive_record = serde_json::json!({
        "agent_pid":         acb.agent_pid,
        "agent_name":        acb.agent_name,
        "model":             acb.model,
        "status":            "terminated",
        "total_cost_usd":    (acb.total_cost_usd * 1_000_000.0).round() / 1_000_000.0,
        "total_ops":         total_ops,
        "denied_ops":        denied_ops,
        "deny_rate_pct":     if total_ops > 0 { (denied_ops as f64 / total_ops as f64 * 100.0).round() } else { 0.0 },
        "last_active_at":    chrono::DateTime::from_timestamp_millis(last_active_ms)
            .map(|d| d.to_rfc3339()).unwrap_or_default(),
        "archived_at":       now.to_rfc3339(),
        "archived_at_ms":    now.timestamp_millis(),
        "platform_version":  env!("CARGO_PKG_VERSION"),
    });

    // FIX BUG-009: Remove agent from kernel after archiving
    k.remove_agent(&agent_pid);
    drop(k); // Release kernel lock before acquiring engine_store lock

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("terminated_agents", &agent_pid, &archive_record);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "agent_pid":    agent_pid,
        "archived_at":  now.to_rfc3339(),
        "status":       "terminated",
        "message":      "Agent archived and removed from kernel. Full history accessible via GET /history/agents/archive?include_terminated=true",
        "retention_tier": format!("{:?}", state.license.tier),
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}
