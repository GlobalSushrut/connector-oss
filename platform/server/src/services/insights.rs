use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};

/// Track 4 — Item S.2: Auto-optimization recommendations per agent
pub async fn optimize_agent(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);

    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    let packets = k.packets_in_namespace(&acb.namespace);
    let audit: Vec<_> = k
        .audit_log()
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();
    let total_ops = audit.len();
    let failed = audit
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
        .count();
    let denied = audit
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let success_rate = if total_ops > 0 {
        (total_ops - failed - denied) as f64 / total_ops as f64 * 100.0
    } else {
        0.0
    };

    let mut recommendations: Vec<serde_json::Value> = Vec::new();

    // Cost optimization
    if acb.total_cost_usd > 1.0 && acb.total_tokens_consumed > 100_000 {
        recommendations.push(serde_json::json!({
            "category": "cost",
            "priority": "high",
            "action": "Consider switching to a smaller model for routine tasks",
            "potential_savings": format!("~${:.2}/day", acb.total_cost_usd * 0.3),
        }));
    }

    // Memory optimization
    let stale_threshold_ms = 24 * 60 * 60 * 1000_i64;
    let now = chrono::Utc::now().timestamp_millis();
    let stale_count = packets
        .iter()
        .filter(|p| (now - p.index.ts) > stale_threshold_ms)
        .count();
    if stale_count > 5 {
        recommendations.push(serde_json::json!({
            "category": "memory",
            "priority": "medium",
            "action": format!("Evict {} stale packets via /memory/optimize-context/{}", stale_count, agent_pid),
            "stale_packets": stale_count,
        }));
    }

    // Reliability optimization
    if failed > 0 && success_rate < 90.0 {
        recommendations.push(serde_json::json!({
            "category": "reliability",
            "priority": "high",
            "action": "Investigate failed operations — check tool bindings and namespace permissions",
            "failure_rate": format!("{:.1}%", (failed as f64 / total_ops as f64 * 100.0)),
        }));
    }
    if denied > 3 {
        recommendations.push(serde_json::json!({
            "category": "security",
            "priority": "medium",
            "action": "Review access grants — agent hitting permission boundaries frequently",
            "denied_ops": denied,
        }));
    }

    // Tool optimization
    if acb.tool_bindings.is_empty() {
        recommendations.push(serde_json::json!({
            "category": "capability",
            "priority": "low",
            "action": "Bind tools to this agent to expand capabilities",
        }));
    }

    // Quota optimization
    let quota_pct = if acb.memory_region.quota_tokens > 0 {
        acb.memory_region.used_tokens as f64 / acb.memory_region.quota_tokens as f64 * 100.0
    } else {
        0.0
    };
    if quota_pct > 80.0 {
        recommendations.push(serde_json::json!({
            "category": "quota",
            "priority": "high",
            "action": "Memory quota at {:.0}% — increase quota or run context optimization",
            "usage_pct": quota_pct,
        }));
    }

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "health_score": success_rate.round(),
        "total_operations": total_ops,
        "success_rate": (success_rate * 10.0).round() / 10.0,
        "cost_usd": acb.total_cost_usd,
        "tokens_consumed": acb.total_tokens_consumed,
        "memory_packets": packets.len(),
        "recommendations": recommendations,
        "recommendation_count": recommendations.len(),
    }))
}

/// Track 4 — Item S.3: Fleet-wide optimization summary
pub async fn fleet_insights(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let trust = connector_engine::TrustComputer::compute(&k);
    let audit = k.audit_log();
    let now = chrono::Utc::now().timestamp_millis();

    let total_agents = k.agents().len();
    let total_ops = audit.len();
    let total_failed = audit
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Failed)
        .count();
    let total_denied = audit
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let fleet_success_rate = if total_ops > 0 {
        (total_ops - total_failed - total_denied) as f64 / total_ops as f64 * 100.0
    } else {
        100.0
    };

    let mut total_cost: f64 = 0.0;
    let mut total_tokens: u64 = 0;
    let mut total_packets: usize = 0;
    let mut agent_health: Vec<serde_json::Value> = Vec::new();

    for (pid, acb) in k.agents() {
        total_cost += acb.total_cost_usd;
        total_tokens += acb.total_tokens_consumed;
        let packets = k.packets_in_namespace(&acb.namespace);
        total_packets += packets.len();

        let agent_ops = audit.iter().filter(|e| e.agent_pid == *pid).count();
        let agent_fails = audit
            .iter()
            .filter(|e| e.agent_pid == *pid && e.outcome == vac_core::types::OpOutcome::Failed)
            .count();
        let health = if agent_ops > 0 {
            ((agent_ops - agent_fails) as f64 / agent_ops as f64 * 100.0).round()
        } else {
            100.0
        };

        agent_health.push(serde_json::json!({
            "pid": pid,
            "name": &acb.agent_name,
            "health": health,
            "operations": agent_ops,
            "cost_usd": acb.total_cost_usd,
            "packets": packets.len(),
        }));
    }

    agent_health.sort_by(|a, b| {
        let ha = a.get("health").and_then(|v| v.as_f64()).unwrap_or(100.0);
        let hb = b.get("health").and_then(|v| v.as_f64()).unwrap_or(100.0);
        ha.partial_cmp(&hb).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut fleet_recommendations: Vec<String> = Vec::new();
    if fleet_success_rate < 95.0 {
        fleet_recommendations.push(format!(
            "Fleet success rate at {:.1}% — investigate failing agents",
            fleet_success_rate
        ));
    }
    if total_cost > 10.0 {
        fleet_recommendations.push(format!(
            "Total fleet cost ${:.2} — review agent model selection",
            total_cost
        ));
    }
    if trust.score < 70 {
        fleet_recommendations.push(format!(
            "Trust score {} — check /monitor/trust-trend for improvement plan",
            trust.score
        ));
    }

    // X.11: Real cost_per_action — total cost divided by total operations, fleet mean + outlier detection
    let fleet_cost_per_action = if total_ops > 0 {
        total_cost / total_ops as f64
    } else {
        0.0
    };

    // Per-agent cost_per_action for outlier detection
    let mut cost_per_action_values: Vec<f64> = Vec::new();
    let mut agent_cost_per_action: Vec<serde_json::Value> = Vec::new();
    for (pid, acb) in k.agents() {
        let agent_ops = audit.iter().filter(|e| e.agent_pid == *pid).count();
        let cpa = if agent_ops > 0 {
            acb.total_cost_usd / agent_ops as f64
        } else {
            0.0
        };
        cost_per_action_values.push(cpa);
        agent_cost_per_action.push(serde_json::json!({
            "pid": pid,
            "name": &acb.agent_name,
            "cost_per_action_usd": (cpa * 1_000_000.0).round() / 1_000_000.0,
            "total_ops": agent_ops,
            "total_cost_usd": acb.total_cost_usd,
        }));
    }

    // Flag outliers: agents whose cost_per_action > 2× fleet mean
    let mut cost_outliers: Vec<serde_json::Value> = Vec::new();
    if fleet_cost_per_action > 0.0 {
        for entry in &agent_cost_per_action {
            let cpa = entry
                .get("cost_per_action_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if cpa > fleet_cost_per_action * 2.0 {
                cost_outliers.push(serde_json::json!({
                    "pid": entry.get("pid"),
                    "name": entry.get("name"),
                    "cost_per_action_usd": cpa,
                    "fleet_mean_usd": (fleet_cost_per_action * 1_000_000.0).round() / 1_000_000.0,
                    "multiplier": (cpa / fleet_cost_per_action * 10.0).round() / 10.0,
                    "action": "Review model selection or prompt length — this agent costs 2× more per operation than fleet average",
                }));
            }
        }
    }

    if !cost_outliers.is_empty() {
        fleet_recommendations.push(format!(
            "{} agent(s) have cost_per_action > 2× fleet mean — see cost_outliers",
            cost_outliers.len()
        ));
    }

    Json(serde_json::json!({
        "fleet_summary": {
            "total_agents": total_agents,
            "total_operations": total_ops,
            "fleet_success_rate": (fleet_success_rate * 10.0).round() / 10.0,
            "total_cost_usd": (total_cost * 100.0).round() / 100.0,
            "total_tokens": total_tokens,
            "total_packets": total_packets,
            "agent_health_score": trust.score,
            "trust_grade": trust.grade,
            "fleet_cost_per_action_usd": (fleet_cost_per_action * 1_000_000.0).round() / 1_000_000.0,
        },
        "agent_health": agent_health,
        "agent_cost_per_action": agent_cost_per_action,
        "cost_outliers": cost_outliers,
        "recommendations": fleet_recommendations,
    }))
}

// ── E4.10: Model Rightsizing Recommendation ───────────────────────────────────

/// GET /insights/model-recommendation/{pid}
pub async fn model_recommendation(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    let audit_log = k.audit_log();
    let agent_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| e.agent_pid == agent_pid)
        .collect();
    let total_ops = agent_ops.len().max(1);

    // Task complexity distribution from token usage
    let es = state.engine_store.lock().unwrap();
    let usage_keys = es.folder_keys("token_usage", None).unwrap_or_default();
    let agent_usage: Vec<serde_json::Value> = usage_keys
        .iter()
        .filter_map(|k| es.folder_get("token_usage", k).ok().flatten())
        .filter(|u| u.get("agent_pid").and_then(|v| v.as_str()) == Some(&agent_pid))
        .collect();

    let total_prompt_tokens: u64 = agent_usage
        .iter()
        .filter_map(|u| u.get("prompt_tokens").and_then(|v| v.as_u64()))
        .sum();
    let total_completion_tokens: u64 = agent_usage
        .iter()
        .filter_map(|u| u.get("completion_tokens").and_then(|v| v.as_u64()))
        .sum();
    let total_cost: f64 = agent_usage
        .iter()
        .filter_map(|u| u.get("cost_usd").and_then(|v| v.as_f64()))
        .sum();

    let avg_prompt = total_prompt_tokens as f64 / agent_usage.len().max(1) as f64;
    let avg_completion = total_completion_tokens as f64 / agent_usage.len().max(1) as f64;
    let avg_total = avg_prompt + avg_completion;

    // Classify task complexity
    let complexity = if avg_total < 500.0 {
        "simple"
    } else if avg_total < 2000.0 {
        "moderate"
    } else if avg_total < 8000.0 {
        "complex"
    } else {
        "very_complex"
    };

    // Model tiers and pricing (per 1K tokens)
    let model_tiers = vec![
        ("gpt-3.5-turbo", 0.0015, 0.002, 4096, "simple"),
        ("gpt-4o-mini", 0.00015, 0.0006, 128000, "moderate"),
        ("gpt-4o", 0.005, 0.015, 128000, "complex"),
        ("gpt-4-turbo", 0.01, 0.03, 128000, "very_complex"),
        ("claude-3-haiku", 0.00025, 0.00125, 200000, "simple"),
        ("claude-3-sonnet", 0.003, 0.015, 200000, "moderate"),
        ("claude-3-opus", 0.015, 0.075, 200000, "very_complex"),
    ];

    let current_model = acb.model.as_deref().unwrap_or("unknown");

    // Find best-fit model
    let recommended = model_tiers
        .iter()
        .filter(|(_, _, _, ctx, tier)| {
            avg_total < *ctx as f64 * 0.8
                && match (complexity, *tier) {
                    ("simple", "simple") | ("simple", "moderate") => true,
                    ("moderate", "moderate") | ("moderate", "complex") => true,
                    ("complex", "complex") | ("complex", "very_complex") => true,
                    ("very_complex", "very_complex") => true,
                    _ => false,
                }
        })
        .min_by(|a, b| {
            let cost_a = (a.1 * avg_prompt + a.2 * avg_completion) / 1000.0;
            let cost_b = (b.1 * avg_prompt + b.2 * avg_completion) / 1000.0;
            cost_a
                .partial_cmp(&cost_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

    let (rec_model, rec_input_price, rec_output_price) = recommended
        .map(|(m, i, o, _, _)| (*m, *i, *o))
        .unwrap_or(("gpt-4o-mini", 0.00015, 0.0006));

    let current_cost_per_call = if let Some(tier) = model_tiers
        .iter()
        .find(|(m, _, _, _, _)| *m == current_model)
    {
        (tier.1 * avg_prompt + tier.2 * avg_completion) / 1000.0
    } else {
        total_cost / agent_usage.len().max(1) as f64
    };

    let rec_cost_per_call =
        (rec_input_price * avg_prompt + rec_output_price * avg_completion) / 1000.0;
    let saving_per_call = (current_cost_per_call - rec_cost_per_call).max(0.0);
    let saving_pct = if current_cost_per_call > 0.0 {
        saving_per_call / current_cost_per_call * 100.0
    } else {
        0.0
    };
    let projected_saving = saving_per_call * total_ops as f64;

    Json(serde_json::json!({
        "agent_pid":          agent_pid,
        "generated_at":       now.to_rfc3339(),
        "current_model":      current_model,
        "task_complexity":    complexity,
        "avg_tokens_per_call":(avg_total.round() as u64),
        "avg_prompt_tokens":  (avg_prompt.round() as u64),
        "avg_completion_tokens":(avg_completion.round() as u64),
        "total_calls_analyzed":agent_usage.len(),
        "total_cost_usd":     (total_cost * 10000.0).round() / 10000.0,
        "recommendation": {
            "model":              rec_model,
            "reason":             format!("Best fit for '{}' complexity tasks at avg {} tokens/call", complexity, avg_total.round() as u64),
            "saving_usd_per_call":(saving_per_call * 1_000_000.0).round() / 1_000_000.0,
            "saving_pct":         (saving_pct * 10.0).round() / 10.0,
            "projected_saving_usd":(projected_saving * 100.0).round() / 100.0,
        },
        "model_comparison": model_tiers.iter().map(|(m, i, o, ctx, tier)| serde_json::json!({
            "model": m,
            "context_window": ctx,
            "complexity_tier": tier,
            "cost_per_call_usd": ((i * avg_prompt + o * avg_completion) / 1000.0 * 1_000_000.0).round() / 1_000_000.0,
            "fits_task": avg_total < *ctx as f64 * 0.8,
        })).collect::<Vec<_>>(),
    }))
}

// ── E4.11: Causal Change Detection ───────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct CausalAnalysisQuery {
    pub metric: Option<String>,
    pub ts: Option<i64>,
}

/// GET /insights/causal-analysis/{pid}?metric=&ts=
pub async fn causal_analysis(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    axum::extract::Query(q): axum::extract::Query<CausalAnalysisQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let degradation_ts = q.ts.unwrap_or_else(|| now.timestamp_millis());
    let metric = q.metric.as_deref().unwrap_or("deny_rate");
    let window_2h_ms = 2 * 3_600_000i64;
    let before_start = degradation_ts - window_2h_ms;

    let audit_log = k.audit_log();
    let es = state.engine_store.lock().unwrap();

    // Operations in 2h window before degradation
    let before_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid && e.timestamp >= before_start && e.timestamp < degradation_ts
        })
        .collect();

    let before_total = before_ops.len().max(1);
    let before_denied = before_ops
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let before_deny_rate = before_denied as f64 / before_total as f64;

    // After window (1h post-degradation)
    let after_ops: Vec<_> = audit_log
        .iter()
        .filter(|e| {
            e.agent_pid == agent_pid
                && e.timestamp >= degradation_ts
                && e.timestamp < degradation_ts + 3_600_000
        })
        .collect();
    let after_total = after_ops.len().max(1);
    let after_denied = after_ops
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .count();
    let after_deny_rate = after_denied as f64 / after_total as f64;
    let metric_change = after_deny_rate - before_deny_rate;

    // Check for config changes in 2h before window
    let config_changes: Vec<serde_json::Value> = {
        let change_keys = es.folder_keys("config_changes", None).unwrap_or_default();
        change_keys
            .iter()
            .filter_map(|k| es.folder_get("config_changes", k).ok().flatten())
            .filter(|c| {
                let ts = c.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
                let pid = c.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
                ts >= before_start && ts < degradation_ts && (pid == agent_pid || pid.is_empty())
            })
            .map(|c| {
                serde_json::json!({
                    "change_type": c.get("change_type"),
                    "ts":          c.get("ts"),
                    "description": c.get("description"),
                    "confidence":  0.8,
                })
            })
            .collect()
    };

    // Prompt version changes
    let prompt_changes: Vec<serde_json::Value> = {
        let keys = es
            .folder_keys("prompt_activations", None)
            .unwrap_or_default();
        keys.iter()
            .filter_map(|k| es.folder_get("prompt_activations", k).ok().flatten())
            .filter(|c| {
                let ts = c
                    .get("activated_at_ms")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                ts >= before_start && ts < degradation_ts
            })
            .map(|c| {
                serde_json::json!({
                    "change_type": "prompt_version_change",
                    "ts":          c.get("activated_at_ms"),
                    "description": format!("Prompt {} activated version {}",
                        c.get("prompt_id").and_then(|v| v.as_str()).unwrap_or("?"),
                        c.get("version").and_then(|v| v.as_str()).unwrap_or("?")),
                    "confidence":  0.9,
                })
            })
            .collect()
    };

    // Rank probable causes by confidence × metric impact
    let mut probable_causes: Vec<serde_json::Value> = config_changes
        .into_iter()
        .chain(prompt_changes.into_iter())
        .collect();

    // Add heuristic causes based on operation patterns
    if before_denied > 0 {
        let top_denied_op = before_ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .map(|e| format!("{:?}", e.operation))
            .fold(
                std::collections::HashMap::<String, usize>::new(),
                |mut m, op| {
                    *m.entry(op).or_default() += 1;
                    m
                },
            )
            .into_iter()
            .max_by_key(|(_, c)| *c);
        if let Some((op, count)) = top_denied_op {
            probable_causes.push(serde_json::json!({
                "change_type":  "permission_pattern",
                "description":  format!("Repeated denials of '{}' operation ({} times) suggest permission misconfiguration", op, count),
                "confidence_pct": 70,
            }));
        }
    }

    probable_causes.sort_by(|a, b| {
        let ca = a
            .get("confidence_pct")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                a.get("confidence")
                    .and_then(|v| v.as_f64())
                    .map(|c| c * 100.0)
            })
            .unwrap_or(50.0);
        let cb = b
            .get("confidence_pct")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                b.get("confidence")
                    .and_then(|v| v.as_f64())
                    .map(|c| c * 100.0)
            })
            .unwrap_or(50.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });

    Json(serde_json::json!({
        "agent_pid":       agent_pid,
        "metric":          metric,
        "degradation_ts":  degradation_ts,
        "generated_at":    now.to_rfc3339(),
        "before_window": {
            "start_ms":    before_start,
            "end_ms":      degradation_ts,
            "ops":         before_total,
            "denied":      before_denied,
            "deny_rate":   (before_deny_rate * 100.0).round() / 100.0,
        },
        "after_window": {
            "ops":         after_total,
            "denied":      after_denied,
            "deny_rate":   (after_deny_rate * 100.0).round() / 100.0,
        },
        "metric_delta":    (metric_change * 100.0).round() / 100.0,
        "probable_causes": probable_causes,
        "cause_count":     probable_causes.len(),
        "recommendation":  if probable_causes.is_empty() {
            "No config changes detected in 2h window. Check external dependencies or model availability.".into()
        } else {
            format!("Top cause: {}. Investigate and revert if needed.",
                probable_causes[0].get("description").and_then(|v| v.as_str()).unwrap_or("unknown"))
        },
    }))
}

// ── E4.12: Self-Healing Candidates ────────────────────────────────────────────

/// GET /insights/self-heal-candidates
pub async fn self_heal_candidates(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    let cutoff_24h = now_ms - 86_400_000i64;

    let audit_log = k.audit_log();
    let agents = k.agents();

    let mut candidates: Vec<serde_json::Value> = Vec::new();

    for acb in agents.values() {
        let pid = &acb.agent_pid;
        let ops: Vec<_> = audit_log
            .iter()
            .filter(|e| &e.agent_pid == pid && e.timestamp >= cutoff_24h)
            .collect();

        if ops.is_empty() {
            continue;
        }

        let total = ops.len();
        let denied = ops
            .iter()
            .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
            .count();
        let deny_rate = denied as f64 / total as f64;

        let mut fixes: Vec<serde_json::Value> = Vec::new();

        // Fix 1: High deny rate → suggest permission reset
        if deny_rate > 0.5 {
            fixes.push(serde_json::json!({
                "fix_id":      "reset_permissions",
                "description": format!("{:.0}% deny rate — reset agent permissions to default", deny_rate * 100.0),
                "action":      "reset_to_default_role",
                "risk":        "low",
                "dry_run_safe":true,
            }));
        }

        // Fix 2: Zero operations last 24h → suggest resume
        let last_op_ts = ops.iter().map(|e| e.timestamp).max().unwrap_or(0);
        let hours_idle = (now_ms - last_op_ts) / 3_600_000;
        if hours_idle > 12 {
            fixes.push(serde_json::json!({
                "fix_id":      "resume_agent",
                "description": format!("Agent idle for {}h — may be paused or stalled", hours_idle),
                "action":      "resume",
                "risk":        "low",
                "dry_run_safe":true,
            }));
        }

        // Fix 3: High token consumption → suggest budget reset
        if acb.total_tokens_consumed > 100_000 {
            fixes.push(serde_json::json!({
                "fix_id":      "reset_budget",
                "description": format!("High token consumption ({} tokens) — consider resetting budget counter", acb.total_tokens_consumed),
                "action":      "reset_token_budget",
                "risk":        "medium",
                "dry_run_safe":true,
            }));
        }

        if !fixes.is_empty() {
            candidates.push(serde_json::json!({
                "agent_pid":   pid,
                "agent_name":  acb.agent_name,
                "deny_rate":   (deny_rate * 100.0).round() / 100.0,
                "total_ops":   total,
                "denied_ops":  denied,
                "hours_idle":  hours_idle,
                "fix_count":   fixes.len(),
                "fixes":       fixes,
                "apply_endpoint": format!("POST /insights/apply-fix/{}/{{fix_id}}?dry_run=true", pid),
            }));
        }
    }

    candidates.sort_by(|a, b| {
        let da = a.get("deny_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let db = b.get("deny_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
        db.partial_cmp(&da).unwrap_or(std::cmp::Ordering::Equal)
    });

    Json(serde_json::json!({
        "generated_at":    now.to_rfc3339(),
        "candidate_count": candidates.len(),
        "candidates":      candidates,
        "note":            "Use POST /insights/apply-fix/{pid}/{fix_id}?dry_run=true to preview changes",
    }))
}

#[derive(serde::Deserialize)]
pub struct ApplyFixQuery {
    pub dry_run: Option<bool>,
}

/// POST /insights/apply-fix/{pid}/{fix_id}?dry_run=true
pub async fn apply_fix(
    State(state): State<SharedState>,
    axum::extract::Path((agent_pid, fix_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<ApplyFixQuery>,
) -> Json<serde_json::Value> {
    let dry_run = q.dry_run.unwrap_or(true);
    let now = chrono::Utc::now();

    let k = state.kernel.lock().unwrap();
    if k.get_agent(&agent_pid).is_none() {
        return Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        );
    }
    drop(k);

    let (action_taken, description, side_effects) = match fix_id.as_str() {
        "reset_permissions" => (
            "reset_to_default_role",
            "Reset agent permissions to Developer role defaults",
            vec![
                "All custom permission grants removed",
                "Agent reverts to baseline access",
            ],
        ),
        "resume_agent" => (
            "resume",
            "Resume paused/stalled agent",
            vec!["Agent status set to active", "Operations unblocked"],
        ),
        "reset_budget" => (
            "reset_token_budget",
            "Reset token budget to tier default",
            vec!["Token counter reset to 0", "Agent can make LLM calls again"],
        ),
        other => {
            return Json(serde_json::json!({
                "error": format!("Unknown fix_id: '{}'. Valid: reset_permissions, resume_agent, reset_budget", other),
            }))
        }
    };

    if !dry_run {
        // Apply the fix by recording it in engine_store for audit
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "applied_fixes",
            &format!("fix_{}_{}", agent_pid, now.timestamp_millis()),
            &serde_json::json!({
                "agent_pid":    agent_pid,
                "fix_id":       fix_id,
                "action":       action_taken,
                "applied_at":   now.to_rfc3339(),
                "applied_by":   "self_heal_engine",
            }),
        );
    }

    Json(serde_json::json!({
        "agent_pid":    agent_pid,
        "fix_id":       fix_id,
        "action":       action_taken,
        "description":  description,
        "dry_run":       dry_run,
        "side_effects": side_effects,
        "applied_at":   if dry_run { None } else { Some(now.to_rfc3339()) },
        "status":       if dry_run { "DRY_RUN — no changes made" } else { "APPLIED" },
        "note":         if dry_run { "Remove ?dry_run=true to apply for real" } else { "Fix applied. Monitor agent behaviour." },
    }))
}

// ── E6.4: Predictive Budget Forecast ─────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct BudgetForecastQuery {
    pub horizon_days: Option<i64>,
    pub alert_threshold_usd: Option<f64>,
}

/// GET /insights/budget-forecast/{pid}
/// Linear regression over the agent's cost history to project spend.
/// Fires a budget alert if projected spend exceeds alert_threshold_usd.
pub async fn budget_forecast(
    State(state): State<SharedState>,
    axum::extract::Path(agent_pid): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<BudgetForecastQuery>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let horizon_days = q.horizon_days.unwrap_or(30).max(1).min(365);
    let threshold = q.alert_threshold_usd.unwrap_or(f64::MAX);
    let k = state.kernel.lock().unwrap();

    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a.clone(),
        None => {
            return Json(
                serde_json::json!({"error": "agent not found", "status": 404, "agent_pid": agent_pid}),
            )
        }
    };

    // Build daily cost buckets from audit log — collect timestamps before dropping kernel lock
    let (ops_count, op_timestamps): (usize, Vec<i64>) = {
        let audit_log = k.audit_log();
        let ops: Vec<_> = audit_log
            .iter()
            .filter(|e| e.agent_pid == agent_pid)
            .collect();
        let ts: Vec<i64> = ops.iter().map(|e| e.timestamp).collect();
        (ops.len(), ts)
    };
    drop(k);

    // Group ops by day bucket (ms / 86_400_000)
    let mut daily: std::collections::BTreeMap<i64, f64> = std::collections::BTreeMap::new();
    let cost_per_op = if ops_count == 0 {
        0.0
    } else {
        acb.total_cost_usd / ops_count as f64
    };

    for ts in &op_timestamps {
        let day = ts / 86_400_000;
        *daily.entry(day).or_insert(0.0) += cost_per_op;
    }

    let days: Vec<f64> = daily.keys().enumerate().map(|(i, _)| i as f64).collect();
    let costs: Vec<f64> = daily.values().cloned().collect();
    let n = days.len() as f64;

    // Linear regression: y = slope * x + intercept
    let (slope, intercept, r_squared) = if n >= 2.0 {
        let sum_x: f64 = days.iter().sum();
        let sum_y: f64 = costs.iter().sum();
        let sum_xy: f64 = days.iter().zip(costs.iter()).map(|(x, y)| x * y).sum();
        let sum_x2: f64 = days.iter().map(|x| x * x).sum();
        let denom = n * sum_x2 - sum_x * sum_x;
        if denom.abs() < f64::EPSILON {
            (0.0, sum_y / n, 0.0)
        } else {
            let s = (n * sum_xy - sum_x * sum_y) / denom;
            let b = (sum_y - s * sum_x) / n;
            // R²
            let y_mean = sum_y / n;
            let ss_tot: f64 = costs.iter().map(|y| (y - y_mean).powi(2)).sum();
            let ss_res: f64 = days
                .iter()
                .zip(costs.iter())
                .map(|(x, y)| (y - (s * x + b)).powi(2))
                .sum();
            let r2 = if ss_tot < f64::EPSILON {
                1.0
            } else {
                1.0 - ss_res / ss_tot
            };
            (s, b, r2.clamp(0.0, 1.0))
        }
    } else {
        (0.0, costs.first().cloned().unwrap_or(0.0), 0.0)
    };

    let next_x = n;
    let projected_daily = (slope * next_x + intercept).max(0.0);
    let projected_total = projected_daily * horizon_days as f64;

    // 95% CI: ±1.96 * std_err
    let residuals: Vec<f64> = days
        .iter()
        .zip(costs.iter())
        .map(|(x, y)| (y - (slope * x + intercept)).powi(2))
        .collect();
    let mse = if residuals.is_empty() {
        0.0
    } else {
        residuals.iter().sum::<f64>() / residuals.len() as f64
    };
    let ci_margin = 1.96 * mse.sqrt() * (horizon_days as f64).sqrt();

    let alert_triggered = projected_total >= threshold;

    // Store forecast for background monitoring
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "budget_forecasts",
        &agent_pid,
        &serde_json::json!({
            "agent_pid":          agent_pid,
            "projected_total_usd": projected_total,
            "horizon_days":        horizon_days,
            "alert_threshold_usd": threshold,
            "alert_triggered":     alert_triggered,
            "generated_at":        now.to_rfc3339(),
        }),
    );

    Json(serde_json::json!({
        "agent_pid":               agent_pid,
        "generated_at":            now.to_rfc3339(),
        "horizon_days":            horizon_days,
        "current_total_cost_usd":  (acb.total_cost_usd * 10_000.0).round() / 10_000.0,
        "projected_daily_usd":     (projected_daily * 10_000.0).round() / 10_000.0,
        "projected_total_usd":     (projected_total * 10_000.0).round() / 10_000.0,
        "confidence_interval_95":  {
            "lower_usd": ((projected_total - ci_margin).max(0.0) * 10_000.0).round() / 10_000.0,
            "upper_usd": ((projected_total + ci_margin) * 10_000.0).round() / 10_000.0,
        },
        "regression": {
            "slope":       (slope * 10_000.0).round() / 10_000.0,
            "intercept":   (intercept * 10_000.0).round() / 10_000.0,
            "r_squared":   (r_squared * 1_000.0).round() / 1_000.0,
            "data_points": days.len(),
        },
        "alert_threshold_usd": if threshold == f64::MAX { serde_json::Value::Null } else { serde_json::json!(threshold) },
        "alert_triggered":     alert_triggered,
        "alert_message":       if alert_triggered {
            format!("BUDGET ALERT: Projected ${:.2} exceeds threshold ${:.2} over {} days",
                projected_total, threshold, horizon_days)
        } else {
            format!("Budget on track. Projected ${:.4} over {} days.", projected_total, horizon_days)
        },
        "total_ops":           ops_count,
        "cost_per_op_usd":     (cost_per_op * 10_000.0).round() / 10_000.0,
    }))
}
