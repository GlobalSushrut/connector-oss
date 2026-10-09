use axum::{extract::State, Json};
use crate::SharedState;
use crate::database::*;
use crate::persist::Db;

// ═══════════════════════════════════════════════════════════════
// RPC Endpoints — called by deployed binaries (phone-home)
// ═══════════════════════════════════════════════════════════════

/// RPC 1: Binary startup check-in
/// Called when a connector-platform binary starts. Reports its embedded
/// identity and gets back permission flags + payment status.
pub async fn rpc_checkin(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let key_id = req.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    let machine_id = req.get("machine_id").and_then(|v| v.as_str()).unwrap_or("");
    let binary_hash = req.get("binary_hash").and_then(|v| v.as_str()).unwrap_or("");
    let binary_id = req.get("binary_id").and_then(|v| v.as_str()).unwrap_or("");
    let hostname = req.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
    let version = req.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0");

    let now = chrono::Utc::now();
    let mut db = state.surveillance_db.lock().unwrap();
    let store = state.store.lock().unwrap();

    // Validate key
    let key = store.get_key(key_id);
    let key_valid = key.map_or(false, |k| !k.revoked);
    let tier = key.map(|k| format!("{:?}", k.tier)).unwrap_or_default();

    // Check blocked binaries
    if db.is_binary_blocked(binary_hash) {
        db.log_event(SurveillanceEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            instance_id: instance_id.to_string(),
            event_type: SurveillanceEventType::TamperDetected,
            timestamp: now.to_rfc3339(),
            details: serde_json::json!({"binary_hash": binary_hash, "reason": "blocked_hash"}),
        });
        return Json(serde_json::json!({
            "allowed": false,
            "command": "shutdown",
            "reason": "Binary hash is blocked",
        }));
    }

    // Check payment status — clone needed data to release borrow
    let (payment_ok, payment_status, customer_id_opt, customer_email) = {
        let customer = db.get_customer_by_key(key_id);
        let ok = customer.map_or(true, |c| {
            c.payment_status == PaymentStatus::Active || c.payment_status == PaymentStatus::Trial
        });
        let status = customer.map(|c| format!("{:?}", c.payment_status))
            .unwrap_or_else(|| "Unknown".into());
        let cid = customer.map(|c| c.customer_id.clone());
        let email = customer.map(|c| c.email.clone()).unwrap_or_else(|| "unknown".into());
        let is_past_due = customer.map_or(false, |c| c.payment_status == PaymentStatus::PastDue);
        (ok, status, cid, email)
    };

    // Re-check for grace (past_due) without holding borrow
    let is_past_due = {
        let customer = db.get_customer_by_key(key_id);
        customer.map_or(false, |c| c.payment_status == PaymentStatus::PastDue)
    };

    // Determine command
    let (command, permissions) = if !key_valid {
        ("shutdown".to_string(), vec![])
    } else if !payment_ok {
        if is_past_due {
            ("degrade".to_string(), vec!["read_only".to_string()])
        } else {
            ("shutdown".to_string(), vec![])
        }
    } else {
        let perms = match tier.as_str() {
            "Sovereign" | "Core" => vec!["full", "air_gap", "on_premise", "unlimited"],
            "Enterprise" => vec!["full", "unlimited"],
            "Scale" => vec!["full", "multi_cell"],
            "Business" => vec!["full", "sso", "judgment"],
            "Growth" => vec!["standard", "multi_agent", "rag"],
            "Startup" => vec!["standard", "experiments", "knowledge_graph"],
            _ => vec!["basic"],
        }.into_iter().map(String::from).collect();
        ("continue".to_string(), perms)
    };

    // Update or create instance record
    if let Some(inst) = db.get_instance_mut(instance_id) {
        inst.last_heartbeat = Some(now.to_rfc3339());
        inst.binary_hash = binary_hash.to_string();
        inst.hostname = hostname.to_string();
        if command == "shutdown" {
            inst.status = InstanceStatus::Suspended;
            inst.kill_issued = true;
        } else if command == "degrade" {
            inst.status = InstanceStatus::Degraded;
        } else {
            inst.status = InstanceStatus::Active;
        }
    } else if !instance_id.is_empty() {
        let customer_id = customer_id_opt.clone().unwrap_or_default();
        db.upsert_instance(InstanceRecord {
            instance_id: instance_id.to_string(),
            key_id: key_id.to_string(),
            customer_id,
            machine_id: machine_id.to_string(),
            hostname: hostname.to_string(),
            binary_hash: binary_hash.to_string(),
            binary_id: binary_id.to_string(),
            license_address: "self".to_string(),
            tier: tier.clone(),
            permissions: permissions.clone(),
            activated_at: now.to_rfc3339(),
            last_heartbeat: Some(now.to_rfc3339()),
            last_usage_report: None,
            status: if command == "continue" { InstanceStatus::Active } else { InstanceStatus::Suspended },
            agents_last: 0,
            packets_last: 0,
            trust_score_last: 0,
            total_tokens_lifetime: 0,
            total_cost_lifetime: 0.0,
            warnings_issued: 0,
            grace_period_ends: None,
            kill_issued: command == "shutdown",
        });
    }

    let event = SurveillanceEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        instance_id: instance_id.to_string(),
        event_type: SurveillanceEventType::Heartbeat,
        timestamp: now.to_rfc3339(),
        details: serde_json::json!({
            "version": version, "machine_id": machine_id,
            "command": &command, "payment_status": &payment_status,
        }),
    };
    db.log_event(event.clone());

    if let Some(inst) = db.get_instance(instance_id) {
        let inst_clone = inst.clone();
        let db2 = state.db.clone();
        tokio::spawn(async move { db2.upsert_instance(&inst_clone).await; });
    }
    {
        let ev_clone = event.clone();
        let db3 = state.db.clone();
        tokio::spawn(async move { db3.log_event(&ev_clone).await; });
    }

    // Sign the response so binary can verify it's from real server
    let response_payload = format!("{}:{}:{}:{}", instance_id, command, now.timestamp(), tier);
    let signature = state.signing_key.sign(response_payload.as_bytes());

    Json(serde_json::json!({
        "allowed": command != "shutdown",
        "command": command,
        "instance_id": instance_id,
        "tier": tier,
        "permissions": permissions,
        "payment_status": payment_status,
        "next_checkin_secs": 3600,
        "server_time": now.to_rfc3339(),
        "signature": signature,
        "banner": format!("Connector Platform [{}] — Licensed to {}", tier, customer_email),
    }))
}

/// RPC 2: Periodic heartbeat from running binary
/// Reports usage metrics — agents, packets, tokens, cost
pub async fn rpc_heartbeat(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let key_id = req.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
    let agents = req.get("agents").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let packets = req.get("packets").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let trust_score = req.get("trust_score").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let tokens = req.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let cost = req.get("total_cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let binary_hash = req.get("binary_hash").and_then(|v| v.as_str()).unwrap_or("");

    let now = chrono::Utc::now();
    let mut db = state.surveillance_db.lock().unwrap();
    let store = state.store.lock().unwrap();

    // Check key validity
    let key = store.get_key(key_id);
    let key_valid = key.map_or(false, |k| !k.revoked);
    let tier = key.map(|k| k.tier).unwrap_or(crate::types::Tier::Indie);

    // Check limits
    let agents_over = tier.max_agents().map_or(false, |max| agents as usize > max);
    let events_over = tier.max_events().map_or(false, |max| packets as usize > max);

    // Determine command
    let mut command = "continue".to_string();
    let mut warnings: Vec<String> = Vec::new();

    if !key_valid {
        command = "shutdown".to_string();
    }

    if db.is_binary_blocked(binary_hash) {
        command = "shutdown".to_string();
        warnings.push("Binary hash blocked".into());
    }

    // Check customer payment
    let customer = db.get_customer_by_key(key_id);
    if let Some(c) = customer {
        match c.payment_status {
            PaymentStatus::Suspended | PaymentStatus::Cancelled => {
                command = "shutdown".to_string();
                warnings.push("Payment cancelled/suspended".into());
            }
            PaymentStatus::PastDue | PaymentStatus::Delinquent => {
                command = "degrade".to_string();
                warnings.push("Payment past due — features degraded".into());
            }
            _ => {}
        }
    }

    if agents_over {
        warnings.push(format!("Over agent limit: {} (max: {:?})", agents, tier.max_agents()));
    }
    if events_over {
        warnings.push(format!("Over event limit: {} (max: {:?})", packets, tier.max_events()));
    }

    // Update instance
    if let Some(inst) = db.get_instance_mut(instance_id) {
        inst.last_heartbeat = Some(now.to_rfc3339());
        inst.agents_last = agents;
        inst.packets_last = packets;
        inst.trust_score_last = trust_score;
        inst.total_tokens_lifetime = tokens;
        inst.total_cost_lifetime = cost;
        if command == "shutdown" {
            inst.status = InstanceStatus::Suspended;
            inst.kill_issued = true;
        } else if command == "degrade" {
            inst.status = InstanceStatus::Degraded;
            inst.warnings_issued += 1;
        }
    }

    db.log_event(SurveillanceEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        instance_id: instance_id.to_string(),
        event_type: SurveillanceEventType::Heartbeat,
        timestamp: now.to_rfc3339(),
        details: serde_json::json!({
            "agents": agents, "packets": packets, "trust_score": trust_score,
            "tokens": tokens, "cost": cost, "command": &command,
        }),
    });

    let sig_payload = format!("{}:{}:{}:{}", instance_id, command, now.timestamp(), agents);
    let signature = state.signing_key.sign(sig_payload.as_bytes());

    Json(serde_json::json!({
        "ack": true,
        "command": command,
        "warnings": warnings,
        "next_heartbeat_secs": if command == "degrade" { 600 } else { 3600 },
        "server_time": now.to_rfc3339(),
        "signature": signature,
    }))
}

/// RPC 3: Usage data push from binary
pub async fn rpc_usage(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let now = chrono::Utc::now();

    let mut db = state.surveillance_db.lock().unwrap();
    if let Some(inst) = db.get_instance_mut(instance_id) {
        inst.last_usage_report = Some(now.to_rfc3339());
        inst.agents_last = req.get("agents").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        inst.packets_last = req.get("packets").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        inst.total_tokens_lifetime = req.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
        inst.total_cost_lifetime = req.get("total_cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
    }

    db.log_event(SurveillanceEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        instance_id: instance_id.to_string(),
        event_type: SurveillanceEventType::UsageReport,
        timestamp: now.to_rfc3339(),
        details: req.clone(),
    });

    Json(serde_json::json!({"recorded": true, "instance_id": instance_id}))
}

// ═══════════════════════════════════════════════════════════════
// Admin dashboard endpoints — for webapp / internal use
// ═══════════════════════════════════════════════════════════════

/// Admin: Full surveillance dashboard
pub async fn dashboard(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let db = state.surveillance_db.lock().unwrap();
    let now = chrono::Utc::now();

    let active = db.active_instances();
    let stale = db.stale_instances(7200); // 2 hours
    let delinquent = db.delinquent_customers();

    let mut tier_breakdown: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for inst in &active {
        *tier_breakdown.entry(inst.tier.clone()).or_insert(0) += 1;
    }

    Json(serde_json::json!({
        "timestamp": now.to_rfc3339(),
        "customers": {
            "total": db.total_customers(),
            "delinquent": delinquent.len(),
        },
        "instances": {
            "total": db.total_instances(),
            "active": active.len(),
            "stale_2h": stale.len(),
        },
        "revenue": {
            "mrr_cents": db.total_mrr(),
            "mrr_display": format!("${:.2}", db.total_mrr() as f64 / 100.0),
            "arr_cents": db.total_mrr() * 12,
        },
        "tier_breakdown": tier_breakdown,
        "events_total": db.total_events(),
        "recent_events": db.events.iter().rev().take(20)
            .map(|e| serde_json::json!({
                "event_id": &e.event_id,
                "instance_id": &e.instance_id,
                "type": format!("{:?}", e.event_type),
                "timestamp": &e.timestamp,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// Admin: List all tracked instances
pub async fn list_tracked_instances(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let db = state.surveillance_db.lock().unwrap();
    let instances: Vec<serde_json::Value> = db.instances.values().map(|i| {
        serde_json::json!({
            "instance_id": &i.instance_id,
            "key_id": &i.key_id,
            "customer_id": &i.customer_id,
            "machine_id": &i.machine_id,
            "hostname": &i.hostname,
            "tier": &i.tier,
            "status": format!("{:?}", i.status),
            "binary_id": &i.binary_id,
            "agents": i.agents_last,
            "packets": i.packets_last,
            "trust_score": i.trust_score_last,
            "last_heartbeat": &i.last_heartbeat,
            "warnings": i.warnings_issued,
            "kill_issued": i.kill_issued,
        })
    }).collect();

    Json(serde_json::json!({"count": instances.len(), "instances": instances}))
}

/// Admin: List all customers with payment status
pub async fn list_customers(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let db = state.surveillance_db.lock().unwrap();
    let customers: Vec<serde_json::Value> = db.customers.values().map(|c| {
        let inst_count = db.instances_for_customer(&c.customer_id).len();
        serde_json::json!({
            "customer_id": &c.customer_id,
            "email": &c.email,
            "name": &c.name,
            "payment_status": format!("{:?}", c.payment_status),
            "total_paid_cents": c.total_paid_cents,
            "key_count": c.key_ids.len(),
            "instance_count": inst_count,
            "last_payment": &c.last_payment_at,
        })
    }).collect();

    Json(serde_json::json!({"count": customers.len(), "customers": customers}))
}

/// Admin: Issue kill command to instance
pub async fn kill_instance(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let reason = req.get("reason").and_then(|v| v.as_str()).unwrap_or("admin_action");
    let now = chrono::Utc::now();

    let mut db = state.surveillance_db.lock().unwrap();
    let found = if let Some(inst) = db.get_instance_mut(instance_id) {
        inst.status = InstanceStatus::Suspended;
        inst.kill_issued = true;
        true
    } else {
        false
    };

    if found {
        db.log_event(SurveillanceEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            instance_id: instance_id.to_string(),
            event_type: SurveillanceEventType::KillSent,
            timestamp: now.to_rfc3339(),
            details: serde_json::json!({"reason": reason}),
        });
        return Json(serde_json::json!({
            "instance_id": instance_id,
            "kill_issued": true,
            "reason": reason,
        }));
    }

    Json(serde_json::json!({"error": "Instance not found"}))
}

/// Admin: Degrade instance (payment issue)
pub async fn degrade_instance(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let instance_id = req.get("instance_id").and_then(|v| v.as_str()).unwrap_or("");
    let now = chrono::Utc::now();
    let grace_days = req.get("grace_days").and_then(|v| v.as_u64()).unwrap_or(7);

    let mut db = state.surveillance_db.lock().unwrap();
    let grace_end = (now + chrono::Duration::days(grace_days as i64)).to_rfc3339();
    let found = if let Some(inst) = db.get_instance_mut(instance_id) {
        inst.status = InstanceStatus::GracePeriod;
        inst.grace_period_ends = Some(grace_end.clone());
        inst.warnings_issued += 1;
        true
    } else {
        false
    };

    if found {
        db.log_event(SurveillanceEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            instance_id: instance_id.to_string(),
            event_type: SurveillanceEventType::GracePeriodStart,
            timestamp: now.to_rfc3339(),
            details: serde_json::json!({"grace_days": grace_days}),
        });
        return Json(serde_json::json!({
            "instance_id": instance_id,
            "degraded": true,
            "grace_period_ends": grace_end,
        }));
    }

    Json(serde_json::json!({"error": "Instance not found"}))
}

/// Admin: Block a binary hash (anti-piracy)
pub async fn block_binary(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let hash = req.get("binary_hash").and_then(|v| v.as_str()).unwrap_or("");
    let reason = req.get("reason").and_then(|v| v.as_str()).unwrap_or("piracy");

    let mut db = state.surveillance_db.lock().unwrap();
    if !hash.is_empty() {
        db.blocked_binary_hashes.push(hash.to_string());
    }

    Json(serde_json::json!({
        "blocked": true,
        "binary_hash": hash,
        "reason": reason,
        "total_blocked": db.blocked_binary_hashes.len(),
    }))
}

/// Admin: Surveillance event log
pub async fn event_log(
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let db = state.surveillance_db.lock().unwrap();
    let events: Vec<serde_json::Value> = db.events.iter().rev().take(100)
        .map(|e| serde_json::json!({
            "event_id": &e.event_id,
            "instance_id": &e.instance_id,
            "type": format!("{:?}", e.event_type),
            "timestamp": &e.timestamp,
            "details": &e.details,
        }))
        .collect();

    Json(serde_json::json!({"count": events.len(), "events": events}))
}
