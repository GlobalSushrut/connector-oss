use crate::auth::{extract_claims, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};

/// Track 5 — Item L.1: View current license info + usage vs limits
pub async fn license_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let lic = &state.license;
    let k = state.kernel.lock().unwrap();
    let agent_count = k.agents().len();
    let packet_count = k.packet_count();
    let audit_count = k.audit_log().len();

    let agent_pct = if lic.agent_limit() < usize::MAX {
        (agent_count as f64 / lic.agent_limit() as f64 * 100.0).round()
    } else {
        0.0
    };
    let packet_pct = if lic.packet_limit() < usize::MAX {
        (packet_count as f64 / lic.packet_limit() as f64 * 100.0).round()
    } else {
        0.0
    };

    Json(serde_json::json!({
        "tier": format!("{:?}", lic.tier),
        "instance_id": &lic.instance_id,
        "valid_until": lic.valid_until,
        "price_cents": lic.price_cents,
        "limits": {
            "max_agents": lic.max_agents,
            "max_events": lic.max_events,
            "max_packets": lic.max_packets,
            "retention_days": lic.retention_days,
        },
        "usage": {
            "agents": agent_count,
            "agents_pct": agent_pct,
            "packets": packet_count,
            "packets_pct": packet_pct,
            "audit_entries": audit_count,
        },
        "features": {
            "pdf_export": lic.has_feature(crate::license::Feature::PdfExport),
            "alerting": lic.has_feature(crate::license::Feature::Alerting),
            "sso": lic.has_feature(crate::license::Feature::Sso),
            "multi_cell": lic.has_feature(crate::license::Feature::MultiCell),
            "knowledge_graph": lic.has_feature(crate::license::Feature::KnowledgeGraph),
            "rag": lic.has_feature(crate::license::Feature::Rag),
            "multi_agent": lic.has_feature(crate::license::Feature::MultiAgent),
            "experiments": lic.has_feature(crate::license::Feature::Experiments),
            "judgment_engine": lic.has_feature(crate::license::Feature::JudgmentEngine),
            "dispute_reports": lic.has_feature(crate::license::Feature::DisputeReports),
            "custom_compliance": lic.has_feature(crate::license::Feature::CustomCompliance),
            "on_premise": lic.has_feature(crate::license::Feature::OnPremise),
            "air_gapped": lic.has_feature(crate::license::Feature::AirGapped),
            "dedicated_csm": lic.has_feature(crate::license::Feature::DedicatedCsm),
        },
    }))
}

/// Track 5 — Item L.2: Validate license key and activate
pub async fn license_activate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let claims = extract_claims(&headers);
    let allowed = claims
        .as_ref()
        .map(|c| PlatformRole::from_str(&c.role).rank() >= PlatformRole::Admin.rank())
        .unwrap_or(false);
    if !allowed {
        return Json(
            serde_json::json!({"error": "Admin privileges required", "status": 403, "activated": false}),
        );
    }

    let key = req
        .get("license_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if key.is_empty() {
        return Json(
            serde_json::json!({"error": "No license key provided", "status": 400, "activated": false}),
        );
    }

    let validated = match crate::license::LicenseInfo::try_validate_key(key) {
        Ok(v) => v,
        Err(reason) => {
            return Json(serde_json::json!({
                "error": reason,
                "activated": false,
                "status": 400,
            }));
        }
    };
    let now = chrono::Utc::now();

    // Store activation record
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "license",
        "activation",
        &serde_json::json!({
            "key_prefix": &key[..key.len().min(12)],
            "tier": format!("{:?}", validated.tier),
            "activated_at": now.to_rfc3339(),
            "instance_id": &validated.instance_id,
            "machine_id": machine_fingerprint(),
        }),
    );

    Json(serde_json::json!({
        "activated": true,
        "tier": format!("{:?}", validated.tier),
        "instance_id": &validated.instance_id,
        "max_agents": validated.max_agents,
        "max_events": validated.max_events,
        "retention_days": validated.retention_days,
        "price_cents": validated.price_cents,
    }))
}

/// Track 5 — Item L.3: Machine fingerprint for license binding
pub async fn machine_info(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    let fp = machine_fingerprint();
    Json(serde_json::json!({
        "machine_id": fp,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": hostname(),
    }))
}

/// Track 5 — Item L.4: Heartbeat — periodic license validation pulse
pub async fn heartbeat(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let lic = &state.license;
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let valid = match lic.valid_until {
        Some(expiry) => now.timestamp_millis() < expiry,
        None => true,
    };

    let agent_ok = k.agents().len() <= lic.agent_limit();
    let packet_ok = k.packet_count() <= lic.packet_limit();

    // Store heartbeat
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "license",
        "last_heartbeat",
        &serde_json::json!({
            "timestamp": now.to_rfc3339(),
            "valid": valid,
            "within_limits": agent_ok && packet_ok,
            "tier": format!("{:?}", lic.tier),
        }),
    );

    Json(serde_json::json!({
        "heartbeat": "ok",
        "timestamp": now.to_rfc3339(),
        "license_valid": valid,
        "within_agent_limit": agent_ok,
        "within_packet_limit": packet_ok,
        "tier": format!("{:?}", lic.tier),
        "instance_id": &lic.instance_id,
    }))
}

/// Track 5 — Item L.5: Usage tracking — cumulative metrics for billing
pub async fn usage_report(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let lic = &state.license;
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let mut total_cost: f64 = 0.0;
    let mut total_tokens: u64 = 0;
    let mut total_packets_created: u64 = 0;

    for (_, acb) in k.agents() {
        total_cost += acb.total_cost_usd;
        total_tokens += acb.total_tokens_consumed;
        total_packets_created += acb.total_packets;
    }

    Json(serde_json::json!({
        "period": {
            "from": "billing_start",
            "to": now.to_rfc3339(),
        },
        "tier": format!("{:?}", lic.tier),
        "instance_id": &lic.instance_id,
        "usage": {
            "agents_active": k.agents().len(),
            "agents_limit": lic.max_agents,
            "packets_stored": k.packet_count(),
            "packets_limit": lic.max_packets,
            "audit_entries": k.audit_log().len(),
            "events_limit": lic.max_events,
            "total_tokens": total_tokens,
            "total_cost_usd": (total_cost * 100.0).round() / 100.0,
            "total_packets_created": total_packets_created,
        },
        "overages": {
            "agents_over": k.agents().len().saturating_sub(lic.agent_limit()),
            "packets_over": k.packet_count().saturating_sub(lic.packet_limit()),
        },
    }))
}

/// Track 5 — Item L.6: Feature gate check
pub async fn feature_check(
    State(state): State<SharedState>,
    Path(feature): Path<String>,
) -> Json<serde_json::Value> {
    let lic = &state.license;

    let feat = match feature.as_str() {
        "pdf_export" => Some(crate::license::Feature::PdfExport),
        "alerting" => Some(crate::license::Feature::Alerting),
        "sso" => Some(crate::license::Feature::Sso),
        "multi_cell" => Some(crate::license::Feature::MultiCell),
        "knowledge_graph" => Some(crate::license::Feature::KnowledgeGraph),
        "rag" => Some(crate::license::Feature::Rag),
        "multi_agent" => Some(crate::license::Feature::MultiAgent),
        "experiments" => Some(crate::license::Feature::Experiments),
        "judgment_engine" => Some(crate::license::Feature::JudgmentEngine),
        "dispute_reports" => Some(crate::license::Feature::DisputeReports),
        "custom_compliance" => Some(crate::license::Feature::CustomCompliance),
        "on_premise" => Some(crate::license::Feature::OnPremise),
        "air_gapped" => Some(crate::license::Feature::AirGapped),
        "dedicated_csm" => Some(crate::license::Feature::DedicatedCsm),
        _ => None,
    };

    match feat {
        Some(f) => {
            let allowed = lic.has_feature(f);
            Json(serde_json::json!({
                "feature": feature,
                "allowed": allowed,
                "tier": format!("{:?}", lic.tier),
                "upgrade_url": if !allowed { Some("/api/v1/license/tiers") } else { None },
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Unknown feature '{}'", feature), "status": 400}),
        ),
    }
}

/// Track 5 — Item L.7: List all tiers with pricing
pub async fn list_tiers(State(_state): State<SharedState>) -> Json<serde_json::Value> {
    use crate::license::Tier;
    let tiers = [
        Tier::Indie,
        Tier::Startup,
        Tier::Growth,
        Tier::Business,
        Tier::Scale,
        Tier::Enterprise,
        Tier::Core,
        Tier::Sovereign,
    ];

    let list: Vec<serde_json::Value> = tiers
        .iter()
        .map(|t| {
            let info = crate::license::LicenseInfo::for_tier(*t);
            serde_json::json!({
                "tier": format!("{:?}", t),
                "price_cents": info.price_cents,
                "price_display": format!("${}/mo", info.price_cents / 100),
                "max_agents": info.max_agents,
                "max_events": info.max_events,
                "max_packets": info.max_packets,
                "retention_days": info.retention_days,
            })
        })
        .collect();

    Json(serde_json::json!({
        "tiers": list,
        "currency": "USD",
    }))
}

fn machine_fingerprint() -> String {
    let hostname = hostname();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let raw = format!("{}:{}:{}", hostname, os, arch);
    format!("mfp_{:x}", fnv_hash(raw.as_bytes()))
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn fnv_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
