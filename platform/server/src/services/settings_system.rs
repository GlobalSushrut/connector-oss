use axum::{extract::State, http::HeaderMap, Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth, state::SharedState};

const SYSTEM_SETTINGS_FOLDER: &str = "settings_system";

#[derive(Debug, Deserialize)]
pub struct SaveBlobRequest {
    pub value: Value,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn get_value(state: &SharedState, key: &str) -> Value {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(SYSTEM_SETTINGS_FOLDER, key)
        .ok()
        .flatten()
        .unwrap_or(Value::Null)
}

fn put_value(state: &SharedState, key: &str, value: &Value) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(SYSTEM_SETTINGS_FOLDER, key, value);
}

pub async fn get_networking(State(state): State<SharedState>) -> Json<Value> {
    let v = get_value(&state, "networking");
    Json(json!({
        "ok": true,
        "networking": if v.is_null() {
            json!({
                "trusted_proxies": state.config.trusted_proxies.clone(),
                "public_url": state.config.public_url(),
                "protocol_gateway_port": state.config.protocol_gateway_port,
                "ui_rpc_port": state.config.ui_rpc_port
            })
        } else { v }
    }))
}

pub async fn set_networking(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    put_value(&state, "networking", &req.value);
    Json(json!({"ok": true}))
}

pub async fn get_identity(State(state): State<SharedState>) -> Json<Value> {
    let v = get_value(&state, "identity");
    Json(json!({
        "ok": true,
        "identity": if v.is_null() {
            json!({
                "runtime_mode": state.runtime_mode.read().unwrap().as_str(),
                "isolation_runtime": state.isolation_runtime.read().unwrap().as_str(),
                "defense_strict": crate::services::runtime_control::defense_strict_enabled()
            })
        } else { v }
    }))
}

pub async fn set_identity(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    put_value(&state, "identity", &req.value);
    Json(json!({"ok": true}))
}

pub async fn get_backup(State(state): State<SharedState>) -> Json<Value> {
    let v = get_value(&state, "backup");
    let schedule = if v.is_null() {
        json!({"enabled": true, "schedule": "daily", "retention_days": 30})
    } else {
        v
    };
    // Schedule JSON is operator intent only — real export/restore is CLI (fail-closed).
    Json(json!({
        "ok": true,
        "backup": schedule,
        "trust_domain": {
            "docs": "docs/TRUST_DOMAIN_BACKUP.md",
            "export_cmd": "connectorctl backup -o connector-backup.tar.gz",
            "restore_cmd": "connectorctl stop && connectorctl restore connector-backup.tar.gz --yes",
            "env_key_refs_required": [
                "CONNECTOR_JWT_SECRET",
                "CONNECTOR_AUDIT_HMAC_KEY",
                "CONNECTOR_CFNI_SECRET",
                "CONNECTOR_CAGE_CAP_SECRET"
            ],
            "honesty": "Schedule fields do not run backups by themselves. Use connectorctl backup/restore. Manifest required on restore.",
            "node_upgrade_cmd": "connectorctl node-upgrade"
        }
    }))
}

pub async fn set_backup(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    put_value(&state, "backup", &req.value);
    Json(json!({"ok": true}))
}

pub async fn get_telemetry(State(state): State<SharedState>) -> Json<Value> {
    let v = get_value(&state, "telemetry");
    Json(json!({
        "ok": true,
        "telemetry": if v.is_null() {
            json!({
                "prometheus_enabled": std::env::var("CONNECTOR_ENABLE_PROM_METRICS")
                    .map(|x| x == "1" || x.eq_ignore_ascii_case("true"))
                    .unwrap_or(false),
                "otel_enabled": std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok()
            })
        } else { v }
    }))
}

pub async fn set_telemetry(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    put_value(&state, "telemetry", &req.value);
    Json(json!({"ok": true}))
}

pub async fn get_license(State(state): State<SharedState>) -> Json<Value> {
    let v = get_value(&state, "license");
    Json(json!({
        "ok": true,
        "license": if v.is_null() {
            json!({
                "tier": format!("{:?}", state.license.tier),
                "instance_id": state.license.instance_id.clone(),
                "max_agents": state.license.max_agents,
                "max_packets": state.license.max_packets,
                "retention_days": state.license.retention_days
            })
        } else { v }
    }))
}

pub async fn set_license(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    put_value(&state, "license", &req.value);
    Json(json!({"ok": true}))
}

/// `GET /api/v1/settings/system/retention` — I-23 / P6.9 policy JSON.
pub async fn get_retention(State(state): State<SharedState>) -> Json<Value> {
    let policy = crate::substrate::retention::load_policy(state.as_ref());
    Json(json!({
        "ok": true,
        "retention": policy,
        "honesty": "not yet moving cold tiers — job stub logs TTL intent only",
        "job_endpoint": "POST /settings/system/retention/run-stub",
    }))
}

/// `POST /api/v1/settings/system/retention` — save simple retention policy JSON.
pub async fn set_retention(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let mut policy: crate::substrate::retention::RetentionPolicyV1 =
        serde_json::from_value(req.value.clone()).unwrap_or_default();
    if policy.schema.is_empty() {
        policy.schema = crate::substrate::retention::RETENTION_POLICY_SCHEMA.into();
    }
    policy.honesty =
        "Policy stored; cold-tier move not yet implemented — jobs log TTL intent only".into();
    crate::substrate::retention::save_policy(state.as_ref(), &policy);
    Json(json!({
        "ok": true,
        "retention": policy,
        "honesty": "not yet moving cold tiers",
    }))
}

/// `POST /api/v1/settings/system/retention/run-stub` — log TTL intent only.
pub async fn run_retention_stub(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let result = crate::substrate::retention::run_retention_job_stub(state.as_ref());
    Json(json!({"ok": true, "result": result}))
}

fn tenant_id_for_store(tenant: &crate::middleware::TenantContext) -> Option<String> {
    if std::env::var("CONNECTOR_MULTI_TENANT").is_ok() {
        Some(tenant.tenant_id.clone())
    } else {
        None
    }
}

pub async fn get_custom_domains(
    State(state): State<SharedState>,
    Extension(tenant): Extension<crate::middleware::TenantContext>,
) -> Json<Value> {
    let tenant_id = tenant_id_for_store(&tenant);
    let store_key =
        crate::services::custom_domain_routing::custom_domains_settings_key(tenant_id.as_deref());
    let v = get_value(&state, &store_key);
    Json(json!({
        "ok": true,
        "tenant_id": tenant_id,
        "store_key": store_key,
        "custom_domains": if v.is_null() {
            json!({
                "public_domain": state.config.public_url(),
                "aliases": [],
                "tls_mode": "lets_encrypt",
                "plugin_public_path_allowlist": {
                    "tracetramp": ["/plugin/tracetramp/*"],
                    "witnessctl": ["/plugin/witnessctl/*"],
                    "devguard": ["/plugin/devguard/*"]
                }
            })
        } else { v }
    }))
}

pub async fn set_custom_domains(
    State(state): State<SharedState>,
    Extension(tenant): Extension<crate::middleware::TenantContext>,
    headers: HeaderMap,
    Json(req): Json<SaveBlobRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let tenant_id = tenant_id_for_store(&tenant);
    if let Err(msg) =
        crate::services::custom_domain_routing::validate_custom_domains_value(&req.value)
    {
        return Json(json!({"ok": false, "error": msg}));
    }
    let store_key =
        crate::services::custom_domain_routing::custom_domains_settings_key(tenant_id.as_deref());
    put_value(&state, &store_key, &req.value);
    Json(json!({
        "ok": true,
        "tenant_id": tenant_id,
        "store_key": store_key,
        "hint": "Aliases active on next request; TLS termination is external to connector-platform (tls_mode is policy metadata). Host routing merges aliases from all tenants.",
    }))
}
