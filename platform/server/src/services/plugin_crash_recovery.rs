//! Phase 5.10 — crash recovery with durable quarantine (OPS-06).
//!
//! Failure counts, exponential backoff hints, and quarantine flags persist in
//! `engine_store` folder `plugin_crash_recovery` so supervisors honor quarantine
//! across process restart.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth;
use crate::services::runtime_control;
use crate::state::{PlatformState, SharedState};

/// After this many consecutive failures, row is marked quarantined (no auto-restart until cleared).
pub const QUARANTINE_AFTER_FAILURES: u32 = 5;
const MAX_BACKOFF_MS: u64 = 300_000;
const FOLDER: &str = "plugin_crash_recovery";

#[derive(Debug, Clone, Default)]
struct Row {
    failures: u32,
    last_failure_unix_ms: i64,
    quarantined: bool,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `min(300s, 2^(n-1) * 1s)` capped for display / scheduling hints.
pub fn backoff_ms_after_failures(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    let exp = (failures - 1).min(18);
    let raw = 1000u64.saturating_mul(1u64 << exp);
    raw.min(MAX_BACKOFF_MS)
}

#[derive(Default)]
pub struct PluginCrashRecovery {
    rows: DashMap<String, Row>,
}

impl PluginCrashRecovery {
    /// Hydrate in-memory map from durable store (call once at boot).
    pub fn hydrate_from_store(&self, state: &PlatformState) {
        let es = match state.engine_store.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let keys = es.folder_keys(FOLDER, None).unwrap_or_default();
        let mut n = 0usize;
        for k in keys {
            if let Ok(Some(v)) = es.folder_get(FOLDER, &k) {
                let failures = v.get("failures").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let quarantined = v
                    .get("quarantined")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false);
                let last_failure_unix_ms = v
                    .get("last_failure_unix_ms")
                    .and_then(|x| x.as_i64())
                    .unwrap_or(0);
                self.rows.insert(
                    k,
                    Row {
                        failures,
                        last_failure_unix_ms,
                        quarantined,
                    },
                );
                n += 1;
            }
        }
        if n > 0 {
            tracing::info!(
                loaded = n,
                "[ops-06] plugin crash recovery hydrated from store"
            );
        }
    }

    fn persist_row(&self, state: &PlatformState, plugin_id: &str, row: &Row) {
        let Ok(mut es) = state.engine_store.lock() else {
            return;
        };
        let _ = es.folder_put(
            FOLDER,
            plugin_id,
            &json!({
                "plugin_id": plugin_id,
                "failures": row.failures,
                "quarantined": row.quarantined,
                "last_failure_unix_ms": row.last_failure_unix_ms,
                "suggested_backoff_ms": backoff_ms_after_failures(row.failures),
                "updated_at": chrono::Utc::now().to_rfc3339(),
                "honesty": "OPS-06 — durable quarantine/backoff; supervisor must honor across restart",
            }),
        );
    }

    fn delete_row(&self, state: &PlatformState, plugin_id: &str) {
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_delete(FOLDER, plugin_id);
        }
    }

    pub fn record_failure(&self, state: &PlatformState, plugin_id: &str) {
        let key = plugin_id.trim().to_string();
        if key.is_empty() {
            return;
        }
        let row = match self.rows.entry(key.clone()) {
            Entry::Occupied(mut o) => {
                let r = o.get_mut();
                r.failures = r.failures.saturating_add(1);
                r.last_failure_unix_ms = now_ms();
                if r.failures >= QUARANTINE_AFTER_FAILURES {
                    r.quarantined = true;
                }
                r.clone()
            }
            Entry::Vacant(v) => {
                let r = Row {
                    failures: 1,
                    last_failure_unix_ms: now_ms(),
                    quarantined: false,
                };
                v.insert(r.clone());
                r
            }
        };
        self.persist_row(state, &key, &row);
    }

    pub fn clear(&self, state: &PlatformState, plugin_id: &str) {
        let k = plugin_id.trim().to_string();
        self.rows.remove(&k);
        self.delete_row(state, &k);
    }

    pub fn unquarantine(&self, state: &PlatformState, plugin_id: &str) {
        let k = plugin_id.trim().to_string();
        if let Some(mut r) = self.rows.get_mut(&k) {
            r.quarantined = false;
            r.failures = 0;
            let snap = r.clone();
            drop(r);
            self.persist_row(state, &k, &snap);
        }
    }

    pub fn is_quarantined(&self, plugin_id: &str) -> bool {
        self.rows
            .get(plugin_id.trim())
            .map(|r| r.quarantined)
            .unwrap_or(false)
    }

    pub fn snapshot_json(&self) -> Value {
        let mut out = Vec::new();
        for r in self.rows.iter() {
            let row = r.value();
            out.push(json!({
                "plugin_id": r.key(),
                "failures": row.failures,
                "quarantined": row.quarantined,
                "last_failure_unix_ms": row.last_failure_unix_ms,
                "suggested_backoff_ms": backoff_ms_after_failures(row.failures),
            }));
        }
        json!({ "plugins": out, "durable": true, "folder": FOLDER })
    }

    pub fn hint_json(&self, plugin_id: &str) -> Value {
        let Some(r) = self.rows.get(plugin_id.trim()) else {
            return Value::Null;
        };
        let row = r.value();
        json!({
            "failures": row.failures,
            "quarantined": row.quarantined,
            "last_failure_unix_ms": row.last_failure_unix_ms,
            "suggested_backoff_ms": backoff_ms_after_failures(row.failures),
            "durable": true,
        })
    }
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
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

#[derive(Debug, Deserialize)]
pub struct CrashRecoveryStatusQuery {
    pub plugin_id: String,
}

pub async fn get_plugin_crash_recovery_status(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<CrashRecoveryStatusQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    let pid = q.plugin_id.trim().to_string();
    if pid.is_empty() || pid.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }
    let quarantined = state.plugin_crash_recovery.is_quarantined(&pid);
    let data = state.plugin_crash_recovery.hint_json(&pid);
    Ok(Json(json!({
        "ok": true,
        "plugin_id": pid,
        "quarantined": quarantined,
        "data": data,
        "quarantine_after_failures": QUARANTINE_AFTER_FAILURES,
        "durable": true,
    })))
}

pub async fn get_plugin_crash_recovery(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    Ok(Json(json!({
        "ok": true,
        "data": state.plugin_crash_recovery.snapshot_json(),
        "quarantine_after_failures": QUARANTINE_AFTER_FAILURES,
        "hint": "Supervisor should call record_failure on crash; clear/unquarantine after operator fix. State survives restart (OPS-06).",
        "durable": true,
    })))
}

fn require_auth_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(json!({"ok": false, "error": "Unauthorized"}))
}

#[derive(Debug, Deserialize)]
pub struct PluginIdBody {
    pub plugin_id: String,
}

pub async fn post_plugin_crash_recovery_record(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PluginIdBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let pid = body.plugin_id.trim().to_string();
    if pid.is_empty() || pid.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }
    state
        .plugin_crash_recovery
        .record_failure(state.as_ref(), &pid);
    Ok(Json(json!({
        "ok": true,
        "plugin_id": pid,
        "quarantined": state.plugin_crash_recovery.is_quarantined(&pid),
        "durable": true,
    })))
}

pub async fn post_plugin_crash_recovery_clear(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PluginIdBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    state
        .plugin_crash_recovery
        .clear(state.as_ref(), &body.plugin_id.trim().to_string());
    Ok(Json(json!({"ok": true, "durable": true})))
}

pub async fn post_plugin_crash_recovery_unquarantine(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PluginIdBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    state
        .plugin_crash_recovery
        .unquarantine(state.as_ref(), &body.plugin_id.trim().to_string());
    Ok(Json(json!({"ok": true, "durable": true})))
}

/// Boot helper.
pub fn hydrate(state: &Arc<PlatformState>) {
    state
        .plugin_crash_recovery
        .hydrate_from_store(state.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_monotonic_cap() {
        assert_eq!(backoff_ms_after_failures(0), 0);
        assert_eq!(backoff_ms_after_failures(1), 1000);
        assert_eq!(backoff_ms_after_failures(2), 2000);
        assert!(backoff_ms_after_failures(20) <= MAX_BACKOFF_MS);
    }
}
