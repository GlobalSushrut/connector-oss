use std::collections::BTreeMap;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use connector_engine::engine_store::{AuditFilter, EngineAuditEntry, EngineStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth,
    services::cls::{ccl_static_action_blueprint, compile_ccl_contract},
    state::SharedState,
};

/// Cap on audit rows fetched for dry-run window (then sorted newest-first and trimmed).
const DRY_RUN_AUDIT_FETCH_CAP: usize = 2000;
/// Max rows embedded in **`dry_run.cnp_replay.events`** (compact summaries).
const DRY_RUN_AUDIT_REPORT_CAP: usize = 500;

/// Product runtime claim for Workflows (P3.1): CLS engine + CNP dispatch only.
pub const RUNTIME_CONTRACT_CLS_CNP: &str = "CLS engine + CNP dispatch";
pub const RUNTIME_ID_CLS_CNP_ONLY: &str = "cls_cnp_only";

/// Stable synthetic id for audit-tail rows (engine audit has no native event_id).
fn synthetic_audit_event_id(e: &EngineAuditEntry) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(e.timestamp.to_le_bytes());
    h.update(e.category.as_bytes());
    h.update(b"|");
    h.update(e.action.as_bytes());
    if let Some(pid) = &e.agent_pid {
        h.update(b"|");
        h.update(pid.as_bytes());
    }
    if let Some(res) = &e.resource {
        h.update(b"|");
        h.update(res.as_bytes());
    }
    format!("aud_{}", hex::encode(&h.finalize()[..8]))
}

fn compact_audit_replay_event(e: &EngineAuditEntry, workflow_id: &str) -> Value {
    let event_id = synthetic_audit_event_id(e);
    let cnp_hint = e
        .agent_pid
        .as_deref()
        .is_some_and(|p| p.contains("workflow-cnp"))
        || e.category.contains("workflow")
        || e.action.contains("workflow")
        || e.details
            .as_ref()
            .map(|d| d.to_string().contains(workflow_id))
            .unwrap_or(false);
    json!({
        "event_id": event_id,
        "timestamp": e.timestamp,
        "category": &e.category,
        "action": &e.action,
        "agent_pid": &e.agent_pid,
        "resource": &e.resource,
        "verdict": &e.verdict,
        "severity": &e.severity,
        "cnp_correlation": {
            "matched": cnp_hint,
            "action_topic": crate::services::workflow_cnp::workflow_action_topic(workflow_id),
            "event_topic": crate::services::workflow_cnp::workflow_event_topic(workflow_id),
            "source": "engine_audit",
        },
    })
}

fn normalize_client_dry_run_event(ev: &Value, idx: usize, workflow_id: &str) -> Value {
    let mut out = ev.clone();
    let obj = match out.as_object_mut() {
        Some(o) => o,
        None => {
            return json!({
                "event_id": format!("cli_{idx}"),
                "payload": ev,
                "cnp_correlation": {
                    "matched": false,
                    "action_topic": crate::services::workflow_cnp::workflow_action_topic(workflow_id),
                    "event_topic": crate::services::workflow_cnp::workflow_event_topic(workflow_id),
                    "source": "request_body",
                },
            });
        }
    };
    if obj
        .get("event_id")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .is_empty()
    {
        let fallback = obj
            .get("id")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("cli_{idx}"));
        obj.insert("event_id".into(), json!(fallback));
    }
    let topic_matched = obj
        .get("topic")
        .and_then(|t| t.as_str())
        .is_some_and(|t| t.contains("workflow.actions") || t.contains("workflow.events"));
    obj.entry("cnp_correlation".to_string()).or_insert_with(|| {
        json!({
            "matched": topic_matched,
            "action_topic": crate::services::workflow_cnp::workflow_action_topic(workflow_id),
            "event_topic": crate::services::workflow_cnp::workflow_event_topic(workflow_id),
            "source": "request_body",
        })
    });
    out
}

/// First 8 bytes of SHA-256 over raw **`cls_source`** UTF-8 bytes (cheap list diff; not a semantic CCL digest).
fn cls_source_fingerprint(source: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{}", hex::encode(&digest[..8]))
}

pub(crate) const WORKFLOW_FOLDER: &str = "workflow_runtime";
pub(crate) const WORKFLOW_RUN_FOLDER: &str = "workflow_runtime_runs";
const WORKFLOW_DRY_RUN_INDEX: &str = "workflow_dry_run_index";
/// When the per-workflow index is empty, scan at most this many run folder keys (undefined order) to rebuild it.
const DRY_RUN_INDEX_BACKFILL_SCAN_CAP: usize = 800;
/// Max workflows whose **empty** dry-run index is backfilled when **`GET /workflows?hydrate_dry_run_index=true`**.
const LIST_WORKFLOWS_HYDRATE_MAX: usize = 15;
pub(crate) const PLUGIN_WORKFLOW_FOLDER: &str = "plugin_workflow_contracts";
const WORKFLOW_VERSION_LOG: &str = "workflow_runtime_version_log";

/// Best-effort: find stored dry-run reports for **`workflow_id`**, sort by **`recorded_at`** (missing → 0), persist index (max 50).
fn backfill_workflow_dry_run_index(es: &mut dyn EngineStore, workflow_id: &str) -> usize {
    let keys = match es.folder_keys(WORKFLOW_RUN_FOLDER, None) {
        Ok(k) => k,
        Err(_) => return 0,
    };
    let mut candidates: Vec<(i64, String, String)> = Vec::new();
    for key in keys.iter().take(DRY_RUN_INDEX_BACKFILL_SCAN_CAP) {
        let Ok(Some(v)) = es.folder_get(WORKFLOW_RUN_FOLDER, key) else {
            continue;
        };
        if v.get("workflow_id").and_then(|x| x.as_str()) != Some(workflow_id) {
            continue;
        }
        let rid = v
            .get("run_id")
            .and_then(|x| x.as_str())
            .unwrap_or(key.as_str())
            .to_string();
        let recorded = v
            .get("recorded_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let ts_ms = chrono::DateTime::parse_from_rfc3339(&recorded)
            .map(|d| d.with_timezone(&chrono::Utc).timestamp_millis())
            .unwrap_or(0);
        candidates.push((ts_ms, rid, recorded));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    candidates.truncate(50);
    if candidates.is_empty() {
        return 0;
    }
    let arr: Vec<Value> = candidates
        .into_iter()
        .map(|(_, rid, rec)| json!({ "run_id": rid, "recorded_at": rec }))
        .collect();
    let n = arr.len();
    let _ = es.folder_put(WORKFLOW_DRY_RUN_INDEX, workflow_id, &json!(arr));
    n
}

pub(crate) fn append_workflow_dry_run_index(
    es: &mut dyn EngineStore,
    workflow_id: &str,
    run_id: &str,
    recorded_at: &str,
) {
    let mut arr: Vec<Value> = es
        .folder_get(WORKFLOW_DRY_RUN_INDEX, workflow_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    arr.insert(
        0,
        json!({
            "run_id": run_id,
            "recorded_at": recorded_at,
        }),
    );
    arr.truncate(50);
    let _ = es.folder_put(WORKFLOW_DRY_RUN_INDEX, workflow_id, &json!(arr));
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowState {
    Draft,
    Compiled,
    Staged,
    Enabled,
    Paused,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRecord {
    pub workflow_id: String,
    pub package_id: String,
    pub version: String,
    pub state: WorkflowState,
    pub cls_source: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterWorkflowRequest {
    pub workflow_id: String,
    pub package_id: String,
    pub version: Option<String>,
    pub cls_source: String,
    /// Universal two-way accounting: `action` | `service_monitoring`.
    /// Required for new custom builds; omitted values are inferred from CCL/institutions.
    #[serde(default)]
    pub accounting_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TransitionWorkflowRequest {
    pub state: String,
    /// AppPackageV2 pin — required when transitioning to ENABLED outside lab.
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
}

#[derive(Debug, Deserialize)]
pub struct ListWorkflowsQuery {
    /// When true, best-effort **`backfill_workflow_dry_run_index`** for up to [`LIST_WORKFLOWS_HYDRATE_MAX`] workflows whose index is empty (bounded scan per workflow). **Requires Admin or dev auth** (expensive).
    #[serde(default)]
    pub hydrate_dry_run_index: bool,
}

#[derive(Debug, Deserialize)]
pub struct DryRunWorkflowRequest {
    pub replay_minutes: Option<u64>,
    pub events: Option<Vec<Value>>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPluginWorkflowContractRequest {
    pub actions: Vec<Value>,
    pub events: Vec<Value>,
}

fn hydrate_auth_error_value(error: &str) -> Value {
    let mut e = json!({ "ok": false, "error": error });
    if let Some(obj) = e.as_object_mut() {
        obj.insert("code".into(), json!("HYDRATE_AUTH_REQUIRED"));
        obj.insert(
            "hint".into(),
            json!("Omit hydrate_dry_run_index for unauthenticated listing, or call with Admin credentials / dev bypass."),
        );
    }
    e
}

fn hydrate_index_denied_response(status: StatusCode, error: &str) -> Response {
    (status, Json(hydrate_auth_error_value(error))).into_response()
}

pub(crate) fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
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

pub(crate) fn parse_state(state: &str) -> Option<WorkflowState> {
    match state.trim().to_ascii_uppercase().as_str() {
        "DRAFT" => Some(WorkflowState::Draft),
        "COMPILED" => Some(WorkflowState::Compiled),
        "STAGED" => Some(WorkflowState::Staged),
        "ENABLED" => Some(WorkflowState::Enabled),
        "PAUSED" => Some(WorkflowState::Paused),
        "ARCHIVED" => Some(WorkflowState::Archived),
        _ => None,
    }
}

pub(crate) fn valid_transition(from: WorkflowState, to: WorkflowState) -> bool {
    use WorkflowState::*;
    matches!(
        (from, to),
        (Draft, Compiled)
            | (Compiled, Staged)
            | (Staged, Enabled)
            | (Enabled, Paused)
            | (Paused, Enabled)
            | (Enabled, Archived)
            | (Paused, Archived)
            | (Staged, Archived)
            | (Compiled, Archived)
            | (Draft, Archived)
    )
}

/// Seed the ready DevGuard workflow so /run shows it as a workflow, not a plugin dump.
pub fn seed_devguard_cage_workflow(state: &SharedState) {
    if get_workflow(state, "devguard-cage").is_some() {
        return;
    }
    let rec = WorkflowRecord {
        workflow_id: "devguard-cage".into(),
        package_id: "devguard".into(),
        version: "v1".into(),
        state: WorkflowState::Enabled,
        cls_source: include_str!("../../resources/workflow_templates/devguard_repo_cage.ccl")
            .into(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    put_workflow(state, &rec);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        crate::operator::surface_merge::OPERATOR_SURFACE_FOLDER,
        "devguard-cage",
        &json!({
            "schema": "operator_surface.v1",
            "workflow_id": "devguard-cage",
            "display": {
                "title": "DevGuard — repo cage",
                "subtitle": "Generate or link a repo. Attach N agents. Same node, different rules. ENABLED means the workflow is seeded — not a busy worker.",
                "category": "workflow"
            },
            "accounting": crate::operator::surface_merge::accounting_block(
                crate::operator::surface_merge::ACCOUNTING_MODE_ACTION,
                "seed",
            ),
        }),
    );
}

pub fn put_workflow(state: &SharedState, rec: &WorkflowRecord) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        WORKFLOW_FOLDER,
        &rec.workflow_id,
        &serde_json::to_value(rec).unwrap_or_default(),
    );
}

pub fn get_workflow(state: &SharedState, workflow_id: &str) -> Option<WorkflowRecord> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(WORKFLOW_FOLDER, workflow_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<WorkflowRecord>(v).ok())
}

/// Upsert from filesystem catalog sync (`workflow_catalog_sync`). Returns action label.
pub fn upsert_workflow_from_catalog(
    state: &SharedState,
    workflow_id: &str,
    package_id: &str,
    version: &str,
    cls_source: &str,
    initial_state: WorkflowState,
) -> &'static str {
    let fp_new = cls_source_fingerprint(cls_source);
    if let Some(existing) = get_workflow(state, workflow_id) {
        if cls_source_fingerprint(&existing.cls_source) == fp_new {
            return "unchanged";
        }
        let mut rec = existing;
        rec.cls_source = cls_source.to_string();
        rec.package_id = package_id.to_string();
        rec.version = version.to_string();
        rec.updated_at = chrono::Utc::now().to_rfc3339();
        put_workflow(state, &rec);
        append_workflow_version_log(state, workflow_id, version, cls_source);
        return "updated";
    }
    let rec = WorkflowRecord {
        workflow_id: workflow_id.to_string(),
        package_id: package_id.to_string(),
        version: version.to_string(),
        state: initial_state,
        cls_source: cls_source.to_string(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    put_workflow(state, &rec);
    append_workflow_version_log(state, workflow_id, version, cls_source);
    "created"
}

/// JSON shape aligned with each row of **`GET /workflows`** (fingerprint, dry-run index head, version log size).
pub(crate) fn workflow_list_row_json(es: &mut dyn EngineStore, rec: &WorkflowRecord) -> Value {
    let mut v = serde_json::to_value(rec).unwrap_or(Value::Null);
    let version_log_len = es
        .folder_get(WORKFLOW_VERSION_LOG, &rec.workflow_id)
        .ok()
        .flatten()
        .and_then(|x| x.as_array().map(|a| a.len()))
        .unwrap_or(0);
    let institutions = crate::operator::surface_merge::infer_institutions_from_cls(&rec.cls_source);
    let accounting_mode = es
        .folder_get(
            crate::operator::surface_merge::OPERATOR_SURFACE_FOLDER,
            &rec.workflow_id,
        )
        .ok()
        .flatten()
        .and_then(|s| {
            s.pointer("/accounting/mode")
                .and_then(|m| m.as_str())
                .and_then(crate::operator::surface_merge::normalize_accounting_mode)
                .map(|m| m.to_string())
        })
        .or_else(|| {
            crate::operator::surface_merge::bundled_reference_surface(&rec.workflow_id).and_then(
                |s| {
                    s.pointer("/accounting/mode")
                        .and_then(|m| m.as_str())
                        .and_then(crate::operator::surface_merge::normalize_accounting_mode)
                        .map(|m| m.to_string())
                },
            )
        })
        .unwrap_or_else(|| {
            crate::operator::surface_merge::infer_accounting_mode(&rec.cls_source, &institutions)
                .to_string()
        });
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "cls_source_fingerprint".into(),
            json!(cls_source_fingerprint(&rec.cls_source)),
        );
        obj.insert("cls_source_byte_len".into(), json!(rec.cls_source.len()));
        obj.insert("version_log_len".into(), json!(version_log_len));
        obj.insert("accounting_mode".into(), json!(accounting_mode));
        obj.insert("institutions".into(), json!(institutions));
        if let Ok(Some(idx)) = es.folder_get(WORKFLOW_DRY_RUN_INDEX, &rec.workflow_id) {
            if let Some(first) = idx.as_array().and_then(|a| a.first()) {
                if let Some(rid) = first.get("run_id").and_then(|x| x.as_str()) {
                    if !rid.is_empty() {
                        obj.insert("last_dry_run_id".into(), json!(rid));
                    }
                }
                if let Some(at) = first.get("recorded_at").and_then(|x| x.as_str()) {
                    if !at.is_empty() {
                        obj.insert("last_dry_run_recorded_at".into(), json!(at));
                    }
                }
            }
        }
        obj.insert("runtime".into(), json!(RUNTIME_ID_CLS_CNP_ONLY));
        obj.insert("dual_runtime".into(), json!(false));
        obj.insert("runtime_contract".into(), json!(RUNTIME_CONTRACT_CLS_CNP));
        if let Ok(Some(meta)) = es.folder_get(
            crate::services::cpkg_gloo_burnin::WORKFLOW_SYSTEM_META_FOLDER,
            &rec.workflow_id,
        ) {
            if let Ok(row) = serde_json::from_value::<
                crate::services::cpkg_gloo_burnin::WorkflowSystemMeta,
            >(meta)
            {
                obj.insert("system_tier".into(), json!(row.system_tier));
                obj.insert("importance".into(), json!(row.importance));
                obj.insert("origin".into(), json!(row.origin));
                obj.insert("plugin_id".into(), json!(row.plugin_id));
                obj.insert(
                    "governance_class".into(),
                    json!("system_default"),
                );
            }
        }
        // WF-02: ENABLED ≠ live worker execution.
        // WF-01: background poller may consume synthetic enable events (cnp_poller_stub).
        let cnp_stub_active = es
            .folder_keys("workflow_cnp_consumed", None)
            .ok()
            .map(|keys| {
                keys.iter()
                    .any(|k| k.starts_with(&format!("{}:", rec.workflow_id)))
            })
            .unwrap_or(false);
        let live_lease = crate::services::workflow_runner::is_executing(es, &rec.workflow_id);
        let (execution_mode, executing, honesty) = match rec.state {
            WorkflowState::Enabled if live_lease => (
                "cls_blueprint_lease_runner",
                true,
                "ENABLED with an unexpired runner lease — executing CLS blueprint steps through kernel admission (not a live CNP bus)",
            ),
            WorkflowState::Enabled if cnp_stub_active => (
                "cnp_poller_stub",
                false,
                "ENABLED + synthetic CNP enable-event consumed by WF-01 poller — not a live CNP bus worker",
            ),
            WorkflowState::Enabled => (
                "activation_record",
                false,
                "ENABLED means CLS/CNP registration/activation record until the lease runner claims a run",
            ),
            WorkflowState::Paused => ("paused", false, "workflow paused — not executing"),
            WorkflowState::Archived => ("archived", false, "workflow archived — not executing"),
            _ => (
                "register_only",
                false,
                "workflow registered only — not ENABLED for dispatch",
            ),
        };
        obj.insert("execution_mode".into(), json!(execution_mode));
        obj.insert("executing".into(), json!(executing));
        obj.insert("execution_honesty".into(), json!(honesty));
        obj.insert("cnp_poller_stub".into(), json!(cnp_stub_active));
        if let Ok(Some(surf)) = es.folder_get(
            crate::operator::surface_merge::OPERATOR_SURFACE_FOLDER,
            &rec.workflow_id,
        ) {
            if let Some(t) = surf.pointer("/display/title").and_then(|x| x.as_str()) {
                obj.insert("title".into(), json!(t));
            }
            if let Some(s) = surf.pointer("/display/subtitle").and_then(|x| x.as_str()) {
                obj.insert("subtitle".into(), json!(s));
            }
        }
    }
    v
}

pub fn append_workflow_version_log(
    state: &SharedState,
    workflow_id: &str,
    version: &str,
    cls_source: &str,
) {
    let mut es = state.engine_store.lock().unwrap();
    let mut log: Vec<Value> = es
        .folder_get(WORKFLOW_VERSION_LOG, workflow_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    log.push(json!({
        "version": version,
        "saved_at": chrono::Utc::now().to_rfc3339(),
        "cls_source": cls_source,
    }));
    while log.len() > 30 {
        log.remove(0);
    }
    let _ = es.folder_put(WORKFLOW_VERSION_LOG, workflow_id, &json!(log));
}

/// Adds **`cls_source_fingerprint`**, **`cls_source_byte_len`**, and **`fingerprint_changed_from_previous`**
/// (JSON **`null`** for the first row, then **`true`/`false`** vs the chronologically prior entry) for list/diff UX.
fn enrich_workflow_version_entries(log: Vec<Value>) -> Vec<Value> {
    let mut prev_fp: Option<String> = None;
    let mut out = Vec::with_capacity(log.len());
    for entry in log {
        let src = entry
            .get("cls_source")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let fp = cls_source_fingerprint(src);
        let byte_len = src.len();
        let changed = match &prev_fp {
            None => Value::Null,
            Some(p) => json!(p != &fp),
        };
        prev_fp = Some(fp.clone());
        let mut v = entry;
        if let Some(o) = v.as_object_mut() {
            o.insert("cls_source_fingerprint".into(), json!(fp));
            o.insert("cls_source_byte_len".into(), json!(byte_len));
            o.insert("fingerprint_changed_from_previous".into(), changed);
        }
        out.push(v);
    }
    out
}

pub async fn list_workflow_versions(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> Json<Value> {
    let es = state.engine_store.lock().unwrap();
    let log: Vec<Value> = es
        .folder_get(WORKFLOW_VERSION_LOG, &workflow_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let versions = enrich_workflow_version_entries(log);
    Json(json!({
        "ok": true,
        "workflow_id": workflow_id,
        "versions": versions,
        "hint": "fingerprint_changed_from_previous compares each row to the prior row in this log (oldest → newest); semantic CCL diff is not computed.",
    }))
}

#[derive(Debug, Deserialize)]
pub struct RollbackWorkflowRequest {
    /// Index into the version log (0 = oldest kept). If omitted, restores the previous snapshot.
    pub index: Option<usize>,
}

pub async fn rollback_workflow(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RollbackWorkflowRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let Some(mut rec) = get_workflow(&state, &workflow_id) else {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    };
    let es = state.engine_store.lock().unwrap();
    let mut log: Vec<Value> = es
        .folder_get(WORKFLOW_VERSION_LOG, &workflow_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    drop(es);
    if log.len() < 2 {
        return Json(json!({"ok": false, "error": "No prior version to rollback to"}));
    }
    let idx = req.index.unwrap_or_else(|| log.len().saturating_sub(2));
    let Some(entry) = log.get(idx) else {
        return Json(json!({"ok": false, "error": "Invalid version index"}));
    };
    let Some(src) = entry.get("cls_source").and_then(|v| v.as_str()) else {
        return Json(json!({"ok": false, "error": "Version entry missing cls_source"}));
    };
    // Intentionally no CCL re-parse here: older log entries must remain restorable even if the parser tightens.
    rec.cls_source = src.to_string();
    rec.state = WorkflowState::Draft;
    rec.updated_at = chrono::Utc::now().to_rfc3339();
    put_workflow(&state, &rec);
    Json(json!({"ok": true, "workflow": rec, "restored_from_index": idx}))
}

pub fn register_workflow_inner(
    state: &SharedState,
    req: RegisterWorkflowRequest,
) -> Result<Value, Value> {
    if req.workflow_id.trim().is_empty() || req.package_id.trim().is_empty() {
        return Err(json!({"ok": false, "error": "workflow_id and package_id required"}));
    }
    if req.cls_source.trim().is_empty() {
        return Err(json!({
            "ok": false,
            "error": "cls_source is required (CCL text, same parse as POST /api/v1/cls/compile field `source`)",
        }));
    }
    let cls_source = req.cls_source;
    let cls_compile = match compile_ccl_contract(&cls_source) {
        Ok(data) => json!({
            "ok": true,
            "contract_cid": data.contract_cid,
            "contract_name": data.name,
            "version": data.version,
            "block_count": data.block_count,
        }),
        Err(err) => {
            return Err(json!({
                "ok": false,
                "error": "cls_source failed CCL parse (same rules as POST /api/v1/cls/compile)",
                "cls_compile": json!({ "ok": false, "error": err }),
            }));
        }
    };
    let institutions = crate::operator::surface_merge::infer_institutions_from_cls(&cls_source);
    let (accounting_mode, accounting_source) = match req
        .accounting_mode
        .as_deref()
        .and_then(|m| crate::operator::surface_merge::normalize_accounting_mode(m))
    {
        Some(mode) => (mode, "register"),
        None => {
            if req
                .accounting_mode
                .as_ref()
                .is_some_and(|m| !m.trim().is_empty())
            {
                return Err(json!({
                    "ok": false,
                    "error": "accounting_mode must be action or service_monitoring",
                    "accounting_modes": [
                        crate::operator::surface_merge::ACCOUNTING_MODE_ACTION,
                        crate::operator::surface_merge::ACCOUNTING_MODE_SERVICE,
                    ],
                }));
            }
            (
                crate::operator::surface_merge::infer_accounting_mode(&cls_source, &institutions),
                "inferred",
            )
        }
    };

    let rec = WorkflowRecord {
        workflow_id: req.workflow_id.trim().to_string(),
        package_id: req.package_id.trim().to_string(),
        version: req.version.unwrap_or_else(|| "v1".to_string()),
        state: WorkflowState::Draft,
        cls_source,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    put_workflow(state, &rec);
    append_workflow_version_log(state, &rec.workflow_id, &rec.version, &rec.cls_source);

    let seed = json!({
        "schema": "operator_surface.v1",
        "workflow_id": rec.workflow_id,
        "display": {
            "title": rec.workflow_id,
            "subtitle": rec.package_id,
            "category": "workflow"
        },
        "accounting": crate::operator::surface_merge::accounting_block(
            accounting_mode,
            accounting_source
        ),
        "institutions": institutions,
    });
    let _ = crate::operator::surface::put_stored_surface(state, &rec.workflow_id, &seed);

    Ok(json!({
        "ok": true,
        "workflow_id": rec.workflow_id,
        "workflow": rec,
        "runtime": "cls_engine_cnp",
        "cls_compile": cls_compile,
        "accounting": crate::operator::surface_merge::accounting_block(
            accounting_mode,
            accounting_source
        ),
        "contract": {
            "required": ["workflow_id", "package_id", "cls_source"],
            "optional": ["version", "accounting_mode"],
            "cls_source": "CCL text, same parse as POST /api/v1/cls/compile field `source`",
            "accounting_mode": ["action", "service_monitoring"],
        },
    }))
}

pub async fn register_workflow(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RegisterWorkflowRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let playground_sid = crate::services::playground::playground_session_id_from_headers(&headers);
    match register_workflow_inner(&state, req) {
        Ok(v) => {
            if let (Some(sid), Some(workflow_id)) = (
                playground_sid.as_deref(),
                v.get("workflow_id").and_then(|x| x.as_str()),
            ) {
                crate::services::playground::record_workflow_created(
                    &state.playground_sessions,
                    sid,
                    workflow_id,
                );
            }
            Json(v)
        }
        Err(e) => Json(e),
    }
}

/// **`GET /api/v1/workflows/:id`** — one workflow with the same list-row enrichments as **`GET /workflows`**.
pub async fn get_workflow_detail(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> impl IntoResponse {
    let rec = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(WORKFLOW_FOLDER, &workflow_id)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value::<WorkflowRecord>(v).ok())
    };
    let Some(rec) = rec else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "Workflow not found"})),
        )
            .into_response();
    };
    let cnp_reg = crate::services::workflow_cnp::cnp_registration(&state, &workflow_id);
    let mut row = {
        let mut es = state.engine_store.lock().unwrap();
        workflow_list_row_json(&mut **es, &rec)
    };
    if let Some(obj) = row.as_object_mut() {
        obj.insert("runtime".into(), json!(RUNTIME_ID_CLS_CNP_ONLY));
        obj.insert("dual_runtime".into(), json!(false));
        if cnp_reg.is_some() {
            obj.insert("cnp_registered".into(), json!(true));
        }
    }
    Json(json!({
        "ok": true,
        "workflow": row,
        "runtime": RUNTIME_ID_CLS_CNP_ONLY,
        "dual_runtime": false,
        "runtime_contract": RUNTIME_CONTRACT_CLS_CNP,
        "runtime_honesty": "Product ENABLE path is CLS engine + CNP dispatch tokens only (no side executor). Dual-runtime product story retired.",
        "cnp_bus_registration": cnp_reg,
        "hint": "version_log_len is the persisted version log length. Dry-run index fields mirror GET /workflows; use ?hydrate_dry_run_index on the collection route to backfill empty indices (admin).",
    }))
    .into_response()
}

pub async fn list_workflows(
    Query(q): Query<ListWorkflowsQuery>,
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    if q.hydrate_dry_run_index && !crate::services::runtime_control::dev_auth_bypass_allowed() {
        let Some(claims) = auth::extract_claims(&headers) else {
            return hydrate_index_denied_response(StatusCode::UNAUTHORIZED, "Unauthorized");
        };
        let role = auth::PlatformRole::from_str(&claims.role);
        if role.rank() < auth::PlatformRole::Admin.rank() {
            return hydrate_index_denied_response(
                StatusCode::FORBIDDEN,
                "Admin privileges required",
            );
        }
    }
    let mut es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(WORKFLOW_FOLDER, None).unwrap_or_default();
    let mut items: Vec<WorkflowRecord> = keys
        .iter()
        .filter_map(|k| es.folder_get(WORKFLOW_FOLDER, k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<WorkflowRecord>(v).ok())
        .collect();
    items.sort_by(|a, b| a.workflow_id.cmp(&b.workflow_id));

    let mut dry_run_index_hydrations = 0_usize;
    if q.hydrate_dry_run_index {
        for rec in items.iter() {
            if dry_run_index_hydrations >= LIST_WORKFLOWS_HYDRATE_MAX {
                break;
            }
            let idx_empty = es
                .folder_get(WORKFLOW_DRY_RUN_INDEX, &rec.workflow_id)
                .ok()
                .flatten()
                .map(|v| v.as_array().map(|a| a.is_empty()).unwrap_or(true))
                .unwrap_or(true);
            if !idx_empty {
                continue;
            }
            if backfill_workflow_dry_run_index(&mut **es, &rec.workflow_id) > 0 {
                dry_run_index_hydrations += 1;
            }
        }
    }

    let workflows: Vec<Value> = items
        .iter()
        .map(|rec| workflow_list_row_json(&mut **es, rec))
        .collect();
    let mut out = json!({
        "ok": true,
        "count": workflows.len(),
        "workflows": workflows,
        "runtime": RUNTIME_ID_CLS_CNP_ONLY,
        "dual_runtime": false,
        "runtime_contract": RUNTIME_CONTRACT_CLS_CNP,
        "runtime_honesty": "Product ENABLE path is CLS engine + CNP dispatch tokens only (no side executor).",
        "hint": "cls_source_fingerprint is SHA-256/8-byte hex prefix of UTF-8 bytes (no CCL parse). version_log_len counts persisted version-log rows. Optional last_dry_run_id / last_dry_run_recorded_at come from the newest indexed dry-run (empty index → omitted). ?hydrate_dry_run_index=true backfills up to 15 empty indices (bounded scan) and requires Admin auth or dev bypass — omit for unauthenticated listing.",
    });
    if q.hydrate_dry_run_index {
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "dry_run_index_hydrations".into(),
                json!(dry_run_index_hydrations),
            );
            obj.insert(
                "dry_run_index_hydrate_cap".into(),
                json!(LIST_WORKFLOWS_HYDRATE_MAX),
            );
        }
    }
    Json(out).into_response()
}

pub fn apply_workflow_transition(
    state: &SharedState,
    workflow_id: &str,
    to: WorkflowState,
    enqueue_run: bool,
    package: Option<&connector_native_contract::PackagePin>,
) -> Result<Value, Value> {
    let Some(mut rec) = get_workflow(state, workflow_id) else {
        return Err(json!({"ok": false, "error": "Workflow not found"}));
    };
    if rec.state == to {
        return Ok(json!({
            "ok": true,
            "workflow": rec,
            "note": "already in requested state",
        }));
    }
    if !valid_transition(rec.state, to) {
        return Err(json!({
            "ok": false,
            "error": format!("Invalid transition {:?} -> {:?}", rec.state, to)
        }));
    }
    if to == WorkflowState::Enabled {
        if let Err(e) =
            crate::substrate::package_gate::require_package_for_consequential_effect(package)
        {
            return Err(json!({
                "ok": false,
                "error": e,
                "honesty": "workflow ENABLE requires signed AppPackageV2 pin outside lab",
            }));
        }
    }
    let cls_gate_meta = match to {
        WorkflowState::Compiled | WorkflowState::Enabled => {
            match compile_ccl_contract(&rec.cls_source) {
                Ok(data) => Some(data),
                Err(err) => {
                    let msg = if to == WorkflowState::Compiled {
                        "cannot transition to COMPILED: cls_source failed CCL parse"
                    } else {
                        "cannot transition to ENABLED: cls_source failed CCL parse (re-check at activation gate)"
                    };
                    return Err(json!({
                        "ok": false,
                        "error": msg,
                        "cls_compile": json!({ "ok": false, "error": err }),
                    }));
                }
            }
        }
        _ => None,
    };
    let contract_name = cls_gate_meta
        .as_ref()
        .map(|d| d.name.clone())
        .unwrap_or_else(|| rec.workflow_id.clone());
    rec.state = to;
    rec.updated_at = chrono::Utc::now().to_rfc3339();
    put_workflow(state, &rec);
    let mut out = json!({"ok": true, "workflow": rec});
    if let Some(data) = cls_gate_meta {
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "cls_compile".into(),
                json!({
                    "ok": true,
                    "contract_cid": data.contract_cid,
                    "contract_name": data.name,
                    "version": data.version,
                    "block_count": data.block_count,
                }),
            );
        }
    }
    if to == WorkflowState::Enabled {
        let cnp = crate::services::workflow_cnp::register_workflow_on_cnp_bus(
            state,
            &rec.workflow_id,
            &contract_name,
        );
        let cls_run = crate::services::workflow_cls_execution::record_cls_engine_activation(
            state,
            &rec.workflow_id,
            &rec.cls_source,
            &contract_name,
            package,
        );
        let durable = if enqueue_run {
            Some(crate::services::workflow_runner::enqueue_enabled_run(
                state, &rec,
            ))
        } else {
            None
        };
        if let Some(obj) = out.as_object_mut() {
            obj.insert("cnp_dispatch".into(), cnp);
            obj.insert("cls_execution".into(), cls_run);
            if let Some(d) = durable {
                obj.insert("durable_run".into(), d);
            }
            obj.insert("runtime_contract".into(), json!(RUNTIME_CONTRACT_CLS_CNP));
            obj.insert("runtime".into(), json!(RUNTIME_ID_CLS_CNP_ONLY));
            obj.insert("dual_runtime".into(), json!(false));
            obj.insert(
                "isolation_attestation".into(),
                crate::services::plugin_runtime_inventory::current_isolation_attestation(state),
            );
        }
    }
    Ok(out)
}

pub async fn transition_workflow(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<TransitionWorkflowRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let Some(to) = parse_state(&req.state) else {
        return Json(json!({"ok": false, "error": "Invalid state"}));
    };
    match apply_workflow_transition(&state, &workflow_id, to, true, req.package.as_ref()) {
        Ok(v) => Json(v),
        Err(e) => Json(e),
    }
}

pub async fn dry_run_workflow(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<DryRunWorkflowRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let Some(rec) = get_workflow(&state, &workflow_id) else {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    };
    let replay_minutes = req.replay_minutes.unwrap_or(15).max(1);
    let events = req.events.unwrap_or_default();
    let run_id = format!("dry_{}", uuid::Uuid::new_v4().simple());

    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ms = (replay_minutes as i64).saturating_mul(60 * 1000);
    let window_from_ms = now_ms.saturating_sub(window_ms);

    let (events_replayed, cnp_replay, correlation): (usize, Value, &'static str) = if !events
        .is_empty()
    {
        let normalized: Vec<Value> = events
            .iter()
            .enumerate()
            .take(DRY_RUN_AUDIT_REPORT_CAP)
            .map(|(i, e)| normalize_client_dry_run_event(e, i, &workflow_id))
            .collect();
        let has_ids = normalized.iter().any(|e| {
            e.get("event_id")
                .and_then(|x| x.as_str())
                .is_some_and(|s| !s.is_empty())
        });
        let enable_tokens =
            crate::services::workflow_cnp::has_enable_dispatch_tokens(&state, &workflow_id);
        let enable_synth = crate::services::workflow_cnp::synthetic_cnp_events_from_enable_tokens(
            &state,
            &workflow_id,
        );
        let corr = if has_ids { "partial" } else { "audit_tail" };
        let product_mode = if enable_tokens || has_ids {
            "cnp_correlated"
        } else {
            "audit_tail"
        };
        (
            events.len(),
            json!({
                "mode": "client_events",
                "source": "request_body",
                "matched_events": events.len(),
                "events": normalized,
                "truncated": events.len() > DRY_RUN_AUDIT_REPORT_CAP,
                "correlation": corr,
                "product_mode": product_mode,
                "enable_dispatch_tokens": enable_tokens,
                "cnp_enable_synthetic_events": enable_synth,
                "note": "Caller-supplied events with event_id / cnp_correlation fields when present; enable tokens keep product_mode=cnp_correlated. Full CNP topic-bus replay not productized."
            }),
            corr,
        )
    } else {
        let mut audit_rows: Vec<EngineAuditEntry> = {
            let es = state.engine_store.lock().unwrap();
            es.query_audit(&AuditFilter {
                from_ms: Some(window_from_ms),
                to_ms: Some(now_ms),
                limit: Some(DRY_RUN_AUDIT_FETCH_CAP),
                ..Default::default()
            })
            .unwrap_or_default()
        };
        audit_rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let matched_in_window = audit_rows.len();
        let wf_needle = workflow_id.as_str();
        let cnp_correlated: Vec<&EngineAuditEntry> = audit_rows
            .iter()
            .filter(|e| {
                e.agent_pid
                    .as_deref()
                    .is_some_and(|p| p.contains("workflow-cnp"))
                    || e.category.contains("workflow")
                    || e.action.contains("workflow")
                    || e.details
                        .as_ref()
                        .map(|d| d.to_string().contains(wf_needle))
                        .unwrap_or(false)
            })
            .collect();
        let mut category_counts: BTreeMap<String, u64> = BTreeMap::new();
        for e in &audit_rows {
            *category_counts.entry(e.category.clone()).or_insert(0) += 1;
        }
        let compact: Vec<Value> = audit_rows
            .iter()
            .take(DRY_RUN_AUDIT_REPORT_CAP)
            .map(|e| compact_audit_replay_event(e, &workflow_id))
            .collect();
        let cnp_compact: Vec<Value> = cnp_correlated
            .iter()
            .take(DRY_RUN_AUDIT_REPORT_CAP)
            .map(|e| compact_audit_replay_event(e, &workflow_id))
            .collect();
        let cnp_registration =
            crate::services::workflow_cnp::cnp_registration(&state, &workflow_id);
        let enable_tokens =
            crate::services::workflow_cnp::has_enable_dispatch_tokens(&state, &workflow_id);
        let enable_synth = crate::services::workflow_cnp::synthetic_cnp_events_from_enable_tokens(
            &state,
            &workflow_id,
        );
        let report_truncated = matched_in_window > compact.len();
        // Partial when CNP-filtered audit rows exist; otherwise honest audit_tail.
        // Enable tokens keep product_mode=cnp_correlated even when replay is audit_tail.
        let corr = if !cnp_correlated.is_empty() {
            "partial"
        } else {
            "audit_tail"
        };
        let product_mode = if enable_tokens || !cnp_correlated.is_empty() {
            "cnp_correlated"
        } else {
            "audit_tail"
        };
        (
            matched_in_window,
            json!({
                "mode": "engine_audit_window",
                "source": "engine_audit",
                "window_from_ms": window_from_ms,
                "window_to_ms": now_ms,
                "replay_minutes": replay_minutes,
                "matched_events": matched_in_window,
                "cnp_correlated_events": cnp_correlated.len(),
                "events_in_report": compact.len(),
                "report_truncated": report_truncated,
                "fetch_cap": DRY_RUN_AUDIT_FETCH_CAP,
                "report_cap": DRY_RUN_AUDIT_REPORT_CAP,
                "category_counts": category_counts,
                "events": compact,
                "correlation": corr,
                "product_mode": product_mode,
                "enable_dispatch_tokens": enable_tokens,
                "cnp_enable_synthetic_events": enable_synth,
                "cnp_topic_filter": {
                    "workflow_id": workflow_id,
                    "action_topic": crate::services::workflow_cnp::workflow_action_topic(&workflow_id),
                    "event_topic": crate::services::workflow_cnp::workflow_event_topic(&workflow_id),
                },
                "cnp_correlated_audit": cnp_compact,
                "cnp_bus_registration": cnp_registration,
                "note": "Events include synthetic event_id + cnp_correlation; enable-token stubs keep product_mode=cnp_correlated. Source remains kernel audit tail (not live CNP topic bus)."
            }),
            corr,
        )
    };

    let cls_compile = match compile_ccl_contract(&rec.cls_source) {
        Ok(data) => json!({
            "ok": true,
            "contract_cid": data.contract_cid,
            "contract_name": data.name,
            "version": data.version,
            "block_count": data.block_count,
            "warnings": data.warnings,
        }),
        Err(err) => json!({
            "ok": false,
            "error": err,
        }),
    };
    let cls_ok = cls_compile
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let dispatched_actions: Value = if cls_ok {
        match ccl_static_action_blueprint(&rec.cls_source) {
            Ok(rows) => Value::Array(rows),
            Err(_) => Value::Array(vec![]),
        }
    } else {
        Value::Array(vec![])
    };
    let blueprint_n = dispatched_actions.as_array().map(|a| a.len()).unwrap_or(0);
    let cnp_corr_n = cnp_replay
        .get("cnp_correlated_events")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let recorded_at = chrono::Utc::now().to_rfc3339();
    let enable_tokens =
        crate::services::workflow_cnp::has_enable_dispatch_tokens(&state, &workflow_id);
    let product_mode = cnp_replay
        .get("product_mode")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if enable_tokens || cnp_corr_n > 0 {
                "cnp_correlated".into()
            } else {
                correlation.to_string()
            }
        });
    // When audit-tail only but ENABLE tokens exist, still attach synthetic CNP event ids.
    let enable_synth = if product_mode == "cnp_correlated" {
        cnp_replay
            .get("cnp_enable_synthetic_events")
            .cloned()
            .unwrap_or_else(|| {
                Value::Array(
                    crate::services::workflow_cnp::synthetic_cnp_events_from_enable_tokens(
                        &state,
                        &workflow_id,
                    ),
                )
            })
    } else {
        Value::Array(vec![])
    };
    let honesty = if product_mode == "cnp_correlated" && correlation == "audit_tail" {
        format!(
            "dry-run is correlated fabric replay: {correlation}; product_mode=cnp_correlated (enable tokens / synthetic CNP event_ids)"
        )
    } else {
        format!("dry-run is correlated fabric replay: {correlation}; product_mode={product_mode}")
    };
    let mut correlated_ids: Vec<Value> = cnp_replay
        .get("cnp_correlated_audit")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("event_id").cloned())
                .take(8)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if correlated_ids.is_empty() {
        if let Some(arr) = enable_synth.as_array() {
            for e in arr.iter().take(8) {
                if let Some(id) = e.get("event_id").cloned() {
                    correlated_ids.push(id);
                }
            }
        }
    }
    let would_fire: Vec<Value> = dispatched_actions
        .as_array()
        .map(|a| {
            a.iter()
                .enumerate()
                .map(|(i, op)| {
                    json!({
                        "op_index": i,
                        "would": "fire",
                        "blueprint": op,
                        "correlated_event_ids": correlated_ids.clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let report = json!({
        "run_id": run_id,
        "recorded_at": recorded_at,
        "workflow_id": workflow_id,
        "state": format!("{:?}", rec.state),
        "replay_minutes": replay_minutes,
        "events_replayed": events_replayed,
        "correlation": correlation,
        "product_mode": product_mode,
        "enable_dispatch_tokens": enable_tokens,
        "honesty": honesty.clone(),
        "cnp_replay": cnp_replay,
        "cnp_enable_synthetic_events": enable_synth,
        "cls_compile": cls_compile,
        "dispatched_actions": dispatched_actions,
        "would_fire": would_fire,
        "would_skip": [],
        "diff": {
            "new_actions": blueprint_n,
            "suppressed_actions": 0,
            "cnp_correlated_in_window": cnp_corr_n,
            "blueprint_only": cnp_corr_n == 0 && !enable_tokens,
            "note": "new_actions = static CCL blueprint ops; cnp_correlated_in_window = audit rows matching workflow CNP registration; enable tokens yield product_mode=cnp_correlated with synthetic event_ids."
        },
        "side_effects": false,
        "cnp_audit": {
            "fabric": "cnp",
            "direct_plugin_dispatch": false,
            "note": "Workflow actions are dispatched through CNP with kernel-scoped tokens (contract); replay does not mint tokens."
        },
        "note": "CCL parse + static blueprint + audit-tail/partial CNP correlation. product_mode=cnp_correlated when ENABLE tokens exist. Full fabric topic replay remains open (P3.2)."
    });
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(WORKFLOW_RUN_FOLDER, &run_id, &report);
    append_workflow_dry_run_index(&mut **es, &workflow_id, &run_id, &recorded_at);
    Json(json!({
        "ok": cls_ok,
        "dry_run": report,
        "correlation": correlation,
        "product_mode": product_mode,
        "honesty": honesty,
        "error": if cls_ok { Value::Null } else { json!("workflow cls_source failed CCL parse (see dry_run.cls_compile.error)") }
    }))
}

/// **`GET /api/v1/workflows/:id/builder-round-trip`** — honesty stub for visual ↔ CLS ↔ package (P3.3).
///
/// When a session CLS fingerprint exists (non-empty `cls_source`), `round_trip` is **`partial`**
/// (fingerprint preserve only). Full visual ↔ source ↔ package remains open (`ok` only after that).
pub async fn get_builder_round_trip_status(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
) -> Json<Value> {
    let Some(rec) = get_workflow(&state, &workflow_id) else {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    };
    let fp = cls_source_fingerprint(&rec.cls_source);
    let session_fingerprint = !rec.cls_source.trim().is_empty();
    let round_trip = if session_fingerprint {
        "partial"
    } else {
        "planned"
    };
    Json(json!({
        "ok": true,
        "workflow_id": workflow_id,
        "round_trip": round_trip,
        "session_fingerprint": session_fingerprint,
        "contract": "docs/agos/workflow-builder-contract.md",
        "cls_source_fingerprint": fp,
        "cls_source_byte_len": rec.cls_source.len(),
        "honesty": if session_fingerprint {
            "Session CLS fingerprint present — round_trip=partial (fingerprint preserve only). Visual ↔ source ↔ package not closed."
        } else {
            "No session CLS fingerprint yet — round_trip=planned until source is saved."
        },
        "status": {
            "visual_to_source": if session_fingerprint { "partial" } else { "planned" },
            "source_to_package": "planned",
            "package_to_visual": "planned",
        },
    }))
}

pub async fn list_workflow_dry_runs(
    State(state): State<SharedState>,
    Path(workflow_id): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    if get_workflow(&state, &workflow_id).is_none() {
        return Json(json!({"ok": false, "error": "Workflow not found"}));
    }
    let mut es = state.engine_store.lock().unwrap();
    let mut runs: Vec<Value> = es
        .folder_get(WORKFLOW_DRY_RUN_INDEX, &workflow_id)
        .ok()
        .flatten()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut backfilled = false;
    if runs.is_empty() {
        let n = backfill_workflow_dry_run_index(&mut **es, &workflow_id);
        backfilled = n > 0;
        runs = es
            .folder_get(WORKFLOW_DRY_RUN_INDEX, &workflow_id)
            .ok()
            .flatten()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
    }
    Json(json!({
        "ok": true,
        "workflow_id": workflow_id,
        "count": runs.len(),
        "runs": runs,
        "backfilled": backfilled,
        "hint": "GET /api/v1/workflows/{workflow_id}/dry-runs/{run_id} for the full stored report.",
    }))
}

pub async fn get_workflow_dry_run_report(
    State(state): State<SharedState>,
    Path((workflow_id, run_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let es = state.engine_store.lock().unwrap();
    let Some(v) = es.folder_get(WORKFLOW_RUN_FOLDER, &run_id).ok().flatten() else {
        return Json(json!({"ok": false, "error": "Dry-run report not found"}));
    };
    let stored_wid = v.get("workflow_id").and_then(|x| x.as_str()).unwrap_or("");
    if stored_wid != workflow_id {
        return Json(json!({"ok": false, "error": "run_id does not belong to this workflow"}));
    }
    Json(json!({"ok": true, "dry_run": v}))
}

pub async fn register_plugin_workflow_contract(
    State(state): State<SharedState>,
    Path(plugin_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<RegisterPluginWorkflowContractRequest>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }
    let plugin_id = plugin_id.trim().to_ascii_lowercase();
    if !crate::services::plugin_matrix::KNOWN_PLUGINS.contains(&plugin_id.as_str()) {
        return Json(json!({"ok": false, "error": "Unknown plugin id"}));
    }
    let payload = json!({
        "plugin_id": plugin_id,
        "actions": req.actions,
        "events": req.events,
        "registered_at": chrono::Utc::now().to_rfc3339()
    });
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(PLUGIN_WORKFLOW_FOLDER, &plugin_id, &payload);
    Json(json!({"ok": true, "contract": payload}))
}

pub async fn list_plugin_workflow_contracts(State(state): State<SharedState>) -> Json<Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys(PLUGIN_WORKFLOW_FOLDER, None)
        .unwrap_or_default();
    let mut contracts: Vec<Value> = keys
        .iter()
        .filter_map(|k| es.folder_get(PLUGIN_WORKFLOW_FOLDER, k).ok().flatten())
        .collect();
    contracts.sort_by(|a, b| {
        a.get("plugin_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("plugin_id").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Json(json!({"ok": true, "count": contracts.len(), "contracts": contracts}))
}

/// Shipped reference CLS workflows (Phase 3.11) — parse-tested CCL sources for operators and the dashboard.
pub async fn list_reference_templates() -> Json<Value> {
    let templates = vec![
        json!({
            "id": "hitl_approve_audit",
            "name": "HITL Approve-and-Audit",
            "description": "TraceTramp capture → WitnessCtl seal → human approval gate with audit emit.",
            "plugins": ["tracetramp", "witnessctl"],
            "cls_source": include_str!("../../resources/workflow_templates/hitl_approve_audit.ccl"),
        }),
        json!({
            "id": "pii_redaction_pipeline",
            "name": "PII Redaction Pipeline",
            "description": "DevGuard policy scan → LLM gateway rewrite → redaction-complete event.",
            "plugins": ["devguard", "llm_gateway"],
            "cls_source": include_str!("../../resources/workflow_templates/pii_redaction_pipeline.ccl"),
        }),
        json!({
            "id": "incident_slack_jira",
            "name": "Incident → Slack → Jira",
            "description": "Community bridge pattern: alert channel then open tracking ticket (Slack + Jira tools).",
            "plugins": ["slack", "jira"],
            "cls_source": include_str!("../../resources/workflow_templates/incident_slack_jira.ccl"),
        }),
        json!({
            "id": "substrate_memory_moment",
            "name": "Substrate Memory → Moment",
            "description": "U6.4 sample: MemWrite → Moment → UsageEvent → ArtifactLog. No TT/WC/DG — substrate APIs only.",
            "plugins": [],
            "institutions": [],
            "builder_contract": "docs/agos/workflow-builder-contract.md",
            "cls_source": include_str!("../../resources/workflow_templates/substrate_memory_moment.ccl"),
        }),
    ];
    Json(json!({
        "ok": true,
        "count": templates.len(),
        "templates": templates,
        "note": "Bundled with Connector OS; register via POST /api/v1/workflows or connectorctl workflow apply. substrate_memory_moment is the substrate-only builder sample.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydrate_auth_error_value_shape() {
        let v = hydrate_auth_error_value("Unauthorized");
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "Unauthorized");
        assert_eq!(v["code"], "HYDRATE_AUTH_REQUIRED");
        assert!(v["hint"]
            .as_str()
            .unwrap()
            .contains("hydrate_dry_run_index"));
    }

    #[test]
    fn list_workflows_query_hydrate_flag_urlencoded() {
        let q: ListWorkflowsQuery =
            serde_urlencoded::from_str("hydrate_dry_run_index=true").unwrap();
        assert!(q.hydrate_dry_run_index);
        let q: ListWorkflowsQuery = serde_urlencoded::from_str("").unwrap();
        assert!(!q.hydrate_dry_run_index);
        let q: ListWorkflowsQuery =
            serde_urlencoded::from_str("hydrate_dry_run_index=false").unwrap();
        assert!(!q.hydrate_dry_run_index);
    }

    #[test]
    fn enrich_workflow_version_entries_fingerprint_chain() {
        let log = vec![
            json!({"version": "v1", "saved_at": "t0", "cls_source": "alpha"}),
            json!({"version": "v2", "saved_at": "t1", "cls_source": "alpha"}),
            json!({"version": "v3", "saved_at": "t2", "cls_source": "beta"}),
        ];
        let out = enrich_workflow_version_entries(log);
        assert!(out[0]["fingerprint_changed_from_previous"].is_null());
        assert_eq!(out[1]["fingerprint_changed_from_previous"], false);
        assert_eq!(out[2]["fingerprint_changed_from_previous"], true);
        assert_eq!(out[0]["cls_source_byte_len"], 5);
        assert!(out[2]["cls_source_fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }
}
