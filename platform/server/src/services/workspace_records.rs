//! Versioned character, directives, and aliases. None of these records grant an effect.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::{PlatformState, SharedState};

pub const CHARACTER_FOLDER: &str = "character_v1";
pub const DIRECTIVE_FOLDER: &str = "directive_v1";
pub const ALIAS_FOLDER: &str = "alias_binding_v1";
pub const FRAME_DROP_FOLDER: &str = "frame_drop_v1";
pub const ACTIVATION_FOLDER: &str = "activation_receipt_v1";
pub const DIRECTIVE_HISTORY_FOLDER: &str = "directive_activation_v1";

#[derive(Debug, Clone, Copy, Default)]
pub struct RecordCounts {
    pub directives: usize,
    pub character_revision: Option<u64>,
    pub aliases: usize,
    pub frame_drops: usize,
}

pub fn record_counts(state: &PlatformState, pid: &str) -> RecordCounts {
    let Ok(store) = state.engine_store.lock() else {
        return RecordCounts::default();
    };
    let character_revision = store
        .folder_get(CHARACTER_FOLDER, pid)
        .ok()
        .flatten()
        .and_then(|row| row.get("revision").and_then(|v| v.as_u64()));
    let prefix = format!("{pid}:");
    let mut directives = 0usize;
    let mut aliases = 0usize;
    let mut frame_drops = 0usize;
    for key in store.folder_keys(DIRECTIVE_FOLDER, None).unwrap_or_default() {
        if key.starts_with(&prefix) {
            directives += 1;
        }
    }
    for key in store.folder_keys(ALIAS_FOLDER, None).unwrap_or_default() {
        if key.starts_with(&prefix) {
            aliases += 1;
        }
    }
    for key in store.folder_keys(FRAME_DROP_FOLDER, None).unwrap_or_default() {
        if key.starts_with(&prefix) {
            frame_drops += 1;
        }
    }
    RecordCounts {
        directives,
        character_revision,
        aliases,
        frame_drops,
    }
}

pub fn directive_source_allowed(kind: &str) -> bool {
    kind.trim().eq_ignore_ascii_case("operator")
}

#[derive(Debug)]
pub enum DirectivePlacement {
    Inactive,
    Conflict,
    Supersede { previous_id: String, version: i64 },
}

fn directive_live(row: &Value) -> bool {
    row.get("lifecycle").and_then(|value| value.as_str()) != Some("superseded")
}

/// A new directive is inactive, a name clash, or a supersession of one live row.
/// Supersession does not activate the replacement.
pub fn place_directive(
    existing: &[Value],
    name: &str,
    supersedes: Option<&str>,
) -> Result<DirectivePlacement, &'static str> {
    if let Some(previous) = supersedes.map(str::trim).filter(|value| !value.is_empty()) {
        let Some(found) = existing
            .iter()
            .find(|row| row.get("directive_id").and_then(|value| value.as_str()) == Some(previous))
        else {
            return Err("supersedes_absent");
        };
        if !directive_live(found) {
            return Err("already_superseded");
        }
        let other_live = existing.iter().any(|row| {
            row.get("directive_id").and_then(|value| value.as_str()) != Some(previous)
                && row.get("name").and_then(|value| value.as_str()) == Some(name)
                && directive_live(row)
        });
        if other_live {
            return Ok(DirectivePlacement::Conflict);
        }
        let version = found.get("version").and_then(|value| value.as_i64()).unwrap_or(1);
        return Ok(DirectivePlacement::Supersede {
            previous_id: previous.to_string(),
            version,
        });
    }
    if existing
        .iter()
        .any(|row| row.get("name").and_then(|value| value.as_str()) == Some(name) && directive_live(row))
    {
        Ok(DirectivePlacement::Conflict)
    } else {
        Ok(DirectivePlacement::Inactive)
    }
}

fn generic_purpose(item: &str) -> bool {
    let trimmed = item.trim();
    trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("general-purpose")
        || trimmed.eq_ignore_ascii_case("general_purpose")
        || trimmed.eq_ignore_ascii_case("general,assistant")
}

fn digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn authorized(headers: &HeaderMap, pid: &str) -> bool {
    crate::services::agents::caller(headers).is_some()
        || crate::kernel::agent_identity_envelope::agent_self_access(headers, pid)
}

pub(crate) fn lifecycle_error(headers: &HeaderMap) -> Option<Value> {
    crate::services::intelligence_authority::require_lifecycle_actor(headers, 3)
        .err()
        .map(|mut error| {
            if let Some(obj) = error.as_object_mut() {
                obj.insert("executed".into(), json!(false));
                obj.insert("admits".into(), json!(false));
            }
            error
        })
}

#[derive(Debug, Deserialize)]
pub struct CharacterBody {
    pub text: String,
    #[serde(default)]
    pub expected_revision: u64,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub expected_contract_version: Option<u32>,
}

/// GET /api/v1/agents/:pid/character
pub async fn get_character(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "admits": false}));
    }
    let row = state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| store.folder_get(CHARACTER_FOLDER, &pid).ok().flatten());
    match row {
        Some(record) => Json(json!({"ok": true, "status": "present", "character": record, "admits": false})),
        None => Json(json!({"ok": true, "status": "absent", "admits": false})),
    }
}

/// PUT /api/v1/agents/:pid/character
pub async fn put_character(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<CharacterBody>,
) -> Json<Value> {
    if let Some(error) = lifecycle_error(&headers) {
        return Json(error);
    }
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "executed": false, "admits": false}));
    }
    let text = body.text.trim();
    if text.is_empty() || generic_purpose(text) {
        return Json(json!({"ok": false, "error": "specific_character_required", "executed": false, "admits": false}));
    }
    if let Some(purpose) = body.purpose.as_deref().map(str::trim).filter(|item| !item.is_empty()) {
        if generic_purpose(purpose) {
            return Json(json!({"ok": false, "error": "specific_purpose_required", "executed": false, "admits": false}));
        }
        let current = crate::kernel::agent_principal::load_contract(state.as_ref(), &pid);
        let Some(current) = current else {
            return Json(json!({"ok": false, "error": "contract_not_found", "executed": false, "admits": false}));
        };
        if body.expected_contract_version != Some(current.contract_version) {
            return Json(json!({"ok": false, "error": "contract_revision_stale", "executed": false, "admits": false, "contract_version": current.contract_version}));
        }
        if let Err(error) = crate::kernel::agent_principal::update_contract(
            state.as_ref(),
            &pid,
            crate::kernel::agent_principal::ContractPatchV2 {
                purpose: Some(vec![purpose.to_string()]),
                ..crate::kernel::agent_principal::ContractPatchV2::default()
            },
        ) {
            return Json(json!({"ok": false, "error": error, "executed": false, "admits": false}));
        }
    }
    let current = state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| store.folder_get(CHARACTER_FOLDER, &pid).ok().flatten());
    let current_revision = current.as_ref().and_then(|row| row.get("revision").and_then(|v| v.as_u64())).unwrap_or(0);
    if current_revision != body.expected_revision {
        return Json(json!({"ok": false, "error": "character_revision_stale", "executed": false, "admits": false, "revision": current_revision}));
    }
    let contract_version = crate::kernel::agent_principal::load_contract(state.as_ref(), &pid).map(|contract| contract.contract_version);
    let record = json!({
        "schema": "connector.character.v1",
        "agent_pid": pid,
        "revision": current_revision + 1,
        "text_digest_sha256": digest(text),
        "text": text,
        "contract_version": contract_version,
        "lifecycle": "draft",
        "admits": false,
    });
    let saved = state.engine_store.lock().ok().and_then(|mut store| {
        store.folder_put(CHARACTER_FOLDER, &pid, &record).ok()
    });
    if saved.is_none() {
        return Json(json!({"ok": false, "error": "character_not_stored", "executed": false, "admits": false}));
    }
    Json(json!({"ok": true, "character": record, "executed": false, "admits": false}))
}

#[derive(Debug, Deserialize)]
pub struct DirectiveBody {
    pub name: String,
    pub scope: String,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub conditions: String,
    pub source_kind: String,
    pub text: String,
    #[serde(default)]
    pub supersedes: Option<String>,
}

/// GET /api/v1/agents/:pid/directives
pub async fn list_directives(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let ordered = ordered_directives(directives_for(state.as_ref(), &pid));
    Json(json!({
        "ok": true,
        "directives": ordered,
        "honesty": "Agent scope is listed before task scope, then higher priority. Superseded rows stay out of this list. Order is not activation and not a grant.",
    }))
}

pub fn directive_scope_rank(scope: &str) -> i64 {
    match scope.trim() {
        "agent" => 0,
        "task" => 1,
        _ => 2,
    }
}

pub fn ordered_directives(mut rows: Vec<Value>) -> Vec<Value> {
    rows.retain(|row| row.get("lifecycle").and_then(|value| value.as_str()) != Some("superseded"));
    rows.sort_by(|left, right| {
        let scope_left = directive_scope_rank(left.get("scope").and_then(|value| value.as_str()).unwrap_or(""));
        let scope_right = directive_scope_rank(right.get("scope").and_then(|value| value.as_str()).unwrap_or(""));
        let priority_left = left.get("priority").and_then(|value| value.as_i64()).unwrap_or(0);
        let priority_right = right.get("priority").and_then(|value| value.as_i64()).unwrap_or(0);
        scope_left.cmp(&scope_right).then(priority_right.cmp(&priority_left))
    });
    rows
}

fn directives_for(state: &PlatformState, pid: &str) -> Vec<Value> {
    let Ok(store) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{pid}:");
    store
        .folder_keys(DIRECTIVE_FOLDER, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.folder_get(DIRECTIVE_FOLDER, &key).ok().flatten())
        .collect()
}

/// POST /api/v1/agents/:pid/directives
pub async fn post_directive(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<DirectiveBody>,
) -> Json<Value> {
    if let Some(error) = lifecycle_error(&headers) {
        return Json(error);
    }
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "executed": false, "admits": false}));
    }
    if !directive_source_allowed(&body.source_kind) {
        return Json(json!({"ok": false, "error": "knowledge_is_not_a_directive", "executed": false, "admits": false}));
    }
    let name = body.name.trim();
    let text = body.text.trim();
    if name.is_empty() || text.is_empty() || generic_purpose(text) {
        return Json(json!({"ok": false, "error": "specific_directive_required", "executed": false, "admits": false}));
    }
    let existing = directives_for(state.as_ref(), &pid);
    let placement = match place_directive(&existing, name, body.supersedes.as_deref()) {
        Ok(placement) => placement,
        Err(error) => {
            return Json(json!({"ok": false, "error": error, "executed": false, "admits": false}));
        }
    };
    let (lifecycle, conflict, version, supersedes) = match &placement {
        DirectivePlacement::Inactive => ("inactive", "none", 1_i64, body.supersedes.clone()),
        DirectivePlacement::Conflict => ("conflict", "name_already_present", 1_i64, body.supersedes.clone()),
        DirectivePlacement::Supersede { previous_id, version } => {
            ("inactive", "none", version.saturating_add(1), Some(previous_id.clone()))
        }
    };
    let id = format!("dir_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let record = json!({
        "schema": "connector.directive.v1",
        "directive_id": id.clone(),
        "agent_pid": pid,
        "name": name,
        "version": version,
        "scope": body.scope.trim(),
        "priority": body.priority,
        "conditions": body.conditions.trim(),
        "source_kind": "operator",
        "text": text,
        "lifecycle": lifecycle,
        "conflict": conflict,
        "supersedes": supersedes,
        "activation": "inactive",
        "admits": false,
    });
    let key = format!("{pid}:{id}");
    let saved = state.engine_store.lock().ok().and_then(|mut store| store.folder_put(DIRECTIVE_FOLDER, &key, &record).ok());
    if saved.is_none() {
        return Json(json!({"ok": false, "error": "directive_not_stored", "executed": false, "admits": false}));
    }
    if let DirectivePlacement::Supersede { previous_id, .. } = placement {
        if let Ok(mut store) = state.engine_store.lock() {
            let key = format!("{pid}:{previous_id}");
            if let Some(mut previous) = store.folder_get(DIRECTIVE_FOLDER, &key).ok().flatten() {
                if let Some(obj) = previous.as_object_mut() {
                    obj.insert("lifecycle".into(), json!("superseded"));
                    obj.insert("activation".into(), json!("inactive"));
                    obj.insert("superseded_by".into(), json!(id));
                    obj.insert("admits".into(), json!(false));
                }
                let _ = store.folder_put(DIRECTIVE_FOLDER, &key, &previous);
                let history = json!({
                    "schema": "connector.directive_activation.v1",
                    "event": "superseded",
                    "agent_pid": pid,
                    "directive_id": previous_id,
                    "superseded_by": id,
                    "activation": "inactive",
                    "admits": false,
                });
                let _ = store.folder_put(
                    DIRECTIVE_HISTORY_FOLDER,
                    &format!("{pid}:{previous_id}:{id}"),
                    &history,
                );
            }
        }
    }
    Json(json!({"ok": true, "directive": record, "executed": false, "admits": false}))
}

#[derive(Debug, Deserialize)]
pub struct AliasBody {
    pub namespace: String,
    pub alias: String,
    #[serde(default = "default_alias_type")]
    pub alias_type: String,
    pub target_principal: String,
    #[serde(default)]
    pub allowed_use: String,
    pub valid_until_ms: i64,
}

fn default_alias_type() -> String {
    "agent".into()
}

#[derive(Debug, Clone)]
pub struct AliasView {
    pub namespace: String,
    pub alias: String,
    pub target_principal: String,
    pub revoked: bool,
    pub valid_until_ms: i64,
}

pub enum AliasResolution {
    Absent,
    Expired,
    Ambiguous,
    Resolved(String),
}

pub fn alias_may_bind(bindings: &[AliasView], namespace: &str, alias: &str, now_ms: i64) -> bool {
    matches!(
        resolve_aliases(bindings, namespace, alias, now_ms),
        AliasResolution::Absent | AliasResolution::Expired
    )
}

pub fn resolve_aliases(bindings: &[AliasView], namespace: &str, alias: &str, now_ms: i64) -> AliasResolution {
    let matches: Vec<&AliasView> = bindings
        .iter()
        .filter(|item| item.namespace == namespace && item.alias == alias && !item.revoked)
        .collect();
    if matches.is_empty() {
        return AliasResolution::Absent;
    }
    let live: Vec<&&AliasView> = matches.iter().filter(|item| item.valid_until_ms > now_ms).collect();
    match live.as_slice() {
        [] => AliasResolution::Expired,
        [one] => AliasResolution::Resolved((*one).target_principal.clone()),
        _ => AliasResolution::Ambiguous,
    }
}

fn alias_rows(state: &PlatformState, pid: &str) -> Vec<Value> {
    let Ok(store) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{pid}:");
    store
        .folder_keys(ALIAS_FOLDER, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| store.folder_get(ALIAS_FOLDER, &key).ok().flatten())
        .collect()
}

/// POST /api/v1/agents/:pid/aliases
pub async fn post_alias(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<AliasBody>,
) -> Json<Value> {
    if let Some(error) = lifecycle_error(&headers) {
        return Json(error);
    }
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "executed": false, "admits": false}));
    }
    let namespace = body.namespace.trim();
    let alias = body.alias.trim();
    let target = body.target_principal.trim();
    if namespace.is_empty() || alias.is_empty() || target.is_empty() || body.valid_until_ms <= 0 {
        return Json(json!({"ok": false, "error": "alias_fields_required", "executed": false, "admits": false}));
    }
    let id = format!("alias_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let record = json!({
        "schema": "connector.alias_binding.v1",
        "binding_id": id,
        "agent_pid": pid,
        "namespace": namespace,
        "alias": alias,
        "alias_type": body.alias_type,
        "target_principal": target,
        "allowed_use": body.allowed_use,
        "valid_until_ms": body.valid_until_ms,
        "revoked": false,
        "revision": 1,
        "admits": false,
        "honesty": "An alias selects a principal. It does not grant authority.",
    });
    let key = format!("{pid}:{namespace}:{alias}");
    let saved = {
        let Ok(mut store) = state.engine_store.lock() else {
            return Json(json!({"ok": false, "error": "alias_not_stored", "executed": false, "admits": false}));
        };
        let prefix = format!("{pid}:");
        let rows: Vec<Value> = store
            .folder_keys(ALIAS_FOLDER, None)
            .unwrap_or_default()
            .into_iter()
            .filter(|item| item.starts_with(&prefix))
            .filter_map(|item| store.folder_get(ALIAS_FOLDER, &item).ok().flatten())
            .collect();
        let now = chrono::Utc::now().timestamp_millis();
        if !alias_may_bind(&alias_views(&rows), namespace, alias, now) {
            return Json(json!({"ok": false, "error": "alias_ambiguous", "executed": false, "admits": false}));
        }
        store.folder_put(ALIAS_FOLDER, &key, &record).ok()
    };
    if saved.is_none() {
        return Json(json!({"ok": false, "error": "alias_not_stored", "executed": false, "admits": false}));
    }
    Json(json!({"ok": true, "alias": record, "executed": false, "admits": false}))
}

fn alias_views(rows: &[Value]) -> Vec<AliasView> {
    rows.iter()
        .filter_map(|row| {
            Some(AliasView {
                namespace: row.get("namespace")?.as_str()?.to_string(),
                alias: row.get("alias")?.as_str()?.to_string(),
                target_principal: row.get("target_principal")?.as_str()?.to_string(),
                revoked: row.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false),
                valid_until_ms: row.get("valid_until_ms")?.as_i64()?,
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct AliasQuery {
    pub namespace: String,
    pub alias: String,
}

/// GET /api/v1/agents/:pid/aliases/resolve
pub async fn resolve_alias(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Query(query): Query<AliasQuery>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let views = alias_views(&alias_rows(state.as_ref(), &pid));
    let now = chrono::Utc::now().timestamp_millis();
    let status = match resolve_aliases(&views, query.namespace.trim(), query.alias.trim(), now) {
        AliasResolution::Absent => json!({"ok": true, "status": "absent", "admits": false}),
        AliasResolution::Expired => json!({"ok": true, "status": "expired", "admits": false}),
        AliasResolution::Ambiguous => json!({"ok": false, "error": "alias_ambiguous", "status": "ambiguous", "admits": false}),
        AliasResolution::Resolved(target) => json!({"ok": true, "status": "present", "target_principal": target, "admits": false}),
    };
    Json(status)
}

pub fn activation_index(
    agent_pid: &str,
    broker_generation: u64,
    moment_range_id: &str,
    manifest_id: &str,
    transfer_id: &str,
    render_digest: &str,
    model_ref: Option<&str>,
) -> Value {
    json!({
        "schema": "connector.activation_receipt.v1",
        "activation_id": format!("act_{transfer_id}"),
        "agent_pid": agent_pid,
        "broker_generation": broker_generation,
        "moment_range_id": moment_range_id,
        "influence_manifest_id": manifest_id,
        "transfer_id": transfer_id,
        "exact_render_digest": render_digest,
        "model_ref": model_ref,
        "admits": false,
        "authority": false,
        "honesty": "Index of an existing context transfer. It is not a grant and it does not admit an effect.",
    })
}

pub fn persist_activation_index(
    state: &PlatformState,
    agent_pid: &str,
    broker_generation: u64,
    moment_range_id: &str,
    manifest_id: &str,
    transfer_id: &str,
    render_digest: &str,
    model_ref: Option<&str>,
) {
    let record = activation_index(
        agent_pid,
        broker_generation,
        moment_range_id,
        manifest_id,
        transfer_id,
        render_digest,
        model_ref,
    );
    let Ok(mut store) = state.engine_store.lock() else {
        return;
    };
    let id = record.get("activation_id").and_then(|value| value.as_str()).unwrap_or(transfer_id);
    let _ = store.folder_put(ACTIVATION_FOLDER, id, &record);
    let _ = store.folder_put(ACTIVATION_FOLDER, &format!("latest:{agent_pid}"), &record);
    let _ = store.folder_put(
        ACTIVATION_FOLDER,
        &format!("gen:{agent_pid}:{broker_generation}"),
        &record,
    );
}

pub fn latest_activation(state: &PlatformState, agent_pid: &str) -> Option<Value> {
    let store = state.engine_store.lock().ok()?;
    store
        .folder_get(ACTIVATION_FOLDER, &format!("latest:{agent_pid}"))
        .ok()
        .flatten()
}

/// GET /api/v1/agents/:pid/activation
pub async fn get_activation(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "admits": false}));
    }
    match latest_activation(state.as_ref(), &pid) {
        Some(record) => Json(json!({"ok": true, "status": "present", "activation": record, "admits": false})),
        None => Json(json!({"ok": true, "status": "absent", "admits": false})),
    }
}

pub fn persist_frame_drops(state: &PlatformState, agent_pid: &str, moment_range_id: &str, drops: &[Value]) {
    let Ok(mut store) = state.engine_store.lock() else {
        return;
    };
    for drop in drops {
        let frame_id = drop.get("frame_id").and_then(|v| v.as_str()).unwrap_or("frame");
        let key = format!("{agent_pid}:{moment_range_id}:{frame_id}");
        let _ = store.folder_put(FRAME_DROP_FOLDER, &key, drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directive_supersession_stays_inactive() {
        let existing = vec![json!({
            "directive_id": "dir_old",
            "name": "hold",
            "version": 2,
            "lifecycle": "inactive",
        })];
        match place_directive(&existing, "hold", Some("dir_old")).unwrap() {
            DirectivePlacement::Supersede { previous_id, version } => {
                assert_eq!(previous_id, "dir_old");
                assert_eq!(version, 2);
            }
            _ => panic!("expected supersession"),
        }
        assert!(matches!(
            place_directive(&existing, "hold", None).unwrap(),
            DirectivePlacement::Conflict
        ));
        assert_eq!(
            place_directive(&existing, "hold", Some("missing")).unwrap_err(),
            "supersedes_absent"
        );
    }

    #[test]
    fn knowledge_cannot_become_a_directive() {
        assert!(!directive_source_allowed("knowledge"));
        assert!(!directive_source_allowed("instruction"));
        assert!(directive_source_allowed("operator"));
    }

    #[test]
    fn alias_resolution_fails_closed() {
        let bindings = vec![
            AliasView { namespace: "desk".into(), alias: "finance".into(), target_principal: "a".into(), revoked: false, valid_until_ms: 100 },
            AliasView { namespace: "desk".into(), alias: "finance".into(), target_principal: "b".into(), revoked: false, valid_until_ms: 100 },
            AliasView { namespace: "desk".into(), alias: "old".into(), target_principal: "c".into(), revoked: false, valid_until_ms: 10 },
        ];
        assert!(matches!(resolve_aliases(&bindings, "desk", "finance", 50), AliasResolution::Ambiguous));
        assert!(matches!(resolve_aliases(&bindings, "desk", "old", 50), AliasResolution::Expired));
        assert!(matches!(resolve_aliases(&bindings, "desk", "missing", 50), AliasResolution::Absent));
        assert!(!alias_may_bind(&bindings, "desk", "finance", 50));
        assert!(alias_may_bind(&bindings, "desk", "old", 50));
    }

    #[test]
    fn directive_order_is_not_activation() {
        let rows = vec![
            json!({"name": "later", "scope": "task", "priority": 9, "lifecycle": "inactive", "activation": "inactive"}),
            json!({"name": "first", "scope": "agent", "priority": 1, "lifecycle": "inactive", "activation": "inactive"}),
            json!({"name": "gone", "scope": "agent", "priority": 100, "lifecycle": "superseded"}),
        ];
        let ordered = ordered_directives(rows);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0]["name"], "first");
        assert_eq!(ordered[1]["name"], "later");
        assert_eq!(ordered[0]["activation"], "inactive");
    }

    #[test]
    fn activation_index_is_not_authority() {
        let record = activation_index("agent", 4, "range", "manifest", "xfer_1", "digest", Some("model"));
        assert_eq!(record["admits"], false);
        assert_eq!(record["authority"], false);
        let rendered = record.to_string();
        assert!(!rendered.contains("exact_render\":"));
        assert!(rendered.contains("exact_render_digest"));
    }
}
