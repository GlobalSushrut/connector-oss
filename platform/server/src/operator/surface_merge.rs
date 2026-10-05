//! Default `operator_surface.v1` synthesis and merge layers.

use serde_json::{json, Value};

use crate::services::workflow_runtime::{WorkflowRecord, WorkflowState, PLUGIN_WORKFLOW_FOLDER};

pub const OPERATOR_SURFACE_SCHEMA: &str = "operator_surface.v1";
pub const OPERATOR_SURFACE_FOLDER: &str = "operator_surfaces";
pub const WORKFLOW_ACCOUNTING_CONTRACT: &str = "workflow_accounting.v1";

/// Universal two-way accounting modes for every workflow (custom, reference, future).
pub const ACCOUNTING_MODE_ACTION: &str = "action";
pub const ACCOUNTING_MODE_SERVICE: &str = "service_monitoring";

/// Panel types supported by the universal drawer renderer.
pub fn panel_type_registry() -> Value {
    json!({
        "schema": "operator_panel_types.v1",
        "types": [
            { "id": "kv", "label": "Key-value", "description": "Label/value rows from workflow or API" },
            { "id": "summary", "label": "Summary", "description": "Human-first summary text block" },
            { "id": "summary_text", "label": "Summary text", "description": "API-backed summary via summary_fn" },
            { "id": "chips", "label": "Chips", "description": "Tag/chip row" },
            { "id": "institution_chips", "label": "Institution chips", "description": "Plugin health chips from plugins/status" },
            { "id": "event_list", "label": "Event list", "description": "Recent actions from actionlog" },
            { "id": "table", "label": "Table", "description": "Tabular data from API" },
            { "id": "approval_queue", "label": "Approval queue", "description": "Pending approvals (tools or TT)" }
        ],
        "accounting": {
            "contract": WORKFLOW_ACCOUNTING_CONTRACT,
            "modes": [ACCOUNTING_MODE_ACTION, ACCOUNTING_MODE_SERVICE],
            "required": true,
            "description": "Every workflow must declare action (agent/workspace perform) or service_monitoring (observe/seal/route)."
        }
    })
}

/// Normalize workflow_id / template id so `ref-hitl-approve-audit` → `hitl_approve_audit`.
pub fn normalize_reference_template_id(workflow_or_template_id: &str) -> String {
    let s = workflow_or_template_id
        .strip_prefix("ref-")
        .unwrap_or(workflow_or_template_id);
    s.replace('-', "_")
}

/// Bundled reference template manifests (shipped with platform server).
pub fn bundled_reference_surface(workflow_or_template_id: &str) -> Option<Value> {
    let template_id = normalize_reference_template_id(workflow_or_template_id);
    let raw = match template_id.as_str() {
        "hitl_approve_audit" => include_str!(
            "../../resources/workflow_templates/hitl_approve_audit.operator.json"
        ),
        "pii_redaction_pipeline" => include_str!(
            "../../resources/workflow_templates/pii_redaction_pipeline.operator.json"
        ),
        "incident_slack_jira" => include_str!(
            "../../resources/workflow_templates/incident_slack_jira.operator.json"
        ),
        "substrate_memory_moment" => include_str!(
            "../../resources/workflow_templates/substrate_memory_moment.operator.json"
        ),
        _ => return None,
    };
    serde_json::from_str(raw).ok()
}

/// Accept aliases; returns canonical `action` | `service_monitoring`.
pub fn normalize_accounting_mode(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "action" | "actor" | "perform" | "action_based" => Some(ACCOUNTING_MODE_ACTION),
        "service" | "service_monitoring" | "monitoring" | "witness" | "observe"
        | "service_based" => Some(ACCOUNTING_MODE_SERVICE),
        _ => None,
    }
}

/// Infer primary accounting mode from institutions + CCL (always one of the two).
pub fn infer_accounting_mode(cls_source: &str, institutions: &[String]) -> &'static str {
    let has_dg = institutions.iter().any(|i| i == "devguard");
    let has_svc = institutions
        .iter()
        .any(|i| i == "tracetramp" || i == "witnessctl");
    let lower = cls_source.to_ascii_lowercase();
    let actionish = has_dg
        || lower.contains("devguard")
        || lower.contains("tool_call")
        || lower.contains("agent ")
        || lower.contains("cage");
    let serviceish = has_svc
        || lower.contains("monitor")
        || lower.contains("witness")
        || lower.contains("seal")
        || lower.contains("tracetramp")
        || lower.contains("receipt");
    match (actionish, serviceish) {
        (true, false) => ACCOUNTING_MODE_ACTION,
        (false, true) => ACCOUNTING_MODE_SERVICE,
        (true, true) => {
            if has_dg {
                ACCOUNTING_MODE_ACTION
            } else {
                ACCOUNTING_MODE_SERVICE
            }
        }
        // Custom / unknown future builds default to action (perform) unless author declares service.
        (false, false) => ACCOUNTING_MODE_ACTION,
    }
}

pub fn accounting_block(mode: &str, source: &str) -> Value {
    let mode = normalize_accounting_mode(mode).unwrap_or(ACCOUNTING_MODE_ACTION);
    json!({
        "contract": WORKFLOW_ACCOUNTING_CONTRACT,
        "mode": mode,
        "source": source,
        "modes": [ACCOUNTING_MODE_ACTION, ACCOUNTING_MODE_SERVICE],
        "two_way": true,
        "labels": {
            "action": "Action — coding agents, workspace binds, perform/HITL",
            "service_monitoring": "Service monitoring — TraceTramp/WitnessCtl observe, seal, route"
        }
    })
}

/// Ensure merged surface always carries a valid accounting block.
pub fn ensure_accounting(surface: &mut Value, cls_source: &str) {
    let institutions: Vec<String> = surface
        .get("institutions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_else(|| infer_institutions_from_cls(cls_source));

    let existing_mode = surface
        .pointer("/accounting/mode")
        .and_then(|v| v.as_str())
        .and_then(normalize_accounting_mode);
    let source_owned = surface
        .pointer("/accounting/source")
        .and_then(|v| v.as_str())
        .unwrap_or("inferred")
        .to_string();
    let mode = existing_mode.unwrap_or_else(|| infer_accounting_mode(cls_source, &institutions));
    let src = if existing_mode.is_some() {
        source_owned.as_str()
    } else {
        "inferred"
    };
    if let Some(obj) = surface.as_object_mut() {
        obj.insert("accounting".into(), accounting_block(mode, src));
    }
}

/// Infer institution plugin ids from CCL source text (tools, events, comments).
pub fn infer_institutions_from_cls(cls_source: &str) -> Vec<String> {
    let lower = cls_source.to_ascii_lowercase();
    let mut out = Vec::new();
    let candidates = [
        ("tracetramp", "tracetramp"),
        ("witnessctl", "witnessctl"),
        ("witness_seal", "witnessctl"),
        ("devguard", "devguard"),
    ];
    for (needle, id) in candidates {
        if lower.contains(needle) && !out.iter().any(|x: &String| x == id) {
            out.push(id.to_string());
        }
    }
    out
}

fn workflow_state_str(state: WorkflowState) -> &'static str {
    match state {
        WorkflowState::Draft => "DRAFT",
        WorkflowState::Compiled => "COMPILED",
        WorkflowState::Staged => "STAGED",
        WorkflowState::Enabled => "ENABLED",
        WorkflowState::Paused => "PAUSED",
        WorkflowState::Archived => "ARCHIVED",
    }
}

fn humanize_id(id: &str) -> String {
    id.split(['-', '_'])
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Default surface when no manifest is attached.
pub fn default_surface(rec: &WorkflowRecord, workflow_row: &Value) -> Value {
    let institutions = infer_institutions_from_cls(&rec.cls_source);
    let title = humanize_id(&rec.workflow_id);
    let state = workflow_state_str(rec.state);
    let last_run = workflow_row
        .get("last_dry_run_recorded_at")
        .cloned()
        .unwrap_or(Value::Null);
    let mode = infer_accounting_mode(&rec.cls_source, &institutions);

    json!({
        "schema": OPERATOR_SURFACE_SCHEMA,
        "workflow_id": rec.workflow_id,
        "display": {
            "title": title,
            "subtitle": rec.package_id,
            "category": "workflow",
            "icon": "workflow"
        },
        "accounting": accounting_block(mode, "inferred"),
        "institutions": institutions,
        "lifecycle": {
            "primary_action": "dry_run",
            "run_label": "Dry-run",
            // Honest path — DRAFT cannot jump to ENABLED.
            "enable_label": "Activate",
            "state_machine": "DRAFT → COMPILED → STAGED → ENABLED ⇄ PAUSED → ARCHIVED"
        },
        "signals": [
            {
                "id": "state",
                "label": "State",
                "source": "workflow",
                "path": "state",
                "format": "text"
            },
            {
                "id": "last_run",
                "label": "Last run",
                "source": "workflow",
                "path": "last_dry_run_recorded_at",
                "format": "time_ago"
            }
        ],
        "actions": default_actions(state),
        "panels": default_panels(&institutions),
        "fix_rules": [],
        "console_links": default_console_links(&institutions),
        "notifications": [],
        "evidence": [],
        "perform": [],
        "forensics": [],
        "_meta": {
            "source": "default_synthesizer",
            "last_dry_run_recorded_at": last_run
        }
    })
}

fn default_actions(state: &str) -> Vec<Value> {
    // Only advertise transitions the lifecycle API accepts (see workflow_runtime::valid_transition).
    vec![
        json!({
            "id": "dry_run",
            "label": "Dry-run",
            "method": "POST",
            "path": "/workflows/{workflow_id}/dry-run",
            "body": {},
            "when_states": ["ENABLED", "STAGED", "COMPILED", "PAUSED", "DRAFT"]
        }),
        json!({
            "id": "compile",
            "label": "Compile",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "COMPILED" },
            "when_states": ["DRAFT"]
        }),
        json!({
            "id": "stage",
            "label": "Stage",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "STAGED" },
            "when_states": ["COMPILED"]
        }),
        json!({
            "id": "enable",
            "label": "Enable",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "ENABLED" },
            "when_states": ["STAGED", "PAUSED"]
        }),
        json!({
            "id": "activate",
            "label": "Activate (compile→stage→enable)",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "ENABLED" },
            "client_chain": ["COMPILED", "STAGED", "ENABLED"],
            "when_states": ["DRAFT", "COMPILED", "STAGED", "PAUSED"],
            "hint": "UI walks the state machine; a single ENABLED post from DRAFT is rejected."
        }),
        json!({
            "id": "pause",
            "label": "Pause",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "PAUSED" },
            "when_states": ["ENABLED"]
        }),
        json!({
            "id": "archive",
            "label": "Archive",
            "method": "POST",
            "path": "/workflows/{workflow_id}/lifecycle",
            "body": { "state": "ARCHIVED" },
            "when_states": ["DRAFT", "COMPILED", "STAGED", "ENABLED", "PAUSED"]
        }),
        json!({
            "id": "current_state",
            "label": state,
            "kind": "state_badge",
            "when_states": ["DRAFT", "COMPILED", "STAGED", "ENABLED", "PAUSED", "ARCHIVED"]
        }),
    ]
}

fn default_panels(institutions: &[String]) -> Vec<Value> {
    let mut panels = vec![
        json!({
            "id": "summary",
            "title": "Summary",
            "type": "kv",
            "source": "workflow",
            "fields": [
                { "label": "Package", "path": "package_id" },
                { "label": "State", "path": "state" },
                { "label": "Version", "path": "version" }
            ]
        }),
        json!({
            "id": "last_dry_run",
            "title": "Last dry-run",
            "type": "summary_text",
            "source": "api",
            "path": "/workflows/{workflow_id}/dry-runs",
            "summary_fn": "workflow_dry_run_summary"
        }),
    ];
    if !institutions.is_empty() {
        panels.push(json!({
            "id": "institution_health",
            "title": "Institutions",
            "type": "institution_chips",
            "source": "plugins_status",
            "plugin_ids": institutions
        }));
    }
    panels.push(json!({
        "id": "recent_events",
        "title": "Recent activity",
        "type": "event_list",
        "source": "api",
        "path": "/actionlog/actions",
        "query": { "limit": "10" }
    }));
    panels
}

fn default_console_links(institutions: &[String]) -> Vec<Value> {
    institutions
        .iter()
        .filter_map(|id| {
            let path = match id.as_str() {
                "tracetramp" => "/plugins/tracetramp",
                "witnessctl" => "/plugins/witnessctl",
                "devguard" => "/plugins/devguard",
                _ => return None,
            };
            Some(json!({
                "institution_id": id,
                "label": format!("Open {id} console"),
                "tier": "T1",
                "path": path
            }))
        })
        .collect()
}

/// Deep-merge overlay onto base (arrays replaced when present in overlay).
pub fn merge_surface_layers(mut base: Value, overlay: Value) -> Value {
    if overlay.is_null() {
        return base;
    }
    let Some(overlay_obj) = overlay.as_object() else {
        return overlay;
    };
    if !base.is_object() {
        base = json!({});
    }
    let base_obj = base.as_object_mut().expect("object");
    for (k, v) in overlay_obj {
        if v.is_object() {
            let child_base = base_obj.remove(k).unwrap_or(json!({}));
            let merged = merge_surface_layers(child_base, v.clone());
            base_obj.insert(k.clone(), merged);
        } else if !v.is_null() {
            base_obj.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Fold plugin workflow-contract actions/events into surface.
pub fn fold_plugin_contracts(mut surface: Value, contracts: &[Value]) -> Value {
    let institutions: Vec<String> = surface
        .get("institutions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mut actions: Vec<Value> = surface
        .get("actions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for contract in contracts {
        let plugin_id = contract
            .get("plugin_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if plugin_id.is_empty() {
            continue;
        }
        if !institutions.iter().any(|i| i == plugin_id) {
            continue;
        }
        if let Some(plugin_actions) = contract.get("actions").and_then(|v| v.as_array()) {
            for a in plugin_actions {
                let mut entry = a.clone();
                if let Some(obj) = entry.as_object_mut() {
                    obj.entry("source_plugin".to_string())
                        .or_insert(json!(plugin_id));
                }
                actions.push(entry);
            }
        }
    }

    if let Some(obj) = surface.as_object_mut() {
        obj.insert("actions".into(), json!(actions));
    }
    surface
}

/// Resolve merge order: default → bundled template → stored manifest → plugin contracts.
pub fn resolve_merged_surface(
    rec: &WorkflowRecord,
    workflow_row: &Value,
    stored: Option<Value>,
    contracts: &[Value],
) -> Value {
    let mut surface = default_surface(rec, workflow_row);

    let has_stored = stored.is_some();
    let has_bundled = bundled_reference_surface(&rec.workflow_id).is_some();
    if let Some(bundled) = bundled_reference_surface(&rec.workflow_id) {
        surface = merge_surface_layers(surface, bundled);
    }
    if let Some(stored) = stored {
        surface = merge_surface_layers(surface, stored);
    }
    surface = fold_plugin_contracts(surface, contracts);
    ensure_accounting(&mut surface, &rec.cls_source);

    if let Some(obj) = surface.as_object_mut() {
        obj.insert("workflow_id".into(), json!(rec.workflow_id));
        obj.insert("schema".into(), json!(OPERATOR_SURFACE_SCHEMA));
        obj.insert(
            "_meta".into(),
            json!({
                "merged_at": chrono::Utc::now().to_rfc3339(),
                "has_stored_manifest": has_stored,
                "has_bundled_template": has_bundled,
            }),
        );
    }
    surface
}

/// Load plugin workflow contracts relevant to a workflow's institutions.
pub fn load_plugin_contracts_for_institutions(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    institutions: &[String],
) -> Vec<Value> {
    let mut out = Vec::new();
    for id in institutions {
        if let Ok(Some(v)) = es.folder_get(PLUGIN_WORKFLOW_FOLDER, id) {
            out.push(v);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::workflow_runtime::WorkflowState;

    #[test]
    fn default_surface_has_schema() {
        let rec = WorkflowRecord {
            workflow_id: "hitl_approve_audit".into(),
            package_id: "hitl".into(),
            version: "v1".into(),
            state: WorkflowState::Draft,
            cls_source: "tool tracetramp_record tool witness_seal".into(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let row = json!({});
        let s = default_surface(&rec, &row);
        assert_eq!(
            s.get("schema").and_then(|v| v.as_str()),
            Some(OPERATOR_SURFACE_SCHEMA)
        );
        let inst = s.get("institutions").and_then(|v| v.as_array()).unwrap();
        assert!(inst.iter().any(|x| x == "tracetramp"));
        assert!(inst.iter().any(|x| x == "witnessctl"));
        assert_eq!(
            s.pointer("/accounting/mode").and_then(|v| v.as_str()),
            Some(ACCOUNTING_MODE_SERVICE)
        );
    }

    #[test]
    fn bundled_hitl_manifest_loads() {
        let m = bundled_reference_surface("ref-hitl-approve-audit").expect("bundled");
        assert_eq!(
            m.get("display")
                .and_then(|d| d.get("title"))
                .and_then(|t| t.as_str()),
            Some("HITL Approve and Audit")
        );
        assert_eq!(
            m.pointer("/accounting/mode").and_then(|v| v.as_str()),
            Some(ACCOUNTING_MODE_SERVICE)
        );
    }

    #[test]
    fn infer_devguard_is_action() {
        let mode = infer_accounting_mode("tool devguard_scan", &["devguard".into()]);
        assert_eq!(mode, ACCOUNTING_MODE_ACTION);
    }

    #[test]
    fn merge_overlay_replaces_arrays() {
        let base = json!({ "signals": [{"id": "a"}], "display": { "title": "Base" } });
        let overlay = json!({ "signals": [{"id": "b"}], "display": { "subtitle": "Sub" } });
        let merged = merge_surface_layers(base, overlay);
        assert_eq!(merged["display"]["title"], "Base");
        assert_eq!(merged["display"]["subtitle"], "Sub");
        assert_eq!(merged["signals"][0]["id"], "b");
    }
}
