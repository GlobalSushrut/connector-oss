//! TG-4 — Fabric task SoT (`connector.fabric.task.v2`).
//!
//! Shared by multiagent dispatch and A2A protocol handlers. Terminal states
//! are immutable. Authority metadata travels with every task.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::kernel::agent_principal;
use crate::kernel::matrix_host_egress;
use crate::state::PlatformState;

pub const FABRIC_TASK_SCHEMA: &str = "connector.fabric.task.v2";
pub const FABRIC_TASK_FOLDER: &str = "a2a_tasks";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FabricTaskState {
    Submitted,
    Working,
    InputRequired,
    AuthRequired,
    Completed,
    Failed,
    Canceled,
    Rejected,
}

impl FabricTaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "SUBMITTED",
            Self::Working => "WORKING",
            Self::InputRequired => "INPUT_REQUIRED",
            Self::AuthRequired => "AUTH_REQUIRED",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Canceled => "CANCELED",
            Self::Rejected => "REJECTED",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Canceled | Self::Rejected
        )
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SUBMITTED" | "QUEUED" => Some(Self::Submitted),
            "WORKING" => Some(Self::Working),
            "INPUT_REQUIRED" | "INPUT-REQUIRED" => Some(Self::InputRequired),
            "AUTH_REQUIRED" | "AUTH-REQUIRED" => Some(Self::AuthRequired),
            "COMPLETED" => Some(Self::Completed),
            "FAILED" => Some(Self::Failed),
            "CANCELED" | "CANCELLED" => Some(Self::Canceled),
            "REJECTED" => Some(Self::Rejected),
            _ => None,
        }
    }

    /// Map onto A2A TaskState names (AuthRequired/Rejected collapse to the A2A vocabulary).
    pub fn to_a2a(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Working => "working",
            Self::InputRequired | Self::AuthRequired => "input-required",
            Self::Completed => "completed",
            Self::Failed | Self::Rejected => "failed",
            Self::Canceled => "canceled",
        }
    }

    pub fn from_a2a(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "submitted" => Some(Self::Submitted),
            "working" => Some(Self::Working),
            "input-required" | "input_required" => Some(Self::InputRequired),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "canceled" | "cancelled" => Some(Self::Canceled),
            _ => Self::parse(s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricAuthority {
    pub principal_id: Option<String>,
    pub intelligence_mark: String,
    pub grant_id: Option<String>,
    pub contract_digest: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricTaskV2 {
    pub schema: String,
    pub task_id: String,
    pub context_id: String,
    pub state: FabricTaskState,
    pub from_pid: String,
    pub to_pid: String,
    pub message: Value,
    pub authority: FabricAuthority,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conp_entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<String>,
    /// INPUT_REQUIRED / AUTH_REQUIRED resume payload (same task_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_resume: Option<Value>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn create_task(
    state: &PlatformState,
    from_pid: &str,
    to_pid: &str,
    message: Value,
    namespace: Option<&str>,
    context_id: Option<&str>,
    grant_id: Option<&str>,
    conp_entity_id: Option<&str>,
) -> Result<FabricTaskV2, String> {
    let principal = agent_principal::load_principal(state, from_pid);
    let contract = agent_principal::load_contract(state, from_pid);
    let mark = matrix_host_egress::intelligence_egress_mark_hex(from_pid);
    let now = now_ms();
    let task = FabricTaskV2 {
        schema: FABRIC_TASK_SCHEMA.into(),
        task_id: format!("task_{}", Uuid::new_v4()),
        context_id: context_id
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("ctx_{}", Uuid::new_v4())),
        state: FabricTaskState::Submitted,
        from_pid: from_pid.into(),
        to_pid: to_pid.into(),
        message,
        authority: FabricAuthority {
            principal_id: principal.map(|p| p.principal_id),
            intelligence_mark: mark,
            grant_id: grant_id.map(|s| s.to_string()),
            contract_digest: contract.map(|c| c.contract_digest_sha256),
            namespace: namespace.map(|s| s.to_string()),
        },
        created_at_ms: now,
        updated_at_ms: now,
        conp_entity_id: conp_entity_id.map(|s| s.to_string()),
        terminal_reason: None,
        input_resume: None,
    };
    persist(state, &task)?;
    Ok(task)
}

/// NP-4 — machine-facing fabric tasks must carry CONP EntityId + intelligence mark + grant_id.
pub fn create_machine_task(
    state: &PlatformState,
    from_pid: &str,
    to_pid: &str,
    message: Value,
    namespace: Option<&str>,
    context_id: Option<&str>,
    grant_id: Option<&str>,
    conp_entity_id: Option<&str>,
) -> Result<FabricTaskV2, String> {
    let entity = conp_entity_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "conp_entity_id_required".to_string())?;
    let gid = grant_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "grant_id_required".to_string())?;
    create_task(
        state,
        from_pid,
        to_pid,
        message,
        namespace,
        context_id,
        Some(gid),
        Some(entity),
    )
}

/// NP-4 — A2A TaskState ↔ fabric.v2 ↔ CNP L6 (contract) / L7 (cognitive).
pub fn cnp_layer_semantics(state: FabricTaskState) -> Value {
    let (l6, l7) = match state {
        FabricTaskState::Submitted => ("contract_offered", "intent_queued"),
        FabricTaskState::Working => ("contract_executing", "cognitive_in_flight"),
        FabricTaskState::InputRequired => ("contract_awaiting_input", "cognitive_paused"),
        FabricTaskState::AuthRequired => ("contract_awaiting_auth", "cognitive_paused"),
        FabricTaskState::Completed => ("contract_receipt", "cognitive_complete"),
        FabricTaskState::Failed => ("contract_rollback", "cognitive_failed"),
        FabricTaskState::Canceled => ("contract_rollback", "cognitive_canceled"),
        FabricTaskState::Rejected => ("contract_denied", "cognitive_rejected"),
    };
    json!({
        "fabric_state": state.as_str(),
        "a2a_state": state.to_a2a(),
        "cnp_l6_contract": l6,
        "cnp_l7_cognitive": l7,
    })
}

pub fn load_task(state: &PlatformState, task_id: &str) -> Option<FabricTaskV2> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FABRIC_TASK_FOLDER, task_id).ok().flatten()?;
    // Accept v1 queued records by upgrading on read.
    if v.get("schema").and_then(|s| s.as_str()) == Some("connector.fabric.task.v1")
        || v.get("state").and_then(|s| s.as_str()) == Some("queued")
    {
        return Some(upgrade_v1(&v));
    }
    serde_json::from_value(v).ok()
}

fn upgrade_v1(v: &Value) -> FabricTaskV2 {
    let from = v
        .get("from_pid")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let to = v
        .get("to_pid")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let task_id = v
        .get("task_id")
        .and_then(|x| x.as_str())
        .unwrap_or("task_unknown")
        .to_string();
    let now = now_ms();
    FabricTaskV2 {
        schema: FABRIC_TASK_SCHEMA.into(),
        task_id,
        context_id: format!("ctx_legacy_{}", from),
        state: FabricTaskState::Submitted,
        from_pid: from.clone(),
        to_pid: to,
        message: v.get("message").cloned().unwrap_or(Value::Null),
        authority: FabricAuthority {
            principal_id: None,
            intelligence_mark: matrix_host_egress::intelligence_egress_mark_hex(&from),
            grant_id: None,
            contract_digest: None,
            namespace: v
                .get("namespace")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        },
        created_at_ms: now,
        updated_at_ms: now,
        conp_entity_id: None,
        terminal_reason: None,
        input_resume: None,
    }
}

pub fn persist(state: &PlatformState, task: &FabricTaskV2) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let v = serde_json::to_value(task).map_err(|e| e.to_string())?;
    es.folder_put(FABRIC_TASK_FOLDER, &task.task_id, &v)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Transition task state. Terminal → any other = Err.
pub fn transition(
    state: &PlatformState,
    task_id: &str,
    new_state: FabricTaskState,
    reason: Option<&str>,
) -> Result<FabricTaskV2, String> {
    let mut task = load_task(state, task_id).ok_or_else(|| "task_not_found".to_string())?;
    if task.state.is_terminal() {
        return Err(format!(
            "terminal_immutable: state={}",
            task.state.as_str()
        ));
    }
    task.state = new_state;
    task.updated_at_ms = now_ms();
    if new_state.is_terminal() {
        task.terminal_reason = reason.map(|s| s.to_string());
    }
    persist(state, &task)?;
    // TG-5: fabric transitions produce decision traces (principal-bound).
    crate::kernel::decision_trace::append_trace(
        state,
        &task.from_pid,
        crate::kernel::decision_trace::TraceAppendOpts {
            gateway: if new_state.is_terminal() {
                "allow".into()
            } else {
                "allow".into()
            },
            outcome: format!("fabric:{}:{}", task.task_id, new_state.as_str()),
            policy_version: task.authority.contract_digest.clone(),
            capability_id: task.conp_entity_id.clone(),
            message_type: Some("fabric.task".into()),
            ..Default::default()
        },
    );
    Ok(task)
}

/// TG-4: resume same taskId from INPUT_REQUIRED / AUTH_REQUIRED with operator/agent input.
pub fn resume_with_input(
    state: &PlatformState,
    task_id: &str,
    input: Value,
) -> Result<FabricTaskV2, String> {
    let mut task = load_task(state, task_id).ok_or_else(|| "task_not_found".to_string())?;
    if !matches!(
        task.state,
        FabricTaskState::InputRequired | FabricTaskState::AuthRequired
    ) {
        return Err(format!(
            "not_awaiting_input: state={}",
            task.state.as_str()
        ));
    }
    task.input_resume = Some(input.clone());
    task.message = json!({
        "prior": task.message,
        "resume_input": input,
    });
    task.state = FabricTaskState::Working;
    task.updated_at_ms = now_ms();
    persist(state, &task)?;
    crate::kernel::decision_trace::append_trace(
        state,
        &task.from_pid,
        crate::kernel::decision_trace::TraceAppendOpts {
            gateway: "allow".into(),
            outcome: format!("fabric_resume:{}:WORKING", task.task_id),
            policy_version: task.authority.contract_digest.clone(),
            message_type: Some("fabric.resume".into()),
            ..Default::default()
        },
    );
    Ok(task)
}

pub fn list_by_context(state: &PlatformState, context_id: &str) -> Vec<FabricTaskV2> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let keys = es.folder_keys(FABRIC_TASK_FOLDER, None).unwrap_or_default();
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(FABRIC_TASK_FOLDER, &k) {
            if let Ok(t) = serde_json::from_value::<FabricTaskV2>(v.clone()) {
                if t.context_id == context_id {
                    out.push(t);
                    continue;
                }
            }
            // v1 upgrade path
            if v.get("schema").and_then(|s| s.as_str()) == Some("connector.fabric.task.v1") {
                let t = upgrade_v1(&v);
                if t.context_id == context_id {
                    out.push(t);
                }
            }
        }
    }
    out.sort_by_key(|t| t.created_at_ms);
    out
}

pub fn task_json(task: &FabricTaskV2) -> Value {
    json!({
        "ok": true,
        "schema": task.schema,
        "task_id": task.task_id,
        "context_id": task.context_id,
        "state": task.state.as_str(),
        "from_pid": task.from_pid,
        "to_pid": task.to_pid,
        "message": task.message,
        "authority": task.authority,
        "conp_entity_id": task.conp_entity_id,
        "created_at_ms": task.created_at_ms,
        "updated_at_ms": task.updated_at_ms,
        "terminal_reason": task.terminal_reason,
        "terminal": task.state.is_terminal(),
        "cnp": cnp_layer_semantics(task.state),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(FabricTaskState::Completed.is_terminal());
        assert!(FabricTaskState::Rejected.is_terminal());
        assert!(!FabricTaskState::Working.is_terminal());
        assert!(!FabricTaskState::InputRequired.is_terminal());
        assert!(!FabricTaskState::AuthRequired.is_terminal());
        assert_eq!(FabricTaskState::parse("queued"), Some(FabricTaskState::Submitted));
        assert_eq!(
            FabricTaskState::parse("INPUT_REQUIRED"),
            Some(FabricTaskState::InputRequired)
        );
        assert_eq!(
            FabricTaskState::parse("AUTH_REQUIRED"),
            Some(FabricTaskState::AuthRequired)
        );
        assert_eq!(FabricTaskState::Working.to_a2a(), "working");
        assert_eq!(
            FabricTaskState::from_a2a("input-required"),
            Some(FabricTaskState::InputRequired)
        );
        let sem = cnp_layer_semantics(FabricTaskState::Working);
        assert_eq!(sem.get("cnp_l6_contract").and_then(|v| v.as_str()), Some("contract_executing"));
        assert_eq!(sem.get("cnp_l7_cognitive").and_then(|v| v.as_str()), Some("cognitive_in_flight"));
    }

    #[test]
    fn resume_states_are_awaiting_input() {
        for s in ["INPUT_REQUIRED", "INPUT-REQUIRED", "AUTH_REQUIRED"] {
            let st = FabricTaskState::parse(s).expect(s);
            assert!(
                matches!(
                    st,
                    FabricTaskState::InputRequired | FabricTaskState::AuthRequired
                ),
                "{s}"
            );
        }
    }
}
