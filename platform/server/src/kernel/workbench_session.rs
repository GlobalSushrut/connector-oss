//! Workbench session journal — orchestrator source of truth.
//!
//! Talk completions persist text only. Workbench owns typed events:
//! user · assistant (projected) · order · admission · tool · hitl · system.
//!
//! Turn appends orders. Admit (DAL/PATE) is the only path that creates `tool` events.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const SESSIONS_FOLDER: &str = "workbench_sessions_v1";
pub const SCHEMA: &str = "connector.workbench.session.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkbenchPhase {
    Idle,
    Consulting,
    AwaitAdmit,
    Acting,
    HitlWait,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    User,
    Assistant,
    Order,
    Admission,
    Tool,
    Hitl,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmTurn {
    pub role: String,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkbenchEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub at_ms: i64,
    pub content: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkbenchSession {
    pub schema: String,
    pub session_id: String,
    pub agent_pid: String,
    pub title: String,
    pub goal: String,
    #[serde(default)]
    pub dal_run_id: Option<String>,
    pub phase: WorkbenchPhase,
    pub events: Vec<WorkbenchEvent>,
    #[serde(default)]
    pub pending_order_ids: Vec<String>,
    /// Orders held after PATE Ask — resume re-queues them; deny cancels them.
    #[serde(default)]
    pub held_order_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hitl_request_id: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl WorkbenchSession {
    pub fn new(agent_pid: &str, title: Option<&str>, goal: Option<&str>) -> Self {
        let now = now_ms();
        let session_id = format!(
            "wb_{}",
            &hex::encode(Sha256::digest(format!("{agent_pid}|{now}").as_bytes()))[..16]
        );
        let goal = goal.unwrap_or("").trim().to_string();
        Self {
            schema: SCHEMA.into(),
            session_id,
            agent_pid: agent_pid.into(),
            title: title.unwrap_or("Workbench").into(),
            goal: if goal.is_empty() {
                "Consult and admit orders".into()
            } else {
                goal
            },
            dal_run_id: None,
            phase: WorkbenchPhase::Idle,
            events: Vec::new(),
            pending_order_ids: Vec::new(),
            held_order_ids: Vec::new(),
            hitl_request_id: None,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn append_user(&mut self, text: &str) -> &WorkbenchEvent {
        self.phase = WorkbenchPhase::Consulting;
        self.push(EventKind::User, text, json!({}))
    }

    pub fn append_assistant_projected(
        &mut self,
        text: &str,
        projection_outcome: &str,
        work_unit: Value,
        binding: Value,
        mutations: Vec<String>,
        tool_calls: Option<Value>,
        aipsprt: Option<Value>,
    ) -> Vec<String> {
        let mut payload = json!({
            "projection_outcome": projection_outcome,
            "work_unit": work_unit,
            "binding": binding,
            "mutations": mutations,
            "tool_calls": tool_calls,
        });
        if let Some(p) = aipsprt {
            payload["aipsprt"] = p;
        }
        self.push(EventKind::Assistant, text, payload);
        let mut new_orders = Vec::new();
        if let Some(calls) = tool_calls.as_ref().and_then(|v| v.as_array()) {
            for call in calls {
                let order_id = self.append_order(call);
                new_orders.push(order_id);
            }
        }
        self.phase = if self.pending_order_ids.is_empty() {
            WorkbenchPhase::Idle
        } else {
            WorkbenchPhase::AwaitAdmit
        };
        new_orders
    }

    pub fn append_order(&mut self, openai_call: &Value) -> String {
        let call_id = openai_call
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let tool_name = openai_call
            .pointer("/function/name")
            .or_else(|| openai_call.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let args = openai_call
            .pointer("/function/arguments")
            .or_else(|| openai_call.get("arguments"))
            .cloned()
            .unwrap_or(json!({}));
        let ev = self.push(
            EventKind::Order,
            &format!("order:{tool_name}"),
            json!({
                "call_id": call_id,
                "tool_name": tool_name,
                "arguments": args,
                "openai_call": openai_call,
                "status": "pending",
            }),
        );
        let id = ev.event_id.clone();
        if !self.pending_order_ids.contains(&id) {
            self.pending_order_ids.push(id.clone());
        }
        self.phase = WorkbenchPhase::AwaitAdmit;
        id
    }

    pub fn take_pending_orders(&mut self, wanted: &[String]) -> Vec<WorkbenchEvent> {
        let filter: Vec<String> = if wanted.is_empty() {
            self.pending_order_ids.clone()
        } else {
            wanted.to_vec()
        };
        let mut out = Vec::new();
        let mut remain = Vec::new();
        for id in &self.pending_order_ids {
            if filter.iter().any(|w| w == id) {
                if let Some(ev) = self.events.iter().find(|e| e.event_id == *id).cloned() {
                    out.push(ev);
                }
            } else {
                remain.push(id.clone());
            }
        }
        self.pending_order_ids = remain;
        out
    }

    pub fn mark_order_status(&mut self, order_id: &str, status: &str) {
        if let Some(ev) = self.events.iter_mut().find(|e| e.event_id == order_id) {
            if let Some(obj) = ev.payload.as_object_mut() {
                obj.insert("status".into(), json!(status));
            }
        }
    }

    pub fn cancel_orders(&mut self, wanted: &[String]) -> usize {
        let taken = self.take_pending_orders(wanted);
        let n = taken.len();
        for ev in &taken {
            self.mark_order_status(&ev.event_id, "cancelled");
        }
        if !taken.is_empty() {
            self.push(
                EventKind::System,
                &format!("cancelled {n} order(s) — no ToolDispatch"),
                json!({ "cancelled": taken.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>() }),
            );
        }
        if self.pending_order_ids.is_empty() && self.phase == WorkbenchPhase::AwaitAdmit {
            self.phase = WorkbenchPhase::Idle;
        }
        n
    }

    pub fn append_admission(&mut self, verdict: &str, order_ids: &[String], pate: Value) {
        self.push(
            EventKind::Admission,
            verdict,
            json!({ "verdict": verdict, "order_ids": order_ids, "pate": pate }),
        );
    }

    pub fn append_tool_receipt(
        &mut self,
        call_id: &str,
        tool_name: &str,
        ok: bool,
        action_digest: Option<&str>,
        task_id: Option<&str>,
        result: Value,
        error: Option<&str>,
    ) {
        self.push(
            EventKind::Tool,
            if ok { "tool:ok" } else { "tool:error" },
            json!({
                "call_id": call_id,
                "tool_name": tool_name,
                "ok": ok,
                "action_digest": action_digest,
                "task_id": task_id,
                "result": result,
                "error": error,
            }),
        );
    }

    pub fn append_hitl(&mut self, detail: &str, order_ids: &[String]) {
        self.phase = WorkbenchPhase::HitlWait;
        // Preserve taken orders so FIX approve can re-admit the same bound set.
        for id in order_ids {
            if !self.held_order_ids.contains(id) {
                self.held_order_ids.push(id.clone());
            }
            self.mark_order_status(id, "ask");
        }
        self.push(
            EventKind::Hitl,
            detail,
            json!({ "status": "pending", "order_ids": order_ids }),
        );
    }

    /// Re-queue orders held by PATE Ask so Admit can run them again.
    pub fn resume_held_orders(&mut self) -> usize {
        let held = std::mem::take(&mut self.held_order_ids);
        self.hitl_request_id = None;
        let mut n = 0usize;
        for id in held {
            if self.events.iter().any(|e| e.event_id == id) {
                self.mark_order_status(&id, "pending");
                if !self.pending_order_ids.contains(&id) {
                    self.pending_order_ids.push(id);
                }
                n += 1;
            }
        }
        if n > 0 {
            self.phase = WorkbenchPhase::AwaitAdmit;
            self.push(
                EventKind::System,
                &format!("hitl_approved: re-queued {n} order(s)"),
                json!({ "requeued": n }),
            );
        } else if self.pending_order_ids.is_empty() {
            self.phase = WorkbenchPhase::Idle;
        }
        n
    }

    /// Deny held HITL orders — cancel without ToolDispatch.
    pub fn deny_held_orders(&mut self, reason: &str) -> usize {
        let held = std::mem::take(&mut self.held_order_ids);
        self.hitl_request_id = None;
        let mut n = 0usize;
        for id in &held {
            self.mark_order_status(id, "cancelled");
            n += 1;
        }
        self.push(
            EventKind::Hitl,
            &format!("denied: {reason}"),
            json!({ "status": "denied", "order_ids": held, "reason": reason }),
        );
        self.push(
            EventKind::System,
            &format!("hitl_denied: cancelled {n} order(s) — no ToolDispatch"),
            json!({ "cancelled": n, "reason": reason }),
        );
        if self.pending_order_ids.is_empty() {
            self.phase = WorkbenchPhase::Idle;
        }
        n
    }

    pub fn append_system(&mut self, text: &str, payload: Value) {
        self.push(EventKind::System, text, payload);
    }

    /// Leave Consulting after a failed / timed-out turn so the UI is not stuck forever.
    pub fn clear_consulting_on_error(&mut self) {
        if self.phase == WorkbenchPhase::Consulting {
            self.phase = if self.pending_order_ids.is_empty() {
                WorkbenchPhase::Idle
            } else {
                WorkbenchPhase::AwaitAdmit
            };
        }
    }

    pub fn pending_order_snapshots(&self) -> Vec<Value> {
        self.pending_order_ids
            .iter()
            .filter_map(|id| {
                self.events.iter().find(|e| e.event_id == *id).map(|e| {
                    json!({
                        "order_id": e.event_id,
                        "tool_name": e.payload.get("tool_name"),
                        "call_id": e.payload.get("call_id"),
                        "arguments": e.payload.get("arguments"),
                        "openai_call": e.payload.get("openai_call"),
                    })
                })
            })
            .collect()
    }

    /// OpenAI-style messages for the next governed Talk. Orders are not executed here.
    pub fn llm_messages(&self) -> Vec<LlmTurn> {
        let mut out = Vec::new();
        for ev in &self.events {
            match ev.kind {
                EventKind::User => out.push(LlmTurn {
                    role: "user".into(),
                    content: ev.content.clone(),
                    tool_calls: None,
                    tool_call_id: None,
                }),
                EventKind::Assistant => out.push(LlmTurn {
                    role: "assistant".into(),
                    content: ev.content.clone(),
                    tool_calls: ev.payload.get("tool_calls").cloned(),
                    tool_call_id: None,
                }),
                EventKind::Tool => {
                    let call_id = ev
                        .payload
                        .get("call_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let body = if ev.payload.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                        ev.payload
                            .get("result")
                            .cloned()
                            .unwrap_or(json!({}))
                            .to_string()
                    } else {
                        ev.payload
                            .get("error")
                            .and_then(|x| x.as_str())
                            .unwrap_or("tool_error")
                            .to_string()
                    };
                    out.push(LlmTurn {
                        role: "tool".into(),
                        content: body,
                        tool_calls: None,
                        tool_call_id: if call_id.is_empty() {
                            None
                        } else {
                            Some(call_id)
                        },
                    });
                }
                EventKind::Order
                | EventKind::Admission
                | EventKind::Hitl
                | EventKind::System => {}
            }
        }
        out
    }

    pub fn last_projection_outcome(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find(|e| e.kind == EventKind::Assistant)
            .and_then(|e| {
                e.payload
                    .get("projection_outcome")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            })
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "schema": self.schema,
            "session_id": self.session_id,
            "agent_pid": self.agent_pid,
            "title": self.title,
            "goal": self.goal,
            "dal_run_id": self.dal_run_id,
            "phase": self.phase,
            "pending_order_ids": self.pending_order_ids,
            "held_order_ids": self.held_order_ids,
            "hitl_request_id": self.hitl_request_id,
            "pending_orders": self.pending_order_snapshots(),
            "event_count": self.events.len(),
            "last_projection_outcome": self.last_projection_outcome(),
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
        })
    }

    pub fn document(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    fn push(&mut self, kind: EventKind, content: &str, payload: Value) -> &WorkbenchEvent {
        let now = now_ms();
        let event_id = format!(
            "wbe_{}",
            &hex::encode(Sha256::digest(
                format!("{}|{}|{}|{}", self.session_id, self.events.len(), now, content).as_bytes()
            ))[..14]
        );
        self.events.push(WorkbenchEvent {
            event_id,
            kind,
            at_ms: now,
            content: content.to_string(),
            payload,
        });
        self.updated_at_ms = now;
        self.events.last().expect("just pushed")
    }
}

fn session_key(agent_pid: &str, session_id: &str) -> String {
    format!("{agent_pid}|{session_id}")
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn create_session(
    state: &PlatformState,
    agent_pid: &str,
    title: Option<&str>,
    goal: Option<&str>,
) -> Result<WorkbenchSession, String> {
    let session = WorkbenchSession::new(agent_pid, title, goal);
    save_session(state, &session)?;
    Ok(session)
}

pub fn save_session(state: &PlatformState, session: &WorkbenchSession) -> Result<(), String> {
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    es.folder_put(
        SESSIONS_FOLDER,
        &session_key(&session.agent_pid, &session.session_id),
        &session.document(),
    )
    .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub fn load_session(
    state: &PlatformState,
    agent_pid: &str,
    session_id: &str,
) -> Result<Option<WorkbenchSession>, String> {
    let es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    let v = es
        .folder_get(SESSIONS_FOLDER, &session_key(agent_pid, session_id))
        .map_err(|e| format!("{e:?}"))?;
    Ok(v.and_then(|x| serde_json::from_value(x).ok()))
}

pub fn list_sessions(state: &PlatformState, agent_pid: &str) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let keys = es.folder_keys(SESSIONS_FOLDER, None).unwrap_or_default();
    let prefix = format!("{agent_pid}|");
    let mut out = Vec::new();
    for k in keys {
        if !k.starts_with(&prefix) {
            continue;
        }
        if let Ok(Some(v)) = es.folder_get(SESSIONS_FOLDER, &k) {
            if let Ok(s) = serde_json::from_value::<WorkbenchSession>(v) {
                out.push(s.snapshot());
            }
        }
    }
    out.sort_by(|a, b| {
        let ta = a.get("updated_at_ms").and_then(|x| x.as_i64()).unwrap_or(0);
        let tb = b.get("updated_at_ms").and_then(|x| x.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    out
}

pub fn latest_session(state: &PlatformState, agent_pid: &str) -> Option<WorkbenchSession> {
    let first = list_sessions(state, agent_pid).into_iter().next()?;
    let sid = first.get("session_id")?.as_str()?;
    load_session(state, agent_pid, sid).ok().flatten()
}

/// True when an error/verdict means PATE Ask — do not continue the model.
pub fn is_hitl_signal(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("ask_hitl")
        || t.contains("askhitl")
        || t.contains("pate_ask")
        || t.contains("hitl_required")
        || t.contains("autonomy_ask")
        || (t.contains("ask") && t.contains("hitl"))
}

/// System block injected on Workbench consult so models can propose tools without
/// Ring-1 gateway `tools` (CPO). Proposals become orders; Talk never dispatches.
pub fn order_proposal_system_block(tool_names: &[String]) -> String {
    let catalog = if tool_names.is_empty() {
        "(no MCP tools registered on this node — do not invent tool names)".to_string()
    } else {
        tool_names
            .iter()
            .take(48)
            .map(|n| format!("  - {n}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        r#"[connector.workbench.orders]
Ring-1: you may PROPOSE tools; you must NOT claim any effect ran.
When a tool is needed, emit one or more fenced JSON blocks using exactly this shape:

```connector.order.v1
{{"name":"<tool_name>","arguments":{{}}}}
```

Rules:
- `name` must be one of the registered tools below (or omit proposals).
- `arguments` must be a JSON object (use {{}} if none).
- Never invent ToolDispatch, receipts, or admissions.
- Speak as the active Connector principal.

Registered tools:
{catalog}"#
    )
}

/// Parse `connector.order.v1` fences (and compact JSON arrays) from assistant text.
/// Returns (display_text_without_fences, openai-shaped tool_calls).
pub fn parse_order_proposals(text: &str) -> (String, Vec<Value>) {
    let mut calls: Vec<Value> = Vec::new();
    let mut display = text.to_string();

    // Fenced blocks: ```connector.order.v1 ... ``` or ```json ... ``` with name/arguments.
    let fence_re = regex::Regex::new(
        r"(?s)```(?:connector\.order\.v1|json)\s*(\{.*?\}|\[.*?\])\s*```",
    )
    .ok();
    if let Some(re) = fence_re.as_ref() {
        for cap in re.captures_iter(text) {
            let raw = cap.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
                push_proposal_values(&v, &mut calls);
            }
        }
        display = re.replace_all(&display, "").to_string();
    }

    // Also accept a single-line marker without fence for robust stub/lab models.
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("connector.order.v1:") {
            if let Ok(v) = serde_json::from_str::<Value>(rest.trim()) {
                push_proposal_values(&v, &mut calls);
            }
        }
    }

    // Dedup by (name, arguments digest).
    let mut seen = std::collections::HashSet::new();
    calls.retain(|c| {
        let name = c
            .pointer("/function/name")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let args = c
            .pointer("/function/arguments")
            .and_then(|x| x.as_str())
            .unwrap_or("{}");
        let key = format!("{name}|{args}");
        seen.insert(key)
    });

    let display = display
        .lines()
        .filter(|l| !l.trim().starts_with("connector.order.v1:"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    (display, calls)
}

fn push_proposal_values(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Array(arr) => {
            for item in arr {
                if let Some(call) = normalize_proposal(item) {
                    out.push(call);
                }
            }
        }
        Value::Object(_) => {
            if let Some(call) = normalize_proposal(v) {
                out.push(call);
            }
        }
        _ => {}
    }
}

fn normalize_proposal(v: &Value) -> Option<Value> {
    // Already OpenAI-shaped?
    if v.pointer("/function/name").and_then(|x| x.as_str()).is_some() {
        let mut call = v.clone();
        if call.get("id").and_then(|x| x.as_str()).unwrap_or("").is_empty() {
            let digest = hex::encode(Sha256::digest(call.to_string().as_bytes()));
            if let Some(obj) = call.as_object_mut() {
                obj.insert(
                    "id".into(),
                    json!(format!("call_{}", &digest[..12])),
                );
            }
        }
        if call.get("type").is_none() {
            if let Some(obj) = call.as_object_mut() {
                obj.insert("type".into(), json!("function"));
            }
        }
        return Some(call);
    }

    let name = v
        .get("name")
        .or_else(|| v.get("tool_name"))
        .and_then(|x| x.as_str())?
        .trim();
    if name.is_empty() {
        return None;
    }
    let args = v.get("arguments").cloned().unwrap_or(json!({}));
    let args_s = match args {
        Value::String(s) => s,
        other => other.to_string(),
    };
    let id = format!(
        "call_{}",
        &hex::encode(Sha256::digest(format!("{name}|{args_s}").as_bytes()))[..12]
    );
    Some(json!({
        "id": id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": args_s,
        }
    }))
}

/// Keep only proposals whose tool names exist in `allowed` (empty allowed = keep none).
pub fn filter_proposals_to_registered(calls: Vec<Value>, allowed: &[String]) -> Vec<Value> {
    if allowed.is_empty() {
        return vec![];
    }
    calls
        .into_iter()
        .filter(|c| {
            let name = c
                .pointer("/function/name")
                .or_else(|| c.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            allowed.iter().any(|a| a == name)
        })
        .collect()
}

/// Validate proposal arguments against an MCP `input_schema` (required keys + object shape).
/// Full JSON-Schema validation is not required — missing required fields is enough to refuse minting.
pub fn validate_proposal_against_schema(call: &Value, input_schema: &Value) -> Result<(), String> {
    let args_raw = call
        .pointer("/function/arguments")
        .cloned()
        .unwrap_or(json!("{}"));
    let args = match args_raw {
        Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(json!({})),
        Value::Object(_) => args_raw,
        other => other,
    };
    if !args.is_object() {
        return Err("arguments_must_be_object".into());
    }
    if let Some(req) = input_schema.get("required").and_then(|x| x.as_array()) {
        for key in req {
            let k = key.as_str().unwrap_or("");
            if k.is_empty() {
                continue;
            }
            if args.get(k).is_none() {
                return Err(format!("missing_required:{k}"));
            }
        }
    }
    Ok(())
}

/// Filter to registered tools, then drop proposals that fail schema required-key checks.
/// Returns (kept, rejections as (tool_name, reason)).
pub fn filter_and_validate_proposals(
    calls: Vec<Value>,
    allowed: &[String],
    schemas: &std::collections::HashMap<String, Value>,
) -> (Vec<Value>, Vec<(String, String)>) {
    let registered = filter_proposals_to_registered(calls, allowed);
    let mut kept = Vec::new();
    let mut rejected = Vec::new();
    for call in registered {
        let name = call
            .pointer("/function/name")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        match schemas.get(&name) {
            Some(schema) => match validate_proposal_against_schema(&call, schema) {
                Ok(()) => kept.push(call),
                Err(reason) => rejected.push((name, reason)),
            },
            None => {
                // Registered by name but no schema map entry — keep (name filter already passed).
                kept.push(call);
            }
        }
    }
    (kept, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turn_appends_orders_without_tool_events() {
        let mut s = WorkbenchSession::new("agent_a", Some("t"), Some("goal"));
        s.append_user("look up the account");
        let calls = json!([{
            "id": "call_1",
            "type": "function",
            "function": { "name": "lookup_account", "arguments": "{\"id\":\"1\"}" }
        }]);
        let orders = s.append_assistant_projected(
            "I will look that up.",
            "pass",
            json!({"work_unit_id": "iwu_1"}),
            json!({"bind_tok": "bind_tok_x"}),
            vec![],
            Some(calls), None);
        assert_eq!(orders.len(), 1);
        assert_eq!(s.phase, WorkbenchPhase::AwaitAdmit);
        assert_eq!(s.pending_order_ids.len(), 1);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
        assert_eq!(
            s.events
                .iter()
                .filter(|e| e.kind == EventKind::Order)
                .count(),
            1
        );
    }

    #[test]
    fn cancel_orders_does_not_dispatch() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_user("x");
        s.append_assistant_projected(
            "ok",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        let n = s.cancel_orders(&[]);
        assert_eq!(n, 1);
        assert!(s.pending_order_ids.is_empty());
        assert_eq!(s.phase, WorkbenchPhase::Idle);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
    }

    #[test]
    fn take_pending_is_idempotent() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_assistant_projected(
            "ok",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        let first = s.take_pending_orders(&[]);
        let second = s.take_pending_orders(&[]);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    #[test]
    fn llm_messages_include_tool_results_not_raw_orders() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_user("run it");
        s.append_assistant_projected(
            "proposing",
            "project",
            json!({}),
            json!({}),
            vec!["project:x".into()],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        s.append_tool_receipt("c1", "ping", true, Some("dig"), None, json!({"ok":true}), None);
        let msgs = s.llm_messages();
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
        assert!(msgs[1].tool_calls.is_some());
        assert_eq!(msgs[2].role, "tool");
        assert_eq!(msgs[2].tool_call_id.as_deref(), Some("c1"));
        assert!(!msgs.iter().any(|m| m.content.starts_with("order:")));
    }

    #[test]
    fn session_json_roundtrip() {
        let mut s = WorkbenchSession::new("agent_a", Some("WB"), Some("prove"));
        s.append_user("who are you");
        let v = s.document();
        let back: WorkbenchSession = serde_json::from_value(v).unwrap();
        assert_eq!(back.agent_pid, "agent_a");
        assert_eq!(back.events.len(), 1);
        assert_eq!(back.events[0].kind, EventKind::User);
    }

    #[test]
    fn admission_allow_ask_block_mark_status() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_assistant_projected(
            "propose",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([
                {"id":"c1","function":{"name":"ping","arguments":"{}"}},
                {"id":"c2","function":{"name":"ping","arguments":"{\"n\":1}"}}
            ])), None);
        let taken = s.take_pending_orders(&[]);
        let ids: Vec<String> = taken.iter().map(|e| e.event_id.clone()).collect();
        assert_eq!(ids.len(), 2);

        s.append_admission("allow", &[ids[0].clone()], json!({ "pate": "allow" }));
        s.mark_order_status(&ids[0], "allow");
        assert_eq!(
            s.events
                .iter()
                .find(|e| e.event_id == ids[0])
                .and_then(|e| e.payload.get("status"))
                .and_then(|x| x.as_str()),
            Some("allow")
        );

        s.append_admission("block", &[ids[1].clone()], json!({ "pate": "block" }));
        s.mark_order_status(&ids[1], "block");
        assert!(s.events.iter().any(|e| e.kind == EventKind::Admission));
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));

        // Ask path holds without tool dispatch
        s.append_assistant_projected(
            "again",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c3","function":{"name":"ping","arguments":"{}"}}])), None);
        let held = s.take_pending_orders(&[]);
        let hid: Vec<String> = held.iter().map(|e| e.event_id.clone()).collect();
        s.append_hitl("ask", &hid);
        assert_eq!(s.phase, WorkbenchPhase::HitlWait);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
    }

    #[test]
    fn hitl_signal_detects_pate_ask() {
        assert!(is_hitl_signal("TaskVerdict::AskHitl"));
        assert!(is_hitl_signal("pate_ask required"));
        assert!(!is_hitl_signal("lookup_account"));
        assert!(!is_hitl_signal("ok"));
    }

    #[test]
    fn hitl_resume_requires_approved_status() {
        // resume_held_orders itself does not check FIX — HTTP layer does.
        // Guard the journal helper still requeues without dispatch.
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_assistant_projected(
            "ok",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        let taken = s.take_pending_orders(&[]);
        let ids: Vec<String> = taken.iter().map(|e| e.event_id.clone()).collect();
        s.append_hitl("ask", &ids);
        s.hitl_request_id = Some("hitl_test".into());
        assert_eq!(s.phase, WorkbenchPhase::HitlWait);
        let n = s.resume_held_orders();
        assert_eq!(n, 1);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
    }

    #[test]
    fn parse_order_v1_fence_mints_openai_shaped_calls() {
        let text = r#"I can look that up.

```connector.order.v1
{"name":"lookup_account","arguments":{"id":"1"}}
```
"#;
        let (display, calls) = parse_order_proposals(text);
        assert!(!display.contains("connector.order.v1"));
        assert!(display.contains("I can look that up"));
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].pointer("/function/name").and_then(|x| x.as_str()),
            Some("lookup_account")
        );
    }

    #[test]
    fn filter_drops_unknown_tools() {
        let calls = vec![json!({
            "id": "c1",
            "type": "function",
            "function": { "name": "nope", "arguments": "{}" }
        })];
        let kept = filter_proposals_to_registered(calls, &["ping".into()]);
        assert!(kept.is_empty());
    }

    #[test]
    fn schema_rejects_missing_required_args() {
        let call = json!({
            "id": "c1",
            "type": "function",
            "function": { "name": "lookup", "arguments": "{}" }
        });
        let schema = json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "string" } }
        });
        assert!(validate_proposal_against_schema(&call, &schema).is_err());
        let ok_call = json!({
            "id": "c2",
            "type": "function",
            "function": { "name": "lookup", "arguments": "{\"id\":\"1\"}" }
        });
        assert!(validate_proposal_against_schema(&ok_call, &schema).is_ok());
    }

    #[test]
    fn filter_and_validate_drops_schema_failures() {
        let calls = vec![
            json!({"id":"c1","function":{"name":"lookup","arguments":"{}"}}),
            json!({"id":"c2","function":{"name":"lookup","arguments":"{\"id\":\"9\"}"}}),
        ];
        let mut schemas = std::collections::HashMap::new();
        schemas.insert(
            "lookup".into(),
            json!({ "type": "object", "required": ["id"] }),
        );
        let (kept, rejected) =
            filter_and_validate_proposals(calls, &["lookup".into()], &schemas);
        assert_eq!(kept.len(), 1);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].1, "missing_required:id");
    }

    #[test]
    fn hitl_hold_resume_requeues_without_dispatch() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_assistant_projected(
            "ok",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        let taken = s.take_pending_orders(&[]);
        let ids: Vec<String> = taken.iter().map(|e| e.event_id.clone()).collect();
        s.append_hitl("PATE Ask", &ids);
        assert_eq!(s.phase, WorkbenchPhase::HitlWait);
        assert!(s.pending_order_ids.is_empty());
        assert_eq!(s.held_order_ids.len(), 1);
        let n = s.resume_held_orders();
        assert_eq!(n, 1);
        assert_eq!(s.phase, WorkbenchPhase::AwaitAdmit);
        assert_eq!(s.pending_order_ids.len(), 1);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
    }

    #[test]
    fn hitl_deny_cancels_held() {
        let mut s = WorkbenchSession::new("agent_a", None, None);
        s.append_assistant_projected(
            "ok",
            "pass",
            json!({}),
            json!({}),
            vec![],
            Some(json!([{"id":"c1","function":{"name":"ping","arguments":"{}"}}])), None);
        let taken = s.take_pending_orders(&[]);
        let ids: Vec<String> = taken.iter().map(|e| e.event_id.clone()).collect();
        s.append_hitl("PATE Ask", &ids);
        let n = s.deny_held_orders("operator refused");
        assert_eq!(n, 1);
        assert!(s.held_order_ids.is_empty());
        assert_eq!(s.phase, WorkbenchPhase::Idle);
        assert!(!s.events.iter().any(|e| e.kind == EventKind::Tool));
    }
}
