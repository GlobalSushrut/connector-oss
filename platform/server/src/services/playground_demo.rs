//! Playground Demo — enterprise verbs + banking ops on the Workbench path.
//!
//! Isolate / Govern / Stop / Prove remain. Banking tools mutate a **tenant-scoped
//! in-memory ledger** after Admit / PATE / ToolDispatch so the demo is a real
//! operations loop (score → hold → decide), not a cinematic UI.
//!
//! Honesty: shared VM, KERNEL_ENFORCE=0 on Fly. Isolate DROP is grant-list at the
//! hosted tool. Ledger is session/tenant store on this node — not a real bank core.

use std::sync::{Arc, OnceLock};

use serde_json::{json, Value};

use crate::kernel::workbench_session::WorkbenchSession;
use crate::state::SharedState;

pub const ECHO_TOOL: &str = "demo_echo";
pub const DENY_TOOL: &str = "demo_denied";
pub const RECEIPTS_TOOL: &str = "demo_receipts";

pub const BANK_SCORE_TOOL: &str = "bank_score_tx";
pub const BANK_HOLD_TOOL: &str = "bank_hold_funds";
pub const BANK_DECIDE_TOOL: &str = "bank_decide";
pub const BANK_LEDGER_TOOL: &str = "bank_ledger";

const LEDGER_FOLDER: &str = "playground_bank_ledger_v1";

/// Canonical suspicious wire used in the banking ops demo (matches OSS banking story).
pub const DEMO_WIRE_AMOUNT_USD: f64 = 47_500.0;
pub const DEMO_WIRE_DEST: &str = "Cayman Islands commercial account";
pub const DEMO_WIRE_REF: &str = "WIRE-CY-47500";

pub fn bank_tool_names() -> &'static [&'static str] {
    &[
        BANK_SCORE_TOOL,
        BANK_HOLD_TOOL,
        BANK_DECIDE_TOOL,
        BANK_LEDGER_TOOL,
    ]
}

pub fn all_demo_tool_names() -> &'static [&'static str] {
    &[
        ECHO_TOOL,
        DENY_TOOL,
        RECEIPTS_TOOL,
        BANK_SCORE_TOOL,
        BANK_HOLD_TOOL,
        BANK_DECIDE_TOOL,
        BANK_LEDGER_TOOL,
        "tool:demo/echo",
        "tool:demo/http_get",
        "mcp:demo",
        "tool:cls",
        "tool:bank/score",
        "tool:bank/hold",
        "tool:bank/decide",
        "tool:bank/ledger",
    ]
}

pub fn install_mcp_tools() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        fn ok(text: String) -> connector_protocols::mcp_server::McpToolResult {
            connector_protocols::mcp_server::McpToolResult {
                content: vec![connector_protocols::mcp_server::McpContent {
                    content_type: "text".into(),
                    text,
                }],
                is_error: None,
            }
        }
        fn err(text: String) -> connector_protocols::mcp_server::McpToolResult {
            connector_protocols::mcp_server::McpToolResult {
                content: vec![connector_protocols::mcp_server::McpContent {
                    content_type: "text".into(),
                    text,
                }],
                is_error: Some(true),
            }
        }

        crate::services::mcp_hosting::register_tool(
            ECHO_TOOL,
            "Governed echo — last mile after Admit / PATE. No world HTTP.",
            json!({"type":"object","properties":{
                "text":{"type":"string","description":"Payload to echo under Connector Admit"}
            }}),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let text = args
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("governed echo");
                let body = json!({
                    "ok": true,
                    "verb": "govern",
                    "agent_pid": agent_pid,
                    "echo": text,
                    "honesty": "Admitted ToolDispatch on a hosted playground tool. Not a vendor LLM call. Not Firecracker.",
                });
                record_demo_receipt(state, agent_pid, "govern", &body);
                ok(body.to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            DENY_TOOL,
            "Ungranted dest — DROP. Isolates the world the Demo agent may not dial.",
            json!({"type":"object","properties":{
                "dest":{"type":"string","description":"Destination that is not on the grant list"}
            }}),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let dest = args
                    .get("dest")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ungranted.example");
                let body = json!({
                    "ok": false,
                    "verb": "isolate",
                    "agent_pid": agent_pid,
                    "dest": dest,
                    "effect": "DROP",
                    "honesty": "Dest is not on this agent's grant list. Hosted playground: KERNEL_ENFORCE may be off, so this DROP is the tool last-mile, not nft/Landlock court grade.",
                });
                record_demo_receipt(state, agent_pid, "isolate", &body);
                err(body.to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            RECEIPTS_TOOL,
            "List HMAC / edge receipts this Demo agent produced in the session.",
            json!({"type":"object","properties":{}}),
            Arc::new(|state: &SharedState, agent_pid: &str, _args: Value| {
                let receipts = list_demo_receipts(state, agent_pid);
                ok(json!({
                    "ok": true,
                    "verb": "prove",
                    "agent_pid": agent_pid,
                    "count": receipts.len(),
                    "receipts": receipts,
                    "honesty": "Issuer HMAC / edge receipts on this node. Evidence a reviewer can inspect — not court-grade quorum, not a sold SOC 2 checkbox.",
                })
                .to_string())
            }),
        );

        // ── Banking ops (tenant ledger) ─────────────────────────────────────
        crate::services::mcp_hosting::register_tool(
            BANK_SCORE_TOOL,
            "Score a wire / ACH for fraud risk (0-100). Reads args; does not move money.",
            json!({"type":"object","properties":{
                "amount_usd":{"type":"number"},
                "destination":{"type":"string"},
                "reference":{"type":"string"},
                "customer_note":{"type":"string"}
            },"required":["amount_usd"]}),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let amount = args
                    .get("amount_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(DEMO_WIRE_AMOUNT_USD);
                let dest = args
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEMO_WIRE_DEST);
                let reference = args
                    .get("reference")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEMO_WIRE_REF);
                let mut score = 12.0;
                let mut signals = vec!["baseline_customer".to_string()];
                if amount >= 10_000.0 {
                    score += 28.0;
                    signals.push("large_wire".into());
                }
                if dest.to_ascii_lowercase().contains("cayman")
                    || dest.to_ascii_lowercase().contains("offshore")
                {
                    score += 35.0;
                    signals.push("high_risk_jurisdiction".into());
                }
                if amount >= 40_000.0 {
                    score += 15.0;
                    signals.push("near_structuring_band".into());
                }
                score = (score as f64).min(99.0);
                let recommendation = if score >= 70.0 {
                    "HOLD_AND_REVIEW"
                } else if score >= 40.0 {
                    "MANUAL_REVIEW"
                } else {
                    "AUTO_CLEAR"
                };
                let body = json!({
                    "ok": true,
                    "op": "bank_score_tx",
                    "agent_pid": agent_pid,
                    "reference": reference,
                    "amount_usd": amount,
                    "destination": dest,
                    "risk_score": score,
                    "signals": signals,
                    "recommendation": recommendation,
                    "honesty": "Model-assisted risk score after Connector Admit. Not a live core-banking decision engine.",
                });
                let _ = upsert_ledger_event(state, agent_pid, "score", &body);
                record_demo_receipt(state, agent_pid, "bank_score", &body);
                ok(body.to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            BANK_HOLD_TOOL,
            "Place a hold on available funds for a wire. Mutates tenant ledger after Admit.",
            json!({"type":"object","properties":{
                "amount_usd":{"type":"number"},
                "reference":{"type":"string"},
                "reason":{"type":"string"}
            },"required":["amount_usd"]}),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let amount = args
                    .get("amount_usd")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(DEMO_WIRE_AMOUNT_USD);
                let reference = args
                    .get("reference")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEMO_WIRE_REF)
                    .to_string();
                let reason = args
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("fraud_review_hold")
                    .to_string();
                match apply_hold(state, agent_pid, amount, &reference, &reason) {
                    Ok(ledger) => {
                        let body = json!({
                            "ok": true,
                            "op": "bank_hold_funds",
                            "agent_pid": agent_pid,
                            "reference": reference,
                            "amount_usd": amount,
                            "reason": reason,
                            "ledger": ledger,
                            "honesty": "Hold applied in playground tenant ledger after Admit. Not FedWire / real bank core.",
                        });
                        record_demo_receipt(state, agent_pid, "bank_hold", &body);
                        ok(body.to_string())
                    }
                    Err(e) => {
                        let body = json!({
                            "ok": false,
                            "op": "bank_hold_funds",
                            "error": e,
                            "honesty": "Hold refused by ledger rules (insufficient available / already held).",
                        });
                        record_demo_receipt(state, agent_pid, "bank_hold_denied", &body);
                        err(body.to_string())
                    }
                }
            }),
        );

        crate::services::mcp_hosting::register_tool(
            BANK_DECIDE_TOOL,
            "Final fraud decision: APPROVE releases hold, DECLINE freezes, REVIEW keeps hold.",
            json!({"type":"object","properties":{
                "decision":{"type":"string","enum":["APPROVE","DECLINE","REVIEW"]},
                "reference":{"type":"string"},
                "rationale":{"type":"string"}
            },"required":["decision"]}),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let decision = args
                    .get("decision")
                    .and_then(|v| v.as_str())
                    .unwrap_or("REVIEW")
                    .to_ascii_uppercase();
                let reference = args
                    .get("reference")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEMO_WIRE_REF)
                    .to_string();
                let rationale = args
                    .get("rationale")
                    .and_then(|v| v.as_str())
                    .unwrap_or("operator_admit")
                    .to_string();
                match apply_decision(state, agent_pid, &decision, &reference, &rationale) {
                    Ok(ledger) => {
                        let body = json!({
                            "ok": true,
                            "op": "bank_decide",
                            "agent_pid": agent_pid,
                            "decision": decision,
                            "reference": reference,
                            "rationale": rationale,
                            "ledger": ledger,
                            "honesty": "Decision recorded on playground ledger after Admit. Not a regulatory filing.",
                        });
                        record_demo_receipt(state, agent_pid, "bank_decide", &body);
                        ok(body.to_string())
                    }
                    Err(e) => {
                        let body = json!({
                            "ok": false,
                            "op": "bank_decide",
                            "error": e,
                        });
                        record_demo_receipt(state, agent_pid, "bank_decide_denied", &body);
                        err(body.to_string())
                    }
                }
            }),
        );

        crate::services::mcp_hosting::register_tool(
            BANK_LEDGER_TOOL,
            "Inspect the tenant playground bank ledger (balances, holds, last decision).",
            json!({"type":"object","properties":{}}),
            Arc::new(|state: &SharedState, agent_pid: &str, _args: Value| {
                let ledger = load_or_init_ledger(state, agent_pid);
                let body = json!({
                    "ok": true,
                    "op": "bank_ledger",
                    "agent_pid": agent_pid,
                    "ledger": ledger,
                    "honesty": "Tenant-scoped in-memory ledger on this playground node.",
                });
                record_demo_receipt(state, agent_pid, "bank_ledger", &body);
                ok(body.to_string())
            }),
        );
    });
}

fn tenant_for_agent(state: &SharedState, agent_pid: &str) -> String {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|es| es.folder_get("agent_meta", agent_pid).ok().flatten())
        .and_then(|m| {
            m.get("tenant_id")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn ledger_key(tenant_id: &str) -> String {
    format!("ledger:{tenant_id}")
}

fn default_ledger(tenant_id: &str) -> Value {
    json!({
        "schema": "connector.playground.bank_ledger.v1",
        "tenant_id": tenant_id,
        "account_id": "chk-ops-1001",
        "currency": "USD",
        "available_usd": 2_000_000.0,
        "held_usd": 0.0,
        "frozen_usd": 0.0,
        "open_holds": [],
        "last_decision": null,
        "events": [],
        "honesty": "Simulated commercial checking for Connector playground ops — not a bank.",
    })
}

fn load_or_init_ledger(state: &SharedState, agent_pid: &str) -> Value {
    let tenant_id = tenant_for_agent(state, agent_pid);
    let key = ledger_key(&tenant_id);
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(LEDGER_FOLDER, &key) {
            return v;
        }
    }
    let ledger = default_ledger(&tenant_id);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(LEDGER_FOLDER, &key, &ledger);
    }
    ledger
}

fn save_ledger(state: &SharedState, tenant_id: &str, ledger: &Value) {
    let key = ledger_key(tenant_id);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(LEDGER_FOLDER, &key, ledger);
    }
}

fn upsert_ledger_event(state: &SharedState, agent_pid: &str, kind: &str, body: &Value) -> Value {
    let tenant_id = tenant_for_agent(state, agent_pid);
    let mut ledger = load_or_init_ledger(state, agent_pid);
    let mut events = ledger
        .get("events")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    events.push(json!({
        "at": chrono::Utc::now().to_rfc3339(),
        "kind": kind,
        "body": body,
    }));
    if events.len() > 40 {
        let skip = events.len() - 40;
        events = events.into_iter().skip(skip).collect();
    }
    ledger["events"] = Value::Array(events);
    save_ledger(state, &tenant_id, &ledger);
    ledger
}

fn apply_hold(
    state: &SharedState,
    agent_pid: &str,
    amount: f64,
    reference: &str,
    reason: &str,
) -> Result<Value, String> {
    if amount <= 0.0 {
        return Err("amount_must_be_positive".into());
    }
    let tenant_id = tenant_for_agent(state, agent_pid);
    let mut ledger = load_or_init_ledger(state, agent_pid);
    let available = ledger
        .get("available_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if amount > available + f64::EPSILON {
        return Err(format!(
            "insufficient_available: need {amount} have {available}"
        ));
    }
    let mut holds = ledger
        .get("open_holds")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default();
    if holds
        .iter()
        .any(|h| h.get("reference").and_then(|r| r.as_str()) == Some(reference))
    {
        return Err(format!("hold_already_open:{reference}"));
    }
    let held = ledger
        .get("held_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    ledger["available_usd"] = json!(available - amount);
    ledger["held_usd"] = json!(held + amount);
    holds.push(json!({
        "reference": reference,
        "amount_usd": amount,
        "reason": reason,
        "at": chrono::Utc::now().to_rfc3339(),
        "status": "OPEN",
    }));
    ledger["open_holds"] = Value::Array(holds);
    let mut events = ledger
        .get("events")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    events.push(json!({
        "at": chrono::Utc::now().to_rfc3339(),
        "kind": "hold",
        "reference": reference,
        "amount_usd": amount,
        "reason": reason,
    }));
    ledger["events"] = Value::Array(events);
    save_ledger(state, &tenant_id, &ledger);
    Ok(ledger)
}

fn apply_decision(
    state: &SharedState,
    agent_pid: &str,
    decision: &str,
    reference: &str,
    rationale: &str,
) -> Result<Value, String> {
    let tenant_id = tenant_for_agent(state, agent_pid);
    let mut ledger = load_or_init_ledger(state, agent_pid);
    let mut holds = ledger
        .get("open_holds")
        .and_then(|h| h.as_array())
        .cloned()
        .unwrap_or_default();
    let idx = holds
        .iter()
        .position(|h| h.get("reference").and_then(|r| r.as_str()) == Some(reference));
    let Some(i) = idx else {
        return Err(format!("no_open_hold:{reference}"));
    };
    let amount = holds[i]
        .get("amount_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let available = ledger
        .get("available_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let held = ledger
        .get("held_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let frozen = ledger
        .get("frozen_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    match decision {
        "APPROVE" => {
            // Release hold — funds leave available (wire posted out).
            ledger["held_usd"] = json!((held - amount).max(0.0));
            holds.remove(i);
            // Available already reduced at hold time; wire posts out (no return).
        }
        "DECLINE" => {
            ledger["held_usd"] = json!((held - amount).max(0.0));
            ledger["frozen_usd"] = json!(frozen + amount);
            holds.remove(i);
        }
        "REVIEW" => {
            if let Some(h) = holds.get_mut(i) {
                h["status"] = json!("REVIEW");
                h["rationale"] = json!(rationale);
            }
        }
        other => return Err(format!("unknown_decision:{other}")),
    }

    ledger["open_holds"] = Value::Array(holds);
    ledger["last_decision"] = json!({
        "decision": decision,
        "reference": reference,
        "rationale": rationale,
        "at": chrono::Utc::now().to_rfc3339(),
        "amount_usd": amount,
        "available_usd_after": ledger.get("available_usd"),
    });
    let _ = available; // hold already deducted available
    let mut events = ledger
        .get("events")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    events.push(json!({
        "at": chrono::Utc::now().to_rfc3339(),
        "kind": "decide",
        "decision": decision,
        "reference": reference,
        "rationale": rationale,
        "amount_usd": amount,
    }));
    ledger["events"] = Value::Array(events);
    save_ledger(state, &tenant_id, &ledger);
    Ok(ledger)
}

pub(crate) fn receipt_key(tenant_id: &str, agent_pid: &str, verb: &str, millis: i64) -> String {
    format!("{tenant_id}:{agent_pid}:{verb}:{millis}")
}

fn record_demo_receipt(state: &SharedState, agent_pid: &str, verb: &str, body: &Value) {
    let tenant_id = tenant_for_agent(state, agent_pid);
    let id = receipt_key(
        &tenant_id,
        agent_pid,
        verb,
        chrono::Utc::now().timestamp_millis(),
    );
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "playground_demo_receipts",
            &id,
            &json!({
                "id": id,
                "tenant_id": tenant_id,
                "agent_pid": agent_pid,
                "verb": verb,
                "at": chrono::Utc::now().to_rfc3339(),
                "body": body,
            }),
        );
    }
}

pub(crate) fn list_demo_receipts(state: &SharedState, agent_pid: &str) -> Vec<Value> {
    let tenant_id = tenant_for_agent(state, agent_pid);
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{tenant_id}:{agent_pid}:");
    let Ok(keys) = es.folder_keys("playground_demo_receipts", Some(prefix.as_str())) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(12) {
        if let Ok(Some(v)) = es.folder_get("playground_demo_receipts", &k) {
            let same_agent = v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid);
            let same_tenant = v.get("tenant_id").and_then(|x| x.as_str()) == Some(tenant_id.as_str());
            if same_agent && same_tenant {
                out.push(v);
            }
        }
    }
    out
}

fn openai_call(tool: &str, arguments: Value) -> Value {
    json!({
        "id": format!("call_demo_{}_{}", tool, uuid::Uuid::new_v4().as_simple()),
        "type": "function",
        "function": {
            "name": tool,
            "arguments": arguments.to_string(),
        }
    })
}

fn demo_wire_args() -> Value {
    json!({
        "amount_usd": DEMO_WIRE_AMOUNT_USD,
        "destination": DEMO_WIRE_DEST,
        "reference": DEMO_WIRE_REF,
    })
}

/// Mutate a live Workbench session for one enterprise / bank verb.
pub fn apply_verb(session: &mut WorkbenchSession, verb: &str) -> Result<&'static str, String> {
    match verb.trim().to_ascii_lowercase().as_str() {
        "isolate" => {
            session.append_assistant_projected(
                "Isolate — proposing an ungranted dest. Admit to run PATE → ToolDispatch. Expect DROP.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_demo_isolate".into()],
                Some(json!([openai_call(
                    DENY_TOOL,
                    json!({"dest": "ungranted.example"})
                )])),
                None,
            );
            Ok("Queued Isolate. Admit the order — ungranted dest DROPs.")
        }
        "govern" => {
            session.append_assistant_projected(
                "Govern — proposing demo_echo. Admit to run PATE → ToolDispatch. Policy before the call.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_demo_govern".into()],
                Some(json!([openai_call(
                    ECHO_TOOL,
                    json!({"text": "enterprise governed echo"})
                )])),
                None,
            );
            Ok("Queued Govern. Admit the order — echo runs only after PATE.")
        }
        "stop" => {
            let n = session.cancel_orders(&[]);
            session.append_system(
                &format!(
                    "Stop — cancelled {n} pending order(s). Kill the loop. Not undo of world effects."
                ),
                json!({
                    "verb": "stop",
                    "cancelled": n,
                    "honesty": "Stop is not rewind. Journals and any prior world effects stay.",
                }),
            );
            Ok("Loop stopped. Pending orders cancelled. Stop is not undo.")
        }
        "prove" => {
            session.append_assistant_projected(
                "Prove — proposing a receipt inspect. Admit to list receipts this agent produced.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_demo_prove".into()],
                Some(json!([openai_call(RECEIPTS_TOOL, json!({}))])),
                None,
            );
            Ok("Queued Prove. Admit to inspect receipts on this node.")
        }
        "score" | "bank_score" => {
            session.append_assistant_projected(
                "Bank ops — proposing bank_score_tx on a $47,500 Cayman wire. Admit to score risk under Connector.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_bank_score".into()],
                Some(json!([openai_call(BANK_SCORE_TOOL, demo_wire_args())])),
                None,
            );
            Ok("Queued bank_score_tx. Admit — risk score runs only after PATE.")
        }
        "hold" | "bank_hold" => {
            session.append_assistant_projected(
                "Bank ops — proposing bank_hold_funds for WIRE-CY-47500 ($47,500). Admit places a real hold on the tenant ledger.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_bank_hold".into()],
                Some(json!([openai_call(
                    BANK_HOLD_TOOL,
                    json!({
                        "amount_usd": DEMO_WIRE_AMOUNT_USD,
                        "reference": DEMO_WIRE_REF,
                        "reason": "high_risk_jurisdiction_wire"
                    })
                )])),
                None,
            );
            Ok("Queued bank_hold_funds. Admit mutates the playground ledger.")
        }
        "decide" | "bank_decide" => {
            session.append_assistant_projected(
                "Bank ops — proposing bank_decide DECLINE on WIRE-CY-47500. Admit freezes held funds on the ledger.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_bank_decide".into()],
                Some(json!([openai_call(
                    BANK_DECIDE_TOOL,
                    json!({
                        "decision": "DECLINE",
                        "reference": DEMO_WIRE_REF,
                        "rationale": "cayman_large_wire_sanctions_review"
                    })
                )])),
                None,
            );
            Ok("Queued bank_decide. Admit records APPROVE/DECLINE/REVIEW on the ledger.")
        }
        "ledger" | "bank_ledger" => {
            session.append_assistant_projected(
                "Bank ops — proposing bank_ledger inspect. Admit to read balances, holds, last decision.",
                "pass",
                Value::Null,
                Value::Null,
                vec!["playground_bank_ledger".into()],
                Some(json!([openai_call(BANK_LEDGER_TOOL, json!({}))])),
                None,
            );
            Ok("Queued bank_ledger. Admit to inspect the tenant ledger.")
        }
        other => Err(format!("unknown_demo_verb:{other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::workbench_session::WorkbenchSession;

    #[test]
    fn install_registers_enterprise_and_bank_tools() {
        install_mcp_tools();
        let names: Vec<String> = crate::services::mcp_hosting::list_tools()
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert!(names.iter().any(|n| n == ECHO_TOOL));
        assert!(names.iter().any(|n| n == BANK_HOLD_TOOL));
        assert!(names.iter().any(|n| n == BANK_SCORE_TOOL));
    }

    #[test]
    fn govern_enqueues_pending_order() {
        let mut s = WorkbenchSession::new("agent_demo", Some("demo"), Some("govern"));
        apply_verb(&mut s, "govern").unwrap();
        assert_eq!(s.pending_order_ids.len(), 1);
    }

    #[test]
    fn hold_enqueues_bank_tool() {
        let mut s = WorkbenchSession::new("agent_demo", Some("demo"), Some("hold"));
        apply_verb(&mut s, "hold").unwrap();
        assert_eq!(s.pending_order_ids.len(), 1);
        let snap = s.pending_order_snapshots();
        let name = snap[0]
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(name, BANK_HOLD_TOOL);
    }

    #[test]
    fn stop_clears_pending() {
        let mut s = WorkbenchSession::new("agent_demo", Some("demo"), Some("stop"));
        apply_verb(&mut s, "govern").unwrap();
        apply_verb(&mut s, "stop").unwrap();
        assert!(s.pending_order_ids.is_empty());
    }

    #[test]
    fn isolate_enqueues_denied_dest() {
        let mut s = WorkbenchSession::new("agent_demo", Some("demo"), Some("isolate"));
        apply_verb(&mut s, "isolate").unwrap();
        assert_eq!(s.pending_order_ids.len(), 1);
        let snap = s.pending_order_snapshots();
        let name = snap[0]
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(name, DENY_TOOL);
    }

    #[test]
    fn receipt_keys_are_tenant_prefixed() {
        let k = receipt_key("pg-aaaa", "agent_demo", "govern", 1);
        assert_eq!(k, "pg-aaaa:agent_demo:govern:1");
        assert!(k.starts_with("pg-aaaa:"));
    }
}
