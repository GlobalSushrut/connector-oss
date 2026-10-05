//! IIA / Charter API helpers (Phase E0).

use serde_json::{json, Value};

use crate::api::{self, ApiError};

pub async fn runtime_self(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/runtime/self?agent_pid={agent_pid}")).await
}

pub async fn identity_envelope(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/identity-envelope")).await
}

pub async fn agent_contract(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/contract")).await
}

pub async fn patch_contract(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::patch_value(&format!("/agents/{agent_pid}/contract"), body).await
}

pub async fn agent_setup(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/setup")).await
}

pub async fn post_setup(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/setup"), body).await
}

pub async fn activate(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/activate"), json!({})).await
}

pub async fn capabilities(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/capabilities")).await
}

pub async fn compliance_contract(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/compliance-contract")).await
}

/// Forced-pid Talk façade (B2). Optional `thread_id` persists turns (B15).
pub async fn completions(
    agent_pid: &str,
    user_text: &str,
    model: &str,
    thread_id: Option<&str>,
) -> Result<Value, ApiError> {
    let mut body = json!({
        "model": model,
        "messages": [
            {"role": "user", "content": user_text}
        ],
        "agent_pid": agent_pid,
    });
    if let Some(tid) = thread_id {
        body["thread_id"] = json!(tid);
    }
    api::post_value_timeout(
        &format!("/agents/{agent_pid}/completions"),
        body,
        api::TALK_COMPLETIONS_TIMEOUT_MS,
    )
    .await
}

/// Principal Projection + Obey-Once receipt from a Talk completions body.
#[derive(Debug, Clone, Default)]
pub struct TalkReceipt {
    pub outcome: String,
    pub work_unit_id: String,
    pub principal_id: String,
    pub character_name: String,
    pub character_purpose: String,
    pub bind_tok: String,
    pub binding_generation: Option<u64>,
    pub attestation_status: String,
    pub mutations: Vec<String>,
    /// AiPassport leave-behind (sibling to content; not inside hashed payload).
    pub aipsprt_id: String,
    pub aipsprt_role: String,
    pub aipsprt_digest_short: String,
}

impl TalkReceipt {
    pub fn is_empty(&self) -> bool {
        self.outcome.is_empty()
            && self.work_unit_id.is_empty()
            && self.principal_id.is_empty()
            && self.attestation_status.is_empty()
            && self.aipsprt_id.is_empty()
    }

    pub fn summary_line(&self) -> String {
        let mut parts = Vec::new();
        if !self.outcome.is_empty() {
            parts.push(format!("projection:{}", self.outcome));
        }
        if !self.character_name.is_empty() {
            parts.push(format!("as {}", self.character_name));
        }
        if !self.principal_id.is_empty() {
            let short = if self.principal_id.len() > 28 {
                format!("{}…", &self.principal_id[..28])
            } else {
                self.principal_id.clone()
            };
            parts.push(short);
        }
        if !self.bind_tok.is_empty() {
            let short = if self.bind_tok.len() > 18 {
                format!("{}…", &self.bind_tok[..18])
            } else {
                self.bind_tok.clone()
            };
            parts.push(format!("bind:{short}"));
        }
        if !self.aipsprt_id.is_empty() {
            let short = if self.aipsprt_id.len() > 18 {
                format!("{}…", &self.aipsprt_id[..18])
            } else {
                self.aipsprt_id.clone()
            };
            parts.push(format!("aipsprt:{short}"));
        }
        if parts.is_empty() {
            "no receipt".into()
        } else {
            parts.join(" · ")
        }
    }
}

fn first_str(v: &Value, paths: &[&str]) -> String {
    for p in paths {
        if let Some(s) = v.pointer(p).and_then(|x| x.as_str()).map(str::trim) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
        // Also try object field without leading slash style via get chain for nested.
        if let Some(s) = v.get(p.trim_start_matches('/')).and_then(|x| x.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

/// Parse Connector Talk receipts (projection / work unit / binding) from API JSON.
pub fn parse_talk_receipt(v: &Value) -> TalkReceipt {
    let root = if v.get("data").is_some() {
        v.get("data").unwrap_or(v)
    } else {
        v
    };
    let outcome = first_str(
        root,
        &[
            "/connector_projection_outcome",
            "/data/connector_projection_outcome",
        ],
    );
    let wu = root
        .get("connector_identity_work_unit")
        .or_else(|| root.pointer("/connector_identity_work_unit"))
        .cloned()
        .unwrap_or(Value::Null);
    let binding = root
        .get("connector_intelligence_binding")
        .or_else(|| root.pointer("/connector_intelligence_binding"))
        .cloned()
        .unwrap_or(Value::Null);
    let attest = root
        .get("connector_output_attestation")
        .or_else(|| root.pointer("/connector_output_attestation"))
        .cloned()
        .unwrap_or(Value::Null);

    let mutations = attest
        .get("enforced_rules")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .filter(|s| s.starts_with("project:") || s.contains("projection"))
                .take(6)
                .collect()
        })
        .unwrap_or_default();

    let principal_id = {
        let a = first_str(&wu, &["/principal_id"]);
        if !a.is_empty() {
            a
        } else {
            first_str(&binding, &["/principal_id"])
        }
    };
    let bind_tok = {
        let a = first_str(&wu, &["/bind_tok"]);
        if !a.is_empty() {
            a
        } else {
            first_str(&binding, &["/bind_tok"])
        }
    };
    let character_name = {
        let a = first_str(&wu, &["/character/name"]);
        if !a.is_empty() {
            a
        } else {
            first_str(&wu, &["/character_name"])
        }
    };
    let character_purpose = {
        let a = first_str(&wu, &["/character/purpose"]);
        if !a.is_empty() {
            a
        } else {
            first_str(&wu, &["/character_purpose"])
        }
    };

    let aipsprt = root
        .get("connector_aipsprt")
        .or_else(|| root.pointer("/connector_aipsprt"))
        .or_else(|| root.pointer("/payload/aipsprt"))
        .cloned()
        .unwrap_or(Value::Null);
    let aipsprt_id = first_str(&aipsprt, &["/passport_id"]);
    let aipsprt_role = first_str(&aipsprt, &["/provenance_role"]);
    let digest = first_str(
        &aipsprt,
        &["/payload/digest", "/digest_hex", "/payload_digest"],
    );
    let aipsprt_digest_short = if digest.len() > 12 {
        format!("{}…", &digest[..12])
    } else {
        digest
    };

    TalkReceipt {
        outcome: if outcome.is_empty() {
            first_str(&attest, &["/status"])
        } else {
            outcome
        },
        work_unit_id: first_str(&wu, &["/work_unit_id"]),
        principal_id,
        character_name,
        character_purpose,
        bind_tok,
        binding_generation: binding
            .get("generation")
            .or_else(|| binding.get("binding_generation"))
            .and_then(|x| x.as_u64()),
        attestation_status: first_str(&attest, &["/status"]),
        mutations,
        aipsprt_id,
        aipsprt_role,
        aipsprt_digest_short,
    }
}

/// Format live burn meter JSON for status chips (admit ledger ≠ provider invoice).
pub fn format_burn_chip(v: &Value) -> String {
    let burn = v.get("burn");
    if burn.map(|b| b.is_null()).unwrap_or(true) {
        let n = v
            .get("inflight_count")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        if n > 0 {
            return format!("burn · — · inflight {n}");
        }
        return String::new();
    }
    let rem_usd = burn
        .and_then(|b| b.get("remaining_usd"))
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0);
    let rem_tok = burn
        .and_then(|b| b.get("remaining_tokens"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let rem_iter = burn
        .and_then(|b| b.get("iterations_remaining"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let inflight = v
        .get("inflight_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    if inflight > 0 {
        format!("burn · ${rem_usd:.2} · {rem_tok} tok · {rem_iter} hop · inflight {inflight}")
    } else {
        format!("burn · ${rem_usd:.2} · {rem_tok} tok · {rem_iter} hop")
    }
}

/// GET /spend/burn/:pid — live ceiling remaining + inflight LLM registry.
pub async fn spend_burn(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/spend/burn/{agent_pid}")).await
}

/// GET /spend/ceiling/:pid
pub async fn spend_ceiling(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/spend/ceiling/{agent_pid}")).await
}

/// GET /spend/cease/latest/:pid
pub async fn spend_cease_latest(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/spend/cease/latest/{agent_pid}")).await
}

/// GET /agents/:pid/expometer — authority + world/LLM exposure.
pub async fn agent_expometer(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/expometer")).await
}

/// POST /agents/:pid/cease — SpendCease fence + void ctx_tok + reap (model desire irrelevant).
pub async fn agent_cease(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/cease"), json!({})).await
}

/// GET /aipsprt/:passport_id — public passport (no private map).
pub async fn aipsprt_get(passport_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/aipsprt/{passport_id}")).await
}

/// GET /aipsprt/:passport_id/c2pa-map — thin Content Credentials export sketch.
pub async fn aipsprt_c2pa_map(passport_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/aipsprt/{passport_id}/c2pa-map")).await
}

// ── Workbench orchestrator (session journal — not B15 chat threads) ─────────

pub async fn workbench_list_sessions(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/workbench/sessions")).await
}

pub async fn workbench_create_session(
    agent_pid: &str,
    title: &str,
    goal: &str,
) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/workbench/sessions"),
        json!({ "title": title, "goal": goal }),
    )
    .await
}

pub async fn workbench_get_session(agent_pid: &str, session_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!(
        "/agents/{agent_pid}/workbench/sessions/{session_id}"
    ))
    .await
}

/// Ensure a session exists: reuse latest or create one.
pub async fn workbench_ensure_session(agent_pid: &str) -> Result<(String, Value), ApiError> {
    let list = workbench_list_sessions(agent_pid).await?;
    if let Some(sid) = list
        .get("sessions")
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("session_id"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        let doc = workbench_get_session(agent_pid, sid).await?;
        return Ok((sid.to_string(), doc));
    }
    let created = workbench_create_session(agent_pid, "Workbench", "Consult and admit orders").await?;
    let src = api::resource_object(&created);
    let sid = created
        .pointer("/session/session_id")
        .or_else(|| src.pointer("/session/session_id"))
        .or_else(|| created.get("session_id"))
        .or_else(|| src.get("session_id"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    if sid.is_empty() {
        let reason = created
            .get("error")
            .or_else(|| src.get("error"))
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("workbench_session_id_missing");
        return Err(ApiError {
            status: 500,
            code: Some(reason.into()),
            message: reason.into(),
            detail: Some(created.to_string()),
            hints: vec![],
            docs: None,
        });
    }
    Ok((sid, created))
}

pub async fn workbench_turn(
    agent_pid: &str,
    session_id: &str,
    message: &str,
    model: &str,
) -> Result<Value, ApiError> {
    api::post_value_timeout(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/turn"),
        json!({ "message": message, "model": model }),
        api::TALK_COMPLETIONS_TIMEOUT_MS,
    )
    .await
}

pub async fn workbench_admit(
    agent_pid: &str,
    session_id: &str,
    order_ids: &[String],
) -> Result<Value, ApiError> {
    api::post_value_timeout(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/admit"),
        json!({ "order_ids": order_ids }),
        api::TALK_COMPLETIONS_TIMEOUT_MS,
    )
    .await
}

pub async fn workbench_demo(
    agent_pid: &str,
    session_id: &str,
    verb: &str,
) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/demo"),
        json!({ "verb": verb }),
    )
    .await
}

pub async fn workbench_cancel_orders(
    agent_pid: &str,
    session_id: &str,
    order_ids: &[String],
) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/cancel-orders"),
        json!({ "order_ids": order_ids }),
    )
    .await
}

pub async fn workbench_hitl_resume(
    agent_pid: &str,
    session_id: &str,
    request_id: Option<&str>,
) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/hitl-resume"),
        json!({ "request_id": request_id }),
    )
    .await
}

pub async fn workbench_hitl_deny(
    agent_pid: &str,
    session_id: &str,
    reason: &str,
    request_id: Option<&str>,
) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/workbench/sessions/{session_id}/hitl-deny"),
        json!({ "reason": reason, "request_id": request_id }),
    )
    .await
}

pub async fn get_mission(mission_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/missions/{mission_id}")).await
}

pub async fn operator_capabilities() -> Result<Value, ApiError> {
    api::get_value("/operator/capabilities").await
}

pub async fn agent_progeny(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/progeny")).await
}

pub async fn context_pressure(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/context/{agent_pid}/pressure")).await
}

pub async fn list_asset_containers(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!(
        "/assets/containers?agent_pid={}",
        agent_pid.replace('&', "%26").replace(' ', "%20")
    ))
    .await
}

pub async fn get_asset_container(container_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/assets/containers/{container_id}")).await
}

pub async fn create_asset_container(name: &str, agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(
        "/assets/containers",
        json!({
            "name": name,
            "agent_pid": agent_pid,
            "allowed_types": ["txt", "md", "json", "yaml", "yml", "csv"],
        }),
    )
    .await
}

pub async fn deploy_verify() -> Result<Value, ApiError> {
    api::get_value("/runtime/deploy-verify?profile=linux-kvm").await
}

pub async fn agent_preflight(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/preflight")).await
}

pub async fn agentgateway_status() -> Result<Value, ApiError> {
    api::get_value("/runtime/agentgateway").await
}

pub async fn agent_workspace(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/workspace")).await
}

pub async fn put_character(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::put_value(&format!("/agents/{agent_pid}/character"), body).await
}

pub async fn post_directive(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/directives"), body).await
}

pub async fn post_alias(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/aliases"), body).await
}

pub async fn runtime_explain(receipt_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/runtime/explain/{receipt_id}")).await
}

pub async fn runtime_cease_proof(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/runtime/cease-proof/{agent_pid}")).await
}

pub async fn post_product_task(body: Value) -> Result<Value, ApiError> {
    api::post_value("/product/tasks", body).await
}

pub async fn upload_asset(container_id: &str, filename: &str, content: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/assets/containers/{container_id}/upload"),
        json!({ "filename": filename, "content": content }),
    )
    .await
}

pub async fn ingest_assets(container_id: &str) -> Result<Value, ApiError> {
    api::post_value(
        "/assets/ingest",
        json!({ "container_id": container_id }),
    )
    .await
}

pub async fn agent_memory(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/memory")).await
}

pub async fn agent_memory_stats(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/memory/stats")).await
}

pub async fn economy_budget_gate(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/economy/budget-gate/{agent_pid}")).await
}

pub async fn list_chat_threads(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/chat/threads")).await
}

pub async fn create_chat_thread(agent_pid: &str, title: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/chat/threads"),
        json!({ "title": title }),
    )
    .await
}

pub async fn get_chat_thread(agent_pid: &str, thread_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/chat/threads/{thread_id}")).await
}

pub async fn list_grants(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/grants")).await
}

/// DI-4 — inter-intelligence AccessGrant (grantor = this principal).
pub async fn grant_access(
    grantor_pid: &str,
    grantee_pid: &str,
    namespace: &str,
    permissions: &[&str],
    justification: &str,
    root_passcode: &str,
) -> Result<Value, ApiError> {
    api::post_value(
        "/multiagent/grant",
        json!({
            "grantor_pid": grantor_pid,
            "grantee_pid": grantee_pid,
            "namespace": namespace,
            "permissions": permissions,
            "justification": justification,
            "root_passcode": root_passcode,
        }),
    )
    .await
}

/// DI-4 — revoke AccessGrant (revoker = this principal).
pub async fn revoke_access(
    revoker_pid: &str,
    target_pid: &str,
    namespace: &str,
) -> Result<Value, ApiError> {
    api::post_value(
        "/multiagent/revoke",
        json!({
            "revoker_pid": revoker_pid,
            "target_pid": target_pid,
            "namespace": namespace,
        }),
    )
    .await
}

pub async fn runtime_matrix(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/runtime/matrix?agent_pid={agent_pid}")).await
}

pub async fn fleet_charter() -> Result<Value, ApiError> {
    api::get_value("/runtime/fleet/charter").await
}

/// DI-4 — chartered inter-intelligence task under grants.
pub async fn dispatch_task(
    from_pid: &str,
    to_pid: &str,
    namespace: &str,
    message: &str,
) -> Result<Value, ApiError> {
    let mut body = json!({
        "from_pid": from_pid,
        "to_pid": to_pid,
        "message": { "role": "user", "parts": [{ "type": "text", "text": message }] },
    });
    if !namespace.trim().is_empty() {
        body["namespace"] = json!(namespace);
    }
    api::post_value("/multiagent/tasks/dispatch", body).await
}

pub async fn knot_summary(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/knot/summary")).await
}

pub async fn hitl_pending(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/hitl/pending")).await
}

pub async fn hitl_create(agent_pid: &str, action: &str, description: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/hitl"),
        json!({ "action": action, "description": description }),
    )
    .await
}

pub async fn hitl_approve(agent_pid: &str, request_id: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/hitl/{request_id}/approve"),
        json!({}),
    )
    .await
}

pub async fn hitl_deny(agent_pid: &str, request_id: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/hitl/{request_id}/deny"),
        json!({}),
    )
    .await
}

pub async fn forensic_universal(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/forensic/universal")).await
}

pub async fn forensic_package(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/forensics/package?agent_pid={agent_pid}")).await
}

pub async fn court_readiness(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/forensics/court-readiness?agent_pid={agent_pid}")).await
}

/// B18: list TT policies filtered by agent (proxied).
pub async fn tt_policies_for_agent(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!(
        "/plugins/tracetramp/admin/policies?agent_pid={agent_pid}"
    ))
    .await
}

/// Bind a TT monitor policy to this agent (B18).
pub async fn tt_bind_agent_policy(agent_pid: &str, tenant_id: &str, name: &str) -> Result<Value, ApiError> {
    api::post_value(
        "/plugins/tracetramp/admin/policies",
        json!({
            "tenant_id": tenant_id,
            "name": name,
            "policy_type": "tool_permission",
            "rules": { "agent_pid": agent_pid, "mode": "monitor" },
            "enforcement_mode": "monitor",
            "priority": 50,
            "agent_pid": agent_pid,
        }),
    )
    .await
}

/// List WC sessions (proxied) — for Evidence bind panel.
pub async fn wc_list_sessions() -> Result<Value, ApiError> {
    api::get_value("/plugins/witnessctl/sessions").await
}

/// Platform IIA join for a WC session id or `wc:agent:…` hint (C57).
pub async fn wc_iia_join(session_id: &str) -> Result<Value, ApiError> {
    api::get_value(&format!(
        "/plugins/witnessctl/sessions/{session_id}/iia-join"
    ))
    .await
}

pub async fn agent_activity(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/activity")).await
}

pub async fn agent_traces(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/traces")).await
}

/// TG-0: cage/runtime plane (≠ audit activity).
pub async fn agent_cage_runtime(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/cage-runtime")).await
}

pub async fn delete_agent(agent_pid: &str) -> Result<Value, ApiError> {
    api::delete_value(&format!("/agents/{agent_pid}")).await
}

pub async fn agent_lifecycle(agent_pid: &str, action: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/{action}"), json!({})).await
}

/// POST /agents/:pid/signal — Suspend | Resume | Terminate
pub async fn agent_signal(agent_pid: &str, signal: &str, reason: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/signal"),
        json!({ "signal": signal, "reason": reason }),
    )
    .await
}

/// POST /agents/:pid/clearance — MAC clearance band
pub async fn agent_set_clearance(agent_pid: &str, level: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/clearance"),
        json!({ "level": level }),
    )
    .await
}

/// POST /agents/:pid/trust — trust override (admin)
pub async fn agent_set_trust(agent_pid: &str, trust_level: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/trust"),
        json!({ "trust_level": trust_level }),
    )
    .await
}

pub async fn agent_reflect(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/reflect"), json!({})).await
}

pub async fn agent_residency(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/residency")).await
}

pub async fn agent_policy_check(agent_pid: &str, body: Value) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/policy/check"), body).await
}

pub async fn agent_audit_receipts(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/audit/receipts")).await
}

pub async fn agent_audit_receipts_verify(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/audit/receipts/verify"),
        json!({}),
    )
    .await
}

pub async fn context_compress(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/context/{agent_pid}/compress"), json!({})).await
}

/// POST /kernel/aios/operate — interrupt | retrieve | compensate
pub async fn aios_operate(op: &str, agent_pid: &str, args: Value) -> Result<Value, ApiError> {
    api::post_value(
        "/kernel/aios/operate",
        json!({ "op": op, "agent_pid": agent_pid, "args": args }),
    )
    .await
}

/// Guard incompleteness for Talk gating — true when DAC index reports incomplete contracts.
pub async fn address_dac_incomplete() -> Result<(bool, String), ApiError> {
    let v = api::get_value("/kernel/address-dac").await?;
    let incomplete = v
        .get("incomplete_count")
        .or_else(|| api::resource_object(&v).get("incomplete_count"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let count = v
        .get("address_count")
        .or_else(|| api::resource_object(&v).get("address_count"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let enforced = v
        .get("identity_stack_enforced")
        .or_else(|| api::resource_object(&v).get("identity_stack_enforced"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let detail = format!("addresses={count} incomplete={incomplete} stack_enforced={enforced}");
    Ok((incomplete > 0 && enforced, detail))
}

/// POST /agents/:pid/quarantine — brain/LLM broker quarantine (≠ TraceTramp traffic quarantine).
pub async fn agent_quarantine(agent_pid: &str, reason: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/quarantine"),
        json!({ "reason": reason }),
    )
    .await
}

/// POST /agents/:pid/unquarantine — requires prior HITL approve unless admin `force`.
pub async fn agent_unquarantine(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/unquarantine"), json!({})).await
}

/// Admin break-glass unquarantine (`force: true`). Prefer HITL approve for operators.
pub async fn agent_unquarantine_force(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/agents/{agent_pid}/unquarantine"),
        json!({ "force": true }),
    )
    .await
}

/// POST /agents/:pid/kill-switch — interrupt Talk then kill.
pub async fn agent_kill_switch(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/agents/{agent_pid}/kill-switch"), json!({})).await
}

/// POST /tools/approvals/:audit_id/deny
pub async fn tool_deny(audit_id: &str) -> Result<Value, ApiError> {
    api::post_value(
        &format!("/tools/approvals/{audit_id}/deny"),
        json!({ "denied_by": "operator-ui", "decision": "deny" }),
    )
    .await
}

/// GET /agents/:pid/audit/isolation — per-agent FS/net/VM/broker proof JSON.
pub async fn agent_isolation_audit(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/agents/{agent_pid}/audit/isolation")).await
}

/// GET /agents — fleet inventory.
pub async fn list_agents() -> Result<Value, ApiError> {
    api::get_value("/agents").await
}

/// GET /substrate/status — Linux bar + LLM governance posture.
pub async fn substrate_status() -> Result<Value, ApiError> {
    api::get_value("/substrate/status").await
}

/// GET /runtime/enforcement — effect exclusivity / sandbox refuse events.
pub async fn runtime_enforcement() -> Result<Value, ApiError> {
    api::get_value("/runtime/enforcement").await
}

/// Extract HITL request id from error text, body fields, or example_fix curl.
pub fn extract_hitl_request_id(blob: &str) -> Option<String> {
    // …/hitl/<id>/approve
    if let Some(i) = blob.find("/hitl/") {
        let rest = &blob[i + 6..];
        let id = rest
            .split(|c: char| c == '/' || c == '"' || c == '\'' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .trim();
        if !id.is_empty() && id != "{id}" && id != "<request_id>" && id != "{{id}}" {
            return Some(id.to_string());
        }
    }
    for key in ["request_id=", "hitl=", "quarantine_hitl_id="] {
        if let Some(i) = blob.find(key) {
            let rest = &blob[i + key.len()..];
            let id = rest
                .split(|c: char| c == ' ' || c == '"' || c == '\'' || c == ',' || c == '·')
                .next()
                .unwrap_or("")
                .trim();
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Resolve pending unquarantine HITL id for an agent (preferred recovery path).
pub async fn resolve_unquarantine_hitl(agent_pid: &str) -> Result<Option<String>, ApiError> {
    let pending = hitl_pending(agent_pid).await?;
    let arr = pending
        .get("pending")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for item in arr {
        let action = item
            .get("action")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let status = item
            .get("status")
            .and_then(|x| x.as_str())
            .unwrap_or("pending");
        if status == "pending" && action.contains("unquarantine") {
            if let Some(id) = item
                .get("request_id")
                .or_else(|| item.get("id"))
                .and_then(|x| x.as_str())
            {
                return Ok(Some(id.to_string()));
            }
        }
    }
    Ok(None)
}

/// Approve quarantine HITL (or create+approve is not done — only approve existing).
pub async fn approve_unquarantine_hitl(agent_pid: &str, hint_blob: &str) -> Result<Value, ApiError> {
    let id = if let Some(parsed) = extract_hitl_request_id(hint_blob) {
        Some(parsed)
    } else {
        resolve_unquarantine_hitl(agent_pid).await?
    };
    match id {
        Some(rid) => {
            let v = hitl_approve(agent_pid, &rid).await?;
            if v.get("ok").and_then(|x| x.as_bool()) == Some(false) {
                return Err(ApiError {
                    status: 409,
                    code: v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .map(str::to_string),
                    message: v
                        .get("error")
                        .and_then(|x| x.as_str())
                        .unwrap_or("hitl_approve_failed")
                        .to_string(),
                    detail: Some(v.to_string()),
                    hints: v
                        .get("hint")
                        .and_then(|x| x.as_str())
                        .map(|s| vec![s.to_string()])
                        .unwrap_or_default(),
                    docs: None,
                });
            }
            Ok(v)
        }
        None => Err(ApiError {
            status: 404,
            code: Some("no_pending_unquarantine_hitl".into()),
            message: "No pending unquarantine HITL to approve".into(),
            detail: Some(hint_blob.to_string()),
            hints: vec![
                "Open Fix queue and Approve unquarantine, or use Force on playground".into(),
            ],
            docs: None,
        }),
    }
}

/// Classify Talk/completions failures for broker-lane UX (200 / 409 / 499).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TalkLaneKind {
    Redo409,
    Quarantine499,
    SandboxRefuse,
    Generic,
}

pub fn classify_talk_lane_error(err: &ApiError) -> TalkLaneKind {
    let code = err.code.as_deref().unwrap_or("").to_ascii_lowercase();
    let msg = err.message.to_ascii_lowercase();
    let detail = err.detail.as_deref().unwrap_or("").to_ascii_lowercase();
    let hints = err.hints.join(" ").to_ascii_lowercase();
    let blob = format!("{code} {msg} {detail} {hints}");
    if err.status == 409
        || code.contains("redo")
        || code.contains("mismatch")
        || blob.contains("llm_broker_redo")
    {
        return TalkLaneKind::Redo409;
    }
    if err.status == 499
        || code.contains("quarantine")
        || code.contains("llm_not_allowed")
        || blob.contains("need human approval")
        || blob.contains("not allowed")
    {
        return TalkLaneKind::Quarantine499;
    }
    if blob.contains("exclusivity")
        || blob.contains("sandbox_unbypassable")
        || blob.contains("sandbox_refuse")
        || blob.contains("unbypassable")
    {
        return TalkLaneKind::SandboxRefuse;
    }
    TalkLaneKind::Generic
}

/// When HTTP 200 carries ok:false with broker semantics.
pub fn classify_talk_lane_body(v: &Value) -> Option<TalkLaneKind> {
    if v.get("ok").and_then(|x| x.as_bool()) != Some(false) {
        return None;
    }
    let status = v
        .get("status")
        .and_then(|x| x.as_u64())
        .or_else(|| v.get("code").and_then(|x| x.as_u64()))
        .unwrap_or(0);
    let err = ApiError {
        status: status as u16,
        code: v
            .get("error")
            .or_else(|| v.get("denial_reason"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        message: v
            .get("message")
            .or_else(|| v.get("error"))
            .and_then(|x| x.as_str())
            .unwrap_or("request failed")
            .to_string(),
        detail: v
            .get("detail")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        hints: v
            .get("hint")
            .and_then(|x| x.as_str())
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        docs: None,
    };
    Some(classify_talk_lane_error(&err))
}

/// GET /intelligence/spec-schema — 5-min create template + classes.
pub async fn intelligence_spec_schema() -> Result<Value, ApiError> {
    api::get_value("/intelligence/spec-schema").await
}

/// POST /intelligence/apply — declare-then-apply IntelligenceSpec.
pub async fn intelligence_apply(body: Value) -> Result<Value, ApiError> {
    api::post_value("/intelligence/apply", body).await
}

/// GET /intelligence/:pid/pack — bound skills / portals / rules.
pub async fn intelligence_pack(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/intelligence/{agent_pid}/pack")).await
}

pub async fn agent_acs(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/runtime/acs/{agent_pid}")).await
}

pub async fn agent_nsfs_ensure(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/runtime/nsfs/{agent_pid}/ensure"), json!({})).await
}

/// GET /protocol/world — CNP/CONP world-connect operator map.
pub async fn protocol_world() -> Result<Value, ApiError> {
    api::get_value("/protocol/world").await
}

pub async fn gateway_status() -> Result<Value, ApiError> {
    api::get_value("/intelligence/gateway/status").await
}

pub async fn gateway_set_root(root_passcode: &str, new_root: Option<&str>) -> Result<Value, ApiError> {
    let mut body = json!({ "root_passcode": root_passcode });
    if let Some(n) = new_root {
        body["new_root_passcode"] = json!(n);
    }
    api::post_value("/intelligence/gateway/root", body).await
}

pub async fn gateway_put_address(body: Value) -> Result<Value, ApiError> {
    api::post_value("/intelligence/gateway/address", body).await
}

pub async fn gateway_list_addresses() -> Result<Value, ApiError> {
    api::get_value("/intelligence/gateway/addresses").await
}

pub async fn gateway_put_grant(body: Value) -> Result<Value, ApiError> {
    api::post_value("/intelligence/gateway/grant", body).await
}

pub async fn gateway_list_grants(agent_pid: Option<&str>) -> Result<Value, ApiError> {
    match agent_pid {
        Some(p) if !p.is_empty() => {
            api::get_value(&format!("/intelligence/gateway/grants?agent_pid={p}")).await
        }
        _ => api::get_value("/intelligence/gateway/grants").await,
    }
}

pub async fn browser_navigate(agent_pid: &str, url: &str, session_id: Option<&str>) -> Result<Value, ApiError> {
    let mut body = json!({ "agent_pid": agent_pid, "url": url });
    if let Some(s) = session_id {
        if !s.is_empty() {
            body["session_id"] = json!(s);
        }
    }
    api::post_value("/world/browser/navigate", body).await
}

pub async fn browser_sessions(agent_pid: Option<&str>) -> Result<Value, ApiError> {
    match agent_pid {
        Some(p) if !p.is_empty() => {
            api::get_value(&format!("/world/browser/sessions?agent_pid={p}")).await
        }
        _ => api::get_value("/world/browser/sessions").await,
    }
}

/// GET /soas/report — Standard Operation Agentic Standard honesty workpaper.
pub async fn soas_report(agent_pid: &str) -> Result<Value, ApiError> {
    api::get_value(&format!("/soas/report?agent_pid={agent_pid}")).await
}

/// GET /soas/report/pdf — printpdf workpaper bytes.
pub async fn soas_report_pdf(agent_pid: &str) -> Result<Vec<u8>, ApiError> {
    api::get_bytes(&format!("/soas/report/pdf?agent_pid={agent_pid}")).await
}

/// POST /aacr/mint — Augmented Agentic Compliance Record epoch.
pub async fn aacr_mint(agent_pid: &str) -> Result<Value, ApiError> {
    api::post_value(&format!("/aacr/mint?agent_pid={agent_pid}"), json!({})).await
}

/// GET /aacr/report
pub async fn aacr_report(agent_pid: &str, framework: &str) -> Result<Value, ApiError> {
    api::get_value(&format!(
        "/aacr/report?agent_pid={agent_pid}&framework={framework}"
    ))
    .await
}

/// GET /aacr/report/pdf
pub async fn aacr_report_pdf(agent_pid: &str) -> Result<Vec<u8>, ApiError> {
    api::get_bytes(&format!("/aacr/report/pdf?agent_pid={agent_pid}")).await
}

/// POST /aapi/capabilities/issue — UCAN-style cap whose subject is this agent.
pub async fn aapi_issue_capability(agent_pid: &str, actions: Vec<String>) -> Result<Value, ApiError> {
    api::post_value(
        "/aapi/capabilities/issue",
        json!({
            "issuer": "operator",
            "subject": agent_pid,
            "actions": actions,
            "resources": [format!("agent:{agent_pid}"), "conp:*", "tool:*"],
            "ttl_hours": 24,
        }),
    )
    .await
}

/// Per-agent AAPI policy: CONP/command requires approval (does not replace charter).
pub async fn aapi_agent_world_policy(agent_pid: &str) -> Result<Value, ApiError> {
    let id = format!("agent-world-{}", &agent_pid[..agent_pid.len().min(12)]);
    api::post_value(
        "/aapi/policies",
        json!({
            "id": id,
            "name": format!("world-gate:{agent_pid}"),
            "rules": [
                {
                    "effect": "require_approval",
                    "action_pattern": "conp.*",
                    "resource_pattern": format!("agent:{agent_pid}*"),
                    "roles": [],
                    "priority": 80,
                },
                {
                    "effect": "require_approval",
                    "action_pattern": "protocol.conp.*",
                    "resource_pattern": format!("agent:{agent_pid}*"),
                    "roles": [],
                    "priority": 80,
                }
            ]
        }),
    )
    .await
}
