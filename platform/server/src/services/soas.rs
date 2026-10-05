//! SOAS — Standard Operation Agentic Standard.
//!
//! Court-grade honesty report: composes existing forensics / isolation / LLM /
//! vault / HITL / tool posture. Never upgrades playground Fly hosts to
//! `military_attach` / CD-9 without Landlock/Firecracker evidence.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

pub const SCHEMA: &str = "connector.soas.report.v1";

#[derive(Debug, Deserialize, Default)]
pub struct SoasQuery {
    pub agent_pid: Option<String>,
}

fn section(id: &str, ok: bool, evidence: Value, fix_hint: &str, grade_min: &str) -> Value {
    json!({
        "id": id,
        "ok": ok,
        "evidence_ptrs": evidence,
        "fix_hint": fix_hint,
        "grade_min": grade_min,
    })
}

fn build_report(state: &SharedState, headers: &HeaderMap, agent_pid: Option<&str>) -> Value {
    let playground = crate::services::playground::is_playground_mode();
    let session_id =
        crate::services::playground::playground_session_id_from_headers(headers);
    let tenant = crate::services::settings_llms::llm_tenant_scope(headers);

    let llm_wired = match agent_pid {
        Some(pid) if !pid.is_empty() => {
            crate::services::settings_llms::talk_llm_wired(state, headers, pid)
        }
        _ if playground => {
            crate::services::settings_llms::restore_llm_router_for_talk(state, headers, None);
            tenant
                .as_ref()
                .map(|t| {
                    // Tenant providers meta present ⇒ visitor linked a key (router may be cold).
                    let key = format!("providers/{t}");
                    state
                        .engine_store
                        .lock()
                        .ok()
                        .and_then(|es| es.folder_get("settings_llms", &key).ok().flatten())
                        .and_then(|v| v.as_array().map(|a| !a.is_empty()))
                        .unwrap_or(false)
                })
                .unwrap_or(false)
        }
        _ => state.llm_wired(),
    };

    let broker = crate::substrate::llm_context_broker::status();
    let broker_on = broker
        .get("enforced")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let unbypassable = std::env::var("CONNECTOR_LLM_BROKER_UNBYPASSABLE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);

    let isolation = match agent_pid.filter(|s| !s.is_empty()) {
        Some(pid) => crate::kernel::isolation_tiers::isolation_for_agent(state.as_ref(), pid),
        None => json!({
            "ok": false,
            "honesty": "pass ?agent_pid= for isolation section",
        }),
    };
    let landlock_ok = isolation
        .pointer("/landlock/enforced")
        .and_then(|v| v.as_bool())
        .or_else(|| isolation.get("landlock").and_then(|v| v.as_bool()))
        .or_else(|| {
            isolation
                .pointer("/docklock/landlock_enforced")
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false);

    let hitl_pending = match agent_pid.filter(|s| !s.is_empty()) {
        Some(pid) => {
            crate::services::agents::hitl_ensure_hydrated(state);
            crate::services::agents::hitl_store_snapshot()
                .values()
                .any(|r| r.agent_pid == pid && r.status == "pending")
        }
        None => false,
    };

    let signing_tier = agent_pid
        .filter(|s| !s.is_empty())
        .and_then(|pid| {
            crate::kernel::forensic_package::build_package(state.as_ref(), pid, None, None)
                .ok()
                .and_then(|pkg| {
                    pkg.pointer("/manifest/signing_tier")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
        })
        .unwrap_or_else(|| {
            if playground {
                "hmac_lab".into()
            } else {
                "unknown".into()
            }
        });

    let sections = vec![
        section(
            "honesty_envelope",
            true,
            json!({
                "playground": playground,
                "signing_tier": &signing_tier,
                "not_cpa": true,
                "not_cd9_counsel": true,
                "stance": "SOAS tells the truth — never greenwashes Fly trial into military court"
            }),
            "Attach Landlock + Ed25519 court package before claiming court_defensible_cd7",
            "playground_demo",
        ),
        section(
            "talk_llm",
            llm_wired,
            json!({
                "router_wired": llm_wired,
                "tenant_id": &tenant,
                "stub": std::env::var("CONNECTOR_LLM_STUB").ok(),
            }),
            "POST /api/v1/settings/llms/link with session JWT (tenant-scoped vault)",
            "playground_demo",
        ),
        section(
            "broker_tokenization",
            broker_on && !unbypassable,
            json!({
                "broker": broker,
                "soft_plane": broker_on && !unbypassable,
                "unbypassable": unbypassable,
            }),
            "Set CONNECTOR_LLM_CONTEXT_BROKER=1; do not set UNBYPASSABLE on Fly",
            "playground_demo",
        ),
        section(
            "vault_secrets",
            tenant.is_some() || !playground,
            json!({
                "tenant_id": &tenant,
                "secret_path_pattern": if playground { "llm/{tenant}/{provider}" } else { "llm/{provider}" },
            }),
            "Exchange playground API key for JWT so tenant_id is present before link",
            "playground_demo",
        ),
        section(
            "hitl_human_retrieval",
            true,
            json!({
                "pending_for_agent": hitl_pending,
                "playground_approve_waiver": playground,
            }),
            "Approve pending HITL or Force unquarantine as session owner on playground",
            "playground_demo",
        ),
        section(
            "tools_cnp_cls_aapi",
            playground,
            json!({
                "tool_lane": "ensure_playground_tool_lane",
                "cls_params": "real step params (not empty {})",
            }),
            "Seed demo agent; invoke MCP with non-empty agent_pid",
            "governance",
        ),
        section(
            "landlock_os",
            landlock_ok,
            json!({
                "isolation": isolation,
                "expect_red_on_fly": playground,
            }),
            "Host attach with DockLock Landlock + microVM for military_attach",
            "host_lab",
        ),
        section(
            "memory_namespace",
            tenant.is_some() || agent_pid.is_some(),
            json!({
                "tenant_id": &tenant,
                "gateway_ns": agent_pid.map(|p| format!("gateway/{p}")),
            }),
            "Use gateway/{pid} Talk namespace",
            "playground_demo",
        ),
        section(
            "forensic_court_spine",
            signing_tier != "hmac_lab" && !playground,
            json!({
                "signing_tier": &signing_tier,
                "court_readiness": "GET /api/v1/forensics/court-readiness?agent_pid=",
                "aacr": "POST /api/v1/aacr/mint?agent_pid= — kernel AACR epochs",
                "aacr_head": agent_pid.filter(|s| !s.is_empty()).and_then(|pid| {
                    crate::kernel::aacr::head_content_digest(state.as_ref(), pid)
                }),
            }),
            "Mint AACR + Ed25519 court package; HMAC lab ≠ court",
            "court_defensible_cd7",
        ),
        section(
            "seven_pillars",
            true,
            json!({
                "pointers": [
                    "GET /api/v1/forensics/court-readiness",
                    "GET /api/v1/soas/report",
                ]
            }),
            "See platform/docs/arch/COURT_GRADE_CLAIMS.md",
            "governance",
        ),
        section(
            "playground_session",
            playground,
            json!({
                "session_id": session_id,
                "tenant_id": tenant,
                "agent_pid": agent_pid,
            }),
            "POST /api/v1/playground/session",
            "playground_demo",
        ),
    ];

    // Fly playground is always playground_demo overall — never upgrade.
    let grade = if playground {
        "playground_demo".to_string()
    } else if landlock_ok && signing_tier != "hmac_lab" {
        "court_defensible_cd7".to_string()
    } else if llm_wired {
        "governance".to_string()
    } else {
        "host_lab".to_string()
    };

    json!({
        "ok": true,
        "schema": SCHEMA,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "overall_grade": grade,
        "honesty": "SOAS is a workpaper aggregator — not CPA attestation, not military court counsel. playground_demo means soft L7 governance on a shared Fly VM.",
        "agent_pid": agent_pid,
        "sections": sections,
        "next": {
            "pdf": "/api/v1/soas/report/pdf",
            "court_readiness": "/api/v1/forensics/court-readiness",
        }
    })
}

fn render_soas_pdf(title: &str, report: &Value) -> Result<Vec<u8>, String> {
    use printpdf::*;
    let (doc, page1, layer1) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer");
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| e.to_string())?;
    let layer = doc.get_page(page1).get_layer(layer1);
    let pretty = serde_json::to_string_pretty(report).unwrap_or_default();
    let mut y = 280.0;
    layer.use_text(title, 14.0, Mm(12.0), Mm(y), &font);
    y -= 8.0;
    for line in pretty.lines().take(90) {
        let clipped: String = line.chars().take(95).collect();
        layer.use_text(&clipped, 7.0, Mm(12.0), Mm(y), &font);
        y -= 3.5;
        if y < 15.0 {
            break;
        }
    }
    doc.save_to_bytes().map_err(|e| e.to_string())
}

/// GET /soas/report
pub async fn get_soas_report(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<SoasQuery>,
) -> Json<Value> {
    Json(build_report(
        &state,
        &headers,
        q.agent_pid.as_deref().filter(|s| !s.is_empty()),
    ))
}

/// GET /soas/report/pdf — printpdf workpaper (not Chromium court package).
pub async fn get_soas_report_pdf(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<SoasQuery>,
) -> impl IntoResponse {
    let report = build_report(
        &state,
        &headers,
        q.agent_pid.as_deref().filter(|s| !s.is_empty()),
    );
    let grade = report
        .get("overall_grade")
        .and_then(|v| v.as_str())
        .unwrap_or("report");
    let title = format!(
        "SOAS {grade} — {}",
        report
            .get("generated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    );
    match render_soas_pdf(&title, &report) {
        Ok(bytes) => (
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/pdf".to_string(),
                ),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"soas-{grade}.pdf\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => Json(json!({
            "ok": false,
            "error": "soas_pdf_render_failed",
            "detail": e,
            "report": report,
        }))
        .into_response(),
    }
}
