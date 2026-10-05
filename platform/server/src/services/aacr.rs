//! HTTP surface for AACR — Augmented Agentic Compliance Record (top-tier).

use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;

#[derive(Debug, Deserialize, Default)]
pub struct AacrQuery {
    pub agent_pid: Option<String>,
    pub framework: Option<String>,
}

/// POST /aacr/mint
pub async fn mint_aacr(
    State(state): State<SharedState>,
    Query(q): Query<AacrQuery>,
) -> impl IntoResponse {
    let Some(pid) = q.agent_pid.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({
            "ok": false,
            "error": "agent_pid_required",
            "hint": "POST /api/v1/aacr/mint?agent_pid=",
        }))
        .into_response();
    };
    crate::services::agents::hitl_ensure_hydrated(&state);
    match crate::kernel::aacr::mint(state.as_ref(), &pid) {
        Ok(v) => Json(v).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e })).into_response(),
    }
}

/// GET /aacr/latest
pub async fn latest_aacr(
    State(state): State<SharedState>,
    Query(q): Query<AacrQuery>,
) -> Json<Value> {
    let Some(pid) = q.agent_pid.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({ "ok": false, "error": "agent_pid_required" }));
    };
    match crate::kernel::aacr::latest(state.as_ref(), &pid) {
        Some(v) => Json(v),
        None => Json(json!({
            "ok": false,
            "error": "no_aacr",
            "hint": "POST /api/v1/aacr/mint?agent_pid=",
        })),
    }
}

/// GET /aacr/chain
pub async fn chain_aacr(
    State(state): State<SharedState>,
    Query(q): Query<AacrQuery>,
) -> Json<Value> {
    let Some(pid) = q.agent_pid.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({ "ok": false, "error": "agent_pid_required" }));
    };
    Json(crate::kernel::aacr::chain_summary(state.as_ref(), &pid))
}

/// GET /aacr/report
pub async fn report_aacr(
    State(state): State<SharedState>,
    Query(q): Query<AacrQuery>,
) -> Json<Value> {
    let Some(pid) = q.agent_pid.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({ "ok": false, "error": "agent_pid_required" }));
    };
    crate::services::agents::hitl_ensure_hydrated(&state);
    let fw = q.framework.unwrap_or_else(|| "all".into());
    Json(crate::kernel::aacr::report(state.as_ref(), &pid, &fw))
}

/// GET /aacr/report/pdf
pub async fn report_aacr_pdf(
    State(state): State<SharedState>,
    Query(q): Query<AacrQuery>,
) -> impl IntoResponse {
    let Some(pid) = q.agent_pid.filter(|s| !s.trim().is_empty()) else {
        return Json(json!({ "ok": false, "error": "agent_pid_required" })).into_response();
    };
    crate::services::agents::hitl_ensure_hydrated(&state);
    let report = crate::kernel::aacr::report(state.as_ref(), &pid, "all");
    let grade = report
        .pointer("/aacr/overall_grade")
        .and_then(|v| v.as_str())
        .unwrap_or("report");
    let tier = report
        .pointer("/aacr/signing_tier")
        .and_then(|v| v.as_str())
        .unwrap_or("hmac_lab");
    let digest = report
        .pointer("/aacr/content_digest_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let title = format!("AACR {grade} ({tier})");
    match render_aacr_pdf(&title, digest, &report) {
        Ok(bytes) => (
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/pdf".to_string(),
                ),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"aacr-{grade}-{pid}.pdf\""),
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => Json(json!({
            "ok": false,
            "error": "aacr_pdf_failed",
            "detail": e,
            "report": report,
        }))
        .into_response(),
    }
}

/// POST /aacr/verify
pub async fn verify_aacr(Json(body): Json<Value>) -> Json<Value> {
    let record = body.get("aacr").cloned().unwrap_or(body);
    Json(crate::kernel::aacr::verify_record(&record))
}

fn render_aacr_pdf(title: &str, digest: &str, report: &Value) -> Result<Vec<u8>, String> {
    use printpdf::*;
    let (doc, page1, layer1) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer");
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| e.to_string())?;
    let bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| e.to_string())?;
    let layer = doc.get_page(page1).get_layer(layer1);
    let mut y = 285.0;
    layer.use_text(title, 14.0, Mm(12.0), Mm(y), &bold);
    y -= 6.0;
    layer.use_text(
        "connector.aacr.v1 — Augmented Agentic Compliance Record",
        8.0,
        Mm(12.0),
        Mm(y),
        &font,
    );
    y -= 4.0;
    layer.use_text(
        "NOT CPA · NOT OCR/BAA · Probabilistic identity · Zero-trust distributed",
        7.0,
        Mm(12.0),
        Mm(y),
        &font,
    );
    y -= 4.0;
    let dig_line: String = format!("content_digest: {}", &digest[..digest.len().min(64)]);
    layer.use_text(&dig_line, 6.5, Mm(12.0), Mm(y), &font);
    y -= 8.0;

    // Section summary table
    if let Some(secs) = report.pointer("/aacr/sections").and_then(|v| v.as_array()) {
        layer.use_text("Sections (S0–S9)", 10.0, Mm(12.0), Mm(y), &bold);
        y -= 5.0;
        for s in secs {
            let id = s.get("id").and_then(|x| x.as_str()).unwrap_or("?");
            let ok = s.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
            let fc = s
                .get("falsification_class")
                .and_then(|x| x.as_str())
                .unwrap_or("-");
            let line = format!(
                "{}  {}  {}",
                id,
                if ok { "OK" } else { "GAP" },
                fc
            );
            layer.use_text(&line, 7.0, Mm(14.0), Mm(y), &font);
            y -= 3.5;
            if y < 40.0 {
                break;
            }
        }
    }
    y -= 4.0;
    layer.use_text(
        "Full JSON appendix (truncated) — verify with POST /aacr/verify",
        8.0,
        Mm(12.0),
        Mm(y),
        &bold,
    );
    y -= 4.0;
    let pretty = serde_json::to_string_pretty(report).unwrap_or_default();
    for line in pretty.lines().take(55) {
        let clipped: String = line.chars().take(98).collect();
        layer.use_text(&clipped, 5.5, Mm(12.0), Mm(y), &font);
        y -= 2.8;
        if y < 12.0 {
            break;
        }
    }
    doc.save_to_bytes().map_err(|e| e.to_string())
}
