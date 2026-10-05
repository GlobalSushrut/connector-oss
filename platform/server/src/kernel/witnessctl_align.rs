//! B16 — align WitnessCtl session frameworks with forensic_profile on activate.
//!
//! When evidence policy requires a WC session, attempt to open one with the
//! profile's frameworks. Persist alignment status even if WC is unavailable
//! (honest mismatch / pending — never pretend a hint string is a live session).

use serde_json::json;

use connector_trust::ForensicProfileV2;

use crate::state::PlatformState;

pub const WC_ALIGNMENT_FOLDER: &str = "witnessctl_alignment_v1";

#[derive(Debug, Clone)]
pub struct WitnessctlAlignResult {
    /// Real WC session id when opened; otherwise None (hint-only).
    pub session_id: Option<String>,
    pub frameworks: Vec<String>,
    /// `aligned` | `opened` | `pending_wc_unavailable` | `not_required` | `open_failed`
    pub status: String,
    pub detail: String,
}

/// Map forensic profile framework ids to WitnessCtl `OpenSessionRequest.frameworks` strings.
fn wc_framework_strings(profile: ForensicProfileV2) -> Vec<String> {
    profile
        .compliance_frameworks()
        .into_iter()
        .filter(|id| {
            matches!(
                id.as_str(),
                "soc2"
                    | "hipaa"
                    | "gdpr"
                    | "eu_ai_act"
                    | "iso27001"
                    | "iso_27001"
                    | "pci_dss"
                    | "nist_800_53"
            )
        })
        .map(|id| match id.as_str() {
            "iso27001" => "iso27001".to_string(),
            other => other.to_string(),
        })
        .collect()
}

fn persist_alignment(state: &PlatformState, api_pid: &str, result: &WitnessctlAlignResult) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let _ = es.folder_put(
        WC_ALIGNMENT_FOLDER,
        api_pid,
        &json!({
            "agent_pid": api_pid,
            "session_id": result.session_id,
            "frameworks": result.frameworks,
            "status": result.status,
            "detail": result.detail,
            "aligned_at_ms": chrono::Utc::now().timestamp_millis(),
        }),
    );
}

pub fn load_alignment(state: &PlatformState, api_pid: &str) -> Option<serde_json::Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(WC_ALIGNMENT_FOLDER, api_pid).ok().flatten()
}

/// B16: bind WC frameworks to forensic profile at activate.
pub fn align_on_activate(state: &PlatformState, api_pid: &str, profile: ForensicProfileV2) -> WitnessctlAlignResult {
    let policy = profile.evidence_policy();
    let frameworks = wc_framework_strings(profile);
    if !policy.witnessctl_session_required {
        let r = WitnessctlAlignResult {
            session_id: None,
            frameworks,
            status: "not_required".into(),
            detail: "forensic_profile does not require witnessctl_session".into(),
        };
        persist_alignment(state, api_pid, &r);
        return r;
    }

    let base = crate::services::plugin_upstream_probe::witnessctl_management_url();
    let token = std::env::var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN")
        .or_else(|_| std::env::var("WITNESSCTL_ADMIN_TOKEN"))
        .ok()
        .filter(|s| !s.trim().is_empty());

    let (Some(base), Some(token)) = (base, token) else {
        let r = WitnessctlAlignResult {
            session_id: None,
            frameworks: frameworks.clone(),
            status: "pending_wc_unavailable".into(),
            detail: "WC required by forensic_profile but CONNECTOR_WITNESSCTL_MANAGEMENT_URL / ADMIN_TOKEN unset — open session manually with these frameworks".into(),
        };
        persist_alignment(state, api_pid, &r);
        return r;
    };

    let url = format!("{}/api/v1/sessions", base.trim_end_matches('/'));
    let body = json!({
        "upstream": std::env::var("CONNECTOR_LLM_BASE_URL").unwrap_or_else(|_| "https://api.openai.com".into()),
        "role": format!("agent:{api_pid}"),
        "mode": "proxy",
        "frameworks": frameworks,
    });

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let r = WitnessctlAlignResult {
                session_id: None,
                frameworks: frameworks.clone(),
                status: "open_failed".into(),
                detail: format!("reqwest client: {e}"),
            };
            persist_alignment(state, api_pid, &r);
            return r;
        }
    };

    match client
        .post(&url)
        .bearer_auth(&token)
        .header("Accept", "application/json")
        .json(&body)
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            if !status.is_success() {
                let r = WitnessctlAlignResult {
                    session_id: None,
                    frameworks: frameworks.clone(),
                    status: "open_failed".into(),
                    detail: format!("WC HTTP {}: {}", status.as_u16(), text.chars().take(400).collect::<String>()),
                };
                persist_alignment(state, api_pid, &r);
                return r;
            }
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(json!({}));
            let sid = v
                .get("session_id")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let r = WitnessctlAlignResult {
                session_id: sid,
                frameworks: frameworks.clone(),
                status: "opened".into(),
                detail: "WitnessCtl session opened with forensic_profile frameworks".into(),
            };
            persist_alignment(state, api_pid, &r);
            r
        }
        Err(e) => {
            let r = WitnessctlAlignResult {
                session_id: None,
                frameworks: frameworks.clone(),
                status: "open_failed".into(),
                detail: format!("WC request failed: {e}"),
            };
            persist_alignment(state, api_pid, &r);
            r
        }
    }
}
