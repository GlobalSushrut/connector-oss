//! Best-effort cancel of in-flight LLM provider work on SpendCease.
//!
//! Honesty: hosted APIs often still bill tokens already generated (cancellation tax).
//! This registry lets Cease mark/abort what Connector owns and optionally call
//! provider cancel endpoints when a response id is known.

use serde_json::json;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::state::SharedState;

#[derive(Debug, Clone)]
pub struct InflightLlm {
    pub agent_pid: String,
    pub provider: String,
    pub request_id: String,
    /// OpenAI Responses API background id, when applicable.
    pub provider_response_id: Option<String>,
    pub started_at_ms: i64,
}

static INFLIGHT: LazyLock<Mutex<HashMap<String, Vec<InflightLlm>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn register(
    agent_pid: &str,
    provider: &str,
    request_id: &str,
    provider_response_id: Option<String>,
) {
    let entry = InflightLlm {
        agent_pid: agent_pid.into(),
        provider: provider.into(),
        request_id: request_id.into(),
        provider_response_id,
        started_at_ms: now_ms(),
    };
    if let Ok(mut g) = INFLIGHT.lock() {
        g.entry(agent_pid.to_string()).or_default().push(entry);
    }
}

pub fn clear(agent_pid: &str, request_id: &str) {
    if let Ok(mut g) = INFLIGHT.lock() {
        if let Some(v) = g.get_mut(agent_pid) {
            v.retain(|e| e.request_id != request_id);
            if v.is_empty() {
                g.remove(agent_pid);
            }
        }
    }
}

/// RAII: clears registry entry on drop (success or error return).
pub struct InflightGuard {
    agent_pid: String,
    request_id: String,
}

impl InflightGuard {
    pub fn register(
        agent_pid: &str,
        provider: &str,
        request_id: &str,
        provider_response_id: Option<String>,
    ) -> Self {
        register(agent_pid, provider, request_id, provider_response_id);
        Self {
            agent_pid: agent_pid.into(),
            request_id: request_id.into(),
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        clear(&self.agent_pid, &self.request_id);
    }
}

/// Live snapshot for burn meter (no provider secrets).
pub fn snapshot_for_agent(agent_pid: &str) -> Vec<serde_json::Value> {
    let Ok(g) = INFLIGHT.lock() else {
        return Vec::new();
    };
    g.get(agent_pid)
        .map(|v| {
            v.iter()
                .map(|e| {
                    json!({
                        "provider": e.provider,
                        "request_id": e.request_id,
                        "has_provider_response_id": e.provider_response_id.is_some(),
                        "started_at_ms": e.started_at_ms,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Abort all in-flight entries for agent. Returns how many were tracked.
/// Best-effort: attempts OpenAI `POST /v1/responses/{id}/cancel` when id present.
pub fn abort_all_for_agent(state: &SharedState, agent_pid: &str) -> (u64, bool) {
    let entries = {
        let Ok(mut g) = INFLIGHT.lock() else {
            return (0, false);
        };
        g.remove(agent_pid).unwrap_or_default()
    };
    let n = entries.len() as u64;
    let mut used_api = false;
    for e in &entries {
        if e.provider.eq_ignore_ascii_case("openai") {
            if let Some(rid) = &e.provider_response_id {
                if try_openai_responses_cancel(rid) {
                    used_api = true;
                }
            }
        }
    }
    if n > 0 {
        if let Ok(mut es) = state.engine_store.lock() {
            let _ = es.folder_put(
                "spend_cease_inflight_v1",
                &format!("abort:{agent_pid}:{}", now_ms()),
                &json!({
                    "agent_pid": agent_pid,
                    "aborted": n,
                    "provider_cancel_api_used": used_api,
                    "honesty": "cancel_tax_may_remain_on_hosted_providers",
                }),
            );
        }
        tracing::warn!(
            agent_pid = %agent_pid,
            aborted = n,
            provider_cancel_api_used = used_api,
            "SpendCease: aborted in-flight LLM registry entries"
        );
    }
    (n, used_api)
}

fn try_openai_responses_cancel(response_id: &str) -> bool {
    let key = match std::env::var("OPENAI_API_KEY")
        .or_else(|_| std::env::var("CONNECTOR_OPENAI_API_KEY"))
        .or_else(|_| std::env::var("CONNECTOR_LLM_API_KEY"))
    {
        Ok(k) if !k.trim().is_empty() => k,
        _ => return false,
    };
    let url = format!("https://api.openai.com/v1/responses/{response_id}/cancel");
    // Blocking best-effort from Cease path (short timeout).
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .post(&url)
        .bearer_auth(key.trim())
        .header("content-type", "application/json")
        .send()
    {
        Ok(resp) => {
            let ok = resp.status().is_success() || resp.status().as_u16() == 409;
            if !ok {
                tracing::debug!(status = %resp.status(), "openai responses.cancel non-success");
            }
            ok
        }
        Err(e) => {
            tracing::debug!(error = %e, "openai responses.cancel failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_clear_roundtrip() {
        register("agt_test_inflight", "openai", "req1", None);
        clear("agt_test_inflight", "req1");
        let g = INFLIGHT.lock().unwrap();
        assert!(!g.contains_key("agt_test_inflight"));
    }

    #[test]
    fn inflight_guard_clears_on_drop() {
        {
            let _g = InflightGuard::register("agt_guard", "openai", "req_g", None);
            assert_eq!(snapshot_for_agent("agt_guard").len(), 1);
        }
        assert!(snapshot_for_agent("agt_guard").is_empty());
    }
}
