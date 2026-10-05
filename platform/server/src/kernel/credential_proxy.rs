//! DI-3 — credential proxy: resolve vault handles on the **platform** plane only.
//!
//! Intelligence / DockLock cages must never receive raw API keys. Tool inputs may
//! reference secrets as:
//! - string: `vault:handle:<handle_id>`
//! - object: `{ "$vault_handle": "<handle_id>" }`
//!
//! Those refs are materialized here before bridge dispatch; values are not logged.

use serde_json::Value;

use crate::state::PlatformState;

const HANDLE_PREFIX: &str = "vault:handle:";

/// Walk `value` in place, replacing vault handle refs with resolved secrets.
/// Returns how many refs were materialized.
pub fn materialize_secret_refs(state: &PlatformState, value: &mut Value) -> Result<usize, String> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut count = 0usize;
    materialize_rec(state, value, now_ms, &mut count)?;
    Ok(count)
}

fn materialize_rec(
    state: &PlatformState,
    value: &mut Value,
    now_ms: i64,
    count: &mut usize,
) -> Result<(), String> {
    match value {
        Value::String(s) => {
            if let Some(hid) = s.strip_prefix(HANDLE_PREFIX) {
                let resolved = resolve(state, hid, now_ms)?;
                *s = resolved;
                *count += 1;
            }
        }
        Value::Object(map) => {
            if let Some(Value::String(hid)) = map.get("$vault_handle").cloned() {
                let resolved = resolve(state, &hid, now_ms)?;
                *value = Value::String(resolved);
                *count += 1;
                return Ok(());
            }
            for (_k, v) in map.iter_mut() {
                materialize_rec(state, v, now_ms, count)?;
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                materialize_rec(state, v, now_ms, count)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve(state: &PlatformState, handle_id: &str, now_ms: i64) -> Result<String, String> {
    let vault = state.secret_store.lock().map_err(|e| format!("vault_lock:{e}"))?;
    vault
        .resolve_handle(handle_id, now_ms)
        .map_err(|e| format!("vault_resolve:{e}"))
}

/// Refuse to put known LLM/provider secret env names into a cage env list.
pub fn strip_secret_env_keys(env: &mut Vec<(String, String)>) -> usize {
    const DENY: &[&str] = &[
        "CONNECTOR_LLM_API_KEY",
        "CONNECTOR_LLM_FALLBACK_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "CONNECTOR_ANTHROPIC_API_KEY",
    ];
    let before = env.len();
    env.retain(|(k, _)| {
        !DENY
            .iter()
            .any(|d| k.eq_ignore_ascii_case(d) || k.to_ascii_uppercase().contains("API_KEY"))
    });
    before.saturating_sub(env.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_api_key_env() {
        let mut env = vec![
            ("CONNECTOR_PRINCIPAL_ID".into(), "p1".into()),
            ("OPENAI_API_KEY".into(), "sk-secret".into()),
            ("FOO_API_KEY".into(), "x".into()),
        ];
        let n = strip_secret_env_keys(&mut env);
        assert_eq!(n, 2);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "CONNECTOR_PRINCIPAL_ID");
    }
}
