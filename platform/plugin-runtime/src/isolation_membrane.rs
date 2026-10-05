//! Isolation membrane — docker_lab / microvm physical closure under LLM distrust.
//!
//! When Connector distrusts the probabilistic model (`CONNECTOR_LLM_DISTRUST`) or
//! effect exclusivity is on, guests must not hold ambient network or secrets:
//! effects reach the world only through the Connector broker (vsock / mounted UDS).

use serde_json::{json, Value};

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn req_env_truthy(req_env: &[(String, String)], key: &str) -> bool {
    req_env
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Break-glass: allow guest TCP egress (weakens bypass resistance).
pub fn guest_egress_break_glass(req_env: &[(String, String)]) -> bool {
    env_truthy("CONNECTOR_ALLOW_GUEST_EGRESS")
        || req_env_truthy(req_env, "CONNECTOR_ALLOW_GUEST_EGRESS")
}

/// Membrane is on when distrust / exclusivity / docklock security is set.
pub fn membrane_enforced(req_env: &[(String, String)]) -> bool {
    if guest_egress_break_glass(req_env) {
        return false;
    }
    env_truthy("CONNECTOR_LLM_DISTRUST")
        || env_truthy("CONNECTOR_EFFECT_EXCLUSIVITY")
        || env_truthy("CONNECTOR_DOCKLOCK_DOCKER_SECURITY")
        || req_env_truthy(req_env, "CONNECTOR_LLM_DISTRUST")
        || req_env_truthy(req_env, "CONNECTOR_EFFECT_EXCLUSIVITY")
        || req_env_truthy(req_env, "CONNECTOR_DOCKLOCK_DOCKER_SECURITY")
        || req_env_truthy(req_env, "CONNECTOR_INTELLIGENCE_EXECUTION_PLANE")
        || crate::productionish_env()
}

/// Guest must not receive secrets / tokens / API keys.
pub fn is_forbidden_guest_env_key(key: &str) -> bool {
    let u = key.to_ascii_uppercase();
    if u == "CONNECTOR_ZT_HANDSHAKE"
        || u == "CONNECTOR_LLM_DISTRUST"
        || u == "CONNECTOR_EFFECT_EXCLUSIVITY"
        || u == "CONNECTOR_AGENT_PID"
        || u == "CONNECTOR_PRINCIPAL_ID"
        || u == "CONNECTOR_EXECUTION_QUANTUM"
        || u == "CONNECTOR_BROKER_ONLY"
        || u.starts_with("CONNECTOR_DOCKLOCK_")
        || u.starts_with("CONNECTOR_DOCKER_LAB_")
        || u.starts_with("CONNECTOR_MICROVM_")
        || u.starts_with("CONNECTOR_PLUGIN_")
        || u.starts_with("CONNECTOR_MATRIX_")
        || u == "CONNECTOR_INTELLIGENCE_EXECUTION_PLANE"
    {
        // Explicit allow for cage posture keys — still block secrets among them.
        if u.contains("SECRET")
            || u.contains("PASSWORD")
            || u.ends_with("_TOKEN")
            || u.ends_with("_API_KEY")
            || u.contains("PRIVATE_KEY")
        {
            return true;
        }
        return false;
    }
    u.contains("SECRET")
        || u.contains("PASSWORD")
        || u.contains("PRIVATE_KEY")
        || u.contains("API_KEY")
        || u.ends_with("_TOKEN")
        || u.contains("CREDENTIAL")
        || u.starts_with("AWS_")
        || u.starts_with("OPENAI_")
        || u.starts_with("ANTHROPIC_")
        || u == "CONNECTOR_JWT_SECRET"
        || u == "CONNECTOR_API_KEY"
        || u == "CONNECTOR_CFNI_SECRET"
        || u == "CONNECTOR_CAGE_CAP_SECRET"
}

/// Strip forbidden keys and inject broker-only posture.
pub fn sanitize_guest_env(req_env: &[(String, String)]) -> Vec<(String, String)> {
    let membrane = membrane_enforced(req_env);
    let mut out: Vec<(String, String)> = req_env
        .iter()
        .filter(|(k, _)| !is_forbidden_guest_env_key(k))
        .cloned()
        .collect();
    if membrane {
        for (k, v) in [
            ("CONNECTOR_LLM_DISTRUST", "1"),
            ("CONNECTOR_EFFECT_EXCLUSIVITY", "1"),
            ("CONNECTOR_ZT_HANDSHAKE", "1"),
            ("CONNECTOR_BROKER_ONLY", "1"),
            ("CONNECTOR_DOCKER_LAB_EGRESS", "deny_all"),
            ("CONNECTOR_MICROVM_EGRESS_MODE", "deny_all"),
            ("CONNECTOR_DOCKLOCK_DOCKER_SECURITY", "1"),
        ] {
            if !out.iter().any(|(ek, _)| ek == k) {
                out.push((k.into(), v.into()));
            } else if let Some((_, ev)) = out.iter_mut().find(|(ek, _)| ek == k) {
                *ev = v.into();
            }
        }
    }
    out
}

/// Under membrane, guest egress is deny_all (no TAP / no docker bridge).
pub fn force_guest_deny_all(req_env: &[(String, String)]) -> bool {
    membrane_enforced(req_env)
}

pub fn membrane_status(req_env: &[(String, String)]) -> Value {
    json!({
        "schema": "connector.isolation_membrane.v1",
        "enforced": membrane_enforced(req_env),
        "guest_egress": if force_guest_deny_all(req_env) {
            "deny_all_broker_only"
        } else if guest_egress_break_glass(req_env) {
            "break_glass_allow_guest_egress"
        } else {
            "policy_default"
        },
        "secrets_in_guest": false,
        "bypass_path": "guest_has_no_ambient_network; effects via Connector broker only",
        "break_glass": "CONNECTOR_ALLOW_GUEST_EGRESS=1",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_api_keys() {
        assert!(is_forbidden_guest_env_key("OPENAI_API_KEY"));
        assert!(is_forbidden_guest_env_key("CONNECTOR_API_KEY"));
        assert!(!is_forbidden_guest_env_key("CONNECTOR_AGENT_PID"));
        assert!(!is_forbidden_guest_env_key("CONNECTOR_ZT_HANDSHAKE"));
    }

    #[test]
    fn sanitize_injects_broker_only() {
        std::env::set_var("CONNECTOR_LLM_DISTRUST", "1");
        let out = sanitize_guest_env(&[("CONNECTOR_AGENT_PID".into(), "a1".into())]);
        assert!(out.iter().any(|(k, v)| k == "CONNECTOR_BROKER_ONLY" && v == "1"));
        assert!(out.iter().any(|(k, v)| k == "CONNECTOR_DOCKER_LAB_EGRESS" && v == "deny_all"));
        std::env::remove_var("CONNECTOR_LLM_DISTRUST");
    }
}
