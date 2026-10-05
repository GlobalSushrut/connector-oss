//! Shared AppPackageV2 package gate for consequential platform effects.
//!
//! Wraps `connector_native_contract::admit_package_for_effect` with the node's
//! `CONNECTOR_ENV` / `CONNECTOR_RUNTIME_PROFILE` runtime profile.

use connector_native_contract::{
    admit_package_for_effect, gate_allows, ApiErrorEnvelope, PackageGateDecision, PackagePin,
    RuntimeProfile,
};
use serde_json::Value;

/// Resolve the effective runtime profile for package admission.
pub fn connector_runtime_profile() -> RuntimeProfile {
    let raw = std::env::var("CONNECTOR_RUNTIME_PROFILE")
        .or_else(|_| std::env::var("CONNECTOR_ENV"))
        .unwrap_or_else(|_| "development".into());
    RuntimeProfile::parse(&raw)
}

/// Require a valid signed package pin for consequential effects outside lab/dev.
///
/// Error string remains `package_gate:<honesty>` for legacy callers; prefer
/// [`require_package_envelope`] / [`deny_json`] for structured API responses.
pub fn require_package_for_consequential_effect(
    package: Option<&PackagePin>,
) -> Result<PackageGateDecision, String> {
    require_package_envelope(package).map_err(|e| format!("package_gate:{}", e.message))
}

/// Same gate returning [`ApiErrorEnvelope`].
pub fn require_package_envelope(
    package: Option<&PackagePin>,
) -> Result<PackageGateDecision, ApiErrorEnvelope> {
    let decision = admit_package_for_effect(connector_runtime_profile(), package, true);
    if !gate_allows(&decision) {
        Err(ApiErrorEnvelope::package_gate(decision.honesty.clone())
            .with_retry_safe(false)
            .with_detail(serde_json::json!({
                "verdict": decision.verdict,
                "profile": decision.profile,
                "lab_labeled": decision.lab_labeled,
            })))
    } else {
        Ok(decision)
    }
}

/// Map a gate/`native_invoker` error string into a canonical API JSON body.
pub fn deny_json(err: &str) -> Value {
    if let Some(env) = ApiErrorEnvelope::from_legacy_string(err) {
        return env.to_response_json();
    }
    serde_json::json!({ "ok": false, "error": err })
}

/// Parse an optional `package` object from a JSON body.
pub fn package_pin_from_json(body: &serde_json::Value) -> Option<PackagePin> {
    body.get("package")
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(env: &str, f: F) {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        let saved_env = std::env::var("CONNECTOR_ENV").ok();
        let saved_profile = std::env::var("CONNECTOR_RUNTIME_PROFILE").ok();
        std::env::remove_var("CONNECTOR_RUNTIME_PROFILE");
        std::env::set_var("CONNECTOR_ENV", env);
        f();
        match saved_profile {
            Some(v) => std::env::set_var("CONNECTOR_RUNTIME_PROFILE", v),
            None => std::env::remove_var("CONNECTOR_RUNTIME_PROFILE"),
        }
        match saved_env {
            Some(v) => std::env::set_var("CONNECTOR_ENV", v),
            None => std::env::remove_var("CONNECTOR_ENV"),
        }
    }

    #[test]
    fn lab_allows_unpackaged() {
        with_env("lab", || {
            let d = require_package_for_consequential_effect(None).unwrap();
            assert!(d.lab_labeled);
        });
    }

    #[test]
    fn production_denies_unpackaged() {
        with_env("production", || {
            let err = require_package_for_consequential_effect(None).unwrap_err();
            assert!(err.starts_with("package_gate:"), "{err}");
            let body = deny_json(&err);
            let env = ApiErrorEnvelope::from_response_value(&body).unwrap();
            assert_eq!(env.code, "package_gate");
        });
    }
}
