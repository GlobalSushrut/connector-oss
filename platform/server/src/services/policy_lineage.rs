//! Shared principal / policy lineage honesty (P5.1).
//!
//! Surfaces the ids that gateway, TraceTramp, WitnessCtl, and DevGuard are
//! expected to share. Full E2E correlation across TT/WC/DG remains partial.

use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    services::runtime_control::{self, load_runtime_policy},
    state::SharedState,
};

fn node_instance_id(state: &SharedState) -> String {
    std::env::var("CONNECTOR_INSTANCE_ID")
        .or_else(|_| std::env::var("CONNECTOR_NODE_ID"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            if state.license.instance_id.trim().is_empty() {
                "local".into()
            } else {
                state.license.instance_id.clone()
            }
        })
}

/// `GET /api/v1/runtime/policy-lineage` — principal + policy id fields shared across institutions.
pub async fn get_policy_lineage(State(state): State<SharedState>) -> Json<Value> {
    let runtime_mode = *state.runtime_mode.read().unwrap();
    let isolation = *state.isolation_runtime.read().unwrap();
    let policy = {
        let es = state.engine_store.lock().unwrap();
        load_runtime_policy(&**es)
    };

    // RuntimePolicy today is limit-shaped (no stable policy UUID). Honesty: partial.
    let policy_fingerprint = format!(
        "runtime_policy:dev={}:pilot={}:prod_default={}:kecs={:.3}",
        policy.dev_agent_limit,
        policy.pilot_agent_limit,
        policy.production_default_agent_limit,
        policy.kecs_suspend_threshold
    );

    let instance_id = node_instance_id(&state);
    let principal_contract = "connector_trust::PrincipalContextV2";
    let shared = json!({
        "principal_contract": principal_contract,
        "principal_fields": [
            "subject",
            "role",
            "permissions",
            "tenant_id",
            "jti",
            "token_type",
            "instance_id",
            "auth_source",
            "contract_version"
        ],
        "node_instance_id": instance_id,
        "license_instance_id": state.license.instance_id,
        "runtime_mode": runtime_mode.as_str(),
        "isolation_runtime": isolation.as_str(),
        "kernel_policy": {
            "id": "platform.runtime_policy",
            "revision": Value::Null,
            "fingerprint": policy_fingerprint,
            "honesty": "No durable policy UUID/revision yet — fingerprint of RuntimePolicy limits only."
        },
        "institutions": {
            "gateway": {
                "principal_source": "auth::Claims → PrincipalContextV2",
                "policy_binding": "admission + runtime_policy agent caps"
            },
            "tracetramp": {
                "principal_source": "platform proxy / gated session (shared JWT or API key)",
                "policy_binding": "partial — TT control plane must not mint a parallel identity"
            },
            "witnessctl": {
                "principal_source": "platform proxy / gated session",
                "policy_binding": "partial — custody receipts cite platform principal when wired"
            },
            "devguard": {
                "principal_source": "connect session bound to node identity",
                "policy_binding": "policy_config YAML roles; sessions must bind instance_id"
            }
        },
    });

    Json(json!({
        "ok": true,
        "schema": "runtime.policy_lineage.v1",
        "implemented": "partial",
        "lineage": shared,
        "honesty": [
            "PrincipalContextV2 is the shared principal type (chaos I2/I6).",
            "policy.id is a stable label; revision is null until a versioned policy store ships.",
            "Same policy id must be visible gateway ↔ TT ↔ DG when E2E correlation closes (P5.1 verify).",
            "Do not mint a second identity plane inside institution plugins."
        ],
        "defense_strict": runtime_control::defense_strict_enabled(),
    }))
}
